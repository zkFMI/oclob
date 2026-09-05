//! Authenticated, fixed-size market intake carries only signed public receipts
//! and threshold-encrypted reservation authority, never an order body.
use crate::edge_client::EdgeAdmissionReceipt;
use crate::market_journal::MarketJournal;
use crate::network::{
    certificate_fingerprint, client_tls_context, ClientIdentityConfig, ClusterPublicConfig,
    ServerTlsConfig,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_edge::SealedReservationAuthority;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const REQUEST_BYTES: usize = 256 * 1024;
const RESPONSE_BYTES: usize = 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MarketEndpoint {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub certificate_sha256: [u8; 32],
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MarketServiceConfig {
    pub endpoint: MarketEndpoint,
    pub participants: Vec<[u8; 32]>,
    pub journal: PathBuf,
    pub journal_key: PathBuf,
    pub base_asset: [u8; 32],
    pub quote_asset: [u8; 32],
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MarketIngress {
    pub version: u16,
    pub receipt: EdgeAdmissionReceipt,
    pub authority: SealedReservationAuthority,
    pub signature: Vec<u8>,
}
impl MarketIngress {
    fn statement(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(b"OCLOB:MARKET-INGRESS:v1")
            .chain_update(
                serde_json::to_vec(&(&self.version, &self.receipt, &self.authority))
                    .map_err(err)?,
            )
            .finalize()
            .into())
    }
    pub fn sign(
        receipt: EdgeAdmissionReceipt,
        authority: SealedReservationAuthority,
        key: &SigningKey,
    ) -> Result<Self, String> {
        if receipt.manifest.signer != key.verifying_key().to_bytes() {
            return Err("market input signer differs from admitted order".into());
        }
        let mut result = Self {
            version: 1,
            receipt,
            authority,
            signature: Vec::new(),
        };
        result.signature = key.sign(&result.statement()?).to_bytes().to_vec();
        Ok(result)
    }
    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(b"OCLOB:MARKET-INGRESS-DIGEST:v1")
            .chain_update(serde_json::to_vec(self).map_err(err)?)
            .finalize()
            .into())
    }
    pub fn verify(&self, cluster: &ClusterPublicConfig, at: u64) -> Result<(), String> {
        if self.version != 1 || !self.receipt.manifest.uses_pretrade_reservation() {
            return Err("market intake refuses legacy or unknown input".into());
        }
        self.receipt.verify(cluster, at).map_err(err)?;
        self.authority
            .validate_envelope(&self.receipt.manifest)
            .map_err(err)?;
        VerifyingKey::from_bytes(&self.receipt.manifest.signer)
            .map_err(err)?
            .verify_strict(
                &self.statement()?,
                &Signature::try_from(self.signature.as_slice()).map_err(err)?,
            )
            .map_err(err)
    }
}
#[derive(Deserialize, Serialize)]
struct Acknowledgement {
    accepted: bool,
    digest: [u8; 32],
    sequence: u64,
}

pub fn submit(
    endpoint: &MarketEndpoint,
    identity: &ClientIdentityConfig,
    input: &MarketIngress,
) -> Result<(), String> {
    let tls = client_tls_context(
        &identity.tls_certificate,
        &identity.tls_private_key,
        &identity.tls_ca,
    )
    .map_err(err)?;
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).map_err(err)?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(err)?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(err)?;
    let mut stream = tls
        .connector
        .connect(&endpoint.server_name, tcp)
        .map_err(|_| "market TLS connection failed")?;
    let certificate = stream
        .ssl()
        .peer_certificate()
        .ok_or("market TLS peer absent")?;
    if certificate_fingerprint(&certificate.to_der().map_err(err)?) != endpoint.certificate_sha256 {
        return Err("market TLS peer differs from configured pin".into());
    }
    write_record(&mut stream, input, REQUEST_BYTES)?;
    let ack: Acknowledgement = read_record(&mut stream, RESPONSE_BYTES)?;
    if !ack.accepted || ack.digest != input.digest()? || ack.sequence == 0 {
        return Err("market did not acknowledge exact durable intake".into());
    }
    Ok(())
}
pub fn serve(
    listener: TcpListener,
    tls: ServerTlsConfig,
    config: MarketServiceConfig,
    cluster: ClusterPublicConfig,
    journal: Arc<MarketJournal>,
) {
    for connection in listener.incoming() {
        let Ok(tcp) = connection else {
            continue;
        };
        let _ = receive_connection(tcp, &tls, &config, &cluster, &journal);
    }
}
/// One real TLS exchange, also exercised by transport-only unit tests.
pub(crate) fn receive_connection(
    tcp: TcpStream,
    tls: &ServerTlsConfig,
    config: &MarketServiceConfig,
    cluster: &ClusterPublicConfig,
    journal: &MarketJournal,
) -> Result<(), String> {
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(err)?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(err)?;
    let mut stream = tls
        .acceptor
        .accept(tcp)
        .map_err(|_| "market TLS handshake failed")?;
    let certificate = stream
        .ssl()
        .peer_certificate()
        .ok_or("market TLS peer absent")?;
    let peer = certificate_fingerprint(&certificate.to_der().map_err(err)?);
    if !config.participants.contains(&peer) {
        return Err("market intake caller is not a participant".into());
    }
    let input: MarketIngress = read_record(&mut stream, REQUEST_BYTES)?;
    let result = journal.accept(&input, cluster, crate::market_runtime::now()?);
    let ack = match result {
        Ok(sequence) => Acknowledgement {
            accepted: true,
            digest: input.digest()?,
            sequence,
        },
        Err(_) => Acknowledgement {
            accepted: false,
            digest: [0; 32],
            sequence: 0,
        },
    };
    write_record(&mut stream, &ack, RESPONSE_BYTES)
}
pub(crate) fn write_record<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
    size: usize,
) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(err)?;
    if body.len() + 4 > size {
        return Err("market input exceeds fixed record size".into());
    }
    let mut record = vec![0u8; size];
    record[..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
    record[4..4 + body.len()].copy_from_slice(&body);
    writer.write_all(&record).map_err(err)?;
    writer.flush().map_err(err)
}
pub(crate) fn read_record<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
    size: usize,
) -> Result<T, String> {
    let mut record = vec![0u8; size];
    reader.read_exact(&mut record).map_err(err)?;
    let len = u32::from_be_bytes(
        record[..4]
            .try_into()
            .map_err(|_| "market frame length invalid")?,
    ) as usize;
    if len == 0 || len > size - 4 || record[4 + len..].iter().any(|x| *x != 0) {
        return Err("market frame length or padding invalid".into());
    }
    serde_json::from_slice(&record[4..4 + len]).map_err(err)
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Retry exact market handoff even if the corporate process died after all
/// node acknowledgements. No new order, credential, funding proof or signature
/// of financial terms is created: only the original order key signs its
/// already-admitted opaque transport envelope.
pub fn publish_corporate_admissions(
    journal: &crate::corporate_journal::NativeCorporateJournal,
    identity: &ClientIdentityConfig,
    cluster: &ClusterPublicConfig,
) -> Result<(), String> {
    let Some(path) = std::env::var_os("OCLOB_MARKET_CONFIG") else {
        return Ok(());
    };
    if path.is_empty() {
        return Ok(());
    }
    let config: MarketServiceConfig =
        serde_json::from_slice(&std::fs::read(path).map_err(err)?).map_err(err)?;
    let endpoint_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&config.endpoint).map_err(err)?).into();
    for id in journal.admitted_request_ids()? {
        let intent = journal
            .intent(&id)?
            .ok_or("market publishing lost original intent")?;
        let receipt: EdgeAdmissionReceipt = journal
            .stage(&id, "receipt")?
            .ok_or("market publishing lost node receipt")?;
        let delivery: crate::corporate_journal::StoredCorporateDelivery = journal
            .stage(&id, "delivery")?
            .ok_or("market publishing lost encrypted authority")?;
        journal.verify_receipt(&receipt, &delivery, cluster, intent.accepted_at)?;
        let input = MarketIngress::sign(
            receipt,
            delivery.authority,
            &SigningKey::from_bytes(&intent.signing_key),
        )?;
        let expected = (endpoint_digest, input.digest()?);
        if let Some(saved) = journal.stage::<([u8; 32], [u8; 32])>(&id, "market")? {
            if saved != expected {
                return Err("market destination or original handoff changed".into());
            }
            continue;
        }
        submit(&config.endpoint, identity, &input)?;
        let saved: ([u8; 32], [u8; 32]) = journal.save_stage(&id, "market", &expected, &intent)?;
        if saved != expected {
            return Err("durable market handoff differs from acknowledgement".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_market_records_reject_bad_size_padding_and_truncation() {
        let value = Acknowledgement {
            accepted: true,
            digest: [7; 32],
            sequence: 1,
        };
        let mut bytes = Vec::new();
        write_record(&mut bytes, &value, RESPONSE_BYTES).unwrap();
        assert_eq!(bytes.len(), RESPONSE_BYTES);
        let restored: Acknowledgement = read_record(&mut bytes.as_slice(), RESPONSE_BYTES).unwrap();
        assert_eq!(restored.sequence, 1);
        let mut changed = bytes.clone();
        changed[RESPONSE_BYTES - 1] = 1;
        assert!(read_record::<Acknowledgement>(&mut changed.as_slice(), RESPONSE_BYTES).is_err());
        let mut changed = bytes.clone();
        changed[..4].copy_from_slice(&(RESPONSE_BYTES as u32).to_be_bytes());
        assert!(read_record::<Acknowledgement>(&mut changed.as_slice(), RESPONSE_BYTES).is_err());
        assert!(read_record::<Acknowledgement>(&mut &bytes[..100], RESPONSE_BYTES).is_err());
        assert!(write_record(&mut Vec::new(), &vec![99u8; REQUEST_BYTES], REQUEST_BYTES).is_err());
    }
}
