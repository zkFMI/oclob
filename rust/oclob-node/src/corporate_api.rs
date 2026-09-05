//! Owner-only corporate RPC. Never mount this service's identity or journal
//! in the public reader, market coordinator, or MPC containers.
use crate::corporate::{private_client, CorporateNativeConfig};
use crate::corporate_authorization::CorporateReserveAuthorization;
use crate::corporate_dispatch::NativeCorporateDispatch;
use crate::corporate_journal::{NativeCorporateJournal, StoredCorporateIntent};
use crate::market_network::{read_record, write_record, MarketEndpoint};
use crate::network::{
    certificate_fingerprint, client_tls_context, ClientIdentityConfig, ClusterPublicConfig,
    ServerTlsConfig,
};
use serde::{Deserialize, Serialize};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

const REQUEST_BYTES: usize = 256 * 1024;
const RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorporateApiConfig {
    pub endpoint: MarketEndpoint,
    /// Exact corporate client certificates; sharing a CA is insufficient.
    pub clients: Vec<[u8; 32]>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CorporateRequest {
    Enqueue {
        request_id: String,
        intent: Box<StoredCorporateIntent>,
        authorization: Box<CorporateReserveAuthorization>,
        source_note: Option<[u8; 32]>,
    },
    QueueStatus,
    WalletSnapshot,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CorporateResponse {
    Queued {
        request_id: String,
        already_present: bool,
    },
    Queue {
        entries: serde_json::Value,
    },
    Wallet {
        snapshot: serde_json::Value,
    },
    Rejected,
}

pub struct CorporateApi {
    pub config: CorporateNativeConfig,
    pub cluster: ClusterPublicConfig,
    pub identity: ClientIdentityConfig,
    pub journal: NativeCorporateJournal,
    pub queue: NativeCorporateDispatch,
}

impl CorporateApi {
    pub fn handle(&self, request: CorporateRequest, now: u64) -> Result<CorporateResponse, String> {
        match request {
            CorporateRequest::QueueStatus => Ok(CorporateResponse::Queue {
                entries: serde_json::to_value(self.queue.summaries()?).map_err(err)?,
            }),
            CorporateRequest::WalletSnapshot => Ok(CorporateResponse::Wallet {
                snapshot: self.wallet_snapshot()?,
            }),
            CorporateRequest::Enqueue {
                request_id,
                intent,
                authorization,
                source_note,
            } => {
                // Reject malformed authorization before touching either file.
                if request_id.is_empty()
                    || request_id.len() > 64
                    || !request_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                    || !intent.reserve_send_tracking
                    || intent.accepted_at > now
                    || authorization.mandate.valid_from < intent.accepted_at
                    || authorization.mandate.valid_from > now
                    || authorization.order_wire != intent.order_wire
                    || authorization.signing_key != intent.signing_key
                    || authorization.eligibility_commitment != intent.eligibility_commitment
                    || authorization.mandate.valid_until != intent.expires_at
                {
                    return Err("invalid corporate authorization".into());
                }
                authorization.validate(&self.config)?;
                let order =
                    oclob_core::SecretOrder::from_secret_wire(&intent.order_wire).map_err(err)?;
                if order.market_id() != self.cluster.market_id {
                    return Err("corporate market mismatch".into());
                }
                let _guard = self.journal.acquire_intake()?;
                let existing = self.journal.intent(&request_id)?;
                if let Some(saved) = &existing {
                    if serde_json::to_vec(saved).map_err(err)?
                        != serde_json::to_vec(&intent).map_err(err)?
                    {
                        return Err("corporate request conflicts with saved intent".into());
                    }
                } else if intent.expires_at <= now {
                    return Err("new corporate request expired".into());
                }
                if let Some(saved) = self.journal.authorization(&request_id)? {
                    if saved.digest()? != authorization.digest()? {
                        return Err("corporate request conflicts with saved authorization".into());
                    }
                }
                self.journal.save_intent(&request_id, &intent)?;
                self.journal
                    .save_authorization(&request_id, &authorization, &self.config)?;
                let already_present = self.queue.enqueue_authorized(
                    &self.journal,
                    &self.config,
                    &request_id,
                    source_note,
                )?;
                // Admission, matching, proving and settlement remain worker duties.
                Ok(CorporateResponse::Queued {
                    request_id,
                    already_present,
                })
            }
        }
    }

    fn wallet_snapshot(&self) -> Result<serde_json::Value, String> {
        use curve25519_dalek::scalar::Scalar;
        use ed25519_dalek::VerifyingKey;
        use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge};
        use qomm_defmi::facility::QuorumAuthorizer;
        use qomm_defmi::notes::{note_nullifier, Wallet};
        use qomm_zk::pedersen::Pedersen;
        use qomm_zkpi::handles::Identity;
        use std::collections::BTreeMap;
        let client = private_client(&self.config, &self.identity)?.chain()?;
        let root = client.state_root()?;
        let facility = if self.journal.reservations()?.is_empty() {
            let canonical = client.credit_facility_snapshot(self.config.facility_id)?;
            let witness = crate::corporate::FacilityWitness {
                facility_id: self.config.facility_id,
                sequence: canonical.facility.sequence,
                values: self.config.facility_values,
                blindings: self.config.facility_blindings,
            };
            if canonical.state_root != root
                || canonical.facility.facility_id != self.config.facility_id
                || witness.commitments()?
                    != [
                        canonical.facility.available_commitment,
                        canonical.facility.held_commitment,
                        canonical.facility.outstanding_commitment,
                    ]
            {
                return Err("initial facility witness does not match canonical state".into());
            }
            witness
        } else {
            crate::native_wallet::recover_facility(&self.config, &client, &self.journal)?
        };
        let authorizer = QuorumAuthorizer::new(
            BTreeMap::from([(
                "read-only".into(),
                VerifyingKey::from_bytes(&self.config.issuer_public).map_err(err)?,
            )]),
            1,
            1,
            "read-only",
        )?;
        let bridge = AvalancheNoteBridge::new(&authorizer, &client);
        let handle = Identity::from_seed(self.config.identity_seed).handle(b"defmi:oclob:v1");
        let spend = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            self.config.wallet_spend_secret,
        ))
        .ok_or("invalid corporate spend key")?;
        let wallet = Wallet::from_parts(handle.secret, spend);
        let key = Pedersen::new(b"qomm:defmi:v1");
        // Escrow note face values remain immutable after a partial fill. Their
        // nullifiers are not a current balance: the reservation head is. Reuse
        // recover_facility's authenticated remainder reconstruction above.
        let mut escrows = BTreeMap::new();
        for prepared in self.journal.reservations()? {
            prepared.validate(&self.config)?;
            if self.journal.was_never_reserved(&prepared)? {
                continue;
            }
            let head = client.application_reservation_snapshot(prepared.request.mandate.hold_id)?;
            if head.state_root != root
                || head.binding != prepared.request.mandate.binding()?
                || !matches!(head.status.as_str(), "active" | "consumed" | "released")
            {
                return Err("wallet reservation changed".into());
            }
            escrows.insert(head.escrow_note_id, head.status == "active");
        }
        let mut assets = Vec::new();
        for asset in [
            oclob_settlement::canonical_cash_asset_id(),
            oclob_settlement::canonical_securities_asset_id(&self.cluster.market_id),
        ] {
            let (read_root, ledger, outputs) = bridge.note_ledger(asset, key.clone(), 32, 4096)?;
            if read_root != root {
                return Err("wallet snapshot changed".into());
            }
            let mut available = 0u128;
            let mut observed_escrows = std::collections::BTreeSet::new();
            for (index, opening) in ledger.scan(&wallet, &key) {
                let serial = note_nullifier(&opening.serial).compress().to_bytes();
                let state = bridge.note_serial(serial)?;
                if state.state_root != root {
                    return Err("wallet snapshot changed".into());
                }
                if !state.spent {
                    if outputs[index].lock_id == [0; 32] {
                        available += u128::from(opening.value);
                    } else {
                        if asset != self.config.asset_id
                            || !escrows.contains_key(&outputs[index].note_id)
                        {
                            return Err("wallet contains an unsupported lock".into());
                        }
                        observed_escrows.insert(outputs[index].note_id);
                    }
                }
            }
            let locked = if asset == self.config.asset_id {
                if escrows
                    .iter()
                    .any(|(id, active)| *active && !observed_escrows.contains(id))
                {
                    return Err("active reservation has no owned escrow note".into());
                }
                u128::from(facility.values[1])
            } else {
                0
            };
            assets.push(serde_json::json!({"asset_id":hex::encode(asset),
                "spendable":available.to_string(),"locked":locked.to_string()}));
        }
        if client.state_root()? != root {
            return Err("wallet snapshot changed".into());
        }
        Ok(
            serde_json::json!({"state_root":hex::encode(root),"assets":assets,
            "facility":{"asset_id":hex::encode(self.config.asset_id),
                "sequence":facility.sequence.to_string(),"available":facility.values[0].to_string(),
                "held":facility.values[1].to_string(),"outstanding":facility.values[2].to_string()},
            "scope":"canonical_notes_and_reservation_heads","unredeemed_claims_included":false}),
        )
    }
}

pub fn serve(
    listener: TcpListener,
    tls: ServerTlsConfig,
    config: CorporateApiConfig,
    api: CorporateApi,
) -> Result<(), String> {
    if config.clients.is_empty() || config.clients.contains(&[0; 32]) {
        return Err("corporate API requires exact client certificate pins".into());
    }
    for tcp in listener.incoming().flatten() {
        // Never print raw RPC errors, order contents or private wallet data.
        let _ = receive(tcp, &tls, &config, &api);
    }
    Ok(())
}

fn receive(
    tcp: TcpStream,
    tls: &ServerTlsConfig,
    config: &CorporateApiConfig,
    api: &CorporateApi,
) -> Result<(), String> {
    tcp.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(err)?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(err)?;
    let mut stream = tls
        .acceptor
        .accept(tcp)
        .map_err(|_| "corporate TLS handshake failed")?;
    let peer = stream
        .ssl()
        .peer_certificate()
        .ok_or("corporate TLS peer absent")?;
    if !config
        .clients
        .contains(&certificate_fingerprint(&peer.to_der().map_err(err)?))
    {
        return Err("corporate client not authorized".into());
    }
    let response = read_record(&mut stream, REQUEST_BYTES)
        .and_then(|r| api.handle(r, crate::market_runtime::now()?))
        .unwrap_or(CorporateResponse::Rejected);
    write_record(&mut stream, &response, RESPONSE_BYTES)
}

pub fn call(
    endpoint: &MarketEndpoint,
    identity: &ClientIdentityConfig,
    request: &CorporateRequest,
) -> Result<CorporateResponse, String> {
    let tls = client_tls_context(
        &identity.tls_certificate,
        &identity.tls_private_key,
        &identity.tls_ca,
    )
    .map_err(err)?;
    let address = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(err)?
        .next()
        .ok_or("corporate endpoint absent")?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(err)?;
    tcp.set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(err)?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(err)?;
    let mut stream = tls
        .connector
        .connect(&endpoint.server_name, tcp)
        .map_err(|_| "corporate TLS connection failed")?;
    let peer = stream
        .ssl()
        .peer_certificate()
        .ok_or("corporate TLS peer absent")?;
    if certificate_fingerprint(&peer.to_der().map_err(err)?) != endpoint.certificate_sha256 {
        return Err("corporate endpoint pin mismatch".into());
    }
    write_record(&mut stream, request, REQUEST_BYTES)?;
    read_record(&mut stream, RESPONSE_BYTES)
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
