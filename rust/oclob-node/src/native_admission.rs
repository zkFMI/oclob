//! Private DeFMI ingress, separate from the OCLOB market coordinator.
//! Transport uses the existing pinned bounded resident-service codec and mTLS.

use crate::network::{certificate_fingerprint, PeerRole, Principal, ServerTlsConfig};
use defmi::application_reservation::ApplicationReserveScope;
use defmi::avalanche::{AvalancheClient, AvalancheNoteBridge, AvalancheRpcClient};
use defmi::facility::QuorumAuthorizer;
use oclob_dekyx::OclobEligibilityVerifier;
use oclob_settlement::pretrade::{PrivateReserveRequest, MAX_PRETRADE_BYTES};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zkfmi_crypto::hybrid::signature::HybridSigner;
use zkpi_committee::proof_party::{
    encode_bounded_response, read_bounded_request_line, ProofRequest, ProofResponse,
};

/// Constructed by the DeFMI operator, not deserialized from an API request.
pub struct AdmissionAuthority {
    pub client: AvalancheRpcClient,
    pub authorizer: QuorumAuthorizer,
    pub governance_signers: BTreeMap<String, defmi::governance::GovernanceSigner>,
    pub receipt_issuer: Arc<HybridSigner>,
    pub private_tag_key: zeroize::Zeroizing<[u8; 32]>,
    pub scope: ApplicationReserveScope,
    pub eligibility: OclobEligibilityVerifier,
}

impl AdmissionAuthority {
    fn dispatch(&self, role: PeerRole, request: ProofRequest) -> Result<Value, String> {
        match request.method.as_str() {
            "scope" if request.params == json!({}) => {
                serde_json::to_value(&self.scope).map_err(err)
            }
            "reserve" | "recover_reservation" if role == PeerRole::Participant => {
                let reserve: PrivateReserveRequest =
                    serde_json::from_value(request.params).map_err(err)?;
                if reserve.mandate.scope != self.scope {
                    return Err("reservation belongs to another issuer deployment".into());
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(err)?
                    .as_secs();
                if request.method == "recover_reservation" {
                    return serde_json::to_value(reserve.recover_finalized(
                        &self.client,
                        &self.receipt_issuer,
                        &self.private_tag_key,
                        now,
                    )?)
                    .map_err(err);
                }
                // Read canonical state first. Replaying the SAME mandate after
                // a lost reply must not need the now-spent input notes or old
                // facility generation. Recovery verifies the complete binding;
                // it never issues a replacement reserve or new funding proof.
                if let Ok(finalized) = reserve.recover_finalized(
                    &self.client,
                    &self.receipt_issuer,
                    &self.private_tag_key,
                    now,
                ) {
                    return serde_json::to_value(finalized).map_err(err);
                }
                let requirement = self.eligibility.requirement();
                let verifier = self
                    .eligibility
                    .directory()
                    .verifier(&requirement.issuer_id, requirement.issuer_key_epoch)
                    .map_err(err)?;
                let bridge = AvalancheNoteBridge::new(&self.authorizer, &self.client);
                let verified = reserve.verify(
                    &bridge,
                    &self.scope,
                    &verifier,
                    requirement,
                    now,
                    &mut rand::rngs::OsRng,
                )?;
                let approval = self.authorizer.approve(
                    verified.reservation().statement()?,
                    self.client.state_root()?,
                    &self.governance_signers,
                )?;
                serde_json::to_value(reserve.finalize(
                    &bridge,
                    &verified,
                    &approval,
                    &self.receipt_issuer,
                    &self.private_tag_key,
                    now,
                )?)
                .map_err(err)
            }
            "chain" => {
                let envelope = request
                    .params
                    .as_object()
                    .ok_or("chain request must be an object")?;
                if envelope.len() != 4 || envelope.get("jsonrpc") != Some(&json!("2.0")) {
                    return Err("chain request envelope is malformed".into());
                }
                let id = envelope
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or("chain request ID is invalid")?;
                let method = envelope
                    .get("method")
                    .and_then(Value::as_str)
                    .ok_or("chain method is invalid")?;
                let params = envelope.get("params").ok_or("chain params are missing")?;
                let read = matches!(
                    method,
                    "defmivm.stateRoot"
                        | "defmivm.asset"
                        | "defmivm.note"
                        | "defmivm.listNotes"
                        | "defmivm.noteSerial"
                        | "defmivm.creditFacility"
                        | "defmivm.creditHold"
                        | "defmivm.applicationNoteReservation"
                        | "defmivm.noteClaim"
                        | "defmivm.listNoteClaims"
                        | "defmivm.txStatus"
                        | "defmivm.network"
                );
                let participant_expiry = if role == PeerRole::Participant
                    && method == "defmivm.issueApplicationNoteRelease"
                {
                    let release: defmi::application_settlement::ApplicationNoteRelease =
                        serde_json::from_value(
                            params
                                .get("release")
                                .cloned()
                                .ok_or("expiry release is missing")?,
                        )
                        .map_err(err)?;
                    release.signing_message()?;
                    release.scope == self.scope
                        && release.reason
                            == defmi::application_settlement::ApplicationReleaseReason::Expired
                        && release.committee_public.is_empty()
                        && release.signature.is_empty()
                    // The VM, not this ingress or the corporate clock, checks
                    // the actual deadline and current canonical reserve head.
                } else {
                    false
                };
                let write = participant_expiry
                    || (role == PeerRole::Participant
                        && method == "defmivm.issueNoteClaimRedemption")
                    || matches!(role, PeerRole::Coordinator | PeerRole::Settlement)
                        && matches!(
                            method,
                            "defmivm.issueApplicationNoteFill"
                                | "defmivm.issueApplicationNoteFillBatch"
                                | "defmivm.issueApplicationNoteRelease"
                        );
                if !read && !write {
                    return Err("chain method is not authorized at the private ingress".into());
                }
                Ok(match self.client.call(method, params.clone()) {
                    Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                    Err(error) => {
                        json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": error}})
                    }
                })
            }
            _ => Err("private ingress operation is not authorized".into()),
        }
    }
}

pub struct AdmissionRpcServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl AdmissionRpcServer {
    pub fn start(
        address: SocketAddr,
        tls: ServerTlsConfig,
        principals: Vec<Principal>,
        authority: AdmissionAuthority,
    ) -> Result<Self, String> {
        if principals.is_empty() {
            return Err("private ingress requires configured principals".into());
        }
        for principal in &principals {
            principal.validate().map_err(err)?;
        }
        authority.scope.validate()?;
        let listener = TcpListener::bind(address).map_err(err)?;
        let address = listener.local_addr().map_err(err)?;
        listener.set_nonblocking(true).map_err(err)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let authority = Arc::new(Mutex::new(authority));
        let connections = Arc::new(AtomicUsize::new(0));
        let worker = thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopping.load(Ordering::Relaxed) {
                workers.retain(|worker: &JoinHandle<()>| !worker.is_finished());
                match listener.accept() {
                    Ok((stream, _)) => {
                        if connections.load(Ordering::Relaxed) >= 16 {
                            continue;
                        }
                        connections.fetch_add(1, Ordering::Relaxed);
                        let (tls, principals, authority, connections) = (
                            tls.clone(),
                            principals.clone(),
                            Arc::clone(&authority),
                            Arc::clone(&connections),
                        );
                        workers.push(thread::spawn(move || {
                            let _ = serve(stream, tls, &principals, &authority);
                            connections.fetch_sub(1, Ordering::Relaxed);
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            stop,
            worker: Some(worker),
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for AdmissionRpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(
    stream: TcpStream,
    tls: ServerTlsConfig,
    principals: &[Principal],
    authority: &Mutex<AdmissionAuthority>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(err)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(err)?;
    let stream = tls.acceptor.accept(stream).map_err(err)?;
    let peer = stream
        .ssl()
        .peer_certificate()
        .ok_or("private ingress requires a certificate")?;
    let fingerprint = certificate_fingerprint(&peer.to_der().map_err(err)?);
    let principal = principals
        .iter()
        .find(|p| p.certificate_sha256 == fingerprint)
        .ok_or("unknown private ingress principal")?;
    let mut stream = BufReader::new(stream);
    while let Some(line) = read_bounded_request_line(&mut stream)? {
        if line.len() > MAX_PRETRADE_BYTES {
            return Err("private ingress request exceeds its wire bound".into());
        }
        let request: ProofRequest = serde_json::from_slice(&line).map_err(err)?;
        let id = request.id;
        // Serialize chain mutations and their readbacks. Participant funds are
        // never merged with another request or retried with substituted roots.
        let result = authority
            .lock()
            .map_err(|_| "private ingress state is poisoned")?
            .dispatch(principal.role, request);
        let response = match result {
            Ok(value) => ProofResponse {
                id,
                ok: true,
                result: Some(value),
                error: None,
            },
            Err(error) => ProofResponse {
                id,
                ok: false,
                result: None,
                error: Some(error.chars().take(512).collect()),
            },
        };
        stream
            .get_mut()
            .write_all(&encode_bounded_response(&response)?)
            .map_err(err)?;
        stream.get_mut().write_all(b"\n").map_err(err)?;
        stream.get_mut().flush().map_err(err)?;
    }
    Ok(())
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit transport stub only. The native Docker gate uses actual mTLS and
    /// five live validators; this test does not substitute for that evidence.
    #[test]
    fn ingress_allows_exact_pinned_read_method_but_not_governance_or_participant_writes() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let client = AvalancheRpcClient::with_transport(
            "https://unit.invalid/defmi",
            Duration::from_secs(1),
            false,
            move |body, _| {
                let request: Value = serde_json::from_slice(body).map_err(err)?;
                recorded
                    .lock()
                    .unwrap()
                    .push(request["method"].as_str().unwrap().to_owned());
                serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": request["id"], "result": {}}))
                    .map_err(err)
            },
        )
        .unwrap();
        let signer = oclob_core::application_crypto::SigningKey::generate(&mut rand::rngs::OsRng);
        let authority = AdmissionAuthority {
            client,
            authorizer: QuorumAuthorizer::new(
                BTreeMap::from([(
                    "unit".into(),
                    defmi::governance::GovernanceSigner::generate("unit", 0, i64::MAX as u64)
                        .unwrap()
                        .verifying_key(),
                )]),
                1,
                1,
                "unit",
            )
            .unwrap(),
            governance_signers: BTreeMap::new(),
            receipt_issuer: Arc::new(signer.raw_hybrid_signer()),
            private_tag_key: zeroize::Zeroizing::new([81; 32]),
            scope: ApplicationReserveScope {
                application_binding: [1; 32],
                venue_id: [2; 32],
                defmi_id: [3; 32],
                committee_key_digest: [4; 32],
                pq_committee_digest: [231; 32],
                committee_epoch: 1,
                amount_bits: 32,
            },
            eligibility: oclob_dekyx::deterministic_demo_environment("UNIT")
                .unwrap()
                .0,
        };
        let chain = |method| ProofRequest {
            id: 1,
            method: "chain".into(),
            params: json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": {}}),
        };
        assert!(authority
            .dispatch(
                PeerRole::Participant,
                chain("defmivm.applicationNoteReservation")
            )
            .is_ok());
        for method in [
            "defmivm.applicationReservation",
            "defmivm.issueApplicationNoteFill",
            "defmivm.issueApplicationReserveScope",
            "defmivm.issueNote",
        ] {
            assert!(authority
                .dispatch(PeerRole::Participant, chain(method))
                .is_err());
        }
        assert!(authority
            .dispatch(PeerRole::Coordinator, chain("defmivm.issueNote"))
            .is_err());
        for method in [
            "defmivm.issueApplicationNoteFill",
            "defmivm.issueApplicationNoteRelease",
            "defmivm.issueNoteClaimRedemption",
            "defmivm.issueApplicationReserveScope",
        ] {
            assert!(authority
                .dispatch(PeerRole::Operator, chain(method))
                .is_err());
        }
        assert!(authority
            .dispatch(PeerRole::Operator, chain("defmivm.txStatus"))
            .is_ok());
        assert_eq!(
            *seen.lock().unwrap(),
            vec!["defmivm.applicationNoteReservation", "defmivm.txStatus"]
        );
        // Unit authorization boundary only: the real VM must still enforce
        // expiry and canonical head checks, exercised by the native Docker run.
        use defmi::application_settlement::{ApplicationNoteRelease, ApplicationReleaseReason};
        let release = ApplicationNoteRelease {
            scope: authority.scope.clone(),
            before_root: [10; 32],
            operation_id: [11; 32],
            hold_id: [12; 32],
            sequence: 0,
            previous_receipt: [13; 32],
            reason: ApplicationReleaseReason::Expired,
            committee_public: Vec::new(),
            pq_committee: None,
            signature: Vec::new(),
            pq_authorization: None,
        };
        let expiry = |value: &ApplicationNoteRelease| ProofRequest {
            id: 3,
            method: "chain".into(),
            params: json!({"jsonrpc":"2.0", "id":4, "method":"defmivm.issueApplicationNoteRelease", "params":{"release":value}}),
        };
        assert!(authority
            .dispatch(PeerRole::Participant, expiry(&release))
            .is_ok());
        let forwarded = seen.lock().unwrap().len();
        let mut wrong_scope = release.clone();
        wrong_scope.scope.defmi_id = [99; 32];
        let mut cancellation = release.clone();
        cancellation.reason = ApplicationReleaseReason::Cancelled;
        let mut signed_expiry = release.clone();
        signed_expiry.signature = vec![1; 64];
        for invalid in [&wrong_scope, &cancellation, &signed_expiry] {
            assert!(authority
                .dispatch(PeerRole::Participant, expiry(invalid))
                .is_err());
        }
        assert!(authority
            .dispatch(PeerRole::Operator, expiry(&release))
            .is_err());
        assert!(authority
            .dispatch(
                PeerRole::Participant,
                chain("defmivm.issueApplicationNoteRelease")
            )
            .is_err());
        assert_eq!(seen.lock().unwrap().len(), forwarded);
    }
}
