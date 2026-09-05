//! Dedicated, bounded mTLS transport for one node-local proof/FROST party.
//!
//! Proof transcripts are intentionally kept off the fixed-size order RPC.
//! The coordinator exchanges only public proof messages over this listener;
//! the [`ProofParty`] reads its own MP-SPDZ Persistence file inside the node.

use crate::executor::ProofSlotMetadata;
use crate::network::{certificate_fingerprint, ServerTlsConfig};
use oclob_core::{Digest32, MAX_MATCH_SLOTS};
use oclob_mpc::SETTLEMENT_PROOF_WIRES_PER_FILL;
use oclob_settlement::collaborative::collaborative_job_id;
use oclob_settlement::native::{
    NativeFillAuthorizationRequest, NativeFillVerifier, NativeReservationTrust,
};
use qomm_transport::proof_party::{
    encode_bounded_response, read_bounded_request_line, ProofParty, ProofRequest, ProofResponse,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const COLLABORATIVE_FILL_DOMAIN: &[u8] = b"OCLOB:COLLABORATIVE-FILL:v1";
const MAX_METADATA_BYTES: u64 = 16 * 1024;
const MAX_PROOF_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
struct ProofLoadGuard {
    root: PathBuf,
    party: u16,
    receipt_signer: Digest32,
    native_trust: Option<NativeReservationTrust>,
    native_finality: Option<(
        oclob_settlement::pretrade::PrivateAdmissionClient,
        crate::native_finality::NativeFinalityHandle,
    )>,
}

impl ProofLoadGuard {
    fn new(
        root: impl AsRef<Path>,
        party: u16,
        receipt_signer: Digest32,
        native_trust: Option<NativeReservationTrust>,
    ) -> Result<Self, String> {
        let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
        if !root.is_dir() || receipt_signer == [0; 32] {
            return Err("proof persistence root is not a directory".into());
        }
        Ok(Self {
            root,
            party,
            receipt_signer,
            native_trust,
            native_finality: None,
        })
    }

    fn validate(&self, params: &Value) -> Result<ProofSlotMetadata, String> {
        let relative = params
            .get("persistence")
            .and_then(Value::as_str)
            .ok_or_else(|| "persistence must be a relative path".to_owned())?;
        let relative_path = Path::new(relative);
        let components = relative_path.components().collect::<Vec<_>>();
        if relative_path.is_absolute()
            || components.len() != 3
            || components
                .iter()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("proof persistence path is not an OCLOB fill path".into());
        }
        let round_text = components[0]
            .as_os_str()
            .to_str()
            .ok_or_else(|| "proof round path is not UTF-8".to_owned())?;
        let round_id = decode_digest(round_text, "proof round")?;
        if hex::encode(round_id) != round_text {
            return Err("proof round path is not canonical lowercase hexadecimal".into());
        }
        let slot_text = components[1]
            .as_os_str()
            .to_str()
            .and_then(|value| value.strip_prefix("proof-slot-"))
            .ok_or_else(|| "proof slot path is malformed".to_owned())?;
        let slot = slot_text
            .parse::<usize>()
            .map_err(|_| "proof slot path is malformed".to_owned())?;
        if slot >= MAX_MATCH_SLOTS || slot.to_string() != slot_text {
            return Err("proof slot is outside its fixed bound".into());
        }
        let expected_file = format!("Transactions-P{}.data", self.party);
        if components[2].as_os_str() != expected_file.as_str() {
            return Err("proof persistence belongs to another MPC party".into());
        }

        let proof_path = self.root.join(relative_path);
        let canonical_proof = fs::canonicalize(&proof_path).map_err(|error| error.to_string())?;
        if !canonical_proof.starts_with(&self.root) || canonical_proof != proof_path {
            return Err("proof persistence escaped its node-local root".into());
        }
        let proof = read_regular_bounded(&canonical_proof, MAX_PROOF_BYTES)?;
        let metadata_path = canonical_proof
            .parent()
            .ok_or_else(|| "proof persistence has no slot directory".to_owned())?
            .join("metadata.json");
        let metadata_bytes = read_regular_bounded(&metadata_path, MAX_METADATA_BYTES)?;
        let metadata: ProofSlotMetadata = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| "proof slot metadata is invalid".to_owned())?;
        let public_output = decode_param_digest(params, "quote_digest")?;
        let job_id = decode_param_digest(params, "job_id")?;
        let persistence_sha256: Digest32 = Sha256::digest(&proof).into();
        let expected_job: Digest32 = Sha256::new()
            .chain_update(COLLABORATIVE_FILL_DOMAIN)
            .chain_update(round_id)
            .chain_update((slot as u16).to_be_bytes())
            .chain_update(public_output)
            .finalize()
            .into();
        if !matches!(metadata.version, 1 | 2)
            || (metadata.version == 1 && metadata.native_fill.is_some())
            || metadata.party != self.party
            || metadata.round_id != round_id
            || usize::from(metadata.slot) != slot
            || metadata.public_output_sha256 != public_output
            || metadata.public_output_sha256 == [0; 32]
            || metadata.private_state_sha256 == [0; 32]
            || metadata.persistence_sha256 != persistence_sha256
            || metadata.proof_wires != SETTLEMENT_PROOF_WIRES_PER_FILL
            || !metadata.verify_signature(self.receipt_signer)
            || job_id != expected_job
        {
            return Err("proof request does not match the signed MPC execution output".into());
        }
        Ok(metadata)
    }

    fn authorize_native_fill(
        &self,
        params: Value,
        party: &mut ProofParty,
    ) -> Result<Value, String> {
        let trust = self
            .native_trust
            .as_ref()
            .ok_or("native reservation trust is not configured")?;
        let request: NativeFillAuthorizationRequest =
            serde_json::from_value(params).map_err(|_| "native fill request is malformed")?;
        let job = collaborative_job_id(
            request.round_id,
            request.slot,
            request.fill.mpc_result_digest,
        )?;
        let metadata = self.validate(&json!({
            "persistence": format!("{}/proof-slot-{}/Transactions-P{}.data", hex::encode(request.round_id), request.slot, self.party),
            "job_id": hex::encode(job), "quote_digest": hex::encode(request.fill.mpc_result_digest),
        }))?;
        let execution = metadata
            .native_fill
            .as_ref()
            .ok_or("node did not execute this pretrade-reserved matching pair")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch")?
            .as_secs();
        let message = party.authorize_application_statement(
            job,
            &NativeFillVerifier {
                request: &request,
                execution,
                trust,
                now,
            },
        )?;
        Ok(
            json!({"authorized": true, "kind": "oclob-native-note-fill", "message": hex::encode(message)}),
        )
    }

    fn confirm_native_finality(&self, params: Value) -> Result<Value, String> {
        let (client, handle) = self
            .native_finality
            .as_ref()
            .ok_or("node has no configured native canonical reader")?;
        let trust = self
            .native_trust
            .as_ref()
            .ok_or("native reservation trust is not configured")?;
        let request: crate::native_finality::NativeFinalityRequest =
            serde_json::from_value(params).map_err(|_| "native finality request is malformed")?;
        let authorization = &request.authorization;
        let job = collaborative_job_id(
            authorization.round_id,
            authorization.slot,
            authorization.fill.mpc_result_digest,
        )?;
        let metadata = self.validate(&json!({
            "persistence": format!("{}/proof-slot-{}/Transactions-P{}.data", hex::encode(authorization.round_id), authorization.slot, self.party),
            "job_id": hex::encode(job), "quote_digest": hex::encode(authorization.fill.mpc_result_digest),
        }))?;
        let verified = crate::native_finality::observe(client, trust, &request, &metadata)?;
        serde_json::to_value(handle.record(verified)?).map_err(|e| e.to_string())
    }
}

fn decode_param_digest(params: &Value, field: &str) -> Result<Digest32, String> {
    decode_digest(
        params
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{field} must be 32-byte hexadecimal"))?,
        field,
    )
}

fn decode_digest(value: &str, label: &str) -> Result<Digest32, String> {
    hex::decode(value)
        .map_err(|_| format!("{label} must be 32-byte hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{label} must be 32-byte hexadecimal"))
}

fn read_regular_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > max
    {
        return Err("proof persistence is not a bounded regular file".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > max {
        return Err("proof persistence exceeds its fixed bound".into());
    }
    Ok(bytes)
}

pub struct ProofRpcServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

pub struct ProofRpcServerConfig {
    pub address: SocketAddr,
    pub tls: ServerTlsConfig,
    pub coordinator_fingerprint: Digest32,
    pub persistence_root: PathBuf,
    pub expected_party: u16,
    pub expected_receipt_signer: Digest32,
    pub native_trust: Option<NativeReservationTrust>,
    pub native_finality: Option<(
        oclob_settlement::pretrade::PrivateAdmissionClient,
        crate::native_finality::NativeFinalityHandle,
    )>,
    pub max_connections: usize,
    pub timeout: Duration,
}

impl ProofRpcServer {
    pub fn start(config: ProofRpcServerConfig, party: ProofParty) -> Result<Self, String> {
        let ProofRpcServerConfig {
            address,
            tls,
            coordinator_fingerprint,
            persistence_root,
            expected_party,
            expected_receipt_signer,
            native_trust,
            native_finality,
            max_connections,
            timeout,
        } = config;
        if coordinator_fingerprint == [0; 32]
            || max_connections == 0
            || max_connections > 1_024
            || timeout.is_zero()
            || timeout > Duration::from_secs(600)
        {
            return Err("proof RPC configuration is outside its fixed bounds".into());
        }
        let listener = TcpListener::bind(address).map_err(|error| error.to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let active = Arc::new(AtomicUsize::new(0));
        let party = Arc::new(Mutex::new(party));
        let mut guard = ProofLoadGuard::new(
            persistence_root,
            expected_party,
            expected_receipt_signer,
            native_trust,
        )?;
        guard.native_finality = native_finality;
        let guard = Arc::new(guard);
        let handle = thread::Builder::new()
            .name("oclob-proof-listener".into())
            .spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if active.fetch_add(1, Ordering::AcqRel) >= max_connections {
                                active.fetch_sub(1, Ordering::AcqRel);
                                drop(stream);
                                continue;
                            }
                            let active = Arc::clone(&active);
                            let tls = tls.clone();
                            let party = Arc::clone(&party);
                            let guard = Arc::clone(&guard);
                            let _ = thread::Builder::new()
                                .name("oclob-proof-connection".into())
                                .spawn(move || {
                                    if let Err(error) = serve_connection(
                                        stream,
                                        tls,
                                        coordinator_fingerprint,
                                        party,
                                        guard,
                                        timeout,
                                    ) {
                                        eprintln!("OCLOB proof RPC connection failed: {error}");
                                    }
                                    active.fetch_sub(1, Ordering::AcqRel);
                                });
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(25)),
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        Ok(Self {
            address,
            stop,
            handle: Some(handle),
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for ProofRpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_connection(
    stream: TcpStream,
    tls: ServerTlsConfig,
    coordinator_fingerprint: Digest32,
    party: Arc<Mutex<ProofParty>>,
    guard: Arc<ProofLoadGuard>,
    timeout: Duration,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| error.to_string())?;
    let stream = tls
        .acceptor
        .accept(stream)
        .map_err(|error| error.to_string())?;
    let peer = stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| "proof RPC peer omitted its certificate".to_owned())?;
    let peer_der = peer.to_der().map_err(|error| error.to_string())?;
    if certificate_fingerprint(&peer_der) != coordinator_fingerprint {
        return Err("proof RPC rejected a non-coordinator certificate".into());
    }
    let mut stream = BufReader::new(stream);
    loop {
        let Some(line) = read_bounded_request_line(&mut stream)? else {
            return Ok(());
        };
        let request: ProofRequest = serde_json::from_slice(&line)
            .map_err(|_| "proof RPC request is not valid JSON".to_owned())?;
        let response = if request.method == "load" {
            match guard.validate(&request.params) {
                Ok(_) => party
                    .lock()
                    .map_err(|_| "proof-party state lock is poisoned".to_owned())?
                    .handle(request),
                Err(error) => ProofResponse {
                    id: request.id,
                    ok: false,
                    result: None,
                    error: Some(error),
                },
            }
        } else if request.method == "confirm_oclob_native_finality" {
            // Read-only network observation takes no proof-party lock and
            // never authorizes, consumes, or regenerates a FROST nonce.
            match guard.confirm_native_finality(request.params) {
                Ok(result) => ProofResponse {
                    id: request.id,
                    ok: true,
                    result: Some(result),
                    error: None,
                },
                Err(error) => ProofResponse {
                    id: request.id,
                    ok: false,
                    result: None,
                    error: Some(error.chars().take(512).collect()),
                },
            }
        } else if request.method == "authorize_oclob_native_fill" {
            let mut party = party
                .lock()
                .map_err(|_| "proof-party state lock is poisoned".to_owned())?;
            match guard.authorize_native_fill(request.params, &mut party) {
                Ok(result) => ProofResponse {
                    id: request.id,
                    ok: true,
                    result: Some(result),
                    error: None,
                },
                Err(error) => ProofResponse {
                    id: request.id,
                    ok: false,
                    result: None,
                    error: Some(error.chars().take(512).collect()),
                },
            }
        } else {
            party
                .lock()
                .map_err(|_| "proof-party state lock is poisoned".to_owned())?
                .handle(request)
        };
        let encoded = encode_bounded_response(&response)?;
        stream
            .get_mut()
            .write_all(&encoded)
            .and_then(|_| stream.get_mut().write_all(b"\n"))
            .and_then(|_| stream.get_mut().flush())
            .map_err(|error| error.to_string())?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn proof_load_is_bound_to_signed_round_slot_output_and_bytes() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("oclob-proof-guard-{}-{suffix}", std::process::id()));
        let cleanup = TestDirectory(root.clone());
        let party = 2_u16;
        let round_id = [7_u8; 32];
        let public_output = [8_u8; 32];
        let private_state = [9_u8; 32];
        let slot = 0_usize;
        let slot_dir = root
            .join(hex::encode(round_id))
            .join(format!("proof-slot-{slot}"));
        fs::create_dir_all(&slot_dir).unwrap();
        let proof = b"bounded node-local proof shares";
        let proof_path = slot_dir.join(format!("Transactions-P{party}.data"));
        fs::write(&proof_path, proof).unwrap();
        let signing = SigningKey::from_bytes(&[4; 32]);
        let mut metadata = ProofSlotMetadata {
            version: 1,
            party,
            round_id,
            slot: slot as u16,
            public_output_sha256: public_output,
            private_state_sha256: private_state,
            persistence_sha256: Sha256::digest(proof).into(),
            proof_wires: SETTLEMENT_PROOF_WIRES_PER_FILL,
            signer: [0; 32],
            signature: Vec::new(),
            native_fill: None,
        };
        metadata.sign(&signing);
        fs::write(
            slot_dir.join("metadata.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        let job_id: Digest32 = Sha256::new()
            .chain_update(COLLABORATIVE_FILL_DOMAIN)
            .chain_update(round_id)
            .chain_update((slot as u16).to_be_bytes())
            .chain_update(public_output)
            .finalize()
            .into();
        let params = json!({
            "job_id": hex::encode(job_id),
            "persistence": format!(
                "{}/proof-slot-{slot}/Transactions-P{party}.data",
                hex::encode(round_id)
            ),
            "quote_digest": hex::encode(public_output),
        });
        let guard =
            ProofLoadGuard::new(&root, party, signing.verifying_key().to_bytes(), None).unwrap();
        guard.validate(&params).unwrap();

        let mut wrong_output = params.clone();
        wrong_output["quote_digest"] = Value::String(hex::encode([3_u8; 32]));
        assert!(guard.validate(&wrong_output).is_err());
        fs::write(&proof_path, b"tampered shares").unwrap();
        assert!(guard.validate(&params).is_err());

        fs::write(&proof_path, proof).unwrap();
        let binding = oclob_settlement::native::ExecutedReservationBinding {
            order_commitment: [11; 32],
            source_order_commitment: [12; 32],
            admission_digest: [13; 32],
            participant_handle: [14; 32],
            amount_commitment: [15; 32],
            side_commitment: [16; 32],
            valid_until: 2_000,
        };
        metadata.version = 2;
        metadata.native_fill = Some(oclob_settlement::native::NativeFillExecution {
            maker: binding.clone(),
            taker: oclob_settlement::native::ExecutedReservationBinding {
                order_commitment: [17; 32],
                ..binding
            },
            taker_may_close: false,
        });
        metadata.sign(&signing);
        fs::write(
            slot_dir.join("metadata.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        assert!(guard.validate(&params).unwrap().native_fill.is_some());
        metadata.native_fill.as_mut().unwrap().taker_may_close = true;
        fs::write(
            slot_dir.join("metadata.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        assert!(
            guard.validate(&params).is_err(),
            "unsigned closure policy change accepted"
        );
        metadata.sign(&signing);
        fs::write(
            slot_dir.join("metadata.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        assert!(guard.validate(&params).is_ok());
        metadata.version = 1;
        metadata.sign(&signing);
        fs::write(
            slot_dir.join("metadata.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        assert!(
            guard.validate(&params).is_err(),
            "v1 sidecar must not authorize a native fill"
        );
        drop(cleanup);
    }
}
