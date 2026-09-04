//! Fixed-record mutual-TLS RPC for participant-to-party delivery.
//!
//! The transport shape is adapted from the MIT-licensed QOMM resident-node
//! service pinned by this workspace. OCLOB uses its own domain, messages and
//! authorization rules; no QOMM order data crosses this interface.

use crate::executor::{NodeExecutionReceipt, PartyExecutor, RoundPlan};
use crate::{IngestOutcome, NodeShareStore, NodeStoreStatus};
use ed25519_dalek::VerifyingKey;
use oclob_core::Digest32;
use oclob_edge::{EdgeOrderManifest, SealedPartyShare};
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const REQUEST_RECORD_BYTES: usize = 32 * 1024;
pub const RESPONSE_RECORD_BYTES: usize = 16 * 1024;
const REQUEST_MAGIC: &[u8; 8] = b"OCLOBRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"OCLOBRS1";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_BYTES: usize = 8 + 2 + 4 + 32;
const MAX_TLS_KEY_BYTES: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    Participant,
    Coordinator,
    Operator,
}

/// Governance-approved binding between one mTLS certificate and one
/// application signing identity. Certificate rotation creates a new binding;
/// it never silently transfers an application key to another certificate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Principal {
    pub certificate_sha256: Digest32,
    pub role: PeerRole,
    pub application_key: Digest32,
}

impl Principal {
    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.certificate_sha256 == [0; 32] || self.application_key == [0; 32] {
            return Err(NetworkError::Configuration);
        }
        VerifyingKey::from_bytes(&self.application_key)
            .map(|_| ())
            .map_err(|_| NetworkError::Configuration)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum NodeRequest {
    Ingest {
        manifest: Box<EdgeOrderManifest>,
        sealed: SealedPartyShare,
    },
    Execute {
        plan: RoundPlan,
    },
    Status,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum NodeResponse {
    Ingested { party: u16, generation: u64 },
    Executed { receipt: Box<NodeExecutionReceipt> },
    Status { status: NodeStoreStatus },
    Rejected { code: String },
}

#[derive(Clone)]
pub struct ServerTlsConfig {
    acceptor: Arc<SslAcceptor>,
}

#[derive(Clone)]
pub struct ClientTlsConfig {
    connector: Arc<SslConnector>,
}

pub fn server_tls_context(
    certificate: impl AsRef<Path>,
    private_key: impl AsRef<Path>,
    ca: impl AsRef<Path>,
) -> Result<ServerTlsConfig, NetworkError> {
    let private_key = load_owner_private_key(private_key.as_ref())?;
    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_certificate_chain_file(certificate)?;
    builder.set_private_key(&private_key)?;
    builder.set_ca_file(ca)?;
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    builder.check_private_key()?;
    Ok(ServerTlsConfig {
        acceptor: Arc::new(builder.build()),
    })
}

pub fn client_tls_context(
    certificate: impl AsRef<Path>,
    private_key: impl AsRef<Path>,
    ca: impl AsRef<Path>,
) -> Result<ClientTlsConfig, NetworkError> {
    let private_key = load_owner_private_key(private_key.as_ref())?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_certificate_chain_file(certificate)?;
    builder.set_private_key(&private_key)?;
    builder.set_ca_file(ca)?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.check_private_key()?;
    Ok(ClientTlsConfig {
        connector: Arc::new(builder.build()),
    })
}

pub fn certificate_fingerprint(der: &[u8]) -> Digest32 {
    Sha256::digest(der).into()
}

struct NodeRuntime {
    store: Mutex<NodeShareStore>,
    executor: Option<Mutex<PartyExecutor>>,
    execute_lock: Mutex<()>,
}

pub struct NodeRpcServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl NodeRpcServer {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        address: SocketAddr,
        tls: ServerTlsConfig,
        principals: Vec<Principal>,
        store: NodeShareStore,
        executor: Option<PartyExecutor>,
        max_connections: usize,
        timeout: Duration,
        minimum_response_time: Duration,
    ) -> Result<Self, NetworkError> {
        if max_connections == 0
            || max_connections > 1_024
            || timeout.is_zero()
            || timeout > Duration::from_secs(600)
            || minimum_response_time > Duration::from_secs(5)
        {
            return Err(NetworkError::Configuration);
        }
        let mut approved = BTreeMap::new();
        for principal in principals {
            principal.validate()?;
            if approved
                .insert(principal.certificate_sha256, principal)
                .is_some()
            {
                return Err(NetworkError::Configuration);
            }
        }
        if approved.is_empty() {
            return Err(NetworkError::Configuration);
        }
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let runtime = Arc::new(NodeRuntime {
            store: Mutex::new(store),
            executor: executor.map(Mutex::new),
            execute_lock: Mutex::new(()),
        });
        let principals = Arc::new(approved);
        let handle = thread::Builder::new()
            .name("oclob-node-listener".into())
            .spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if active.fetch_add(1, Ordering::AcqRel) >= max_connections {
                                active.fetch_sub(1, Ordering::AcqRel);
                                drop(stream);
                                continue;
                            }
                            let active = active.clone();
                            let tls = tls.clone();
                            let principals = principals.clone();
                            let runtime = runtime.clone();
                            let _ = thread::Builder::new()
                                .name("oclob-node-connection".into())
                                .spawn(move || {
                                    serve_connection(
                                        stream,
                                        tls,
                                        principals,
                                        runtime,
                                        timeout,
                                        minimum_response_time,
                                    );
                                    active.fetch_sub(1, Ordering::AcqRel);
                                });
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(25)),
                    }
                }
            })?;
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

impl Drop for NodeRpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeEndpoint {
    pub party: u16,
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub certificate_sha256: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterNodePublic {
    pub party: u16,
    pub host: String,
    pub rpc_port: u16,
    pub server_name: String,
    pub tls_certificate_sha256: Digest32,
    pub share_encryption_key: oclob_edge::NodeEncryptionKey,
    pub receipt_verifying_key: Digest32,
}

impl ClusterNodePublic {
    pub fn endpoint(&self) -> NodeEndpoint {
        NodeEndpoint {
            party: self.party,
            host: self.host.clone(),
            port: self.rpc_port,
            server_name: self.server_name.clone(),
            certificate_sha256: self.tls_certificate_sha256,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterPublicConfig {
    pub version: u16,
    pub market_id: String,
    pub program: String,
    pub nodes: Vec<ClusterNodePublic>,
}

impl ClusterPublicConfig {
    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.version != 1
            || self.market_id.is_empty()
            || self.market_id.len() > 64
            || self.program.is_empty()
            || self.nodes.len() != oclob_edge::MPC_PARTIES
        {
            return Err(NetworkError::Configuration);
        }
        for (party, node) in self.nodes.iter().enumerate() {
            if usize::from(node.party) != party
                || node.host.is_empty()
                || node.rpc_port == 0
                || node.server_name.is_empty()
                || node.tls_certificate_sha256 == [0; 32]
                || node.share_encryption_key.0 == [0; 32]
                || VerifyingKey::from_bytes(&node.receipt_verifying_key).is_err()
            {
                return Err(NetworkError::Configuration);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientIdentityConfig {
    pub version: u16,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub tls_ca: PathBuf,
    pub application_signing_key: PathBuf,
}

impl ClientIdentityConfig {
    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.version != 1
            || self.tls_certificate.as_os_str().is_empty()
            || self.tls_private_key.as_os_str().is_empty()
            || self.tls_ca.as_os_str().is_empty()
            || self.application_signing_key.as_os_str().is_empty()
        {
            return Err(NetworkError::Configuration);
        }
        Ok(())
    }
}

pub struct NodeRpcClient {
    endpoint: NodeEndpoint,
    tls: ClientTlsConfig,
    timeout: Duration,
}

impl NodeRpcClient {
    pub fn new(
        endpoint: NodeEndpoint,
        tls: ClientTlsConfig,
        timeout: Duration,
    ) -> Result<Self, NetworkError> {
        if usize::from(endpoint.party) >= oclob_edge::MPC_PARTIES
            || endpoint.host.is_empty()
            || endpoint.port == 0
            || endpoint.server_name.is_empty()
            || endpoint.certificate_sha256 == [0; 32]
            || timeout.is_zero()
            || timeout > Duration::from_secs(600)
        {
            return Err(NetworkError::Configuration);
        }
        Ok(Self {
            endpoint,
            tls,
            timeout,
        })
    }

    pub fn ingest(
        &self,
        manifest: EdgeOrderManifest,
        sealed: SealedPartyShare,
    ) -> Result<u64, NetworkError> {
        match self.call(NodeRequest::Ingest {
            manifest: Box::new(manifest),
            sealed,
        })? {
            NodeResponse::Ingested { party, generation } if party == self.endpoint.party => {
                Ok(generation)
            }
            NodeResponse::Rejected { code } => Err(NetworkError::Remote(code)),
            _ => Err(NetworkError::Protocol),
        }
    }

    pub fn execute(&self, plan: RoundPlan) -> Result<NodeExecutionReceipt, NetworkError> {
        match self.call(NodeRequest::Execute { plan })? {
            NodeResponse::Executed { receipt } if receipt.party == self.endpoint.party => {
                Ok(*receipt)
            }
            NodeResponse::Rejected { code } => Err(NetworkError::Remote(code)),
            _ => Err(NetworkError::Protocol),
        }
    }

    pub fn status(&self) -> Result<NodeStoreStatus, NetworkError> {
        match self.call(NodeRequest::Status)? {
            NodeResponse::Status { status } if status.party == self.endpoint.party => Ok(status),
            NodeResponse::Rejected { code } => Err(NetworkError::Remote(code)),
            _ => Err(NetworkError::Protocol),
        }
    }

    fn call(&self, request: NodeRequest) -> Result<NodeResponse, NetworkError> {
        let tcp = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))?;
        tcp.set_read_timeout(Some(self.timeout))?;
        tcp.set_write_timeout(Some(self.timeout))?;
        let mut stream = self
            .tls
            .connector
            .connect(&self.endpoint.server_name, tcp)
            .map_err(|_| NetworkError::TlsHandshake)?;
        let certificate = stream
            .ssl()
            .peer_certificate()
            .ok_or(NetworkError::TlsPeer)?;
        if certificate_fingerprint(&certificate.to_der()?) != self.endpoint.certificate_sha256 {
            return Err(NetworkError::TlsPeer);
        }
        let record = encode_record::<_, REQUEST_RECORD_BYTES>(REQUEST_MAGIC, &request)?;
        stream.write_all(&record)?;
        stream.flush()?;
        let mut response = [0_u8; RESPONSE_RECORD_BYTES];
        stream.read_exact(&mut response)?;
        decode_record(RESPONSE_MAGIC, &response)
    }
}

fn serve_connection(
    stream: TcpStream,
    tls: ServerTlsConfig,
    principals: Arc<BTreeMap<Digest32, Principal>>,
    runtime: Arc<NodeRuntime>,
    timeout: Duration,
    minimum_response_time: Duration,
) {
    let started = Instant::now();
    let result = (|| -> Result<(), NetworkError> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let mut stream = tls
            .acceptor
            .accept(stream)
            .map_err(|_| NetworkError::TlsHandshake)?;
        let certificate = stream
            .ssl()
            .peer_certificate()
            .ok_or(NetworkError::TlsPeer)?;
        let fingerprint = certificate_fingerprint(&certificate.to_der()?);
        let principal = principals
            .get(&fingerprint)
            .ok_or(NetworkError::Unauthorized)?;
        let mut request = [0_u8; REQUEST_RECORD_BYTES];
        stream.read_exact(&mut request)?;
        let request: NodeRequest = decode_record(REQUEST_MAGIC, &request)?;
        let response = dispatch(principal, request, &runtime);
        let elapsed = started.elapsed();
        if elapsed < minimum_response_time {
            thread::sleep(minimum_response_time - elapsed);
        }
        let record = encode_record::<_, RESPONSE_RECORD_BYTES>(RESPONSE_MAGIC, &response)?;
        stream.write_all(&record)?;
        stream.flush()?;
        Ok(())
    })();
    let _ = result;
}

fn dispatch(principal: &Principal, request: NodeRequest, runtime: &NodeRuntime) -> NodeResponse {
    match dispatch_checked(principal, request, runtime) {
        Ok(response) => response,
        Err(error) => NodeResponse::Rejected {
            code: error.public_code().into(),
        },
    }
}

fn dispatch_checked(
    principal: &Principal,
    request: NodeRequest,
    runtime: &NodeRuntime,
) -> Result<NodeResponse, NetworkError> {
    let now = unix_seconds()?;
    match request {
        NodeRequest::Ingest { manifest, sealed } => {
            require_role(principal, PeerRole::Participant)?;
            if manifest.signer != principal.application_key {
                return Err(NetworkError::Unauthorized);
            }
            let mut store = runtime.store.lock().map_err(|_| NetworkError::State)?;
            let outcome = store
                .ingest(*manifest, sealed, now)
                .map_err(|_| NetworkError::Admission)?;
            let status = store.status().map_err(|_| NetworkError::State)?;
            let generation = match outcome {
                IngestOutcome::Stored { generation }
                | IngestOutcome::AlreadyPresent { generation } => generation,
            };
            if generation != status.generation {
                return Err(NetworkError::State);
            }
            Ok(NodeResponse::Ingested {
                party: status.party,
                generation,
            })
        }
        NodeRequest::Execute { plan } => {
            require_role(principal, PeerRole::Coordinator)?;
            plan.verify(now).map_err(|_| NetworkError::Plan)?;
            if plan.coordinator != principal.application_key {
                return Err(NetworkError::Unauthorized);
            }
            let _guard = runtime
                .execute_lock
                .lock()
                .map_err(|_| NetworkError::State)?;
            if let Some(receipt) = runtime
                .store
                .lock()
                .map_err(|_| NetworkError::State)?
                .completed_round(plan.round_id)
            {
                return Ok(NodeResponse::Executed {
                    receipt: Box::new(receipt),
                });
            }
            let prepared = runtime
                .store
                .lock()
                .map_err(|_| NetworkError::State)?
                .prepare_round(&plan.resting, plan.arriving, now)
                .map_err(|_| NetworkError::RoundInput)?;
            let executor = runtime
                .executor
                .as_ref()
                .ok_or(NetworkError::RuntimeDisabled)?;
            let receipt = executor
                .lock()
                .map_err(|_| NetworkError::State)?
                .execute(&prepared, &plan)
                .map_err(|error| {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "mpc_execution_failed",
                            "party": prepared.party(),
                            "round_id": hex::encode(plan.round_id),
                            "error": error.to_string(),
                        })
                    );
                    NetworkError::Execution
                })?;
            runtime
                .store
                .lock()
                .map_err(|_| NetworkError::State)?
                .record_completed_round(receipt.clone())
                .map_err(|_| NetworkError::State)?;
            Ok(NodeResponse::Executed {
                receipt: Box::new(receipt),
            })
        }
        NodeRequest::Status => {
            if !matches!(principal.role, PeerRole::Coordinator | PeerRole::Operator) {
                return Err(NetworkError::Unauthorized);
            }
            let status = runtime
                .store
                .lock()
                .map_err(|_| NetworkError::State)?
                .status()
                .map_err(|_| NetworkError::State)?;
            Ok(NodeResponse::Status { status })
        }
    }
}

fn require_role(principal: &Principal, expected: PeerRole) -> Result<(), NetworkError> {
    if principal.role == expected {
        Ok(())
    } else {
        Err(NetworkError::Unauthorized)
    }
}

fn encode_record<T: Serialize, const N: usize>(
    magic: &[u8; 8],
    message: &T,
) -> Result<[u8; N], NetworkError> {
    let payload = serde_json::to_vec(message).map_err(|_| NetworkError::Protocol)?;
    if N <= RECORD_HEADER_BYTES || payload.len() > N - RECORD_HEADER_BYTES {
        return Err(NetworkError::RecordSize);
    }
    let mut record = [0_u8; N];
    record[..8].copy_from_slice(magic);
    record[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
    record[10..14].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    record[14..46].copy_from_slice(&Sha256::digest(&payload));
    record[46..46 + payload.len()].copy_from_slice(&payload);
    rand::rngs::OsRng.fill_bytes(&mut record[46 + payload.len()..]);
    Ok(record)
}

fn decode_record<T: DeserializeOwned>(magic: &[u8; 8], record: &[u8]) -> Result<T, NetworkError> {
    if record.len() < RECORD_HEADER_BYTES
        || &record[..8] != magic
        || u16::from_be_bytes(
            record[8..10]
                .try_into()
                .map_err(|_| NetworkError::Protocol)?,
        ) != RECORD_VERSION
    {
        return Err(NetworkError::Protocol);
    }
    let length = u32::from_be_bytes(
        record[10..14]
            .try_into()
            .map_err(|_| NetworkError::Protocol)?,
    ) as usize;
    let end = RECORD_HEADER_BYTES
        .checked_add(length)
        .filter(|end| *end <= record.len())
        .ok_or(NetworkError::RecordSize)?;
    let payload = &record[RECORD_HEADER_BYTES..end];
    if &record[14..46] != Sha256::digest(payload).as_slice() {
        return Err(NetworkError::Protocol);
    }
    serde_json::from_slice(payload).map_err(|_| NetworkError::Protocol)
}

fn load_owner_private_key(path: &Path) -> Result<PKey<Private>, NetworkError> {
    let symlink = fs::symlink_metadata(path)?;
    if symlink.file_type().is_symlink() {
        return Err(NetworkError::UnsafeKey);
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_TLS_KEY_BYTES
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(NetworkError::UnsafeKey);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_TLS_KEY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TLS_KEY_BYTES {
        return Err(NetworkError::UnsafeKey);
    }
    PKey::private_key_from_pem(&bytes)
        .or_else(|_| PKey::private_key_from_der(&bytes))
        .map_err(|_| NetworkError::UnsafeKey)
}

/// Load a raw 32-byte application key through the same owner-only file gate
/// used for TLS keys. The bytes are never formatted or returned by an API.
pub fn load_secret_32(path: impl AsRef<Path>) -> Result<Digest32, NetworkError> {
    let path = path.as_ref();
    let symlink = fs::symlink_metadata(path)?;
    if symlink.file_type().is_symlink() {
        return Err(NetworkError::UnsafeKey);
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file()
        || metadata.len() != 32
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(NetworkError::UnsafeKey);
    }
    let mut secret = [0_u8; 32];
    File::open(path)?.read_exact(&mut secret)?;
    Ok(secret)
}

fn unix_seconds() -> Result<u64, NetworkError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| NetworkError::Clock)
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("OCLOB node configuration is invalid")]
    Configuration,
    #[error("TLS private key is not a bounded owner-only regular file")]
    UnsafeKey,
    #[error("mutual TLS handshake failed")]
    TlsHandshake,
    #[error("mutual TLS peer identity is missing or unpinned")]
    TlsPeer,
    #[error("peer is not authorized for this operation")]
    Unauthorized,
    #[error("fixed transport record is invalid")]
    Protocol,
    #[error("message exceeds the fixed transport record")]
    RecordSize,
    #[error("order share admission failed")]
    Admission,
    #[error("round plan is invalid")]
    Plan,
    #[error("round input is not available")]
    RoundInput,
    #[error("party execution is disabled")]
    RuntimeDisabled,
    #[error("party execution failed")]
    Execution,
    #[error("node state is unavailable")]
    State,
    #[error("system clock is invalid")]
    Clock,
    #[error("remote node rejected the request: {0}")]
    Remote(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

impl NetworkError {
    fn public_code(&self) -> &'static str {
        match self {
            Self::Unauthorized | Self::TlsPeer | Self::TlsHandshake => "unauthorized",
            Self::Admission => "admission_rejected",
            Self::Plan => "plan_rejected",
            Self::RoundInput => "round_input_unavailable",
            Self::RuntimeDisabled => "runtime_disabled",
            Self::Execution => "execution_failed",
            Self::State => "state_unavailable",
            Self::Clock => "clock_unavailable",
            Self::RecordSize | Self::Protocol => "invalid_request",
            Self::Configuration
            | Self::UnsafeKey
            | Self::Remote(_)
            | Self::Io(_)
            | Self::OpenSsl(_) => "internal_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use oclob_core::{SecretOrder, Side, TimeInForce};
    use oclob_edge::{EdgeOrderBundle, NodeDecryptionKey, NodeEncryptionKey, MPC_PARTIES};
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509NameBuilder, X509};
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    struct Files {
        root: PathBuf,
        ca: PathBuf,
        server_cert: PathBuf,
        server_key: PathBuf,
        participant_cert: PathBuf,
        participant_key: PathBuf,
        coordinator_cert: PathBuf,
        coordinator_key: PathBuf,
        server_fingerprint: Digest32,
        participant_fingerprint: Digest32,
        coordinator_fingerprint: Digest32,
    }

    impl Drop for Files {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn fixed_records_reject_corruption_and_do_not_expose_length() {
        let request = NodeRequest::Status;
        let mut encoded =
            encode_record::<_, REQUEST_RECORD_BYTES>(REQUEST_MAGIC, &request).unwrap();
        assert_eq!(encoded.len(), REQUEST_RECORD_BYTES);
        let _: NodeRequest = decode_record(REQUEST_MAGIC, &encoded).unwrap();
        encoded[20] ^= 1;
        assert!(decode_record::<NodeRequest>(REQUEST_MAGIC, &encoded).is_err());
    }

    #[test]
    fn participant_delivers_only_one_nodes_ciphertext_over_mutual_tls() {
        let files = tls_files();
        let node_keys: [NodeDecryptionKey; MPC_PARTIES] =
            std::array::from_fn(|_| NodeDecryptionKey::generate().unwrap());
        let public_keys: [NodeEncryptionKey; MPC_PARTIES] =
            std::array::from_fn(|party| node_keys[party].public_key().unwrap());
        let participant_signer = SigningKey::from_bytes(&[7; 32]);
        let coordinator_signer = SigningKey::from_bytes(&[8; 32]);
        let principals = vec![
            Principal {
                certificate_sha256: files.participant_fingerprint,
                role: PeerRole::Participant,
                application_key: participant_signer.verifying_key().to_bytes(),
            },
            Principal {
                certificate_sha256: files.coordinator_fingerprint,
                role: PeerRole::Coordinator,
                application_key: coordinator_signer.verifying_key().to_bytes(),
            },
        ];
        let store_path = files.root.join("shares.bin");
        let store = NodeShareStore::open(&store_path, 0, node_keys[0].clone()).unwrap();
        let server = NodeRpcServer::start(
            "127.0.0.1:0".parse().unwrap(),
            server_tls_context(&files.server_cert, &files.server_key, &files.ca).unwrap(),
            principals,
            store,
            None,
            8,
            Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .unwrap();
        let endpoint = NodeEndpoint {
            party: 0,
            host: "127.0.0.1".into(),
            port: server.address().port(),
            server_name: "localhost".into(),
            certificate_sha256: files.server_fingerprint,
        };
        let participant = NodeRpcClient::new(
            endpoint.clone(),
            client_tls_context(&files.participant_cert, &files.participant_key, &files.ca).unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();
        let coordinator = NodeRpcClient::new(
            endpoint,
            client_tls_context(&files.coordinator_cert, &files.coordinator_key, &files.ca).unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();
        let order = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            100,
            40,
            TimeInForce::GoodTilCancelled,
            2_000_000_000,
            [1; 32],
            [2; 32],
            [3; 32],
        )
        .unwrap();
        let bundle = EdgeOrderBundle::create(
            &order,
            [4; 32],
            [5; 32],
            &participant_signer,
            &public_keys,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let manifest = bundle.manifest().clone();
        let delivery = bundle.into_deliveries()[0].1.clone();
        assert_eq!(
            participant
                .ingest(manifest.clone(), delivery.clone())
                .unwrap(),
            1
        );
        assert_eq!(participant.ingest(manifest, delivery).unwrap(), 1);
        assert_eq!(coordinator.status().unwrap().record_count, 1);
        assert!(participant.status().is_err());
    }

    fn tls_files() -> Files {
        let root = std::env::temp_dir().join(format!(
            "oclob-node-tls-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&root).unwrap();
        let (ca_key, ca_cert) = make_ca();
        let (server_key, server_cert) = make_leaf(&ca_key, &ca_cert, "localhost", true);
        let (participant_key, participant_cert) =
            make_leaf(&ca_key, &ca_cert, "participant", false);
        let (coordinator_key, coordinator_cert) =
            make_leaf(&ca_key, &ca_cert, "coordinator", false);
        let ca = root.join("ca.pem");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server-key.pem");
        let participant_cert_path = root.join("participant.pem");
        let participant_key_path = root.join("participant-key.pem");
        let coordinator_cert_path = root.join("coordinator.pem");
        let coordinator_key_path = root.join("coordinator-key.pem");
        fs::write(&ca, ca_cert.to_pem().unwrap()).unwrap();
        write_private(&server_key_path, &server_key);
        fs::write(&server_cert_path, server_cert.to_pem().unwrap()).unwrap();
        write_private(&participant_key_path, &participant_key);
        fs::write(&participant_cert_path, participant_cert.to_pem().unwrap()).unwrap();
        write_private(&coordinator_key_path, &coordinator_key);
        fs::write(&coordinator_cert_path, coordinator_cert.to_pem().unwrap()).unwrap();
        Files {
            root,
            ca,
            server_cert: server_cert_path,
            server_key: server_key_path,
            participant_cert: participant_cert_path,
            participant_key: participant_key_path,
            coordinator_cert: coordinator_cert_path,
            coordinator_key: coordinator_key_path,
            server_fingerprint: certificate_fingerprint(&server_cert.to_der().unwrap()),
            participant_fingerprint: certificate_fingerprint(&participant_cert.to_der().unwrap()),
            coordinator_fingerprint: certificate_fingerprint(&coordinator_cert.to_der().unwrap()),
        }
    }

    fn write_private(path: &Path, key: &PKey<Private>) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&key.private_key_to_pem_pkcs8().unwrap())
            .unwrap();
    }

    fn make_ca() -> (PKey<Private>, X509) {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "OCLOB test CA")
            .unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        set_serial(&mut builder);
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(&key, MessageDigest::null()).unwrap();
        (key, builder.build())
    }

    fn make_leaf(
        ca_key: &PKey<Private>,
        ca_cert: &X509,
        name: &str,
        server: bool,
    ) -> (PKey<Private>, X509) {
        let key = PKey::generate_ed25519().unwrap();
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_nid(Nid::COMMONNAME, name).unwrap();
        let subject = subject.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        set_serial(&mut builder);
        builder.set_subject_name(&subject).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let extension = if server {
            ExtendedKeyUsage::new()
                .server_auth()
                .client_auth()
                .build()
                .unwrap()
        } else {
            ExtendedKeyUsage::new().client_auth().build().unwrap()
        };
        builder.append_extension(extension).unwrap();
        if server {
            let san = SubjectAlternativeName::new()
                .dns("localhost")
                .ip("127.0.0.1")
                .build(&builder.x509v3_context(Some(ca_cert), None))
                .unwrap();
            builder.append_extension(san).unwrap();
        }
        builder.sign(ca_key, MessageDigest::null()).unwrap();
        (key, builder.build())
    }

    fn set_serial(builder: &mut openssl::x509::X509Builder) {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
    }
}
