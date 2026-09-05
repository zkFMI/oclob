//! Fixed-record mutual-TLS RPC for participant-to-party delivery.
//!
//! The transport shape is adapted from the MIT-licensed QOMM resident-node
//! service pinned by this workspace. OCLOB uses its own domain, messages and
//! authorization rules; no QOMM order data crosses this interface.

use crate::executor::{NodeExecutionReceipt, PartyExecutor, RoundPlan};
use crate::{IngestOutcome, NodeShareStore, NodeStoreStatus, PrivateStateFinality};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{Digest32, OrderCommitment};
use oclob_edge::{
    CapabilityKeyShare, EdgeOrderManifest, SealedCapabilityKeyShare, SealedPartyShare,
};
use oclob_ordering::{vote_digest, CommitteePolicy, OrderVote};
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

pub const REQUEST_RECORD_BYTES: usize = 64 * 1024;
pub const RESPONSE_RECORD_BYTES: usize = 16 * 1024;
const REQUEST_MAGIC: &[u8; 8] = b"OCLOBRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"OCLOBRS1";
const ADMISSION_RECEIPT_DOMAIN: &[u8] = b"OCLOB:NODE-ADMISSION-RECEIPT:v1";
const CAPABILITY_RELEASE_DOMAIN: &[u8] = b"OCLOB:NODE-CAPABILITY-RELEASE:v1";
const PRIVATE_STATE_RECEIPT_DOMAIN: &[u8] = b"OCLOB:NODE-PRIVATE-STATE-RECEIPT:v1";
const RECORD_VERSION: u16 = 3;
const RECORD_HEADER_BYTES: usize = 8 + 2 + 4 + 32;
const MAX_TLS_KEY_BYTES: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    Participant,
    Coordinator,
    Settlement,
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
        sealed_capability_key_share: SealedCapabilityKeyShare,
    },
    Vote {
        market_id: String,
        sequence: u64,
        commitment: OrderCommitment,
        previous_certificate: Digest32,
        expires_at: u64,
    },
    Execute {
        plan: RoundPlan,
    },
    Release {
        plan: Box<RoundPlan>,
        order_commitment: OrderCommitment,
    },
    FinalizePrivateState {
        plan: Box<RoundPlan>,
        finality: PrivateStateFinality,
    },
    Status,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum NodeResponse {
    Ingested {
        receipt: Box<NodeAdmissionReceipt>,
    },
    Voted {
        vote: OrderVote,
    },
    Executed {
        receipt: Box<NodeExecutionReceipt>,
    },
    Released {
        release: Box<NodeCapabilityRelease>,
    },
    PrivateStateFinalized {
        receipt: Box<NodePrivateStateReceipt>,
    },
    Status {
        status: NodeStoreStatus,
    },
    Rejected {
        code: String,
    },
}

/// Durable proof that one authenticated node accepted one participant-signed
/// manifest into a specific persistent-store generation.  TLS authenticates
/// the live channel; this signature keeps the acknowledgement verifiable after
/// the connection and participant process have gone away.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeAdmissionReceipt {
    pub version: u16,
    pub party: u16,
    pub order_commitment: OrderCommitment,
    pub manifest_signer: Digest32,
    pub order_share_digest: Digest32,
    pub capability_key_share_digest: Digest32,
    pub generation: u64,
    pub state_digest: Digest32,
    pub signer: Digest32,
    pub signature: Vec<u8>,
}

impl NodeAdmissionReceipt {
    fn sign(
        party: u16,
        manifest: &EdgeOrderManifest,
        order_share_digest: Digest32,
        capability_key_share_digest: Digest32,
        generation: u64,
        state_digest: Digest32,
        key: &SigningKey,
    ) -> Result<Self, NetworkError> {
        if usize::from(party) >= oclob_edge::MPC_PARTIES
            || generation == 0
            || state_digest == [0; 32]
            || order_share_digest == [0; 32]
            || capability_key_share_digest == [0; 32]
        {
            return Err(NetworkError::State);
        }
        let mut receipt = Self {
            version: RECORD_VERSION,
            party,
            order_commitment: manifest.commitment,
            manifest_signer: manifest.signer,
            order_share_digest,
            capability_key_share_digest,
            generation,
            state_digest,
            signer: key.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        receipt.signature = key.sign(&receipt.signature_body()).to_bytes().to_vec();
        Ok(receipt)
    }

    pub fn verify(
        &self,
        manifest: &EdgeOrderManifest,
        expected_party: u16,
        expected_order_share_digest: Digest32,
        expected_capability_key_share_digest: Digest32,
        expected_signer: &VerifyingKey,
    ) -> Result<(), NetworkError> {
        if self.version != RECORD_VERSION
            || self.party != expected_party
            || usize::from(self.party) >= oclob_edge::MPC_PARTIES
            || self.order_commitment != manifest.commitment
            || self.manifest_signer != manifest.signer
            || self.order_share_digest != expected_order_share_digest
            || self.capability_key_share_digest != expected_capability_key_share_digest
            || self.order_share_digest == [0; 32]
            || self.capability_key_share_digest == [0; 32]
            || self.generation == 0
            || self.state_digest == [0; 32]
            || self.signer != expected_signer.to_bytes()
        {
            return Err(NetworkError::Protocol);
        }
        let signature =
            Signature::try_from(self.signature.as_slice()).map_err(|_| NetworkError::Protocol)?;
        expected_signer
            .verify_strict(&self.signature_body(), &signature)
            .map_err(|_| NetworkError::Protocol)
    }

    fn signature_body(&self) -> Vec<u8> {
        [
            ADMISSION_RECEIPT_DOMAIN,
            &self.version.to_be_bytes(),
            &self.party.to_be_bytes(),
            &self.order_commitment.0,
            &self.manifest_signer,
            &self.order_share_digest,
            &self.capability_key_share_digest,
            &self.generation.to_be_bytes(),
            &self.state_digest,
            &self.signer,
        ]
        .concat()
    }
}

/// Sensitive fixed-record response released by one node only after its local
/// durable MPC receipt authorizes this order. The key share is never included
/// in logs or public acceptance artifacts; `Debug` deliberately redacts it.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeCapabilityRelease {
    pub version: u16,
    pub party: u16,
    pub order_commitment: OrderCommitment,
    pub round_id: Digest32,
    pub public_output_sha256: Digest32,
    pub capability_key_share: CapabilityKeyShare,
    pub signer: Digest32,
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for NodeCapabilityRelease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeCapabilityRelease")
            .field("party", &self.party)
            .field("order_commitment", &self.order_commitment.hex())
            .field("round_id", &hex::encode(self.round_id))
            .field("capability_key_share", &"[redacted]")
            .finish()
    }
}

impl NodeCapabilityRelease {
    fn sign(
        party: u16,
        order_commitment: OrderCommitment,
        plan: &RoundPlan,
        public_output_sha256: Digest32,
        capability_key_share: CapabilityKeyShare,
        key: &SigningKey,
    ) -> Result<Self, NetworkError> {
        if usize::from(party) >= oclob_edge::MPC_PARTIES
            || capability_key_share.party() != party
            || capability_key_share.order_commitment() != order_commitment
            || public_output_sha256 == [0; 32]
        {
            return Err(NetworkError::State);
        }
        let mut release = Self {
            version: RECORD_VERSION,
            party,
            order_commitment,
            round_id: plan.round_id,
            public_output_sha256,
            capability_key_share,
            signer: key.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        release.signature = key.sign(&release.signature_body()).to_bytes().to_vec();
        Ok(release)
    }

    pub fn verify(
        &self,
        manifest: &EdgeOrderManifest,
        plan: &RoundPlan,
        expected_output: Digest32,
        expected_party: u16,
        expected_signer: &VerifyingKey,
        now: u64,
    ) -> Result<(), NetworkError> {
        if self.version != RECORD_VERSION
            || self.party != expected_party
            || self.order_commitment != manifest.commitment
            || self.round_id != plan.round_id
            || self.public_output_sha256 != expected_output
            || self.public_output_sha256 == [0; 32]
            || self.signer != expected_signer.to_bytes()
        {
            return Err(NetworkError::Protocol);
        }
        self.capability_key_share
            .verify(manifest, expected_party, now)
            .map_err(|_| NetworkError::Protocol)?;
        let signature =
            Signature::try_from(self.signature.as_slice()).map_err(|_| NetworkError::Protocol)?;
        expected_signer
            .verify_strict(&self.signature_body(), &signature)
            .map_err(|_| NetworkError::Protocol)
    }

    fn signature_body(&self) -> Vec<u8> {
        [
            CAPABILITY_RELEASE_DOMAIN,
            &self.version.to_be_bytes(),
            &self.party.to_be_bytes(),
            &self.order_commitment.0,
            &self.round_id,
            &self.public_output_sha256,
            &self.capability_key_share.wire_digest(),
            &self.signer,
        ]
        .concat()
    }
}

/// Signed evidence that one MPC node advanced its local secret-share head only
/// after the exact public match transition reached canonical DeFMI finality.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodePrivateStateReceipt {
    pub version: u16,
    pub party: u16,
    pub round_id: Digest32,
    pub private_state_sha256: Digest32,
    pub transition_digest: Digest32,
    pub canonical_receipt_digest: Digest32,
    pub canonical_height: u64,
    pub generation: u64,
    pub state_digest: Digest32,
    pub signer: Digest32,
    pub signature: Vec<u8>,
}

impl NodePrivateStateReceipt {
    #[allow(clippy::too_many_arguments)]
    fn sign(
        party: u16,
        execution: &NodeExecutionReceipt,
        finality: &PrivateStateFinality,
        generation: u64,
        state_digest: Digest32,
        key: &SigningKey,
    ) -> Result<Self, NetworkError> {
        if execution.party != party
            || execution.round_id != finality.round_id
            || execution.public_output_sha256 != finality.public_output_sha256
            || execution.private_state_sha256 == [0; 32]
            || finality.transition_digest == [0; 32]
            || finality.canonical_receipt_digest == [0; 32]
            || finality.canonical_height == 0
            || generation == 0
            || state_digest == [0; 32]
        {
            return Err(NetworkError::State);
        }
        let mut receipt = Self {
            version: RECORD_VERSION,
            party,
            round_id: finality.round_id,
            private_state_sha256: execution.private_state_sha256,
            transition_digest: finality.transition_digest,
            canonical_receipt_digest: finality.canonical_receipt_digest,
            canonical_height: finality.canonical_height,
            generation,
            state_digest,
            signer: key.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        receipt.signature = key.sign(&receipt.signature_body()).to_bytes().to_vec();
        Ok(receipt)
    }

    pub fn verify(
        &self,
        execution: &NodeExecutionReceipt,
        finality: &PrivateStateFinality,
        expected_party: u16,
        expected_signer: &VerifyingKey,
    ) -> Result<(), NetworkError> {
        if self.version != RECORD_VERSION
            || self.party != expected_party
            || self.round_id != finality.round_id
            || self.round_id != execution.round_id
            || self.private_state_sha256 != execution.private_state_sha256
            || self.transition_digest != finality.transition_digest
            || self.canonical_receipt_digest != finality.canonical_receipt_digest
            || self.canonical_height != finality.canonical_height
            || execution.public_output_sha256 != finality.public_output_sha256
            || self.generation == 0
            || self.state_digest == [0; 32]
            || self.signer != expected_signer.to_bytes()
        {
            return Err(NetworkError::Protocol);
        }
        let signature =
            Signature::try_from(self.signature.as_slice()).map_err(|_| NetworkError::Protocol)?;
        expected_signer
            .verify_strict(&self.signature_body(), &signature)
            .map_err(|_| NetworkError::Protocol)
    }

    fn signature_body(&self) -> Vec<u8> {
        [
            PRIVATE_STATE_RECEIPT_DOMAIN,
            &self.version.to_be_bytes(),
            &self.party.to_be_bytes(),
            &self.round_id,
            &self.private_state_sha256,
            &self.transition_digest,
            &self.canonical_receipt_digest,
            &self.canonical_height.to_be_bytes(),
            &self.generation.to_be_bytes(),
            &self.state_digest,
            &self.signer,
        ]
        .concat()
    }
}

#[derive(Clone)]
pub struct ServerTlsConfig {
    pub(crate) acceptor: Arc<SslAcceptor>,
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
    store: Arc<Mutex<NodeShareStore>>,
    receipt_signing_key: SigningKey,
    ordering_policy: CommitteePolicy,
    ordering_keys: BTreeMap<u16, VerifyingKey>,
    executor: Option<Mutex<PartyExecutor>>,
    execute_lock: Mutex<()>,
}

pub struct NodeRpcServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    native_finality: crate::native_finality::NativeFinalityHandle,
}

impl NodeRpcServer {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        address: SocketAddr,
        tls: ServerTlsConfig,
        principals: Vec<Principal>,
        store: NodeShareStore,
        receipt_signing_key: SigningKey,
        ordering_policy: CommitteePolicy,
        ordering_keys: BTreeMap<u16, VerifyingKey>,
        executor: Option<PartyExecutor>,
        max_connections: usize,
        timeout: Duration,
        minimum_response_time: Duration,
    ) -> Result<Self, NetworkError> {
        ordering_policy
            .validate()
            .map_err(|_| NetworkError::Configuration)?;
        let mut store = store;
        if let Some(executor) = executor.as_ref() {
            store
                .bind_private_state_root(executor.private_state_root())
                .map_err(|_| NetworkError::Configuration)?;
        }
        let party = store.status().map_err(|_| NetworkError::State)?.party;
        let node_id = party.checked_add(1).ok_or(NetworkError::Configuration)?;
        if max_connections == 0
            || max_connections > 1_024
            || timeout.is_zero()
            || timeout > Duration::from_secs(600)
            || minimum_response_time > Duration::from_secs(5)
            || ordering_keys.len() != ordering_policy.nodes
            || (1..=ordering_policy.nodes).any(|id| !ordering_keys.contains_key(&(id as u16)))
            || ordering_keys.get(&node_id) != Some(&receipt_signing_key.verifying_key())
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
        let store = Arc::new(Mutex::new(store));
        let native_finality = crate::native_finality::NativeFinalityHandle::new(Arc::clone(&store));
        let runtime = Arc::new(NodeRuntime {
            store,
            receipt_signing_key,
            ordering_policy,
            ordering_keys,
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
            native_finality,
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn native_finality_handle(&self) -> crate::native_finality::NativeFinalityHandle {
        self.native_finality.clone()
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
    pub receipt_verifying_key: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterNodePublic {
    pub party: u16,
    pub host: String,
    pub rpc_port: u16,
    pub proof_port: u16,
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
            receipt_verifying_key: self.receipt_verifying_key,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterPublicConfig {
    pub version: u16,
    pub market_id: String,
    pub program: String,
    pub settlement_release_threshold: usize,
    pub nodes: Vec<ClusterNodePublic>,
}

impl ClusterPublicConfig {
    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.version != 3
            || self.market_id.is_empty()
            || self.market_id.len() > 64
            || self.program.is_empty()
            || self.settlement_release_threshold != oclob_edge::SETTLEMENT_KEY_THRESHOLD
            || self.nodes.len() != oclob_edge::MPC_PARTIES
        {
            return Err(NetworkError::Configuration);
        }
        for (party, node) in self.nodes.iter().enumerate() {
            if usize::from(node.party) != party
                || node.host.is_empty()
                || node.rpc_port == 0
                || node.proof_port == 0
                || node.server_name.is_empty()
                || node.tls_certificate_sha256 == [0; 32]
                || node.share_encryption_key.0 == [0; 32]
                || VerifyingKey::from_bytes(&node.receipt_verifying_key).is_err()
            {
                return Err(NetworkError::Configuration);
            }
        }
        let unique_keys = self
            .nodes
            .iter()
            .map(|node| node.receipt_verifying_key)
            .collect::<std::collections::BTreeSet<_>>();
        if unique_keys.len() != self.nodes.len() {
            return Err(NetworkError::Configuration);
        }
        Ok(())
    }

    /// Ordering node identifiers are 1..=7, whereas MP-SPDZ party identifiers
    /// are 0..=6. The already pinned node receipt key signs ordering votes over
    /// a separate domain-separated statement.
    pub fn ordering_verifying_keys(&self) -> Result<BTreeMap<u16, VerifyingKey>, NetworkError> {
        self.validate()?;
        self.nodes
            .iter()
            .map(|node| {
                let node_id = node
                    .party
                    .checked_add(1)
                    .ok_or(NetworkError::Configuration)?;
                let key = VerifyingKey::from_bytes(&node.receipt_verifying_key)
                    .map_err(|_| NetworkError::Configuration)?;
                Ok((node_id, key))
            })
            .collect()
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
            || VerifyingKey::from_bytes(&endpoint.receipt_verifying_key).is_err()
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
        sealed_capability_key_share: SealedCapabilityKeyShare,
    ) -> Result<NodeAdmissionReceipt, NetworkError> {
        let expected_manifest = manifest.clone();
        let expected_order_share_digest = sealed.wire_digest();
        let expected_capability_key_share_digest = sealed_capability_key_share.wire_digest();
        match self.call(NodeRequest::Ingest {
            manifest: Box::new(manifest),
            sealed,
            sealed_capability_key_share,
        })? {
            NodeResponse::Ingested { receipt } if receipt.party == self.endpoint.party => {
                receipt.verify(
                    &expected_manifest,
                    self.endpoint.party,
                    expected_order_share_digest,
                    expected_capability_key_share_digest,
                    &VerifyingKey::from_bytes(&self.endpoint.receipt_verifying_key)
                        .map_err(|_| NetworkError::Protocol)?,
                )?;
                Ok(*receipt)
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

    pub fn release_capability_key_share(
        &self,
        manifest: &EdgeOrderManifest,
        plan: RoundPlan,
        order_commitment: OrderCommitment,
        expected_output: Digest32,
        now: u64,
    ) -> Result<NodeCapabilityRelease, NetworkError> {
        match self.call(NodeRequest::Release {
            plan: Box::new(plan.clone()),
            order_commitment,
        })? {
            NodeResponse::Released { release } if release.party == self.endpoint.party => {
                release.verify(
                    manifest,
                    &plan,
                    expected_output,
                    self.endpoint.party,
                    &VerifyingKey::from_bytes(&self.endpoint.receipt_verifying_key)
                        .map_err(|_| NetworkError::Protocol)?,
                    now,
                )?;
                Ok(*release)
            }
            NodeResponse::Rejected { code } => Err(NetworkError::Remote(code)),
            _ => Err(NetworkError::Protocol),
        }
    }

    pub fn finalize_private_state(
        &self,
        plan: RoundPlan,
        finality: PrivateStateFinality,
        execution: &NodeExecutionReceipt,
    ) -> Result<NodePrivateStateReceipt, NetworkError> {
        match self.call(NodeRequest::FinalizePrivateState {
            plan: Box::new(plan),
            finality: finality.clone(),
        })? {
            NodeResponse::PrivateStateFinalized { receipt }
                if receipt.party == self.endpoint.party =>
            {
                receipt.verify(
                    execution,
                    &finality,
                    self.endpoint.party,
                    &VerifyingKey::from_bytes(&self.endpoint.receipt_verifying_key)
                        .map_err(|_| NetworkError::Protocol)?,
                )?;
                Ok(*receipt)
            }
            NodeResponse::Rejected { code } => Err(NetworkError::Remote(code)),
            _ => Err(NetworkError::Protocol),
        }
    }

    pub fn vote(
        &self,
        market_id: &str,
        sequence: u64,
        commitment: OrderCommitment,
        previous_certificate: Digest32,
        expires_at: u64,
    ) -> Result<OrderVote, NetworkError> {
        let expected = vote_digest(
            market_id,
            sequence,
            commitment,
            previous_certificate,
            expires_at,
        );
        match self.call(NodeRequest::Vote {
            market_id: market_id.to_owned(),
            sequence,
            commitment,
            previous_certificate,
            expires_at,
        })? {
            NodeResponse::Voted { vote }
                if vote.node_id == self.endpoint.party.saturating_add(1)
                    && vote.statement_digest == expected =>
            {
                let signature = Signature::try_from(vote.signature.as_slice())
                    .map_err(|_| NetworkError::Protocol)?;
                VerifyingKey::from_bytes(&self.endpoint.receipt_verifying_key)
                    .map_err(|_| NetworkError::Protocol)?
                    .verify_strict(&expected, &signature)
                    .map_err(|_| NetworkError::Protocol)?;
                Ok(vote)
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
        NodeRequest::Ingest {
            manifest,
            sealed,
            sealed_capability_key_share,
        } => {
            require_role(principal, PeerRole::Participant)?;
            let manifest = *manifest;
            let order_share_digest = sealed.wire_digest();
            let capability_key_share_digest = sealed_capability_key_share.wire_digest();
            let (generation, status) = {
                let mut store = runtime.store.lock().map_err(|_| NetworkError::State)?;
                let outcome = store
                    .ingest(manifest.clone(), sealed, sealed_capability_key_share, now)
                    .map_err(|_| NetworkError::Admission)?;
                let status = store.status().map_err(|_| NetworkError::State)?;
                let generation = match outcome {
                    IngestOutcome::Stored { generation }
                    | IngestOutcome::AlreadyPresent { generation } => generation,
                };
                (generation, status)
            };
            if generation != status.generation {
                return Err(NetworkError::State);
            }
            let receipt = NodeAdmissionReceipt::sign(
                status.party,
                &manifest,
                order_share_digest,
                capability_key_share_digest,
                generation,
                status.state_digest,
                &runtime.receipt_signing_key,
            )?;
            Ok(NodeResponse::Ingested {
                receipt: Box::new(receipt),
            })
        }
        NodeRequest::Vote {
            market_id,
            sequence,
            commitment,
            previous_certificate,
            expires_at,
        } => {
            require_role(principal, PeerRole::Coordinator)?;
            let (statement_digest, node_id) = {
                let mut store = runtime.store.lock().map_err(|_| NetworkError::State)?;
                let statement_digest = store
                    .record_order_vote(
                        &market_id,
                        sequence,
                        commitment,
                        previous_certificate,
                        expires_at,
                        now,
                    )
                    .map_err(|_| NetworkError::Ordering)?;
                let node_id = store
                    .status()
                    .map_err(|_| NetworkError::State)?
                    .party
                    .checked_add(1)
                    .ok_or(NetworkError::State)?;
                (statement_digest, node_id)
            };
            Ok(NodeResponse::Voted {
                vote: OrderVote {
                    node_id,
                    statement_digest,
                    signature: runtime
                        .receipt_signing_key
                        .sign(&statement_digest)
                        .to_bytes()
                        .to_vec(),
                },
            })
        }
        NodeRequest::Execute { plan } => {
            require_role(principal, PeerRole::Coordinator)?;
            plan.verify_ordering(runtime.ordering_policy, &runtime.ordering_keys, now)
                .map_err(|_| NetworkError::Plan)?;
            if plan.coordinator != principal.application_key {
                return Err(NetworkError::Unauthorized);
            }
            let _guard = runtime
                .execute_lock
                .lock()
                .map_err(|_| NetworkError::State)?;
            runtime
                .store
                .lock()
                .map_err(|_| NetworkError::State)?
                .accept_order_certificate(
                    &plan.ordering_certificate,
                    runtime.ordering_policy,
                    &runtime.ordering_keys,
                    now,
                )
                .map_err(|_| NetworkError::Ordering)?;
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
                .prepare_round(&plan.market_id, &plan.resting, plan.arriving, now)
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
        NodeRequest::Release {
            plan,
            order_commitment,
        } => {
            require_role(principal, PeerRole::Settlement)?;
            let plan = *plan;
            plan.verify_ordering(runtime.ordering_policy, &runtime.ordering_keys, now)
                .map_err(|_| NetworkError::Plan)?;
            let (party, capability_key_share, public_output_sha256) = {
                let store = runtime.store.lock().map_err(|_| NetworkError::State)?;
                let party = store.status().map_err(|_| NetworkError::State)?.party;
                let (share, output) = store
                    .release_capability_key_share(&plan, order_commitment, now)
                    .map_err(|_| NetworkError::Release)?;
                (party, share, output)
            };
            let release = NodeCapabilityRelease::sign(
                party,
                order_commitment,
                &plan,
                public_output_sha256,
                capability_key_share,
                &runtime.receipt_signing_key,
            )?;
            Ok(NodeResponse::Released {
                release: Box::new(release),
            })
        }
        NodeRequest::FinalizePrivateState { plan, finality } => {
            require_role(principal, PeerRole::Settlement)?;
            let plan = *plan;
            plan.verify_ordering(runtime.ordering_policy, &runtime.ordering_keys, now)
                .map_err(|_| NetworkError::Plan)?;
            let (execution, generation, status) = {
                let mut store = runtime.store.lock().map_err(|_| NetworkError::State)?;
                let execution = store
                    .completed_round(plan.round_id)
                    .ok_or(NetworkError::Execution)?;
                let generation = store
                    .finalize_private_round(&plan, &finality)
                    .map_err(|_| NetworkError::State)?;
                let status = store.status().map_err(|_| NetworkError::State)?;
                (execution, generation, status)
            };
            if generation != status.generation {
                return Err(NetworkError::State);
            }
            let receipt = NodePrivateStateReceipt::sign(
                status.party,
                &execution,
                &finality,
                generation,
                status.state_digest,
                &runtime.receipt_signing_key,
            )?;
            Ok(NodeResponse::PrivateStateFinalized {
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
    #[error("ordering vote or certificate was rejected")]
    Ordering,
    #[error("round input is not available")]
    RoundInput,
    #[error("party execution is disabled")]
    RuntimeDisabled,
    #[error("party execution failed")]
    Execution,
    #[error("settlement capability release is not authorized")]
    Release,
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
            Self::Ordering => "ordering_rejected",
            Self::RoundInput => "round_input_unavailable",
            Self::RuntimeDisabled => "runtime_disabled",
            Self::Execution => "execution_failed",
            Self::Release => "capability_release_rejected",
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
    use oclob_core::{
        MpcBatchResult, MpcSlotResult, SecretOrder, Side, TimeInForce, MAX_MATCH_SLOTS,
    };
    use oclob_edge::{EdgeOrderBundle, NodeDecryptionKey, NodeEncryptionKey, MPC_PARTIES};
    use oclob_mpc::public_output_digest;
    use oclob_ordering::OrderingCommittee;
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
        settlement_cert: PathBuf,
        settlement_key: PathBuf,
        server_fingerprint: Digest32,
        participant_fingerprint: Digest32,
        coordinator_fingerprint: Digest32,
        settlement_fingerprint: Digest32,
    }

    impl Drop for Files {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Transport-only peer: real mutual TLS and the pinned bounded codec,
    /// but no financial state machine. Native Docker acceptance separately
    /// verifies the actual DeFMI reads/writes and validator state.
    fn private_admission_exchange_peer(
        files: &Files,
        replies: Vec<Option<serde_json::Value>>,
    ) -> (
        SocketAddr,
        JoinHandle<Vec<qomm_transport::proof_party::ProofRequest>>,
    ) {
        use qomm_transport::proof_party::{
            encode_bounded_response, read_bounded_request_line, ProofRequest, ProofResponse,
        };
        use std::io::BufReader;
        let tls = server_tls_context(&files.server_cert, &files.server_key, &files.ca).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let expected_peer = files.participant_fingerprint;
        let worker = thread::spawn(move || {
            let mut seen = Vec::new();
            for reply in replies {
                let until = std::time::Instant::now() + Duration::from_secs(5);
                let tcp = loop {
                    match listener.accept() {
                        Ok((tcp, _)) => break tcp,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < until,
                                "missing fresh connection"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                };
                tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                let tls = tls.acceptor.accept(tcp).unwrap();
                assert_eq!(
                    certificate_fingerprint(
                        &tls.ssl().peer_certificate().unwrap().to_der().unwrap()
                    ),
                    expected_peer
                );
                let mut stream = BufReader::new(tls);
                let request: ProofRequest = serde_json::from_slice(
                    &read_bounded_request_line(&mut stream).unwrap().unwrap(),
                )
                .unwrap();
                let id = request.id;
                seen.push(request);
                if let Some(value) = reply {
                    let response = ProofResponse {
                        id,
                        ok: true,
                        result: Some(value),
                        error: None,
                    };
                    stream
                        .get_mut()
                        .write_all(&encode_bounded_response(&response).unwrap())
                        .unwrap();
                    stream.get_mut().write_all(b"\n").unwrap();
                    stream.get_mut().flush().unwrap();
                    // Deterministic: the client must end a successful exchange,
                    // not keep the socket until an idle timeout or next call.
                    assert!(read_bounded_request_line(&mut stream).unwrap().is_none());
                } else {
                    // A request was received, but its reply is lost. No implicit
                    // retry may turn this ambiguous outcome into a second write.
                    let _ = stream.get_mut().shutdown();
                    let _ = stream
                        .get_ref()
                        .get_ref()
                        .shutdown(std::net::Shutdown::Both);
                }
            }
            seen
        });
        (address, worker)
    }

    fn private_admission_client(
        files: &Files,
        address: SocketAddr,
    ) -> oclob_settlement::pretrade::PrivateAdmissionClient {
        oclob_settlement::pretrade::PrivateAdmissionClient::new(
            "127.0.0.1",
            address.port(),
            "localhost",
            qomm_transport::node_service::client_ssl_context(
                &files.participant_cert,
                &files.participant_key,
                &files.ca,
            )
            .unwrap(),
            Duration::from_secs(3),
        )
        .unwrap()
    }

    #[test]
    fn private_admission_clones_open_fresh_connections_after_success() {
        let files = tls_files();
        let value = serde_json::json!({"scope": "transport-unit-only"});
        let (address, worker) =
            private_admission_exchange_peer(&files, vec![Some(value.clone()), Some(value.clone())]);
        let client = private_admission_client(&files, address);
        assert_eq!(client.call("scope", serde_json::json!({})).unwrap(), value);
        assert_eq!(
            client.clone().call("scope", serde_json::json!({})).unwrap(),
            value
        );
        let seen = worker.join().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|request| request.method == "scope"));
        assert!(seen[0].id < seen[1].id);
    }

    #[test]
    fn private_admission_lost_reply_requires_explicit_recovery_without_replay() {
        let files = tls_files();
        let recovered = serde_json::json!({"finalized": "transport-unit-only"});
        let mandate = serde_json::json!({"same_mandate": "unit"});
        let (address, worker) =
            private_admission_exchange_peer(&files, vec![None, Some(recovered.clone())]);
        let client = private_admission_client(&files, address);
        assert!(client.call("reserve", mandate.clone()).is_err());
        assert_eq!(
            client.call("recover_reservation", mandate.clone()).unwrap(),
            recovered
        );
        let seen = worker.join().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].method, "reserve");
        assert_eq!(seen[1].method, "recover_reservation");
        assert!(seen.iter().all(|request| request.params == mandate));
        assert!(seen[0].id < seen[1].id);
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
        let one_time_order_signer = SigningKey::from_bytes(&[10; 32]);
        let coordinator_signer = SigningKey::from_bytes(&[8; 32]);
        let receipt_signer = SigningKey::from_bytes(&[9; 32]);
        let ordering_keys = (1_u16..=7)
            .map(|node_id| {
                let key = if node_id == 1 {
                    receipt_signer.verifying_key()
                } else {
                    SigningKey::from_bytes(&[node_id as u8 + 20; 32]).verifying_key()
                };
                (node_id, key)
            })
            .collect();
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
            receipt_signer.clone(),
            CommitteePolicy::seven_node(),
            ordering_keys,
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
            receipt_verifying_key: receipt_signer.verifying_key().to_bytes(),
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
            &one_time_order_signer,
            &public_keys,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let manifest = bundle.manifest().clone();
        assert_ne!(
            manifest.signer,
            participant_signer.verifying_key().to_bytes()
        );
        let deliveries = bundle.into_deliveries();
        let delivery = deliveries[0].1.clone();
        let capability_key_delivery = deliveries[0].2.clone();
        let order_share_digest = delivery.wire_digest();
        let capability_key_share_digest = capability_key_delivery.wire_digest();
        let first = participant
            .ingest(
                manifest.clone(),
                delivery.clone(),
                capability_key_delivery.clone(),
            )
            .unwrap();
        first
            .verify(
                &manifest,
                0,
                order_share_digest,
                capability_key_share_digest,
                &receipt_signer.verifying_key(),
            )
            .unwrap();
        assert_eq!(first.generation, 1);
        assert_eq!(
            participant
                .ingest(manifest, delivery, capability_key_delivery)
                .unwrap(),
            first
        );
        assert_eq!(coordinator.status().unwrap().record_count, 1);
        let vote = coordinator
            .vote(
                "JGB10Y-JPY",
                1,
                first.order_commitment,
                [0; 32],
                2_000_000_000,
            )
            .unwrap();
        assert_eq!(vote.node_id, 1);
        assert!(participant.status().is_err());
    }

    #[test]
    fn settlement_role_releases_only_the_completed_rounds_bound_key_share() {
        let files = tls_files();
        let now = unix_seconds().unwrap();
        let node_keys: [NodeDecryptionKey; MPC_PARTIES] =
            std::array::from_fn(|_| NodeDecryptionKey::generate().unwrap());
        let public_keys: [NodeEncryptionKey; MPC_PARTIES] =
            std::array::from_fn(|party| node_keys[party].public_key().unwrap());
        let participant_signer = SigningKey::from_bytes(&[51; 32]);
        let coordinator_signer = SigningKey::from_bytes(&[52; 32]);
        let settlement_signer = SigningKey::from_bytes(&[53; 32]);
        let receipt_signer = SigningKey::from_bytes(&[1; 32]);
        let order = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            100,
            40,
            TimeInForce::GoodTilCancelled,
            now + 600,
            [54; 32],
            [55; 32],
            [56; 32],
        )
        .unwrap();
        let bundle = EdgeOrderBundle::create(
            &order,
            [57; 32],
            [58; 32],
            &participant_signer,
            &public_keys,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let manifest = bundle.manifest().clone();
        let deliveries = bundle.into_deliveries();
        let mut committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let certificate = committee
            .certify("JGB10Y-JPY", manifest.commitment, now + 120, now)
            .unwrap();
        let plan =
            RoundPlan::sign(certificate, vec![], now, now + 120, &coordinator_signer).unwrap();
        let result = MpcBatchResult {
            slots: vec![
                MpcSlotResult {
                    matched: false,
                    trade_price: 0,
                    trade_quantity: 0,
                };
                MAX_MATCH_SLOTS
            ],
            arriving_remaining: 40,
        };
        let output = public_output_digest(&result);
        let store_path = files.root.join("release-shares.bin");
        let mut store = NodeShareStore::open(&store_path, 0, node_keys[0].clone()).unwrap();
        store
            .ingest(
                manifest.clone(),
                deliveries[0].1.clone(),
                deliveries[0].2.clone(),
                now,
            )
            .unwrap();
        let generation = store.status().unwrap().generation;
        store
            .record_completed_round(NodeExecutionReceipt {
                version: 1,
                party: 0,
                round_id: plan.round_id,
                generation,
                round_commitment: [59; 32],
                program_sha256: [60; 32],
                artifact_sha256: [61; 32],
                private_parent_digest: [62; 32],
                private_state_sha256: [63; 32],
                public_output_sha256: output,
                result,
                execution_ms: 1,
                signer: receipt_signer.verifying_key().to_bytes(),
                signature: vec![62; 64],
            })
            .unwrap();
        let ordering_keys = committee.verifying_keys();
        let principals = vec![
            Principal {
                certificate_sha256: files.coordinator_fingerprint,
                role: PeerRole::Coordinator,
                application_key: coordinator_signer.verifying_key().to_bytes(),
            },
            Principal {
                certificate_sha256: files.settlement_fingerprint,
                role: PeerRole::Settlement,
                application_key: settlement_signer.verifying_key().to_bytes(),
            },
        ];
        let server = NodeRpcServer::start(
            "127.0.0.1:0".parse().unwrap(),
            server_tls_context(&files.server_cert, &files.server_key, &files.ca).unwrap(),
            principals,
            store,
            receipt_signer.clone(),
            CommitteePolicy::seven_node(),
            ordering_keys,
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
            receipt_verifying_key: receipt_signer.verifying_key().to_bytes(),
        };
        let settlement = NodeRpcClient::new(
            endpoint.clone(),
            client_tls_context(&files.settlement_cert, &files.settlement_key, &files.ca).unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();
        let coordinator = NodeRpcClient::new(
            endpoint,
            client_tls_context(&files.coordinator_cert, &files.coordinator_key, &files.ca).unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();

        let release = settlement
            .release_capability_key_share(&manifest, plan.clone(), manifest.commitment, output, now)
            .unwrap();
        release
            .verify(
                &manifest,
                &plan,
                output,
                0,
                &receipt_signer.verifying_key(),
                now,
            )
            .unwrap();
        assert!(settlement
            .release_capability_key_share(
                &manifest,
                plan.clone(),
                manifest.commitment,
                [63; 32],
                now,
            )
            .is_err());
        assert!(
            coordinator
                .release_capability_key_share(
                    &manifest,
                    plan.clone(),
                    manifest.commitment,
                    output,
                    now,
                )
                .is_err()
        );
        assert!(settlement.execute(plan).is_err());
        assert!(settlement.status().is_err());
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
        let (settlement_key, settlement_cert) = make_leaf(&ca_key, &ca_cert, "settlement", false);
        let ca = root.join("ca.pem");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server-key.pem");
        let participant_cert_path = root.join("participant.pem");
        let participant_key_path = root.join("participant-key.pem");
        let coordinator_cert_path = root.join("coordinator.pem");
        let coordinator_key_path = root.join("coordinator-key.pem");
        let settlement_cert_path = root.join("settlement.pem");
        let settlement_key_path = root.join("settlement-key.pem");
        fs::write(&ca, ca_cert.to_pem().unwrap()).unwrap();
        write_private(&server_key_path, &server_key);
        fs::write(&server_cert_path, server_cert.to_pem().unwrap()).unwrap();
        write_private(&participant_key_path, &participant_key);
        fs::write(&participant_cert_path, participant_cert.to_pem().unwrap()).unwrap();
        write_private(&coordinator_key_path, &coordinator_key);
        fs::write(&coordinator_cert_path, coordinator_cert.to_pem().unwrap()).unwrap();
        write_private(&settlement_key_path, &settlement_key);
        fs::write(&settlement_cert_path, settlement_cert.to_pem().unwrap()).unwrap();
        Files {
            root,
            ca,
            server_cert: server_cert_path,
            server_key: server_key_path,
            participant_cert: participant_cert_path,
            participant_key: participant_key_path,
            coordinator_cert: coordinator_cert_path,
            coordinator_key: coordinator_key_path,
            settlement_cert: settlement_cert_path,
            settlement_key: settlement_key_path,
            server_fingerprint: certificate_fingerprint(&server_cert.to_der().unwrap()),
            participant_fingerprint: certificate_fingerprint(&participant_cert.to_der().unwrap()),
            coordinator_fingerprint: certificate_fingerprint(&coordinator_cert.to_der().unwrap()),
            settlement_fingerprint: certificate_fingerprint(&settlement_cert.to_der().unwrap()),
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
