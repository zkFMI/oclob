//! Standalone OCLOB MPC node. One process owns one share and one MP-SPDZ party.

use oclob_core::application_crypto::SigningKey;
use oclob_edge::NodeDecryptionKey;
use oclob_node::executor::PartyExecutor;
use oclob_node::network::{
    load_application_signing_seed, load_hybrid_kem_seed, load_secret_32, server_tls_context,
    ClusterPublicConfig, NodeRpcServer, Principal,
};
use oclob_node::proof_network::{ProofRpcServer, ProofRpcServerConfig};
use oclob_node::NodeShareStore;
use oclob_ordering::CommitteePolicy;
use qomm_transport::proof_party::{ProofParty, ProofPartyConfig};
use serde::Deserialize;
use serde_json::json;
use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
struct Config {
    recipient_opening_keys: Vec<qomm_transport::proof_party::RecipientOpeningKey>,
    version: u16,
    party: u16,
    listen: SocketAddr,
    tls_certificate: PathBuf,
    tls_private_key: PathBuf,
    tls_ca: PathBuf,
    principals: Vec<Principal>,
    share_private_key: PathBuf,
    receipt_signing_key: PathBuf,
    cluster_public_config: PathBuf,
    share_store: PathBuf,
    ready_file: PathBuf,
    mp_spdz_root: PathBuf,
    mpc_work_root: PathBuf,
    program: String,
    mpc_hosts: String,
    execution_timeout_seconds: u64,
    rpc_timeout_seconds: u64,
    max_connections: usize,
    minimum_response_millis: u64,
    proof_listen: SocketAddr,
    proof_state_file: PathBuf,
    proof_state_passphrase: PathBuf,
    trusted_defmi_id: String,
    trusted_reservation_venue_id: String,
    trusted_defmi_receipt_public: String,
    /// Optional enrollment for the separate QOMM typed pre-trade ACK protocol.
    #[serde(default)]
    qomm_pretrade_ack_fingerprint: Option<String>,
    #[serde(default)]
    native_finality_endpoint: Option<NativeFinalityEndpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeFinalityEndpoint {
    host: String,
    port: u16,
    server_name: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("oclob-node failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let path = parse_config_path()?;
    let config: Config = read_json(&path)?;
    if config.version != 4 {
        return Err("unsupported node configuration version".into());
    }
    let share_key = NodeDecryptionKey::from_raw(
        load_hybrid_kem_seed(&config.share_private_key).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let receipt_key = SigningKey::from_bytes(
        &load_application_signing_seed(&config.receipt_signing_key)
            .map_err(|error| error.to_string())?,
    );
    let cluster: ClusterPublicConfig = read_json(&config.cluster_public_config)?;
    cluster.validate().map_err(|error| error.to_string())?;
    let public_node = cluster
        .nodes
        .get(usize::from(config.party))
        .ok_or_else(|| "node is absent from the public cluster configuration".to_owned())?;
    if public_node.party != config.party
        || public_node.receipt_verifying_key != receipt_key.verifying_key().to_bytes()
        || cluster.program != config.program
    {
        return Err("node private identity does not match the public cluster configuration".into());
    }
    let ordering_keys = cluster
        .ordering_verifying_keys()
        .map_err(|error| error.to_string())?;
    let mut store = NodeShareStore::open(&config.share_store, config.party, share_key)
        .map_err(|error| error.to_string())?;
    let trusted_defmi_id = parse_hex_32(&config.trusted_defmi_id, "trusted DeFMI id")?;
    let trusted_venue_id = parse_hex_32(
        &config.trusted_reservation_venue_id,
        "trusted reservation venue id",
    )?;
    let trusted_defmi_receipt_public = hex::decode(&config.trusted_defmi_receipt_public)
        .map_err(|_| "malformed hybrid issuer key")?;
    if trusted_defmi_receipt_public.len() != 1984 {
        return Err("legacy issuer key requires PQC re-enrollment".into());
    }
    store
        .pin_reservation_trust(
            trusted_venue_id,
            trusted_defmi_id,
            trusted_defmi_receipt_public.clone(),
        )
        .map_err(|error| error.to_string())?;
    let executor = PartyExecutor::open(
        config.party,
        &config.mp_spdz_root,
        &config.mpc_work_root,
        &config.program,
        &config.mpc_hosts,
        Duration::from_secs(config.execution_timeout_seconds),
        receipt_key.clone(),
    )
    .map_err(|error| error.to_string())?;
    let tls = server_tls_context(
        &config.tls_certificate,
        &config.tls_private_key,
        &config.tls_ca,
    )
    .map_err(|error| error.to_string())?;
    let coordinator_fingerprint = config
        .principals
        .iter()
        .find(|principal| principal.role == oclob_node::network::PeerRole::Coordinator)
        .map(|principal| principal.certificate_sha256)
        .ok_or_else(|| "node configuration has no proof coordinator".to_owned())?;
    let server = NodeRpcServer::start(
        config.listen,
        tls.clone(),
        config.principals,
        store,
        receipt_key,
        CommitteePolicy::seven_node(),
        ordering_keys,
        Some(executor),
        config.max_connections,
        Duration::from_secs(config.rpc_timeout_seconds),
        Duration::from_millis(config.minimum_response_millis),
    )
    .map_err(|error| error.to_string())?;
    let qomm_pretrade_ack_fingerprint = config
        .qomm_pretrade_ack_fingerprint
        .as_deref()
        .map(|encoded| -> Result<[u8; 32], String> {
            let bytes: [u8; 32] = hex::decode(encoded)
                .map_err(|_| "QOMM pre-trade ACK fingerprint is not hexadecimal".to_owned())?
                .try_into()
                .map_err(|_| "QOMM pre-trade ACK fingerprint must be 32 bytes".to_owned())?;
            qomm_transport::application_crypto::VerifyingKey::from_bytes(&bytes)
                .map_err(|error| error.to_string())?;
            Ok(bytes)
        })
        .transpose()?;
    let proof_party = ProofParty::new(ProofPartyConfig {
        recipient_opening_keys: config.recipient_opening_keys.clone(),
        node: config.party,
        allowed_root: config.mpc_work_root.join("private-state"),
        state_file: config.proof_state_file,
        state_passphrase: load_secret_32(&config.proof_state_passphrase)
            .map_err(|error| error.to_string())?
            .to_vec(),
        n_mm: 1,
        n_parties: 7,
        threshold: 2,
        amount_bits: 32,
        price_bits: 32,
        remainder_bits: 32,
        complete_quote_proof: false,
        quote_eligibility_bits: 34,
        quote_span_bits: 32,
        trusted_defmi_receipt_public: qomm_pretrade_ack_fingerprint,
        allow_health_signing: false,
    })?;
    let native_finality = config
        .native_finality_endpoint
        .map(|endpoint| {
            let tls = qomm_transport::node_service::client_ssl_context(
                &config.tls_certificate,
                &config.tls_private_key,
                &config.tls_ca,
            )?;
            let client = oclob_settlement::pretrade::PrivateAdmissionClient::new(
                &endpoint.host,
                endpoint.port,
                &endpoint.server_name,
                tls,
                Duration::from_secs(15),
            )?;
            Ok::<_, String>((client, server.native_finality_handle()))
        })
        .transpose()?;
    let proof_server = ProofRpcServer::start(
        ProofRpcServerConfig {
            address: config.proof_listen,
            tls,
            coordinator_fingerprint,
            persistence_root: config.mpc_work_root.join("private-state"),
            expected_party: config.party,
            expected_receipt_signer: public_node.receipt_verifying_key,
            native_trust: Some(oclob_settlement::native::NativeReservationTrust {
                venue_id: trusted_venue_id,
                defmi_id: trusted_defmi_id,
                issuer: trusted_defmi_receipt_public.clone(),
            }),
            native_finality,
            max_connections: config.max_connections,
            timeout: Duration::from_secs(config.rpc_timeout_seconds),
        },
        proof_party,
    )?;
    write_ready_file(&config.ready_file, config.party, server.address())?;
    println!(
        "{}",
        json!({
            "status": "ready",
            "party": config.party,
            "listen": server.address(),
            "proof_listen": proof_server.address(),
            "program": config.program,
        })
    );
    loop {
        thread::park_timeout(Duration::from_secs(3600));
    }
}

fn parse_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|_| format!("{label} is not hex"))?
        .try_into()
        .map_err(|_| format!("{label} is not 32 bytes"))
}

fn write_ready_file(path: &Path, party: u16, address: SocketAddr) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let payload = serde_json::to_vec(&json!({
        "version": 1,
        "party": party,
        "listen": address,
        "ready": true
    }))
    .map_err(|error| error.to_string())?;
    fs::write(&temporary, payload).map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())
}

fn parse_config_path() -> Result<PathBuf, String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || args[0] != "--config" {
        return Err("usage: oclob-node --config PATH".into());
    }
    Ok(PathBuf::from(&args[1]))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err("node configuration path is unsafe".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}
