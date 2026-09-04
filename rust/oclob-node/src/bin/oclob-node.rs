//! Standalone OCLOB MPC node. One process owns one share and one MP-SPDZ party.

use ed25519_dalek::SigningKey;
use oclob_edge::NodeDecryptionKey;
use oclob_node::executor::PartyExecutor;
use oclob_node::network::{
    load_secret_32, server_tls_context, ClusterPublicConfig, NodeRpcServer, Principal,
};
use oclob_node::NodeShareStore;
use oclob_ordering::CommitteePolicy;
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
    if config.version != 1 {
        return Err("unsupported node configuration version".into());
    }
    let share_key = NodeDecryptionKey::from_raw(
        load_secret_32(&config.share_private_key).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let receipt_key = SigningKey::from_bytes(
        &load_secret_32(&config.receipt_signing_key).map_err(|error| error.to_string())?,
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
    let store = NodeShareStore::open(&config.share_store, config.party, share_key)
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
    let server = NodeRpcServer::start(
        config.listen,
        tls,
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
    write_ready_file(&config.ready_file, config.party, server.address())?;
    println!(
        "{}",
        json!({
            "status": "ready",
            "party": config.party,
            "listen": server.address(),
            "program": config.program,
        })
    );
    loop {
        thread::park_timeout(Duration::from_secs(3600));
    }
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
