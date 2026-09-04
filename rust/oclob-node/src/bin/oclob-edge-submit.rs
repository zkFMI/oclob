//! Demo corporate module: create a private order and fan out seven shares.

use ed25519_dalek::SigningKey;
use oclob_core::{Digest32, SecretOrder, Side, TimeInForce};
use oclob_edge::{EdgeOrderBundle, NodeEncryptionKey, MPC_PARTIES};
use oclob_node::edge_client::{EdgeAdmissionReceipt, EdgeDistributor};
use oclob_node::network::{
    client_tls_context, load_secret_32, ClientIdentityConfig, ClusterPublicConfig,
};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy)]
enum Scenario {
    Maker,
    Taker,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("oclob-edge-submit failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (cluster_path, identity_path, handoff_path, scenario) = parse_args()?;
    let cluster: ClusterPublicConfig = read_json(&cluster_path)?;
    cluster.validate().map_err(|error| error.to_string())?;
    let identity: ClientIdentityConfig = read_json(&identity_path)?;
    identity.validate().map_err(|error| error.to_string())?;
    let signing_key = SigningKey::from_bytes(
        &load_secret_32(&identity.application_signing_key).map_err(|error| error.to_string())?,
    );
    let tls = client_tls_context(
        &identity.tls_certificate,
        &identity.tls_private_key,
        &identity.tls_ca,
    )
    .map_err(|error| error.to_string())?;
    let node_keys: [NodeEncryptionKey; MPC_PARTIES] = cluster
        .nodes
        .iter()
        .map(|node| node.share_encryption_key.clone())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "cluster does not contain exactly seven encryption keys".to_owned())?;
    let order = demo_order(&cluster.market_id, scenario, &signing_key)?;
    let eligibility_commitment = hidden_eligibility_commitment(&order);
    let settlement_capability_commitment = hidden_settlement_commitment(&order);
    let bundle = EdgeOrderBundle::create(
        &order,
        eligibility_commitment,
        settlement_capability_commitment,
        &signing_key,
        &node_keys,
        &mut rand::rngs::OsRng,
    )
    .map_err(|error| error.to_string())?;
    let distributor = EdgeDistributor::new(cluster, tls, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    let receipt = distributor
        .submit(bundle)
        .map_err(|error| error.to_string())?;
    write_handoff(&handoff_path, &receipt)?;
    println!(
        "{}",
        json!({
            "status": "admitted_by_all_nodes",
            "role": match scenario { Scenario::Maker => "maker", Scenario::Taker => "taker" },
            "order_commitment": receipt.commitment().hex(),
            "edge_receipt": hex::encode(receipt.receipt_digest),
            "nodes": MPC_PARTIES
        })
    );
    Ok(())
}

fn demo_order(
    market: &str,
    scenario: Scenario,
    signer: &SigningKey,
) -> Result<SecretOrder, String> {
    let now = unix_seconds()?;
    let mut nonce = [0_u8; 32];
    let mut salt = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut participant = Sha256::new();
    participant.update(b"OCLOB:LAB-PARTICIPANT:v1");
    participant.update(signer.verifying_key().to_bytes());
    participant.update(match scenario {
        Scenario::Maker => b"maker".as_slice(),
        Scenario::Taker => b"taker".as_slice(),
    });
    let participant: Digest32 = participant.finalize().into();
    let (side, price, quantity, tif) = match scenario {
        Scenario::Maker => (Side::Sell, 100, 60, TimeInForce::GoodTilCancelled),
        Scenario::Taker => (Side::Buy, 101, 40, TimeInForce::ImmediateOrCancel),
    };
    SecretOrder::new(
        market,
        side,
        price,
        quantity,
        tif,
        now.saturating_add(600),
        participant,
        nonce,
        salt,
    )
    .map_err(|error| error.to_string())
}

fn hidden_eligibility_commitment(order: &SecretOrder) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:LAB-ELIGIBILITY-COMMITMENT:v1");
    hash.update(order.dekyx_nullifier());
    hash.update(order.market_id().as_bytes());
    hash.finalize().into()
}

fn hidden_settlement_commitment(order: &SecretOrder) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:LAB-SETTLEMENT-CAPABILITY:v1");
    hash.update(order.reservation_id());
    hash.update(order.participant_handle());
    hash.update(order.reservation_limit().to_be_bytes());
    hash.finalize().into()
}

fn write_handoff(path: &Path, receipt: &EdgeAdmissionReceipt) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut bytes = serde_json::to_vec_pretty(receipt).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_FILE_BYTES
    {
        return Err("input path is unsafe".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn parse_args() -> Result<(PathBuf, PathBuf, PathBuf, Scenario), String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 8
        || args[0] != "--cluster"
        || args[2] != "--identity"
        || args[4] != "--handoff"
        || args[6] != "--scenario"
    {
        return Err("usage: oclob-edge-submit --cluster PATH --identity PATH --handoff PATH --scenario maker|taker".into());
    }
    let scenario = match args[7].to_str() {
        Some("maker") => Scenario::Maker,
        Some("taker") => Scenario::Taker,
        _ => return Err("scenario must be maker or taker".into()),
    };
    Ok((
        PathBuf::from(&args[1]),
        PathBuf::from(&args[3]),
        PathBuf::from(&args[5]),
        scenario,
    ))
}

fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}
