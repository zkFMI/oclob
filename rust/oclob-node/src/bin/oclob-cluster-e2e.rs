//! Coordinator-only acceptance client for the seven-container OCLOB cluster.

use ed25519_dalek::{SigningKey, VerifyingKey};
use oclob_core::{MpcBatchResult, MAX_MATCH_SLOTS};
use oclob_node::edge_client::{collect_order_certificate, EdgeAdmissionReceipt};
use oclob_node::executor::{NodeExecutionReceipt, RoundPlan};
use oclob_node::network::{
    client_tls_context, load_secret_32, ClientIdentityConfig, ClientTlsConfig, ClusterPublicConfig,
    NodeRpcClient,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("oclob-cluster-e2e failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let paths = parse_args()?;
    let research = validate_research_binding(&paths.contract, &paths.manifest)?;
    let cluster: ClusterPublicConfig = read_json(&paths.cluster)?;
    cluster.validate().map_err(|error| error.to_string())?;
    let identity: ClientIdentityConfig = read_json(&paths.identity)?;
    identity.validate().map_err(|error| error.to_string())?;
    let maker: EdgeAdmissionReceipt = read_json(&paths.maker)?;
    let taker: EdgeAdmissionReceipt = read_json(&paths.taker)?;
    let now = unix_seconds()?;
    maker
        .verify(&cluster, now)
        .map_err(|error| error.to_string())?;
    taker
        .verify(&cluster, now)
        .map_err(|error| error.to_string())?;
    if maker.manifest.market_id != cluster.market_id
        || taker.manifest.market_id != cluster.market_id
        || maker.commitment() == taker.commitment()
    {
        return Err("edge handoff does not describe two distinct orders in this market".into());
    }
    let coordinator = SigningKey::from_bytes(
        &load_secret_32(&identity.application_signing_key).map_err(|error| error.to_string())?,
    );
    let tls = client_tls_context(
        &identity.tls_certificate,
        &identity.tls_private_key,
        &identity.tls_ca,
    )
    .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let maker_certificate = collect_order_certificate(
        &cluster,
        &tls,
        None,
        maker.commitment(),
        maker.manifest.retention_deadline,
        Duration::from_secs(30),
    )
    .map_err(|error| error.to_string())?;
    let maker_plan = RoundPlan::sign(
        maker_certificate.clone(),
        vec![],
        now,
        now.saturating_add(300),
        &coordinator,
    )
    .map_err(|error| error.to_string())?;
    let maker_receipts = execute_all(&cluster, &tls, &maker_plan)?;
    let maker_result = agreed_result(&cluster, &maker_plan, &maker_receipts)?;
    validate_maker_result(&maker_result)?;

    let now = unix_seconds()?;
    let taker_certificate = collect_order_certificate(
        &cluster,
        &tls,
        Some(&maker_certificate),
        taker.commitment(),
        taker.manifest.retention_deadline,
        Duration::from_secs(30),
    )
    .map_err(|error| error.to_string())?;
    let taker_plan = RoundPlan::sign(
        taker_certificate.clone(),
        vec![maker.commitment()],
        now,
        now.saturating_add(300),
        &coordinator,
    )
    .map_err(|error| error.to_string())?;
    let taker_receipts = execute_all(&cluster, &tls, &taker_plan)?;
    let taker_result = agreed_result(&cluster, &taker_plan, &taker_receipts)?;
    validate_taker_result(&taker_result)?;

    // A coordinator retry is safe: every node returns its persisted receipt
    // instead of launching a second party process.
    let retry_receipts = execute_all(&cluster, &tls, &taker_plan)?;
    if retry_receipts != taker_receipts {
        return Err("idempotent round retry did not return identical receipts".into());
    }
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let artifact = json!({
        "schema": "oclob.distributed-acceptance/v1",
        "verdict": "accepted",
        "research": research,
        "market_id": cluster.market_id,
        "topology": {
            "mpc_containers": 7,
            "mpc_processes_per_container": 1,
            "operator_hosts": 1,
            "independent_operators_claimed": false,
            "transport": "mutual TLS 1.3 with pinned certificate SHA-256",
            "request_record_bytes": oclob_node::network::REQUEST_RECORD_BYTES,
            "response_record_bytes": oclob_node::network::RESPONSE_RECORD_BYTES
        },
        "edge_admission": {
            "maker": hex::encode(maker.receipt_digest),
            "taker": hex::encode(taker.receipt_digest),
            "maker_signed_node_receipts": maker.node_receipts.len(),
            "taker_signed_node_receipts": taker.node_receipts.len(),
            "all_seven_nodes_acknowledged": true,
            "coordinator_received_plain_order": false
        },
        "ordering": {
            "quorum": 5,
            "maker_sequence": maker_certificate.sequence,
            "taker_sequence": taker_certificate.sequence,
            "maker_votes": maker_certificate.votes.len(),
            "taker_votes": taker_certificate.votes.len(),
            "node_verified_certificate_chain": true
        },
        "matching": {
            "protocol": "MP-SPDZ malicious-shamir",
            "parties": 7,
            "max_corrupt_parties": 2,
            "all_party_outputs_agreed": true,
            "program_sha256": hex::encode(taker_receipts[0].program_sha256),
            "artifact_sha256": hex::encode(taker_receipts[0].artifact_sha256),
            "maker_arriving_remainder": maker_result.arriving_remaining,
            "trade_price": taker_result.slots[0].trade_price,
            "trade_quantity": taker_result.slots[0].trade_quantity,
            "taker_remainder": taker_result.arriving_remaining,
            "idempotent_retry": true,
            "party_execution_ms": taker_receipts.iter().map(|receipt| receipt.execution_ms).collect::<Vec<_>>()
        },
        "elapsed_ms": elapsed_ms,
        "non_claims": [
            "Seven containers on one host are not seven independent operators or WAN evidence.",
            "This acceptance stops at distributed matching; live Avalanche DeFMI settlement is a separate gate."
        ]
    });
    write_json_exclusive(&paths.artifact, &artifact)?;
    println!(
        "{}",
        json!({
            "status": "accepted",
            "artifact": paths.artifact,
            "trade_price": taker_result.slots[0].trade_price,
            "trade_quantity": taker_result.slots[0].trade_quantity,
            "elapsed_ms": elapsed_ms
        })
    );
    Ok(())
}

fn execute_all(
    cluster: &ClusterPublicConfig,
    tls: &ClientTlsConfig,
    plan: &RoundPlan,
) -> Result<Vec<NodeExecutionReceipt>, String> {
    let handles = cluster
        .nodes
        .iter()
        .cloned()
        .map(|node| {
            let tls = tls.clone();
            let plan = plan.clone();
            thread::spawn(move || -> Result<NodeExecutionReceipt, String> {
                let deadline = Instant::now() + Duration::from_secs(300);
                let mut first_error = None;
                loop {
                    let client =
                        NodeRpcClient::new(node.endpoint(), tls.clone(), Duration::from_secs(320))
                            .map_err(|error| error.to_string())?;
                    match client.execute(plan.clone()) {
                        Ok(receipt) => return Ok(receipt),
                        Err(error) if Instant::now() < deadline => {
                            first_error.get_or_insert_with(|| error.to_string());
                            if unix_seconds()? >= plan.expires_at {
                                return Err(format!(
                                    "node {} execution expired; first error: {}; last error: {}",
                                    node.party,
                                    first_error.as_deref().unwrap_or("unknown"),
                                    error
                                ));
                            }
                            thread::sleep(Duration::from_millis(250));
                        }
                        Err(error) => {
                            return Err(format!(
                                "node {} execution failed; first error: {}; last error: {}",
                                node.party,
                                first_error.as_deref().unwrap_or("unknown"),
                                error
                            ))
                        }
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| "node execution worker panicked".to_owned())?
        })
        .collect()
}

fn agreed_result(
    cluster: &ClusterPublicConfig,
    plan: &RoundPlan,
    receipts: &[NodeExecutionReceipt],
) -> Result<MpcBatchResult, String> {
    if receipts.len() != cluster.nodes.len() {
        return Err("not all seven nodes returned a receipt".into());
    }
    for (party, (node, receipt)) in cluster.nodes.iter().zip(receipts).enumerate() {
        let key = VerifyingKey::from_bytes(&node.receipt_verifying_key)
            .map_err(|_| "node receipt key is invalid".to_owned())?;
        receipt
            .verify(plan, party as u16, &key)
            .map_err(|error| error.to_string())?;
    }
    let first = receipts
        .first()
        .ok_or_else(|| "cluster returned no receipts".to_owned())?;
    if receipts.iter().any(|receipt| {
        receipt.result != first.result
            || receipt.public_output_sha256 != first.public_output_sha256
            || receipt.program_sha256 != first.program_sha256
            || receipt.artifact_sha256 != first.artifact_sha256
    }) {
        return Err("the seven parties did not agree on code and output".into());
    }
    Ok(first.result.clone())
}

fn validate_maker_result(result: &MpcBatchResult) -> Result<(), String> {
    if result.slots.len() != MAX_MATCH_SLOTS
        || result
            .slots
            .iter()
            .any(|slot| slot.matched || slot.trade_price != 0 || slot.trade_quantity != 0)
        || result.arriving_remaining != 60
    {
        return Err("maker resting transition produced an unexpected public result".into());
    }
    Ok(())
}

fn validate_taker_result(result: &MpcBatchResult) -> Result<(), String> {
    if result.slots.len() != MAX_MATCH_SLOTS
        || !result.slots[0].matched
        || result.slots[0].trade_price != 100
        || result.slots[0].trade_quantity != 40
        || result.arriving_remaining != 0
        || result.slots[1..]
            .iter()
            .any(|slot| slot.matched || slot.trade_price != 0 || slot.trade_quantity != 0)
    {
        return Err("taker transition produced an unexpected public result".into());
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = read_bounded_file(path)?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, String> {
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
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("input path exceeds the maximum size".into());
    }
    Ok(bytes)
}

fn validate_research_binding(contract_path: &Path, manifest_path: &Path) -> Result<Value, String> {
    let contract_bytes = read_bounded_file(contract_path)?;
    let contract: Value = serde_json::from_slice(&contract_bytes)
        .map_err(|_| "distributed research contract is malformed".to_owned())?;
    let manifest: Value = read_json(manifest_path)?;
    let contract_id = contract
        .get("contract_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "distributed research contract has no id".to_owned())?;
    let manifest_contract = manifest.get("contract_id").and_then(Value::as_str);
    let manifest_id = manifest
        .get("manifest_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "distributed research manifest has no id".to_owned())?;
    let expected_sha = manifest
        .get("contract_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "distributed research manifest has no contract digest".to_owned())?;
    let actual_sha: [u8; 32] = Sha256::digest(&contract_bytes).into();
    if contract_id != "oclob-distributed-edge-mpc-v1"
        || manifest_contract != Some(contract_id)
        || expected_sha != hex::encode(actual_sha)
        || manifest.get("stage").and_then(Value::as_str)
            != Some("RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC")
        || manifest.get("primary_metric").and_then(Value::as_str)
            != Some("complete_distributed_matching_path")
    {
        return Err("distributed research contract and manifest are not the approved pair".into());
    }
    Ok(json!({
        "contract_id": contract_id,
        "contract_sha256": expected_sha,
        "manifest_id": manifest_id,
        "stage": "RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC",
        "primary_metric": "complete_distributed_matching_path",
        "observed_value": 1
    }))
}

fn write_json_exclusive(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
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

struct AcceptancePaths {
    cluster: PathBuf,
    identity: PathBuf,
    maker: PathBuf,
    taker: PathBuf,
    contract: PathBuf,
    manifest: PathBuf,
    artifact: PathBuf,
}

fn parse_args() -> Result<AcceptancePaths, String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 14
        || args[0] != "--cluster"
        || args[2] != "--identity"
        || args[4] != "--maker"
        || args[6] != "--taker"
        || args[8] != "--contract"
        || args[10] != "--manifest"
        || args[12] != "--artifact"
    {
        return Err("usage: oclob-cluster-e2e --cluster PATH --identity PATH --maker PATH --taker PATH --contract PATH --manifest PATH --artifact PATH".into());
    }
    Ok(AcceptancePaths {
        cluster: PathBuf::from(&args[1]),
        identity: PathBuf::from(&args[3]),
        maker: PathBuf::from(&args[5]),
        taker: PathBuf::from(&args[7]),
        contract: PathBuf::from(&args[9]),
        manifest: PathBuf::from(&args[11]),
        artifact: PathBuf::from(&args[13]),
    })
}

fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}
