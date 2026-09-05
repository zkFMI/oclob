//! Dedicated whole-flow queued-expiry acceptance; no synthetic matching result.
use super::*;

pub(super) fn run(
    cluster: &ClusterPublicConfig,
    identity: &ClientIdentityConfig,
    manifest: &Value,
    contract_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for path in [
        "/handoff/expiry-absent-nodes.txt",
        "/handoff/expiry-release-nodes.txt",
    ] {
        let stopped = fs::read_to_string(path)?;
        if stopped.lines().count() != 7 || stopped.lines().any(|line| line != "false") {
            return Err("all seven real MPC containers must be stopped during expiry".into());
        }
    }
    let absent: Value = read("/handoff/expiry-absent.json")?;
    let released: Value = read("/handoff/expiry-released.json")?;
    let before: Value = read("/handoff/expiry-before-restart.json")?;
    let after: Value = read("/handoff/expiry-after-restart.json")?;
    let wallet: Value = read("/handoff/queued-expiry-recovery.wallet.json")?;
    let funding: Value = read("/handoff/queued-expiry-next.corporate.json")?;
    let receipt: EdgeAdmissionReceipt = read("/handoff/queued-expiry-next.json")?;
    receipt.verify(cluster, now()?)?;
    let stop_log = fs::read("/handoff/expiry-release-stop.jsonl")?;
    if stop_log.len() > 64 * 1024 {
        return Err("expiry stop log exceeds bound".into());
    }
    let stop: Value = serde_json::from_slice(
        stop_log
            .split(|byte| *byte == b'\n')
            .rfind(|line| !line.is_empty())
            .ok_or("missing expiry stop event")?,
    )?;
    if absent["status"] != "never_reserved"
        || absent["request_id"] != "native-expiry-absent-001"
        || released["status"] != "released"
        || released["request_id"] != "native-expiry-release-002"
        || stop["checkpoint"] != "after-expiry-before-journal"
        || before != after
        || after.as_array().map(Vec::len) != Some(2)
        || after[0]["state"]["aborted_before_reserve"].is_null()
        || after[1]["state"]["released"]["receipt"]["transaction_id"] != released["transaction_id"]
        || wallet["wallet_recovered"] != true
        || wallet["expected_private_balances_verified"] != true
        || wallet["facility_sequence"] != 2
        || wallet["unfilled_releases_recovered"] != 1
        || funding["selected_funding_note_spent_verified"] != true
        || funding["canonical_reserve_verified"] != true
        || funding["facility_sequence"] != 3
        || funding["order_commitment"] != receipt.commitment().hex()
    {
        return Err(
            "queued native expiry did not recover the exact request and reusable funds".into(),
        );
    }
    let tls = client_ssl_context(
        &identity.tls_certificate,
        &identity.tls_private_key,
        &identity.tls_ca,
    )?;
    let private = PrivateAdmissionClient::new(
        "oclob-defmi",
        9443,
        "oclob-defmi",
        tls,
        Duration::from_secs(120),
    )?;
    let client = private.chain()?;
    let transaction = released["transaction_id"]
        .as_str()
        .ok_or("no release transaction")?;
    let accepted = client.wait_accepted(
        transaction,
        Duration::from_secs(30),
        Duration::from_millis(200),
    )?;
    if released["statement"] != hex::encode(accepted.statement)
        || released["before_root"] != hex::encode(accepted.before_root)
        || released["after_root"] != hex::encode(accepted.after_root)
        || released["block_id"] != accepted.block_id
        || released["height"] != accepted.height
    {
        return Err("corporate release receipt differs from canonical DeFMI".into());
    }
    let node_tls = client_tls_context(
        &identity.tls_certificate,
        &identity.tls_private_key,
        &identity.tls_ca,
    )?;
    for node in &cluster.nodes {
        if NodeRpcClient::new(node.endpoint(), node_tls.clone(), Duration::from_secs(30))?
            .status()?
            .record_count
            != 1
        {
            return Err("MPC nodes did not receive only the fresh refund-funded order".into());
        }
    }
    let result = json!({"manifest_id":manifest["manifest_id"], "contract_sha256":contract_hash,
        "verdict":"smoke_only", "reconciled_expired_requests":2, "never_reserved":1,
        "completed_native_releases":1, "mpc_nodes_down_during_reconciliation":7,
        "next_order_admitted_nodes":7, "exact_released_note_reused":true,
        "worker_restart_unchanged":true, "release_response_loss_recovered":true,
        "native_after_root":hex::encode(client.state_root()?), "release":released,
        "wallet":wallet, "next_order_commitment":receipt.commitment().hex(),
        "next_order_matched":false, "partial_admission_cleanup_claimed":false});
    publish_result(&result, "/handoff/native-result.json")?;
    Ok(())
}
