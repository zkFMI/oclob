//! Corporate-side native dispatcher. No issuer key or coordinator identity.
use oclob_node::corporate::CorporateNativeConfig;
use oclob_node::corporate_dispatch::{DispatchProgress, NativeCorporateDispatch};
use oclob_node::corporate_journal::NativeCorporateJournal;
use oclob_node::corporate_submission::SubmissionCheckpoint;
use oclob_node::network::{load_secret_32, ClientIdentityConfig, ClusterPublicConfig};
use serde::de::DeserializeOwned;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(error) = run() {
        eprintln!("corporate worker failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(args.is_empty()
        || args.len() == 1
            && matches!(
                args[0].as_str(),
                "--once" | "--status" | "--preparation-status" | "--initialize"
            )
        || args.len() == 2 && matches!(args[0].as_str(), "--wait-admitted" | "--wait-reconciled"))
    {
        return Err(
            "usage: oclob-corporate-worker [--once|--status|--preparation-status|--initialize|--wait-admitted ID|--wait-reconciled ID]"
                .into(),
        );
    }
    let cluster: ClusterPublicConfig = read(Path::new("/public/cluster.json"), false)?;
    let identity: ClientIdentityConfig = read(Path::new("/identity/client.json"), true)?;
    cluster.validate().map_err(|e| e.to_string())?;
    identity.validate().map_err(|e| e.to_string())?;
    let config: CorporateNativeConfig = read(&env_path("OCLOB_NATIVE_RESERVATION_CONFIG")?, true)?;
    let journal_path = env_path("OCLOB_CORPORATE_JOURNAL")?;
    let secret =
        load_secret_32(env_path("OCLOB_CORPORATE_JOURNAL_KEY")?).map_err(|e| e.to_string())?;
    let journal = NativeCorporateJournal::open(&journal_path, &secret, &config, &cluster)?;
    let queue_path = journal_path.with_file_name("dispatch.enc");
    if args.first().is_some_and(|arg| arg == "--initialize") {
        NativeCorporateDispatch::initialize(queue_path, &secret)?;
        return Ok(());
    }
    let queue = NativeCorporateDispatch::open(queue_path, &secret)?;
    if args
        .first()
        .is_some_and(|arg| arg == "--preparation-status")
    {
        let mut entries = Vec::new();
        for entry in queue.summaries()? {
            let authorization = journal.authorization(&entry.request_id)?;
            if let Some(value) = &authorization {
                value.validate(&config)?;
            }
            entries.push(serde_json::json!({"request_id":entry.request_id,
                "authorization_digest":authorization.as_ref().map(|a| a.digest().map(hex::encode)).transpose()?,
                "order_commitment":authorization.as_ref().map(|a| oclob_core::SecretOrder::from_secret_wire(&a.order_wire).map(|o|o.commitment().hex()).map_err(|e|e.to_string())).transpose()?,
                "funding_prepared":journal.stage::<oclob_node::corporate::PreparedCorporateReserve>(&entry.request_id,"reserve")?.is_some(),
                "admitted":journal.stage::<oclob_node::edge_client::EdgeAdmissionReceipt>(&entry.request_id,"receipt")?.is_some(),
                "ended":journal.ended_authorization(&entry.request_id)?.is_some()}));
        }
        println!(
            "{}",
            serde_json::to_string(&entries).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--status") {
        println!(
            "{}",
            serde_json::to_string(&queue.summaries()?).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--wait-reconciled") {
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        loop {
            if let Some(entry) = queue
                .summaries()?
                .into_iter()
                .find(|entry| entry.request_id == args[1])
            {
                if matches!(
                    entry.state,
                    zkpi_defmi_sdk::corporate::OutboxState::AbortedBeforeReserve { .. }
                ) {
                    if let Some(ended) = journal.ended_authorization(&args[1])? {
                        let status = match ended.reason {
                            oclob_node::corporate_journal::AuthorizationEndReason::Expired => "never_reserved",
                            oclob_node::corporate_journal::AuthorizationEndReason::InsufficientFunding => "funding_rejected",
                        };
                        println!(
                            "{}",
                            serde_json::json!({"status":status,"request_id":args[1],
                            "funding_prepared":journal.stage::<oclob_node::corporate::PreparedCorporateReserve>(&args[1],"reserve")?.is_some()})
                        );
                        return Ok(());
                    }
                }
                if let Some(result) = journal.completed_expiry(&args[1])? {
                    use oclob_node::corporate_expiry::ExpiryOutcome;
                    use zkpi_defmi_sdk::corporate::OutboxState;
                    let report = match (result.outcome, entry.state) {
                        (
                            ExpiryOutcome::NeverReserved { state_root },
                            OutboxState::AbortedBeforeReserve { .. },
                        ) => Some(
                            serde_json::json!({"status":"never_reserved", "state_root":hex::encode(state_root)}),
                        ),
                        (
                            ExpiryOutcome::Released {
                                release,
                                transaction_id,
                                block_id,
                                height,
                                after_root,
                            },
                            OutboxState::Released { receipt },
                        ) if receipt.transaction_id == transaction_id
                            && receipt.ledger_height == height
                            && receipt.request_digest == entry.request_digest =>
                        {
                            Some(
                                serde_json::json!({"status":"released", "transaction_id":transaction_id,
                                "block_id":block_id, "height":height, "hold_id":hex::encode(release.hold_id),
                                "statement":hex::encode(release.signing_message()?),
                                "before_root":hex::encode(release.before_root), "after_root":hex::encode(after_root)}),
                            )
                        }
                        _ => None,
                    };
                    if let Some(mut report) = report {
                        report["request_id"] = serde_json::json!(args[1]);
                        println!("{report}");
                        return Ok(());
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("timed out waiting for canonical expiry reconciliation".into());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if args.first().is_some_and(|arg| arg == "--wait-admitted") {
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        loop {
            if queue.summaries()?.iter().any(|entry| {
                entry.request_id == args[1]
                    && matches!(
                        entry.state,
                        zkpi_defmi_sdk::corporate::OutboxState::MpcAdmitted { .. }
                    )
            }) {
                let receipt: oclob_node::edge_client::EdgeAdmissionReceipt = journal
                    .stage(&args[1], "receipt")?
                    .ok_or("queue admission has no durable node receipt")?;
                let delivery = journal
                    .stage(&args[1], "delivery")?
                    .ok_or("queue admission has no delivery")?;
                let intent = journal
                    .intent(&args[1])?
                    .ok_or("queue admission has no intent")?;
                journal.verify_receipt(&receipt, &delivery, &cluster, intent.accepted_at)?;
                println!(
                    "{}",
                    serde_json::json!({"status":"admitted", "request_id":args[1], "receipt_digest":hex::encode(receipt.receipt_digest)})
                );
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err("timed out waiting for actual worker admission".into());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let _worker_guard = queue.acquire_worker()?;
    let mut previous = String::new();
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let progress = queue.pump(&config, &identity, &cluster, &journal, now, 2, |point| {
            let name = match point {
                SubmissionCheckpoint::ReserveObservedBeforeJournal => {
                    "after-reserve-before-journal"
                }
                SubmissionCheckpoint::NodesAcknowledgedBeforeJournal => {
                    "after-node-admission-before-journal"
                }
                SubmissionCheckpoint::ExpiryObservedBeforeJournal => "after-expiry-before-journal",
            };
            // Explicit lab process fault only, not a remote dispatch/RPC field.
            if std::env::var("OCLOB_NATIVE_RECOVERY_TEST_STOP")
                .ok()
                .as_deref()
                == Some(name)
            {
                eprintln!("native worker recovery test stopped at {name}; exact request retained");
                println!(
                    "{}",
                    serde_json::json!({"status":"checkpoint_stop", "checkpoint":name})
                );
                std::process::exit(75);
            }
            Ok(())
        })?;
        let line = serde_json::to_string(&progress).map_err(|e| e.to_string())?;
        if line != previous {
            println!("{line}");
            previous = line;
        }
        if args.first().is_some_and(|arg| arg == "--once") {
            return Ok(());
        }
        if matches!(
            progress,
            DispatchProgress::ReleaseReconciliationRequired { .. }
                | DispatchProgress::ManualReviewRequired { .. }
        ) {
            // No synthetic success when an expired, possibly reserved job still
            // needs its canonical release path. The durable state stays pending.
            std::thread::sleep(Duration::from_secs(10));
        } else {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

fn env_path(name: &str) -> Result<PathBuf, String> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required"))
}

fn read<T: DeserializeOwned>(path: &Path, private: bool) -> Result<T, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "configured input cannot be read")?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.len() == 0
        || meta.len() > 1024 * 1024
        || private && meta.permissions().mode() & 0o077 != 0
    {
        return Err("configured input is not a bounded safe file".into());
    }
    serde_json::from_slice(&fs::read(path).map_err(|_| "configured input cannot be read")?)
        .map_err(|_| "configured input is malformed".into())
}
