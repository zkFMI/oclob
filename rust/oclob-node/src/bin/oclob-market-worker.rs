//! Resident native market. Financial input enters through authenticated intake,
//! not scenario files. The separate acceptance mode only observes actual work.
use oclob_node::market_journal::MarketJournal;
use oclob_node::market_network::{serve, MarketServiceConfig};
use oclob_node::market_runtime::NativeMarketRuntime;
use oclob_node::network::{
    load_secret_32, server_tls_context, ClientIdentityConfig, ClusterPublicConfig,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    if let Err(e) = run() {
        eprintln!("native market worker failed: {e}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if !(args.is_empty()
        || args.len() == 1
            && matches!(
                args[0].as_str(),
                "--initialize" | "--status" | "--acceptance"
            )
        || args.len() == 2 && args[0] == "--wait-rounds")
    {
        return Err(
            "usage: oclob-market-worker [--initialize|--status|--wait-rounds N|--acceptance]"
                .into(),
        );
    }
    let cluster: ClusterPublicConfig = read("/public/cluster.json")?;
    let config: MarketServiceConfig = read("/public/market.json")?;
    let initialize = args.first().is_some_and(|a| a == "--initialize");
    let key = load_secret_32(&config.journal_key).map_err(err)?;
    let journal = Arc::new(MarketJournal::open(
        &config.journal,
        &key,
        &cluster,
        initialize,
    )?);
    let settings: Value = journal.put(
        "settings",
        &serde_json::to_value(&config).map_err(err)?,
        1,
        u64::MAX,
    )?;
    if settings != serde_json::to_value(&config).map_err(err)? {
        return Err("market settings differ from the durable deployment".into());
    }
    if initialize {
        println!("{}", json!({"status":"initialized"}));
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "--status") {
        println!("{}", status(&journal)?);
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "--wait-rounds") {
        wait_rounds(&journal, args[1].parse().map_err(err)?)?;
        println!("{}", status(&journal)?);
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "--acceptance") {
        return acceptance(&journal);
    }
    let _lock = journal.acquire_worker()?;
    reconcile_public_book(&journal, &cluster)?;
    let coordinator: ClientIdentityConfig = read("/identity/client.json")?;
    let settlement: ClientIdentityConfig = read("/settlement/client.json")?;
    coordinator.validate().map_err(err)?;
    settlement.validate().map_err(err)?;
    let tls = server_tls_context(
        "/market-identity/tls.pem",
        "/market-identity/tls-key.pem",
        "/public/ca.pem",
    )
    .map_err(err)?;
    let listener = TcpListener::bind(("0.0.0.0", config.endpoint.port)).map_err(err)?;
    let engine = NativeMarketRuntime {
        cluster: cluster.clone(),
        coordinator,
        settlement,
        config: config.clone(),
        journal: journal.clone(),
        committee: fs::read("/handoff/native-committee.bin").map_err(err)?,
        issuer: read("/public/native-issuer.json")?,
    };
    std::thread::spawn(move || serve(listener, tls, config, cluster, journal));
    eprintln!("native market intake ready; durable progress loaded");
    let mut last_error = None;
    loop {
        match engine.pump() {
            Ok(true) => {
                last_error = None;
                eprintln!("native market completed an ordered matching round");
            }
            Ok(false) => {}
            Err(e) => {
                let digest = hex::encode(Sha256::digest(e.as_bytes()));
                if last_error.as_ref() != Some(&digest) {
                    eprintln!("native market retained pending work; error digest {digest}");
                    last_error = Some(digest);
                }
            }
        }
        if let Err(e) = reconcile_public_book(&engine.journal, &engine.cluster) {
            eprintln!(
                "public book retained; error digest {}",
                hex::encode(Sha256::digest(e.as_bytes()))
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
fn reconcile_public_book(
    journal: &MarketJournal,
    cluster: &ClusterPublicConfig,
) -> Result<(), String> {
    if let Some(done) = journal.completed()?.last() {
        let book = done
            .public_snapshot
            .as_ref()
            .ok_or("historical round lacks native depth; explicit migration required")?;
        book.verify(
            cluster,
            book.attestations
                .first()
                .ok_or("depth signatures absent")?
                .issued_at,
            book.sequence,
        )?;
        oclob_node::public_depth::publish(Path::new("/market-public/current.json"), book)?;
    }
    Ok(())
}
fn read<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, String> {
    let bytes = fs::read(path).map_err(err)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("market configuration exceeds size bound".into());
    }
    serde_json::from_slice(&bytes).map_err(err)
}
fn wait_rounds(journal: &MarketJournal, n: usize) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if journal.completed()?.len() >= n {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("resident market did not complete expected rounds".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
fn status(journal: &MarketJournal) -> Result<Value, String> {
    let rounds = journal.completed()?;
    Ok(
        json!({"completed_market_rounds":rounds.len(),"autonomously_settled_fills":rounds.iter().flat_map(|r|&r.result.slots).filter(|s|s.matched).count(),
        "completed_round_digests":rounds.iter().map(|r|hex::encode(r.certificate.digest())).collect::<Vec<_>>(),
        "transaction_ids":rounds.iter().filter_map(|r|r.transaction_id.as_ref()).collect::<Vec<_>>(),
        "canonical_roots":rounds.iter().filter_map(|r|r.canonical_root.map(hex::encode)).collect::<Vec<_>>()}),
    )
}
/// Lab observer, never an executor: assertions derive from the live service's
/// durable receipts and Docker process observations, not a replacement matcher.
fn acceptance(journal: &MarketJournal) -> Result<(), String> {
    let contract = fs::read(std::env::var("OCLOB_RESEARCH_CONTRACT").map_err(err)?).map_err(err)?;
    let manifest: Value = read(std::env::var("OCLOB_RESEARCH_MANIFEST").map_err(err)?)?;
    let hash = hex::encode(Sha256::digest(&contract));
    let depth = manifest["contract_id"] == "oclob-native-depth-v1";
    if manifest["contract_sha256"] != hash
        || (!depth && manifest["contract_id"] != "oclob-native-market-v1")
        || manifest["stage"] != "RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC"
    {
        return Err("resident market acceptance preflight failed".into());
    }
    let expected_rounds = if depth { 4 } else { 3 };
    wait_rounds(journal, expected_rounds)?;
    let rounds = journal.completed()?;
    if rounds.len() != expected_rounds
        || rounds[..expected_rounds - 1]
            .iter()
            .any(|r| r.transaction_id.is_some())
    {
        return Err("resident market did not execute expected rounds".into());
    }
    let last = &rounds[expected_rounds - 1];
    let matched = last
        .result
        .slots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.matched)
        .collect::<Vec<_>>();
    let notional = matched.iter().try_fold(0u64, |total, (_, s)| {
        total
            .checked_add(
                s.trade_price
                    .checked_mul(s.trade_quantity)
                    .ok_or("notional overflow")?,
            )
            .ok_or("notional overflow")
    })?;
    if matched.len() != 2
        || matched[0].0 != if depth { 1 } else { 0 }
        || matched[0].1.trade_price != if depth { 100 } else { 101 }
        || matched[0].1.trade_quantity != 30
        || matched[1].0 != if depth { 2 } else { 1 }
        || matched[1].1.trade_price != 100
        || matched[1].1.trade_quantity != if depth { 45 } else { 60 }
        || notional != if depth { 7500 } else { 9030 }
        || last.result.arriving_remaining != 0
        || last.finality_observations != 14
    {
        return Err(
            "secret price priority or autonomous canonical fills differ from prediction".into(),
        );
    }
    let before: Value = read("/handoff/market-before-restart.json")?;
    let after = status(journal)?;
    if before != after {
        return Err("market restart changed completed rounds or canonical settlement".into());
    }
    let observed_processes = fs::read_to_string("/handoff/market-processes.txt").map_err(err)?;
    let ids = observed_processes.split_whitespace().collect::<Vec<_>>();
    if ids.len() != 3
        || ids[0] == ids[1]
        || ids[1] == ids[2]
        || ids[0] == ids[2]
        || ids
            .iter()
            .any(|id| id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
        || fs::read_to_string("/handoff/market-crash-exit.txt")
            .map_err(err)?
            .trim()
            != "75"
    {
        return Err("actual market crash and process replacement were not observed".into());
    }
    let id = last.certificate.commitment.hex();
    let fault: Value = journal
        .get(&format!("fault-observation:{id}"))?
        .ok_or("canonical fault observation absent")?;
    let settled: Value = journal
        .get(&format!("settled:{id}"))?
        .ok_or("actual recovered canonical receipt absent")?;
    if fault != settled {
        return Err("exact native request retry produced a different canonical receipt".into());
    }
    let mut result = json!({"native_note_settlement":true,"contract_sha256":hash,"manifest_id":manifest["manifest_id"],
        "admitted_orders":expected_rounds,"completed_market_rounds":rounds.len(),"autonomously_settled_fills":matched.len(),
        "trade_notional":notional,"node_finality_observations":last.finality_observations,
        "post_match_participant_signatures":0,"restart_did_not_duplicate_settlement":true,
        "canonical_response_loss_recovered":true,"service_processes":ids,
        "native_transaction_id":last.transaction_id,"native_after_root":hex::encode(last.canonical_root.ok_or("canonical root absent")?),
        "status":"smoke_only","independent_operators":false,"wan_evidence":false});
    if depth {
        use oclob_node::public_depth::FinalizedPublicBook;
        let cluster: ClusterPublicConfig = read("/public/cluster.json")?;
        let expected = [
            vec![(101, 30)],
            vec![(100, 30), (101, 30)],
            vec![(100, 90), (101, 30)],
            vec![(100, 15), (101, 30)],
        ];
        let paths = [
            "depth-1.json",
            "depth-2.json",
            "depth-3.json",
            "depth-final.json",
        ];
        for (i, (path, levels)) in paths.iter().zip(expected).enumerate() {
            let public: FinalizedPublicBook = read(Path::new("/handoff").join(path))?;
            public.verify(&cluster, public.attestations[0].issued_at, (i + 1) as u64)?;
            if public.sequence != (i + 1) as u64
                || rounds[i].public_snapshot.as_ref() != Some(&public)
                || public
                    .levels
                    .iter()
                    .any(|v| v.side != oclob_core::Side::Sell)
                || public
                    .levels
                    .iter()
                    .map(|v| (v.price, v.quantity))
                    .collect::<Vec<_>>()
                    != levels
            {
                return Err(
                    "network public price-level snapshot differs from actual completed MPC".into(),
                );
            }
        }
        let before: FinalizedPublicBook = read("/handoff/depth-before-finality.json")?;
        let after: FinalizedPublicBook = read("/handoff/depth-after-restart.json")?;
        if Some(&before) != rounds[2].public_snapshot.as_ref()
            || Some(&after) != last.public_snapshot.as_ref()
        {
            return Err("public depth changed before finality or during completed restart".into());
        }
        result["canonically_published_depth_snapshots"] = json!(4);
        result["public_depth_stays_old_before_finality"] = json!(true);
        result["network_reader_requires_no_corporate_keys_or_journal"] = json!(true);
        result["pretrade_100_quantity"] = json!(90);
        result["posttrade_100_quantity"] = json!(15);
        result["posttrade_101_quantity"] = json!(30);
        result["public_snapshot"] = serde_json::to_value(after).map_err(err)?;
    }
    publish(Path::new("/handoff/native-result.json"), &result)?;
    println!("{}", result);
    Ok(())
}
fn publish(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(err)?;
    let temp = path.with_extension(format!("{}.pending", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(err)?;
    file.write_all(&bytes).map_err(err)?;
    file.sync_all().map_err(err)?;
    fs::hard_link(&temp, path).map_err(err)?;
    fs::remove_file(&temp).map_err(err)?;
    File::open(path.parent().ok_or("publication parent absent")?)
        .map_err(err)?
        .sync_all()
        .map_err(err)
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
