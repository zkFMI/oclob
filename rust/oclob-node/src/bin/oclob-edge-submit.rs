//! Demo corporate module: create a private order and fan out seven shares.

use ed25519_dalek::SigningKey;
use oclob_core::{Digest32, SecretOrder, Side, TimeInForce};
use oclob_dekyx::deterministic_demo_environment;
use oclob_edge::{
    settlement_capability_commitment, EdgeOrderBundle, NodeEncryptionKey,
    SealedSettlementCapability, MPC_PARTIES,
};
use oclob_node::corporate::{
    build_reserved_delivery, finalize_reservation, prepare_reservation_from_note, verify_finalized,
    CorporateNativeConfig, PreparedCorporateReserve,
};
use oclob_node::corporate_journal::{
    NativeCorporateJournal, StoredCorporateDelivery, StoredCorporateIntent,
};
use oclob_node::edge_client::{EdgeAdmissionReceipt, EdgeDistributor, PreparedEdgeDelivery};
use oclob_node::network::{
    client_tls_context, load_secret_32, ClientIdentityConfig, ClusterPublicConfig,
};
use oclob_settlement::pretrade::FinalizedReservation;
use qomm_zkpi::handles::Identity;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const VENUE_DOMAIN: &[u8] = b"defmi:oclob:v1";

#[derive(Clone, Copy)]
enum Scenario {
    Maker,
    Taker,
}

/// Private corporate input. This file is never sent to the coordinator.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct NativeOrderInstruction {
    side: Side,
    limit_price: u64,
    quantity: u64,
    time_in_force: TimeInForce,
    valid_for_seconds: u64,
    source_note: Option<String>,
}

impl NativeOrderInstruction {
    fn source(&self) -> Result<Option<[u8; 32]>, String> {
        self.source_note
            .as_ref()
            .map(|s| {
                hex::decode(s)
                    .map_err(|_| "funding note must be hexadecimal".to_string())?
                    .try_into()
                    .map_err(|_| "funding note must contain 32 bytes".into())
            })
            .transpose()
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("oclob-edge-submit failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (cluster_path, identity_path, handoff_path, settlement_handoff_path, scenario) =
        parse_args()?;
    let cluster: ClusterPublicConfig = read_json(&cluster_path)?;
    cluster.validate().map_err(|error| error.to_string())?;
    let identity: ClientIdentityConfig = read_json(&identity_path)?;
    identity.validate().map_err(|error| error.to_string())?;
    let native = std::env::var_os("OCLOB_NATIVE_RESERVATION_CONFIG")
        .map(|path| {
            let path = PathBuf::from(path);
            if fs::symlink_metadata(&path)
                .map_err(|error| error.to_string())?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err("native funding configuration must be owner-only".to_string());
            }
            read_json::<CorporateNativeConfig>(&path)
        })
        .transpose()?;
    if let Some(config) = native {
        return run_native(
            &cluster,
            &identity,
            &config,
            &handoff_path,
            &settlement_handoff_path,
            scenario,
        );
    }
    // Each order gets an unlinkable signing key. The long-lived corporate mTLS
    // identity authorizes transport admission, while DeKYX proves eligibility;
    // neither the coordinator nor the public ordering certificate receives the
    // corporate application key.
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
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
    let (_, issuer) =
        deterministic_demo_environment(&cluster.market_id).map_err(|error| error.to_string())?;
    let subject_seed = match scenario {
        Scenario::Maker => 11,
        Scenario::Taker => 22,
    };
    let wallet = issuer
        .issue_wallet(
            subject_seed,
            match scenario {
                Scenario::Maker => b"distributed-maker".as_slice(),
                Scenario::Taker => b"distributed-taker".as_slice(),
            },
            &mut rand::rngs::OsRng,
        )
        .map_err(|error| error.to_string())?;
    let settlement_handle = Identity::from_seed(match scenario {
        Scenario::Maker => [11; 32],
        Scenario::Taker => [22; 32],
    })
    .handle(VENUE_DOMAIN);
    let order = demo_order(
        &cluster.market_id,
        scenario,
        settlement_handle.point.compress().to_bytes(),
        wallet.subject_nullifier(),
    )?;
    let eligibility_commitment = hidden_eligibility_commitment(&order);
    let settlement_capability_commitment =
        settlement_capability_commitment(&order, &signing_key.verifying_key().to_bytes());
    let bundle = EdgeOrderBundle::create_with_settlement_handle(
        &order,
        &settlement_handle,
        eligibility_commitment,
        settlement_capability_commitment,
        &signing_key,
        &node_keys,
        &mut rand::rngs::OsRng,
    )
    .map_err(|error| error.to_string())?;
    let eligibility_evidence = wallet
        .present(
            bundle.manifest().commitment.0,
            random_digest(),
            order.expires_at(),
            &mut rand::rngs::OsRng,
        )
        .map_err(|error| error.to_string())?;
    let eligibility_wire =
        serde_json::to_vec(&eligibility_evidence).map_err(|error| error.to_string())?;
    let settlement_envelope = bundle
        .seal_settlement_capability(
            &order,
            eligibility_commitment,
            &eligibility_wire,
            &signing_key,
            &mut rand::rngs::OsRng,
        )
        .map_err(|error| error.to_string())?;
    let distributor = EdgeDistributor::new(cluster, tls, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    let receipt = distributor
        .submit(bundle)
        .map_err(|error| error.to_string())?;
    write_handoff(&handoff_path, &receipt)?;
    write_settlement_handoff(&settlement_handoff_path, &settlement_envelope)?;
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

fn run_native(
    cluster: &ClusterPublicConfig,
    identity: &ClientIdentityConfig,
    config: &CorporateNativeConfig,
    handoff: &Path,
    authority_handoff: &Path,
    scenario: Scenario,
) -> Result<(), String> {
    let journal_path = std::env::var_os("OCLOB_CORPORATE_JOURNAL")
        .ok_or("native intake requires a durable corporate journal path")?;
    let journal_key = std::env::var_os("OCLOB_CORPORATE_JOURNAL_KEY")
        .ok_or("native intake requires a private corporate journal key file")?;
    let request_id = std::env::var("OCLOB_CORPORATE_REQUEST_ID")
        .map_err(|_| "native intake requires a stable corporate request ID")?;
    let secret = load_secret_32(PathBuf::from(journal_key)).map_err(|e| e.to_string())?;
    let journal =
        NativeCorporateJournal::open(PathBuf::from(journal_path), &secret, config, cluster)?;
    if std::env::var("OCLOB_NATIVE_RECOVER_WALLET").ok().as_deref() == Some("1") {
        return recover_native_wallet(config, identity, &journal, handoff, scenario);
    }
    let instruction: Option<NativeOrderInstruction> =
        std::env::var_os("OCLOB_CORPORATE_ORDER_FILE")
            .map(|p| {
                let p = PathBuf::from(p);
                if fs::symlink_metadata(&p)
                    .map_err(|e| e.to_string())?
                    .permissions()
                    .mode()
                    & 0o077
                    != 0
                {
                    return Err("corporate order file must be owner-only".into());
                }
                read_json(&p)
            })
            .transpose()?;
    if let Some(input) = &instruction {
        let asset = match input.side {
            Side::Buy => oclob_settlement::canonical_cash_asset_id(),
            Side::Sell => oclob_settlement::canonical_securities_asset_id(&cluster.market_id),
        };
        if asset != config.asset_id || !(10..=3600).contains(&input.valid_for_seconds) {
            return Err("order asset or validity is outside the corporate configuration".into());
        }
        input.source()?;
    }
    let input_digest = if let Some(input) = &instruction {
        NativeCorporateJournal::input_digest(&(
            "oclob-corporate-order-v1",
            &cluster.market_id,
            input,
        ))?
    } else {
        NativeCorporateJournal::input_digest(&(
            "oclob-demo-order-v1",
            &cluster.market_id,
            match scenario {
                Scenario::Maker => "sell-60-at-100-gtc",
                Scenario::Taker => "buy-40-at-101-ioc",
            },
        ))?
    };
    let handle = Identity::from_seed(config.identity_seed).handle(VENUE_DOMAIN);
    let (_, issuer) =
        deterministic_demo_environment(&cluster.market_id).map_err(|e| e.to_string())?;
    let (subject, label) = match scenario {
        Scenario::Maker => (11, b"distributed-maker".as_slice()),
        Scenario::Taker => (22, b"distributed-taker".as_slice()),
    };
    let wallet = issuer
        .issue_wallet(subject, label, &mut rand::rngs::OsRng)
        .map_err(|e| e.to_string())?;
    let intent = if let Some(intent) = journal.intent(&request_id)? {
        intent
    } else {
        let order = if let Some(input) = &instruction {
            SecretOrder::new_with_dekyx_nullifier(
                &cluster.market_id,
                input.side,
                input.limit_price,
                input.quantity,
                input.time_in_force,
                unix_seconds()?
                    .checked_add(input.valid_for_seconds)
                    .ok_or("order expiry overflow")?,
                handle.point.compress().to_bytes(),
                wallet.subject_nullifier(),
                random_digest(),
                random_digest(),
            )
            .map_err(|e| e.to_string())?
        } else {
            demo_order(
                &cluster.market_id,
                scenario,
                handle.point.compress().to_bytes(),
                wallet.subject_nullifier(),
            )?
        };
        let intent = StoredCorporateIntent {
            input_digest,
            order_wire: order.to_secret_wire(),
            signing_key: SigningKey::generate(&mut rand::rngs::OsRng).to_bytes(),
            eligibility_commitment: hidden_eligibility_commitment(&order),
            accepted_at: unix_seconds()?,
            expires_at: order.expires_at(),
        };
        journal.save_intent(&request_id, &intent)?
    };
    if intent.input_digest != input_digest {
        return Err("corporate request ID names a different order instruction".into());
    }
    journal.require_turn(&request_id)?;
    let order = SecretOrder::from_secret_wire(&intent.order_wire).map_err(|e| e.to_string())?;
    let prepared: PreparedCorporateReserve =
        if let Some(saved) = journal.stage(&request_id, "reserve")? {
            saved
        } else {
            let funding = journal.latest_funding(config)?;
            let pending = prepare_reservation_from_note(
                &funding,
                identity,
                &wallet,
                &order,
                &handle,
                intent.eligibility_commitment,
                &SigningKey::from_bytes(&intent.signing_key),
                unix_seconds()?,
                instruction
                    .as_ref()
                    .map(|i| i.source())
                    .transpose()?
                    .flatten(),
            )?;
            journal.save_stage(&request_id, "reserve", &pending, &intent)?
        };
    prepared.validate(config)?;
    if prepared.order_wire != intent.order_wire
        || prepared.signing_key != intent.signing_key
        || prepared.eligibility_commitment != intent.eligibility_commitment
    {
        return Err("saved reserve belongs to another durable corporate intent".into());
    }
    let reserve_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&prepared.request).map_err(|e| e.to_string())?).into();
    let completed: Option<EdgeAdmissionReceipt> = journal.stage(&request_id, "receipt")?;
    let delivery: StoredCorporateDelivery = if let Some(saved) =
        journal.stage(&request_id, "delivery")?
    {
        saved
    } else {
        let finalized: FinalizedReservation =
            if let Some(saved) = journal.stage(&request_id, "admission")? {
                verify_finalized(config, identity, &prepared, &saved, unix_seconds()?)?;
                saved
            } else {
                let finalized = finalize_reservation(config, identity, &prepared, unix_seconds()?)?;
                recovery_test_stop("after-reserve-before-journal")?;
                journal.save_stage(&request_id, "admission", &finalized, &intent)?
            };
        // Update private openings only after independently reading canonical acceptance.
        journal.save_reserved_witness(&prepared)?;
        let node_keys: [NodeEncryptionKey; MPC_PARTIES] = cluster
            .nodes
            .iter()
            .map(|n| n.share_encryption_key.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "cluster must have seven node keys")?;
        let (bundle, authority) = build_reserved_delivery(
            config,
            &prepared,
            &finalized,
            &handle,
            &node_keys,
            unix_seconds()?,
        )?;
        journal.save_stage(
            &request_id,
            "delivery",
            &StoredCorporateDelivery {
                reserve_digest,
                delivery: PreparedEdgeDelivery::from_bundle(bundle),
                authority,
            },
            &intent,
        )?
    };
    if delivery.reserve_digest != reserve_digest {
        return Err("saved ciphertexts name another reserve request".into());
    }
    // A crash after publication must never overwrite a different authority.
    publish_unchanged(authority_handoff, &delivery.authority)?;
    let reused_receipt = completed.is_some();
    let receipt = if let Some(receipt) = completed {
        receipt
    } else {
        let tls = client_tls_context(
            &identity.tls_certificate,
            &identity.tls_private_key,
            &identity.tls_ca,
        )
        .map_err(|e| e.to_string())?;
        let distributor = EdgeDistributor::new(cluster.clone(), tls, Duration::from_secs(30))
            .map_err(|e| e.to_string())?;
        let receipt = distributor
            .submit_prepared(&delivery.delivery)
            .map_err(|e| e.to_string())?;
        recovery_test_stop("after-node-admission-before-journal")?;
        journal.save_receipt(&request_id, &receipt, &delivery, cluster, &intent)?
    };
    journal.verify_receipt(&receipt, &delivery, cluster, intent.accepted_at)?;
    publish_unchanged(handoff, &receipt)?;
    if let Some(source) = instruction
        .as_ref()
        .map(|i| i.source())
        .transpose()?
        .flatten()
    {
        oclob_node::native_wallet::verify_selected_funding_spent(
            config, identity, &prepared, source,
        )?;
        publish_unchanged(
            &handoff.with_extension("corporate.json"),
            &json!({
                "order_commitment": receipt.commitment().hex(),
                "selected_funding_note_spent_verified": true,
                "canonical_reserve_verified": true,
                "facility_sequence": prepared.facility_after.sequence,
            }),
        )?;
    }
    println!(
        "{}",
        json!({"status": "pretrade_reserved_and_admitted", "nodes": MPC_PARTIES,
        "order_commitment": receipt.commitment().hex(), "native_pretrade": true, "durable_corporate_journal": true,
        "reused_completed_receipt": reused_receipt})
    );
    Ok(())
}

fn recover_native_wallet(
    config: &CorporateNativeConfig,
    identity: &ClientIdentityConfig,
    journal: &NativeCorporateJournal,
    handoff: &Path,
    scenario: Scenario,
) -> Result<(), String> {
    let recovered = oclob_node::native_wallet::recover_wallet(config, identity, journal)?;
    // Fixed financial assertions and next-order construction are explicitly
    // confined to the opt-in lab acceptance, not the reusable recovery API.
    if std::env::var("OCLOB_NATIVE_WALLET_ACCEPTANCE")
        .ok()
        .as_deref()
        != Some("1")
    {
        println!(
            "{}",
            json!({"status": "wallet_recovered", "notes": recovered.notes.len(),
            "facility_sequence": recovered.facility.sequence})
        );
        return Ok(());
    }
    let expected = match scenario {
        Scenario::Maker => [60, 20, 40],
        Scenario::Taker => [6000, 0, 4000],
    };
    let expected_notes = match scenario {
        Scenario::Maker => 1,
        Scenario::Taker => 2,
    };
    if recovered.facility.values != expected
        || recovered.facility.sequence != 2
        || recovered.notes.len() != expected_notes
    {
        return Err("lab wallet recovery differs from the executed native fill".into());
    }
    if matches!(scenario, Scenario::Taker) {
        let note = recovered
            .own_asset_refund
            .ok_or("actual cash refund note was not recovered")?;
        let instruction = NativeOrderInstruction {
            side: Side::Buy,
            limit_price: 40,
            quantity: 1,
            time_in_force: TimeInForce::GoodTilCancelled,
            valid_for_seconds: 600,
            source_note: Some(hex::encode(note)),
        };
        publish_unchanged(Path::new("/corporate/reuse-order.json"), &instruction)?;
    }
    let report = json!({"wallet_recovered": true, "notes": recovered.notes.len(),
        "facility_sequence": recovered.facility.sequence, "facility_id": hex::encode(config.facility_id),
        "expected_private_balances_verified": true, "after_root": hex::encode(recovered.after_root),
        "canonical_notes": recovered.notes.iter().map(|n| hex::encode(n.note_id)).collect::<Vec<_>>()});
    publish_unchanged(&handoff.with_extension("wallet.json"), &report)?;
    println!("{}", report);
    Ok(())
}

/// Explicit opt-in in the laboratory CLI, never a remote protocol flag. The
/// process exits before storing the response, leaving the exact request durable.
fn recovery_test_stop(point: &str) -> Result<(), String> {
    if std::env::var("OCLOB_NATIVE_RECOVERY_TEST_STOP")
        .ok()
        .as_deref()
        == Some(point)
    {
        eprintln!("native recovery test stopped at {point}; durable request retained");
        std::process::exit(75);
    }
    Ok(())
}

fn publish_unchanged<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    if path.exists() {
        let existing: serde_json::Value = read_json(path)?;
        if existing != serde_json::to_value(value).map_err(|e| e.to_string())? {
            return Err("public handoff already contains a different request".into());
        }
        return Ok(());
    }
    let parent = path.parent().ok_or("handoff needs a parent directory")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let pending = parent.join(format!(
        ".oclob-handoff-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        match fs::hard_link(&pending, path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing: serde_json::Value = read_json(path)?;
                if existing != serde_json::to_value(value).map_err(|e| e.to_string())? {
                    return Err("another writer published a different request".into());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
        File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())
    })();
    let _ = fs::remove_file(pending);
    result
}

fn demo_order(
    market: &str,
    scenario: Scenario,
    participant: Digest32,
    dekyx_nullifier: Digest32,
) -> Result<SecretOrder, String> {
    let now = unix_seconds()?;
    let mut nonce = [0_u8; 32];
    let mut salt = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let (side, price, quantity, tif) = match scenario {
        Scenario::Maker => (Side::Sell, 100, 60, TimeInForce::GoodTilCancelled),
        Scenario::Taker => (Side::Buy, 101, 40, TimeInForce::ImmediateOrCancel),
    };
    SecretOrder::new_with_dekyx_nullifier(
        market,
        side,
        price,
        quantity,
        tif,
        now.saturating_add(600),
        participant,
        dekyx_nullifier,
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

fn write_handoff(path: &Path, receipt: &EdgeAdmissionReceipt) -> Result<(), String> {
    write_json_exclusive(path, receipt)
}

fn write_settlement_handoff(
    path: &Path,
    capability: &SealedSettlementCapability,
) -> Result<(), String> {
    write_json_exclusive(path, capability)
}

fn write_json_exclusive<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
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

fn parse_args() -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, Scenario), String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 10
        || args[0] != "--cluster"
        || args[2] != "--identity"
        || args[4] != "--handoff"
        || args[6] != "--settlement-handoff"
        || args[8] != "--scenario"
    {
        return Err("usage: oclob-edge-submit --cluster PATH --identity PATH --handoff PATH --settlement-handoff PATH --scenario maker|taker".into());
    }
    let scenario = match args[9].to_str() {
        Some("maker") => Scenario::Maker,
        Some("taker") => Scenario::Taker,
        _ => return Err("scenario must be maker or taker".into()),
    };
    Ok((
        PathBuf::from(&args[1]),
        PathBuf::from(&args[3]),
        PathBuf::from(&args[5]),
        PathBuf::from(&args[7]),
        scenario,
    ))
}

fn random_digest() -> Digest32 {
    let mut value = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut value);
    value
}

fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}
