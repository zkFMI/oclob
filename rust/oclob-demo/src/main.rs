#![forbid(unsafe_code)]

use oclob_core::application_crypto::SigningKey;
use oclob_core::{authorize_order, SecretOrder, Side, TimeInForce};
use oclob_dekyx::deterministic_demo_environment;
use oclob_service::OclobService;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;

const MARKET: &str = "JGB10Y-JPY";
const NOW: u64 = 1_000;

#[derive(Debug, Deserialize)]
struct ResearchManifest {
    manifest_id: String,
    contract_id: String,
    contract_sha256: String,
    stage: String,
    point_prediction: PointPrediction,
}

#[derive(Debug, Deserialize)]
struct PointPrediction {
    complete_acceptance_path: u8,
    wall_ms_excluding_toolchain_build: u64,
}

#[derive(Debug, Serialize)]
struct TimelineEvent {
    stage: &'static str,
    public_information: String,
}

#[derive(Debug, Serialize)]
struct RoughReceipt {
    receipt_version: u32,
    contract_id: String,
    contract_sha256: String,
    manifest_id: String,
    stage: String,
    verdict: &'static str,
    complete_acceptance_path: u8,
    predicted_wall_ms: u64,
    observed_wall_ms: f64,
    resting_order_certificate_signers: usize,
    arriving_order_certificate_signers: usize,
    mpc_protocol: String,
    mpc_parties: usize,
    mpc_all_parties_agreed: bool,
    mpc_compile_ms: f64,
    mpc_execution_ms: f64,
    matched_price: u64,
    matched_quantity: u64,
    aggregate_resting_quantity_after: u64,
    transition_attestations: usize,
    threshold_amount_range: bool,
    threshold_price_range: bool,
    settlement_authorization_quorum: usize,
    post_match_participant_signatures: usize,
    atomic_securities_change: bool,
    atomic_cash_change: bool,
    replay_rejected: bool,
    solvent: bool,
    canonical_state_root: String,
    canonical_receipt_digest: String,
    timeline: Vec<TimelineEvent>,
    limitations: Vec<&'static str>,
}

struct Options {
    contract: PathBuf,
    manifest: PathBuf,
    receipt: PathBuf,
    ledger: PathBuf,
    mp_spdz_root: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("OCLOB rough E2E rejected: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DemoError> {
    let options = parse_options()?;
    let contract_bytes = fs::read(&options.contract)?;
    let contract_sha256 = hex::encode(Sha256::digest(&contract_bytes));
    let contract: serde_json::Value = serde_json::from_slice(&contract_bytes)?;
    let manifest_bytes = fs::read(&options.manifest)?;
    let manifest: ResearchManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.contract_sha256 != contract_sha256
        || contract
            .get("contract_id")
            .and_then(serde_json::Value::as_str)
            != Some(manifest.contract_id.as_str())
        || manifest.stage != "RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC"
        || manifest.point_prediction.complete_acceptance_path != 1
    {
        return Err(DemoError::ResearchGate(
            "contract, manifest, stage, or sealed prediction does not match".into(),
        ));
    }

    let started = Instant::now();
    let (eligibility, eligibility_issuer) = deterministic_demo_environment(MARKET)
        .map_err(|error| DemoError::Execution(error.to_string()))?;
    let seller_eligibility = eligibility_issuer
        .issue_wallet(11, b"demo-seller", &mut OsRng)
        .map_err(|error| DemoError::Execution(error.to_string()))?;
    let buyer_eligibility = eligibility_issuer
        .issue_wallet(22, b"demo-buyer", &mut OsRng)
        .map_err(|error| DemoError::Execution(error.to_string()))?;
    let mut service = OclobService::new(MARKET, &options.mp_spdz_root, eligibility)
        .map_err(|error| DemoError::Execution(error.to_string()))?;
    let (seller_handle, buyer_handle) = service.demo_participant_handles();
    let maker_key = SigningKey::from_bytes(&[41; 64]);
    let taker_key = SigningKey::from_bytes(&[42; 64]);
    let resting = SecretOrder::new_with_dekyx_nullifier(
        MARKET,
        Side::Sell,
        100,
        100,
        TimeInForce::GoodTilCancelled,
        2_000,
        seller_handle,
        seller_eligibility.subject_nullifier(),
        [1; 32],
        [31; 32],
    )?;
    let resting_authority = authorize_order(&resting, 2_100, &maker_key)?;
    let resting_eligibility = seller_eligibility
        .present(resting.commitment().0, [61; 32], 2_000, &mut OsRng)
        .map_err(|error| DemoError::Execution(error.to_string()))?;
    let resting_receipt = service
        .submit(resting, resting_authority, resting_eligibility, NOW)
        .map_err(|error| DemoError::Execution(error.to_string()))?;
    let arriving = SecretOrder::new_with_dekyx_nullifier(
        MARKET,
        Side::Buy,
        101,
        40,
        TimeInForce::ImmediateOrCancel,
        2_000,
        buyer_handle,
        buyer_eligibility.subject_nullifier(),
        [2; 32],
        [32; 32],
    )?;
    let arriving_authority = authorize_order(&arriving, 2_100, &taker_key)?;
    let arriving_eligibility = buyer_eligibility
        .present(arriving.commitment().0, [62; 32], 2_000, &mut OsRng)
        .map_err(|error| DemoError::Execution(error.to_string()))?;
    let execution = service
        .submit(arriving, arriving_authority, arriving_eligibility, NOW)
        .map_err(|error| DemoError::Execution(error.to_string()))?;
    let fill = execution
        .book_transition
        .fill
        .as_ref()
        .ok_or_else(|| DemoError::Acceptance("crossing order produced no fill".into()))?;
    let settlement = execution
        .settlement
        .as_ref()
        .ok_or_else(|| DemoError::Acceptance("crossing order produced no settlement".into()))?;
    let aggregate_resting_quantity_after = execution
        .book_transition
        .public_after
        .levels
        .iter()
        .filter(|level| level.side == Side::Sell && level.price == 100)
        .map(|level| level.quantity)
        .sum::<u64>();
    let atomic_securities_change =
        settlement.securities_before_root != settlement.securities_after_root;
    let atomic_cash_change = settlement.cash_before_root != settlement.cash_after_root;
    let accepted = resting_receipt.certificate.votes.len() == 5
        && execution.certificate.votes.len() == 5
        && execution.mpc.parties == 7
        && execution.mpc.all_parties_agreed
        && fill.price == 100
        && fill.quantity == 40
        && aggregate_resting_quantity_after == 60
        && execution.transition_proof.attestations.len() == 5
        && settlement.amount_range_is_threshold
        && settlement.price_range_is_threshold
        && settlement.members.len() == 1
        && settlement.settlement_authorization_quorum == 3
        && settlement.post_match_participant_signatures == 0
        && atomic_securities_change
        && atomic_cash_change
        && settlement.replay_rejected
        && settlement.solvent
        && execution.book_transition.private_before_root
            != execution.book_transition.private_after_root
        && execution.book_transition.public_before_root
            != execution.book_transition.public_after.state_root;
    if !accepted {
        return Err(DemoError::Acceptance(
            "one or more preregistered functional gates failed".into(),
        ));
    }
    let receipt = RoughReceipt {
        receipt_version: 2,
        contract_id: manifest.contract_id,
        contract_sha256,
        manifest_id: manifest.manifest_id,
        stage: manifest.stage,
        verdict: "accepted",
        complete_acceptance_path: 1,
        predicted_wall_ms: manifest.point_prediction.wall_ms_excluding_toolchain_build,
        observed_wall_ms: started.elapsed().as_secs_f64() * 1_000.0,
        resting_order_certificate_signers: resting_receipt.certificate.votes.len(),
        arriving_order_certificate_signers: execution.certificate.votes.len(),
        mpc_protocol: execution.mpc.protocol,
        mpc_parties: execution.mpc.parties,
        mpc_all_parties_agreed: execution.mpc.all_parties_agreed,
        mpc_compile_ms: execution.mpc.compile_ms,
        mpc_execution_ms: execution.mpc.execution_ms,
        matched_price: fill.price,
        matched_quantity: fill.quantity,
        aggregate_resting_quantity_after,
        transition_attestations: execution.transition_proof.attestations.len(),
        threshold_amount_range: settlement.amount_range_is_threshold,
        threshold_price_range: settlement.price_range_is_threshold,
        settlement_authorization_quorum: settlement.settlement_authorization_quorum,
        post_match_participant_signatures: settlement.post_match_participant_signatures,
        atomic_securities_change,
        atomic_cash_change,
        replay_rejected: settlement.replay_rejected,
        solvent: settlement.solvent,
        canonical_state_root: hex::encode(settlement.canonical_state_root),
        canonical_receipt_digest: hex::encode(settlement.canonical_receipt_digest),
        timeline: vec![
            TimelineEvent {
                stage: "maker_authority",
                public_information: "signed commitment only; no order field".into(),
            },
            TimelineEvent {
                stage: "resting_order_certificate",
                public_information: format!(
                    "sequence={} signers={}",
                    resting_receipt.certificate.sequence,
                    resting_receipt.certificate.votes.len()
                ),
            },
            TimelineEvent {
                stage: "public_book_after_resting_commit",
                public_information:
                    "no-cross MPC result admitted the GTC remainder; only its aggregate level became public"
                        .into(),
            },
            TimelineEvent {
                stage: "taker_authority",
                public_information: "signed commitment only; no order field".into(),
            },
            TimelineEvent {
                stage: "arriving_order_certificate",
                public_information: format!(
                    "sequence={} signers={}",
                    execution.certificate.sequence,
                    execution.certificate.votes.len()
                ),
            },
            TimelineEvent {
                stage: "mpc_match_completed",
                public_information: format!(
                    "post-match price={} quantity={}",
                    fill.price, fill.quantity
                ),
            },
            TimelineEvent {
                stage: "zkpi_defmi_finality",
                public_information: "threshold proofs, atomic DvP and canonical roots accepted".into(),
            },
        ],
        limitations: vec![
            "The single-process coordinator receives each clear order before generating cryptographically randomized Shamir shares; client-edge sharing is not part of this rough run.",
            "Seven MP-SPDZ processes run on one Linux host; this receipt is not WAN evidence.",
            "DeFMI is the real Rust verifier/state machine in-process; Avalanche validator consensus is not part of this rough run.",
            "One resting order and one arrival prove the seam, not production throughput or a multi-level book.",
        ],
    };
    write_receipt(&options.receipt, &receipt)?;
    append_ledger(&options.ledger, &receipt)?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

fn write_receipt(path: &Path, receipt: &RoughReceipt) -> Result<(), DemoError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(receipt)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn append_ledger(path: &Path, receipt: &RoughReceipt) -> Result<(), DemoError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, receipt)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn parse_options() -> Result<Options, DemoError> {
    let mut contract = PathBuf::from("../research/oclob_contract.json");
    let mut manifest = PathBuf::from("../research/manifests/oclob_rough_e2e.json");
    let mut receipt = PathBuf::from("../artifacts/oclob_rough_e2e.json");
    let mut ledger = PathBuf::from("../research/oclob_ledger.jsonl");
    let mut mp_spdz_root = env::var_os("MP_SPDZ_ROOT").map(PathBuf::from);
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| DemoError::Arguments(format!("{argument} needs a value")))
        };
        match argument.as_str() {
            "--contract" => contract = PathBuf::from(value()?),
            "--manifest" => manifest = PathBuf::from(value()?),
            "--receipt" => receipt = PathBuf::from(value()?),
            "--ledger" => ledger = PathBuf::from(value()?),
            "--mp-spdz-root" => mp_spdz_root = Some(PathBuf::from(value()?)),
            _ => return Err(DemoError::Arguments(format!("unknown argument {argument}"))),
        }
    }
    Ok(Options {
        contract,
        manifest,
        receipt,
        ledger,
        mp_spdz_root: mp_spdz_root.ok_or_else(|| {
            DemoError::Arguments("--mp-spdz-root or MP_SPDZ_ROOT is required".into())
        })?,
    })
}

#[derive(Debug, Error)]
enum DemoError {
    #[error("invalid arguments: {0}")]
    Arguments(String),
    #[error("research gate blocked the run: {0}")]
    ResearchGate(String),
    #[error("OCLOB execution failed: {0}")]
    Execution(String),
    #[error("OCLOB acceptance failed: {0}")]
    Acceptance(String),
    #[error(transparent)]
    Order(#[from] oclob_core::OrderError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
