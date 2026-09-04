//! OCLOB acceptance over a real five-validator, non-EVM DeFMI Avalanche L1.

#![forbid(unsafe_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use oclob_core::{authorize_order, SecretOrder, Side, TimeInForce};
use oclob_dekyx::deterministic_demo_environment;
use oclob_service::OclobService;
use oclob_settlement::avalanche::AvalancheCanonicalGateway;
use qomm_defmi::avalanche::{AvalancheClient, AvalancheRpcClient};
use qomm_defmi::facility::{DefmiFacility, QuorumAuthorizer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MARKET: &str = "JGB10Y-JPY";
const EXPECTED_VALIDATORS: usize = 5;
type RunResult<T> = Result<T, Box<dyn Error>>;

struct Options {
    chain_id: String,
    node_uris: Vec<String>,
    projection: PathBuf,
    out: PathBuf,
    mp_spdz_root: PathBuf,
    runner: Option<PathBuf>,
    avalanchego: Option<PathBuf>,
    runner_endpoint: String,
    restart_node: String,
    plugin_dir: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("OCLOB Avalanche acceptance rejected: {error}");
        std::process::exit(1);
    }
}

fn run_main() -> RunResult<()> {
    let options = parse_args()?;
    let result = run(&options)?;
    write_json_atomic(&options.out, &result)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn run(options: &Options) -> RunResult<Value> {
    let started = Instant::now();
    let clients = rpc_clients(&options.node_uris, &options.chain_id)?;
    if clients.len() != EXPECTED_VALIDATORS {
        return Err(failure(format!(
            "acceptance requires exactly {EXPECTED_VALIDATORS} validator RPC endpoints"
        )));
    }
    let network = clients[0]
        .call("defmivm.network", json!({}))
        .map_err(failure)?;
    if network.get("chainID").and_then(Value::as_str) != Some(&options.chain_id) {
        return Err(failure("Avalanche RPC returned another chain identifier"));
    }
    let initial_roots = agreed_roots(&clients)?;

    let now = unix_seconds()?;
    let expires_at = now
        .checked_add(3_600)
        .ok_or_else(|| failure("order expiry overflowed"))?;
    let (eligibility, eligibility_issuer) =
        deterministic_demo_environment(MARKET).map_err(|error| failure(error.to_string()))?;
    let seller_wallet = eligibility_issuer
        .issue_wallet(11, b"avalanche-seller", &mut rand::rngs::OsRng)
        .map_err(|error| failure(error.to_string()))?;
    let buyer_wallet = eligibility_issuer
        .issue_wallet(22, b"avalanche-buyer", &mut rand::rngs::OsRng)
        .map_err(|error| failure(error.to_string()))?;
    let mut matcher = OclobService::new(MARKET, &options.mp_spdz_root, eligibility)
        .map_err(|error| failure(error.to_string()))?;
    let (seller_handle, buyer_handle) = matcher.demo_participant_handles();
    let maker = SecretOrder::new_with_dekyx_nullifier(
        MARKET,
        Side::Sell,
        100,
        100,
        TimeInForce::GoodTilCancelled,
        expires_at,
        seller_handle,
        seller_wallet.subject_nullifier(),
        [1; 32],
        [31; 32],
    )?;
    let taker = SecretOrder::new_with_dekyx_nullifier(
        MARKET,
        Side::Buy,
        101,
        40,
        TimeInForce::ImmediateOrCancel,
        expires_at,
        buyer_handle,
        buyer_wallet.subject_nullifier(),
        [2; 32],
        [32; 32],
    )?;
    let maker_key = SigningKey::from_bytes(&[41; 32]);
    let taker_key = SigningKey::from_bytes(&[42; 32]);
    let maker_authority = authorize_order(&maker, expires_at.saturating_add(60), &maker_key)?;
    let maker_eligibility = seller_wallet
        .present(
            maker.commitment().0,
            [61; 32],
            expires_at,
            &mut rand::rngs::OsRng,
        )
        .map_err(|error| failure(error.to_string()))?;
    let (authorizer, approval_keys) = committee(&options.chain_id)?;
    let receipt_key = SigningKey::from_bytes(&digest(b"oclob-avalanche-receipt-key-v1"));
    let facility =
        DefmiFacility::open(&options.projection, authorizer, receipt_key).map_err(failure)?;
    let gateway = AvalancheCanonicalGateway::new(&facility, &clients, &approval_keys)?;

    let maker_book_before = matcher.public_book();
    let maker_settlement_before = matcher.settlement_state();
    let maker_prepared = matcher
        .prepare_canonical_submit(maker.clone(), maker_authority, maker_eligibility, now)
        .map_err(|error| failure(error.to_string()))?;
    if !maker_prepared.book_transition().fills.is_empty()
        || matcher.public_book() != maker_book_before
        || matcher.settlement_state() != maker_settlement_before
    {
        return Err(failure("the first maker order unexpectedly traded"));
    }
    let bootstrap_started = Instant::now();
    let bootstrap_root = gateway.bootstrap(maker_prepared.canonical_transition())?;
    let bootstrap_ms = bootstrap_started.elapsed().as_secs_f64() * 1_000.0;
    let maker_reservation_started = Instant::now();
    let maker_acceptance = gateway.settle(maker_prepared.canonical_transition(), now)?;
    let maker_reservation_ms = maker_reservation_started.elapsed().as_secs_f64() * 1_000.0;
    if matcher.public_book() != maker_book_before
        || matcher.settlement_state() != maker_settlement_before
    {
        return Err(failure(
            "maker state changed before its pre-trade reserve reached finality",
        ));
    }
    let maker_reservation_tx = maker_acceptance.transaction_id().to_owned();
    let maker_reservation_block = maker_acceptance.block_id().to_owned();
    let maker_reservation_height = maker_acceptance.height();
    let maker_reservation_root = maker_acceptance.after_state_root();
    let maker_execution = maker_prepared
        .accept(&mut matcher, maker_acceptance)
        .map_err(|error| failure(error.to_string()))?;
    if maker_execution.settlement.is_some()
        || maker_execution.reservation.zkpi_digest.is_none()
        || maker_execution.reservation.proof_digest.is_none()
        || maker_execution.reservation.instruction_nullifier.is_none()
        || maker_execution
            .reservation
            .avalanche_transaction_id
            .as_deref()
            != Some(maker_reservation_tx.as_str())
        || maker_execution.reservation.avalanche_block_id.as_deref()
            != Some(maker_reservation_block.as_str())
        || maker_execution.reservation.canonical_height != maker_reservation_height
        || facility.state_root().map_err(failure)? != maker_reservation_root
    {
        return Err(failure(
            "maker order entered the book without its canonical zkPI reservation",
        ));
    }

    let taker_authority = authorize_order(&taker, expires_at.saturating_add(60), &taker_key)?;
    let taker_eligibility = buyer_wallet
        .present(
            taker.commitment().0,
            [62; 32],
            expires_at,
            &mut rand::rngs::OsRng,
        )
        .map_err(|error| failure(error.to_string()))?;
    let book_before_prepare = matcher.public_book();
    let settlement_before_prepare = matcher.settlement_state();
    let prepared_execution = matcher
        .prepare_canonical_submit(taker.clone(), taker_authority, taker_eligibility, now)
        .map_err(|error| failure(error.to_string()))?;
    let fill = prepared_execution
        .book_transition()
        .fills
        .first()
        .cloned()
        .ok_or_else(|| failure("crossing order produced no fill"))?;
    if prepared_execution.book_transition().fills.len() != 1
        || fill.price != 100
        || fill.quantity != 40
        || prepared_execution.book_transition().arriving_remaining != 0
        || prepared_execution.transition_proof().attestations.len() != 5
        || prepared_execution.mpc().parties != 7
        || !prepared_execution.mpc().all_parties_agreed
    {
        return Err(failure(
            "the verified matching path returned an unexpected result",
        ));
    }
    if matcher.public_book() != book_before_prepare
        || matcher.settlement_state() != settlement_before_prepare
    {
        return Err(failure(
            "preparing canonical settlement mutated the live OCLOB service",
        ));
    }

    let settlement_started = Instant::now();
    let acceptance = gateway.settle(prepared_execution.canonical_transition(), now)?;
    let settlement_ms = settlement_started.elapsed().as_secs_f64() * 1_000.0;
    if matcher.public_book() != book_before_prepare
        || matcher.settlement_state() != settlement_before_prepare
    {
        return Err(failure(
            "live OCLOB service changed before Avalanche acceptance was applied",
        ));
    }
    let accepted_tx = acceptance.transaction_id().to_owned();
    let accepted_block = acceptance.block_id().to_owned();
    let accepted_height = acceptance.height();
    let accepted_root = acceptance.after_state_root();
    let application_binding = acceptance.application_binding();
    let binding_digest = acceptance.binding_digest();
    let replay_rejected = gateway
        .settle(prepared_execution.canonical_transition(), now)
        .is_err();
    if !replay_rejected {
        return Err(failure("the canonical settlement replay was accepted"));
    }
    let execution = prepared_execution
        .accept(&mut matcher, acceptance)
        .map_err(|error| failure(error.to_string()))?;
    let settlement = execution
        .settlement
        .as_ref()
        .ok_or_else(|| failure("accepted execution omitted its settlement receipt"))?;
    if matcher.public_book() == book_before_prepare
        || matcher.settlement_state() == settlement_before_prepare
        || facility.state_root().map_err(failure)? != accepted_root
        || settlement.avalanche_transaction_id.as_deref() != Some(accepted_tx.as_str())
        || settlement.avalanche_block_id.as_deref() != Some(accepted_block.as_str())
        || settlement.canonical_height != accepted_height
        || settlement.arriving_reservation_zkpi_digest.is_none()
        || settlement
            .arriving_reservation_instruction_nullifier
            .is_none()
        || settlement.arriving_reservation_proof_digest.is_none()
        || execution.reservation.zkpi_digest != settlement.arriving_reservation_zkpi_digest
        || execution.reservation.instruction_nullifier
            != settlement.arriving_reservation_instruction_nullifier
        || execution.reservation.proof_digest != settlement.arriving_reservation_proof_digest
    {
        return Err(failure(
            "accepted Avalanche state was not applied exactly once",
        ));
    }
    let roots_before_restart = wait_for_roots(&clients, accepted_root, Duration::from_secs(30))?;
    let mut restart_ms = None;
    let mut roots_after_restart = roots_before_restart.clone();
    if let Some(runner) = options.runner.as_deref() {
        restart_ms = Some(restart_validator(
            runner,
            &options.runner_endpoint,
            &options.restart_node,
            options.plugin_dir.as_deref(),
        )?);
        let restarted = rpc_clients(&options.node_uris, &options.chain_id)?;
        roots_after_restart = wait_for_roots(&restarted, accepted_root, Duration::from_secs(30))?;
    }

    let seller = matcher
        .participant_portfolio(seller_handle)
        .map_err(|error| failure(error.to_string()))?;
    let buyer = matcher
        .participant_portfolio(buyer_handle)
        .map_err(|error| failure(error.to_string()))?;
    if seller.securities != 9_960
        || seller.cash != 100_004_000
        || seller.reserved_securities != 60
        || buyer.securities != 10_040
        || buyer.cash != 99_996_000
        || buyer.reserved_cash != 0
    {
        return Err(failure(
            "post-settlement balances or reserves are incorrect",
        ));
    }
    let last_accepted = clients[0]
        .call("defmivm.lastAccepted", json!({}))
        .map_err(failure)?;
    let receipt_chain_verified = facility.verify_receipt_chain().map_err(failure)?;
    if !receipt_chain_verified || roots_after_restart != roots_before_restart {
        return Err(failure("canonical receipt or restart recovery failed"));
    }

    Ok(json!({
        "schema": "oclob.avalanche-acceptance/v1",
        "verdict": "accepted",
        "environment": "five local AvalancheGo validator processes on one OmenX host",
        "evm_used": false,
        "chain_id": options.chain_id,
        "network": network,
        "validator_rpc_endpoints": clients.len(),
        "external_binaries": {
            "avalanchego": tool_record(options.avalanchego.as_deref(), true)?,
            "avalanche_network_runner": tool_record(options.runner.as_deref(), false)?,
        },
        "initial_roots": initial_roots,
        "bootstrap_root": hex::encode(bootstrap_root),
        "matching": {
            "ordering_votes": execution.certificate.votes.len(),
            "transition_attestations": execution.transition_proof.attestations.len(),
            "mpc_protocol": execution.mpc.protocol,
            "mpc_parties": execution.mpc.parties,
            "mpc_output_agreed": execution.mpc.all_parties_agreed,
            "price": fill.price,
            "quantity": fill.quantity,
            "maker_remainder": 60,
            "taker_remainder": execution.book_transition.arriving_remaining,
        },
        "zkpi": {
            "maker_pretrade_reservation": {
                "zkpi_digest": maker_execution.reservation.zkpi_digest.map(hex::encode),
                "proof_digest": maker_execution.reservation.proof_digest.map(hex::encode),
                "instruction_nullifier": maker_execution.reservation.instruction_nullifier.map(hex::encode),
                "transaction_id": maker_reservation_tx,
                "block_id": maker_reservation_block,
                "height": maker_reservation_height,
                "state_root": hex::encode(maker_reservation_root),
                "finalized_before_book_admission": true,
            },
            "taker_atomic_reservation": {
                "zkpi_digest": settlement.arriving_reservation_zkpi_digest.map(hex::encode),
                "proof_digest": settlement.arriving_reservation_proof_digest.map(hex::encode),
                "instruction_nullifier": settlement.arriving_reservation_instruction_nullifier.map(hex::encode),
                "finalized_with_dvp": true,
            },
            "threshold_amount_range": settlement.amount_range_is_threshold,
            "threshold_price_range": settlement.price_range_is_threshold,
            "authorization_quorum": settlement.settlement_authorization_quorum,
            "post_match_participant_signatures": settlement.post_match_participant_signatures,
            "payment_instruction_digest": hex::encode(settlement.members[0].zkpi_digest),
            "dvp_package_digest": hex::encode(settlement.members[0].package_digest),
        },
        "canonical_settlement": {
            "transaction_id": accepted_tx,
            "block_id": accepted_block,
            "height": accepted_height,
            "state_root": hex::encode(accepted_root),
            "application_binding": hex::encode(application_binding),
            "binding_digest": hex::encode(binding_digest),
            "receipt_digest": hex::encode(settlement.canonical_receipt_digest),
            "receipt_chain_verified": receipt_chain_verified,
            "local_state_unchanged_before_acceptance": true,
            "replay_rejected": replay_rejected,
            "all_validator_roots_before_restart": roots_before_restart,
            "all_validator_roots_after_restart": roots_after_restart,
        },
        "private_portfolios_after": {
            "maker": seller,
            "taker": buyer,
        },
        "restart": {
            "node": options.restart_node,
            "elapsed_ms": restart_ms,
            "root_recovered": true,
        },
        "timings_ms": {
            "bootstrap": bootstrap_ms,
            "maker_pretrade_reservation": maker_reservation_ms,
            "settlement": settlement_ms,
            "whole_acceptance": started.elapsed().as_secs_f64() * 1_000.0,
        },
        "last_accepted_block_id": last_accepted
            .get("blockID")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("lastAccepted response omitted blockID"))?,
        "non_claims": [
            "Five validator processes on one host are not independent validator operators or WAN evidence.",
            "This gate uses the compatibility coordinator for matching; participant-edge distributed matching is proven by a separate acceptance and is not yet one atomic run with this L1 gate.",
            "The DeFMI approval keys are deterministic laboratory keys in one process, not production HSM custody.",
            "Canonical DeFMI state currently uses pseudonymous commitment accounts and a commitment-only reservation root; the account-free note rail remains a separate production cutover.",
        ],
    }))
}

fn committee(domain: &str) -> RunResult<(QuorumAuthorizer, BTreeMap<String, SigningKey>)> {
    let keys = (0..7)
        .map(|index| {
            (
                format!("node-{index}"),
                SigningKey::from_bytes(&digest(format!("key:{index}").as_bytes())),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let nodes = keys
        .iter()
        .map(|(name, key)| (name.clone(), key.verifying_key()))
        .collect::<BTreeMap<String, VerifyingKey>>();
    let authorizer = QuorumAuthorizer::new(nodes, 3, 1, domain.to_owned()).map_err(failure)?;
    Ok((authorizer, keys))
}

fn rpc_clients(node_uris: &[String], chain_id: &str) -> RunResult<Vec<AvalancheRpcClient>> {
    node_uris
        .iter()
        .map(|uri| {
            AvalancheRpcClient::new(
                &format!("{}/ext/bc/{chain_id}", uri.trim_end_matches('/')),
                Duration::from_secs(30),
                true,
            )
            .map_err(failure)
        })
        .collect()
}

fn agreed_roots(clients: &[AvalancheRpcClient]) -> RunResult<Vec<String>> {
    let roots = clients
        .iter()
        .map(AvalancheClient::state_root)
        .collect::<Result<Vec<_>, _>>()
        .map_err(failure)?;
    if roots.is_empty() || roots.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(failure("Avalanche validators disagree on canonical state"));
    }
    Ok(roots.into_iter().map(hex::encode).collect())
}

fn wait_for_roots(
    clients: &[AvalancheRpcClient],
    expected: [u8; 32],
    timeout: Duration,
) -> RunResult<Vec<String>> {
    let deadline = Instant::now() + timeout;
    let mut last = Vec::new();
    loop {
        if let Ok(roots) = clients
            .iter()
            .map(AvalancheClient::state_root)
            .collect::<Result<Vec<_>, _>>()
        {
            last = roots.iter().copied().map(hex::encode).collect();
            if roots.len() == EXPECTED_VALIDATORS && roots.iter().all(|root| *root == expected) {
                return Ok(last);
            }
        }
        if Instant::now() >= deadline {
            return Err(failure(format!(
                "validators did not converge to {}; last={last:?}",
                hex::encode(expected)
            )));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn restart_validator(
    runner: &Path,
    endpoint: &str,
    node: &str,
    plugin_dir: Option<&Path>,
) -> RunResult<f64> {
    let started = Instant::now();
    let mut restart = Command::new(runner);
    restart.args([
        "control",
        "restart-node",
        node,
        &format!("--endpoint={endpoint}"),
        "--request-timeout=3m",
    ]);
    if let Some(plugin_dir) = plugin_dir {
        restart.arg(format!(
            "--plugin-dir={}",
            plugin_dir.canonicalize()?.display()
        ));
    }
    let output = output_with_timeout(restart, Duration::from_secs(180))?;
    if !output.status.success() {
        return Err(failure(format!(
            "validator restart failed: {}",
            command_detail(&output.stdout, &output.stderr)
        )));
    }
    let mut healthy = Command::new(runner);
    healthy.args([
        "control",
        "wait-for-healthy",
        &format!("--endpoint={endpoint}"),
        "--request-timeout=3m",
    ]);
    let output = output_with_timeout(healthy, Duration::from_secs(180))?;
    if !output.status.success() {
        return Err(failure(format!(
            "validator network did not recover: {}",
            command_detail(&output.stdout, &output.stderr)
        )));
    }
    Ok(started.elapsed().as_secs_f64() * 1_000.0)
}

fn tool_record(path: Option<&Path>, require_version: bool) -> RunResult<Value> {
    let Some(path) = path else {
        return Ok(Value::Null);
    };
    let resolved = path.canonicalize()?;
    let mut command = Command::new(&resolved);
    command.arg("--version");
    let output = output_with_timeout(command, Duration::from_secs(20))?;
    if require_version && !output.status.success() {
        return Err(failure(
            "external acceptance binary did not report a version",
        ));
    }
    let version = if output.status.success() {
        let bytes = if output.stdout.is_empty() {
            &output.stderr
        } else {
            &output.stdout
        };
        Some(String::from_utf8_lossy(bytes).trim().to_owned())
    } else {
        None
    };
    let mut file = File::open(&resolved)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(json!({
        "version": version,
        "sha256": hex::encode(hash.finalize()),
    }))
}

struct CapturedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn output_with_timeout(mut command: Command, timeout: Duration) -> RunResult<CapturedOutput> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure("missing stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| failure("missing stderr pipe"))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            return Err(failure(format!(
                "external command exceeded {} seconds",
                timeout.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ok(CapturedOutput {
        status,
        stdout: stdout_reader
            .join()
            .map_err(|_| failure("stdout reader panicked"))??,
        stderr: stderr_reader
            .join()
            .map_err(|_| failure("stderr reader panicked"))??,
    })
}

fn command_detail(stdout: &[u8], stderr: &[u8]) -> String {
    let bytes = if stderr.is_empty() { stdout } else { stderr };
    String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(2_000)..]).into_owned()
}

fn write_json_atomic(path: &Path, value: &Value) -> RunResult<()> {
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temporary = PathBuf::from(format!("{}.tmp-{}", path.display(), std::process::id()));
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn parse_args() -> RunResult<Options> {
    let mut options = Options {
        chain_id: String::new(),
        node_uris: Vec::new(),
        projection: PathBuf::new(),
        out: PathBuf::from("artifacts/oclob_avalanche_acceptance.json"),
        mp_spdz_root: std::env::var_os("MP_SPDZ_ROOT")
            .map(PathBuf::from)
            .unwrap_or_default(),
        runner: None,
        avalanchego: None,
        runner_endpoint: "localhost:18080".into(),
        restart_node: "node3".into(),
        plugin_dir: None,
    };
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        let name = argument.to_string_lossy();
        let mut value = || -> RunResult<String> {
            args.next()
                .ok_or_else(|| failure(format!("{name} needs a value")))?
                .into_string()
                .map_err(|_| failure(format!("{name} is not valid UTF-8")))
        };
        match name.as_ref() {
            "--chain-id" => options.chain_id = value()?,
            "--node-uri" => options.node_uris.push(value()?),
            "--projection" => options.projection = PathBuf::from(value()?),
            "--out" => options.out = PathBuf::from(value()?),
            "--mp-spdz-root" => options.mp_spdz_root = PathBuf::from(value()?),
            "--runner" => options.runner = Some(PathBuf::from(value()?)),
            "--avalanchego" => options.avalanchego = Some(PathBuf::from(value()?)),
            "--runner-endpoint" => options.runner_endpoint = value()?,
            "--restart-node" => options.restart_node = value()?,
            "--plugin-dir" => options.plugin_dir = Some(PathBuf::from(value()?)),
            "-h" | "--help" => {
                println!(
                    "usage: oclob-avalanche-acceptance --chain-id ID --node-uri URI \
                     [--node-uri URI ...] --projection PATH --mp-spdz-root PATH [--out PATH] \
                     [--runner PATH] [--avalanchego PATH] [--runner-endpoint HOST:PORT] \
                     [--restart-node NAME] [--plugin-dir PATH]"
                );
                std::process::exit(0);
            }
            _ => return Err(failure(format!("unknown argument {name}"))),
        }
    }
    if options.chain_id.is_empty()
        || options.node_uris.len() != EXPECTED_VALIDATORS
        || options.projection.as_os_str().is_empty()
        || options.mp_spdz_root.as_os_str().is_empty()
    {
        return Err(failure(
            "chain id, exactly five node URIs, projection and MP-SPDZ root are required",
        ));
    }
    Ok(options)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn unix_seconds() -> RunResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}
