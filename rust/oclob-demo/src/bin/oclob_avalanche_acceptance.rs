//! OCLOB acceptance over a real five-validator, non-EVM DeFMI Avalanche L1.

#![forbid(unsafe_code)]

#[path = "native_acceptance/mod.rs"]
mod native_acceptance;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use ed25519_dalek::{SigningKey, VerifyingKey};
use oclob_core::{authorize_order, PublicFill, SecretOrder, Side, TimeInForce, MAX_MATCH_SLOTS};
use oclob_dekyx::{deterministic_demo_environment, AnonymousPresentation};
use oclob_edge::SealedSettlementCapability;
use oclob_mpc::{PERSISTENCE_WIRES, PRIVATE_BOOK_WIRES, SETTLEMENT_PROOF_WIRES_PER_FILL};
use oclob_node::edge_client::{
    collect_order_certificate, collect_threshold_capability_release, execute_agreed_round,
    finalize_agreed_private_state, AgreedRoundExecution, EdgeAdmissionReceipt,
};
use oclob_node::executor::RoundPlan;
use oclob_node::network::{
    client_tls_context, load_secret_32, ClientIdentityConfig, ClusterPublicConfig,
};
use oclob_node::PrivateStateFinality;
use oclob_ordering::{OrderCertificate, OrderingCommittee};
use oclob_proofs::{
    public_fills_digest, TransitionProof, TransitionStatement, VerifiedTransitionProof,
};
use oclob_service::OclobService;
use oclob_settlement::avalanche::AvalancheCanonicalGateway;
use oclob_settlement::collaborative::{
    collaborative_job_id, load_fill, prove_fill, setup_frost, CollaborativeFillProof,
    CollaborativeFillRequest,
};
use oclob_settlement::CollaborativeCanonicalAdmissionBatch;
use oclob_settlement::{canonical_securities_asset_id, SettlementEngine};
use qomm_defmi::avalanche::{AvalancheClient, AvalancheRpcClient};
use qomm_defmi::facility::{DefmiFacility, QuorumAuthorizer};
use qomm_defmi::settlement::{build_threshold_package_from_proofs, Sides};
use qomm_proofs::price_limit::PriceLimitDirection;
use qomm_transport::node_service::client_ssl_context as proof_tls_context;
use qomm_transport::proof_client::ProofPartyTlsClient;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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

struct IntegratedPaths {
    cluster: PathBuf,
    coordinator_identity: PathBuf,
    maker_receipt: PathBuf,
    taker_receipt: PathBuf,
    maker_capability: PathBuf,
    taker_capability: PathBuf,
    settlement_identity: PathBuf,
    research_contract: PathBuf,
    research_manifest: PathBuf,
}

struct VerifiedCollaborativeSettlement {
    proof: CollaborativeFillProof,
    report: Value,
    zkpi_digest: [u8; 32],
    instruction_nullifier: [u8; 32],
    package_digest: [u8; 32],
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
    if std::env::var_os("OCLOB_NATIVE_L1_SERVICE").is_some() {
        return native_acceptance::serve(options);
    }
    match IntegratedPaths::from_environment()? {
        Some(paths) => run_integrated(options, &paths),
        None => run_compatibility(options),
    }
}

impl IntegratedPaths {
    fn from_environment() -> RunResult<Option<Self>> {
        const NAMES: [&str; 9] = [
            "OCLOB_CLUSTER_CONFIG",
            "OCLOB_COORDINATOR_IDENTITY",
            "OCLOB_MAKER_RECEIPT",
            "OCLOB_TAKER_RECEIPT",
            "OCLOB_MAKER_CAPABILITY",
            "OCLOB_TAKER_CAPABILITY",
            "OCLOB_SETTLEMENT_IDENTITY",
            "OCLOB_RESEARCH_CONTRACT",
            "OCLOB_RESEARCH_MANIFEST",
        ];
        let values = NAMES.map(std::env::var_os);
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        if values.iter().any(Option::is_none) {
            return Err(failure(
                "integrated acceptance requires all nine OCLOB_* path variables",
            ));
        }
        let mut values = values.into_iter().map(|value| {
            PathBuf::from(value.expect("all integrated acceptance variables were checked"))
        });
        Ok(Some(Self {
            cluster: values.next().expect("cluster path"),
            coordinator_identity: values.next().expect("identity path"),
            maker_receipt: values.next().expect("maker receipt path"),
            taker_receipt: values.next().expect("taker receipt path"),
            maker_capability: values.next().expect("maker capability path"),
            taker_capability: values.next().expect("taker capability path"),
            settlement_identity: values.next().expect("settlement identity path"),
            research_contract: values.next().expect("research contract path"),
            research_manifest: values.next().expect("research manifest path"),
        }))
    }
}

fn run_integrated(options: &Options, paths: &IntegratedPaths) -> RunResult<Value> {
    let started = Instant::now();
    let research =
        validate_integrated_research_binding(&paths.research_contract, &paths.research_manifest)?;
    let clients = rpc_clients(&options.node_uris, &options.chain_id)?;
    if clients.len() != EXPECTED_VALIDATORS {
        return Err(failure(format!(
            "acceptance requires exactly {EXPECTED_VALIDATORS} validator RPC endpoints"
        )));
    }
    let network = clients[0]
        .call("defmivm.network", json!({}))
        .map_err(failure)?;
    let initial_roots = agreed_roots(&clients)?;
    let cluster: ClusterPublicConfig = read_json_limited(&paths.cluster)?;
    cluster
        .validate()
        .map_err(|error| failure(error.to_string()))?;
    if cluster.market_id != MARKET {
        return Err(failure(
            "distributed cluster is configured for another market",
        ));
    }
    let coordinator_identity: ClientIdentityConfig =
        read_json_limited(&paths.coordinator_identity)?;
    coordinator_identity
        .validate()
        .map_err(|error| failure(error.to_string()))?;
    let coordinator = SigningKey::from_bytes(
        &load_secret_32(&coordinator_identity.application_signing_key)
            .map_err(|error| failure(error.to_string()))?,
    );
    let coordinator_tls = client_tls_context(
        &coordinator_identity.tls_certificate,
        &coordinator_identity.tls_private_key,
        &coordinator_identity.tls_ca,
    )
    .map_err(|error| failure(error.to_string()))?;
    let settlement_identity: ClientIdentityConfig = read_json_limited(&paths.settlement_identity)?;
    settlement_identity
        .validate()
        .map_err(|error| failure(error.to_string()))?;
    let settlement_tls = client_tls_context(
        &settlement_identity.tls_certificate,
        &settlement_identity.tls_private_key,
        &settlement_identity.tls_ca,
    )
    .map_err(|error| failure(error.to_string()))?;
    let maker_receipt: EdgeAdmissionReceipt = read_json_limited(&paths.maker_receipt)?;
    let taker_receipt: EdgeAdmissionReceipt = read_json_limited(&paths.taker_receipt)?;
    let now = unix_seconds()?;
    maker_receipt
        .verify(&cluster, now)
        .map_err(|error| failure(error.to_string()))?;
    taker_receipt
        .verify(&cluster, now)
        .map_err(|error| failure(error.to_string()))?;
    if maker_receipt.manifest.market_id != MARKET
        || taker_receipt.manifest.market_id != MARKET
        || maker_receipt.commitment() == taker_receipt.commitment()
    {
        return Err(failure(
            "edge receipts are not two distinct orders in this market",
        ));
    }

    let maker_envelope: SealedSettlementCapability = read_json_limited(&paths.maker_capability)?;
    let taker_envelope: SealedSettlementCapability = read_json_limited(&paths.taker_capability)?;
    if maker_envelope.order_commitment != maker_receipt.commitment()
        || maker_envelope.capability_commitment
            != maker_receipt.manifest.settlement_capability_commitment
        || taker_envelope.order_commitment != taker_receipt.commitment()
        || taker_envelope.capability_commitment
            != taker_receipt.manifest.settlement_capability_commitment
    {
        return Err(failure(
            "encrypted settlement handoff is not bound to its edge manifest",
        ));
    }
    let (mut eligibility, _) =
        deterministic_demo_environment(MARKET).map_err(|error| failure(error.to_string()))?;

    let transition_committee =
        OrderingCommittee::deterministic_for_demo().map_err(|error| failure(error.to_string()))?;
    let proof_tls = proof_tls_context(
        &coordinator_identity.tls_certificate,
        &coordinator_identity.tls_private_key,
        &coordinator_identity.tls_ca,
    )
    .map_err(failure)?;
    let mut bootstrap_proof_parties = cluster
        .nodes
        .iter()
        .map(|node| {
            ProofPartyTlsClient::new(
                node.host.clone(),
                node.proof_port,
                proof_tls.clone(),
                node.server_name.clone(),
                Duration::from_secs(120),
            )
        })
        .collect::<Vec<_>>();
    let frost_session = tagged_digest(b"OCLOB:COLLABORATIVE-FROST:v1", MARKET.as_bytes());
    let collaborative_frost_public =
        setup_frost(&mut bootstrap_proof_parties, frost_session).map_err(failure)?;
    let mut settlement = SettlementEngine::new_with_transition_committee(
        &mut rand::rngs::OsRng,
        &transition_committee.verifying_keys(),
        transition_committee.policy(),
    )
    .map_err(|error| failure(error.to_string()))?;
    settlement
        .pin_collaborative_settlement_committee(
            collaborative_frost_public.clone(),
            qomm_transport::frost_coordinator::read_pq_committee(
                &mut bootstrap_proof_parties,
                &collaborative_frost_public,
            )
            .map_err(failure)?,
        )
        .map_err(|error| failure(error.to_string()))?;
    let (authorizer, approval_keys) = committee(&options.chain_id)?;
    let receipt_key = SigningKey::from_bytes(&digest(b"oclob-integrated-receipt-key-v1"));
    let facility =
        DefmiFacility::open(&options.projection, authorizer, receipt_key).map_err(failure)?;
    let gateway = AvalancheCanonicalGateway::new(&facility, &clients, &approval_keys)?;

    let now = unix_seconds()?;
    let maker_certificate = collect_order_certificate(
        &cluster,
        &coordinator_tls,
        None,
        maker_receipt.commitment(),
        maker_receipt.manifest.retention_deadline,
        Duration::from_secs(30),
    )
    .map_err(|error| failure(error.to_string()))?;
    let maker_plan = RoundPlan::sign(
        maker_certificate.clone(),
        vec![],
        now,
        now.saturating_add(300)
            .min(maker_receipt.manifest.retention_deadline),
        &coordinator,
    )
    .map_err(|error| failure(error.to_string()))?;
    let maker_execution = execute_agreed_round(
        &cluster,
        &coordinator_tls,
        &maker_plan,
        Duration::from_secs(300),
    )
    .map_err(|error| failure(error.to_string()))?;
    validate_integrated_maker(&maker_execution)?;
    let maker_release = collect_threshold_capability_release(
        &cluster,
        &settlement_tls,
        &maker_plan,
        &maker_execution,
        &maker_receipt.manifest,
        maker_receipt.commitment(),
        Duration::from_secs(30),
    )
    .map_err(|error| failure(error.to_string()))?;
    let maker = maker_release
        .open(&maker_envelope, &maker_receipt.manifest, now)
        .map_err(|error| failure(error.to_string()))?;
    if hidden_eligibility_commitment(maker.order()) != maker.eligibility_commitment() {
        return Err(failure(
            "maker capability is not bound to its eligibility scope",
        ));
    }
    let maker_presentation: AnonymousPresentation =
        serde_json::from_slice(maker.eligibility_evidence())?;
    let maker_eligibility = eligibility
        .verify_order(
            maker.order_commitment().0,
            maker.order().dekyx_nullifier(),
            maker.order().expires_at(),
            &maker_presentation,
            now,
        )
        .map_err(|error| failure(error.to_string()))?;
    let private_genesis = tagged_digest(b"OCLOB:DISTRIBUTED:PRIVATE-GENESIS:v1", MARKET.as_bytes());
    let public_genesis = tagged_digest(b"OCLOB:DISTRIBUTED:PUBLIC-GENESIS:v1", MARKET.as_bytes());
    let (maker_transition, private_after_maker, public_after_maker) = verified_round_transition(
        &transition_committee,
        &maker_certificate,
        &maker_plan,
        &maker_execution,
        maker_eligibility.proof_digest,
        &[],
        private_genesis,
        public_genesis,
    )?;
    let maker_base_snapshot = settlement.state_snapshot();
    let mut maker_candidate = settlement.clone();
    maker_candidate
        .bind_eligible_participant(
            maker.order().participant_handle(),
            maker_eligibility.subject_nullifier,
        )
        .map_err(|error| failure(error.to_string()))?;
    let maker_reserve_commitment = manifest_point(
        maker_receipt.manifest.settlement_field_commitments[1][0],
        "Maker reserve",
    )?;
    let maker_reservation = maker_candidate
        .reserve_order_with_commitment(&maker, maker_reserve_commitment)
        .map_err(|error| failure(error.to_string()))?;
    let maker_prepared = settlement
        .prepare_canonical_reservation(
            maker_candidate,
            maker_reservation,
            &maker,
            &maker_certificate,
            &maker_transition,
            now,
        )
        .map_err(|error| failure(error.to_string()))?;
    if settlement.state_snapshot() != maker_base_snapshot {
        return Err(failure(
            "maker entity binding or reservation mutated live state before finality",
        ));
    }
    let bootstrap_root = gateway.bootstrap(&maker_prepared)?;
    let maker_acceptance = gateway.settle(&maker_prepared, now)?;
    let maker_tx = maker_acceptance.transaction_id().to_owned();
    let maker_height = maker_acceptance.height();
    let maker_finality = PrivateStateFinality {
        round_id: maker_plan.round_id,
        public_output_sha256: maker_execution.receipts[0].public_output_sha256,
        transition_digest: maker_transition.digest(),
        canonical_receipt_digest: maker_acceptance.receipt_digest(),
        canonical_height: maker_height,
    };
    let maker_applied = maker_prepared
        .accept(&mut settlement, maker_acceptance)
        .map_err(|error| failure(error.to_string()))?;
    let maker_reservation = match maker_applied {
        oclob_settlement::AppliedCanonicalTransition::Reservation(receipt) => receipt,
        oclob_settlement::AppliedCanonicalTransition::Settlement(_) => {
            return Err(failure("maker admission unexpectedly produced DvP"));
        }
    };
    let maker_private_state_receipts = finalize_agreed_private_state(
        &cluster,
        &settlement_tls,
        &maker_plan,
        &maker_execution,
        maker_finality.clone(),
        Duration::from_secs(30),
    )
    .map_err(|error| failure(error.to_string()))?;
    let maker_private_state_retry = finalize_agreed_private_state(
        &cluster,
        &settlement_tls,
        &maker_plan,
        &maker_execution,
        maker_finality,
        Duration::from_secs(30),
    )
    .map_err(|error| failure(error.to_string()))?;
    if maker_private_state_retry != maker_private_state_receipts {
        return Err(failure(
            "Maker private-state finality retry was not idempotent",
        ));
    }

    let now = unix_seconds()?;
    let taker_certificate = collect_order_certificate(
        &cluster,
        &coordinator_tls,
        Some(&maker_certificate),
        taker_receipt.commitment(),
        taker_receipt.manifest.retention_deadline,
        Duration::from_secs(30),
    )
    .map_err(|error| failure(error.to_string()))?;
    let taker_plan = RoundPlan::sign(
        taker_certificate.clone(),
        vec![maker_receipt.commitment()],
        now,
        now.saturating_add(300)
            .min(taker_receipt.manifest.retention_deadline),
        &coordinator,
    )
    .map_err(|error| failure(error.to_string()))?;
    let taker_execution = execute_agreed_round(
        &cluster,
        &coordinator_tls,
        &taker_plan,
        Duration::from_secs(300),
    )
    .map_err(|error| failure(error.to_string()))?;
    validate_integrated_taker(&taker_execution)?;
    validate_private_state_chain(&maker_execution, &taker_execution)?;
    let taker_release = collect_threshold_capability_release(
        &cluster,
        &settlement_tls,
        &taker_plan,
        &taker_execution,
        &taker_receipt.manifest,
        taker_receipt.commitment(),
        Duration::from_secs(30),
    )
    .map_err(|error| failure(error.to_string()))?;
    let taker = taker_release
        .open(&taker_envelope, &taker_receipt.manifest, now)
        .map_err(|error| failure(error.to_string()))?;
    if hidden_eligibility_commitment(taker.order()) != taker.eligibility_commitment() {
        return Err(failure(
            "taker capability is not bound to its eligibility scope",
        ));
    }
    let taker_presentation: AnonymousPresentation =
        serde_json::from_slice(taker.eligibility_evidence())?;
    let taker_eligibility = eligibility
        .verify_order(
            taker.order_commitment().0,
            taker.order().dekyx_nullifier(),
            taker.order().expires_at(),
            &taker_presentation,
            now,
        )
        .map_err(|error| failure(error.to_string()))?;
    let fills = vec![PublicFill {
        maker_order: maker.order_commitment(),
        taker_order: taker.order_commitment(),
        price: taker_execution.result.slots[0].trade_price,
        quantity: taker_execution.result.slots[0].trade_quantity,
    }];
    let (taker_transition, _, _) = verified_round_transition(
        &transition_committee,
        &taker_certificate,
        &taker_plan,
        &taker_execution,
        taker_eligibility.proof_digest,
        &fills,
        private_after_maker,
        public_after_maker,
    )?;
    let mut collaborative_settlement = verify_collaborative_fill(
        &cluster,
        &coordinator_identity,
        &maker_receipt,
        &taker_receipt,
        &taker_certificate,
        &taker_plan,
        &taker_execution,
        collaborative_frost_public,
        now,
    )?;
    let taker_base_snapshot = settlement.state_snapshot();
    let mut taker_candidate = settlement.clone();
    taker_candidate
        .bind_eligible_participant(
            taker.order().participant_handle(),
            taker_eligibility.subject_nullifier,
        )
        .map_err(|error| failure(error.to_string()))?;
    let taker_reserve_commitment = manifest_point(
        taker_receipt.manifest.settlement_field_commitments[1][0],
        "Taker reserve",
    )?;
    let taker_reservation = taker_candidate
        .reserve_order_with_commitment(&taker, taker_reserve_commitment)
        .map_err(|error| failure(error.to_string()))?;

    if maker_reserve_commitment == taker_reserve_commitment {
        return Err(failure(
            "Maker and Taker reserve commitments unexpectedly coincide",
        ));
    }
    let mut wrong_reservation_candidate = settlement.clone();
    wrong_reservation_candidate
        .bind_eligible_participant(
            taker.order().participant_handle(),
            taker_eligibility.subject_nullifier,
        )
        .map_err(|error| failure(error.to_string()))?;
    let wrong_reservation = wrong_reservation_candidate
        .reserve_order_with_commitment(&taker, maker_reserve_commitment)
        .map_err(|error| failure(error.to_string()))?;
    let reservation_commitment_mismatch_rejected = settlement
        .prepare_canonical_admission_batch_collaborative(CollaborativeCanonicalAdmissionBatch {
            reserved_candidate: wrong_reservation_candidate,
            reservation_receipt: &wrong_reservation,
            fills: &fills,
            proofs: std::slice::from_ref(&collaborative_settlement.proof),
            round_id: taker_plan.round_id,
            transition: &taker_transition,
            certificate: &taker_certificate,
            arriving: &taker,
            arriving_remaining: taker_execution.result.arriving_remaining,
            now,
        })
        .is_err();

    let original_market_proof_digest = collaborative_settlement.proof.market_proof_digest;
    collaborative_settlement.proof.market_proof_digest[0] ^= 1;
    let tampered_output_binding_rejected = settlement
        .prepare_canonical_admission_batch_collaborative(CollaborativeCanonicalAdmissionBatch {
            reserved_candidate: taker_candidate.clone(),
            reservation_receipt: &taker_reservation,
            fills: &fills,
            proofs: std::slice::from_ref(&collaborative_settlement.proof),
            round_id: taker_plan.round_id,
            transition: &taker_transition,
            certificate: &taker_certificate,
            arriving: &taker,
            arriving_remaining: taker_execution.result.arriving_remaining,
            now,
        })
        .is_err();
    collaborative_settlement.proof.market_proof_digest = original_market_proof_digest;

    let (_, unpinned_public) =
        qomm_zkpi::distributed_key_generation(7, 3, &mut rand::rngs::OsRng).map_err(failure)?;
    let pinned_proof_public = std::mem::replace(
        &mut collaborative_settlement.proof.frost_public,
        unpinned_public,
    );
    let unpinned_proof_key_rejected = settlement
        .prepare_canonical_admission_batch_collaborative(CollaborativeCanonicalAdmissionBatch {
            reserved_candidate: taker_candidate.clone(),
            reservation_receipt: &taker_reservation,
            fills: &fills,
            proofs: std::slice::from_ref(&collaborative_settlement.proof),
            round_id: taker_plan.round_id,
            transition: &taker_transition,
            certificate: &taker_certificate,
            arriving: &taker,
            arriving_remaining: taker_execution.result.arriving_remaining,
            now,
        })
        .is_err();
    collaborative_settlement.proof.frost_public = pinned_proof_public;
    if !reservation_commitment_mismatch_rejected
        || !tampered_output_binding_rejected
        || !unpinned_proof_key_rejected
    {
        return Err(failure(
            "canonical admission accepted tampered MPC settlement authority",
        ));
    }

    let taker_prepared = settlement
        .prepare_canonical_admission_batch_collaborative(CollaborativeCanonicalAdmissionBatch {
            reserved_candidate: taker_candidate,
            reservation_receipt: &taker_reservation,
            fills: &fills,
            proofs: std::slice::from_ref(&collaborative_settlement.proof),
            round_id: taker_plan.round_id,
            transition: &taker_transition,
            certificate: &taker_certificate,
            arriving: &taker,
            arriving_remaining: taker_execution.result.arriving_remaining,
            now,
        })
        .map_err(|error| failure(error.to_string()))?;
    if settlement.state_snapshot() != taker_base_snapshot {
        return Err(failure(
            "taker entity binding or reservation mutated live state before finality",
        ));
    }
    let taker_acceptance = gateway.settle(&taker_prepared, now)?;
    let accepted_tx = taker_acceptance.transaction_id().to_owned();
    let accepted_height = taker_acceptance.height();
    let accepted_root = taker_acceptance.after_state_root();
    let taker_finality = PrivateStateFinality {
        round_id: taker_plan.round_id,
        public_output_sha256: taker_execution.receipts[0].public_output_sha256,
        transition_digest: taker_transition.digest(),
        canonical_receipt_digest: taker_acceptance.receipt_digest(),
        canonical_height: accepted_height,
    };
    let replay_rejected = gateway.settle(&taker_prepared, now).is_err();
    if !replay_rejected {
        return Err(failure(
            "integrated canonical settlement replay was accepted",
        ));
    }
    let taker_applied = taker_prepared
        .accept(&mut settlement, taker_acceptance)
        .map_err(|error| failure(error.to_string()))?;
    let settlement_receipt = match taker_applied {
        oclob_settlement::AppliedCanonicalTransition::Settlement(receipt) => receipt,
        oclob_settlement::AppliedCanonicalTransition::Reservation(_) => {
            return Err(failure("crossing taker produced no DvP"));
        }
    };
    let canonical_member = settlement_receipt
        .members
        .first()
        .filter(|_| settlement_receipt.members.len() == 1)
        .ok_or_else(|| failure("canonical settlement did not contain exactly one MPC fill"))?;
    if canonical_member.zkpi_digest != collaborative_settlement.zkpi_digest
        || canonical_member.instruction_nullifier != collaborative_settlement.instruction_nullifier
        || canonical_member.package_digest != collaborative_settlement.package_digest
    {
        return Err(failure(
            "canonical DeFMI accepted evidence other than the MPC collaborative proof",
        ));
    }
    let taker_private_state_receipts = finalize_agreed_private_state(
        &cluster,
        &settlement_tls,
        &taker_plan,
        &taker_execution,
        taker_finality.clone(),
        Duration::from_secs(30),
    )
    .map_err(|error| failure(error.to_string()))?;
    let taker_private_state_retry = finalize_agreed_private_state(
        &cluster,
        &settlement_tls,
        &taker_plan,
        &taker_execution,
        taker_finality,
        Duration::from_secs(30),
    )
    .map_err(|error| failure(error.to_string()))?;
    if taker_private_state_retry != taker_private_state_receipts {
        return Err(failure(
            "Taker private-state finality retry was not idempotent",
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
    let maker_portfolio = settlement
        .participant_portfolio(maker.order().participant_handle())
        .map_err(|error| failure(error.to_string()))?;
    let taker_portfolio = settlement
        .participant_portfolio(taker.order().participant_handle())
        .map_err(|error| failure(error.to_string()))?;
    if maker_portfolio.securities != 9_960
        || maker_portfolio.cash != 100_004_000
        || maker_portfolio.reserved_securities != 20
        || taker_portfolio.securities != 10_040
        || taker_portfolio.cash != 99_996_000
        || taker_portfolio.reserved_cash != 0
        || !facility.verify_receipt_chain().map_err(failure)?
        || roots_before_restart != roots_after_restart
    {
        return Err(failure(
            "integrated balances, reserves, receipt chain, or restart recovery failed",
        ));
    }

    Ok(json!({
        "schema": "oclob.distributed-avalanche-acceptance/v4",
        "verdict": "accepted",
        "research": research,
        "environment": "seven MPC containers plus five AvalancheGo validators on one host",
        "evm_used": false,
        "network": network,
        "chain_id": options.chain_id,
        "initial_roots": initial_roots,
        "topology": {
            "mpc_nodes": cluster.nodes.len(),
            "avalanche_validators": clients.len(),
            "operator_hosts": 1,
            "independent_operators_claimed": false,
        },
        "privacy_boundary": {
            "participant_edge_shared_before_coordinator": true,
            "coordinator_received_plain_order": false,
            "maker_signed_admission_receipts": maker_receipt.node_receipts.len(),
            "taker_signed_admission_receipts": taker_receipt.node_receipts.len(),
            "settlement_capability_threshold": cluster.settlement_release_threshold,
            "maker_post_match_releases": maker_release.release_count(),
            "taker_post_match_releases": taker_release.release_count(),
            "maker_releasing_parties": maker_release.releasing_parties(),
            "taker_releasing_parties": taker_release.releasing_parties(),
            "single_pre_match_decryption_key_exists": false,
            "key_shares_released_only_after_durable_mpc_receipt": true,
            "dekyx_binding_finalized_with_reservation": true,
            "mpc_values_bound_to_settlement_capability": true,
            "party_local_private_state_after_finality": true,
            "maker_private_state_receipts": maker_private_state_receipts.len(),
            "taker_private_state_receipts": taker_private_state_receipts.len(),
            "private_state_finality_retry_idempotent": true,
            "dekyx_presentations_verified_by_settlement_gateway": true,
        },
        "distributed_ordering": {
            "quorum": 5,
            "maker_sequence": maker_certificate.sequence,
            "taker_sequence": taker_certificate.sequence,
            "maker_votes": maker_certificate.votes.len(),
            "taker_votes": taker_certificate.votes.len(),
            "certificate_chain_verified_and_persisted_by_each_mpc_node": true,
        },
        "distributed_matching": {
            "protocol": "MP-SPDZ malicious-shamir",
            "parties": 7,
            "max_corrupt_parties": 2,
            "maker_round_receipts": maker_execution.receipts.len(),
            "taker_round_receipts": taker_execution.receipts.len(),
            "private_book_wires_per_node": PRIVATE_BOOK_WIRES,
            "persistence_wires_per_node": PERSISTENCE_WIRES,
            "proof_wires_per_fill_slot": SETTLEMENT_PROOF_WIRES_PER_FILL,
            "distinct_maker_private_state_digests": distinct_private_state_digests(&maker_execution),
            "distinct_taker_private_state_digests": distinct_private_state_digests(&taker_execution),
            "taker_parent_heads_are_party_local": taker_execution.receipts.iter().map(|receipt| receipt.private_parent_digest).collect::<BTreeSet<_>>().len() == cluster.nodes.len(),
            "all_outputs_agreed": true,
            "program_sha256": hex::encode(taker_execution.receipts[0].program_sha256),
            "artifact_sha256": hex::encode(taker_execution.receipts[0].artifact_sha256),
            "price": fills[0].price,
            "quantity": fills[0].quantity,
            "maker_remainder": maker_execution.result.arriving_remaining - fills[0].quantity,
            "taker_remainder": taker_execution.result.arriving_remaining,
        },
        "canonical_settlement": {
            "bootstrap_root": hex::encode(bootstrap_root),
            "maker_reservation_transaction_id": maker_tx,
            "maker_reservation_height": maker_height,
            "maker_reservation_zkpi": maker_reservation.zkpi_digest.map(hex::encode),
            "taker_dvp_transaction_id": accepted_tx,
            "taker_dvp_height": accepted_height,
            "state_root": hex::encode(accepted_root),
            "threshold_amount_range": settlement_receipt.amount_range_is_threshold,
            "threshold_price_range": settlement_receipt.price_range_is_threshold,
            "taker_reservation_finalized_with_dvp": settlement_receipt.arriving_reservation_zkpi_digest.is_some(),
            "canonical_member_matches_collaborative_proof": true,
            "reservation_commitment_mismatch_rejected": reservation_commitment_mismatch_rejected,
            "tampered_output_binding_rejected": tampered_output_binding_rejected,
            "unpinned_proof_key_rejected": unpinned_proof_key_rejected,
            "replay_rejected": replay_rejected,
            "receipt_chain_verified": true,
            "validator_roots_before_restart": roots_before_restart,
            "validator_roots_after_restart": roots_after_restart,
        },
        "collaborative_settlement": collaborative_settlement.report,
        "restart": {
            "node": options.restart_node,
            "elapsed_ms": restart_ms,
            "root_recovered": true,
        },
        "external_binaries": {
            "avalanchego": tool_record(options.avalanchego.as_deref(), true)?,
            "avalanche_network_runner": tool_record(options.runner.as_deref(), false)?,
        },
        "elapsed_ms": started.elapsed().as_secs_f64() * 1_000.0,
        "non_claims": [
            "Seven MPC containers and five AvalancheGo validators on one host are not independent-operator or WAN evidence.",
            "The arriving settlement capability is still opened after durable MPC execution to authorize its atomic pre-trade reservation; the DvP zkPI, proofs, nullifier and canonical account changes come directly from the pinned MPC proof committee without local reproving.",
            "The OCLOB settlement application verifies the full collaborative proof before the DeFMI boundary; the current Avalanche VM verifies committee approval over proof digests and account deltas rather than deserializing that proof.",
            "Transition and DeFMI approval keys are deterministic laboratory keys, not HSM-backed operator custody.",
            "Canonical DeFMI state uses commitment accounts and a reservation root rather than account-free product notes.",
            "One functional scenario is not throughput, security-attack or economic-effect evidence."
        ]
    }))
}

#[allow(clippy::too_many_arguments)]
fn verify_collaborative_fill(
    cluster: &ClusterPublicConfig,
    coordinator_identity: &ClientIdentityConfig,
    maker_receipt: &EdgeAdmissionReceipt,
    taker_receipt: &EdgeAdmissionReceipt,
    taker_certificate: &OrderCertificate,
    taker_plan: &RoundPlan,
    taker_execution: &AgreedRoundExecution,
    frost_public: qomm_zkpi::frost::keys::PublicKeyPackage,
    now: u64,
) -> RunResult<VerifiedCollaborativeSettlement> {
    if !maker_receipt.manifest.settlement_proof_enabled
        || !taker_receipt.manifest.settlement_proof_enabled
        || taker_execution.receipts.len() != cluster.nodes.len()
    {
        return Err(failure(
            "the matched orders do not carry seven-node settlement witnesses",
        ));
    }
    let tls = proof_tls_context(
        &coordinator_identity.tls_certificate,
        &coordinator_identity.tls_private_key,
        &coordinator_identity.tls_ca,
    )
    .map_err(failure)?;
    let mut parties = cluster
        .nodes
        .iter()
        .map(|node| {
            ProofPartyTlsClient::new(
                node.host.clone(),
                node.proof_port,
                tls.clone(),
                node.server_name.clone(),
                Duration::from_secs(120),
            )
        })
        .collect::<Vec<_>>();
    let output_digest = taker_execution.receipts[0].public_output_sha256;
    let job_id = collaborative_job_id(taker_plan.round_id, 0, output_digest).map_err(failure)?;
    // Every proof node independently checks this value against the owner-only
    // sidecar written by the exact MP-SPDZ execution that produced its 616
    // settlement wires. The later transition proof separately commits to the
    // same public output, composing matching finality with zkPI settlement.
    let market_proof_digest = output_digest;
    load_fill(
        &mut parties,
        taker_plan.round_id,
        0,
        job_id,
        market_proof_digest,
    )
    .map_err(failure)?;

    let maker_handle = manifest_point(
        maker_receipt.manifest.settlement_field_commitments[0][0],
        "Maker settlement handle",
    )?;
    let taker_handle = manifest_point(
        taker_receipt.manifest.settlement_field_commitments[0][0],
        "Taker settlement handle",
    )?;
    let maker_reserve = manifest_point(
        maker_receipt.manifest.settlement_field_commitments[1][0],
        "Maker reserve",
    )?;
    let taker_reserve = manifest_point(
        taker_receipt.manifest.settlement_field_commitments[1][0],
        "Taker reserve",
    )?;
    let limit_commitment = manifest_point(
        taker_receipt.manifest.field_commitments[1][0],
        "Taker limit",
    )?;
    let limit_context: [u8; 32] = Sha256::new()
        .chain_update(b"OCLOB:SIGNED-TAKER-LIMIT:v1")
        .chain_update(taker_receipt.manifest.commitment.0)
        .chain_update(taker_certificate.digest())
        .chain_update(market_proof_digest)
        .finalize()
        .into();
    let proof = prove_fill(
        &mut parties,
        frost_public,
        CollaborativeFillRequest {
            job_id,
            market_proof_digest,
            limit_direction: PriceLimitDirection::MaximumBuyPrice,
            limit_commitment,
            limit_context,
            taker_handle,
            asset_id: canonical_securities_asset_id(MARKET),
            deadline: now.saturating_add(600),
            now,
        },
    )
    .map_err(failure)?;
    verify_collaborative_statements(&proof, maker_handle, maker_reserve, taker_reserve)?;
    let package = build_threshold_package_from_proofs(
        &qomm_zk::pedersen::Pedersen::new(b"qomm:defmi:v1"),
        proof.instruction.clone(),
        Sides::of(&proof.instruction),
        maker_reserve,
        taker_reserve,
        proof.cash_commitment,
        proof.dvp_proofs.clone(),
        32,
    )
    .map_err(failure)?;
    let instruction_digest: [u8; 32] =
        Sha256::digest(qomm_zkpi::wire::encode(&proof.instruction)).into();
    let frost_public_digest: [u8; 32] = Sha256::digest(
        proof
            .frost_public
            .serialize()
            .map_err(|_| failure("FROST public package could not be encoded"))?,
    )
    .into();
    let report = json!({
        "proof_job_id": hex::encode(proof.job_id),
        "market_proof_digest": hex::encode(market_proof_digest),
        "zkpi_digest": hex::encode(instruction_digest),
        "instruction_nullifier": hex::encode(proof.instruction.nullifier()),
        "dvp_package_digest": hex::encode(package.digest()),
        "frost_public_package_sha256": hex::encode(frost_public_digest),
        "proof_parties": cluster.nodes.len(),
        "signing_quorum": 3,
        "central_order_reconstruction_for_proof": false,
        "threshold_amount_range": proof.instruction.ranges.is_threshold(),
        "threshold_price_range": proof.instruction.ranges.is_threshold(),
        "limit_proof_verified": true,
        "dvp_product_and_remainders_verified": true,
        "recipient_scoped_openings_verified": true,
        "canonical_dvp_input": true,
        "locally_reproved_for_canonical_settlement": false,
    });
    Ok(VerifiedCollaborativeSettlement {
        proof,
        report,
        zkpi_digest: instruction_digest,
        instruction_nullifier: package.instruction.nullifier(),
        package_digest: package.digest(),
    })
}

fn verify_collaborative_statements(
    proof: &CollaborativeFillProof,
    maker_handle: RistrettoPoint,
    maker_reserve: RistrettoPoint,
    taker_reserve: RistrettoPoint,
) -> RunResult<()> {
    let key = qomm_zk::pedersen::Pedersen::new(b"qomm:defmi:v1");
    if proof.maker_handle != maker_handle
        || proof.instruction.payee_handle != maker_handle
        || proof.instruction.payer_handle == maker_handle
        || !qomm_defmi::asset_link::verify(
            &key,
            &canonical_securities_asset_id(MARKET),
            &proof.instruction.asset_commitment,
            &proof.asset_link,
        )
        || proof.securities_remainder + proof.instruction.amount_commitment != maker_reserve
        || proof.cash_remainder + proof.cash_commitment != taker_reserve
        || proof.maker_pool_remainder != proof.securities_remainder
        || !proof.instruction.ranges.is_threshold()
    {
        return Err(failure(
            "collaborative proof statements differ from the signed edge manifests",
        ));
    }
    for opening in [
        &proof.securities_delivery_opening,
        &proof.securities_refund_opening,
        &proof.cash_delivery_opening,
        &proof.cash_refund_opening,
    ] {
        opening.validate().map_err(failure)?;
    }
    Ok(())
}

fn manifest_point(encoded: [u8; 32], name: &str) -> RunResult<RistrettoPoint> {
    CompressedRistretto(encoded)
        .decompress()
        .ok_or_else(|| failure(format!("{name} commitment is not canonical")))
}

fn validate_integrated_research_binding(
    contract_path: &Path,
    manifest_path: &Path,
) -> RunResult<Value> {
    let contract_bytes = read_limited_bytes(contract_path)?;
    let contract: Value = serde_json::from_slice(&contract_bytes)
        .map_err(|_| failure("integrated research contract is malformed"))?;
    let manifest: Value = read_json_limited(manifest_path)?;
    let contract_id = contract
        .get("contract_id")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("integrated research contract has no id"))?;
    let manifest_contract = manifest.get("contract_id").and_then(Value::as_str);
    let manifest_id = manifest
        .get("manifest_id")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("integrated research manifest has no id"))?;
    let expected_sha = manifest
        .get("contract_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("integrated research manifest has no contract digest"))?;
    let actual_sha: [u8; 32] = Sha256::digest(&contract_bytes).into();
    if contract_id != "oclob-collaborative-canonical-settlement-v1"
        || manifest_contract != Some(contract_id)
        || expected_sha != hex::encode(actual_sha)
        || manifest.get("stage").and_then(Value::as_str)
            != Some("RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC")
        || manifest.get("primary_metric").and_then(Value::as_str)
            != Some("canonical_member_exactly_equals_collaborative_mpc_proof")
    {
        return Err(failure(
            "integrated research contract and manifest are not the approved pair",
        ));
    }
    Ok(json!({
        "contract_id": contract_id,
        "contract_sha256": expected_sha,
        "manifest_id": manifest_id,
        "stage": "RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC",
        "primary_metric": "canonical_member_exactly_equals_collaborative_mpc_proof",
        "observed_value": 1
    }))
}

fn validate_integrated_maker(execution: &AgreedRoundExecution) -> RunResult<()> {
    if execution.result.slots.len() != MAX_MATCH_SLOTS
        || execution.result.arriving_remaining != 60
        || execution
            .result
            .slots
            .iter()
            .any(|slot| slot.matched || slot.trade_price != 0 || slot.trade_quantity != 0)
    {
        return Err(failure(
            "distributed maker round returned an unexpected result",
        ));
    }
    Ok(())
}

fn validate_integrated_taker(execution: &AgreedRoundExecution) -> RunResult<()> {
    if execution.result.slots.len() != MAX_MATCH_SLOTS
        || !execution.result.slots[0].matched
        || execution.result.slots[0].trade_price != 100
        || execution.result.slots[0].trade_quantity != 40
        || execution.result.arriving_remaining != 0
        || execution.result.slots[1..]
            .iter()
            .any(|slot| slot.matched || slot.trade_price != 0 || slot.trade_quantity != 0)
    {
        return Err(failure(
            "distributed taker round returned an unexpected result",
        ));
    }
    Ok(())
}

fn distinct_private_state_digests(execution: &AgreedRoundExecution) -> usize {
    execution
        .receipts
        .iter()
        .map(|receipt| receipt.private_state_sha256)
        .collect::<BTreeSet<_>>()
        .len()
}

fn validate_private_state_chain(
    maker: &AgreedRoundExecution,
    taker: &AgreedRoundExecution,
) -> RunResult<()> {
    let maker_parents = maker
        .receipts
        .iter()
        .map(|receipt| receipt.private_parent_digest)
        .collect::<BTreeSet<_>>();
    let taker_parents = taker
        .receipts
        .iter()
        .map(|receipt| receipt.private_parent_digest)
        .collect::<BTreeSet<_>>();
    if maker.receipts.len() != oclob_edge::MPC_PARTIES
        || taker.receipts.len() != oclob_edge::MPC_PARTIES
        || maker_parents.len() != 1
        || taker_parents.len() != oclob_edge::MPC_PARTIES
        || taker_parents == maker_parents
        || distinct_private_state_digests(maker) != oclob_edge::MPC_PARTIES
        || distinct_private_state_digests(taker) != oclob_edge::MPC_PARTIES
        || maker.receipts.iter().any(|receipt| {
            receipt.private_parent_digest == [0; 32] || receipt.private_state_sha256 == [0; 32]
        })
        || taker.receipts.iter().any(|receipt| {
            receipt.private_parent_digest == [0; 32] || receipt.private_state_sha256 == [0; 32]
        })
    {
        return Err(failure(
            "party-local private book state did not carry from Maker finality into the Taker round",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verified_round_transition(
    committee: &OrderingCommittee,
    certificate: &OrderCertificate,
    plan: &RoundPlan,
    execution: &AgreedRoundExecution,
    eligibility_proof_digest: [u8; 32],
    fills: &[PublicFill],
    private_before_root: [u8; 32],
    public_before_root: [u8; 32],
) -> RunResult<(VerifiedTransitionProof, [u8; 32], [u8; 32])> {
    if execution.receipts.is_empty()
        || execution.receipts[0].round_id != plan.round_id
        || certificate.commitment != plan.arriving
        || certificate.digest() != plan.ordering_certificate.digest()
    {
        return Err(failure(
            "distributed execution is not bound to its ordering certificate",
        ));
    }
    let private_after_root = chained_round_root(
        b"OCLOB:DISTRIBUTED:PRIVATE-ROUND:v1",
        private_before_root,
        plan,
        &execution.receipts[0].public_output_sha256,
    );
    let public_after_root = chained_round_root(
        b"OCLOB:DISTRIBUTED:PUBLIC-ROUND:v1",
        public_before_root,
        plan,
        &public_fills_digest(fills),
    );
    let proof = TransitionProof::attest(
        TransitionStatement {
            market_id: certificate.market_id.clone(),
            sequence: certificate.sequence,
            order_certificate_digest: certificate.digest(),
            eligibility_proof_digest,
            private_before_root,
            private_after_root,
            public_before_root,
            public_after_root,
            mpc_program_digest: execution.receipts[0].program_sha256,
            mpc_output_digest: execution.receipts[0].public_output_sha256,
            fill_digest: public_fills_digest(fills),
        },
        &committee.transition_signers(),
        committee.policy(),
    )?
    .into_verified(&committee.verifying_keys(), committee.policy())?;
    Ok((proof, private_after_root, public_after_root))
}

fn chained_round_root(
    domain: &[u8],
    before: [u8; 32],
    plan: &RoundPlan,
    output: &[u8; 32],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(before)
        .chain_update(plan.round_id)
        .chain_update(output)
        .finalize()
        .into()
}

fn tagged_digest(domain: &[u8], body: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update((body.len() as u64).to_be_bytes())
        .chain_update(body)
        .finalize()
        .into()
}

fn hidden_eligibility_commitment(order: &SecretOrder) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"OCLOB:LAB-ELIGIBILITY-COMMITMENT:v1")
        .chain_update(order.dekyx_nullifier())
        .chain_update(order.market_id().as_bytes())
        .finalize()
        .into()
}

fn run_compatibility(options: &Options) -> RunResult<Value> {
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

fn read_json_limited<T: DeserializeOwned>(path: &Path) -> RunResult<T> {
    Ok(serde_json::from_slice(&read_limited_bytes(path)?)?)
}

fn read_limited_bytes(path: &Path) -> RunResult<Vec<u8>> {
    const MAX_BYTES: u64 = 4 * 1024 * 1024;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_BYTES
    {
        return Err(failure(format!(
            "refusing unsafe or oversized JSON input {}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(failure(format!(
            "refusing oversized input {}",
            path.display()
        )));
    }
    Ok(bytes)
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
