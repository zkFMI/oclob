//! Live native-note settlement coordinator. No issuer or participant secrets.
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use ed25519_dalek::{SigningKey, VerifyingKey};
use oclob_edge::SealedReservationAuthority;
use oclob_node::edge_client::{
    collect_order_certificate, collect_threshold_capability_release, execute_agreed_round,
    finalize_agreed_private_state, EdgeAdmissionReceipt,
};
use oclob_node::executor::RoundPlan;
use oclob_node::network::{
    client_tls_context, load_secret_32, ClientIdentityConfig, ClusterPublicConfig,
};
use oclob_node::PrivateStateFinality;
use oclob_settlement::collaborative::{
    collaborative_job_id, load_fill, prove_fill, CollaborativeFillRequest,
};
use oclob_settlement::native::{
    certify_native_fill, prepare_native_fill, NativeFillAuthorizationRequest,
    NativeReservationAuthority,
};
use oclob_settlement::pretrade::PrivateAdmissionClient;
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge};
use qomm_defmi::facility::QuorumAuthorizer;
use qomm_proofs::price_limit::PriceLimitDirection;
use qomm_transport::node_service::client_ssl_context;
use qomm_transport::proof_client::ProofPartyTlsClient;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(error) = run() {
        eprintln!("native settlement failed: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let manifest: Value = read(
        &std::env::var("OCLOB_RESEARCH_MANIFEST")
            .unwrap_or_else(|_| "/research/manifests/oclob_native_notes_001.json".into()),
    )?;
    let contract = fs::read(
        std::env::var("OCLOB_RESEARCH_CONTRACT")
            .unwrap_or_else(|_| "/research/oclob_native_notes_contract.json".into()),
    )?;
    let contract_hash = hex::encode(Sha256::digest(&contract));
    if manifest["contract_sha256"] != contract_hash
        || !matches!(
            manifest["contract_id"].as_str(),
            Some("oclob-native-notes-v1" | "oclob-native-recovery-v1")
        )
        || manifest["stage"] != "RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC"
    {
        return Err("native research preflight failed".into());
    }
    let cluster: ClusterPublicConfig = read("/public/cluster.json")?;
    cluster.validate()?;
    let coordinator: ClientIdentityConfig = read("/identity/client.json")?;
    coordinator.validate()?;
    let settlement: ClientIdentityConfig = read("/settlement/client.json")?;
    settlement.validate()?;
    let maker: EdgeAdmissionReceipt = read("/handoff/maker.json")?;
    let taker: EdgeAdmissionReceipt = read("/handoff/taker.json")?;
    maker.verify(&cluster, now()?)?;
    taker.verify(&cluster, now()?)?;
    if !maker.manifest.uses_pretrade_reservation() || !taker.manifest.uses_pretrade_reservation() {
        return Err("native acceptance refuses legacy raw-order capabilities".into());
    }
    let public = qomm_zkpi::frost::keys::PublicKeyPackage::deserialize(&fs::read(
        "/handoff/native-committee.bin",
    )?)?;
    let key = SigningKey::from_bytes(&load_secret_32(&coordinator.application_signing_key)?);
    let tls = client_tls_context(
        &coordinator.tls_certificate,
        &coordinator.tls_private_key,
        &coordinator.tls_ca,
    )?;
    let settlement_tls = client_tls_context(
        &settlement.tls_certificate,
        &settlement.tls_private_key,
        &settlement.tls_ca,
    )?;
    let proof_tls = client_ssl_context(
        &coordinator.tls_certificate,
        &coordinator.tls_private_key,
        &coordinator.tls_ca,
    )?;
    let private = PrivateAdmissionClient::new(
        "oclob-defmi",
        9443,
        "oclob-defmi",
        proof_tls.clone(),
        Duration::from_secs(120),
    )?;
    let scope: ApplicationReserveScope = serde_json::from_value(private.call("scope", json!({}))?)?;
    if scope.committee_key_digest != <[u8; 32]>::from(Sha256::digest(public.serialize()?)) {
        return Err("native scope has another MPC committee".into());
    }
    let issuer_bytes: [u8; 32] = read("/public/native-issuer.json")?;
    let issuer = VerifyingKey::from_bytes(&issuer_bytes)?;
    let client = private.chain()?;
    let readonly = QuorumAuthorizer::new(
        BTreeMap::from([("read-only".into(), issuer)]),
        1,
        1,
        "read-only",
    )?;
    let bridge = AvalancheNoteBridge::new(&readonly, &client);
    let maker_certificate = collect_order_certificate(
        &cluster,
        &tls,
        None,
        maker.commitment(),
        maker.manifest.retention_deadline,
        Duration::from_secs(30),
    )?;
    let maker_plan = RoundPlan::sign(
        maker_certificate.clone(),
        vec![],
        now()?,
        now()? + 300,
        &key,
    )?;
    let maker_execution =
        execute_agreed_round(&cluster, &tls, &maker_plan, Duration::from_secs(300))?;
    if maker_execution.result.slots.iter().any(|fill| fill.matched) {
        return Err("first native order unexpectedly matched".into());
    }
    // A no-fill admission leaves the source shares unchanged. Do not invent a
    // canonical trade receipt just to copy unchanged shares into private state.
    let taker_certificate = collect_order_certificate(
        &cluster,
        &tls,
        Some(&maker_certificate),
        taker.commitment(),
        taker.manifest.retention_deadline,
        Duration::from_secs(30),
    )?;
    let plan = RoundPlan::sign(
        taker_certificate.clone(),
        vec![maker.commitment()],
        now()?,
        now()? + 300,
        &key,
    )?;
    let execution = execute_agreed_round(&cluster, &tls, &plan, Duration::from_secs(300))?;
    if execution
        .result
        .slots
        .iter()
        .filter(|fill| fill.matched)
        .count()
        != 1
        || execution.result.slots[0].trade_price != 100
        || execution.result.slots[0].trade_quantity != 40
        || execution.result.arriving_remaining != 0
    {
        return Err("native scenario did not produce exactly one fill".into());
    }
    let open = |receipt: &EdgeAdmissionReceipt,
                path|
     -> Result<NativeReservationAuthority, Box<dyn std::error::Error>> {
        let envelope: SealedReservationAuthority = read(path)?;
        let release = collect_threshold_capability_release(
            &cluster,
            &settlement_tls,
            &plan,
            &execution,
            &receipt.manifest,
            receipt.commitment(),
            Duration::from_secs(30),
        )?;
        let authority = release.open_reservation(
            &envelope,
            &receipt.manifest,
            scope.venue_id,
            scope.defmi_id,
            &issuer,
            now()?,
        )?;
        Ok(NativeReservationAuthority::from(&authority))
    };
    let maker_authority = open(&maker, "/handoff/maker-capability.json")?;
    let taker_authority = open(&taker, "/handoff/taker-capability.json")?;
    let maker_head =
        client.application_reservation_snapshot(maker_authority.permit.reservation_id)?;
    let taker_head =
        client.application_reservation_snapshot(taker_authority.permit.reservation_id)?;
    if maker_head.sequence != 0 || taker_head.sequence != 0 {
        return Err("initial native holds were already consumed".into());
    }
    let reserve_sequences = [
        client
            .credit_facility_snapshot(maker_authority.permit.facility_id)?
            .facility
            .sequence,
        client
            .credit_facility_snapshot(taker_authority.permit.facility_id)?
            .facility
            .sequence,
    ];
    if reserve_sequences != [1, 1] {
        return Err("native fixture contains duplicate or unexpected pretrade reservations".into());
    }
    let output = execution.receipts[0].public_output_sha256;
    let job = collaborative_job_id(plan.round_id, 0, output)?;
    let mut parties = cluster
        .nodes
        .iter()
        .map(|node| {
            ProofPartyTlsClient::new(
                &node.host,
                node.proof_port,
                proof_tls.clone(),
                &node.server_name,
                Duration::from_secs(120),
            )
        })
        .collect::<Vec<_>>();
    load_fill(&mut parties, plan.round_id, 0, job, output)?;
    let proof = prove_fill(
        &mut parties,
        public,
        CollaborativeFillRequest {
            job_id: job,
            market_proof_digest: output,
            limit_direction: PriceLimitDirection::MaximumBuyPrice,
            limit_commitment: point(taker.manifest.field_commitments[1][0])?,
            limit_context: Sha256::new()
                .chain_update(b"OCLOB:SIGNED-TAKER-LIMIT:v1")
                .chain_update(taker.commitment().0)
                .chain_update(taker_certificate.digest())
                .chain_update(output)
                .finalize()
                .into(),
            taker_handle: point(taker_authority.permit.participant_handle)?,
            asset_id: maker_authority.permit.asset_id,
            deadline: maker
                .manifest
                .retention_deadline
                .min(taker.manifest.retention_deadline),
            now: now()?,
        },
    )?;
    for (index, party) in parties.iter_mut().enumerate() {
        party.call(
            if [0, 3, 6].contains(&index) {
                "complete"
            } else {
                "complete_observer"
            },
            json!({"job_id": hex::encode(job)}),
        )?;
    }
    let fill = prepare_native_fill(
        &proof,
        scope,
        &maker_authority,
        &taker_authority,
        &maker_head,
        &taker_head,
        true,
    )?;
    let request = NativeFillAuthorizationRequest {
        round_id: plan.round_id,
        slot: 0,
        fill,
        maker: maker_authority,
        taker: taker_authority,
    };
    let mut substituted = request.clone();
    substituted.fill.mpc_result_digest[0] ^= 1;
    if certify_native_fill(&mut parties, &substituted).is_ok() {
        return Err("resident node signed a substituted MPC result".into());
    }
    let signed = certify_native_fill(&mut parties, &request)?;
    let accepted = bridge.settle_application(&signed)?;
    let after_maker = client.application_reservation_snapshot(maker_head.binding.hold_id)?;
    let after_taker = client.application_reservation_snapshot(taker_head.binding.hold_id)?;
    if after_maker.sequence != 1
        || after_maker.status != "active"
        || after_maker.remaining_opening.is_none()
        || after_taker.sequence != 1
        || after_taker.status != "consumed"
    {
        return Err("native canonical reserve lifecycle differs from the fill".into());
    }
    // Exact transport retry returns the existing receipt, never a second fill.
    let retry = bridge.settle_application(&signed)?;
    if retry.tx_id != accepted.tx_id || client.state_root()? != accepted.after_root {
        return Err("native retry applied a second state transition".into());
    }
    let finality = PrivateStateFinality {
        round_id: plan.round_id,
        public_output_sha256: output,
        transition_digest: signed.signing_message()?,
        canonical_receipt_digest: accepted.statement,
        canonical_height: accepted.height,
    };
    finalize_agreed_private_state(
        &cluster,
        &settlement_tls,
        &plan,
        &execution,
        finality,
        Duration::from_secs(30),
    )?;
    let result = json!({"native_note_settlement": true, "contract_sha256": contract_hash,
        "manifest_id": manifest["manifest_id"], "verdict": "smoke_only", "mpc_nodes": 7,
        "post_match_participant_signatures": 0, "raw_order_capability_opened": false,
        "canonical_transaction": accepted.tx_id, "canonical_height": accepted.height,
        "exact_retry_did_not_apply_twice": true, "native_after_root": hex::encode(accepted.after_root),
        "substituted_mpc_output_rejected_by_resident_node": true,
        "trade_price": execution.result.slots[0].trade_price,
        "trade_quantity": execution.result.slots[0].trade_quantity,
        "pretrade_facility_sequences": reserve_sequences,
        "mpc_output_sha256": hex::encode(output),
        "zkpi_sha256": hex::encode(Sha256::digest(&signed.instruction)),
        "maker_reserve_active": true, "taker_reserve_closed": true, "elapsed_ms": started.elapsed().as_millis()});
    let pending = format!("/handoff/.native-result-{}.json", std::process::id());
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(&pending)?;
    file.write_all(&serde_json::to_vec_pretty(&result)?)?;
    file.sync_all()?;
    // The observer must never see a partially written receipt. A hard link
    // publishes atomically and refuses to replace a previous final result.
    fs::hard_link(&pending, "/handoff/native-result.json")?;
    fs::remove_file(&pending)?;
    println!("{}", result);
    Ok(())
}
fn read<T: DeserializeOwned>(path: &str) -> Result<T, Box<dyn std::error::Error>> {
    let path = Path::new(path);
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return Err("native input file is outside its bound".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn point(bytes: [u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(bytes)
        .decompress()
        .ok_or("invalid native point".into())
}
fn now() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
