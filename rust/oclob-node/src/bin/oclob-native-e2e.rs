//! Live native-note settlement coordinator. No issuer or participant secrets.
#![recursion_limit = "256"]

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use defmi::application_reservation::ApplicationReserveScope;
use defmi::application_settlement::ApplicationNoteFillBatch;
use defmi::avalanche::{AvalancheClient, AvalancheNoteBridge};
use defmi::facility::QuorumAuthorizer;
use oclob_core::application_crypto::SigningKey;
use oclob_edge::SealedReservationAuthority;
use oclob_node::corporate_api::request_claim_authorizations;
use oclob_node::edge_client::{
    collect_order_certificate, collect_threshold_capability_release, execute_agreed_round,
    finalize_agreed_private_state, EdgeAdmissionReceipt,
};
use oclob_node::executor::RoundPlan;
use oclob_node::native_finality::{
    aggregate_finality, NativeFinalityRecord, NativeFinalityRequest,
};
use oclob_node::network::{
    client_tls_context, load_application_signing_seed, ClientIdentityConfig, ClusterPublicConfig,
    NetworkError, NodeRpcClient,
};
use oclob_node::PrivateStateFinality;
use oclob_settlement::collaborative::{
    collaborative_job_id, load_fill, prove_fill, CollaborativeFillRequest,
};
use oclob_settlement::native::{
    certify_native_fill, claim_authorization_evidence, native_batch_binding,
    native_claim_authorization_issue, prepare_native_fill, project_pending_native_head,
    NativeFillAuthorizationRequest, NativeFillClaimAuthorizations, NativeReservationAuthority,
};
use oclob_settlement::pretrade::PrivateAdmissionClient;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zkpi_committee::node_service::client_ssl_context;
use zkpi_committee::proof_client::ProofPartyTlsClient;
use zkpi_proofs::price_limit::PriceLimitDirection;

#[path = "native_expiry_acceptance/mod.rs"]
mod expiry_acceptance;
#[path = "native_lifecycle_acceptance/mod.rs"]
mod lifecycle_acceptance;

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
            Some(
                "oclob-native-notes-v1"
                    | "oclob-native-recovery-v1"
                    | "oclob-native-wallet-v1"
                    | "oclob-native-finality-v1"
                    | "oclob-native-finality-v2"
                    | "oclob-native-multifill-v1"
                    | "oclob-native-cycle-v1"
                    | "oclob-native-lifecycle-v1"
                    | "oclob-native-lifecycle-v2"
                    | "oclob-native-worker-v1"
                    | "oclob-native-expiry-v1"
                    | "oclob-native-expiry-v2"
                    | "oclob-native-deferred-v1"
            )
        )
        || manifest["stage"] != "RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC"
    {
        return Err("native research preflight failed".into());
    }
    let cluster: ClusterPublicConfig = read("/public/cluster.json")?;
    cluster.validate()?;
    let coordinator: ClientIdentityConfig = read("/identity/client.json")?;
    coordinator.validate()?;
    if matches!(
        manifest["contract_id"].as_str(),
        Some("oclob-native-expiry-v1" | "oclob-native-expiry-v2")
    ) {
        return expiry_acceptance::run(&cluster, &coordinator, &manifest, &contract_hash);
    }
    let settlement: ClientIdentityConfig = read("/settlement/client.json")?;
    settlement.validate()?;
    let lifecycle = matches!(
        manifest["contract_id"].as_str(),
        Some("oclob-native-lifecycle-v1" | "oclob-native-lifecycle-v2" | "oclob-native-worker-v1")
    );
    if let Ok(phase) = std::env::var("OCLOB_NATIVE_LIFECYCLE_PHASE") {
        if !lifecycle {
            return Err("lifecycle execution needs its bound contract".into());
        }
        return lifecycle_acceptance::run(
            &phase,
            &contract_hash,
            manifest["contract_id"] == "oclob-native-worker-v1",
        );
    }
    let cycle = manifest["contract_id"] == "oclob-native-cycle-v1" || lifecycle;
    let next_match = std::env::var("OCLOB_NATIVE_NEXT_MATCH").ok().as_deref() == Some("1");
    if next_match && !cycle {
        return Err("next-match mode needs its cycle contract".into());
    }
    let maker: EdgeAdmissionReceipt = read(if next_match {
        "/handoff/maker2.json"
    } else {
        "/handoff/maker.json"
    })?;
    let taker: EdgeAdmissionReceipt = read(if next_match {
        "/handoff/reuse-taker.json"
    } else {
        "/handoff/taker.json"
    })?;
    let multifill = matches!(
        manifest["contract_id"].as_str(),
        Some("oclob-native-multifill-v1" | "oclob-native-deferred-v1")
    ) || (cycle && !next_match);
    let mut makers = vec![maker.clone()];
    if multifill {
        makers.push(read("/handoff/maker2.json")?);
    }
    for receipt in &makers {
        receipt.verify(&cluster, now()?)?;
    }
    maker.verify(&cluster, now()?)?;
    taker.verify(&cluster, now()?)?;
    if !maker.manifest.uses_pretrade_reservation() || !taker.manifest.uses_pretrade_reservation() {
        return Err("native acceptance refuses legacy raw-order capabilities".into());
    }
    let public = zkpi::frost::keys::PublicKeyPackage::deserialize(&fs::read(
        "/handoff/native-committee.bin",
    )?)?;
    let key = SigningKey::from_bytes(&load_application_signing_seed(
        &coordinator.application_signing_key,
    )?);
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
    let pq_committee: zkpi::QuorumPolicy = read("/handoff/native-committee.pq.json")?;
    scope.verify_committee(&public.serialize()?, &pq_committee)?;
    if scope.committee_key_digest != <[u8; 32]>::from(Sha256::digest(public.serialize()?)) {
        return Err("native scope has another MPC committee".into());
    }
    let issuer: Vec<u8> = read("/public/native-issuer.json")?;
    if issuer.len() != 1984 {
        return Err("legacy issuer key requires PQC re-enrollment".into());
    }
    let client = private.chain()?;
    if std::env::var("OCLOB_NATIVE_WALLET_FINALIZE")
        .ok()
        .as_deref()
        == Some("1")
    {
        return if cycle {
            finalize_cycle_acceptance(&client, &cluster, &contract_hash, lifecycle)
        } else {
            finalize_wallet_acceptance(&client, &cluster, &contract_hash)
        };
    }
    let readonly = QuorumAuthorizer::read_only();
    let bridge = AvalancheNoteBridge::new(&readonly, &client);
    let maker_certificate = if next_match {
        // Public signed sequence checkpoint only. Each node still selects its
        // own finalized private remainder rather than this caller's quantities.
        read("/handoff/native-first-certificate.json")?
    } else {
        collect_order_certificate(
            &cluster,
            &tls,
            None,
            maker.commitment(),
            maker.manifest.retention_deadline,
            Duration::from_secs(30),
        )?
    };
    if !next_match {
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
    }
    // A no-fill admission leaves the source shares unchanged. Do not invent a
    // canonical trade receipt just to copy unchanged shares into private state.
    let mut previous_certificate = maker_certificate.clone();
    if multifill {
        previous_certificate = collect_order_certificate(
            &cluster,
            &tls,
            Some(&maker_certificate),
            makers[1].commitment(),
            makers[1].manifest.retention_deadline,
            Duration::from_secs(30),
        )?;
        let second_plan = RoundPlan::sign(
            previous_certificate.clone(),
            vec![maker.commitment()],
            now()?,
            now()? + 300,
            &key,
        )?;
        let second_execution =
            execute_agreed_round(&cluster, &tls, &second_plan, Duration::from_secs(300))?;
        if second_execution
            .result
            .slots
            .iter()
            .any(|fill| fill.matched)
        {
            return Err("second resting sell unexpectedly matched".into());
        }
    }
    let taker_certificate = collect_order_certificate(
        &cluster,
        &tls,
        Some(&previous_certificate),
        taker.commitment(),
        taker.manifest.retention_deadline,
        Duration::from_secs(30),
    )?;
    let plan = RoundPlan::sign(
        taker_certificate.clone(),
        makers.iter().map(|receipt| receipt.commitment()).collect(),
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
        != makers.len()
        || execution.result.slots[0].trade_price != if next_match { 101 } else { 100 }
        || execution.result.slots[0].trade_quantity
            != if next_match {
                1
            } else if multifill {
                60
            } else {
                40
            }
        || (multifill
            && (execution.result.slots[1].trade_price != 101
                || execution.result.slots[1].trade_quantity != 30))
        || execution.result.arriving_remaining != 0
    {
        return Err("native scenario did not produce the exact expected fills".into());
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
    let mut maker_authorities = vec![open(
        &maker,
        if next_match {
            "/handoff/maker2-capability.json"
        } else {
            "/handoff/maker-capability.json"
        },
    )?];
    if multifill {
        maker_authorities.push(open(&makers[1], "/handoff/maker2-capability.json")?);
    }
    let maker_authority = &maker_authorities[0];
    let taker_authority = open(
        &taker,
        if next_match {
            "/handoff/reuse-taker-authority.json"
        } else {
            "/handoff/taker-capability.json"
        },
    )?;
    let maker_head =
        client.application_reservation_snapshot(maker_authority.permit.reservation_id)?;
    let mut taker_head =
        client.application_reservation_snapshot(taker_authority.permit.reservation_id)?;
    if maker_head.sequence != u64::from(next_match) || taker_head.sequence != 0 {
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
    if reserve_sequences
        != if next_match {
            [4, 4]
        } else {
            [makers.len() as u64, 1]
        }
    {
        return Err("native fixture contains duplicate or unexpected pretrade reservations".into());
    }
    let output = execution.receipts[0].public_output_sha256;
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
    let slots = (0..makers.len()).collect::<Vec<_>>();
    let mut requests = Vec::new();
    for slot in &slots {
        let maker_authority = &maker_authorities[*slot];
        let maker_head =
            client.application_reservation_snapshot(maker_authority.permit.reservation_id)?;
        let job = collaborative_job_id(plan.round_id, *slot, output)?;
        load_fill(&mut parties, plan.round_id, *slot, job, output)?;
        let proof = prove_fill(
            &mut parties,
            public.clone(),
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
                deadline: makers[*slot]
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
        let claim_issue = native_claim_authorization_issue(
            &proof,
            maker_authority,
            &taker_authority,
            &maker_head,
            &taker_head,
        )?;
        let prior_fills = requests
            .iter()
            .map(|request: &NativeFillAuthorizationRequest| request.fill.clone())
            .collect::<Vec<_>>();
        let payer_authority =
            if maker_authority.permit.reservation_id == claim_issue.payer.reservation_id {
                maker_authority
            } else {
                &taker_authority
            };
        let payee_authority =
            if maker_authority.permit.reservation_id == claim_issue.payee.reservation_id {
                maker_authority
            } else {
                &taker_authority
            };
        let claim_authorizations = NativeFillClaimAuthorizations {
            payer: request_claim_authorizations(
                &payer_authority.claim_authorization_endpoint,
                &coordinator,
                claim_issue.payer.reservation_id,
                &claim_issue,
                &prior_fills,
                payer_authority.order_signer,
            )?,
            payee: request_claim_authorizations(
                &payee_authority.claim_authorization_endpoint,
                &coordinator,
                claim_issue.payee.reservation_id,
                &claim_issue,
                &prior_fills,
                payee_authority.order_signer,
            )?,
        };
        let mut fill = prepare_native_fill(
            &proof,
            scope.clone(),
            maker_authority,
            &taker_authority,
            &maker_head,
            &taker_head,
            &claim_authorizations,
            *slot == slots.len() - 1,
        )?;
        fill.batch = native_batch_binding(
            &scope,
            fill.before_root,
            plan.round_id,
            output,
            &slots,
            *slot,
        )?;
        let request = NativeFillAuthorizationRequest {
            round_id: plan.round_id,
            slot: *slot,
            fill,
            maker: maker_authority.clone(),
            taker: taker_authority.clone(),
            claim_authorizations,
        };
        let mut substituted = request.clone();
        substituted.fill.mpc_result_digest[0] ^= 1;
        if certify_native_fill(&mut parties, &substituted).is_ok() {
            return Err("resident node signed a substituted MPC result".into());
        }
        if multifill {
            let mut extracted = request.clone();
            extracted.fill.batch = None;
            match certify_native_fill(&mut parties, &extracted) {
                Err(error) if error.contains("locally executed matched slots") => {}
                _ => return Err("node did not reject signing an extracted member".into()),
            }
        }
        let signed = certify_native_fill(&mut parties, &request)?;
        if multifill && *slot + 1 < slots.len() {
            taker_head = project_pending_native_head(&taker_head, &signed, now()?)?;
        }
        requests.push(NativeFillAuthorizationRequest {
            fill: signed,
            ..request
        });
    }
    let signed = &requests[0].fill;
    if lifecycle && next_match {
        let command: oclob_node::native_lifecycle::LifecycleCommand =
            read("/handoff/maker-cancel.json")?;
        for node in &cluster.nodes {
            let rpc = NodeRpcClient::new(node.endpoint(), tls.clone(), Duration::from_secs(30))?;
            let before = rpc.status()?;
            match rpc.stage_lifecycle(command.clone()) {
                Err(NetworkError::Remote(code)) if code == "ordering_rejected" => {}
                _ => {
                    return Err("node allowed a cancellation to overtake unsettled matching".into())
                }
            }
            if rpc.status()? != before {
                return Err("refused early cancellation changed the store".into());
            }
        }
    }
    let batch = multifill.then(|| ApplicationNoteFillBatch {
        version: 1,
        fills: requests
            .iter()
            .map(|request| request.fill.clone())
            .collect(),
    });
    let statement = match &batch {
        Some(batch) => batch.statement()?,
        None => signed.signing_message()?,
    };
    let claimed = PrivateStateFinality {
        round_id: plan.round_id,
        public_output_sha256: output,
        transition_digest: statement,
        canonical_receipt_digest: statement,
        canonical_height: 1,
    };
    let reject_unobserved =
        |finality: &PrivateStateFinality| -> Result<(), Box<dyn std::error::Error>> {
            for (node, receipt) in cluster.nodes.iter().zip(&execution.receipts) {
                let reader =
                    NodeRpcClient::new(node.endpoint(), tls.clone(), Duration::from_secs(30))?;
                let writer = NodeRpcClient::new(
                    node.endpoint(),
                    settlement_tls.clone(),
                    Duration::from_secs(30),
                )?;
                let before = reader.status()?;
                match writer.finalize_private_state(plan.clone(), finality.clone(), receipt) {
                    Err(NetworkError::Remote(code)) if code == "state_unavailable" => {}
                    _ => {
                        return Err(
                            "node did not explicitly reject an unobserved canonical finality"
                                .into(),
                        )
                    }
                }
                if reader.status()? != before {
                    return Err("rejected finality changed node state".into());
                }
            }
            Ok(())
        };
    reject_unobserved(&claimed)?;
    if let Some(batch) = &batch {
        let before = client.state_root()?;
        for member in &batch.fills {
            match bridge.settle_application(member) {
                Err(error) if error.contains("batch member cannot settle individually") => {}
                _ => return Err("DeFMI did not reject an extracted signed member".into()),
            }
        }
        if client.state_root()? != before {
            return Err("rejected extraction changed canonical state".into());
        }
    }
    let accepted = match &batch {
        Some(batch) => bridge.settle_application_batch(batch)?,
        None => bridge.settle_application(signed)?,
    };
    let after_maker = client.application_reservation_snapshot(maker_head.binding.hold_id)?;
    let after_taker = client.application_reservation_snapshot(taker_head.binding.hold_id)?;
    if after_maker.sequence != maker_head.sequence + 1
        || after_maker.status != "active"
        || after_maker.remaining_opening.is_none()
        || after_taker.sequence != makers.len() as u64
        || after_taker.status != "consumed"
    {
        return Err("native canonical reserve lifecycle differs from the fill".into());
    }
    // Exact transport retry returns the existing receipt, never a second fill.
    if multifill {
        let second =
            client.application_reservation_snapshot(maker_authorities[1].permit.reservation_id)?;
        let verified = requests[1].fill.verify(&scope, now()?)?;
        if second.sequence != 1
            || second.remaining_commitment != verified.remaining[0]
            || after_taker.remaining_commitment != verified.remaining[1]
        {
            return Err("cumulative native reservation head differs from the proofs".into());
        }
    }
    let retry = match &batch {
        Some(batch) => bridge.settle_application_batch(batch)?,
        None => bridge.settle_application(signed)?,
    };
    if retry.tx_id != accepted.tx_id || client.state_root()? != accepted.after_root {
        return Err("native retry applied a second state transition".into());
    }
    let finality = PrivateStateFinality {
        round_id: plan.round_id,
        public_output_sha256: output,
        transition_digest: statement,
        canonical_receipt_digest: accepted.statement,
        canonical_height: accepted.height,
    };
    // Even a true coordinator assertion is insufficient until this particular
    // node has independently read and bound the configured canonical record.
    reject_unobserved(&finality)?;
    let mut confirmed = Vec::new();
    for (member_index, request) in requests.iter().enumerate() {
        let confirmation = NativeFinalityRequest {
            authorization: request.clone(),
            transaction_id: accepted.tx_id.clone(),
            batch: batch.clone(),
        };
        for (index, party) in parties.iter_mut().enumerate() {
            let reader = NodeRpcClient::new(
                cluster.nodes[index].endpoint(),
                tls.clone(),
                Duration::from_secs(30),
            )?;
            let before = reader.status()?;
            let mut substituted = confirmation.clone();
            substituted.authorization.fill.before_root[0] ^= 1;
            match party.call(
                "confirm_oclob_native_finality",
                serde_json::to_value(&substituted)?,
            ) {
                Err(error)
                    if error
                        .contains("configured DeFMI has not confirmed this exact native fill")
                        || error.contains(
                            "confirmed batch does not contain this exact signed fill",
                        ) => {}
                Err(error) => return Err(format!("canonical parent substitution reached unexpected guard on node {index}: {error}").into()),
                Ok(_) => {
                    return Err(
                        "node did not reject substituted canonical transaction bytes".into(),
                    )
                }
            }
            if reader.status()? != before {
                return Err("rejected canonical observation changed node state".into());
            }
            let record: NativeFinalityRecord = serde_json::from_value(party.call(
                "confirm_oclob_native_finality",
                serde_json::to_value(&confirmation)?,
            )?)?;
            if record.transaction_id != accepted.tx_id
                || record.before_root != accepted.before_root
                || record.after_root != accepted.after_root
                || record.block_id != accepted.block_id
                || aggregate_finality(&BTreeMap::from([(record.slot, record.clone())]))? != finality
            {
                return Err("nodes observed inconsistent native canonical evidence".into());
            }
            let once = reader.status()?;
            let again: NativeFinalityRecord = serde_json::from_value(party.call(
                "confirm_oclob_native_finality",
                serde_json::to_value(&confirmation)?,
            )?)?;
            if again != record || reader.status()? != once {
                return Err("repeated canonical observation changed node state".into());
            }
            confirmed.push(record);
        }
        if member_index + 1 < requests.len() {
            reject_unobserved(&finality)?;
        }
    }
    let mut wrong_height = finality.clone();
    wrong_height.canonical_height += 1;
    reject_unobserved(&wrong_height)?;
    let finalized = finalize_agreed_private_state(
        &cluster,
        &settlement_tls,
        &plan,
        &execution,
        finality.clone(),
        Duration::from_secs(30),
    )?;
    let repeated = finalize_agreed_private_state(
        &cluster,
        &settlement_tls,
        &plan,
        &execution,
        finality,
        Duration::from_secs(30),
    )?;
    if repeated != finalized {
        return Err("exact private-head finalization retry changed signed state receipts".into());
    }
    let (claim_signatures, claim_key_fingerprints) = claim_authorization_evidence(&requests)?;
    let mut result = json!({"native_note_settlement": true, "contract_sha256": contract_hash,
        "manifest_id": manifest["manifest_id"], "verdict": "smoke_only", "mpc_nodes": 7,
        "post_match_participant_signatures": claim_signatures,
        "claim_authorization_response_signatures": claim_signatures,
        "fresh_claim_authorization_keys": claim_key_fingerprints.len(),
        "claim_authorization_key_fingerprints": claim_key_fingerprints.iter().map(hex::encode).collect::<Vec<_>>(),
        "post_match_financial_approval_signatures": 0, "raw_order_capability_opened": false,
        "canonical_transaction": accepted.tx_id, "canonical_height": accepted.height,
        "exact_retry_did_not_apply_twice": true, "native_after_root": hex::encode(accepted.after_root),
        "substituted_mpc_output_rejected_by_resident_node": true,
        "node_observed_canonical_finality": confirmed.len(),
        "unsettled_and_unobserved_finality_rejected_by_all_nodes": true,
        "substituted_canonical_fill_rejected_by_all_nodes": true,
        "canonical_observation_retry_unchanged": true,
        "observed_finality_height_substitution_rejected_by_all_nodes": true,
        "private_finalization_retry_unchanged": true,
        "trade_price": execution.result.slots[0].trade_price,
        "trade_quantity": execution.result.slots[0].trade_quantity,
        "atomic_multi_fill": multifill, "fill_count": requests.len(),
        "atomically_settled_fills": requests.len(),
        "arriving_order_commitment": plan.arriving.hex(),
        "resting_order_commitments": plan.resting.iter().map(|order| order.hex()).collect::<Vec<_>>(),
        "maker_head_sequence_before": maker_head.sequence,
        "maker_head_sequence_after": after_maker.sequence,
        "fills": execution.result.slots.iter().filter(|s| s.matched).collect::<Vec<_>>(),
        "batch_extraction_rejected": multifill,
        "partial_observation_did_not_advance": multifill,
        "same_maker_legal_entity": multifill,
        "posttrade_facility_sequences": [client.credit_facility_snapshot(maker_authorities[0].permit.facility_id)?.facility.sequence, client.credit_facility_snapshot(taker_authority.permit.facility_id)?.facility.sequence],
        "pretrade_facility_sequences": reserve_sequences,
        "mpc_output_sha256": hex::encode(output),
        "zkpi_sha256": hex::encode(Sha256::digest(&signed.instruction)),
        "maker_reserve_active": true, "taker_reserve_closed": true, "elapsed_ms": started.elapsed().as_millis()});
    if manifest["contract_id"] == "oclob-native-deferred-v1" {
        result["deferred_authorization"] = verify_deferred_intake(&makers)?;
    }
    if cycle && !next_match {
        publish_result(
            &serde_json::to_value(&taker_certificate)?,
            "/handoff/native-first-certificate.json",
        )?;
    }
    if lifecycle && next_match {
        publish_result(
            &serde_json::to_value(&taker_certificate)?,
            "/handoff/native-second-certificate.json",
        )?;
    }
    let target = if next_match {
        "/handoff/native-next-match-result.json"
    } else if std::env::var("OCLOB_NATIVE_WALLET").ok().as_deref() == Some("1") {
        "/handoff/native-match-result.json"
    } else {
        "/handoff/native-result.json"
    };
    publish_result(&result, target)?;
    println!("{}", result);
    Ok(())
}

fn verify_deferred_intake(
    makers: &[EdgeAdmissionReceipt],
) -> Result<Value, Box<dyn std::error::Error>> {
    let stopped = fs::read_to_string("/handoff/deferred-nodes-stopped.txt")?;
    if stopped.lines().count() != 7
        || stopped.lines().any(|l| l != "false")
        || fs::read_to_string("/handoff/deferred-defmi-paused.txt")?.trim() != "true"
    {
        return Err("deferred intake did not run during actual MPC and DeFMI outage".into());
    }
    let before: Vec<Value> = read("/handoff/deferred-before.json")?;
    let after: Vec<Value> = read("/handoff/deferred-after.json")?;
    let queue_before: Value = read("/handoff/deferred-queue-before-restart.json")?;
    let queue_after: Value = read("/handoff/deferred-queue-after-restart.json")?;
    let rejected: Value = read("/handoff/deferred-rejected.json")?;
    if before.len() != 3
        || after.len() != 3
        || queue_before != queue_after
        || rejected["status"] != "funding_rejected"
        || rejected["funding_prepared"] != false
    {
        return Err("deferred queue did not reject overcommit or survive restart".into());
    }
    let mut accepted = std::collections::BTreeSet::new();
    for original in &before {
        let updated = after
            .iter()
            .find(|a| a["request_id"] == original["request_id"])
            .ok_or("deferred request disappeared")?;
        if original["funding_prepared"] != false
            || original["admitted"] != false
            || original["authorization_digest"]
                .as_str()
                .is_none_or(|v| v.len() != 64)
            || original["authorization_digest"] != updated["authorization_digest"]
            || original["order_commitment"] != updated["order_commitment"]
        {
            return Err("deferred intake prepared funding offline or changed signed terms".into());
        }
        if original["request_id"] == "native-maker-too-large" {
            if updated["funding_prepared"] != false
                || updated["admitted"] != false
                || updated["ended"] != true
            {
                return Err("over-capacity request produced a financial reserve".into());
            }
        } else {
            if updated["funding_prepared"] != true
                || updated["admitted"] != true
                || updated["ended"] != false
            {
                return Err("deferred accepted maker did not reach real MPC admission".into());
            }
            accepted.insert(
                updated["order_commitment"]
                    .as_str()
                    .ok_or("missing admitted commitment")?
                    .to_owned(),
            );
        }
    }
    // The admission manifest binds the signed original source order to the
    // funded order. Its final commitment additionally includes the reservation
    // admission; equating the two would reject every legitimate native reserve.
    if accepted.len() != 2
        || makers
            .iter()
            .map(|m| hex::encode(m.manifest.source_order_commitment))
            .collect::<std::collections::BTreeSet<_>>()
            != accepted
    {
        return Err("deferred makers differ from the makers actually settled".into());
    }
    Ok(
        json!({"queued_without_funding":3,"accepted_maker_orders":2,"over_capacity_rejected":1,
        "actual_mpc_outage":true,"actual_defmi_pause":true,"concurrent_intake_clients":2,
        "original_authorizations_unchanged":true,"worker_restart_unchanged":true}),
    )
}

fn publish_result(result: &Value, target: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    fs::hard_link(&pending, target)?;
    fs::remove_file(&pending)?;
    Ok(())
}

fn finalize_cycle_acceptance<C: AvalancheClient>(
    client: &C,
    cluster: &ClusterPublicConfig,
    contract_hash: &str,
    continues_lifecycle: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first: Value = read("/handoff/native-match-result.json")?;
    let next: Value = read("/handoff/native-next-match-result.json")?;
    let reuse: EdgeAdmissionReceipt = read("/handoff/reuse-taker.json")?;
    reuse.verify(cluster, now()?)?;
    let source: Value = read("/handoff/reuse-taker.corporate.json")?;
    let first_claim_signatures = first["claim_authorization_response_signatures"]
        .as_u64()
        .ok_or("first native round lacks claim response evidence")?;
    let next_claim_signatures = next["claim_authorization_response_signatures"]
        .as_u64()
        .ok_or("next native round lacks claim response evidence")?;
    let first_claim_fingerprints = first["claim_authorization_key_fingerprints"]
        .as_array()
        .ok_or("first native round lacks claim key fingerprints")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or("first native round has an invalid claim key fingerprint")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_claim_fingerprints = next["claim_authorization_key_fingerprints"]
        .as_array()
        .ok_or("next native round lacks claim key fingerprints")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or("next native round has an invalid claim key fingerprint")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut all_claim_fingerprints = BTreeSet::new();
    for fingerprint in first_claim_fingerprints
        .iter()
        .chain(&next_claim_fingerprints)
    {
        let decoded: [u8; 32] = hex::decode(fingerprint)?
            .try_into()
            .map_err(|_| "claim authorization key fingerprint has incorrect length")?;
        if !all_claim_fingerprints.insert(decoded) {
            return Err("claim authorization key was reused across native rounds".into());
        }
    }
    let first_claim_keys = u64::try_from(first_claim_fingerprints.len())
        .map_err(|_| "first native round claim key count overflow")?;
    let next_claim_keys = u64::try_from(next_claim_fingerprints.len())
        .map_err(|_| "next native round claim key count overflow")?;
    if first["contract_sha256"] != contract_hash
        || next["contract_sha256"] != contract_hash
        || first["native_note_settlement"] != true
        || next["native_note_settlement"] != true
        || first["atomically_settled_fills"] != 2
        || next["atomically_settled_fills"] != 1
        || first["node_observed_canonical_finality"] != 14
        || next["node_observed_canonical_finality"] != 7
        || first_claim_signatures != 4
        || next_claim_signatures != 2
        || first_claim_keys != 8
        || next_claim_keys != 4
        || first["post_match_participant_signatures"] != first_claim_signatures
        || next["post_match_participant_signatures"] != next_claim_signatures
        || first["fresh_claim_authorization_keys"] != first_claim_keys
        || next["fresh_claim_authorization_keys"] != next_claim_keys
        || first["post_match_financial_approval_signatures"] != 0
        || next["post_match_financial_approval_signatures"] != 0
        || next["trade_price"] != 101
        || next["trade_quantity"] != 1
        || next["maker_head_sequence_before"] != 1
        || next["maker_head_sequence_after"] != 2
        || next["arriving_order_commitment"] != reuse.commitment().hex()
        || source["order_commitment"] != reuse.commitment().hex()
        || source["selected_funding_note_spent_verified"] != true
        || source["canonical_reserve_verified"] != true
        || source["facility_sequence"] != 4
        || first["canonical_transaction"] == next["canonical_transaction"]
    {
        return Err("native cycle is missing its exact refund-funded second match".into());
    }
    for (path, count, sequence, final_report) in [
        ("/handoff/maker.wallet.json", 2, 4, false),
        ("/handoff/taker.wallet.json", 3, 3, false),
        ("/handoff/maker-cycle-final.wallet.json", 3, 5, true),
        ("/handoff/taker-cycle-final.wallet.json", 5, 5, true),
    ] {
        let report: Value = read(path)?;
        if report["wallet_recovered"] != true
            || report["expected_private_balances_verified"] != true
            || report["notes"] != count
            || report["facility_sequence"] != sequence
        {
            return Err("corporate cycle recovery did not validate the expected balances".into());
        }
        let notes = report["canonical_notes"]
            .as_array()
            .ok_or("cycle notes missing")?;
        if notes.len() != count as usize {
            return Err("cycle note count differs".into());
        }
        for note in notes {
            let id: [u8; 32] = hex::decode(note.as_str().ok_or("invalid cycle note")?)?
                .try_into()
                .map_err(|_| "invalid cycle note length")?;
            let canonical = client.note_snapshot(id)?;
            if canonical.output.note_id != id || canonical.output.lock_id != [0; 32] {
                return Err("cycle note is not the canonical recipient output".into());
            }
        }
        if final_report {
            let id: [u8; 32] = hex::decode(
                report["facility_id"]
                    .as_str()
                    .ok_or("cycle facility absent")?,
            )?
            .try_into()
            .map_err(|_| "cycle facility length differs")?;
            if client.credit_facility_snapshot(id)?.facility.sequence != sequence {
                return Err("canonical cycle facility differs from the private witness".into());
            }
        }
    }
    first["first_settlement_root"] = first["native_after_root"].clone();
    first["native_after_root"] = json!(hex::encode(client.state_root()?));
    first["next_match"] = next;
    first["completed_native_rounds"] = json!(2);
    first["total_native_fills"] = json!(3);
    first["post_match_participant_signatures"] =
        json!(first_claim_signatures + next_claim_signatures);
    first["claim_authorization_response_signatures"] =
        json!(first_claim_signatures + next_claim_signatures);
    first["fresh_claim_authorization_keys"] = json!(first_claim_keys + next_claim_keys);
    first["claim_authorization_key_fingerprints"] = json!(all_claim_fingerprints
        .into_iter()
        .map(hex::encode)
        .collect::<Vec<_>>());
    first["post_match_financial_approval_signatures"] = json!(0);
    first["recipient_claims_redeemed"] = json!(8);
    first["private_facility_witnesses_recovered"] = json!(4);
    first["recovered_note_funded_next_order"] = json!(true);
    first["next_order_matched"] = json!(true);
    first["next_order_mpc_nodes"] = json!(7);
    first["final_facility_sequences"] = json!([5, 5]);
    let target = if continues_lifecycle {
        "/handoff/native-cycle-complete.json"
    } else {
        "/handoff/native-result.json"
    };
    publish_result(&first, target)?;
    println!("{}", first);
    Ok(())
}

fn finalize_wallet_acceptance<C: AvalancheClient>(
    client: &C,
    cluster: &ClusterPublicConfig,
    contract_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut result: Value = read("/handoff/native-match-result.json")?;
    if result["contract_sha256"] != contract_hash || result["native_note_settlement"] != true {
        return Err("wallet acceptance lacks its exact preceding settlement".into());
    }
    let maker: Value = read("/handoff/maker.wallet.json")?;
    let taker: Value = read("/handoff/taker.wallet.json")?;
    for (report, count) in [(&maker, 1), (&taker, 2)] {
        if report["wallet_recovered"] != true
            || report["expected_private_balances_verified"] != true
            || report["notes"] != count
            || report["facility_sequence"] != 2
        {
            return Err("corporate recovery report did not verify its actual wallet".into());
        }
        let notes = report["canonical_notes"]
            .as_array()
            .ok_or("recovered canonical notes absent")?;
        if notes.len() != count as usize {
            return Err("wallet note count differs".into());
        }
        for note in notes {
            let id: [u8; 32] = hex::decode(note.as_str().ok_or("invalid recovered note ID")?)?
                .try_into()
                .map_err(|_| "recovered note ID has wrong length")?;
            let canonical = client.note_snapshot(id)?;
            if canonical.output.note_id != id || canonical.output.lock_id != [0; 32] {
                return Err("recovered note is not the actual unlocked canonical output".into());
            }
        }
    }
    let reuse: EdgeAdmissionReceipt = read("/handoff/reuse-taker.json")?;
    reuse.verify(cluster, now()?)?;
    let source: Value = read("/handoff/reuse-taker.corporate.json")?;
    if !reuse.manifest.uses_pretrade_reservation()
        || source["order_commitment"] != reuse.commitment().hex()
        || source["selected_funding_note_spent_verified"] != true
        || source["canonical_reserve_verified"] != true
        || source["facility_sequence"] != 3
    {
        return Err("new order did not prove consumption of its selected recovered note".into());
    }
    for (report, sequence) in [(&maker, 2), (&taker, 3)] {
        let id: [u8; 32] =
            hex::decode(report["facility_id"].as_str().ok_or("facility ID absent")?)?
                .try_into()
                .map_err(|_| "facility ID has wrong length")?;
        if client.credit_facility_snapshot(id)?.facility.sequence != sequence {
            return Err("canonical facility did not advance through wallet reuse".into());
        }
    }
    result["native_settlement_root"] = result["native_after_root"].clone();
    result["native_after_root"] = json!(hex::encode(client.state_root()?));
    result["recipient_claims_redeemed"] = json!(3);
    result["private_facility_witnesses_recovered"] = json!(2);
    result["recovered_note_funded_next_order"] = json!(true);
    result["next_order_mpc_nodes"] = json!(7);
    result["next_order_commitment"] = json!(reuse.commitment().hex());
    result["next_order_matched"] = json!(false);
    result["verdict"] = json!("smoke_only");
    publish_result(&result, "/handoff/native-result.json")?;
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
