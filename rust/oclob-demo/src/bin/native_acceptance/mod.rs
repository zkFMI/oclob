//! Native-note path. This module never reads corporate wallet configuration.
use super::*;
use ed25519_dalek::{Signature, Signer};
use oclob_node::native_admission::{AdmissionAuthority, AdmissionRpcServer};
use oclob_node::network::{server_tls_context, Principal};
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::avalanche::AvalancheNoteBridge;
use qomm_defmi::facility::{
    AssetDefinition, AssetKind, CreditFacilityGrant, GuarantorDefinition, GuarantorKind,
};
use qomm_defmi::note_chain::{CsdIssuerDefinition, NoteIssuance, NoteOutput};
use serde::Deserialize;
use zkpi_defmi_sdk::application::oclob_manifest_v1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabFunding {
    asset: [u8; 32],
    facility: [u8; 32],
    entity: [u8; 32],
    capacity: [u8; 32],
    notes: Vec<Value>,
}

/// Reuse the known-working ANR startup, but keep its five validators alive
/// while separate corporate and matching containers connect over mTLS.
pub(super) fn serve(options: &Options) -> RunResult<Value> {
    let contract_path = PathBuf::from(std::env::var("OCLOB_RESEARCH_CONTRACT")?);
    let manifest_path = PathBuf::from(std::env::var("OCLOB_RESEARCH_MANIFEST")?);
    let contract = fs::read(&contract_path)?;
    let manifest: Value = read_json_limited(&manifest_path)?;
    let contract_hash = hex::encode(Sha256::digest(&contract));
    if manifest["contract_sha256"] != contract_hash
        || manifest["stage"] != "RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC"
        || !matches!(
            manifest["contract_id"].as_str(),
            Some(
                "oclob-native-notes-v1"
                    | "oclob-native-recovery-v1"
                    | "oclob-native-wallet-v1"
                    | "oclob-native-finality-v1"
                    | "oclob-native-multifill-v1"
                    | "oclob-native-cycle-v1"
                    | "oclob-native-lifecycle-v1"
                    | "oclob-native-worker-v1"
                    | "oclob-native-expiry-v1"
                    | "oclob-native-expiry-v2"
                    | "oclob-native-deferred-v1"
                    | "oclob-native-market-v1"
                    | "oclob-native-depth-v1"
                    | "oclob-native-http-v1"
            )
        )
    {
        return Err(failure(
            "native-note research contract/manifest preflight failed",
        ));
    }
    let clients = rpc_clients(&options.node_uris, &options.chain_id)?;
    if clients.len() != 5 {
        return Err(failure("native-note acceptance needs five live validators"));
    }
    // ANR health can precede the custom VM's HTTP readiness (observed 503).
    // Wait only on reads before issuing any financial/governance operation;
    // never replay an ambiguous write as a startup workaround.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match agreed_roots(&clients) {
            Ok(_) => break,
            Err(error) if Instant::now() >= deadline => {
                return Err(failure(format!(
                    "native DeFMI read readiness failed: {error}"
                )));
            }
            Err(_) => thread::sleep(Duration::from_millis(200)),
        }
    }
    let (authorizer, signers) = committee(&options.chain_id)?;
    let bridge = AvalancheNoteBridge::new(&authorizer, &clients[0]);
    let funding: Vec<LabFunding> = read_json_limited(Path::new("/defmi/funding.json"))?;
    if funding.len() != 2 {
        return Err(failure(
            "native lab needs exactly two independently held funding wallets",
        ));
    }
    let issuer_signer = SigningKey::generate(&mut rand::rngs::OsRng);
    let approve = |statement| authorizer.approve(statement, clients[0].state_root()?, &signers);
    let now = unix_seconds()?;
    let policy = digest(b"oclob-native-lab-funding-policy-v1");
    for entry in &funding {
        let is_cash = entry.asset == oclob_settlement::canonical_cash_asset_id();
        let asset = AssetDefinition {
            asset_id: entry.asset,
            code: if is_cash { "JPY" } else { "JGB10Y" }.into(),
            kind: if is_cash {
                AssetKind::Cash
            } else {
                AssetKind::Security
            },
            decimals: 0,
            terms_digest: policy,
        };
        bridge.register_asset(&asset, &approve(asset.statement()?)?)?;
    }
    let mut assets = funding.iter().map(|entry| entry.asset).collect::<Vec<_>>();
    assets.sort();
    assets.dedup();
    let csd = CsdIssuerDefinition {
        issuer_id: digest(b"oclob-native-lab-csd-v1"),
        code: "OCLOB-LAB".into(),
        jurisdiction: "LAB".into(),
        operator_entity_commitment: digest(b"oclob-native-lab-operator-v1"),
        public_key: issuer_signer.verifying_key().to_bytes(),
        permitted_asset_ids: assets,
        policy_digest: policy,
        valid_from: now,
        valid_until: now + 3600,
    };
    bridge.register_csd_issuer(&csd, &approve(csd.statement()?)?)?;
    let guarantor = GuarantorDefinition {
        guarantor_id: digest(b"oclob-native-lab-guarantor-v1"),
        kind: GuarantorKind::SelfGuaranteed,
        name: "OCLOB laboratory funding authority".into(),
        public_key: issuer_signer.verifying_key().to_bytes(),
        risk_policy_digest: policy,
    };
    bridge.register_guarantor(&guarantor, &approve(guarantor.statement()?)?)?;
    for entry in &funding {
        let mut grant = CreditFacilityGrant {
            operation_id: tagged_digest(b"OCLOB:LAB:GRANT:v1", &entry.facility),
            facility_id: entry.facility,
            guarantor_id: guarantor.guarantor_id,
            beneficiary_commitment: entry.entity,
            rail_asset_id: entry.asset,
            cap_commitment: entry.capacity,
            available_commitment: entry.capacity,
            held_commitment: [0; 32],
            outstanding_commitment: [0; 32],
            collateral_commitment: entry.capacity,
            risk_policy_digest: policy,
            relation_proof_digest: policy,
            valid_from: now,
            valid_until: now + 3600,
            nonce: entry.facility,
            guarantor_signature: Signature::from_bytes(&[0; 64]),
        };
        grant.guarantor_signature = issuer_signer.sign(&grant.guarantor_message()?);
        bridge.grant_credit_facility(&grant, &approve(grant.statement()?)?)?;
        for note in &entry.notes {
            let output = NoteOutput::from_body(note)?;
            let issuance = NoteIssuance {
                operation_id: tagged_digest(b"OCLOB:LAB:NOTE:v1", &output.note_id),
                issuance_nonce: output.note_id,
                issuer_id: csd.issuer_id,
                issued_at: unix_seconds()?,
                output,
                proof_digest: policy,
                issuer_signature: Signature::from_bytes(&[0; 64]),
            }
            .sign_issuer(&issuer_signer)?;
            bridge.issue_note(&issuance, &approve(issuance.statement()?)?)?;
        }
    }
    let public_bytes = fs::read("/handoff/native-committee.bin")?;
    let public = qomm_zkpi::frost::keys::PublicKeyPackage::deserialize(&public_bytes)?;
    let scope = ApplicationReserveScope {
        application_binding: oclob_manifest_v1().digest()?,
        venue_id: digest(b"defmi:oclob:v1"),
        defmi_id: digest(b"oclob-integrated-defmi-v1"),
        committee_key_digest: Sha256::digest(public.serialize()?).into(),
        committee_epoch: 1,
        amount_bits: 32,
    };
    bridge.register_application_scope(&scope, &approve(scope.statement()?)?)?;
    wait_for_roots(&clients, clients[0].state_root()?, Duration::from_secs(30))?;
    let tls = server_tls_context("/defmi/tls.pem", "/defmi/tls-key.pem", "/public/ca.pem")?;
    let principals: Vec<Principal> = read_json_limited(Path::new("/defmi/principals.json"))?;
    let receipt_issuer =
        SigningKey::from_bytes(&load_secret_32(Path::new("/defmi/receipt-key.raw"))?);
    let (eligibility, _) = deterministic_demo_environment(MARKET)?;
    let service = AdmissionRpcServer::start(
        "0.0.0.0:9443".parse()?,
        tls,
        principals,
        AdmissionAuthority {
            client: rpc_clients(&options.node_uris[..1], &options.chain_id)?.remove(0),
            authorizer,
            governance_signers: signers,
            receipt_issuer,
            scope: scope.clone(),
            eligibility,
        },
    )?;
    write_json_atomic(
        Path::new("/out/native-ready.json"),
        &json!({"scope": scope, "contract_sha256": contract_hash, "validators": 5}),
    )?;
    eprintln!("native DeFMI ready: five live validators; corporate wallets can reserve over mTLS");
    let started = Instant::now();
    while !Path::new("/handoff/native-result.json").exists() {
        if started.elapsed() > Duration::from_secs(1200) {
            return Err(failure(
                "native corporate/matching acceptance did not produce a result",
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
    let result: Value = read_json_limited(Path::new("/handoff/native-result.json"))?;
    if matches!(
        manifest["contract_id"].as_str(),
        Some("oclob-native-expiry-v1" | "oclob-native-expiry-v2")
    ) {
        if result["reconciled_expired_requests"] != 2
            || result["never_reserved"] != 1
            || result["completed_native_releases"] != 1
            || result["mpc_nodes_down_during_reconciliation"] != 7
            || result["next_order_admitted_nodes"] != 7
            || result["exact_released_note_reused"] != true
            || result["worker_restart_unchanged"] != true
            || result["release_response_loss_recovered"] != true
            || result["contract_sha256"] != contract_hash
        {
            return Err(failure("native queued expiry acceptance is incomplete"));
        }
    } else if result["native_note_settlement"] != true {
        return Err(failure("native settlement result is incomplete"));
    }
    if manifest["contract_id"] == "oclob-native-market-v1"
        && (result["admitted_orders"] != 3
            || result["completed_market_rounds"] != 3
            || result["autonomously_settled_fills"] != 2
            || result["trade_notional"] != 9030
            || result["node_finality_observations"] != 14
            || result["post_match_participant_signatures"] != 0
            || result["restart_did_not_duplicate_settlement"] != true
            || result["canonical_response_loss_recovered"] != true
            || result["contract_sha256"] != contract_hash)
    {
        return Err(failure("resident native market acceptance is incomplete"));
    }
    if (manifest["contract_id"] == "oclob-native-depth-v1"
        || manifest["contract_id"] == "oclob-native-http-v1")
        && (result["admitted_orders"] != 4
            || result["completed_market_rounds"] != 4
            || result["canonically_published_depth_snapshots"] != 4
            || result["trade_notional"] != 7500
            || result["autonomously_settled_fills"] != 2
            || result["node_finality_observations"] != 14
            || result["post_match_participant_signatures"] != 0
            || result["restart_did_not_duplicate_settlement"] != true
            || result["canonical_response_loss_recovered"] != true
            || result["public_depth_stays_old_before_finality"] != true
            || result["network_reader_requires_no_corporate_keys_or_journal"] != true
            || result["contract_sha256"] != contract_hash)
    {
        return Err(failure("native depth acceptance is incomplete"));
    }
    if manifest["contract_id"] == "oclob-native-http-v1"
        && (result["http_verified_depth_snapshots"] != 4 || result["http_fail_closed_checks"] != 6)
    {
        return Err(failure("native HTTP book acceptance is incomplete"));
    }
    if manifest["contract_id"] == "oclob-native-finality-v1"
        && (result["node_observed_canonical_finality"] != 7
            || result["unsettled_and_unobserved_finality_rejected_by_all_nodes"] != true
            || result["substituted_canonical_fill_rejected_by_all_nodes"] != true
            || result["canonical_observation_retry_unchanged"] != true
            || result["recovered_note_funded_next_order"] != true)
    {
        return Err(failure("native finality/reuse acceptance is incomplete"));
    }
    let expected: [u8; 32] = hex::decode(
        // The cycle contract additionally requires actual settlement after reuse.
        // The accepted transaction has already been read independently by all
        // seven nodes; this observer additionally checks five real validators.
        result["native_after_root"]
            .as_str()
            .ok_or("native result lacks final root")?,
    )?
    .try_into()
    .map_err(|_| "native result root has incorrect length")?;
    let roots = wait_for_roots(&clients, expected, Duration::from_secs(30))?;
    if manifest["contract_id"] == "oclob-native-cycle-v1"
        && (result["completed_native_rounds"] != 2
            || result["total_native_fills"] != 3
            || result["recipient_claims_redeemed"] != 8
            || result["next_order_matched"] != true
            || result["recovered_note_funded_next_order"] != true
            || result["final_facility_sequences"] != json!([5, 5]))
    {
        return Err(failure("native repeated settlement cycle is incomplete"));
    }
    if matches!(
        manifest["contract_id"].as_str(),
        Some("oclob-native-lifecycle-v1" | "oclob-native-worker-v1")
    ) && (result["completed_native_rounds"] != 2
        || result["completed_native_releases"] != 2
        || result["recipient_claims_redeemed"] != 9
        || result["final_facility_sequences"] != json!([8, 5])
        || result["expiry_wallet"]["unfilled_releases_recovered"] != 1
        || result["node_restart_state_preserved"] != true
        || result["cancellation_refund_funded_expiry_order"] != true)
    {
        return Err(failure(
            "native cancellation/expiry lifecycle is incomplete",
        ));
    }
    if manifest["contract_id"] == "oclob-native-worker-v1"
        && (result["corporate_worker"]["completed_dispatches"] != 1
            || result["corporate_worker"]["waiting_without_dispatch"] != true
            || result["corporate_worker"]["reserve_response_loss_recovered"] != true
            || result["corporate_worker"]["node_response_loss_recovered"] != true
            || result["corporate_worker"]["actual_restart_unchanged"] != true
            || result["corporate_worker"]["admission_matches_settled_order"] != true)
    {
        return Err(failure("native corporate worker recovery is incomplete"));
    }
    if manifest["contract_id"] == "oclob-native-deferred-v1"
        && (result["deferred_authorization"]["queued_without_funding"] != 3
            || result["deferred_authorization"]["accepted_maker_orders"] != 2
            || result["deferred_authorization"]["over_capacity_rejected"] != 1
            || result["deferred_authorization"]["worker_restart_unchanged"] != true)
    {
        return Err(failure(
            "native deferred authorization acceptance is incomplete",
        ));
    }
    if matches!(
        manifest["contract_id"].as_str(),
        Some("oclob-native-multifill-v1" | "oclob-native-deferred-v1")
    ) && (result["atomic_multi_fill"] != true
        || result["fill_count"] != 2
        || result["atomically_settled_fills"] != 2
        || result["node_observed_canonical_finality"] != 14
        || result["partial_observation_did_not_advance"] != true
        || result["batch_extraction_rejected"] != true
        || result["posttrade_facility_sequences"] != json!([4, 3]))
    {
        return Err(failure("native atomic multi-fill acceptance is incomplete"));
    }
    drop(service);
    restart_validator(
        options
            .runner
            .as_deref()
            .ok_or("native acceptance requires ANR restart verification")?,
        &options.runner_endpoint,
        &options.restart_node,
        options.plugin_dir.as_deref(),
    )?;
    let recovered_roots = wait_for_roots(&clients, expected, Duration::from_secs(30))?;
    Ok(
        json!({"status": "smoke_only", "contract_sha256": contract_hash,
        "manifest_id": manifest["manifest_id"], "native": result, "validator_roots": roots,
        "validator_restart_recovered": true, "recovered_validator_roots": recovered_roots,
        "independent_operators": false, "wan_evidence": false}),
    )
}
