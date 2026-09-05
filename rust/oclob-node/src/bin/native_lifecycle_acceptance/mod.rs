//! Actual native lifecycle laboratory, reusing the resident protocol and VM.
use super::*;
use oclob_node::native_lifecycle::{
    certify_native_release, order_lifecycle, LifecycleCommand, LifecycleFinality,
    NativeReleaseConfirmation, NativeReleaseRequest,
};
use oclob_ordering::OrderCertificate;
use qomm_defmi::application_settlement::ApplicationNoteRelease;

pub(super) fn run(phase: &str, contract_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cluster: ClusterPublicConfig = read("/public/cluster.json")?;
    cluster.validate()?;
    let coordinator: ClientIdentityConfig = read("/identity/client.json")?;
    let settlement: ClientIdentityConfig = read("/settlement/client.json")?;
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
    let client = private.chain()?;
    let scope: ApplicationReserveScope = serde_json::from_value(private.call("scope", json!({}))?)?;
    let issuer = VerifyingKey::from_bytes(&read::<[u8; 32]>("/public/native-issuer.json")?)?;
    let readonly = QuorumAuthorizer::new(
        BTreeMap::from([("read-only".into(), issuer)]),
        1,
        1,
        "read-only",
    )?;
    let bridge = AvalancheNoteBridge::new(&readonly, &client);
    let read_node_states =
        || -> Result<Vec<oclob_node::NodeStoreStatus>, Box<dyn std::error::Error>> {
            cluster
                .nodes
                .iter()
                .map(|node| {
                    Ok(
                        NodeRpcClient::new(node.endpoint(), tls.clone(), Duration::from_secs(30))?
                            .status()?,
                    )
                })
                .collect()
        };
    if phase == "checkpoint" {
        publish_result(
            &serde_json::to_value(read_node_states()?)?,
            "/handoff/native-terminal-node-states.json",
        )?;
        return Ok(());
    }
    if phase == "final" {
        let mut cycle: Value = read("/handoff/native-cycle-complete.json")?;
        if cycle["contract_sha256"] != contract_hash || cycle["completed_native_rounds"] != 2 {
            return Err("lifecycle is missing its real continuing settlement cycle".into());
        }
        for (phase, expected_seq) in [("cancel", 6), ("expiry", 8)] {
            let result: Value = read(&format!("/handoff/native-{phase}-result.json"))?;
            let wallet: Value = read(&format!("/handoff/maker-{phase}-final.wallet.json"))?;
            if result["node_observations"] != 7
                || result["exact_retry_unchanged"] != true
                || wallet["expected_private_balances_verified"] != true
                || wallet["facility_sequence"] != expected_seq
                || wallet["notes"] != 4
            {
                return Err("native lifecycle or recovered wallet is incomplete".into());
            }
            cycle[phase] = result;
            cycle[format!("{phase}_wallet")] = wallet;
        }
        if cycle["expiry_wallet"]["unfilled_releases_recovered"] != 1 {
            return Err("expiry did not return the original note to the corporate wallet".into());
        }
        let checkpoint: Vec<oclob_node::NodeStoreStatus> =
            read("/handoff/native-terminal-node-states.json")?;
        let reopened = read_node_states()?;
        verify_terminal_restart(&checkpoint, &reopened)?;
        let funding: Value = read("/handoff/expiry-maker.corporate.json")?;
        let order: EdgeAdmissionReceipt = read("/handoff/expiry-maker.json")?;
        // This post-expiry read verifies the signed admission at its original
        // deadline; it does not make the order eligible for another match.
        order.verify(&cluster, order.manifest.retention_deadline)?;
        if funding["selected_funding_note_spent_verified"] != true
            || funding["canonical_reserve_verified"] != true
            || funding["facility_sequence"] != 7
            || funding["order_commitment"] != order.commitment().hex()
        {
            return Err(
                "expiry order was not funded from the exact recovered cancellation note".into(),
            );
        }
        cycle["node_restart_state_preserved"] = json!(true);
        cycle["node_restart_states"] = serde_json::to_value(reopened)?;
        cycle["cancellation_refund_funded_expiry_order"] = json!(true);
        cycle["native_after_root"] = json!(hex::encode(client.state_root()?));
        cycle["completed_native_releases"] = json!(2);
        cycle["recipient_claims_redeemed"] = json!(9);
        cycle["final_facility_sequences"] = json!([8, 5]);
        publish_result(&cycle, "/handoff/native-result.json")?;
        return Ok(());
    }
    if !matches!(phase, "cancel" | "expiry") {
        return Err("unknown native lifecycle phase".into());
    }
    let expired = phase == "expiry";
    let receipt: EdgeAdmissionReceipt = read(if expired {
        "/handoff/expiry-maker.json"
    } else {
        "/handoff/maker2.json"
    })?;
    receipt.verify(&cluster, now()?)?;
    let mut previous: OrderCertificate = read(if expired {
        "/handoff/native-cancel-certificate.json"
    } else {
        "/handoff/native-second-certificate.json"
    })?;
    if expired {
        previous = collect_order_certificate(
            &cluster,
            &tls,
            Some(&previous),
            receipt.commitment(),
            receipt.manifest.retention_deadline,
            Duration::from_secs(30),
        )?;
        let key = SigningKey::from_bytes(&load_secret_32(&coordinator.application_signing_key)?);
        let plan = RoundPlan::sign(
            previous.clone(),
            vec![],
            now()?,
            receipt.manifest.retention_deadline,
            &key,
        )?;
        let execution = execute_agreed_round(&cluster, &tls, &plan, Duration::from_secs(120))?;
        if execution.result.arriving_remaining != 5
            || execution.result.slots.iter().any(|s| s.matched)
        {
            return Err("expiry fixture did not execute the actual no-fill MPC path".into());
        }
        // Real wall clock and real VM deadline; no shortened/fake expiry check.
        while now()? <= receipt.manifest.retention_deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    let command: LifecycleCommand = if expired {
        LifecycleCommand::expire(&receipt.manifest, now()?, now()? + 300)?
    } else {
        read("/handoff/maker-cancel.json")?
    };
    if !expired {
        let mut wrong = command.clone();
        wrong.signature[0] ^= 1;
        for node in &cluster.nodes {
            let rpc = NodeRpcClient::new(node.endpoint(), tls.clone(), Duration::from_secs(30))?;
            let before = rpc.status()?;
            if rpc.stage_lifecycle(wrong.clone()).is_ok() || rpc.status()? != before {
                return Err("invalid owner cancellation changed a node".into());
            }
        }
    }
    let (certificate, keys) = order_lifecycle(
        &cluster,
        tls.clone(),
        settlement_tls.clone(),
        &receipt.manifest,
        &command,
        &previous,
    )?;
    let envelope: SealedReservationAuthority = read(if expired {
        "/handoff/expiry-maker-authority.json"
    } else {
        "/handoff/maker2-capability.json"
    })?;
    let authority = keys.open_reservation(
        &envelope,
        &receipt.manifest,
        scope.venue_id,
        scope.defmi_id,
        &issuer,
        receipt.manifest.retention_deadline,
    )?;
    let authority = NativeReservationAuthority::from(&authority);
    let head = client.application_reservation_snapshot(authority.permit.reservation_id)?;
    let mut request = NativeReleaseRequest {
        command: command.digest()?,
        release: ApplicationNoteRelease {
            pq_committee: if expired {
                None
            } else {
                Some(serde_json::from_slice(&fs::read(
                    "/handoff/native-committee.pq.json",
                )?)?)
            },
            pq_authorization: None,
            scope,
            before_root: client.state_root()?,
            operation_id: command.digest()?,
            hold_id: head.binding.hold_id,
            sequence: head.sequence,
            previous_receipt: head.head_receipt,
            reason: command.reason,
            committee_public: if expired {
                Vec::new()
            } else {
                fs::read("/handoff/native-committee.bin")?
            },
            signature: Vec::new(),
        },
        authority,
    };
    if head.sequence != if expired { 0 } else { 2 } {
        return Err("lifecycle did not select the current carried reserve head".into());
    }
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
    if !expired {
        let mut stale = request.clone();
        stale.release.sequence = 0;
        if certify_native_release(&mut parties, &stale).is_ok() {
            return Err("committee signed stale cancellation head".into());
        }
        request.release = certify_native_release(&mut parties, &request)?;
    }
    let accepted = bridge.release_application(&request.release)?;
    let after = client.application_reservation_snapshot(head.binding.hold_id)?;
    if after.status != "released"
        || after.sequence != head.sequence + 1
        || after.remaining_commitment != head.remaining_commitment
    {
        return Err("release did not preserve and terminate the exact remainder".into());
    }
    let retry = bridge.release_application(&request.release)?;
    if retry != accepted || client.state_root()? != accepted.after_root {
        return Err("release retry changed state".into());
    }
    let confirmation = NativeReleaseConfirmation {
        authorization: request,
        transaction_id: accepted.tx_id.clone(),
    };
    for (node, party) in cluster.nodes.iter().zip(&mut parties) {
        let rpc = NodeRpcClient::new(node.endpoint(), tls.clone(), Duration::from_secs(30))?;
        let before = rpc.status()?;
        let mut altered = confirmation.clone();
        altered.authorization.release.before_root[0] ^= 1;
        if party
            .call(
                "confirm_oclob_native_release",
                serde_json::to_value(&altered)?,
            )
            .is_ok()
            || rpc.status()? != before
        {
            return Err("node accepted an altered canonical release".into());
        }
        let first = party.call(
            "confirm_oclob_native_release",
            serde_json::to_value(&confirmation)?,
        )?;
        let record: LifecycleFinality = serde_json::from_value(first.clone())?;
        if record.statement != accepted.statement || record.target != receipt.commitment() {
            return Err("node observed another release".into());
        }
        let status = rpc.status()?;
        let repeated = party.call(
            "confirm_oclob_native_release",
            serde_json::to_value(&confirmation)?,
        )?;
        if first != repeated
            || rpc.status()? != status
            || status.record_count + 1 != before.record_count
        {
            return Err("node did not durably and idempotently terminate its order".into());
        }
    }
    publish_result(
        &serde_json::to_value(certificate)?,
        &format!("/handoff/native-{phase}-certificate.json"),
    )?;
    publish_result(
        &json!({"contract_sha256": contract_hash, "kind": phase, "canonical_transaction": accepted.tx_id,
        "statement": hex::encode(accepted.statement), "node_observations": 7, "head_sequence_before": head.sequence,
        "head_sequence_after": after.sequence, "exact_retry_unchanged": true, "canonical_root": hex::encode(accepted.after_root)}),
        &format!("/handoff/native-{phase}-result.json"),
    )?;
    Ok(())
}

fn verify_terminal_restart(
    checkpoint: &[oclob_node::NodeStoreStatus],
    reopened: &[oclob_node::NodeStoreStatus],
) -> Result<(), &'static str> {
    if checkpoint.len() != 7 || checkpoint != reopened {
        return Err("native terminal state changed after node restart");
    }
    // Three encrypted input records survive the two explicit releases. The
    // fully filled first maker also retains its finalized encrypted head:
    // finalize_private_state retains every resting slot, including zero
    // remainder. This is not a live quote or a resurrected cancelled order.
    // Exact equality above includes the digest of the entire durable state.
    if reopened
        .iter()
        .any(|state| state.record_count != 3 || state.private_head_count != 1)
    {
        return Err("native terminal checkpoint has an unexpected retained-record count");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verify_terminal_restart;
    use oclob_node::NodeStoreStatus;

    #[test]
    fn restart_gate_preserves_closed_resting_head_but_rejects_changed_state() {
        let checkpoint: Vec<_> = (0..7)
            .map(|party| NodeStoreStatus {
                party,
                generation: 33,
                record_count: 3,
                completed_round_count: 5,
                private_head_count: 1,
                finalized_private_round_count: 2,
                ordering_sequence: 7,
                ordering_head: [1; 32],
                state_digest: [party as u8 + 1; 32],
            })
            .collect();
        assert!(verify_terminal_restart(&checkpoint, &checkpoint).is_ok());
        let mut changed = checkpoint.clone();
        changed[0].state_digest[0] ^= 1;
        assert!(verify_terminal_restart(&checkpoint, &changed).is_err());
        let mut resurrected = checkpoint.clone();
        resurrected[0].record_count += 1;
        assert!(verify_terminal_restart(&checkpoint, &resurrected).is_err());
        let mut unexpectedly_empty = checkpoint.clone();
        unexpectedly_empty[0].private_head_count = 0;
        assert!(verify_terminal_restart(&unexpectedly_empty, &unexpectedly_empty).is_err());
        assert!(verify_terminal_restart(&checkpoint[..6], &checkpoint[..6]).is_err());
    }
}
