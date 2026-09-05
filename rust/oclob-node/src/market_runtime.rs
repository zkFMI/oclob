//! Scenario-independent native market pipeline. Inputs are certified encrypted
//! orders; all matching and cryptographic work uses the existing node/DeFMI APIs.
use crate::edge_client::{
    collect_order_certificate, collect_threshold_capability_release, execute_agreed_round,
    finalize_agreed_private_state, AgreedRoundExecution,
};
use crate::executor::RoundPlan;
use crate::market_journal::{MarketBookEntry, MarketCompletedRound, MarketJournal};
use crate::market_network::MarketServiceConfig;
use crate::native_finality::{aggregate_finality, NativeFinalityRecord, NativeFinalityRequest};
use crate::network::{
    client_tls_context, load_secret_32, ClientIdentityConfig, ClusterPublicConfig,
};
use crate::PrivateStateFinality;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use ed25519_dalek::{SigningKey, VerifyingKey};
use oclob_ordering::OrderCertificate;
use oclob_settlement::collaborative::{
    collaborative_job_id, load_fill, prove_fill, CollaborativeFillRequest,
};
use oclob_settlement::native::{
    certify_native_fill, native_batch_binding, prepare_native_fill, project_pending_native_head,
    NativeFillAuthorizationRequest, NativeReservationAuthority,
};
use oclob_settlement::pretrade::PrivateAdmissionClient;
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::application_settlement::ApplicationNoteFillBatch;
use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge};
use qomm_defmi::facility::QuorumAuthorizer;
use qomm_proofs::price_limit::PriceLimitDirection;
use qomm_transport::node_service::client_ssl_context;
use qomm_transport::proof_client::ProofPartyTlsClient;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Deserialize, Serialize)]
struct Settled {
    transaction_id: String,
    block_id: String,
    before_root: [u8; 32],
    after_root: [u8; 32],
    height: u64,
    statement: [u8; 32],
}
pub struct NativeMarketRuntime {
    pub cluster: ClusterPublicConfig,
    pub coordinator: ClientIdentityConfig,
    pub settlement: ClientIdentityConfig,
    pub config: MarketServiceConfig,
    pub journal: Arc<MarketJournal>,
    pub committee: Vec<u8>,
    pub issuer: [u8; 32],
}
impl NativeMarketRuntime {
    pub fn pump(&self) -> Result<bool, String> {
        let Some(input) = self.journal.next()? else {
            return Ok(false);
        };
        let id = input.receipt.commitment().hex();
        let completed = self.journal.completed()?;
        let previous = completed.last();
        let book = previous.map(|v| v.book.clone()).unwrap_or_default();
        if book.len() > oclob_core::MAX_MATCH_SLOTS {
            return Err(
                "native market book capacity needs explicit expansion or lifecycle processing"
                    .into(),
            );
        }
        let tls = client_tls_context(
            &self.coordinator.tls_certificate,
            &self.coordinator.tls_private_key,
            &self.coordinator.tls_ca,
        )
        .map_err(err)?;
        let certificate: OrderCertificate = match self.journal.get(&format!("certificate:{id}"))? {
            Some(saved) => saved,
            None => {
                input.verify(&self.cluster, now()?)?;
                let cert = collect_order_certificate(
                    &self.cluster,
                    &tls,
                    previous.map(|v| &v.certificate),
                    input.receipt.commitment(),
                    input.receipt.manifest.retention_deadline,
                    Duration::from_secs(30),
                )
                .map_err(err)?;
                self.journal
                    .put(&format!("certificate:{id}"), &cert, now()?, u64::MAX)?
            }
        };
        let plan: RoundPlan = match self.journal.get(&format!("plan:{id}"))? {
            Some(saved) => saved,
            None => {
                let key = SigningKey::from_bytes(
                    &load_secret_32(&self.coordinator.application_signing_key).map_err(err)?,
                );
                let at = now()?;
                let expiry = book.iter().try_fold(
                    input.receipt.manifest.retention_deadline.min(at + 300),
                    |deadline, entry| {
                        Ok::<_, String>(
                            deadline.min(
                                self.journal
                                    .ingress(entry.commitment)?
                                    .receipt
                                    .manifest
                                    .retention_deadline,
                            ),
                        )
                    },
                )?;
                let plan = RoundPlan::sign(
                    certificate.clone(),
                    book.iter().map(|e| e.commitment).collect(),
                    at,
                    expiry,
                    &key,
                )
                .map_err(err)?;
                self.journal
                    .put(&format!("plan:{id}"), &plan, at, u64::MAX)?
            }
        };
        let execution: AgreedRoundExecution = match self.journal.get(&format!("execution:{id}"))? {
            Some(saved) => saved,
            None => {
                let result =
                    execute_agreed_round(&self.cluster, &tls, &plan, Duration::from_secs(300))
                        .map_err(err)?;
                self.journal
                    .put(&format!("execution:{id}"), &result, now()?, u64::MAX)?
            }
        };
        let slots = execution
            .result
            .slots
            .iter()
            .enumerate()
            .filter_map(|(slot, fill)| fill.matched.then_some(slot))
            .collect::<Vec<_>>();
        let settled = if slots.is_empty() {
            None
        } else {
            Some(self.settle(&id, &plan, &execution, &slots)?)
        };
        let mut next = Vec::new();
        for (slot, entry) in book.iter().enumerate() {
            let spent = execution
                .result
                .slots
                .get(slot)
                .ok_or("market result omitted a resting slot")?
                .trade_quantity;
            let remaining = entry
                .remaining
                .checked_sub(spent)
                .ok_or("market result exceeds resting quantity")?;
            if remaining > 0 {
                next.push(MarketBookEntry {
                    commitment: entry.commitment,
                    remaining,
                });
            }
        }
        if execution.result.arriving_remaining > 0 {
            next.push(MarketBookEntry {
                commitment: input.receipt.commitment(),
                remaining: execution.result.arriving_remaining,
            });
        }
        let finality_receipts = if settled.is_some() {
            self.journal
                .get(&format!("depth-finality:{id}"))?
                .ok_or("depth finality not durable")?
        } else {
            Vec::new()
        };
        let public_snapshot = Some(crate::public_depth::FinalizedPublicBook::from_execution(
            &self.cluster,
            &plan,
            &execution,
            finality_receipts,
        )?);
        let done = MarketCompletedRound {
            certificate,
            result: execution.result,
            book: next,
            transaction_id: settled.as_ref().map(|s| s.transaction_id.clone()),
            canonical_root: settled.as_ref().map(|s| s.after_root),
            finality_observations: slots.len() * 7,
            public_snapshot,
        };
        self.journal
            .put::<MarketCompletedRound>(&format!("done:{id}"), &done, now()?, u64::MAX)?;
        Ok(true)
    }

    fn settle(
        &self,
        id: &str,
        plan: &RoundPlan,
        execution: &AgreedRoundExecution,
        slots: &[usize],
    ) -> Result<Settled, String> {
        let settlement_tls = client_tls_context(
            &self.settlement.tls_certificate,
            &self.settlement.tls_private_key,
            &self.settlement.tls_ca,
        )
        .map_err(err)?;
        let proof_tls = client_ssl_context(
            &self.coordinator.tls_certificate,
            &self.coordinator.tls_private_key,
            &self.coordinator.tls_ca,
        )?;
        let private = PrivateAdmissionClient::new(
            "oclob-defmi",
            9443,
            "oclob-defmi",
            proof_tls.clone(),
            Duration::from_secs(120),
        )?;
        let scope: ApplicationReserveScope =
            serde_json::from_value(private.call("scope", json!({}))?).map_err(err)?;
        let public =
            qomm_zkpi::frost::keys::PublicKeyPackage::deserialize(&self.committee).map_err(err)?;
        if scope.committee_key_digest
            != <[u8; 32]>::from(Sha256::digest(public.serialize().map_err(err)?))
        {
            return Err("market native scope differs from pinned committee".into());
        }
        let issuer = VerifyingKey::from_bytes(&self.issuer).map_err(err)?;
        let client = private.chain()?;
        let readonly = QuorumAuthorizer::new(
            BTreeMap::from([("read-only".into(), issuer)]),
            1,
            1,
            "read-only",
        )?;
        let bridge = AvalancheNoteBridge::new(&readonly, &client);
        let mut parties = self
            .cluster
            .nodes
            .iter()
            .map(|n| {
                ProofPartyTlsClient::new(
                    &n.host,
                    n.proof_port,
                    proof_tls.clone(),
                    &n.server_name,
                    Duration::from_secs(120),
                )
            })
            .collect::<Vec<_>>();
        let output = execution
            .receipts
            .first()
            .ok_or("market execution has no node receipts")?
            .public_output_sha256;
        let requests: Vec<NativeFillAuthorizationRequest> =
            match self.journal.get(&format!("signed:{id}"))? {
                Some(saved) => saved,
                None => {
                    let open = |commitment| -> Result<NativeReservationAuthority, String> {
                        let input = self.journal.ingress(commitment)?;
                        let release = collect_threshold_capability_release(
                            &self.cluster,
                            &settlement_tls,
                            plan,
                            execution,
                            &input.receipt.manifest,
                            commitment,
                            Duration::from_secs(30),
                        )
                        .map_err(err)?;
                        let opened = release
                            .open_reservation(
                                &input.authority,
                                &input.receipt.manifest,
                                scope.venue_id,
                                scope.defmi_id,
                                &issuer,
                                now()?,
                            )
                            .map_err(err)?;
                        Ok(NativeReservationAuthority::from(&opened))
                    };
                    let taker = open(plan.arriving)?;
                    let arriving = self.journal.ingress(plan.arriving)?;
                    let direction = if taker.permit.asset_id == self.config.quote_asset {
                        PriceLimitDirection::MaximumBuyPrice
                    } else if taker.permit.asset_id == self.config.base_asset {
                        PriceLimitDirection::MinimumSellPrice
                    } else {
                        return Err("arrival reservation is outside this market pair".into());
                    };
                    let mut taker_head =
                        client.application_reservation_snapshot(taker.permit.reservation_id)?;
                    let mut requests = Vec::new();
                    for (position, slot) in slots.iter().enumerate() {
                        let maker_commitment = *plan
                            .resting
                            .get(*slot)
                            .ok_or("matched slot has no original order")?;
                        let maker = open(maker_commitment)?;
                        let maker_input = self.journal.ingress(maker_commitment)?;
                        let maker_head =
                            client.application_reservation_snapshot(maker.permit.reservation_id)?;
                        let job = collaborative_job_id(plan.round_id, *slot, output)?;
                        load_fill(&mut parties, plan.round_id, *slot, job, output)?;
                        let proof = prove_fill(
                            &mut parties,
                            public.clone(),
                            CollaborativeFillRequest {
                                job_id: job,
                                market_proof_digest: output,
                                limit_direction: direction,
                                limit_commitment: point(
                                    arriving.receipt.manifest.field_commitments[1][0],
                                )?,
                                limit_context: Sha256::new()
                                    .chain_update(b"OCLOB:SIGNED-TAKER-LIMIT:v1")
                                    .chain_update(plan.arriving.0)
                                    .chain_update(plan.ordering_certificate.digest())
                                    .chain_update(output)
                                    .finalize()
                                    .into(),
                                taker_handle: point(taker.permit.participant_handle)?,
                                asset_id: self.config.base_asset,
                                deadline: maker_input
                                    .receipt
                                    .manifest
                                    .retention_deadline
                                    .min(arriving.receipt.manifest.retention_deadline),
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
                                json!({"job_id":hex::encode(job)}),
                            )?;
                        }
                        let mut fill = prepare_native_fill(
                            &proof,
                            scope.clone(),
                            &maker,
                            &taker,
                            &maker_head,
                            &taker_head,
                            position + 1 == slots.len() && execution.result.arriving_remaining == 0,
                        )?;
                        fill.batch = native_batch_binding(
                            &scope,
                            fill.before_root,
                            plan.round_id,
                            output,
                            slots,
                            *slot,
                        )?;
                        let mut request = NativeFillAuthorizationRequest {
                            round_id: plan.round_id,
                            slot: *slot,
                            fill,
                            maker,
                            taker: taker.clone(),
                        };
                        request.fill = certify_native_fill(&mut parties, &request)?;
                        if position + 1 < slots.len() {
                            taker_head =
                                project_pending_native_head(&taker_head, &request.fill, now()?)?;
                        }
                        requests.push(request);
                    }
                    self.journal
                        .put(&format!("signed:{id}"), &requests, now()?, u64::MAX)?
                }
            };
        if requests.len() != slots.len()
            || requests.iter().zip(slots).any(|(r, s)| {
                r.slot != *s || r.round_id != plan.round_id || r.fill.mpc_result_digest != output
            })
        {
            return Err("durable native fill set differs from actual matching".into());
        }
        let batch = (requests.len() > 1).then(|| ApplicationNoteFillBatch {
            version: 1,
            fills: requests.iter().map(|r| r.fill.clone()).collect(),
        });
        let statement = match &batch {
            Some(b) => b.statement()?,
            None => requests[0].fill.signing_message()?,
        };
        let settled: Settled = match self.journal.get(&format!("settled:{id}"))? {
            Some(saved) => saved,
            None => {
                let accepted = match &batch {
                    Some(b) => bridge.settle_application_batch(b)?,
                    None => bridge.settle_application(&requests[0].fill)?,
                };
                let settled = Settled {
                    transaction_id: accepted.tx_id,
                    block_id: accepted.block_id,
                    before_root: accepted.before_root,
                    after_root: accepted.after_root,
                    height: accepted.height,
                    statement: accepted.statement,
                };
                if std::env::var("OCLOB_MARKET_CRASH_AFTER_CANONICAL")
                    .ok()
                    .as_deref()
                    == Some("1")
                {
                    // Test observation only; recovery MUST resubmit the saved
                    // signed request, never use this record to advance state.
                    self.journal.put::<Settled>(
                        &format!("fault-observation:{id}"),
                        &settled,
                        now()?,
                        u64::MAX,
                    )?;
                    eprintln!("market recovery test stopped after canonical settlement; exact signed request retained");
                    std::process::exit(75);
                }
                self.journal
                    .put(&format!("settled:{id}"), &settled, now()?, u64::MAX)?
            }
        };
        let finality = PrivateStateFinality {
            round_id: plan.round_id,
            public_output_sha256: output,
            transition_digest: statement,
            canonical_receipt_digest: settled.statement,
            canonical_height: settled.height,
        };
        for request in &requests {
            let confirm = NativeFinalityRequest {
                authorization: request.clone(),
                transaction_id: settled.transaction_id.clone(),
                batch: batch.clone(),
            };
            for party in &mut parties {
                let record: NativeFinalityRecord = serde_json::from_value(party.call(
                    "confirm_oclob_native_finality",
                    serde_json::to_value(&confirm).map_err(err)?,
                )?)
                .map_err(err)?;
                if record.transaction_id != settled.transaction_id
                    || record.before_root != settled.before_root
                    || record.after_root != settled.after_root
                    || record.block_id != settled.block_id
                    || aggregate_finality(&BTreeMap::from([(record.slot, record.clone())]))?
                        != finality
                {
                    return Err(
                        "market node canonical observation differs from committed transaction"
                            .into(),
                    );
                }
            }
        }
        let receipts = finalize_agreed_private_state(
            &self.cluster,
            &settlement_tls,
            plan,
            execution,
            finality,
            Duration::from_secs(30),
        )
        .map_err(err)?;
        self.journal
            .put::<Vec<crate::network::NodePrivateStateReceipt>>(
                &format!("depth-finality:{id}"),
                &receipts,
                now()?,
                u64::MAX,
            )?;
        Ok(settled)
    }
}
pub fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(err)
}
fn point(bytes: [u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(bytes)
        .decompress()
        .ok_or("invalid public commitment".into())
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
