//! Application-note settlement, with no reconstructed order or account ledger.
//! The node listener supplies locally authenticated execution bindings; a
//! coordinator cannot provide those bindings through the signing request.

use crate::collaborative::{collaborative_job_id, CollaborativeFillProof, SIGNING_QUORUM};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::VerifyingKey;
use oclob_edge::{EdgeOrderManifest, VerifiedReservationAuthority};
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::application_settlement::{
    application_fill_group, point, ApplicationFillBatchBinding, ApplicationNoteFill,
    ApplicationOpening, ApplicationSpendHead,
};
use qomm_defmi::avalanche::CanonicalApplicationReservation;
use qomm_transport::frost_coordinator::distributed_hybrid_sign;
use qomm_transport::proof_client::ProofPartyRpc;
use qomm_transport::proof_codec::encode_dvp_proofs;
use qomm_transport::proof_party::{
    ApplicationStatementAuthorization, ApplicationStatementVerifier, CompletedApplicationProof,
};
use qomm_zk::pedersen::Pedersen;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use zkpi_defmi_sdk::admission::ReservationAdmission;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::reservation::{ReservationPermit, ReservationRole};

/// Only authenticated commitment terms, copied by the local executor from
/// the same admitted manifest that supplied the MPC input. No ledger lookup
/// identifiers, raw order, private scalar or original note opening is here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedReservationBinding {
    pub order_commitment: [u8; 32],
    pub source_order_commitment: [u8; 32],
    pub admission_digest: [u8; 32],
    pub participant_handle: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub side_commitment: [u8; 32],
    pub valid_until: u64,
}

impl ExecutedReservationBinding {
    pub fn from_manifest(manifest: &EdgeOrderManifest) -> Option<Self> {
        manifest.uses_pretrade_reservation().then(|| Self {
            order_commitment: manifest.commitment.0,
            source_order_commitment: manifest.source_order_commitment,
            admission_digest: manifest.reservation_admission_digest,
            participant_handle: manifest.settlement_field_commitments[0][0],
            amount_commitment: manifest.settlement_field_commitments[1][0],
            side_commitment: manifest.field_commitments[0][0],
            valid_until: manifest.retention_deadline,
        })
    }
}

/// Stored and signed ONLY by the node after its matching execution succeeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFillExecution {
    pub maker: ExecutedReservationBinding,
    pub taker: ExecutedReservationBinding,
    /// Closure is allowed only for the last fill of a fully consumed arriving
    /// order. Resting remainders stay locked; expiry/cancel releases them.
    pub taker_may_close: bool,
}

impl NativeFillExecution {
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new().chain_update(b"OCLOB:NATIVE-EXECUTED-RESERVES:v1");
        for binding in [&self.maker, &self.taker] {
            for value in [
                binding.order_commitment,
                binding.source_order_commitment,
                binding.admission_digest,
                binding.participant_handle,
                binding.amount_commitment,
                binding.side_commitment,
            ] {
                hash.update(value);
            }
            hash.update(binding.valid_until.to_be_bytes());
        }
        hash.update([u8::from(self.taker_may_close)]);
        hash.finalize().into()
    }
}

/// The encrypted authority is opened only for this already-matched pair.
/// This wire deliberately cannot contain an order or any amount opening.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReservationAuthority {
    pub admission: ReservationAdmission,
    pub permit: ReservationPermit,
    pub reserve_reblinding: [u8; 32],
}

impl From<&VerifiedReservationAuthority> for NativeReservationAuthority {
    fn from(value: &VerifiedReservationAuthority) -> Self {
        Self {
            admission: value.admission.clone(),
            permit: value.permit.clone(),
            reserve_reblinding: value.reserve_reblinding.to_bytes(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFillAuthorizationRequest {
    pub round_id: [u8; 32],
    pub slot: usize,
    pub fill: ApplicationNoteFill,
    pub maker: NativeReservationAuthority,
    pub taker: NativeReservationAuthority,
}

#[derive(Clone)]
pub struct NativeReservationTrust {
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub issuer: VerifyingKey,
}

/// Installed in the OCLOB listener, not selected by a caller. It ties the
/// generic proof node's completed evidence to OCLOB's own signed MPC sidecar.
pub struct NativeFillVerifier<'a> {
    pub request: &'a NativeFillAuthorizationRequest,
    pub execution: &'a NativeFillExecution,
    pub trust: &'a NativeReservationTrust,
    /// Full ordered matched-slot set, read from this node's completed round.
    /// Never accept this value from a coordinator request.
    pub matched_slots: &'a [usize],
    pub now: u64,
}

impl ApplicationStatementVerifier for NativeFillVerifier<'_> {
    fn verify(
        &self,
        evidence: CompletedApplicationProof<'_>,
    ) -> Result<ApplicationStatementAuthorization, String> {
        let request = self.request;
        let fill = &request.fill;
        self.verify_group()?;
        let app = oclob_manifest_v1()
            .digest()
            .map_err(|error| error.to_string())?;
        let public = evidence
            .committee_public
            .serialize()
            .map_err(|error| error.to_string())?;
        if evidence.job_id
            != collaborative_job_id(request.round_id, request.slot, evidence.quote_digest)?
            || fill.operation_id != native_fill_operation(evidence.job_id)
            || fill.mpc_result_digest != evidence.quote_digest
            || fill.scope.application_binding != app
            || fill.scope.venue_id != self.trust.venue_id
            || fill.scope.defmi_id != self.trust.defmi_id
            || fill.scope.amount_bits != 32
            || fill.committee_public != public
            || self.execution.maker.order_commitment == self.execution.taker.order_commitment
        {
            return Err(
                "native fill differs from this executed OCLOB job or pinned deployment".into(),
            );
        }
        let instruction =
            qomm_zkpi::wire::decode(&fill.instruction).map_err(|error| error.to_string())?;
        if instruction.digest() != evidence.payment_digest
            || instruction.nonce != evidence.job_id
            || self.execution.maker.participant_handle != evidence.maker_handle
            || self.execution.taker.participant_handle != evidence.taker_handle
        {
            return Err(
                "native fill replaced the node's completed payment or admitted participants".into(),
            );
        }
        let (maker_head, taker_head, maker_asset, taker_asset) = if evidence.maker_is_payer {
            (
                &fill.cash,
                &fill.securities,
                fill.cash_asset,
                fill.securities_asset,
            )
        } else {
            (
                &fill.securities,
                &fill.cash,
                fill.securities_asset,
                fill.cash_asset,
            )
        };
        if maker_head.close || (taker_head.close && !self.execution.taker_may_close) {
            return Err("native fill cannot release a resting or still-active reservation".into());
        }
        self.verify_authority(
            &request.maker,
            &self.execution.maker,
            maker_head,
            maker_asset,
            instruction.deadline,
        )?;
        self.verify_authority(
            &request.taker,
            &self.execution.taker,
            taker_head,
            taker_asset,
            instruction.deadline,
        )?;
        let key = Pedersen::new(b"qomm:defmi:v1");
        for (head, expected) in [
            (&fill.securities, evidence.securities_reserve),
            (&fill.cash, evidence.cash_reserve),
        ] {
            let delta =
                Option::<Scalar>::from(Scalar::from_canonical_bytes(head.reserve_reblinding))
                    .ok_or("native reserve reblinding is not canonical")?;
            if (point(head.remaining_commitment)? + key.h * delta)
                .compress()
                .to_bytes()
                != expected
            {
                return Err(
                    "native head differs from the reserve used by this node's MPC proof".into(),
                );
            }
        }
        // A coordinator must not replace this node's encrypted opening while
        // retaining otherwise valid range/product proofs. Other nodes check
        // their own contribution before issuing their signature share.
        for (index, leg) in [
            "securities_delivery",
            "securities_refund",
            "cash_delivery",
            "cash_refund",
        ]
        .iter()
        .enumerate()
        {
            let opening = &fill.openings[index];
            let own = evidence
                .opening_shares
                .get(*leg)
                .ok_or("local encrypted opening is absent")?;
            let party = own
                .get("party")
                .and_then(serde_json::Value::as_u64)
                .ok_or("local opening party is invalid")?;
            let own_wire = opening
                .shares
                .iter()
                .find(|share| u64::from(share.party) == party)
                .ok_or("native fill omitted this node's encrypted opening")?;
            let ids = opening
                .shares
                .iter()
                .map(|share| usize::from(share.party))
                .collect::<Vec<_>>();
            if opening.threshold != 3 || ids.as_slice() != SIGNING_QUORUM {
                return Err("native opening has another reconstruction quorum".into());
            }
            let expected = json!({
                "party": own_wire.party,
                "context": hex::encode(opening.context),
                "recipient_view": hex::encode(opening.recipient_view),
                "ephemeral": hex::encode(own_wire.ephemeral),
                "masked_value": hex::encode(own_wire.masked_value),
                "masked_blinding": hex::encode(own_wire.masked_blinding),
            });
            if own != &expected {
                return Err("native fill changed the node's encrypted opening contribution".into());
            }
        }
        fill.verify_unsigned(&fill.scope, self.now)?;
        let message = fill.signing_message()?;
        let mut immutable = fill.clone();
        immutable.before_root = [1; 32];
        Ok(ApplicationStatementAuthorization {
            message,
            action_digest: immutable.signing_message()?,
        })
    }
}

impl NativeFillVerifier<'_> {
    fn verify_group(&self) -> Result<(), String> {
        let expected = native_batch_binding(
            &self.request.fill.scope,
            self.request.fill.before_root,
            self.request.round_id,
            self.request.fill.mpc_result_digest,
            self.matched_slots,
            self.request.slot,
        )?;
        if self.request.fill.batch != expected {
            return Err("native fill omits or reorders locally executed matched slots".into());
        }
        Ok(())
    }

    /// Retrospective binding check after canonical acceptance. This does not
    /// authorize signing and therefore also works for non-signing observers.
    /// `now` is a cryptographic validity anchor, not a claimed block time;
    /// the configured canonical VM has already enforced execution-time bounds.
    pub fn verify_finalized_execution(&self) -> Result<(), String> {
        self.verify_group()?;
        let fill = &self.request.fill;
        let instruction =
            qomm_zkpi::wire::decode(&fill.instruction).map_err(|error| error.to_string())?;
        let job = collaborative_job_id(
            self.request.round_id,
            self.request.slot,
            fill.mpc_result_digest,
        )?;
        let maker = self.execution.maker.participant_handle;
        let taker = self.execution.taker.participant_handle;
        let payer = instruction.payer_handle.compress().to_bytes();
        let payee = instruction.payee_handle.compress().to_bytes();
        if fill.operation_id != native_fill_operation(job)
            || instruction.nonce != job
            || fill.scope.application_binding
                != oclob_manifest_v1().digest().map_err(|e| e.to_string())?
            || fill.scope.venue_id != self.trust.venue_id
            || fill.scope.defmi_id != self.trust.defmi_id
            || fill.scope.amount_bits != 32
            || self.execution.maker.order_commitment == self.execution.taker.order_commitment
            || !((payer == maker && payee == taker) || (payer == taker && payee == maker))
        {
            return Err("finalized fill differs from the locally executed pair or job".into());
        }
        let (maker_head, taker_head, maker_asset, taker_asset) = if payer == maker {
            (
                &fill.cash,
                &fill.securities,
                fill.cash_asset,
                fill.securities_asset,
            )
        } else {
            (
                &fill.securities,
                &fill.cash,
                fill.securities_asset,
                fill.cash_asset,
            )
        };
        if maker_head.close || (taker_head.close && !self.execution.taker_may_close) {
            return Err("finalized fill closes an active order reservation".into());
        }
        self.verify_authority(
            &self.request.maker,
            &self.execution.maker,
            maker_head,
            maker_asset,
            instruction.deadline,
        )?;
        self.verify_authority(
            &self.request.taker,
            &self.execution.taker,
            taker_head,
            taker_asset,
            instruction.deadline,
        )
    }

    fn verify_authority(
        &self,
        authority: &NativeReservationAuthority,
        executed: &ExecutedReservationBinding,
        head: &ApplicationSpendHead,
        asset: [u8; 32],
        deadline: u64,
    ) -> Result<(), String> {
        let app = self.request.fill.scope.application_binding;
        authority
            .admission
            .verify(app, self.trust.defmi_id, &self.trust.issuer, self.now)
            .map_err(|error| error.to_string())?;
        authority
            .permit
            .verify(app, self.trust.defmi_id, &self.trust.issuer, self.now)
            .map_err(|error| error.to_string())?;
        let delta =
            Option::<Scalar>::from(Scalar::from_canonical_bytes(authority.reserve_reblinding))
                .ok_or("authority reblinding is not canonical")?;
        authority
            .admission
            .verify_authority(&authority.permit, &delta)
            .map_err(|error| error.to_string())?;
        if authority.permit.role != ReservationRole::Application
            || authority.permit.venue_id != self.trust.venue_id
            || authority
                .admission
                .digest()
                .map_err(|error| error.to_string())?
                != executed.admission_digest
            || authority.admission.order_commitment != executed.source_order_commitment
            || authority.admission.participant_handle != executed.participant_handle
            || authority.admission.amount_commitment != executed.amount_commitment
            || authority.admission.side_commitment != executed.side_commitment
            || authority.admission.valid_until < executed.valid_until
            || authority.admission.valid_until < deadline
            || head.hold_id != authority.permit.reservation_id
            || head.reserve_reblinding != authority.reserve_reblinding
            || asset != authority.permit.asset_id
            || (head.sequence == 0
                && (head.previous_receipt != authority.permit.reserve_receipt_digest
                    || head.remaining_commitment != authority.permit.amount_commitment))
        {
            return Err(
                "native authority does not belong to the exact admitted order and reserve".into(),
            );
        }
        Ok(())
    }
}

pub fn native_fill_operation(job: [u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"OCLOB:NATIVE-NOTE-FILL:v1")
        .chain_update(job)
        .finalize()
        .into()
}

/// The listener supplies the full locally executed set. The coordinator uses
/// the same public calculation but cannot choose a subset for a signer.
pub fn native_batch_binding(
    scope: &ApplicationReserveScope,
    parent: [u8; 32],
    round: [u8; 32],
    output: [u8; 32],
    slots: &[usize],
    slot: usize,
) -> Result<Option<ApplicationFillBatchBinding>, String> {
    if slots.is_empty() || slots.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("native matched slots are empty, repeated or unordered".into());
    }
    let index = slots
        .iter()
        .position(|s| *s == slot)
        .ok_or("slot was not matched")?;
    let operations = slots
        .iter()
        .map(|s| collaborative_job_id(round, *s, output).map(native_fill_operation))
        .collect::<Result<Vec<_>, _>>()?;
    if slots.len() == 1 {
        return Ok(None);
    }
    Ok(Some(ApplicationFillBatchBinding {
        group: application_fill_group(scope, parent, &operations)?,
        index: index as u16,
        count: slots.len() as u16,
    }))
}

/// Off-chain projection for preparing the next member of an atomic group.
/// This is NOT a canonical readback or finality receipt. The common parent is
/// retained; the VM independently verifies all cumulative changes at commit.
pub fn project_pending_native_head(
    head: &CanonicalApplicationReservation,
    fill: &ApplicationNoteFill,
    now: u64,
) -> Result<CanonicalApplicationReservation, String> {
    if fill.batch.is_none() || head.state_root != fill.before_root || head.status != "active" {
        return Err("pending head requires an active hold at the signed batch parent".into());
    }
    let index = [&fill.securities, &fill.cash]
        .iter()
        .position(|spend| spend.hold_id == head.binding.hold_id)
        .ok_or("batch member does not use this reservation")?;
    let spend = [&fill.securities, &fill.cash][index];
    if head.sequence != spend.sequence
        || head.head_receipt != spend.previous_receipt
        || head.remaining_commitment != spend.remaining_commitment
    {
        return Err("pending batch member does not extend the current hold".into());
    }
    let verified = fill.verify(&head.binding.scope, now)?;
    let mut next = head.clone();
    next.sequence = next
        .sequence
        .checked_add(1)
        .ok_or("pending sequence overflow")?;
    next.remaining_commitment = verified.remaining[index];
    next.head_receipt = verified.statement;
    next.remaining_opening = (!spend.close).then(|| verified.normalized_openings[index].clone());
    if spend.close {
        next.status = "consumed".into();
        next.settlement_digest = verified.statement;
    }
    Ok(next)
}

/// Construct a candidate from a proved fill and already-read canonical heads.
/// Nodes still perform their independent local verification before signing.
pub fn prepare_native_fill(
    proof: &CollaborativeFillProof,
    scope: ApplicationReserveScope,
    maker: &NativeReservationAuthority,
    taker: &NativeReservationAuthority,
    maker_head: &CanonicalApplicationReservation,
    taker_head: &CanonicalApplicationReservation,
    close_taker: bool,
) -> Result<ApplicationNoteFill, String> {
    if maker_head.state_root == [0; 32] || maker_head.state_root != taker_head.state_root {
        return Err("native reserve reads do not share one canonical root".into());
    }
    let spend = |authority: &NativeReservationAuthority,
                 canonical: &CanonicalApplicationReservation,
                 close| {
        if canonical.status != "active"
            || canonical.binding.scope != scope
            || canonical.binding.hold_id != authority.permit.reservation_id
            || canonical.binding.mandate_digest != authority.permit.authority_digest
            || canonical.escrow_note_id != authority.permit.escrow_note_id
        {
            return Err("native canonical head differs from its pretrade authority".to_string());
        }
        Ok(ApplicationSpendHead {
            hold_id: canonical.binding.hold_id,
            sequence: canonical.sequence,
            previous_receipt: canonical.head_receipt,
            remaining_commitment: canonical.remaining_commitment,
            reserve_reblinding: authority.reserve_reblinding,
            close,
        })
    };
    let maker_spend = spend(maker, maker_head, false)?;
    let taker_spend = spend(taker, taker_head, close_taker)?;
    let maker_is_payer =
        proof.instruction.payer_handle.compress().to_bytes() == maker.permit.participant_handle;
    let (securities, cash, securities_asset, cash_asset) = if maker_is_payer {
        (
            taker_spend,
            maker_spend,
            taker.permit.asset_id,
            maker.permit.asset_id,
        )
    } else {
        (
            maker_spend,
            taker_spend,
            maker.permit.asset_id,
            taker.permit.asset_id,
        )
    };
    if proof.asset_id != securities_asset {
        return Err("native asset rail differs from the proved asset".into());
    }
    Ok(ApplicationNoteFill {
        version: 2,
        pq_committee: proof.pq_committee.clone(),
        pq_authorization: None,
        scope,
        before_root: maker_head.state_root,
        operation_id: native_fill_operation(proof.job_id),
        mpc_result_digest: proof.market_proof_digest,
        securities_asset,
        cash_asset,
        securities,
        cash,
        instruction: qomm_zkpi::wire::encode(&proof.instruction),
        dvp_proofs: encode_dvp_proofs(&proof.dvp_proofs)?,
        cash_commitment: proof.cash_commitment.compress().to_bytes(),
        asset_link_announcement: proof.asset_link.announcement.compress().to_bytes(),
        asset_link_response: proof.asset_link.response.to_bytes(),
        openings: [
            ApplicationOpening::from_domain(&proof.securities_delivery_opening)?,
            ApplicationOpening::from_domain(&proof.securities_refund_opening)?,
            ApplicationOpening::from_domain(&proof.cash_delivery_opening)?,
            ApplicationOpening::from_domain(&proof.cash_refund_opening)?,
        ],
        committee_public: proof
            .frost_public
            .serialize()
            .map_err(|error| error.to_string())?,
        signature: Vec::new(),
        batch: None,
    })
}

/// Call only after `complete` has persisted the signing parties' local proof
/// evidence. No raw message-signing RPC is used, and authorization failure on
/// any selected node stops before the FROST commitment round.
pub fn certify_native_fill<T: ProofPartyRpc>(
    parties: &mut [T],
    request: &NativeFillAuthorizationRequest,
) -> Result<ApplicationNoteFill, String> {
    if parties.len() != 7 {
        return Err("native fill requires the configured seven-node committee".into());
    }
    let message = request.fill.signing_message()?;
    for party in SIGNING_QUORUM {
        let response = parties[party - 1].call(
            "authorize_oclob_native_fill",
            serde_json::to_value(request).map_err(|error| error.to_string())?,
        )?;
        if response.get("message").and_then(serde_json::Value::as_str)
            != Some(&hex::encode(message))
        {
            return Err("native node authorized a different settlement".into());
        }
    }
    let public =
        qomm_zkpi::frost::keys::PublicKeyPackage::deserialize(&request.fill.committee_public)
            .map_err(|error| error.to_string())?;
    let signed = distributed_hybrid_sign(
        parties,
        &SIGNING_QUORUM,
        &message,
        &public,
        &request.fill.pq_committee,
    )?;
    let mut fill = request.fill.clone();
    fill.signature = signed
        .classical
        .serialize()
        .map_err(|error| error.to_string())?;
    fill.pq_authorization = Some(signed.pq);
    Ok(fill)
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
