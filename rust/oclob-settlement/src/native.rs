//! Application-note settlement, with no reconstructed order or account ledger.
//! The node listener supplies locally authenticated execution bindings; a
//! coordinator cannot provide those bindings through the signing request.

use crate::collaborative::{collaborative_job_id, CollaborativeFillProof, SIGNING_QUORUM};
use curve25519_dalek::scalar::Scalar;

use oclob_core::application_crypto::{
    Signature as ApplicationSignature, Signer as _, SigningKey as ApplicationSigningKey,
    VerifyingKey as ApplicationVerifyingKey,
};
use oclob_edge::{ClaimAuthorizationEndpoint, EdgeOrderManifest, VerifiedReservationAuthority};
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::application_settlement::{
    application_fill_group, point, ApplicationFillBatchBinding, ApplicationNoteFill,
    ApplicationOpening, ApplicationSpendHead,
};
use qomm_defmi::avalanche::CanonicalApplicationReservation;
use qomm_defmi::note_chain::{
    note_claim_recipient_commitment, ClaimAuthorizationCommitment, NoteClaimKind,
};
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
    pub order_signer: [u8; 32],
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
            order_signer: manifest.signer,
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
        let mut hash = Sha256::new().chain_update(b"OCLOB:NATIVE-EXECUTED-RESERVES:v2");
        for binding in [&self.maker, &self.taker] {
            for value in [
                binding.order_commitment,
                binding.source_order_commitment,
                binding.admission_digest,
                binding.participant_handle,
                binding.amount_commitment,
                binding.side_commitment,
                binding.order_signer,
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
    pub claim_authorization_endpoint: ClaimAuthorizationEndpoint,
    pub order_signer: [u8; 32],
}

impl From<&VerifiedReservationAuthority> for NativeReservationAuthority {
    fn from(value: &VerifiedReservationAuthority) -> Self {
        Self {
            admission: value.admission.clone(),
            permit: value.permit.clone(),
            reserve_reblinding: value.reserve_reblinding.to_bytes(),
            claim_authorization_endpoint: value.claim_authorization_endpoint.clone(),
            order_signer: value.order_signer,
        }
    }
}

pub const CLAIM_AUTHORIZATION_ISSUE_VERSION: u16 = 1;

/// The four public claim positions in the canonical DvP opening array.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeClaimLeg {
    SecuritiesDelivery,
    SecuritiesRefund,
    CashDelivery,
    CashRefund,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeClaimReservation {
    pub reservation_id: [u8; 32],
    pub participant_handle: [u8; 32],
    pub asset_id: [u8; 32],
    pub sequence: u64,
}

/// Public context sent over the operation-scoped corporate mTLS endpoint.
/// It contains no order, scalar opening, signing seed, or wallet secret.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeClaimAuthorizationIssue {
    pub version: u16,
    pub instruction_nullifier: [u8; 32],
    pub payer: NativeClaimReservation,
    pub payee: NativeClaimReservation,
}

#[derive(Serialize)]
struct NativeParticipantClaimIssueView {
    version: u16,
    instruction_nullifier: [u8; 32],
    payer_reservation_id: [u8; 32],
    payer_asset_id: [u8; 32],
    payer_sequence: u64,
    payee_reservation_id: [u8; 32],
    payee_asset_id: [u8; 32],
    payee_sequence: u64,
    participant_handle: [u8; 32],
}

impl NativeClaimAuthorizationIssue {
    pub fn validate(&self) -> Result<(), String> {
        let payer = &self.payer;
        let payee = &self.payee;
        if self.version != CLAIM_AUTHORIZATION_ISSUE_VERSION
            || self.instruction_nullifier == [0; 32]
            || payer.reservation_id == [0; 32]
            || payee.reservation_id == [0; 32]
            || payer.reservation_id == payee.reservation_id
            || payer.participant_handle == [0; 32]
            || payee.participant_handle == [0; 32]
            || payer.participant_handle == payee.participant_handle
            || payer.asset_id == [0; 32]
            || payee.asset_id == [0; 32]
            || payer.asset_id == payee.asset_id
            || payer.sequence == u64::MAX
            || payee.sequence == u64::MAX
        {
            return Err("native claim authorization context is invalid".into());
        }
        Ok(())
    }

    pub fn expected_for(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<[(NativeClaimLeg, [u8; 32]); 2], String> {
        self.validate()?;
        let payer = &self.payer;
        let payee = &self.payee;
        let (handle, claims) = if reservation_id == payer.reservation_id {
            (
                payer.participant_handle,
                [
                    (
                        NativeClaimLeg::SecuritiesDelivery,
                        payee.asset_id,
                        payee.reservation_id,
                        NoteClaimKind::Delivery,
                    ),
                    (
                        NativeClaimLeg::CashRefund,
                        payer.asset_id,
                        payer.reservation_id,
                        NoteClaimKind::Refund,
                    ),
                ],
            )
        } else if reservation_id == payee.reservation_id {
            (
                payee.participant_handle,
                [
                    (
                        NativeClaimLeg::SecuritiesRefund,
                        payee.asset_id,
                        payee.reservation_id,
                        NoteClaimKind::Refund,
                    ),
                    (
                        NativeClaimLeg::CashDelivery,
                        payer.asset_id,
                        payer.reservation_id,
                        NoteClaimKind::Delivery,
                    ),
                ],
            )
        } else {
            return Err("claim authorization requested from a non-participant".into());
        };
        claims
            .map(|(leg, asset, hold, kind)| {
                Ok((
                    leg,
                    note_claim_recipient_commitment(
                        handle,
                        self.instruction_nullifier,
                        asset,
                        hold,
                        kind,
                    )?,
                ))
            })
            .into_iter()
            .collect::<Result<Vec<_>, String>>()?
            .try_into()
            .map_err(|_| "claim authorization did not produce two claim bindings".into())
    }

    pub fn sequence_for(&self, reservation_id: [u8; 32]) -> Result<u64, String> {
        if reservation_id == self.payer.reservation_id {
            Ok(self.payer.sequence)
        } else if reservation_id == self.payee.reservation_id {
            Ok(self.payee.sequence)
        } else {
            Err("claim authorization sequence belongs to another reservation".into())
        }
    }

    fn participant_view(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<NativeParticipantClaimIssueView, String> {
        self.validate()?;
        let participant_handle = if reservation_id == self.payer.reservation_id {
            self.payer.participant_handle
        } else if reservation_id == self.payee.reservation_id {
            self.payee.participant_handle
        } else {
            return Err("claim authorization participant view names another reservation".into());
        };
        Ok(NativeParticipantClaimIssueView {
            version: self.version,
            instruction_nullifier: self.instruction_nullifier,
            payer_reservation_id: self.payer.reservation_id,
            payer_asset_id: self.payer.asset_id,
            payer_sequence: self.payer.sequence,
            payee_reservation_id: self.payee.reservation_id,
            payee_asset_id: self.payee.asset_id,
            payee_sequence: self.payee.sequence,
            participant_handle,
        })
    }

    pub fn participant_view_digest(&self, reservation_id: [u8; 32]) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(b"OCLOB:NATIVE-CLAIM-AUTHORIZATION-ISSUE-VIEW:v1")
            .chain_update(
                serde_json::to_vec(&self.participant_view(reservation_id)?)
                    .map_err(|error| error.to_string())?,
            )
            .finalize()
            .into())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeClaimAuthorizationCommitment {
    pub leg: NativeClaimLeg,
    pub recipient_commitment: [u8; 32],
    pub authorization: ClaimAuthorizationCommitment,
}

/// Exact public response from one participant. The corresponding two seed
/// pairs remain only in that participant's encrypted corporate journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeParticipantClaimAuthorizations {
    pub version: u16,
    pub reservation_id: [u8; 32],
    pub sequence: u64,
    pub claims: [NativeClaimAuthorizationCommitment; 2],
    pub signature: Vec<u8>,
}

impl NativeParticipantClaimAuthorizations {
    pub fn validate_shape(&self) -> Result<(), String> {
        let legs = [self.claims[0].leg, self.claims[1].leg];
        if self.version != CLAIM_AUTHORIZATION_ISSUE_VERSION
            || self.reservation_id == [0; 32]
            || self.sequence == u64::MAX
            || self.claims[0].recipient_commitment == [0; 32]
            || self.claims[1].recipient_commitment == [0; 32]
            || self.claims[0].recipient_commitment == self.claims[1].recipient_commitment
            || !matches!(
                legs,
                [
                    NativeClaimLeg::SecuritiesDelivery,
                    NativeClaimLeg::CashRefund
                ] | [
                    NativeClaimLeg::SecuritiesRefund,
                    NativeClaimLeg::CashDelivery
                ]
            )
            || self.claims[0].authorization.key_fingerprint
                == self.claims[1].authorization.key_fingerprint
        {
            return Err("participant claim authorization shape is invalid".into());
        }
        for claim in &self.claims {
            claim.authorization.validate()?;
        }
        Ok(())
    }

    pub fn validate(&self, issue: &NativeClaimAuthorizationIssue) -> Result<(), String> {
        self.validate_shape()?;
        let expected = issue.expected_for(self.reservation_id)?;
        if self.sequence != issue.sequence_for(self.reservation_id)?
            || self.claims[0].leg != expected[0].0
            || self.claims[0].recipient_commitment != expected[0].1
            || self.claims[1].leg != expected[1].0
            || self.claims[1].recipient_commitment != expected[1].1
        {
            return Err("participant claim authorizations differ from the requested claims".into());
        }
        Ok(())
    }

    fn signing_message_for_view(&self, issue_view: [u8; 32]) -> Result<[u8; 32], String> {
        self.validate_shape()?;
        if issue_view == [0; 32] {
            return Err("claim authorization participant view is empty".into());
        }
        Ok(Sha256::new()
            .chain_update(b"OCLOB:NATIVE-CLAIM-AUTHORIZATIONS:v1")
            .chain_update(
                serde_json::to_vec(&(
                    issue_view,
                    self.version,
                    self.reservation_id,
                    self.sequence,
                    self.claims,
                ))
                .map_err(|error| error.to_string())?,
            )
            .finalize()
            .into())
    }

    pub fn signing_message(
        &self,
        issue: &NativeClaimAuthorizationIssue,
    ) -> Result<[u8; 32], String> {
        self.validate(issue)?;
        self.signing_message_for_view(issue.participant_view_digest(self.reservation_id)?)
    }

    pub fn sign(
        mut self,
        issue: &NativeClaimAuthorizationIssue,
        signer: &ApplicationSigningKey,
    ) -> Result<Self, String> {
        if !self.signature.is_empty() {
            return Err("claim authorization response is already signed".into());
        }
        self.signature = signer
            .try_sign(&self.signing_message(issue)?)
            .map_err(|error| error.to_string())?
            .to_bytes();
        Ok(self)
    }

    pub fn verify(
        &self,
        issue: &NativeClaimAuthorizationIssue,
        expected_signer: [u8; 32],
    ) -> Result<(), String> {
        self.validate(issue)?;
        self.verify_participant_view(
            issue.participant_view_digest(self.reservation_id)?,
            expected_signer,
        )
    }

    pub fn verify_participant_view(
        &self,
        issue_view: [u8; 32],
        expected_signer: [u8; 32],
    ) -> Result<(), String> {
        let signature = ApplicationSignature::try_from(self.signature.as_slice())
            .map_err(|error| error.to_string())?;
        ApplicationVerifyingKey::from_bytes(&expected_signer)
            .map_err(|error| error.to_string())?
            .verify_strict(&self.signing_message_for_view(issue_view)?, &signature)
            .map_err(|error| error.to_string())
    }

    fn authorization(&self, leg: NativeClaimLeg) -> Option<ClaimAuthorizationCommitment> {
        self.claims
            .iter()
            .find(|claim| claim.leg == leg)
            .map(|claim| claim.authorization)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFillClaimAuthorizations {
    pub payer: NativeParticipantClaimAuthorizations,
    pub payee: NativeParticipantClaimAuthorizations,
}

impl NativeFillClaimAuthorizations {
    pub fn validate(&self, issue: &NativeClaimAuthorizationIssue) -> Result<(), String> {
        if self.payer.reservation_id != issue.payer.reservation_id
            || self.payee.reservation_id != issue.payee.reservation_id
        {
            return Err(
                "claim authorization responses were substituted between participants".into(),
            );
        }
        self.payer.validate(issue)?;
        self.payee.validate(issue)?;
        let claims = self
            .payer
            .claims
            .iter()
            .chain(&self.payee.claims)
            .collect::<Vec<_>>();
        if claims.iter().enumerate().any(|(index, claim)| {
            claims[..index].iter().any(|prior| {
                prior.authorization.key_fingerprint == claim.authorization.key_fingerprint
            })
        }) {
            return Err("native fill reuses a claim authorization key".into());
        }
        Ok(())
    }

    pub fn verify(
        &self,
        issue: &NativeClaimAuthorizationIssue,
        payer_signer: [u8; 32],
        payee_signer: [u8; 32],
    ) -> Result<(), String> {
        self.validate(issue)?;
        self.payer.verify(issue, payer_signer)?;
        self.payee.verify(issue, payee_signer)
    }

    fn verify_openings(&self, openings: &[ApplicationOpening; 4]) -> Result<(), String> {
        for (opening, leg) in openings.iter().zip([
            NativeClaimLeg::SecuritiesDelivery,
            NativeClaimLeg::SecuritiesRefund,
            NativeClaimLeg::CashDelivery,
            NativeClaimLeg::CashRefund,
        ]) {
            if opening.claim_authorization != self.authorization(leg)? {
                return Err("native fill substituted a participant claim authorization".into());
            }
        }
        Ok(())
    }

    fn authorization(&self, leg: NativeClaimLeg) -> Result<ClaimAuthorizationCommitment, String> {
        self.payer
            .authorization(leg)
            .or_else(|| self.payee.authorization(leg))
            .ok_or_else(|| "native fill is missing a claim authorization".into())
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
    pub claim_authorizations: NativeFillClaimAuthorizations,
}

/// Return the participant-response count and sorted one-time claim-key
/// fingerprints present in the exact fill requests signed by the proof nodes.
/// This keeps financial approvals separate from post-match custody responses
/// and lets multi-round observers reject cross-round key reuse.
pub fn claim_authorization_evidence(
    requests: &[NativeFillAuthorizationRequest],
) -> Result<(usize, Vec<[u8; 32]>), String> {
    if requests.is_empty() {
        return Err("claim authorization evidence has no fill requests".into());
    }
    let mut responses = 0usize;
    let mut keys = std::collections::BTreeSet::new();
    for request in requests {
        for participant in [
            &request.claim_authorizations.payer,
            &request.claim_authorizations.payee,
        ] {
            participant.validate_shape()?;
            ApplicationSignature::try_from(participant.signature.as_slice())
                .map_err(|error| error.to_string())?;
            responses = responses
                .checked_add(1)
                .ok_or("claim authorization response count overflow")?;
            for claim in &participant.claims {
                if !keys.insert(claim.authorization.key_fingerprint) {
                    return Err("claim authorization key was reused across fill requests".into());
                }
            }
        }
    }
    let expected_responses = requests
        .len()
        .checked_mul(2)
        .ok_or("claim authorization response count overflow")?;
    let expected_keys = requests
        .len()
        .checked_mul(4)
        .ok_or("claim authorization key count overflow")?;
    if responses != expected_responses || keys.len() != expected_keys {
        return Err("claim authorization evidence count is incomplete".into());
    }
    Ok((responses, keys.into_iter().collect()))
}

#[derive(Clone)]
pub struct NativeReservationTrust {
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub issuer: Vec<u8>,
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
        let claim_issue = native_claim_authorization_issue_from_sequences(
            &instruction,
            &request.maker,
            &request.taker,
            maker_head.sequence,
            taker_head.sequence,
        )?;
        let (payer_signer, payee_signer) = if evidence.maker_is_payer {
            (
                self.execution.maker.order_signer,
                self.execution.taker.order_signer,
            )
        } else {
            (
                self.execution.taker.order_signer,
                self.execution.maker.order_signer,
            )
        };
        request
            .claim_authorizations
            .verify(&claim_issue, payer_signer, payee_signer)?;
        request
            .claim_authorizations
            .verify_openings(&fill.openings)?;
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
            if own_wire.blinding_adjustment != Scalar::ZERO.to_bytes() {
                return Err("native fill changed the node's opening blinding adjustment".into());
            }
            let expected = json!({
                "party": own_wire.party,
                "context": hex::encode(opening.context),
                "recipient_view": hex::encode(opening.recipient_view),
                "recipient_public": own_wire.recipient_public,
                "sealed": own_wire.sealed,
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
        let claim_issue = native_claim_authorization_issue_from_sequences(
            &instruction,
            &self.request.maker,
            &self.request.taker,
            maker_head.sequence,
            taker_head.sequence,
        )?;
        let (payer_signer, payee_signer) = if payer == maker {
            (
                self.execution.maker.order_signer,
                self.execution.taker.order_signer,
            )
        } else {
            (
                self.execution.taker.order_signer,
                self.execution.maker.order_signer,
            )
        };
        self.request
            .claim_authorizations
            .verify(&claim_issue, payer_signer, payee_signer)?;
        self.request
            .claim_authorizations
            .verify_openings(&fill.openings)?;
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
            || authority.order_signer == [0; 32]
            || authority.order_signer != executed.order_signer
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
pub fn native_claim_authorization_issue(
    proof: &CollaborativeFillProof,
    maker: &NativeReservationAuthority,
    taker: &NativeReservationAuthority,
    maker_head: &CanonicalApplicationReservation,
    taker_head: &CanonicalApplicationReservation,
) -> Result<NativeClaimAuthorizationIssue, String> {
    maker
        .claim_authorization_endpoint
        .validate()
        .map_err(|error| error.to_string())?;
    taker
        .claim_authorization_endpoint
        .validate()
        .map_err(|error| error.to_string())?;
    if maker_head.status != "active"
        || taker_head.status != "active"
        || maker_head.binding.hold_id != maker.permit.reservation_id
        || taker_head.binding.hold_id != taker.permit.reservation_id
    {
        return Err("claim authorization requires the current active reservation heads".into());
    }
    native_claim_authorization_issue_from_sequences(
        &proof.instruction,
        maker,
        taker,
        maker_head.sequence,
        taker_head.sequence,
    )
}

fn native_claim_authorization_issue_from_sequences(
    instruction: &qomm_zkpi::Instruction,
    maker: &NativeReservationAuthority,
    taker: &NativeReservationAuthority,
    maker_sequence: u64,
    taker_sequence: u64,
) -> Result<NativeClaimAuthorizationIssue, String> {
    maker
        .claim_authorization_endpoint
        .validate()
        .map_err(|error| error.to_string())?;
    taker
        .claim_authorization_endpoint
        .validate()
        .map_err(|error| error.to_string())?;
    let payer_handle = instruction.payer_handle.compress().to_bytes();
    let payee_handle = instruction.payee_handle.compress().to_bytes();
    let (payer, payee) = if maker.permit.participant_handle == payer_handle
        && taker.permit.participant_handle == payee_handle
    {
        (
            NativeClaimReservation {
                reservation_id: maker.permit.reservation_id,
                participant_handle: maker.permit.participant_handle,
                asset_id: maker.permit.asset_id,
                sequence: maker_sequence,
            },
            NativeClaimReservation {
                reservation_id: taker.permit.reservation_id,
                participant_handle: taker.permit.participant_handle,
                asset_id: taker.permit.asset_id,
                sequence: taker_sequence,
            },
        )
    } else if taker.permit.participant_handle == payer_handle
        && maker.permit.participant_handle == payee_handle
    {
        (
            NativeClaimReservation {
                reservation_id: taker.permit.reservation_id,
                participant_handle: taker.permit.participant_handle,
                asset_id: taker.permit.asset_id,
                sequence: taker_sequence,
            },
            NativeClaimReservation {
                reservation_id: maker.permit.reservation_id,
                participant_handle: maker.permit.participant_handle,
                asset_id: maker.permit.asset_id,
                sequence: maker_sequence,
            },
        )
    } else {
        return Err("proved claim recipients differ from the reservation participants".into());
    };
    let issue = NativeClaimAuthorizationIssue {
        version: CLAIM_AUTHORIZATION_ISSUE_VERSION,
        instruction_nullifier: instruction.nullifier(),
        payer,
        payee,
    };
    issue.validate()?;
    Ok(issue)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_native_fill(
    proof: &CollaborativeFillProof,
    scope: ApplicationReserveScope,
    maker: &NativeReservationAuthority,
    taker: &NativeReservationAuthority,
    maker_head: &CanonicalApplicationReservation,
    taker_head: &CanonicalApplicationReservation,
    claim_authorizations: &NativeFillClaimAuthorizations,
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
    let claim_issue =
        native_claim_authorization_issue(proof, maker, taker, maker_head, taker_head)?;
    claim_authorizations.validate(&claim_issue)?;
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
            ApplicationOpening::from_domain(
                &proof.securities_delivery_opening,
                claim_issue.instruction_nullifier,
                claim_authorizations.authorization(NativeClaimLeg::SecuritiesDelivery)?,
            )?,
            ApplicationOpening::from_domain(
                &proof.securities_refund_opening,
                claim_issue.instruction_nullifier,
                claim_authorizations.authorization(NativeClaimLeg::SecuritiesRefund)?,
            )?,
            ApplicationOpening::from_domain(
                &proof.cash_delivery_opening,
                claim_issue.instruction_nullifier,
                claim_authorizations.authorization(NativeClaimLeg::CashDelivery)?,
            )?,
            ApplicationOpening::from_domain(
                &proof.cash_refund_opening,
                claim_issue.instruction_nullifier,
                claim_authorizations.authorization(NativeClaimLeg::CashRefund)?,
            )?,
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
