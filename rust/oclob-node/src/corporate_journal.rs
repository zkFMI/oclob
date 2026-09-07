//! Corporate-only recovery journal, backed by the pinned encrypted and
//! crash-atomic CorporateOutbox. Its immutable records are protocol stages,
//! not substitute settlement receipts. No project-owned encryption core.

use crate::corporate::{CorporateNativeConfig, FacilityWitness, PreparedCorporateReserve};
use crate::edge_client::{EdgeAdmissionReceipt, PreparedEdgeDelivery};
use crate::network::ClusterPublicConfig;
use oclob_core::application_crypto::SigningKey;
use oclob_edge::SealedReservationAuthority;
use oclob_settlement::native::{
    NativeClaimAuthorizationCommitment, NativeClaimAuthorizationIssue, NativeClaimLeg,
    NativeParticipantClaimAuthorizations, CLAIM_AUTHORIZATION_ISSUE_VERSION,
};
use defmi::claim_redemption::NoteClaimAuthorization;
use defmi::note_chain::NoteClaim;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use zkpi_defmi_sdk::corporate::CorporateOutbox;

const RECORD_BYTES: usize = 4 * 1024 * 1024;

/// Only the participant's encrypted journal may serialize this value.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCorporateIntent {
    pub input_digest: [u8; 32],
    pub order_wire: Vec<u8>,
    #[serde(with = "oclob_core::application_crypto::secret_serde")]
    pub signing_key: [u8; 64],
    pub eligibility_commitment: [u8; 32],
    pub accepted_at: u64,
    pub expires_at: u64,
    /// Old journals cannot prove that no untracked request was sent.
    #[serde(default)]
    pub reserve_send_tracking: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReserveSendDecision {
    intent_digest: [u8; 32],
    reserve_digest: [u8; 32],
    may_send: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCorporateDelivery {
    pub reserve_digest: [u8; 32],
    pub delivery: PreparedEdgeDelivery,
    pub authority: SealedReservationAuthority,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredClaimAuthorizationKey {
    leg: NativeClaimLeg,
    recipient_commitment: [u8; 32],
    #[serde(with = "oclob_core::application_crypto::secret_serde")]
    signing_key: [u8; 64],
    authorization: defmi::note_chain::ClaimAuthorizationCommitment,
}

/// Private one-time claim signers. Only the encrypted CorporateOutbox may
/// serialize this record; public RPC responses are reconstructed separately.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredClaimAuthorizations {
    version: u16,
    issue_view: [u8; 32],
    reservation_id: [u8; 32],
    sequence: u64,
    not_before: u64,
    not_after: u64,
    order_signer: [u8; 32],
    response_wire: Vec<u8>,
    keys: [StoredClaimAuthorizationKey; 2],
}

impl StoredClaimAuthorizationKey {
    fn restore(&self, not_before: u64, not_after: u64) -> Result<NoteClaimAuthorization, String> {
        let authorization = NoteClaimAuthorization::from_signer(
            self.recipient_commitment,
            not_before,
            not_after,
            SigningKey::from_bytes(&self.signing_key).raw_hybrid_signer(),
        )?;
        if authorization.commitment()? != self.authorization {
            return Err("stored claim authorization key differs from its public commitment".into());
        }
        Ok(authorization)
    }
}

impl StoredClaimAuthorizations {
    fn generate(
        issue: &NativeClaimAuthorizationIssue,
        reservation_id: [u8; 32],
        now: u64,
        order_signer: &SigningKey,
    ) -> Result<Self, String> {
        if now == u64::MAX {
            return Err("claim authorization cannot start at the maximum timestamp".into());
        }
        let expected = issue.expected_for(reservation_id)?;
        let build = |(leg, recipient_commitment)| {
            let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
            let authorization = NoteClaimAuthorization::from_signer(
                recipient_commitment,
                now,
                u64::MAX,
                signing_key.raw_hybrid_signer(),
            )?
            .commitment()?;
            Ok::<_, String>(StoredClaimAuthorizationKey {
                leg,
                recipient_commitment,
                signing_key: signing_key.to_bytes(),
                authorization,
            })
        };
        let mut result = Self {
            version: CLAIM_AUTHORIZATION_ISSUE_VERSION,
            issue_view: issue.participant_view_digest(reservation_id)?,
            reservation_id,
            sequence: issue.sequence_for(reservation_id)?,
            not_before: now,
            not_after: u64::MAX,
            order_signer: order_signer.verifying_key().to_bytes(),
            response_wire: Vec::new(),
            keys: [build(expected[0])?, build(expected[1])?],
        };
        let response = result.public_unsigned(issue)?.sign(issue, order_signer)?;
        result.response_wire = serde_json::to_vec(&response).map_err(err)?;
        result.public(issue, result.order_signer)?;
        Ok(result)
    }

    fn retained_unsigned(&self) -> Result<NativeParticipantClaimAuthorizations, String> {
        if self.version != CLAIM_AUTHORIZATION_ISSUE_VERSION
            || self.issue_view == [0; 32]
            || self.reservation_id == [0; 32]
            || self.sequence == u64::MAX
            || self.not_before >= self.not_after
            || self.order_signer == [0; 32]
            || self.keys[0].leg == self.keys[1].leg
        {
            return Err("stored claim authorization context is inconsistent".into());
        }
        let mut claims = Vec::with_capacity(2);
        for key in &self.keys {
            key.restore(self.not_before, self.not_after)?;
            claims.push(NativeClaimAuthorizationCommitment {
                leg: key.leg,
                recipient_commitment: key.recipient_commitment,
                authorization: key.authorization,
            });
        }
        let response = NativeParticipantClaimAuthorizations {
            version: self.version,
            reservation_id: self.reservation_id,
            sequence: self.sequence,
            claims: claims
                .try_into()
                .map_err(|_| "stored claim authorization count is invalid")?,
            signature: Vec::new(),
        };
        response.validate_shape()?;
        Ok(response)
    }

    fn public_unsigned(
        &self,
        expected_issue: &NativeClaimAuthorizationIssue,
    ) -> Result<NativeParticipantClaimAuthorizations, String> {
        if self.issue_view != expected_issue.participant_view_digest(self.reservation_id)?
            || self.sequence != expected_issue.sequence_for(self.reservation_id)?
        {
            return Err("stored claim authorization participant view is inconsistent".into());
        }
        let response = self.retained_unsigned()?;
        response.validate(expected_issue)?;
        Ok(response)
    }

    fn retained_public(&self) -> Result<NativeParticipantClaimAuthorizations, String> {
        if self.response_wire.is_empty() || self.response_wire.len() > 64 * 1024 {
            return Err("stored claim authorization response wire is invalid".into());
        }
        let response: NativeParticipantClaimAuthorizations =
            serde_json::from_slice(&self.response_wire).map_err(err)?;
        if serde_json::to_vec(&response).map_err(err)? != self.response_wire {
            return Err("stored claim authorization response wire is not canonical".into());
        }
        let mut unsigned = response.clone();
        unsigned.signature.clear();
        if unsigned != self.retained_unsigned()? {
            return Err(
                "stored claim authorization response differs from its retained keys".into(),
            );
        }
        response.verify_participant_view(self.issue_view, self.order_signer)?;
        Ok(response)
    }

    fn public(
        &self,
        expected_issue: &NativeClaimAuthorizationIssue,
        expected_signer: [u8; 32],
    ) -> Result<NativeParticipantClaimAuthorizations, String> {
        if self.order_signer != expected_signer
            || self.issue_view != expected_issue.participant_view_digest(self.reservation_id)?
            || self.sequence != expected_issue.sequence_for(self.reservation_id)?
        {
            return Err("stored claim authorization signer is inconsistent".into());
        }
        let response = self.retained_public()?;
        let mut unsigned = response.clone();
        unsigned.signature.clear();
        if self.public_unsigned(expected_issue)? != unsigned {
            return Err(
                "stored claim authorization response differs from the requested claims".into(),
            );
        }
        response.verify(expected_issue, expected_signer)?;
        Ok(response)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundRecord<T> {
    version: u16,
    context: [u8; 32],
    body: T,
}

/// No Debug/Clone: this object owns an encryption secret. Each insertion is
/// independently locked and fsynced by CorporateOutbox. Competing writers use
/// the first persisted record; no writer may replace an in-flight request.
pub struct NativeCorporateJournal {
    outbox: CorporateOutbox,
    context: [u8; 32],
    path: PathBuf,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationEndReason {
    Expired,
    InsufficientFunding,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndedCorporateAuthorization {
    pub request_id: String,
    pub authorization_digest: [u8; 32],
    pub ended_at: u64,
    pub reason: AuthorizationEndReason,
}

impl NativeCorporateJournal {
    /// Explicit enrollment only. Normal CLI restart must recover the exact
    /// issued holder, never manufacture a new independent signing key.
    pub fn enroll_eligibility(
        &self,
        config: &CorporateNativeConfig,
        scope: [u8; 32],
        encrypted: &oclob_dekyx::EncryptedEligibilityWallet,
    ) -> Result<(), String> {
        let recovery = config.credential_custody_key()?;
        let proposed = encrypted.restore(&recovery, scope).map_err(err)?;
        let stored: oclob_dekyx::EncryptedEligibilityWallet = self.put_first(
            &format!("eligibility:{}", hex::encode(scope)),
            encrypted,
            1,
            u64::MAX,
        )?;
        let accepted = stored.restore(&recovery, scope).map_err(err)?;
        if accepted.credential_digest().map_err(err)?
            != proposed.credential_digest().map_err(err)?
        {
            return Err(
                "credential already enrolled; renewal requires an explicit new credential epoch"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn enrolled_eligibility(
        &self,
        config: &CorporateNativeConfig,
        scope: [u8; 32],
    ) -> Result<oclob_dekyx::DemoEligibilityWallet, String> {
        let saved: oclob_dekyx::EncryptedEligibilityWallet = self
            .get(&format!("eligibility:{}", hex::encode(scope)))?
            .ok_or(
                "corporate holder credential is not enrolled; authenticated recovery is required",
            )?;
        saved
            .restore(&config.credential_custody_key()?, scope)
            .map_err(err)
    }

    pub(crate) fn context_digest(&self) -> [u8; 32] {
        self.context
    }
    /// Explicit provisioning only. Missing history on a normal restart must
    /// never become a new empty funding state.
    pub fn initialize(
        path: impl Into<PathBuf>,
        secret: &[u8; 32],
        config: &CorporateNativeConfig,
        cluster: &ClusterPublicConfig,
    ) -> Result<Self, String> {
        Self::load(path.into(), secret, config, cluster, true)
    }

    pub fn open(
        path: impl Into<PathBuf>,
        secret: &[u8; 32],
        config: &CorporateNativeConfig,
        cluster: &ClusterPublicConfig,
    ) -> Result<Self, String> {
        Self::load(path.into(), secret, config, cluster, false)
    }

    fn load(
        path: PathBuf,
        secret: &[u8; 32],
        config: &CorporateNativeConfig,
        cluster: &ClusterPublicConfig,
        initialize: bool,
    ) -> Result<Self, String> {
        if *secret == [0; 32] {
            return Err("corporate journal key is empty".into());
        }
        cluster.validate().map_err(err)?;
        let context: [u8; 32] = Sha256::new()
            .chain_update(b"OCLOB:NATIVE-JOURNAL-CONTEXT:v1")
            .chain_update(serde_json::to_vec(config).map_err(err)?)
            .chain_update(serde_json::to_vec(cluster).map_err(err)?)
            .finalize()
            .into();
        let outbox = CorporateOutbox::new(&path, secret, 1024, RECORD_BYTES)?;
        if initialize {
            outbox.initialize()?;
        } else {
            outbox.summaries()?;
        }
        let journal = Self {
            outbox,
            context,
            path,
        };
        // A wrong deployment or key is an error, never a new empty wallet.
        let stored: [u8; 32] = journal.put_first("context", &context, 1, u64::MAX)?;
        if stored != context {
            return Err("corporate journal belongs to another deployment".into());
        }
        Ok(journal)
    }

    pub fn input_digest<T: Serialize>(input: &T) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(b"OCLOB:CORPORATE-INPUT:v1")
            .chain_update(serde_json::to_vec(input).map_err(err)?)
            .finalize()
            .into())
    }

    pub fn intent(&self, id: &str) -> Result<Option<StoredCorporateIntent>, String> {
        self.get(&record_id("intent", id)?)
    }

    /// Corporate-only enumeration for resuming delivery of public signed
    /// admissions. No order bodies or participant keys leave this method.
    pub fn admitted_request_ids(&self) -> Result<Vec<String>, String> {
        Ok(self
            .outbox
            .summaries()?
            .into_iter()
            .filter_map(|e| e.request_id.strip_prefix("receipt:").map(str::to_owned))
            .collect())
    }

    /// Serializes corporate intake's intent/authorization/queue insertions so
    /// the journal and dispatch FIFO cannot acquire opposite orders.
    pub fn acquire_intake(&self) -> Result<std::fs::File, String> {
        crate::corporate_dispatch::acquire_corporate_lock(
            &self.path.with_extension("intake.lock"),
            true,
        )
    }

    pub fn authorization_scope(
        &self,
        config: &CorporateNativeConfig,
        identity: &crate::network::ClientIdentityConfig,
    ) -> Result<defmi::application_reservation::ApplicationReserveScope, String> {
        use crate::corporate_authorization::{read_authorization_scope, validate_scope};
        let saved = match self.get("authorization-scope")? {
            Some(saved) => saved,
            None => self.put_first(
                "authorization-scope",
                &read_authorization_scope(config, identity)?,
                1,
                u64::MAX,
            )?,
        };
        validate_scope(config, &saved)?;
        Ok(saved)
    }

    pub fn authorization(
        &self,
        id: &str,
    ) -> Result<Option<crate::corporate_authorization::CorporateReserveAuthorization>, String> {
        self.get(&record_id("authorization", id)?)
    }

    pub fn save_authorization(
        &self,
        id: &str,
        value: &crate::corporate_authorization::CorporateReserveAuthorization,
        config: &CorporateNativeConfig,
    ) -> Result<crate::corporate_authorization::CorporateReserveAuthorization, String> {
        let intent = self
            .intent(id)?
            .ok_or("authorization has no durable corporate intent")?;
        value.validate(config)?;
        if value.order_wire != intent.order_wire
            || value.signing_key != intent.signing_key
            || value.eligibility_commitment != intent.eligibility_commitment
            || value.mandate.valid_from < intent.accepted_at
            || value.mandate.valid_until != intent.expires_at
        {
            return Err("authorization differs from corporate intake".into());
        }
        let saved = self.put_first(
            &record_id("authorization", id)?,
            value,
            intent.accepted_at,
            intent.expires_at,
        )?;
        let saved: crate::corporate_authorization::CorporateReserveAuthorization = saved;
        saved.validate(config)?;
        if saved.order_wire != intent.order_wire
            || saved.signing_key != intent.signing_key
            || saved.eligibility_commitment != intent.eligibility_commitment
            || saved.mandate.valid_from < intent.accepted_at
            || saved.mandate.valid_until != intent.expires_at
        {
            return Err("saved authorization differs from corporate intake".into());
        }
        Ok(saved)
    }

    pub fn ended_authorization(
        &self,
        id: &str,
    ) -> Result<Option<EndedCorporateAuthorization>, String> {
        let ended: Option<EndedCorporateAuthorization> =
            self.get(&record_id("authorization-end", id)?)?;
        if let Some(value) = &ended {
            let authorization = self
                .authorization(id)?
                .ok_or("ended authorization lost its terms")?;
            let intent = self
                .intent(id)?
                .ok_or("ended authorization lost its intent")?;
            let decision: ReserveSendDecision = self
                .get(&record_id("reserve-send", id)?)?
                .ok_or("ended authorization has no send fence")?;
            if value.request_id != id
                || value.authorization_digest != authorization.digest()?
                || !intent.reserve_send_tracking
                || decision.may_send
                || decision.intent_digest != intent.input_digest
                || decision.reserve_digest != value.authorization_digest
                || value.ended_at < intent.accepted_at
                || value.reason == AuthorizationEndReason::Expired
                    && value.ended_at <= intent.expires_at
            {
                return Err("ended authorization is inconsistent or could have been sent".into());
            }
        }
        Ok(ended)
    }

    /// Only before any funding request exists. An immutable send fence also
    /// prevents a racing preparation from ever sending its late result.
    pub fn end_unprepared_authorization(
        &self,
        id: &str,
        at: u64,
        reason: AuthorizationEndReason,
    ) -> Result<EndedCorporateAuthorization, String> {
        if let Some(saved) = self.ended_authorization(id)? {
            return Ok(saved);
        }
        let intent = self
            .intent(id)?
            .ok_or("ending authorization has no intent")?;
        if !intent.reserve_send_tracking
            || at < intent.accepted_at
            || reason == AuthorizationEndReason::Expired && at <= intent.expires_at
        {
            return Err("authorization cannot end before its permitted boundary".into());
        }
        for stage in ["reserve", "admission", "delivery", "receipt"] {
            if self.stage::<serde_json::Value>(id, stage)?.is_some() {
                return Err(
                    "prepared or delivered authorization requires canonical reconciliation".into(),
                );
            }
        }
        let authorization = self
            .authorization(id)?
            .ok_or("ending authorization has no signed terms")?;
        let digest = authorization.digest()?;
        if self.choose_reserve_send(id, digest, false, at)? {
            return Err("authorization has an ambiguous send".into());
        }
        let ended = EndedCorporateAuthorization {
            request_id: id.into(),
            authorization_digest: digest,
            ended_at: at,
            reason,
        };
        self.put_first::<EndedCorporateAuthorization>(
            &record_id("authorization-end", id)?,
            &ended,
            at,
            u64::MAX,
        )?;
        self.ended_authorization(id)?
            .ok_or("authorization end was not durable".into())
    }

    pub fn save_intent(
        &self,
        id: &str,
        intent: &StoredCorporateIntent,
    ) -> Result<StoredCorporateIntent, String> {
        let stored: StoredCorporateIntent = self.put_first(
            &record_id("intent", id)?,
            intent,
            intent.accepted_at,
            intent.expires_at,
        )?;
        if stored.input_digest != intent.input_digest {
            return Err("corporate request ID was reused for another order instruction".into());
        }
        Ok(stored)
    }

    /// Do not let a later request overtake an ambiguous earlier reservation or
    /// partial MPC delivery. Expired entries are retained for explicit release.
    pub fn require_turn(&self, id: &str) -> Result<(), String> {
        let target = record_id("intent", id)?;
        let records = self.outbox.summaries()?;
        if records.iter().any(|r| {
            r.request_id == format!("resolved:{id}")
                || r.request_id == format!("authorization-end:{id}")
        }) {
            return Err("corporate request already ended without admission".into());
        }
        let completed: BTreeSet<_> = records
            .iter()
            .filter_map(|r| {
                r.request_id
                    .strip_prefix("receipt:")
                    .or_else(|| r.request_id.strip_prefix("resolved:"))
                    .or_else(|| r.request_id.strip_prefix("authorization-end:"))
            })
            .collect();
        if completed.contains(id) {
            return Ok(());
        }
        let oldest = records
            .iter()
            .filter(|r| {
                r.request_id.starts_with("intent:") && !completed.contains(&r.request_id[7..])
            })
            .min_by_key(|r| r.sequence);
        if oldest.is_some_and(|r| r.request_id != target) {
            return Err("an earlier corporate request must be admitted or reconciled first".into());
        }
        Ok(())
    }

    pub fn stage<T: DeserializeOwned>(&self, id: &str, stage: &str) -> Result<Option<T>, String> {
        self.get(&record_id(stage, id)?)
    }

    fn choose_reserve_send(
        &self,
        id: &str,
        reserve_digest: [u8; 32],
        may_send: bool,
        at: u64,
    ) -> Result<bool, String> {
        let intent = self
            .intent(id)?
            .ok_or("reserve send has no durable intent")?;
        let reserve_digest = self.send_binding(id, reserve_digest)?;
        let decision: ReserveSendDecision = self.put_first(
            &record_id("reserve-send", id)?,
            &ReserveSendDecision {
                intent_digest: intent.input_digest,
                reserve_digest,
                may_send,
            },
            at,
            u64::MAX,
        )?;
        if decision.intent_digest != intent.input_digest
            || decision.reserve_digest != reserve_digest
        {
            return Err("reserve send decision differs from the original request".into());
        }
        Ok(decision.may_send)
    }

    fn send_binding(&self, id: &str, digest: [u8; 32]) -> Result<[u8; 32], String> {
        let Some(authorization) = self.authorization(id)? else {
            return Ok(digest);
        };
        let binding = authorization.digest()?;
        if digest != binding {
            let prepared: PreparedCorporateReserve = self
                .stage(id, "reserve")?
                .ok_or("authorized send lost its prepared funding")?;
            if digest != crate::corporate_submission::reserve_digest(&prepared)?
                || prepared.request.mandate != authorization.mandate
                || prepared.order_wire != authorization.order_wire
                || prepared.request.order_authorization_salt
                    != authorization.order_authorization_salt
                || prepared.request.reserve_reblinding != authorization.reserve_reblinding
            {
                return Err("prepared send differs from the original signed authorization".into());
            }
        }
        Ok(binding)
    }

    pub(crate) fn mark_reserve_send_started(
        &self,
        id: &str,
        digest: [u8; 32],
        at: u64,
    ) -> Result<(), String> {
        if !self.choose_reserve_send(id, digest, true, at)? {
            return Err("unsent expiry fence prevents this reserve send".into());
        }
        Ok(())
    }

    pub(crate) fn seal_never_dispatched(
        &self,
        id: &str,
        digest: [u8; 32],
        at: u64,
    ) -> Result<bool, String> {
        let intent = self.intent(id)?.ok_or("unsent expiry has no intent")?;
        if !intent.reserve_send_tracking || at <= intent.expires_at {
            return Ok(false);
        }
        for stage in ["admission", "delivery", "receipt"] {
            if self.stage::<serde_json::Value>(id, stage)?.is_some() {
                return Ok(false);
            }
        }
        // One first-write-wins record decides between sending and ending
        // unsent, including when a separate corporate CLI races the worker.
        Ok(!self.choose_reserve_send(id, digest, false, at)?)
    }

    pub(crate) fn expiry_release(
        &self,
        id: &str,
    ) -> Result<Option<defmi::application_settlement::ApplicationNoteRelease>, String> {
        self.get(&record_id("expiry", id)?)
    }

    pub(crate) fn save_expiry_release(
        &self,
        id: &str,
        release: &defmi::application_settlement::ApplicationNoteRelease,
        prepared: &PreparedCorporateReserve,
        now: u64,
    ) -> Result<defmi::application_settlement::ApplicationNoteRelease, String> {
        crate::corporate_expiry::validate_expiry_release(release, prepared, now)?;
        let saved = self.put_first(&record_id("expiry", id)?, release, now, u64::MAX)?;
        crate::corporate_expiry::validate_expiry_release(&saved, prepared, now)?;
        Ok(saved)
    }

    fn verify_unsent_resolution(
        &self,
        value: &crate::corporate_expiry::NativeExpiryResolution,
    ) -> Result<(), String> {
        if matches!(
            value.outcome,
            crate::corporate_expiry::ExpiryOutcome::NeverReserved { .. }
        ) {
            let intent = self
                .intent(&value.request_id)?
                .ok_or("absence record lost its intent")?;
            let decision: ReserveSendDecision = self
                .get(&record_id("reserve-send", &value.request_id)?)?
                .ok_or("absence record has no atomic unsent fence")?;
            if !intent.reserve_send_tracking
                || decision.may_send
                || decision.intent_digest != intent.input_digest
                || decision.reserve_digest
                    != self.send_binding(&value.request_id, value.reserve_digest)?
            {
                return Err("absence record cannot exclude an ambiguous or legacy send".into());
            }
        }
        Ok(())
    }

    pub(crate) fn expiry_resolution(
        &self,
        prepared: &PreparedCorporateReserve,
    ) -> Result<Option<crate::corporate_expiry::NativeExpiryResolution>, String> {
        let value: Option<crate::corporate_expiry::NativeExpiryResolution> = self.get(&format!(
            "expiry-result:{}",
            hex::encode(prepared.request.mandate.hold_id)
        ))?;
        if let Some(value) = &value {
            value.validate(prepared)?;
            self.verify_unsent_resolution(value)?;
        }
        Ok(value)
    }

    pub(crate) fn was_never_reserved(
        &self,
        prepared: &PreparedCorporateReserve,
    ) -> Result<bool, String> {
        for record in self.outbox.summaries()? {
            if let Some(id) = record.request_id.strip_prefix("authorization-end:") {
                if self.ended_authorization(id)?.is_some()
                    && self
                        .authorization(id)?
                        .is_some_and(|a| a.mandate.hold_id == prepared.request.mandate.hold_id)
                {
                    self.send_binding(id, crate::corporate_submission::reserve_digest(prepared)?)?;
                    return Ok(true);
                }
            }
        }
        Ok(self.expiry_resolution(prepared)?.is_some_and(|value| {
            matches!(
                value.outcome,
                crate::corporate_expiry::ExpiryOutcome::NeverReserved { .. }
            )
        }))
    }

    pub(crate) fn save_expiry_resolution(
        &self,
        value: &crate::corporate_expiry::NativeExpiryResolution,
        prepared: &PreparedCorporateReserve,
    ) -> Result<crate::corporate_expiry::NativeExpiryResolution, String> {
        value.validate(prepared)?;
        self.verify_unsent_resolution(value)?;
        let stored: crate::corporate_expiry::NativeExpiryResolution = self.put_first(
            &format!(
                "expiry-result:{}",
                hex::encode(prepared.request.mandate.hold_id)
            ),
            value,
            value.checked_at,
            u64::MAX,
        )?;
        stored.validate(prepared)?;
        if stored != *value {
            return Err("expiry result conflicts with earlier canonical evidence".into());
        }
        Ok(stored)
    }

    pub(crate) fn complete_expiry(
        &self,
        value: &crate::corporate_expiry::NativeExpiryResolution,
        prepared: &PreparedCorporateReserve,
    ) -> Result<(), String> {
        value.validate(prepared)?;
        if self.expiry_resolution(prepared)?.as_ref() != Some(value) {
            return Err("expiry completion has no durable canonical evidence".into());
        }
        let stored: crate::corporate_expiry::NativeExpiryResolution = self.put_first(
            &record_id("resolved", &value.request_id)?,
            value,
            value.checked_at,
            u64::MAX,
        )?;
        if stored != *value {
            return Err("expiry completion conflicts with saved outcome".into());
        }
        Ok(())
    }

    pub fn completed_expiry(
        &self,
        id: &str,
    ) -> Result<Option<crate::corporate_expiry::NativeExpiryResolution>, String> {
        let value: Option<crate::corporate_expiry::NativeExpiryResolution> =
            self.get(&record_id("resolved", id)?)?;
        if let Some(value) = &value {
            let prepared: PreparedCorporateReserve = self
                .stage(id, "reserve")?
                .ok_or("completed expiry lost its reserve")?;
            value.validate(&prepared)?;
            if value.request_id != id || self.expiry_resolution(&prepared)?.as_ref() != Some(value)
            {
                return Err("completed expiry differs from saved canonical evidence".into());
            }
        }
        Ok(value)
    }

    pub fn cancellation(
        &self,
        id: &str,
    ) -> Result<Option<crate::native_lifecycle::LifecycleCommand>, String> {
        self.get(&record_id("cancel", id)?)
    }

    pub fn save_cancellation(
        &self,
        id: &str,
        command: &crate::native_lifecycle::LifecycleCommand,
    ) -> Result<crate::native_lifecycle::LifecycleCommand, String> {
        let intent = self
            .intent(id)?
            .ok_or("cancel has no saved corporate intent")?;
        let receipt: EdgeAdmissionReceipt = self
            .stage(id, "receipt")?
            .ok_or("cancel has no admitted order")?;
        let delivery: StoredCorporateDelivery = self
            .stage(id, "delivery")?
            .ok_or("cancel has no saved delivery")?;
        if delivery.delivery.manifest != receipt.manifest
            || oclob_core::application_crypto::SigningKey::from_bytes(&intent.signing_key)
                .verifying_key()
                .to_bytes()
                != receipt.manifest.signer
            || command.reason
                != defmi::application_settlement::ApplicationReleaseReason::Cancelled
        {
            return Err("cancel does not belong to the originally admitted corporate order".into());
        }
        command.verify(&receipt.manifest, command.issued_at)?;
        let saved: crate::native_lifecycle::LifecycleCommand = self.put_first(
            &record_id("cancel", id)?,
            command,
            command.issued_at,
            command.expires_at,
        )?;
        saved.verify(&receipt.manifest, saved.issued_at)?;
        Ok(saved)
    }

    pub fn save_stage<T: Serialize + DeserializeOwned>(
        &self,
        id: &str,
        stage: &str,
        body: &T,
        intent: &StoredCorporateIntent,
    ) -> Result<T, String> {
        if !matches!(
            stage,
            "reserve" | "admission" | "delivery" | "market-input" | "market"
        ) {
            return Err("unknown corporate submission stage".into());
        }
        self.put_first(
            &record_id(stage, id)?,
            body,
            intent.accepted_at,
            intent.expires_at,
        )
    }

    pub fn save_receipt(
        &self,
        id: &str,
        receipt: &EdgeAdmissionReceipt,
        delivery: &StoredCorporateDelivery,
        cluster: &ClusterPublicConfig,
        intent: &StoredCorporateIntent,
    ) -> Result<EdgeAdmissionReceipt, String> {
        self.verify_receipt(receipt, delivery, cluster, intent.accepted_at)?;
        let stored = self.put_first(
            &record_id("receipt", id)?,
            receipt,
            intent.accepted_at,
            intent.expires_at,
        )?;
        self.verify_receipt(&stored, delivery, cluster, intent.accepted_at)?;
        Ok(stored)
    }

    pub fn save_reserved_witness(&self, prepared: &PreparedCorporateReserve) -> Result<(), String> {
        self.save_funding_witness(&prepared.facility_after)
    }

    pub fn save_funding_witness(&self, witness: &FacilityWitness) -> Result<(), String> {
        let commitments = witness.commitments()?;
        let id = format!(
            "funding:{}:{}",
            hex::encode(witness.facility_id),
            witness.sequence
        );
        let stored: FacilityWitness = self.put_first(&id, witness, 1, u64::MAX)?;
        if stored.facility_id != witness.facility_id
            || stored.sequence != witness.sequence
            || stored.commitments()? != commitments
        {
            return Err(
                "two different corporate funding witnesses name the same canonical generation"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn reservations(&self) -> Result<Vec<PreparedCorporateReserve>, String> {
        let mut records = self.outbox.summaries()?;
        records.sort_by_key(|r| r.sequence);
        records
            .into_iter()
            .filter(|r| r.request_id.starts_with("reserve:"))
            .map(|r| {
                self.get(&r.request_id)?
                    .ok_or("saved reserve disappeared".into())
            })
            .collect()
    }

    /// Resolve one locally admitted reservation without exposing another
    /// participant's records. Claim keys may be issued only after the exact
    /// reserve and its market admission receipt are durable.
    pub fn admitted_reservation(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<
        (
            PreparedCorporateReserve,
            oclob_settlement::pretrade::FinalizedReservation,
        ),
        String,
    > {
        let mut found = None;
        for summary in self.outbox.summaries()? {
            let Some(request_id) = summary.request_id.strip_prefix("reserve:") else {
                continue;
            };
            let prepared: PreparedCorporateReserve = self
                .get(&summary.request_id)?
                .ok_or("saved reserve disappeared")?;
            if prepared.request.mandate.hold_id != reservation_id {
                continue;
            }
            if found.is_some() {
                return Err("corporate journal contains duplicate reservation ownership".into());
            }
            let finalized = self
                .stage(request_id, "admission")?
                .ok_or("claim authorization reservation has no durable permit")?;
            let _: EdgeAdmissionReceipt = self
                .stage(request_id, "receipt")?
                .ok_or("claim authorization reservation was not admitted to the market")?;
            found = Some((prepared, finalized));
        }
        found.ok_or_else(|| "claim authorization reservation is not owned by this journal".into())
    }

    pub fn saved_claim_authorizations(
        &self,
        issue: &NativeClaimAuthorizationIssue,
        reservation_id: [u8; 32],
        expected_signer: [u8; 32],
    ) -> Result<Option<NativeParticipantClaimAuthorizations>, String> {
        let Some(stored): Option<StoredClaimAuthorizations> = self.get(
            &claim_authorization_record_id(reservation_id, issue.sequence_for(reservation_id)?),
        )?
        else {
            return Ok(None);
        };
        stored.public(issue, expected_signer).map(Some)
    }

    /// Persist both independently generated signer seeds before returning
    /// their public commitments. A racing retry adopts and validates the first
    /// encrypted record instead of returning newly generated keys.
    pub fn issue_claim_authorizations(
        &self,
        issue: &NativeClaimAuthorizationIssue,
        reservation_id: [u8; 32],
        now: u64,
        order_signer: &SigningKey,
    ) -> Result<NativeParticipantClaimAuthorizations, String> {
        if let Some(saved) = self.saved_claim_authorizations(
            issue,
            reservation_id,
            order_signer.verifying_key().to_bytes(),
        )? {
            return Ok(saved);
        }
        let proposed =
            StoredClaimAuthorizations::generate(issue, reservation_id, now, order_signer)?;
        let stored: StoredClaimAuthorizations = self.put_first(
            &claim_authorization_record_id(reservation_id, issue.sequence_for(reservation_id)?),
            &proposed,
            now,
            u64::MAX,
        )?;
        stored.public(issue, order_signer.verifying_key().to_bytes())
    }

    /// Restore only the signer whose opaque public commitment was already
    /// fixed in canonical claim state. Missing or conflicting custody fails;
    /// recovery never manufactures a replacement key.
    pub fn claim_authorization(&self, claim: &NoteClaim) -> Result<NoteClaimAuthorization, String> {
        claim.validate()?;
        let mut fingerprints = BTreeSet::new();
        let mut found = None;
        for summary in self.outbox.summaries()? {
            if !summary.request_id.starts_with("claim-authorization:") {
                continue;
            }
            let stored: StoredClaimAuthorizations = self
                .get(&summary.request_id)?
                .ok_or("stored claim authorization disappeared")?;
            stored.retained_public()?;
            for key in &stored.keys {
                if !fingerprints.insert(key.authorization.key_fingerprint) {
                    return Err("corporate journal reuses a claim authorization key".into());
                }
                if key.authorization.key_fingerprint != claim.authorization.key_fingerprint {
                    continue;
                }
                if found.is_some()
                    || key.recipient_commitment != claim.recipient_commitment
                    || key.authorization != claim.authorization
                {
                    return Err("canonical claim substituted its participant authorization".into());
                }
                found = Some(key.restore(stored.not_before, stored.not_after)?);
            }
        }
        found.ok_or_else(|| "canonical claim has no retained participant authorization".into())
    }

    pub fn claim_redemption(
        &self,
        claim: [u8; 32],
    ) -> Result<Option<defmi::claim_redemption::NoteClaimRedemption>, String> {
        self.get(&format!("redemption:{}", hex::encode(claim)))
    }

    pub fn save_claim_redemption(
        &self,
        value: &defmi::claim_redemption::NoteClaimRedemption,
    ) -> Result<defmi::claim_redemption::NoteClaimRedemption, String> {
        value.signing_message()?;
        self.put_first(
            &format!("redemption:{}", hex::encode(value.claim_id)),
            value,
            1,
            u64::MAX,
        )
    }

    pub fn latest_funding(
        &self,
        config: &CorporateNativeConfig,
    ) -> Result<CorporateNativeConfig, String> {
        let prefix = format!("funding:{}:", hex::encode(config.facility_id));
        let records = self.outbox.summaries()?;
        let latest = records
            .iter()
            .filter_map(|r| {
                r.request_id
                    .strip_prefix(&prefix)
                    .and_then(|n| n.parse::<u64>().ok())
                    .map(|sequence| (sequence, r))
            })
            .max_by_key(|(sequence, _)| *sequence);
        let mut next = config.clone();
        if let Some((sequence, record)) = latest {
            let witness: FacilityWitness = self
                .get(&record.request_id)?
                .ok_or("funding witness disappeared")?;
            if witness.facility_id != config.facility_id || witness.sequence != sequence {
                return Err("corporate funding witness index is inconsistent".into());
            }
            witness.commitments()?;
            next.facility_values = witness.values;
            next.facility_blindings = witness.blindings;
        }
        // prepare_reservation compares these openings with fresh canonical
        // commitments. A newer fill/release generation cannot pass as current.
        Ok(next)
    }

    pub fn verify_receipt(
        &self,
        receipt: &EdgeAdmissionReceipt,
        delivery: &StoredCorporateDelivery,
        cluster: &ClusterPublicConfig,
        original_time: u64,
    ) -> Result<(), String> {
        delivery
            .delivery
            .validate(cluster, original_time)
            .map_err(err)?;
        receipt.verify(cluster, original_time).map_err(err)?;
        if receipt.manifest != delivery.delivery.manifest {
            return Err("stored receipt belongs to another encrypted delivery".into());
        }
        for (party, share, key) in &delivery.delivery.deliveries {
            if receipt.order_share_digests[usize::from(*party)] != share.wire_digest()
                || receipt.capability_key_share_digests[usize::from(*party)] != key.wire_digest()
            {
                return Err("stored receipt does not acknowledge the persisted ciphertexts".into());
            }
        }
        Ok(())
    }

    fn get<T: DeserializeOwned>(&self, id: &str) -> Result<Option<T>, String> {
        let Some(summary) = self
            .outbox
            .summaries()?
            .into_iter()
            .find(|r| r.request_id == id)
        else {
            return Ok(None);
        };
        let bytes = self.outbox.signed_request(id, summary.request_digest)?;
        let record: BoundRecord<T> =
            serde_json::from_slice(&bytes).map_err(|_| "corporate stage record is malformed or uses legacy signing custody; explicit PQC migration is required")?;
        if record.version != 2 || record.context != self.context {
            return Err("corporate stage record has a legacy schema or belongs to another deployment; explicit migration is required".into());
        }
        Ok(Some(record.body))
    }

    fn put_first<T: Serialize + DeserializeOwned>(
        &self,
        id: &str,
        body: &T,
        at: u64,
        expiry: u64,
    ) -> Result<T, String> {
        if let Some(stored) = self.get(id)? {
            return Ok(stored);
        }
        let bytes = serde_json::to_vec(&BoundRecord {
            version: 2,
            context: self.context,
            body,
        })
        .map_err(err)?;
        let result = self.outbox.enqueue_first_seen(id, &bytes, at, expiry);
        // Another process may have won with different random proof/encryption
        // bytes. Adopt its immutable record, never send our losing candidate.
        if let Some(stored) = self.get(id)? {
            return Ok(stored);
        }
        result?;
        Err("corporate stage was not durable after insertion".into())
    }
}

fn record_id(stage: &str, id: &str) -> Result<String, String> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        || !matches!(
            stage,
            "intent"
                | "reserve"
                | "admission"
                | "delivery"
                | "receipt"
                | "cancel"
                | "expiry"
                | "resolved"
                | "reserve-send"
                | "authorization"
                | "authorization-end"
                | "market-input"
                | "market"
        )
    {
        return Err("corporate request ID or stage is invalid".into());
    }
    Ok(format!("{stage}:{id}"))
}

fn claim_authorization_record_id(reservation_id: [u8; 32], sequence: u64) -> String {
    format!(
        "claim-authorization:{}",
        hex::encode(
            Sha256::new()
                .chain_update(b"OCLOB:CLAIM-AUTHORIZATION-RECORD:v1")
                .chain_update(reservation_id)
                .chain_update(sequence.to_be_bytes())
                .finalize()
        )
    )
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ClusterNodePublic;
    use curve25519_dalek::scalar::Scalar;
    use oclob_core::application_crypto::SigningKey;
    use oclob_core::{SecretOrder, Side, TimeInForce};
    use oclob_edge::{EdgeOrderBundle, NodeDecryptionKey, NodeEncryptionKey, MPC_PARTIES};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    use std::thread;

    struct Files {
        root: PathBuf,
    }
    impl Files {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "oclob-corporate-journal-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self { root }
        }
        fn path(&self) -> PathBuf {
            self.root.join("journal.enc")
        }
    }
    impl Drop for Files {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn fixture() -> (CorporateNativeConfig, ClusterPublicConfig) {
        let config = CorporateNativeConfig {
            host: "unit-defmi".into(),
            port: 9443,
            server_name: "unit-defmi".into(),
            claim_authorization_endpoint: oclob_edge::ClaimAuthorizationEndpoint {
                host: "unit-claim-authority".into(),
                port: 9890,
                server_name: "unit-claim-authority".into(),
                certificate_sha256: [31; 32],
            },
            venue_id: [1; 32],
            defmi_id: [2; 32],
            issuer_public: SigningKey::from_bytes(&[3; 64]).hybrid_public_key(),
            facility_id: [4; 32],
            asset_id: [5; 32],
            facility_values: [120, 0, 0],
            facility_blindings: [Scalar::from(9u64).to_bytes(), [0; 32], [0; 32]],
            wallet_spend_secret: Scalar::from(10u64).to_bytes(),
            wallet_opening_seed: vec![28; 96],
            credential_custody_seed: vec![29; 96],
            identity_seed: [11; 32],
        };
        let cluster = ClusterPublicConfig {
            version: 5,
            market_id: "CORPORATE-UNIT".into(),
            program: "oclob_match_v1".into(),
            settlement_release_threshold: 3,
            nodes: (0..7)
                .map(|i| ClusterNodePublic {
                    party: i,
                    host: format!("unit-node-{i}"),
                    rpc_port: 7443,
                    proof_port: 8443,
                    server_name: format!("unit-node-{i}"),
                    tls_certificate_sha256: [i as u8 + 1; 32],
                    share_encryption_key: NodeDecryptionKey::generate()
                        .unwrap()
                        .public_key()
                        .unwrap(),
                    receipt_verifying_key: SigningKey::from_bytes(&[i as u8 + 51; 64])
                        .verifying_key()
                        .to_bytes(),
                })
                .collect(),
        };
        (config, cluster)
    }

    fn intent(seed: u8) -> StoredCorporateIntent {
        let order = SecretOrder::new_with_dekyx_nullifier(
            "CORPORATE-UNIT",
            Side::Sell,
            100,
            60,
            TimeInForce::GoodTilCancelled,
            1000,
            [12; 32],
            [13; 32],
            [seed; 32],
            [seed + 1; 32],
        )
        .unwrap();
        StoredCorporateIntent {
            input_digest: [14; 32],
            order_wire: order.to_secret_wire(),
            signing_key: [seed; 64],
            eligibility_commitment: [15; 32],
            accepted_at: 100,
            expires_at: 1000,
            reserve_send_tracking: true,
        }
    }

    #[test]
    fn enrolled_holder_survives_encrypted_journal_restart_and_cannot_be_silently_reissued() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let (mut verifier, issuer) =
            oclob_dekyx::deterministic_demo_environment(&cluster.market_id).unwrap();
        let scope = verifier.requirement().scope_digest;
        assert!(journal.enrolled_eligibility(&config, scope).is_err());
        let wallet = issuer
            .issue_wallet(21, b"durable-holder", &mut rand::rngs::OsRng)
            .unwrap();
        let public = zkfmi_crypto::traits::KemDecapsulator::public_key(
            &config.credential_custody_key().unwrap(),
        );
        let encrypted = wallet.seal_custody(&public).unwrap();
        let credential_digest = wallet.credential_digest().unwrap();
        let nullifier = wallet.subject_nullifier();
        journal
            .enroll_eligibility(&config, scope, &encrypted)
            .unwrap();
        journal
            .enroll_eligibility(&config, scope, &encrypted)
            .unwrap();
        let replacement = issuer
            .issue_wallet(21, b"replacement-holder", &mut rand::rngs::OsRng)
            .unwrap();
        assert!(journal
            .enroll_eligibility(&config, scope, &replacement.seal_custody(&public).unwrap())
            .is_err());
        drop(wallet);
        drop(journal);
        let journal =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        let restored = journal.enrolled_eligibility(&config, scope).unwrap();
        assert_eq!(restored.credential_digest().unwrap(), credential_digest);
        assert_eq!(restored.subject_nullifier(), nullifier);
        let proof = restored
            .present([77; 32], [78; 32], 1000, &mut rand::rngs::OsRng)
            .unwrap();
        verifier
            .verify_order([77; 32], nullifier, 1000, &proof, 100)
            .unwrap();
        assert!(verifier
            .verify_order([77; 32], nullifier, 1000, &proof, 100)
            .is_err());
        let mut bad = config.clone();
        // X25519 clamps the low three bits; change an effective secret bit.
        bad.credential_custody_seed[0] ^= 8;
        assert!(journal.enrolled_eligibility(&bad, scope).is_err());
        bad = config.clone();
        bad.credential_custody_seed[32] ^= 1;
        assert!(journal.enrolled_eligibility(&bad, scope).is_err());
        bad.credential_custody_seed = bad.wallet_opening_seed.clone();
        assert!(bad.credential_custody_key().is_err());
    }

    fn authorized_intent(
        config: &CorporateNativeConfig,
        seed: u8,
    ) -> (
        StoredCorporateIntent,
        crate::corporate_authorization::CorporateReserveAuthorization,
    ) {
        let (_, issuer) = oclob_dekyx::deterministic_demo_environment("CORPORATE-UNIT").unwrap();
        let wallet = issuer
            .issue_wallet(u64::from(seed), &[seed], &mut rand::rngs::OsRng)
            .unwrap();
        let handle =
            zkpi::handles::Identity::from_seed(config.identity_seed).handle(b"defmi:oclob:v1");
        let order = SecretOrder::new_with_dekyx_nullifier(
            "CORPORATE-UNIT",
            Side::Sell,
            100,
            60,
            TimeInForce::GoodTilCancelled,
            1000,
            handle.point.compress().to_bytes(),
            wallet.subject_nullifier(),
            [seed; 32],
            [seed + 1; 32],
        )
        .unwrap();
        let intent = StoredCorporateIntent {
            input_digest: [seed; 32],
            order_wire: order.to_secret_wire(),
            signing_key: [seed; 64],
            eligibility_commitment: [15; 32],
            accepted_at: 100,
            expires_at: 1000,
            reserve_send_tracking: true,
        };
        let scope = defmi::application_reservation::ApplicationReserveScope {
            application_binding: zkpi_defmi_sdk::application::oclob_manifest_v1()
                .digest()
                .unwrap(),
            venue_id: config.venue_id,
            defmi_id: config.defmi_id,
            committee_key_digest: [7; 32],
            pq_committee_digest: [8; 32],
            committee_epoch: 1,
            amount_bits: 32,
        };
        let authorization = crate::corporate_authorization::CorporateReserveAuthorization::create(
            config,
            scope,
            &wallet,
            &order,
            &handle,
            intent.eligibility_commitment,
            &SigningKey::from_bytes(&intent.signing_key),
            100,
        )
        .unwrap();
        (intent, authorization)
    }

    // API state-machine fixtures, not network or financial acceptance.
    fn api_fixture(files: &Files) -> crate::corporate_api::CorporateApi {
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[81; 32], &config, &cluster).unwrap();
        let queue = crate::corporate_dispatch::NativeCorporateDispatch::initialize(
            files.root.join("dispatch.enc"),
            &[81; 32],
        )
        .unwrap();
        crate::corporate_api::CorporateApi {
            config,
            cluster,
            journal,
            queue,
            identity: crate::network::ClientIdentityConfig {
                version: 2,
                tls_certificate: "not-used.pem".into(),
                tls_private_key: "not-used.key".into(),
                tls_ca: "not-used-ca.pem".into(),
                application_signing_key: "not-used.raw".into(),
            },
        }
    }
    fn api_request(
        api: &crate::corporate_api::CorporateApi,
        id: &str,
    ) -> crate::corporate_api::CorporateRequest {
        let (intent, authorization) = authorized_intent(&api.config, 21);
        crate::corporate_api::CorporateRequest::Enqueue {
            request_id: id.into(),
            intent: Box::new(intent),
            authorization: Box::new(authorization),
            source_note: None,
        }
    }
    #[test]
    fn corporate_api_exact_retry_survives_reopen_and_does_not_reserve() {
        use crate::corporate_api::{CorporateApi, CorporateRequest, CorporateResponse};
        let files = Files::new();
        let api = api_fixture(&files);
        let request = api_request(&api, "api-order-1");
        let bytes = serde_json::to_vec(&request).unwrap();
        assert!(matches!(
            api.handle(request, 101).unwrap(),
            CorporateResponse::Queued {
                already_present: false,
                ..
            }
        ));
        assert!(api
            .journal
            .stage::<PreparedCorporateReserve>("api-order-1", "reserve")
            .unwrap()
            .is_none());
        let reopened = CorporateApi {
            journal: NativeCorporateJournal::open(
                files.path(),
                &[81; 32],
                &api.config,
                &api.cluster,
            )
            .unwrap(),
            queue: crate::corporate_dispatch::NativeCorporateDispatch::open(
                files.root.join("dispatch.enc"),
                &[81; 32],
            )
            .unwrap(),
            config: api.config,
            cluster: api.cluster,
            identity: api.identity,
        };
        assert!(matches!(
            reopened
                .handle(serde_json::from_slice(&bytes).unwrap(), 1100)
                .unwrap(),
            CorporateResponse::Queued {
                already_present: true,
                ..
            }
        ));
        assert_eq!(reopened.queue.summaries().unwrap().len(), 1);
        let mut changed: CorporateRequest = serde_json::from_slice(&bytes).unwrap();
        if let CorporateRequest::Enqueue { intent, .. } = &mut changed {
            intent.input_digest[0] ^= 1;
        }
        assert!(reopened.handle(changed, 101).is_err());
        let mut changed: CorporateRequest = serde_json::from_slice(&bytes).unwrap();
        if let CorporateRequest::Enqueue { source_note, .. } = &mut changed {
            *source_note = Some([51; 32]);
        }
        assert!(reopened.handle(changed, 101).is_err());
        assert_eq!(reopened.queue.summaries().unwrap().len(), 1);
    }
    #[test]
    fn corporate_api_accepts_separate_client_outbox_and_replays_original_authorization() {
        use crate::corporate_api::{CorporateRequest, CorporateResponse};
        let server_files = Files::new();
        let client_files = Files::new();
        let api = api_fixture(&server_files);
        let client = NativeCorporateJournal::initialize(
            client_files.path(),
            &[82; 32],
            &api.config,
            &api.cluster,
        )
        .unwrap();
        let (intent, authorization) = authorized_intent(&api.config, 21);
        client.save_intent("external-1", &intent).unwrap();
        client
            .save_authorization("external-1", &authorization, &api.config)
            .unwrap();
        let client_bytes = fs::read(client_files.path()).unwrap();
        assert!(api.journal.intent("external-1").unwrap().is_none());
        let request = || CorporateRequest::Enqueue {
            request_id: "external-1".into(),
            intent: Box::new(client.intent("external-1").unwrap().unwrap()),
            authorization: Box::new(client.authorization("external-1").unwrap().unwrap()),
            source_note: None,
        };
        assert!(matches!(
            api.handle(request(), 101).unwrap(),
            CorporateResponse::Queued {
                already_present: false,
                ..
            }
        ));
        assert!(matches!(
            api.handle(request(), 1100).unwrap(),
            CorporateResponse::Queued {
                already_present: true,
                ..
            }
        ));
        assert_eq!(api.queue.summaries().unwrap().len(), 1);
        assert_eq!(client_bytes, fs::read(client_files.path()).unwrap());
        assert!(!client_files.root.join("dispatch.enc").exists());
        assert!(client.reservations().unwrap().is_empty());
        assert!(NativeCorporateJournal::open(
            server_files.path(),
            &[82; 32],
            &api.config,
            &api.cluster
        )
        .is_err());
    }

    #[test]
    fn corporate_api_rejects_invalid_or_expired_intake_before_writing() {
        use crate::corporate_api::CorporateRequest;
        let files = Files::new();
        let api = api_fixture(&files);
        for id in ["bad/path", "has.dot", ""] {
            assert!(api.handle(api_request(&api, id), 101).is_err());
        }
        assert!(api.handle(api_request(&api, "expired"), 1001).is_err());
        let mut mismatch = api_request(&api, "mismatch");
        if let CorporateRequest::Enqueue { authorization, .. } = &mut mismatch {
            authorization.mandate.facility_id = [99; 32];
        }
        assert!(api.handle(mismatch, 101).is_err());
        assert!(api.queue.summaries().unwrap().is_empty());
        for id in ["expired", "mismatch"] {
            assert!(api.journal.intent(id).unwrap().is_none());
        }
    }

    #[test]
    fn original_authorization_checks_terms_identity_signature_scope_and_openings() {
        let (config, _) = fixture();
        let (_, original) = authorized_intent(&config, 21);
        original.validate(&config).unwrap();
        let mut changed = original.clone();
        changed.order_wire[0] ^= 1;
        assert!(changed.validate(&config).is_err());
        changed = original.clone();
        changed.mandate.valid_until -= 1;
        assert!(changed.validate(&config).is_err());
        changed = original.clone();
        changed.identity.nullifier[0] ^= 1;
        assert!(changed.validate(&config).is_err());
        changed = original.clone();
        changed.identity.context.request_digest[0] ^= 1;
        assert!(changed.validate(&config).is_err());
        changed = original.clone();
        changed.reserve_reblinding = [255; 32];
        assert!(changed.validate(&config).is_err());
        changed = original.clone();
        changed.reserve_blinding = Scalar::from(99u64).to_bytes();
        assert!(changed.validate(&config).is_err());
        let mut other = config;
        other.defmi_id = [99; 32];
        assert!(original.validate(&other).is_err());
    }

    #[test]
    fn signed_authorization_survives_encrypted_reopen_without_issuer_or_witness() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let (intent, authorization) = authorized_intent(&config, 21);
        journal.save_intent("auth-001", &intent).unwrap();
        let saved = journal
            .save_authorization("auth-001", &authorization, &config)
            .unwrap();
        let digest = saved.digest().unwrap();
        assert!(journal
            .stage::<serde_json::Value>("auth-001", "reserve")
            .unwrap()
            .is_none());
        let bytes = fs::read(files.path()).unwrap();
        assert!(!bytes
            .windows(intent.order_wire.len())
            .any(|w| w == intent.order_wire));
        assert!(!bytes
            .windows(intent.signing_key.len())
            .any(|w| w == intent.signing_key));
        drop(journal);
        let reopened =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        let restored = reopened.authorization("auth-001").unwrap().unwrap();
        restored.validate(&config).unwrap();
        assert_eq!(restored.digest().unwrap(), digest);
        assert!(restored.mandate == saved.mandate);
        assert_eq!(restored.order_wire, intent.order_wire);
        let (another, other_authorization) = authorized_intent(&config, 22);
        assert!(reopened
            .save_authorization("auth-001", &other_authorization, &config)
            .is_err());
        assert!(reopened.save_intent("auth-001", &another).is_err());
    }

    #[test]
    fn claim_keys_and_randomized_signed_response_are_first_write_and_exact_after_restart() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let signer = SigningKey::from_bytes(&[71; 64]);
        let issue = NativeClaimAuthorizationIssue {
            version: CLAIM_AUTHORIZATION_ISSUE_VERSION,
            instruction_nullifier: [72; 32],
            payer: oclob_settlement::native::NativeClaimReservation {
                reservation_id: [73; 32],
                participant_handle: [74; 32],
                asset_id: [75; 32],
                sequence: 4,
            },
            payee: oclob_settlement::native::NativeClaimReservation {
                reservation_id: [76; 32],
                participant_handle: [77; 32],
                asset_id: [78; 32],
                sequence: 9,
            },
        };
        let mut unverified_counterparty = issue.clone();
        unverified_counterparty.payee.participant_handle[0] ^= 1;
        let payer = journal
            .issue_claim_authorizations(
                &unverified_counterparty,
                issue.payer.reservation_id,
                100,
                &signer,
            )
            .unwrap();
        let first_wire = serde_json::to_vec(&payer).unwrap();
        let retry = journal
            .issue_claim_authorizations(&issue, issue.payer.reservation_id, 101, &signer)
            .unwrap();
        assert_eq!(serde_json::to_vec(&retry).unwrap(), first_wire);
        payer
            .verify(&issue, signer.verifying_key().to_bytes())
            .unwrap();

        let payee = journal
            .issue_claim_authorizations(&issue, issue.payee.reservation_id, 100, &signer)
            .unwrap();
        assert_eq!(
            payer.claims.map(|claim| claim.leg),
            [
                NativeClaimLeg::SecuritiesDelivery,
                NativeClaimLeg::CashRefund,
            ]
        );
        assert_eq!(
            payee.claims.map(|claim| claim.leg),
            [
                NativeClaimLeg::SecuritiesRefund,
                NativeClaimLeg::CashDelivery,
            ]
        );
        let fingerprints = payer
            .claims
            .iter()
            .chain(&payee.claims)
            .map(|claim| claim.authorization.key_fingerprint)
            .collect::<BTreeSet<_>>();
        assert_eq!(fingerprints.len(), 4);

        let encrypted = fs::read(files.path()).unwrap();
        assert!(!encrypted
            .windows(first_wire.len())
            .any(|window| window == first_wire));
        drop(journal);
        let reopened =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        let restored = reopened
            .saved_claim_authorizations(
                &issue,
                issue.payer.reservation_id,
                signer.verifying_key().to_bytes(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), first_wire);
        let recipient_view =
            curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * Scalar::from(17_u64);
        let recipient_key = zkfmi_crypto::hybrid::kem::HybridKemKey::from_seed(&[81; 96]);
        let recipient_public = zkfmi_crypto::traits::KemDecapsulator::public_key(&recipient_key);
        let context = [82; 32];
        let share = qomm_proofs::opening_envelope::encrypt_opening_share(
            context,
            1,
            Scalar::from(3_u64),
            Scalar::from(5_u64),
            &recipient_view,
            &recipient_public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let mut claim = NoteClaim {
            claim_id: [1; 32],
            asset_id: issue.payee.asset_id,
            value_commitment: [2; 32],
            recipient_commitment: payer.claims[0].recipient_commitment,
            authorization: payer.claims[0].authorization,
            source_hold_id: issue.payee.reservation_id,
            kind: defmi::note_chain::NoteClaimKind::Delivery,
            opening_envelope: qomm_proofs::opening_envelope::OpeningEnvelope::new(
                context,
                1,
                recipient_view,
                vec![share],
            )
            .unwrap(),
        };
        claim.claim_id = claim.derived_id().unwrap();
        let restored_signer = reopened.claim_authorization(&claim).unwrap();
        assert_eq!(restored_signer.commitment().unwrap(), claim.authorization);

        let mut conflicting = issue.clone();
        conflicting.instruction_nullifier[0] ^= 1;
        assert!(reopened
            .issue_claim_authorizations(
                &conflicting,
                conflicting.payer.reservation_id,
                102,
                &signer,
            )
            .is_err());
        let wrong_signer = SigningKey::from_bytes(&[79; 64]);
        assert!(reopened
            .saved_claim_authorizations(
                &issue,
                issue.payer.reservation_id,
                wrong_signer.verifying_key().to_bytes(),
            )
            .is_err());

        let mut next_issue = issue.clone();
        next_issue.instruction_nullifier = [80; 32];
        next_issue.payer.sequence += 1;
        next_issue.payee.sequence += 1;
        let next = reopened
            .issue_claim_authorizations(&next_issue, next_issue.payer.reservation_id, 103, &signer)
            .unwrap();
        assert!(next
            .claims
            .iter()
            .all(|claim| !fingerprints.contains(&claim.authorization.key_fingerprint)));
    }

    #[test]
    fn rejected_unprepared_authorization_is_fenced_and_advances_fifo_after_restart() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let (first, authorization) = authorized_intent(&config, 21);
        let (second, _) = authorized_intent(&config, 22);
        journal.save_intent("first", &first).unwrap();
        journal
            .save_authorization("first", &authorization, &config)
            .unwrap();
        journal.save_intent("second", &second).unwrap();
        assert!(journal.require_turn("second").is_err());
        journal
            .end_unprepared_authorization("first", 101, AuthorizationEndReason::InsufficientFunding)
            .unwrap();
        assert!(journal
            .mark_reserve_send_started("first", authorization.digest().unwrap(), 102)
            .is_err());
        assert!(journal.require_turn("first").is_err());
        journal.require_turn("second").unwrap();
        drop(journal);
        let journal =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        assert!(journal.ended_authorization("first").unwrap().is_some());
        assert!(journal
            .mark_reserve_send_started("first", authorization.digest().unwrap(), 103)
            .is_err());
        journal.require_turn("second").unwrap();
    }

    #[test]
    fn local_authorization_end_refuses_live_deadline_legacy_and_prepared_or_sent_work() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let (intent, authorization) = authorized_intent(&config, 21);
        for stage in ["reserve", "admission", "delivery"] {
            journal.save_intent(stage, &intent).unwrap();
            journal
                .save_authorization(stage, &authorization, &config)
                .unwrap();
            // Unit-only presence fixture: no fake financial receipt is used by
            // any integration journey. Any existing financial stage must block.
            journal
                .save_stage(
                    stage,
                    stage,
                    &serde_json::json!({"unit_presence_only":true}),
                    &intent,
                )
                .unwrap();
            assert!(journal
                .end_unprepared_authorization(stage, 1001, AuthorizationEndReason::Expired)
                .is_err());
        }
        journal.save_intent("live", &intent).unwrap();
        journal
            .save_authorization("live", &authorization, &config)
            .unwrap();
        assert!(journal
            .end_unprepared_authorization("live", 1000, AuthorizationEndReason::Expired)
            .is_err());
        journal
            .mark_reserve_send_started("live", authorization.digest().unwrap(), 101)
            .unwrap();
        assert!(journal
            .end_unprepared_authorization("live", 1001, AuthorizationEndReason::Expired)
            .is_err());
        let mut legacy = intent;
        legacy.reserve_send_tracking = false;
        journal.save_intent("legacy", &legacy).unwrap();
        journal
            .save_authorization("legacy", &authorization, &config)
            .unwrap();
        assert!(journal
            .end_unprepared_authorization("legacy", 1001, AuthorizationEndReason::Expired)
            .is_err());
    }

    #[test]
    fn authorized_expiry_and_interrupted_local_end_finish_without_network_or_tls() {
        use crate::corporate_dispatch::{DispatchProgress, NativeCorporateDispatch};
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let queue_path = files.root.join("dispatch.enc");
        let queue = NativeCorporateDispatch::initialize(&queue_path, &[19; 32]).unwrap();
        let (intent, authorization) = authorized_intent(&config, 21);
        for id in ["expired", "interrupted"] {
            journal.save_intent(id, &intent).unwrap();
            journal
                .save_authorization(id, &authorization, &config)
                .unwrap();
            assert!(!queue
                .enqueue_authorized(&journal, &config, id, None)
                .unwrap());
            assert!(queue
                .enqueue_authorized(&journal, &config, id, None)
                .unwrap());
        }
        let unavailable = crate::network::ClientIdentityConfig {
            version: 2,
            tls_certificate: "/intentionally-missing".into(),
            tls_private_key: "/intentionally-missing".into(),
            tls_ca: "/intentionally-missing".into(),
            application_signing_key: "/intentionally-missing".into(),
        };
        assert_eq!(
            queue
                .pump(
                    &config,
                    &unavailable,
                    &cluster,
                    &journal,
                    1001,
                    2,
                    |_| panic!("no financial side effect allowed")
                )
                .unwrap(),
            DispatchProgress::NeverReserved {
                request_id: "expired".into()
            }
        );
        // Model the precise local crash boundary: end is durable, queue is not.
        journal
            .end_unprepared_authorization(
                "interrupted",
                1001,
                AuthorizationEndReason::InsufficientFunding,
            )
            .unwrap();
        drop(queue);
        let queue = NativeCorporateDispatch::open(&queue_path, &[19; 32]).unwrap();
        assert_eq!(
            queue
                .pump(
                    &config,
                    &unavailable,
                    &cluster,
                    &journal,
                    1002,
                    2,
                    |_| panic!("no financial side effect allowed")
                )
                .unwrap(),
            DispatchProgress::FundingRejected {
                request_id: "interrupted".into()
            }
        );
        assert!(queue.summaries().unwrap().iter().all(|e| matches!(
            e.state,
            zkpi_defmi_sdk::corporate::OutboxState::AbortedBeforeReserve { .. }
        )));
        for id in ["expired", "interrupted"] {
            assert!(journal
                .stage::<serde_json::Value>(id, "reserve")
                .unwrap()
                .is_none());
            assert!(journal
                .mark_reserve_send_started(id, authorization.digest().unwrap(), 1003)
                .is_err());
        }
    }

    #[test]
    fn intake_lock_excludes_independent_journal_writer_and_releases_on_drop() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let first =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let second =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        let guard = first.acquire_intake().unwrap();
        assert!(crate::corporate_dispatch::acquire_corporate_lock(
            &second.path.with_extension("intake.lock"),
            false
        )
        .is_err());
        drop(guard);
        assert!(second.acquire_intake().is_ok());
    }

    #[test]
    fn unsent_expiry_fence_prevents_future_send_and_survives_restart() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        journal.save_intent("fenced-001", &intent(21)).unwrap();
        assert!(!journal
            .seal_never_dispatched("fenced-001", [31; 32], 1000)
            .unwrap());
        assert!(journal
            .seal_never_dispatched("fenced-001", [31; 32], 1001)
            .unwrap());
        assert!(journal
            .mark_reserve_send_started("fenced-001", [31; 32], 1002)
            .is_err());
        drop(journal);
        let reopened =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        assert!(reopened
            .seal_never_dispatched("fenced-001", [31; 32], 1003)
            .unwrap());
        assert!(reopened
            .mark_reserve_send_started("fenced-001", [32; 32], 1004)
            .is_err());
    }

    #[test]
    fn legacy_or_ambiguous_send_cannot_be_reclassified_as_never_reserved() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let mut legacy = intent(21);
        legacy.reserve_send_tracking = false;
        journal.save_intent("legacy-001", &legacy).unwrap();
        assert!(!journal
            .seal_never_dispatched("legacy-001", [31; 32], 1001)
            .unwrap());
        journal.save_intent("ambiguous-001", &intent(22)).unwrap();
        journal
            .mark_reserve_send_started("ambiguous-001", [32; 32], 999)
            .unwrap();
        assert!(!journal
            .seal_never_dispatched("ambiguous-001", [32; 32], 1001)
            .unwrap());
    }

    #[test]
    fn concurrent_send_and_unsent_expiry_have_only_one_durable_winner() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        journal.save_intent("racing-001", &intent(21)).unwrap();
        let barrier = std::sync::Barrier::new(2);
        let (sent, fenced) = std::thread::scope(|scope| {
            let sending = scope.spawn(|| {
                barrier.wait();
                journal
                    .mark_reserve_send_started("racing-001", [31; 32], 999)
                    .is_ok()
            });
            let ending = scope.spawn(|| {
                barrier.wait();
                journal
                    .seal_never_dispatched("racing-001", [31; 32], 1001)
                    .unwrap()
            });
            (sending.join().unwrap(), ending.join().unwrap())
        });
        assert_ne!(sent, fenced);
        assert_eq!(
            journal
                .seal_never_dispatched("racing-001", [31; 32], 1002)
                .unwrap(),
            fenced
        );
    }

    #[test]
    fn cancellation_has_a_typed_namespace_not_a_generic_completion_shortcut() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[71; 32], &config, &cluster).unwrap();
        assert_eq!(record_id("cancel", "first").unwrap(), "cancel:first");
        assert!(journal.cancellation("first").unwrap().is_none());
        assert!(journal
            .save_stage("first", "cancel", &serde_json::json!({}), &intent(20))
            .is_err());
    }

    #[test]
    fn journal_reopens_exact_intent_without_plaintext_or_new_randomness() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let original = intent(21);
        let saved = journal.save_intent("client-001", &original).unwrap();
        let candidate = intent(22);
        let reused = journal.save_intent("client-001", &candidate).unwrap();
        assert_eq!(reused.order_wire, saved.order_wire);
        assert_eq!(reused.signing_key, original.signing_key);
        let bytes = fs::read(files.path()).unwrap();
        assert!(bytes.starts_with(b"QOMMOUT1"));
        let clear = serde_json::to_vec(&original).unwrap();
        assert!(!bytes.windows(clear.len()).any(|window| window == clear));
        assert!(!bytes
            .windows(b"CORPORATE-UNIT".len())
            .any(|w| w == b"CORPORATE-UNIT"));
        assert_eq!(
            fs::metadata(files.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(journal);
        let reopened =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        assert_eq!(
            reopened.intent("client-001").unwrap().unwrap().order_wire,
            original.order_wire
        );
    }

    #[test]
    fn journal_rejects_wrong_key_context_and_changed_instruction_without_resetting() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        journal.save_intent("client-001", &intent(21)).unwrap();
        let before = fs::read(files.path()).unwrap();
        assert!(NativeCorporateJournal::open(files.path(), &[20; 32], &config, &cluster).is_err());
        let mut changed = config.clone();
        changed.defmi_id[0] ^= 1;
        assert!(NativeCorporateJournal::open(files.path(), &[19; 32], &changed, &cluster).is_err());
        let mut other = intent(22);
        other.input_digest[0] ^= 1;
        assert!(journal.save_intent("client-001", &other).is_err());
        assert!(journal.save_intent("../another-wallet", &other).is_err());
        assert_eq!(fs::read(files.path()).unwrap(), before);
    }

    #[test]
    fn corrupted_journal_is_not_reinitialized() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        journal.save_intent("client-001", &intent(21)).unwrap();
        drop(journal);
        let mut raw = fs::read(files.path()).unwrap();
        let at = raw.len() - 1;
        raw[at] ^= 1;
        fs::write(files.path(), &raw).unwrap();
        assert!(NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).is_err());
        assert_eq!(fs::read(files.path()).unwrap(), raw);
    }

    #[test]
    fn concurrent_preparers_adopt_one_immutable_intent() {
        let files = Files::new();
        let (config, cluster) = fixture();
        NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let barrier = Arc::new(Barrier::new(4));
        let workers = (0..4)
            .map(|n| {
                let (config, cluster, path, barrier) = (
                    config.clone(),
                    cluster.clone(),
                    files.path(),
                    Arc::clone(&barrier),
                );
                thread::spawn(move || {
                    let journal =
                        NativeCorporateJournal::open(path, &[19; 32], &config, &cluster).unwrap();
                    barrier.wait();
                    let saved = journal
                        .save_intent("concurrent-001", &intent(21 + n))
                        .unwrap();
                    (saved.order_wire, saved.signing_key)
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>();
        assert!(results.iter().all(|r| r == &results[0]));
    }

    #[test]
    fn ambiguous_earlier_request_blocks_overtaking_and_cannot_be_marked_complete_by_generic_stage()
    {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let first = intent(21);
        journal.save_intent("first", &first).unwrap();
        journal.save_intent("second", &intent(22)).unwrap();
        assert!(journal.require_turn("first").is_ok());
        assert!(journal.require_turn("second").is_err());
        assert!(journal
            .save_stage("first", "receipt", &true, &first)
            .is_err());
        assert!(journal.require_turn("second").is_err());
        drop(journal);
        let reopened =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        assert!(reopened.require_turn("second").is_err());
    }

    #[test]
    fn funding_witness_survives_restart_and_invalid_scalars_fail_closed() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let witness = FacilityWitness {
            facility_id: config.facility_id,
            sequence: 1,
            values: [60, 60, 0],
            blindings: [
                Scalar::from(7u64).to_bytes(),
                Scalar::from(2u64).to_bytes(),
                [0; 32],
            ],
        };
        journal
            .put_first::<FacilityWitness>(
                &format!("funding:{}:1", hex::encode(config.facility_id)),
                &witness,
                1,
                u64::MAX,
            )
            .unwrap();
        drop(journal);
        let reopened =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        let restored = reopened.latest_funding(&config).unwrap();
        assert_eq!(restored.facility_values, witness.values);
        assert_eq!(restored.facility_blindings, witness.blindings);
        let mut invalid = witness;
        invalid.blindings[0] = [255; 32];
        assert!(invalid.commitments().is_err());
    }

    #[test]
    fn recovered_funding_is_immutable_and_invalid_input_cannot_poison_its_generation() {
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let witness = FacilityWitness {
            facility_id: config.facility_id,
            sequence: 2,
            values: [80, 0, 40],
            blindings: [
                Scalar::from(8u64).to_bytes(),
                [0; 32],
                Scalar::ONE.to_bytes(),
            ],
        };
        let before = fs::read(files.path()).unwrap();
        let mut invalid = witness.clone();
        invalid.blindings[0] = [255; 32];
        assert!(journal.save_funding_witness(&invalid).is_err());
        assert_eq!(fs::read(files.path()).unwrap(), before);
        journal.save_funding_witness(&witness).unwrap();
        let canonical_bytes = fs::read(files.path()).unwrap();
        journal.save_funding_witness(&witness).unwrap();
        assert_eq!(fs::read(files.path()).unwrap(), canonical_bytes);
        let mut conflict = witness.clone();
        conflict.values[0] -= 1;
        assert!(journal.save_funding_witness(&conflict).is_err());
        assert_eq!(fs::read(files.path()).unwrap(), canonical_bytes);
        drop(journal);
        let reopened =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        let funding = reopened.latest_funding(&config).unwrap();
        assert_eq!(funding.facility_values, witness.values);
        assert_eq!(funding.facility_blindings, witness.blindings);
    }

    #[test]
    fn claim_request_recovery_preserves_first_destination_and_signature_bytes() {
        use defmi::claim_redemption::NoteClaimRedemption;
        use defmi::note_chain::NoteOutput;
        use defmi::notes::{NoteLedger, Wallet};
        use zkfmi_zk::pedersen::Pedersen;
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let key = Pedersen::new(b"qomm:defmi:v1");
        let ledger = NoteLedger::new(key.clone(), 32);
        let wallet = Wallet::new(&mut rand::rngs::OsRng);
        let build_output = || {
            let note = ledger
                .build_note(
                    &wallet.address,
                    40,
                    key.commit_u64(40, &Scalar::ONE),
                    &Scalar::ONE,
                    &mut rand::rngs::OsRng,
                )
                .expect("valid fixture note encryption");
            NoteOutput::from_note(&note, config.asset_id, [0; 32]).unwrap()
        };
        let claim_authorization = NoteClaimAuthorization::from_signer(
            [46; 32],
            1,
            u64::MAX,
            SigningKey::from_bytes(&[47; 64]).raw_hybrid_signer(),
        )
        .unwrap();
        // This unit tests durable bytes only; VM ownership verification is
        // covered by the real-signature DeFMI tests and live acceptance.
        let original = NoteClaimRedemption {
            version: defmi::claim_redemption::VERSION,
            domain: "unit-chain".into(),
            before_root: [41; 32],
            operation_id: [42; 32],
            claim_id: [43; 32],
            output: build_output(),
            authorization_key: claim_authorization.key_record().clone(),
            recipient_signature: vec![44; 64],
            authorization_signature: vec![44; 64 + zkfmi_crypto::suite::ML_DSA_65_SIG_BYTES],
        };
        let stored = journal.save_claim_redemption(&original).unwrap();
        assert_eq!(stored, original);
        let before = fs::read(files.path()).unwrap();
        let mut another = original.clone();
        another.output = build_output();
        another.recipient_signature = vec![45; 64];
        assert_eq!(journal.save_claim_redemption(&another).unwrap(), original);
        assert_eq!(fs::read(files.path()).unwrap(), before);
        let mut malformed = original.clone();
        malformed.claim_id = [0; 32];
        assert!(journal.save_claim_redemption(&malformed).is_err());
        assert_eq!(fs::read(files.path()).unwrap(), before);
        drop(journal);
        let reopened =
            NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).unwrap();
        assert_eq!(
            reopened
                .claim_redemption(original.claim_id)
                .unwrap()
                .unwrap(),
            original
        );
    }

    #[test]
    fn saved_delivery_preserves_exact_ciphertexts_and_rejects_wrong_node_binding() {
        let (_config, cluster) = fixture();
        let order = SecretOrder::from_secret_wire(&intent(21).order_wire).unwrap();
        let keys: [NodeEncryptionKey; MPC_PARTIES] = cluster
            .nodes
            .iter()
            .map(|n| n.share_encryption_key.clone())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let bundle = EdgeOrderBundle::create(
            &order,
            [16; 32],
            [17; 32],
            &SigningKey::from_bytes(&[21; 64]),
            &keys,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let prepared = PreparedEdgeDelivery::from_bundle(bundle);
        let encoded = serde_json::to_vec(&prepared).unwrap();
        let mut restored: PreparedEdgeDelivery = serde_json::from_slice(&encoded).unwrap();
        restored.validate(&cluster, 100).unwrap();
        for ((_, old, old_key), (_, new, new_key)) in
            prepared.deliveries.iter().zip(&restored.deliveries)
        {
            assert_eq!(old.wire_digest(), new.wire_digest());
            assert_eq!(old_key.wire_digest(), new_key.wire_digest());
        }
        restored.deliveries[0].1.recipient = cluster.nodes[1].share_encryption_key.fingerprint();
        assert!(restored.validate(&cluster, 100).is_err());
        restored = serde_json::from_slice(&encoded).unwrap();
        restored.deliveries[0].0 = 7;
        assert!(restored.validate(&cluster, 100).is_err());
    }

    #[test]
    fn a_missing_initialized_journal_never_becomes_an_empty_wallet() {
        let files = Files::new();
        let (config, cluster) = fixture();
        assert!(NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).is_err());
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        journal.save_intent("client-001", &intent(21)).unwrap();
        assert!(
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).is_err()
        );
        drop(journal);
        fs::remove_file(files.path()).unwrap();
        assert!(NativeCorporateJournal::open(files.path(), &[19; 32], &config, &cluster).is_err());
        assert!(!files.path().exists());
    }
}
