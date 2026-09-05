//! Corporate-only recovery journal, backed by the pinned encrypted and
//! crash-atomic CorporateOutbox. Its immutable records are protocol stages,
//! not substitute settlement receipts. No project-owned encryption core.

use crate::corporate::{CorporateNativeConfig, FacilityWitness, PreparedCorporateReserve};
use crate::edge_client::{EdgeAdmissionReceipt, PreparedEdgeDelivery};
use crate::network::ClusterPublicConfig;
use oclob_edge::SealedReservationAuthority;
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
    pub signing_key: [u8; 32],
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
}

impl NativeCorporateJournal {
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
        let outbox = CorporateOutbox::new(path, secret, 1024, RECORD_BYTES)?;
        if initialize {
            outbox.initialize()?;
        } else {
            outbox.summaries()?;
        }
        let journal = Self { outbox, context };
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
        if records
            .iter()
            .any(|r| r.request_id == format!("resolved:{id}"))
        {
            return Err("corporate request already ended after expiry".into());
        }
        let completed: BTreeSet<_> = records
            .iter()
            .filter_map(|r| {
                r.request_id
                    .strip_prefix("receipt:")
                    .or_else(|| r.request_id.strip_prefix("resolved:"))
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
    ) -> Result<Option<qomm_defmi::application_settlement::ApplicationNoteRelease>, String> {
        self.get(&record_id("expiry", id)?)
    }

    pub(crate) fn save_expiry_release(
        &self,
        id: &str,
        release: &qomm_defmi::application_settlement::ApplicationNoteRelease,
        prepared: &PreparedCorporateReserve,
        now: u64,
    ) -> Result<qomm_defmi::application_settlement::ApplicationNoteRelease, String> {
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
                || decision.reserve_digest != value.reserve_digest
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
            || ed25519_dalek::SigningKey::from_bytes(&intent.signing_key)
                .verifying_key()
                .to_bytes()
                != receipt.manifest.signer
            || command.reason
                != qomm_defmi::application_settlement::ApplicationReleaseReason::Cancelled
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
        if !matches!(stage, "reserve" | "admission" | "delivery") {
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

    pub fn claim_redemption(
        &self,
        claim: [u8; 32],
    ) -> Result<Option<qomm_defmi::claim_redemption::NoteClaimRedemption>, String> {
        self.get(&format!("redemption:{}", hex::encode(claim)))
    }

    pub fn save_claim_redemption(
        &self,
        value: &qomm_defmi::claim_redemption::NoteClaimRedemption,
    ) -> Result<qomm_defmi::claim_redemption::NoteClaimRedemption, String> {
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
            serde_json::from_slice(&bytes).map_err(|_| "corporate stage record is malformed")?;
        if record.version != 1 || record.context != self.context {
            return Err("corporate stage record belongs to another deployment".into());
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
            version: 1,
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
        )
    {
        return Err("corporate request ID or stage is invalid".into());
    }
    Ok(format!("{stage}:{id}"))
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ClusterNodePublic;
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::SigningKey;
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
            venue_id: [1; 32],
            defmi_id: [2; 32],
            issuer_public: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
            facility_id: [4; 32],
            asset_id: [5; 32],
            facility_values: [120, 0, 0],
            facility_blindings: [Scalar::from(9u64).to_bytes(), [0; 32], [0; 32]],
            wallet_spend_secret: Scalar::from(10u64).to_bytes(),
            identity_seed: [11; 32],
        };
        let cluster = ClusterPublicConfig {
            version: 3,
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
                    receipt_verifying_key: SigningKey::from_bytes(&[i as u8 + 51; 32])
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
            signing_key: [seed; 32],
            eligibility_commitment: [15; 32],
            accepted_at: 100,
            expires_at: 1000,
            reserve_send_tracking: true,
        }
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
        use qomm_defmi::claim_redemption::NoteClaimRedemption;
        use qomm_defmi::note_chain::NoteOutput;
        use qomm_defmi::notes::{NoteLedger, Wallet};
        use qomm_zk::pedersen::Pedersen;
        let files = Files::new();
        let (config, cluster) = fixture();
        let journal =
            NativeCorporateJournal::initialize(files.path(), &[19; 32], &config, &cluster).unwrap();
        let key = Pedersen::new(b"qomm:defmi:v1");
        let ledger = NoteLedger::new(key.clone(), 32);
        let wallet = Wallet::new(&mut rand::rngs::OsRng);
        let build_output = || {
            let note = ledger.build_note(
                &wallet.address,
                40,
                key.commit_u64(40, &Scalar::ONE),
                &Scalar::ONE,
                &mut rand::rngs::OsRng,
            );
            NoteOutput::from_note(&note, config.asset_id, [0; 32]).unwrap()
        };
        // This unit tests durable bytes only; VM ownership verification is
        // covered by the real-signature DeFMI tests and live acceptance.
        let original = NoteClaimRedemption {
            domain: "unit-chain".into(),
            before_root: [41; 32],
            operation_id: [42; 32],
            claim_id: [43; 32],
            output: build_output(),
            recipient_signature: vec![44; 64],
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
            &SigningKey::from_bytes(&[21; 32]),
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
        restored.deliveries[0].1.recipient = cluster.nodes[1].share_encryption_key.0;
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
