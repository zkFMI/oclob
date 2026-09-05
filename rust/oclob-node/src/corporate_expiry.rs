//! Corporate reconciliation of an expired request whose MPC admission is not
//! complete. Transport failure is never proof that a reserve was absent.

use crate::corporate::{private_client, CorporateNativeConfig, PreparedCorporateReserve};
use crate::corporate_journal::NativeCorporateJournal;
use crate::corporate_submission::{reserve_digest, SubmissionCheckpoint};
use crate::network::ClientIdentityConfig;
use ed25519_dalek::VerifyingKey;
use qomm_defmi::application_settlement::{ApplicationNoteRelease, ApplicationReleaseReason};
use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge};
use qomm_defmi::facility::QuorumAuthorizer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExpiryOutcome {
    NeverReserved {
        state_root: [u8; 32],
    },
    Released {
        release: Box<ApplicationNoteRelease>,
        transaction_id: String,
        block_id: String,
        height: u64,
        after_root: [u8; 32],
    },
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExpiryResolution {
    pub request_id: String,
    pub reserve_digest: [u8; 32],
    pub checked_at: u64,
    pub outcome: ExpiryOutcome,
}

impl NativeExpiryResolution {
    pub(crate) fn validate(&self, prepared: &PreparedCorporateReserve) -> Result<(), String> {
        if self.reserve_digest != reserve_digest(prepared)?
            || self.checked_at <= prepared.request.mandate.valid_until
            || self.request_id.is_empty()
            || self.request_id.len() > 64
        {
            return Err("expiry resolution differs from its original reserve".into());
        }
        match &self.outcome {
            ExpiryOutcome::NeverReserved { state_root } if *state_root != [0; 32] => Ok(()),
            ExpiryOutcome::Released {
                release,
                transaction_id,
                block_id,
                height,
                after_root,
            } => {
                validate_expiry_release(release, prepared, self.checked_at)?;
                if transaction_id.is_empty()
                    || transaction_id.len() > 128
                    || block_id.is_empty()
                    || block_id.len() > 128
                    || *height == 0
                    || *after_root == [0; 32]
                    || *after_root == release.before_root
                {
                    return Err("expiry receipt is incomplete".into());
                }
                Ok(())
            }
            _ => Err("expiry resolution has no canonical evidence".into()),
        }
    }
}

pub(crate) fn validate_expiry_release(
    release: &ApplicationNoteRelease,
    prepared: &PreparedCorporateReserve,
    now: u64,
) -> Result<(), String> {
    if release.reason != ApplicationReleaseReason::Expired
        || release.hold_id != prepared.request.mandate.hold_id
        || release.sequence != 0
    {
        return Err("unadmitted expiry cannot release another or already used reserve".into());
    }
    release.verify(
        &prepared.request.mandate.scope,
        prepared.request.mandate.valid_until,
        now,
    )?;
    Ok(())
}

pub fn reconcile_expired_submission(
    config: &CorporateNativeConfig,
    identity: &ClientIdentityConfig,
    journal: &NativeCorporateJournal,
    request_id: &str,
    now: u64,
    mut observe: impl FnMut(SubmissionCheckpoint) -> Result<(), String>,
) -> Result<NativeExpiryResolution, String> {
    let prepared: PreparedCorporateReserve = journal
        .stage(request_id, "reserve")?
        .ok_or("expired request has no saved signed reserve")?;
    prepared.validate(config)?;
    if now <= prepared.request.mandate.valid_until {
        return Err("canonical reserve deadline has not elapsed".into());
    }
    let client = private_client(config, identity)?.chain()?;
    let saved = journal.expiry_resolution(&prepared)?;
    let resolution = if let Some(saved) = saved {
        saved.validate(&prepared)?;
        if saved.request_id != request_id {
            return Err("expiry record belongs to another corporate request".into());
        }
        saved
    } else {
        let root = client.state_root()?;
        let facility = client.credit_facility_snapshot(config.facility_id)?;
        if facility.state_root != root || facility.facility.facility_id != config.facility_id {
            return Err("expiry facility read crossed canonical context".into());
        }
        let unchanged = facility.facility.sequence == prepared.request.before_sequence
            && [
                facility.facility.available_commitment,
                facility.facility.held_commitment,
                facility.facility.outstanding_commitment,
            ] == prepared.request.before;
        let outcome = if unchanged
            && journal.seal_never_dispatched(request_id, reserve_digest(&prepared)?, now)?
        {
            // The VM atomically increments this non-resettable sequence for
            // every reserve. The atomic corporate unsent fence is essential:
            // a local clock or old generation alone cannot exclude an in-flight
            // request. The fence prevents future sends; exact old capacity
            // confirms no funding change. Legacy/ambiguous sends do not qualify.
            if client.state_root()? != root {
                return Err("absence observation crossed canonical generations".into());
            }
            ExpiryOutcome::NeverReserved { state_root: root }
        } else {
            let head = client.application_reservation_snapshot(prepared.request.mandate.hold_id)?;
            if head.state_root != root
                || head.binding != prepared.request.mandate.binding()?
                || head.sequence > 1
            {
                return Err("expiry read does not identify the original unfilled reserve".into());
            }
            let release = if let Some(saved) = journal.expiry_release(request_id)? {
                saved
            } else {
                if head.status != "active" || head.sequence != 0 {
                    return Err("external release needs its canonical transaction receipt".into());
                }
                let release = ApplicationNoteRelease {
                    scope: prepared.request.mandate.scope.clone(),
                    before_root: root,
                    operation_id: Sha256::new()
                        .chain_update(b"OCLOB:CORPORATE-EXPIRY:v1")
                        .chain_update(reserve_digest(&prepared)?)
                        .finalize()
                        .into(),
                    hold_id: head.binding.hold_id,
                    sequence: head.sequence,
                    previous_receipt: head.head_receipt,
                    reason: ApplicationReleaseReason::Expired,
                    committee_public: Vec::new(),
                    signature: Vec::new(),
                };
                journal.save_expiry_release(request_id, &release, &prepared, now)?
            };
            validate_expiry_release(&release, &prepared, now)?;
            let reader = QuorumAuthorizer::new(
                BTreeMap::from([(
                    "read-only".into(),
                    VerifyingKey::from_bytes(&config.issuer_public).map_err(|e| e.to_string())?,
                )]),
                1,
                1,
                "read-only",
            )?;
            let bridge = AvalancheNoteBridge::new(&reader, &client);
            let accepted = bridge.release_application(&release)?;
            let after = client.application_reservation_snapshot(release.hold_id)?;
            if after.status != "released"
                || after.sequence != 1
                || after.binding != prepared.request.mandate.binding()?
                || after.head_receipt != accepted.statement
                || after.remaining_commitment != prepared.request.mandate.amount_commitment
            {
                return Err("expiry did not terminate the exact original reserve".into());
            }
            ExpiryOutcome::Released {
                release: Box::new(release),
                transaction_id: accepted.tx_id,
                block_id: accepted.block_id,
                height: accepted.height,
                after_root: accepted.after_root,
            }
        };
        let resolution = NativeExpiryResolution {
            request_id: request_id.into(),
            reserve_digest: reserve_digest(&prepared)?,
            checked_at: now,
            outcome,
        };
        resolution.validate(&prepared)?;
        observe(SubmissionCheckpoint::ExpiryObservedBeforeJournal)?;
        journal.save_expiry_resolution(&resolution, &prepared)?
    };
    // No terminal queue acknowledgement until real notes/facility openings are
    // read and recovered. A crash here resumes from the saved canonical result.
    crate::native_wallet::recover_wallet(config, identity, journal)?;
    journal.complete_expiry(&resolution, &prepared)?;
    Ok(resolution)
}
