//! Corporate-only background dispatch using the existing encrypted outbox.
//! Admission acknowledgements are not settlement receipts. The journal remains
//! the source of exact signed reserve/proof/encrypted-delivery bytes.

use crate::corporate::{CorporateNativeConfig, PreparedCorporateReserve};
use crate::corporate_journal::NativeCorporateJournal;
use crate::corporate_submission::{
    complete_native_submission, reserve_digest, SubmissionCheckpoint,
};
use crate::network::{
    client_tls_context, ClientIdentityConfig, ClusterPublicConfig, NodeRpcClient,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zkpi_defmi_sdk::corporate::{
    CorporateOutbox, MpcAdmissionReceipt, OutboxEntrySummary, QueueAction,
};

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DispatchRequest {
    version: u16,
    journal_context: [u8; 32],
    request_id: String,
    intent_digest: [u8; 32],
    reserve_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_digest: Option<[u8; 32]>,
    source_note: Option<[u8; 32]>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DispatchProgress {
    Idle,
    WaitingForNodes,
    RetryScheduled {
        request_id: String,
        attempt: u32,
    },
    Admitted {
        request_id: String,
        receipt_digest: String,
    },
    ReleaseReconciliationRequired {
        request_id: String,
    },
    ManualReviewRequired {
        request_id: String,
    },
    ReservationReleased {
        request_id: String,
        transaction_id: String,
    },
    NeverReserved {
        request_id: String,
    },
    FundingRejected {
        request_id: String,
    },
}

pub struct NativeCorporateDispatch {
    outbox: CorporateOutbox,
    path: PathBuf,
}

impl NativeCorporateDispatch {
    pub fn initialize(path: impl Into<PathBuf>, secret: &[u8; 32]) -> Result<Self, String> {
        let result = Self::create(path.into(), secret)?;
        result.outbox.initialize()?;
        Ok(result)
    }

    pub fn open(path: impl Into<PathBuf>, secret: &[u8; 32]) -> Result<Self, String> {
        let result = Self::create(path.into(), secret)?;
        result.outbox.summaries()?;
        Ok(result)
    }

    fn create(path: PathBuf, secret: &[u8; 32]) -> Result<Self, String> {
        if *secret == [0; 32] {
            return Err("dispatch encryption key is empty".into());
        }
        // Separate the queue's encryption role from the native journal even
        // when both are provisioned from the same corporate master secret.
        // CorporateOutbox still owns the KDF and authenticated encryption.
        let dispatch_secret = Sha256::new()
            .chain_update(b"OCLOB:NATIVE-DISPATCH-KEY:v1")
            .chain_update(secret)
            .finalize();
        Ok(Self {
            outbox: CorporateOutbox::new(&path, &dispatch_secret, 1024, 4096)?,
            path,
        })
    }

    /// Hold for the worker's lifetime. Use the standard OS-backed Rust file
    /// lock, not a PID file or a time lease that can expire during a live RPC.
    /// Source: https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock
    pub fn acquire_worker(&self) -> Result<File, String> {
        acquire_corporate_lock(&self.path.with_extension("worker.lock"), false)
    }

    pub fn enqueue(
        &self,
        journal: &NativeCorporateJournal,
        config: &CorporateNativeConfig,
        request_id: &str,
        source_note: Option<[u8; 32]>,
    ) -> Result<bool, String> {
        let intent = journal
            .intent(request_id)?
            .ok_or("queued request has no saved intent")?;
        let reserve: PreparedCorporateReserve = journal
            .stage(request_id, "reserve")?
            .ok_or("queued request has no saved signed reserve")?;
        reserve.validate(config)?;
        if reserve.order_wire != intent.order_wire || reserve.signing_key != intent.signing_key {
            return Err("queued reserve differs from the original intent".into());
        }
        let request = DispatchRequest {
            version: 1,
            journal_context: journal.context_digest(),
            request_id: request_id.into(),
            intent_digest: intent.input_digest,
            reserve_digest: reserve_digest(&reserve)?,
            authorization_digest: None,
            source_note,
        };
        self.enqueue_request(&request, &intent)
    }

    pub fn enqueue_authorized(
        &self,
        journal: &NativeCorporateJournal,
        config: &CorporateNativeConfig,
        request_id: &str,
        source_note: Option<[u8; 32]>,
    ) -> Result<bool, String> {
        let intent = journal
            .intent(request_id)?
            .ok_or("authorized queue request has no intent")?;
        let authorization = journal
            .authorization(request_id)?
            .ok_or("authorized queue request has no signed terms")?;
        authorization.validate(config)?;
        if authorization.order_wire != intent.order_wire
            || authorization.signing_key != intent.signing_key
        {
            return Err("authorized queue request differs from corporate intake".into());
        }
        self.enqueue_request(
            &DispatchRequest {
                version: 2,
                journal_context: journal.context_digest(),
                request_id: request_id.into(),
                intent_digest: intent.input_digest,
                reserve_digest: [0; 32],
                authorization_digest: Some(authorization.digest()?),
                source_note,
            },
            &intent,
        )
    }

    fn enqueue_request(
        &self,
        request: &DispatchRequest,
        intent: &crate::corporate_journal::StoredCorporateIntent,
    ) -> Result<bool, String> {
        let request_id = &request.request_id;
        let bytes = serde_json::to_vec(&request).map_err(err)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let outcome = self.outbox.enqueue_first_seen(
            request_id,
            &bytes,
            intent.accepted_at,
            intent.expires_at,
        )?;
        let saved = self.outbox.signed_request(request_id, digest)?;
        if saved != bytes {
            return Err("dispatch request ID was reused with different contents".into());
        }
        Ok(matches!(
            outcome,
            zkpi_defmi_sdk::corporate::EnqueueOutcome::AlreadyPresent { .. }
        ))
    }

    pub fn summaries(&self) -> Result<Vec<OutboxEntrySummary>, String> {
        self.outbox.summaries()
    }

    fn no_claim_progress(&self, healthy: bool) -> Result<DispatchProgress, String> {
        if let Some(entry) = self.outbox.summaries()?.into_iter().find(|entry| {
            matches!(
                entry.state,
                zkpi_defmi_sdk::corporate::OutboxState::ManualReview { .. }
            )
        }) {
            return Ok(DispatchProgress::ManualReviewRequired {
                request_id: entry.request_id,
            });
        }
        Ok(if healthy {
            DispatchProgress::Idle
        } else {
            DispatchProgress::WaitingForNodes
        })
    }

    fn verified_request(
        &self,
        journal: &NativeCorporateJournal,
        request_id: &str,
        request_digest: [u8; 32],
    ) -> Result<DispatchRequest, String> {
        let bytes = self.outbox.signed_request(request_id, request_digest)?;
        let request: DispatchRequest =
            serde_json::from_slice(&bytes).map_err(|_| "malformed encrypted dispatch payload")?;
        let intent = journal
            .intent(request_id)?
            .ok_or("dispatch intent disappeared")?;
        let source_matches = match (request.version, request.authorization_digest) {
            (1, None) => journal
                .stage::<PreparedCorporateReserve>(request_id, "reserve")?
                .map(|prepared| reserve_digest(&prepared).map(|d| d == request.reserve_digest))
                .transpose()?
                .unwrap_or(false),
            (2, Some(digest)) if request.reserve_digest == [0; 32] => journal
                .authorization(request_id)?
                .map(|authorization| authorization.digest().map(|d| d == digest))
                .transpose()?
                .unwrap_or(false),
            _ => false,
        };
        if !source_matches
            || request.journal_context != journal.context_digest()
            || request.request_id != request_id
            || request.intent_digest != intent.input_digest
        {
            return Err("dispatch payload does not match its corporate journal".into());
        }
        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_expiry(
        &self,
        config: &CorporateNativeConfig,
        identity: &ClientIdentityConfig,
        journal: &NativeCorporateJournal,
        request_id: String,
        request_digest: [u8; 32],
        now: u64,
        observe: impl FnMut(SubmissionCheckpoint) -> Result<(), String>,
    ) -> Result<DispatchProgress, String> {
        let request = self.verified_request(journal, &request_id, request_digest)?;
        self.outbox
            .mark_release_pending(&request_id, request_digest, now)?;
        if request.version == 2
            && journal
                .stage::<PreparedCorporateReserve>(&request_id, "reserve")?
                .is_none()
        {
            match journal.end_unprepared_authorization(
                &request_id,
                now,
                crate::corporate_journal::AuthorizationEndReason::Expired,
            ) {
                Ok(ended) => return self.record_authorization_end(request_digest, ended),
                Err(_) => {
                    return Ok(DispatchProgress::ReleaseReconciliationRequired { request_id })
                }
            }
        }
        let result = match crate::corporate_expiry::reconcile_expired_submission(
            config,
            identity,
            journal,
            &request_id,
            now,
            observe,
        ) {
            Ok(result) => result,
            Err(_) => return Ok(DispatchProgress::ReleaseReconciliationRequired { request_id }),
        };
        match result.outcome {
            crate::corporate_expiry::ExpiryOutcome::NeverReserved { .. } => {
                self.outbox.record_pre_reserve_abort(
                    &request_id,
                    request_digest,
                    result.checked_at,
                )?;
                Ok(DispatchProgress::NeverReserved { request_id })
            }
            crate::corporate_expiry::ExpiryOutcome::Released {
                transaction_id,
                height,
                ..
            } => {
                self.outbox.record_release(
                    &request_id,
                    request_digest,
                    zkpi_defmi_sdk::corporate::CanonicalReceipt {
                        defmi_network_id: hex::encode(config.defmi_id),
                        transaction_id: transaction_id.clone(),
                        ledger_height: height,
                        request_digest,
                        finalized_at: result.checked_at,
                    },
                )?;
                Ok(DispatchProgress::ReservationReleased {
                    request_id,
                    transaction_id,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn pump(
        &self,
        config: &CorporateNativeConfig,
        identity: &ClientIdentityConfig,
        cluster: &ClusterPublicConfig,
        journal: &NativeCorporateJournal,
        now: u64,
        retry_after_seconds: u64,
        mut observe: impl FnMut(SubmissionCheckpoint) -> Result<(), String>,
    ) -> Result<DispatchProgress, String> {
        if !(1..=300).contains(&retry_after_seconds) {
            return Err("dispatch retry interval outside1..300 seconds".into());
        }
        // Crash after the durable pre-funding end but before updating the queue.
        // No network is needed to finish this already fenced local transition.
        for entry in self.outbox.summaries()? {
            if matches!(
                entry.state,
                zkpi_defmi_sdk::corporate::OutboxState::AbortedBeforeReserve { .. }
            ) {
                continue;
            }
            if let Some(ended) = journal.ended_authorization(&entry.request_id)? {
                self.verified_request(journal, &entry.request_id, entry.request_digest)?;
                return self.record_authorization_end(entry.request_digest, ended);
            }
        }
        // Expiry reconciliation must not wait for any MPC node or even start
        // its health connections: canonical funds can be recovered while all
        // MPC endpoints are unreachable.
        if let Some(QueueAction::Expire {
            request_id,
            request_digest,
        }) = self.outbox.claim_next(now, false, retry_after_seconds)?
        {
            return self.reconcile_expiry(
                config,
                identity,
                journal,
                request_id,
                request_digest,
                now,
                &mut observe,
            );
        }
        let tls = client_tls_context(
            &identity.tls_certificate,
            &identity.tls_private_key,
            &identity.tls_ca,
        )
        .map_err(err)?;
        let healthy = std::thread::scope(|scope| {
            let jobs: Vec<_> = cluster
                .nodes
                .iter()
                .map(|node| {
                    let tls = tls.clone();
                    scope.spawn(move || {
                        NodeRpcClient::new(node.endpoint(), tls, Duration::from_secs(3))
                            .and_then(|client| client.health())
                            .is_ok()
                    })
                })
                .collect();
            jobs.into_iter().all(|job| job.join().unwrap_or(false))
        });
        let action = self.outbox.claim_next(now, healthy, retry_after_seconds)?;
        let Some(action) = action else {
            return self.no_claim_progress(healthy);
        };
        let claimed = match action {
            QueueAction::Expire {
                request_id,
                request_digest,
            } => {
                return self.reconcile_expiry(
                    config,
                    identity,
                    journal,
                    request_id,
                    request_digest,
                    now,
                    &mut observe,
                );
            }
            QueueAction::Dispatch(claimed) => claimed,
        };
        let request =
            self.verified_request(journal, &claimed.request_id, claimed.request_digest)?;
        if request.version == 2
            && journal
                .stage::<PreparedCorporateReserve>(&claimed.request_id, "reserve")?
                .is_none()
        {
            let preparation = (|| {
                journal.require_turn(&claimed.request_id)?;
                let authorization = journal
                    .authorization(&claimed.request_id)?
                    .ok_or_else(|| "queued authorization disappeared".to_string())?;
                let intent = journal
                    .intent(&claimed.request_id)?
                    .ok_or_else(|| "queued intent disappeared".to_string())?;
                let funding = journal.latest_funding(config)?;
                let prepared = crate::corporate_authorization::prepare_authorized_reservation(
                    &funding,
                    identity,
                    &authorization,
                    now,
                    request.source_note,
                )?;
                journal.save_stage::<PreparedCorporateReserve>(
                    &claimed.request_id,
                    "reserve",
                    &prepared,
                    &intent,
                )?;
                Ok::<_, crate::corporate_authorization::PreparationError>(())
            })();
            match preparation {
                Ok(()) => (),
                Err(crate::corporate_authorization::PreparationError::InsufficientFunding) => {
                    let ended = journal.end_unprepared_authorization(
                        &claimed.request_id,
                        now,
                        crate::corporate_journal::AuthorizationEndReason::InsufficientFunding,
                    )?;
                    return self.record_authorization_end(claimed.request_digest, ended);
                }
                Err(crate::corporate_authorization::PreparationError::Retry(_)) => {
                    // Recover only from real canonical heads and local witness
                    // history. A missing/changed head remains an explicit retry.
                    if let Ok(witness) = crate::native_wallet::recover_facility(
                        config,
                        &crate::corporate::private_client(config, identity)?.chain()?,
                        journal,
                    ) {
                        journal.save_funding_witness(&witness)?;
                    }
                    return Ok(DispatchProgress::RetryScheduled {
                        request_id: claimed.request_id,
                        attempt: claimed.attempt,
                    });
                }
            }
        }
        let completed = match complete_native_submission(
            config,
            identity,
            cluster,
            journal,
            &claimed.request_id,
            request.source_note,
            &mut observe,
        ) {
            Ok(completed) => completed,
            Err(_) => {
                return Ok(DispatchProgress::RetryScheduled {
                    request_id: claimed.request_id,
                    attempt: claimed.attempt,
                })
            }
        };
        self.outbox.record_mpc_admission(
            &claimed.request_id,
            claimed.request_digest,
            now,
            MpcAdmissionReceipt {
                committee_id: format!("oclob:{}", cluster.market_id),
                job_id: completed.receipt.commitment().hex(),
                admitted_request_digest: claimed.request_digest,
            },
        )?;
        Ok(DispatchProgress::Admitted {
            request_id: claimed.request_id,
            receipt_digest: hex::encode(completed.receipt.receipt_digest),
        })
    }

    fn record_authorization_end(
        &self,
        digest: [u8; 32],
        ended: crate::corporate_journal::EndedCorporateAuthorization,
    ) -> Result<DispatchProgress, String> {
        self.outbox
            .record_pre_reserve_abort(&ended.request_id, digest, ended.ended_at)?;
        Ok(match ended.reason {
            crate::corporate_journal::AuthorizationEndReason::Expired => {
                DispatchProgress::NeverReserved {
                    request_id: ended.request_id,
                }
            }
            crate::corporate_journal::AuthorizationEndReason::InsufficientFunding => {
                DispatchProgress::FundingRejected {
                    request_id: ended.request_id,
                }
            }
        })
    }
}

pub(crate) fn acquire_corporate_lock(path: &Path, wait: bool) -> Result<File, String> {
    let parent = path.parent().ok_or("corporate lock path has no parent")?;
    let meta = fs::symlink_metadata(parent).map_err(err)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err("corporate lock parent must be an owner-only directory".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(err)?;
    let lock_meta = file.metadata().map_err(err)?;
    if !lock_meta.is_file()
        || lock_meta.nlink() != 1
        || lock_meta.uid() != meta.uid()
        || lock_meta.permissions().mode() & 0o077 != 0
    {
        return Err("corporate lock file is unsafe".into());
    }
    let started = std::time::Instant::now();
    loop {
        if file.try_lock().is_ok() {
            return Ok(file);
        }
        if !wait || started.elapsed() >= Duration::from_secs(30) {
            return Err("corporate lock unavailable; another writer may own it".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn dispatch_restart_never_reinitializes_missing_or_wrong_key_history() {
        let root =
            std::env::temp_dir().join(format!("oclob-dispatch-{:016x}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("dispatch.enc");
        assert!(NativeCorporateDispatch::open(&path, &[7; 32]).is_err());
        let queue = NativeCorporateDispatch::initialize(&path, &[7; 32]).unwrap();
        assert!(queue.summaries().unwrap().is_empty());
        assert!(NativeCorporateDispatch::open(&path, &[8; 32]).is_err());
        let guard = queue.acquire_worker().unwrap();
        assert!(queue.acquire_worker().is_err());
        drop(guard);
        assert!(queue.acquire_worker().is_ok());
        let lock = path.with_extension("worker.lock");
        fs::remove_file(&lock).unwrap();
        symlink(&path, &lock).unwrap();
        assert!(queue.acquire_worker().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dispatch_and_journal_encryption_roles_cannot_be_swapped() {
        let root = std::env::temp_dir().join(format!(
            "oclob-dispatch-role-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("dispatch.enc");
        NativeCorporateDispatch::initialize(&path, &[7; 32]).unwrap();
        assert!(CorporateOutbox::new(&path, &[7; 32], 1024, 4096)
            .unwrap()
            .summaries()
            .is_err());
        let journal = root.join("outbox.enc");
        CorporateOutbox::new(&journal, &[7; 32], 1024, 4096)
            .unwrap()
            .initialize()
            .unwrap();
        assert!(NativeCorporateDispatch::open(&journal, &[7; 32]).is_err());
        assert!(NativeCorporateDispatch::open(&path, &[7; 32]).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retry_exhaustion_is_reported_as_manual_review_not_idle() {
        let root = std::env::temp_dir().join(format!(
            "oclob-dispatch-review-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let queue =
            NativeCorporateDispatch::initialize(root.join("dispatch.enc"), &[7; 32]).unwrap();
        queue
            .outbox
            .enqueue_first_seen("retry-test", b"unit-test-only", 1, 100_000)
            .unwrap();
        for attempt in 1..=10 {
            let action = queue.outbox.claim_next(attempt * 1_000, true, 2).unwrap();
            assert!(
                matches!(action, Some(QueueAction::Dispatch(ref request)) if u64::from(request.attempt) == attempt)
            );
        }
        assert!(queue.outbox.claim_next(11_000, true, 2).unwrap().is_none());
        let expected = DispatchProgress::ManualReviewRequired {
            request_id: "retry-test".into(),
        };
        assert_eq!(queue.no_claim_progress(true).unwrap(), expected);
        assert_eq!(queue.no_claim_progress(false).unwrap(), expected);
        fs::remove_dir_all(root).unwrap();
    }
}
