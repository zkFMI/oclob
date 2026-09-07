//! One fail-closed application seam from confidential order admission to
//! canonical settlement.  No cleartext matcher or local-settlement fallback is
//! present: unavailable MPC or proof services leave the order unexecuted.

#![forbid(unsafe_code)]

use oclob_core::{
    expiry_commitment, BookTransition, CancellationTransition, Digest32, ExpiryTransition,
    OrderAuthority, PrivateBook, PublicBookSnapshot, SecretCancellation, SecretOrder,
};
use oclob_dekyx::{AnonymousPresentation, OclobEligibilityVerifier, VerifiedOrderEligibility};
use oclob_mpc::{MpcBatchReceipt, MpcRunner};
use oclob_ordering::{OrderCertificate, OrderingCommittee};
use oclob_proofs::{
    CancellationProof, CancellationStatement, ExpiryProof, ExpiryStatement, TransitionProof,
    TransitionStatement, VerifiedTransitionProof,
};
use oclob_settlement::{
    AppliedCanonicalTransition, CanonicalAdmissionBatch, CanonicalSettlementAcceptance,
    OclobSettlementReceipt, ParticipantPortfolio, PreparedCanonicalTransition,
    ReservationBatchReleaseReceipt, ReservationReceipt, ReservationReleaseReceipt,
    SettlementEngine, SettlementStateSnapshot,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zkpi_defmi_sdk::corporate::{
    CanonicalReceipt, CorporateOutbox, CoverAction, EnqueueOutcome, OutboxEntrySummary,
    OutboxMetrics, QueueAction,
};

const QUEUED_SUBMISSION_VERSION: u16 = 1;
const DEFAULT_MAX_QUEUED_SUBMISSION_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OclobExecutionReceipt {
    pub expired_before: Option<OclobExpiryReceipt>,
    pub certificate: OrderCertificate,
    pub reservation: ReservationReceipt,
    pub eligibility: VerifiedOrderEligibility,
    pub mpc: MpcBatchReceipt,
    pub book_transition: BookTransition,
    pub transition_proof: TransitionProof,
    pub settlement: Option<OclobSettlementReceipt>,
    pub reservation_release: Option<ReservationReleaseReceipt>,
}

/// One complete private match whose public book and local settlement state
/// have not yet changed. The object cannot be serialized or cloned: it carries
/// the staged private book and can be consumed only after the exact DeFMI
/// transition reaches canonical finality.
pub struct PreparedOclobSubmission {
    base_book_root: Digest32,
    base_settlement: SettlementStateSnapshot,
    staged_book: PrivateBook,
    staged_ordering: OrderingCommittee,
    staged_settlement: SettlementEngine,
    staged_eligibility: OclobEligibilityVerifier,
    certificate: OrderCertificate,
    reservation: ReservationReceipt,
    eligibility: VerifiedOrderEligibility,
    mpc: MpcBatchReceipt,
    book_transition: BookTransition,
    transition_proof: TransitionProof,
    canonical: PreparedCanonicalTransition,
}

impl PreparedOclobSubmission {
    pub fn certificate(&self) -> &OrderCertificate {
        &self.certificate
    }

    pub fn mpc(&self) -> &MpcBatchReceipt {
        &self.mpc
    }

    pub fn book_transition(&self) -> &BookTransition {
        &self.book_transition
    }

    pub fn transition_proof(&self) -> &TransitionProof {
        &self.transition_proof
    }

    pub fn canonical_transition(&self) -> &PreparedCanonicalTransition {
        &self.canonical
    }

    /// Commit the private book, ordering log, DeKYX replay ledger and local
    /// confidential balances only after canonical DeFMI finality for the exact
    /// prepared zkPI/DvP batch has been verified.
    pub fn accept(
        self,
        service: &mut OclobService,
        acceptance: CanonicalSettlementAcceptance,
    ) -> Result<OclobExecutionReceipt, ServiceError> {
        if service.book.public_snapshot().state_root != self.base_book_root
            || service.settlement.state_snapshot() != self.base_settlement
        {
            return Err(ServiceError::Settlement(
                "prepared OCLOB execution is stale against current service state".into(),
            ));
        }
        let Self {
            staged_book,
            staged_ordering,
            mut staged_settlement,
            staged_eligibility,
            certificate,
            reservation,
            eligibility,
            mpc,
            book_transition,
            transition_proof,
            canonical,
            ..
        } = self;
        let applied = canonical
            .accept(&mut staged_settlement, acceptance)
            .map_err(|error| ServiceError::Settlement(error.to_string()))?;
        let (reservation, settlement) = match applied {
            AppliedCanonicalTransition::Reservation(reservation) => (reservation, None),
            AppliedCanonicalTransition::Settlement(settlement) => {
                let mut accepted_reservation = reservation;
                accepted_reservation.state_root = settlement.reservation_after_root;
                accepted_reservation.canonical_receipt_digest = settlement.canonical_receipt_digest;
                accepted_reservation.canonical_height = settlement.canonical_height;
                accepted_reservation.zkpi_digest = settlement.arriving_reservation_zkpi_digest;
                accepted_reservation.instruction_nullifier =
                    settlement.arriving_reservation_instruction_nullifier;
                accepted_reservation.proof_digest = settlement.arriving_reservation_proof_digest;
                accepted_reservation.avalanche_transaction_id =
                    settlement.avalanche_transaction_id.clone();
                accepted_reservation.avalanche_block_id = settlement.avalanche_block_id.clone();
                (accepted_reservation, Some(settlement))
            }
        };
        service.book = staged_book;
        service.ordering = staged_ordering;
        service.settlement = staged_settlement;
        service.eligibility = staged_eligibility;
        Ok(OclobExecutionReceipt {
            expired_before: None,
            certificate,
            reservation,
            eligibility,
            mpc,
            book_transition,
            transition_proof,
            settlement,
            reservation_release: None,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OclobExpiryReceipt {
    pub certificate: OrderCertificate,
    pub transition: ExpiryTransition,
    pub proof: ExpiryProof,
    pub reservation_release: ReservationBatchReleaseReceipt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OclobCancellationReceipt {
    pub certificate: OrderCertificate,
    pub transition: CancellationTransition,
    pub proof: CancellationProof,
    pub reservation_release: ReservationReleaseReceipt,
}

/// Public acknowledgement of one private, encrypted queue entry. No order
/// direction, price, quantity, participant or credential appears here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueuedSubmissionReceipt {
    pub request_id: String,
    pub request_digest: Digest32,
    pub sequence: u64,
    pub expires_at: u64,
    pub already_present: bool,
}

/// Result of one queue worker tick. A worker never bypasses MPC when the
/// committee is unavailable and never allows a later request to overtake the
/// oldest eligible entry.
#[derive(Clone, Debug)]
pub enum QueueWorkerResult {
    Idle,
    WaitingForMpc,
    DummyCover {
        slot: u64,
        due_at: u64,
    },
    Expired {
        request_id: String,
    },
    Executed {
        request_id: String,
        receipt: Box<OclobExecutionReceipt>,
    },
    RetryableFailure {
        request_id: String,
        reason: String,
    },
    Rejected {
        request_id: String,
        reason: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QueuedSubmissionEnvelope {
    version: u16,
    order_wire: Vec<u8>,
    authority: OrderAuthority,
    eligibility: AnonymousPresentation,
}

impl QueuedSubmissionEnvelope {
    fn encode(
        order: &SecretOrder,
        authority: &OrderAuthority,
        eligibility: &AnonymousPresentation,
    ) -> Result<Vec<u8>, ServiceError> {
        let envelope = Self {
            version: QUEUED_SUBMISSION_VERSION,
            order_wire: order.to_secret_wire(),
            authority: authority.clone(),
            eligibility: eligibility.clone(),
        };
        serde_json::to_vec(&envelope).map_err(|error| ServiceError::Queue(error.to_string()))
    }

    fn decode(
        bytes: &[u8],
    ) -> Result<(SecretOrder, OrderAuthority, AnonymousPresentation), String> {
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|_| "queued submission envelope is malformed".to_string())?;
        if envelope.version != QUEUED_SUBMISSION_VERSION {
            return Err("queued submission version is unsupported".into());
        }
        let order = SecretOrder::from_secret_wire(&envelope.order_wire)
            .map_err(|error| error.to_string())?;
        if envelope.authority.commitment != order.commitment() {
            return Err("queued authority belongs to another order".into());
        }
        Ok((order, envelope.authority, envelope.eligibility))
    }
}

/// Crash-atomic, encrypted participant-side queue. It stores exact signed
/// request bytes, not a lossy reconstruction, and hands them only to the one
/// OCLOB coordinator path after quorum health is restored.
pub struct DurableOclobQueue {
    outbox: CorporateOutbox,
    defmi_network_id: String,
    retry_after_seconds: u64,
}

impl DurableOclobQueue {
    pub fn open(
        path: impl Into<PathBuf>,
        passphrase: &[u8],
        defmi_network_id: impl Into<String>,
        max_entries: usize,
        retry_after_seconds: u64,
    ) -> Result<Self, ServiceError> {
        let defmi_network_id = defmi_network_id.into();
        if defmi_network_id.is_empty() || retry_after_seconds == 0 {
            return Err(ServiceError::Queue(
                "DeFMI network id and retry interval are required".into(),
            ));
        }
        let outbox = CorporateOutbox::new(
            path,
            passphrase,
            max_entries,
            DEFAULT_MAX_QUEUED_SUBMISSION_BYTES,
        )
        .map_err(ServiceError::Queue)?;
        outbox
            .initialize_if_missing()
            .map_err(ServiceError::Queue)?;
        Ok(Self {
            outbox,
            defmi_network_id,
            retry_after_seconds,
        })
    }

    pub fn enqueue(
        &self,
        order: &SecretOrder,
        authority: &OrderAuthority,
        eligibility: &AnonymousPresentation,
        accepted_at: u64,
    ) -> Result<QueuedSubmissionReceipt, ServiceError> {
        authority
            .verify(order, accepted_at)
            .map_err(|error| ServiceError::Order(error.to_string()))?;
        let request_id = order.commitment().hex();
        let signed_request = QueuedSubmissionEnvelope::encode(order, authority, eligibility)?;
        // The shared outbox binds this digest to the exact encrypted payload;
        // OCLOB's application domain is carried by the strict envelope version.
        let request_digest: Digest32 = Sha256::digest(&signed_request).into();
        let outcome = self
            .outbox
            .enqueue_first_seen(
                &request_id,
                &signed_request,
                accepted_at,
                order.expires_at(),
            )
            .map_err(ServiceError::Queue)?;
        let (sequence, already_present) = match outcome {
            EnqueueOutcome::Enqueued { sequence } => (sequence, false),
            EnqueueOutcome::AlreadyPresent { sequence } => (sequence, true),
        };
        Ok(QueuedSubmissionReceipt {
            request_id,
            request_digest,
            sequence,
            expires_at: order.expires_at(),
            already_present,
        })
    }

    pub fn pump(
        &self,
        service: &mut OclobService,
        now: u64,
        mpc_quorum_healthy: bool,
    ) -> Result<QueueWorkerResult, ServiceError> {
        let action = self
            .outbox
            .claim_next(now, mpc_quorum_healthy, self.retry_after_seconds)
            .map_err(ServiceError::Queue)?;
        match action {
            None if mpc_quorum_healthy => Ok(QueueWorkerResult::Idle),
            None => Ok(QueueWorkerResult::WaitingForMpc),
            Some(QueueAction::Expire {
                request_id,
                request_digest,
            }) => {
                self.outbox
                    .record_pre_reserve_abort(&request_id, request_digest, now)
                    .map_err(ServiceError::Queue)?;
                Ok(QueueWorkerResult::Expired { request_id })
            }
            Some(QueueAction::Dispatch(claimed)) => self.dispatch_claimed(
                service,
                claimed.request_id,
                claimed.request_digest,
                &claimed.signed_request,
                now,
            ),
        }
    }

    pub fn pump_cover_slot(
        &self,
        service: &mut OclobService,
        now: u64,
        mpc_quorum_healthy: bool,
        interval_seconds: u64,
    ) -> Result<QueueWorkerResult, ServiceError> {
        let slot = self
            .outbox
            .claim_cover_slot(
                now,
                mpc_quorum_healthy,
                self.retry_after_seconds,
                interval_seconds,
            )
            .map_err(ServiceError::Queue)?;
        let Some(slot) = slot else {
            return Ok(if mpc_quorum_healthy {
                QueueWorkerResult::Idle
            } else {
                QueueWorkerResult::WaitingForMpc
            });
        };
        match slot.action {
            CoverAction::Dummy => Ok(QueueWorkerResult::DummyCover {
                slot: slot.slot,
                due_at: slot.due_at,
            }),
            CoverAction::Expire {
                request_id,
                request_digest,
            } => {
                self.outbox
                    .record_pre_reserve_abort(&request_id, request_digest, now)
                    .map_err(ServiceError::Queue)?;
                Ok(QueueWorkerResult::Expired { request_id })
            }
            CoverAction::Real(claimed) => self.dispatch_claimed(
                service,
                claimed.request_id,
                claimed.request_digest,
                &claimed.signed_request,
                now,
            ),
        }
    }

    pub fn summaries(&self) -> Result<Vec<OutboxEntrySummary>, ServiceError> {
        self.outbox.summaries().map_err(ServiceError::Queue)
    }

    pub fn metrics(&self, now: u64) -> Result<OutboxMetrics, ServiceError> {
        self.outbox.metrics(now).map_err(ServiceError::Queue)
    }

    fn dispatch_claimed(
        &self,
        service: &mut OclobService,
        request_id: String,
        request_digest: Digest32,
        signed_request: &[u8],
        now: u64,
    ) -> Result<QueueWorkerResult, ServiceError> {
        let (order, authority, eligibility) = match QueuedSubmissionEnvelope::decode(signed_request)
        {
            Ok(decoded) => decoded,
            Err(reason) => {
                self.outbox
                    .mark_manual_review(&request_id, request_digest, now, &reason)
                    .map_err(ServiceError::Queue)?;
                return Ok(QueueWorkerResult::Rejected { request_id, reason });
            }
        };
        match service.submit(order, authority, eligibility, now) {
            Ok(receipt) => {
                let (transaction_digest, height) = canonical_result(&receipt);
                self.outbox
                    .record_settlement(
                        &request_id,
                        request_digest,
                        CanonicalReceipt {
                            defmi_network_id: self.defmi_network_id.clone(),
                            transaction_id: hex::encode(transaction_digest),
                            ledger_height: height,
                            request_digest,
                            finalized_at: now,
                        },
                    )
                    .map_err(ServiceError::Queue)?;
                Ok(QueueWorkerResult::Executed {
                    request_id,
                    receipt: Box::new(receipt),
                })
            }
            Err(error) if error.retryable() => Ok(QueueWorkerResult::RetryableFailure {
                request_id,
                reason: error.to_string(),
            }),
            Err(error) => {
                let reason = error.to_string();
                self.outbox
                    .record_pre_reserve_abort(&request_id, request_digest, now)
                    .map_err(ServiceError::Queue)?;
                Ok(QueueWorkerResult::Rejected { request_id, reason })
            }
        }
    }
}

struct StagedSubmission {
    settlement_order: SecretOrder,
    staged_book: PrivateBook,
    staged_ordering: OrderingCommittee,
    staged_settlement: SettlementEngine,
    staged_eligibility: OclobEligibilityVerifier,
    certificate: OrderCertificate,
    reservation: ReservationReceipt,
    eligibility: VerifiedOrderEligibility,
    mpc: MpcBatchReceipt,
    book_transition: BookTransition,
    transition_proof: TransitionProof,
    verified_transition: VerifiedTransitionProof,
}

pub struct OclobService {
    market_id: String,
    book: PrivateBook,
    ordering: OrderingCommittee,
    mpc: MpcRunner,
    settlement: SettlementEngine,
    eligibility: OclobEligibilityVerifier,
    demo_handles: (Digest32, Digest32),
}

impl OclobService {
    pub fn new(
        market_id: impl Into<String>,
        mp_spdz_root: impl AsRef<Path>,
        eligibility: OclobEligibilityVerifier,
    ) -> Result<Self, ServiceError> {
        let market_id = market_id.into();
        let mut rng = OsRng;
        let settlement = SettlementEngine::new(&mut rng)
            .map_err(|error| ServiceError::Settlement(error.to_string()))?;
        let demo_handles = settlement.demo_participant_handles();
        Ok(Self {
            book: PrivateBook::new(market_id.clone())
                .map_err(|error| ServiceError::Order(error.to_string()))?,
            ordering: OrderingCommittee::deterministic_for_demo()
                .map_err(|error| ServiceError::Ordering(error.to_string()))?,
            mpc: MpcRunner::compile(mp_spdz_root)
                .map_err(|error| ServiceError::Mpc(error.to_string()))?,
            settlement,
            eligibility,
            demo_handles,
            market_id,
        })
    }

    pub const fn demo_participant_handles(&self) -> (Digest32, Digest32) {
        self.demo_handles
    }

    pub fn public_book(&self) -> PublicBookSnapshot {
        self.book.public_snapshot()
    }

    pub fn settlement_state(&self) -> SettlementStateSnapshot {
        self.settlement.state_snapshot()
    }

    /// Re-verify a wire-safe transition receipt against this service's frozen
    /// ordering committee before another component can use it as settlement
    /// authority. `VerifiedTransitionProof` cannot be deserialized, so this is
    /// the only hand-off from a public receipt into the canonical settlement
    /// path.
    pub fn verify_transition_for_settlement(
        &self,
        proof: TransitionProof,
    ) -> Result<VerifiedTransitionProof, ServiceError> {
        proof
            .into_verified(&self.ordering.verifying_keys(), self.ordering.policy())
            .map_err(|error| ServiceError::Proof(error.to_string()))
    }

    /// Corporate-module-only portfolio view. A public operator endpoint must
    /// never enumerate this method for arbitrary participant handles.
    pub fn participant_portfolio(
        &self,
        participant_handle: Digest32,
    ) -> Result<ParticipantPortfolio, ServiceError> {
        self.settlement
            .participant_portfolio(participant_handle)
            .map_err(|error| ServiceError::Settlement(error.to_string()))
    }

    pub fn submit(
        &mut self,
        order: SecretOrder,
        authority: OrderAuthority,
        eligibility_evidence: AnonymousPresentation,
        now: u64,
    ) -> Result<OclobExecutionReceipt, ServiceError> {
        let expired_before = self.expire_due(now)?;
        let staged = self.stage_submission(order, authority, eligibility_evidence, now)?;
        let StagedSubmission {
            settlement_order,
            staged_book,
            staged_ordering,
            mut staged_settlement,
            staged_eligibility,
            certificate,
            reservation,
            eligibility,
            mpc,
            book_transition,
            transition_proof,
            verified_transition,
        } = staged;
        let (settlement, reservation_release) = if book_transition.fills.is_empty() {
            let release =
                if settlement_order.time_in_force() == oclob_core::TimeInForce::ImmediateOrCancel {
                    Some(
                        staged_settlement
                            .release_order(settlement_order.commitment().0)
                            .map_err(|error| ServiceError::Settlement(error.to_string()))?,
                    )
                } else {
                    None
                };
            (None, release)
        } else {
            let settled = staged_settlement
                .settle_batch(
                    &book_transition.fills,
                    &verified_transition,
                    &settlement_order,
                    book_transition.arriving_remaining,
                    now,
                )
                .map_err(|error| ServiceError::Settlement(error.to_string()))?;
            (Some(settled), None)
        };
        self.book = staged_book;
        self.ordering = staged_ordering;
        self.settlement = staged_settlement;
        self.eligibility = staged_eligibility;
        Ok(OclobExecutionReceipt {
            expired_before,
            certificate,
            reservation,
            eligibility,
            mpc,
            book_transition,
            transition_proof,
            settlement,
            reservation_release,
        })
    }

    /// Prepare one admission without changing any live OCLOB state. This path
    /// is for a canonical DeFMI adapter: the caller submits
    /// `canonical_transition()` and
    /// consumes the returned acceptance through `PreparedOclobSubmission::accept`.
    pub fn prepare_canonical_submit(
        &mut self,
        order: SecretOrder,
        authority: OrderAuthority,
        eligibility_evidence: AnonymousPresentation,
        now: u64,
    ) -> Result<PreparedOclobSubmission, ServiceError> {
        if !self.book.expired_commitments(now).is_empty() {
            return Err(ServiceError::Settlement(
                "expired reservations must reach canonical finality before a new execution".into(),
            ));
        }
        let base_book_root = self.book.public_snapshot().state_root;
        let base_settlement = self.settlement.state_snapshot();
        let staged = self.stage_submission(order, authority, eligibility_evidence, now)?;
        if staged.book_transition.fills.is_empty()
            && staged.settlement_order.time_in_force() == oclob_core::TimeInForce::ImmediateOrCancel
        {
            return Err(ServiceError::Settlement(
                "a no-fill immediate-or-cancel order needs one atomic reserve-release transition"
                    .into(),
            ));
        }
        let canonical = if staged.book_transition.fills.is_empty() {
            self.settlement
                .prepare_canonical_reservation(
                    staged.staged_settlement.clone(),
                    staged.reservation.clone(),
                    &staged.settlement_order,
                    &staged.certificate,
                    &staged.verified_transition,
                    now,
                )
                .map_err(|error| ServiceError::Settlement(error.to_string()))?
        } else {
            self.settlement
                .prepare_canonical_admission_batch(CanonicalAdmissionBatch {
                    reserved_candidate: staged.staged_settlement.clone(),
                    reservation_receipt: &staged.reservation,
                    fills: &staged.book_transition.fills,
                    transition: &staged.verified_transition,
                    certificate: &staged.certificate,
                    arriving: &staged.settlement_order,
                    arriving_remaining: staged.book_transition.arriving_remaining,
                    now,
                })
                .map_err(|error| ServiceError::Settlement(error.to_string()))?
        };
        Ok(PreparedOclobSubmission {
            base_book_root,
            base_settlement,
            staged_book: staged.staged_book,
            staged_ordering: staged.staged_ordering,
            // The opaque canonical plan owns the candidate. Acceptance must
            // begin from the live finalized base, never from the locally staged
            // reservation that has not reached DeFMI yet.
            staged_settlement: self.settlement.clone(),
            staged_eligibility: staged.staged_eligibility,
            certificate: staged.certificate,
            reservation: staged.reservation,
            eligibility: staged.eligibility,
            mpc: staged.mpc,
            book_transition: staged.book_transition,
            transition_proof: staged.transition_proof,
            canonical,
        })
    }

    fn stage_submission(
        &mut self,
        order: SecretOrder,
        authority: OrderAuthority,
        eligibility_evidence: AnonymousPresentation,
        now: u64,
    ) -> Result<StagedSubmission, ServiceError> {
        self.check_eligibility(&order)?;
        authority
            .verify(&order, now)
            .map_err(|error| ServiceError::Order(error.to_string()))?;
        order
            .validate_market_rules(oclob_core::MarketRules::p1())
            .map_err(|error| ServiceError::Order(error.to_string()))?;
        if self.book.exceeds_fixed_match_capacity(&order, now) {
            return Err(ServiceError::Order(format!(
                "one order may match at most {} resting orders in the fixed circuit",
                oclob_core::MAX_MATCH_SLOTS
            )));
        }
        let mut staged_eligibility = self.eligibility.clone();
        let verified_eligibility = staged_eligibility
            .verify_order(
                order.commitment().0,
                order.dekyx_nullifier(),
                order.expires_at(),
                &eligibility_evidence,
                now,
            )
            .map_err(|error| ServiceError::Eligibility(error.to_string()))?;
        let mut staged_settlement = self.settlement.clone();
        staged_settlement
            .bind_eligible_participant(
                order.participant_handle(),
                verified_eligibility.subject_nullifier,
            )
            .map_err(|error| ServiceError::Settlement(error.to_string()))?;
        let reservation = staged_settlement
            .reserve_order(&order)
            .map_err(|error| ServiceError::Settlement(error.to_string()))?;
        let mut staged_ordering = self.ordering.clone();
        // This certificate is intentionally fixed before the private frame is
        // handed to the matcher.  No log or receipt below includes order fields.
        let certificate = staged_ordering
            .certify(
                &self.market_id,
                authority.commitment,
                order.expires_at(),
                now,
            )
            .map_err(|error| ServiceError::Ordering(error.to_string()))?;
        let private_input = self
            .book
            .private_match_batch(&order, now)
            .map_err(|error| ServiceError::Order(error.to_string()))?;
        let mpc = self
            .mpc
            .execute_batch(&private_input)
            .map_err(|error| ServiceError::Mpc(error.to_string()))?;
        // Build the transition on a private staged copy.  If proof generation
        // or settlement fails, the public and private books remain unchanged.
        let settlement_order = order.clone();
        let mut staged_book = self.book.clone();
        let book_transition = staged_book
            .apply_mpc_batch_result(
                order,
                authority,
                certificate.sequence,
                now,
                mpc.result.clone(),
            )
            .map_err(|error| ServiceError::Order(error.to_string()))?;
        let statement = TransitionStatement::from_batch_execution(
            &certificate,
            &book_transition,
            &mpc,
            verified_eligibility.proof_digest,
        )
        .map_err(|error| ServiceError::Proof(error.to_string()))?;
        let transition_proof = TransitionProof::attest(
            statement,
            &staged_ordering.transition_signers(),
            staged_ordering.policy(),
        )
        .map_err(|error| ServiceError::Proof(error.to_string()))?;
        transition_proof
            .verify(&staged_ordering.verifying_keys(), staged_ordering.policy())
            .map_err(|error| ServiceError::Proof(error.to_string()))?;
        let verified_transition = transition_proof
            .clone()
            .into_verified(&staged_ordering.verifying_keys(), staged_ordering.policy())
            .map_err(|error| ServiceError::Proof(error.to_string()))?;
        Ok(StagedSubmission {
            settlement_order,
            staged_book,
            staged_ordering,
            staged_settlement,
            staged_eligibility,
            certificate,
            reservation,
            eligibility: verified_eligibility,
            mpc,
            book_transition,
            transition_proof,
            verified_transition,
        })
    }

    pub fn cancel(
        &mut self,
        cancellation: SecretCancellation,
        now: u64,
    ) -> Result<OclobCancellationReceipt, ServiceError> {
        let mut staged_ordering = self.ordering.clone();
        let certificate = staged_ordering
            .certify(
                &self.market_id,
                cancellation.commitment(),
                now.saturating_add(60),
                now,
            )
            .map_err(|error| ServiceError::Ordering(error.to_string()))?;
        let mut staged_book = self.book.clone();
        let transition = staged_book
            .apply_cancellation(&cancellation, certificate.sequence)
            .map_err(|error| ServiceError::Order(error.to_string()))?;
        let statement = CancellationStatement::from_transition(&certificate, &transition)
            .map_err(|error| ServiceError::Proof(error.to_string()))?;
        let proof = CancellationProof::attest(
            statement,
            &staged_ordering.transition_signers(),
            staged_ordering.policy(),
        )
        .map_err(|error| ServiceError::Proof(error.to_string()))?;
        proof
            .verify(&staged_ordering.verifying_keys(), staged_ordering.policy())
            .map_err(|error| ServiceError::Proof(error.to_string()))?;
        let mut staged_settlement = self.settlement.clone();
        let reservation_release = staged_settlement
            .release_order(cancellation.target().0)
            .map_err(|error| ServiceError::Settlement(error.to_string()))?;
        self.book = staged_book;
        self.ordering = staged_ordering;
        self.settlement = staged_settlement;
        Ok(OclobCancellationReceipt {
            certificate,
            transition,
            proof,
            reservation_release,
        })
    }

    pub fn expire_due(&mut self, now: u64) -> Result<Option<OclobExpiryReceipt>, ServiceError> {
        let expired_orders = self.book.expired_commitments(now);
        if expired_orders.is_empty() {
            return Ok(None);
        }
        let commitment = expiry_commitment(&self.market_id, now, &expired_orders);
        let mut staged_ordering = self.ordering.clone();
        let certificate = staged_ordering
            .certify(&self.market_id, commitment, now.saturating_add(60), now)
            .map_err(|error| ServiceError::Ordering(error.to_string()))?;
        let mut staged_book = self.book.clone();
        let transition = staged_book
            .apply_expiry(now, commitment, certificate.sequence)
            .map_err(|error| ServiceError::Order(error.to_string()))?;
        let statement = ExpiryStatement::from_transition(&certificate, &transition)
            .map_err(|error| ServiceError::Proof(error.to_string()))?;
        let proof = ExpiryProof::attest(
            statement,
            &staged_ordering.transition_signers(),
            staged_ordering.policy(),
        )
        .map_err(|error| ServiceError::Proof(error.to_string()))?;
        proof
            .verify(&staged_ordering.verifying_keys(), staged_ordering.policy())
            .map_err(|error| ServiceError::Proof(error.to_string()))?;
        let commitments = expired_orders
            .iter()
            .map(|commitment| commitment.0)
            .collect::<Vec<_>>();
        let mut staged_settlement = self.settlement.clone();
        let reservation_release = staged_settlement
            .release_orders_atomic(&commitments)
            .map_err(|error| ServiceError::Settlement(error.to_string()))?;
        self.book = staged_book;
        self.ordering = staged_ordering;
        self.settlement = staged_settlement;
        Ok(Some(OclobExpiryReceipt {
            certificate,
            transition,
            proof,
            reservation_release,
        }))
    }

    fn check_eligibility(&self, order: &SecretOrder) -> Result<(), ServiceError> {
        if order.market_id() != self.market_id {
            return Err(ServiceError::Order("order is for another market".into()));
        }
        Ok(())
    }
}

fn canonical_result(receipt: &OclobExecutionReceipt) -> (Digest32, u64) {
    if let Some(settlement) = &receipt.settlement {
        return (
            settlement.canonical_receipt_digest,
            settlement.canonical_height,
        );
    }
    if let Some(release) = &receipt.reservation_release {
        return (release.canonical_receipt_digest, release.canonical_height);
    }
    (
        receipt.reservation.canonical_receipt_digest,
        receipt.reservation.canonical_height,
    )
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("order admission failed: {0}")]
    Order(String),
    #[error("DeKYX eligibility failed: {0}")]
    Eligibility(String),
    #[error("order sequencing failed: {0}")]
    Ordering(String),
    #[error("private matching failed closed: {0}")]
    Mpc(String),
    #[error("book-transition proof failed: {0}")]
    Proof(String),
    #[error("zkPI/DeFMI settlement failed: {0}")]
    Settlement(String),
    #[error("durable OCLOB queue failed: {0}")]
    Queue(String),
}

impl ServiceError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Ordering(_) | Self::Mpc(_) | Self::Proof(_) | Self::Settlement(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oclob_core::application_crypto::SigningKey;
    use oclob_core::{authorize_order, Side, TimeInForce};
    use oclob_dekyx::deterministic_demo_environment;
    use rand::rngs::OsRng;
    use std::fs;

    fn queue_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "oclob-service-{}-{}-{}",
            label,
            std::process::id(),
            u64::from_le_bytes(rand::random())
        ))
    }

    #[test]
    fn queue_is_encrypted_idempotent_and_waits_for_mpc() {
        let root = queue_path("encrypted-queue");
        let path = root.join("outbox.bin");
        let (_verifier, issuer) = deterministic_demo_environment("JGB10Y-JPY").unwrap();
        let wallet = issuer
            .issue_wallet(11, b"queue-wallet", &mut OsRng)
            .unwrap();
        let order = SecretOrder::new_with_dekyx_nullifier(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            40,
            TimeInForce::ImmediateOrCancel,
            2_000,
            [11; 32],
            wallet.subject_nullifier(),
            [12; 32],
            [13; 32],
        )
        .unwrap();
        let authority = authorize_order(&order, 2_100, &SigningKey::from_bytes(&[41; 64])).unwrap();
        let evidence = wallet
            .present(order.commitment().0, [14; 32], 2_000, &mut OsRng)
            .unwrap();
        let queue =
            DurableOclobQueue::open(&path, b"correct horse battery staple", "defmi-test", 16, 1)
                .unwrap();
        let first = queue.enqueue(&order, &authority, &evidence, 1_000).unwrap();
        let duplicate = queue.enqueue(&order, &authority, &evidence, 1_001).unwrap();
        assert!(!first.already_present);
        assert!(duplicate.already_present);
        assert_eq!(first.sequence, duplicate.sequence);
        assert_eq!(queue.summaries().unwrap().len(), 1);
        assert!(matches!(
            queue.pump_cover_slot(
                &mut OclobService::new(
                    "JGB10Y-JPY",
                    std::env::var("MP_SPDZ_ROOT").unwrap_or_else(|_| "/opt/MP-SPDZ".into()),
                    deterministic_demo_environment("JGB10Y-JPY").unwrap().0,
                )
                .unwrap(),
                1_002,
                false,
                1,
            ),
            Ok(QueueWorkerResult::DummyCover { .. })
        ));

        let stored = fs::read(&path).unwrap();
        assert!(!stored
            .windows(b"JGB10Y-JPY".len())
            .any(|window| window == b"JGB10Y-JPY"));
        assert!(!stored
            .windows(first.request_id.len())
            .any(|window| window == first.request_id.as_bytes()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_preparation_does_not_commit_book_or_balances() {
        let (verifier, issuer) = deterministic_demo_environment("JGB10Y-JPY").unwrap();
        let seller_wallet = issuer
            .issue_wallet(11, b"prepared-seller", &mut OsRng)
            .unwrap();
        let buyer_wallet = issuer
            .issue_wallet(22, b"prepared-buyer", &mut OsRng)
            .unwrap();
        let mut service = OclobService::new(
            "JGB10Y-JPY",
            std::env::var("MP_SPDZ_ROOT").unwrap_or_else(|_| "/opt/MP-SPDZ".into()),
            verifier,
        )
        .unwrap();
        let (seller, buyer) = service.demo_participant_handles();
        let maker = SecretOrder::new_with_dekyx_nullifier(
            "JGB10Y-JPY",
            Side::Sell,
            100,
            100,
            TimeInForce::GoodTilCancelled,
            2_000,
            seller,
            seller_wallet.subject_nullifier(),
            [31; 32],
            [41; 32],
        )
        .unwrap();
        let maker_authority =
            authorize_order(&maker, 2_100, &SigningKey::from_bytes(&[51; 64])).unwrap();
        let maker_evidence = seller_wallet
            .present(maker.commitment().0, [61; 32], 2_000, &mut OsRng)
            .unwrap();
        service
            .submit(maker, maker_authority, maker_evidence, 1_000)
            .unwrap();

        let taker = SecretOrder::new_with_dekyx_nullifier(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            40,
            TimeInForce::ImmediateOrCancel,
            2_000,
            buyer,
            buyer_wallet.subject_nullifier(),
            [32; 32],
            [42; 32],
        )
        .unwrap();
        let taker_authority =
            authorize_order(&taker, 2_100, &SigningKey::from_bytes(&[52; 64])).unwrap();
        let taker_evidence = buyer_wallet
            .present(taker.commitment().0, [62; 32], 2_000, &mut OsRng)
            .unwrap();
        let book_before = service.public_book();
        let settlement_before = service.settlement_state();
        let prepared = service
            .prepare_canonical_submit(taker, taker_authority, taker_evidence, 1_001)
            .unwrap();
        assert_eq!(prepared.book_transition().fills.len(), 1);
        assert_eq!(prepared.book_transition().fills[0].price, 100);
        assert_eq!(prepared.book_transition().fills[0].quantity, 40);
        assert_eq!(service.public_book(), book_before);
        assert_eq!(service.settlement_state(), settlement_before);
        drop(prepared);
        assert_eq!(service.public_book(), book_before);
        assert_eq!(service.settlement_state(), settlement_before);
    }
}
