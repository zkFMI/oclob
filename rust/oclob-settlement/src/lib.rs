//! OCLOB fill settlement through the production zkPI and DeFMI verifiers.

#![forbid(unsafe_code)]

pub mod avalanche;
pub mod collaborative;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use oclob_core::{Digest32, OrderCommitment, PublicFill, SecretOrder, Side, TimeInForce};
use oclob_edge::VerifiedSettlementCapability;
use oclob_ordering::{CommitteePolicy, OrderCertificate, OrderingCommittee};
use oclob_proofs::{committee_trust_root, VerifiedTransitionProof};
use qomm_defmi::ledger::Ledger;
use qomm_defmi::settlement::{
    account_of, build_package, Defmi, Holdings, InstructionOpenings, CASH_RAIL, SECURITIES_RAIL,
};
use qomm_proofs::threshold_range::{deal_bits, joint_prove_range_from_contributions, ValueShares};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::{Handle, Identity};
use qomm_zkpi::{
    distributed_key_generation, frost, Bounds, PartialInstruction, Venue, AMOUNT_RANGE_CONTEXT,
    PRICE_RANGE_CONTEXT,
};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::finality::{
    accept_canonical_transition, CanonicalReadback, CanonicalTransition, ReadbackKind,
};

pub const RANGE_BITS: usize = 32;
pub const PROOF_PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
pub const PROOF_QUORUM: [PartyId; 3] = [1, 2, 3];
pub const PROOF_THRESHOLD: usize = 2;
const VENUE_DOMAIN: &[u8] = b"defmi:oclob:v1";
const ASSET_INDEX: u32 = 3;

/// Minimal private order view required by reservation and DvP.  The ordinary
/// service implements it with `SecretOrder`; the participant-edge path uses a
/// verified settlement capability whose public identity is the VSS manifest
/// commitment rather than the inner secret-order commitment.
pub trait SettlementOrderView {
    fn settlement_market_id(&self) -> &str;
    fn settlement_side(&self) -> Side;
    fn settlement_limit_price(&self) -> u64;
    fn settlement_quantity(&self) -> u64;
    fn settlement_time_in_force(&self) -> TimeInForce;
    fn settlement_expires_at(&self) -> u64;
    fn settlement_participant_handle(&self) -> Digest32;
    fn settlement_dekyx_nullifier(&self) -> Digest32;
    fn settlement_reservation_id(&self) -> Digest32;
    fn settlement_reservation_limit(&self) -> u64;
    fn settlement_max_fee(&self) -> u64;
    fn settlement_commitment(&self) -> OrderCommitment;
}

impl SettlementOrderView for SecretOrder {
    fn settlement_market_id(&self) -> &str {
        self.market_id()
    }

    fn settlement_side(&self) -> Side {
        self.side()
    }

    fn settlement_limit_price(&self) -> u64 {
        self.limit_price()
    }

    fn settlement_quantity(&self) -> u64 {
        self.quantity()
    }

    fn settlement_time_in_force(&self) -> TimeInForce {
        self.time_in_force()
    }

    fn settlement_expires_at(&self) -> u64 {
        self.expires_at()
    }

    fn settlement_participant_handle(&self) -> Digest32 {
        self.participant_handle()
    }

    fn settlement_dekyx_nullifier(&self) -> Digest32 {
        self.dekyx_nullifier()
    }

    fn settlement_reservation_id(&self) -> Digest32 {
        self.reservation_id()
    }

    fn settlement_reservation_limit(&self) -> u64 {
        self.reservation_limit()
    }

    fn settlement_max_fee(&self) -> u64 {
        self.max_fee()
    }

    fn settlement_commitment(&self) -> OrderCommitment {
        self.commitment()
    }
}

impl SettlementOrderView for VerifiedSettlementCapability {
    fn settlement_market_id(&self) -> &str {
        self.order().market_id()
    }

    fn settlement_side(&self) -> Side {
        self.order().side()
    }

    fn settlement_limit_price(&self) -> u64 {
        self.order().limit_price()
    }

    fn settlement_quantity(&self) -> u64 {
        self.order().quantity()
    }

    fn settlement_time_in_force(&self) -> TimeInForce {
        self.order().time_in_force()
    }

    fn settlement_expires_at(&self) -> u64 {
        self.order().expires_at()
    }

    fn settlement_participant_handle(&self) -> Digest32 {
        self.order().participant_handle()
    }

    fn settlement_dekyx_nullifier(&self) -> Digest32 {
        self.order().dekyx_nullifier()
    }

    fn settlement_reservation_id(&self) -> Digest32 {
        self.order().reservation_id()
    }

    fn settlement_reservation_limit(&self) -> u64 {
        self.order().reservation_limit()
    }

    fn settlement_max_fee(&self) -> u64 {
        self.order().max_fee()
    }

    fn settlement_commitment(&self) -> OrderCommitment {
        self.order_commitment()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OclobSettlementReceipt {
    pub batch_digest: Digest32,
    pub members: Vec<OclobSettlementMemberReceipt>,
    pub amount_range_is_threshold: bool,
    pub price_range_is_threshold: bool,
    pub settlement_authorization_quorum: usize,
    pub post_match_participant_signatures: usize,
    pub securities_before_root: Digest32,
    pub securities_after_root: Digest32,
    pub cash_before_root: Digest32,
    pub cash_after_root: Digest32,
    pub reservation_before_root: Digest32,
    pub reservation_after_root: Digest32,
    /// Threshold zkPI evidence for the arriving order's pre-trade maximum.
    /// On the canonical admission path this reservation and all resulting DvP
    /// fills are one compare-and-swap; the compatibility path leaves these
    /// fields empty.
    pub arriving_reservation_zkpi_digest: Option<Digest32>,
    pub arriving_reservation_instruction_nullifier: Option<Digest32>,
    pub arriving_reservation_proof_digest: Option<Digest32>,
    pub canonical_state_root: Digest32,
    pub canonical_receipt_digest: Digest32,
    pub canonical_height: u64,
    /// Present only when the transition was accepted by Avalanche consensus.
    /// The legacy in-process demonstrator deliberately leaves these fields
    /// empty and therefore cannot be mistaken for live L1 finality.
    pub avalanche_transaction_id: Option<String>,
    pub avalanche_block_id: Option<String>,
    pub replay_rejected: bool,
    pub solvent: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OclobSettlementMemberReceipt {
    pub instruction_nullifier: Digest32,
    pub zkpi_digest: Digest32,
    pub package_digest: Digest32,
    pub maker_order: Digest32,
    pub taker_order: Digest32,
    pub maker_reservation_remaining: u64,
    pub taker_reservation_remaining: u64,
}

/// One confidential-ledger account that must exist in canonical DeFMI state
/// before a prepared OCLOB settlement can be submitted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalAccountOpening {
    pub handle: Digest32,
    pub asset_id: Digest32,
    pub commitment: Digest32,
}

/// One net account change for an atomic OCLOB batch. Multiple fills touching
/// the same participant are collapsed into one compare-and-swap leg.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalAccountDelta {
    pub handle: Digest32,
    pub asset_id: Digest32,
    pub before_commitment: Digest32,
    pub after_commitment: Digest32,
}

/// Consensus evidence returned by the canonical settlement adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalSettlementAcceptance {
    transaction_id: String,
    block_id: String,
    height: u64,
    statement: Digest32,
    before_state_root: Digest32,
    after_state_root: Digest32,
    receipt_digest: Digest32,
    application_binding: Digest32,
    binding_digest: Digest32,
}

impl CanonicalSettlementAcceptance {
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub fn block_id(&self) -> &str {
        &self.block_id
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn statement(&self) -> Digest32 {
        self.statement
    }

    pub const fn before_state_root(&self) -> Digest32 {
        self.before_state_root
    }

    pub const fn after_state_root(&self) -> Digest32 {
        self.after_state_root
    }

    pub const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }

    pub const fn application_binding(&self) -> Digest32 {
        self.application_binding
    }

    pub const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }
}

/// Opaque, locally verified state candidate. It is intentionally neither
/// serializable nor clonable: callers may inspect only public commitments and
/// can apply it exactly once after canonical finality is proven.
pub struct PreparedCanonicalBatch {
    candidate: SettlementEngine,
    base_snapshot: SettlementStateSnapshot,
    receipt: OclobSettlementReceipt,
    market_id: String,
    transition_digest: Digest32,
    payment_instruction_digest: Digest32,
    proof_digest: Digest32,
    application_binding: Digest32,
    binding_digest: Digest32,
    account_openings: Vec<CanonicalAccountOpening>,
    account_deltas: Vec<CanonicalAccountDelta>,
    deadline: u64,
}

impl PreparedCanonicalBatch {
    pub fn receipt(&self) -> &OclobSettlementReceipt {
        &self.receipt
    }

    pub fn market_id(&self) -> &str {
        &self.market_id
    }

    pub const fn transition_digest(&self) -> Digest32 {
        self.transition_digest
    }

    pub const fn payment_instruction_digest(&self) -> Digest32 {
        self.payment_instruction_digest
    }

    pub const fn proof_digest(&self) -> Digest32 {
        self.proof_digest
    }

    pub const fn application_binding(&self) -> Digest32 {
        self.application_binding
    }

    pub const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }

    pub fn account_openings(&self) -> &[CanonicalAccountOpening] {
        &self.account_openings
    }

    pub fn account_deltas(&self) -> &[CanonicalAccountDelta] {
        &self.account_deltas
    }

    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Apply the already-verified candidate only after the canonical adapter
    /// proves that the exact application binding reached finality.
    pub fn accept(
        mut self,
        engine: &mut SettlementEngine,
        acceptance: CanonicalSettlementAcceptance,
    ) -> Result<OclobSettlementReceipt, SettlementError> {
        if engine.state_snapshot() != self.base_snapshot {
            return Err(SettlementError::CanonicalDivergence);
        }
        verify_acceptance(&acceptance, self.application_binding, self.binding_digest)?;
        self.candidate.height = acceptance.height;
        self.receipt.canonical_state_root = acceptance.after_state_root;
        self.receipt.canonical_receipt_digest = acceptance.receipt_digest;
        self.receipt.canonical_height = acceptance.height;
        self.receipt.avalanche_transaction_id = Some(acceptance.transaction_id);
        self.receipt.avalanche_block_id = Some(acceptance.block_id);
        *engine = self.candidate;
        Ok(self.receipt)
    }
}

/// A pre-trade reserve that has been proved as a threshold zkPI but has not
/// yet changed either the local reservation ledger or the order book. The
/// canonical DeFMI transition advances a dedicated reservation-state account,
/// so concurrent admissions are serialized by the same compare-and-swap rule
/// as cash and securities settlement.
pub struct PreparedCanonicalReservation {
    candidate: SettlementEngine,
    base_snapshot: SettlementStateSnapshot,
    receipt: ReservationReceipt,
    market_id: String,
    transition_digest: Digest32,
    payment_instruction_digest: Digest32,
    proof_digest: Digest32,
    instruction_nullifier: Digest32,
    application_binding: Digest32,
    binding_digest: Digest32,
    account_openings: Vec<CanonicalAccountOpening>,
    account_deltas: Vec<CanonicalAccountDelta>,
    deadline: u64,
}

impl PreparedCanonicalReservation {
    fn accept(
        mut self,
        engine: &mut SettlementEngine,
        acceptance: CanonicalSettlementAcceptance,
    ) -> Result<ReservationReceipt, SettlementError> {
        if engine.state_snapshot() != self.base_snapshot {
            return Err(SettlementError::CanonicalDivergence);
        }
        verify_acceptance(&acceptance, self.application_binding, self.binding_digest)?;
        self.candidate.height = acceptance.height;
        self.receipt.canonical_receipt_digest = acceptance.receipt_digest;
        self.receipt.canonical_height = acceptance.height;
        self.receipt.avalanche_transaction_id = Some(acceptance.transaction_id);
        self.receipt.avalanche_block_id = Some(acceptance.block_id);
        *engine = self.candidate;
        Ok(self.receipt)
    }
}

/// The only two canonical state changes an admitted order may request. Keeping
/// one opaque enum lets the service follow the same two-phase protocol for a
/// resting reservation and for an immediately matched DvP batch.
pub enum PreparedCanonicalTransition {
    Reservation(PreparedCanonicalReservation),
    Settlement(PreparedCanonicalBatch),
}

pub enum AppliedCanonicalTransition {
    Reservation(ReservationReceipt),
    Settlement(OclobSettlementReceipt),
}

/// Inputs already checked by the OCLOB admission pipeline and consumed while
/// constructing one atomic taker-reservation plus DvP transition.
pub struct CanonicalAdmissionBatch<'a, O: SettlementOrderView + ?Sized> {
    pub reserved_candidate: SettlementEngine,
    pub reservation_receipt: &'a ReservationReceipt,
    pub fills: &'a [PublicFill],
    pub transition: &'a VerifiedTransitionProof,
    pub certificate: &'a OrderCertificate,
    pub arriving: &'a O,
    pub arriving_remaining: u64,
    pub now: u64,
}

/// Production admission input. The arriving capability is used only for its
/// already-authorized pre-trade reservation; every post-match zkPI and DvP
/// statement comes from the resident MPC proof committee.
pub struct CollaborativeCanonicalAdmissionBatch<'a, O: SettlementOrderView + ?Sized> {
    pub reserved_candidate: SettlementEngine,
    pub reservation_receipt: &'a ReservationReceipt,
    pub fills: &'a [PublicFill],
    pub proofs: &'a [collaborative::CollaborativeFillProof],
    pub round_id: Digest32,
    pub transition: &'a VerifiedTransitionProof,
    pub certificate: &'a OrderCertificate,
    pub arriving: &'a O,
    pub arriving_remaining: u64,
    pub now: u64,
}

impl PreparedCanonicalTransition {
    pub fn market_id(&self) -> &str {
        match self {
            Self::Reservation(value) => &value.market_id,
            Self::Settlement(value) => &value.market_id,
        }
    }

    pub fn transition_digest(&self) -> Digest32 {
        match self {
            Self::Reservation(value) => value.transition_digest,
            Self::Settlement(value) => value.transition_digest,
        }
    }

    pub fn payment_instruction_digest(&self) -> Digest32 {
        match self {
            Self::Reservation(value) => value.payment_instruction_digest,
            Self::Settlement(value) => value.payment_instruction_digest,
        }
    }

    pub fn proof_digest(&self) -> Digest32 {
        match self {
            Self::Reservation(value) => value.proof_digest,
            Self::Settlement(value) => value.proof_digest,
        }
    }

    pub fn application_binding(&self) -> Digest32 {
        match self {
            Self::Reservation(value) => value.application_binding,
            Self::Settlement(value) => value.application_binding,
        }
    }

    pub fn binding_digest(&self) -> Digest32 {
        match self {
            Self::Reservation(value) => value.binding_digest,
            Self::Settlement(value) => value.binding_digest,
        }
    }

    pub fn account_openings(&self) -> &[CanonicalAccountOpening] {
        match self {
            Self::Reservation(value) => &value.account_openings,
            Self::Settlement(value) => &value.account_openings,
        }
    }

    pub fn account_deltas(&self) -> &[CanonicalAccountDelta] {
        match self {
            Self::Reservation(value) => &value.account_deltas,
            Self::Settlement(value) => &value.account_deltas,
        }
    }

    pub fn deadline(&self) -> u64 {
        match self {
            Self::Reservation(value) => value.deadline,
            Self::Settlement(value) => value.deadline,
        }
    }

    pub fn operation_id(&self) -> Digest32 {
        digest(
            b"OCLOB:DEFMI:CANONICAL-OPERATION:v1",
            &self.binding_digest(),
        )
    }

    pub fn nullifier(&self) -> Digest32 {
        match self {
            Self::Reservation(value) => value.instruction_nullifier,
            Self::Settlement(value) => digest(
                b"OCLOB:DEFMI:SETTLEMENT-NULLIFIER:v1",
                &value.receipt.batch_digest,
            ),
        }
    }

    pub fn accept(
        self,
        engine: &mut SettlementEngine,
        acceptance: CanonicalSettlementAcceptance,
    ) -> Result<AppliedCanonicalTransition, SettlementError> {
        match self {
            Self::Reservation(value) => value
                .accept(engine, acceptance)
                .map(AppliedCanonicalTransition::Reservation),
            Self::Settlement(value) => value
                .accept(engine, acceptance)
                .map(AppliedCanonicalTransition::Settlement),
        }
    }
}

fn verify_acceptance(
    acceptance: &CanonicalSettlementAcceptance,
    application_binding: Digest32,
    binding_digest: Digest32,
) -> Result<(), SettlementError> {
    if acceptance.transaction_id.is_empty()
        || acceptance.block_id.is_empty()
        || acceptance.height == 0
        || acceptance.statement == [0; 32]
        || acceptance.receipt_digest == [0; 32]
        || acceptance.before_state_root == acceptance.after_state_root
        || acceptance.application_binding != application_binding
        || acceptance.binding_digest != binding_digest
    {
        return Err(SettlementError::Finality(
            "canonical settlement acceptance is incomplete".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementStateSnapshot {
    pub securities_root: Digest32,
    pub cash_root: Digest32,
    pub reservation_root: Digest32,
    pub height: u64,
}

/// Private participant view returned only by an authenticated corporate
/// module. It is deliberately separate from the public order-book snapshot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParticipantPortfolio {
    pub securities: u64,
    pub cash: u64,
    pub reserved_securities: u64,
    pub reserved_cash: u64,
    pub available_securities: u64,
    pub available_cash: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationKind {
    Cash,
    Securities,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Active,
    Consumed,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservationReceipt {
    pub reservation_id: Digest32,
    pub order_commitment: Digest32,
    pub kind: ReservationKind,
    pub reserved: u64,
    pub state_root: Digest32,
    pub canonical_receipt_digest: Digest32,
    pub canonical_height: u64,
    /// Set only when the reservation itself was authorized as a threshold
    /// zkPI and accepted by a canonical Avalanche DeFMI transition.
    pub zkpi_digest: Option<Digest32>,
    pub instruction_nullifier: Option<Digest32>,
    pub proof_digest: Option<Digest32>,
    pub avalanche_transaction_id: Option<String>,
    pub avalanche_block_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservationReleaseReceipt {
    pub order_commitment: Digest32,
    pub before_root: Digest32,
    pub after_root: Digest32,
    pub canonical_receipt_digest: Digest32,
    pub canonical_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservationBatchReleaseReceipt {
    pub order_commitments: Vec<Digest32>,
    pub before_root: Digest32,
    pub after_root: Digest32,
    pub canonical_receipt_digest: Digest32,
    pub canonical_height: u64,
}

#[derive(Clone)]
struct ReservationRecord {
    reservation_id: Digest32,
    order_commitment: Digest32,
    participant_handle: Digest32,
    entity_nullifier: Digest32,
    market_id: String,
    kind: ReservationKind,
    limit_price: u64,
    time_in_force: TimeInForce,
    original_quantity: u64,
    remaining_quantity: u64,
    max_fee: u64,
    expires_at: u64,
    reserved: u64,
    remaining: u64,
    reserve_commitment: RistrettoPoint,
    status: ReservationStatus,
}

#[derive(Clone, Default)]
struct ReservationBook {
    capacities: BTreeMap<(Digest32, u8), u64>,
    participant_entities: BTreeMap<Digest32, Digest32>,
    entity_participants: BTreeMap<Digest32, Digest32>,
    records: BTreeMap<Digest32, ReservationRecord>,
}

impl ReservationBook {
    fn bind_participant(
        &mut self,
        participant: Digest32,
        entity: Digest32,
        cash: u64,
        securities: u64,
    ) -> Result<(), SettlementError> {
        if participant == [0; 32] || entity == [0; 32] {
            return Err(SettlementError::Reservation(
                "participant and DeKYX entity identifiers are required".into(),
            ));
        }
        if self
            .participant_entities
            .get(&participant)
            .is_some_and(|existing| existing != &entity)
            || self
                .entity_participants
                .get(&entity)
                .is_some_and(|existing| existing != &participant)
        {
            return Err(SettlementError::Reservation(
                "one participant handle and one DeKYX entity must remain one-to-one".into(),
            ));
        }
        self.participant_entities.insert(participant, entity);
        self.entity_participants.insert(entity, participant);
        self.capacities.insert((entity, 1), cash);
        self.capacities.insert((entity, 2), securities);
        Ok(())
    }

    fn refresh_capacity(
        &mut self,
        participant: Digest32,
        cash: u64,
        securities: u64,
    ) -> Result<(), SettlementError> {
        let entity = self
            .participant_entities
            .get(&participant)
            .copied()
            .ok_or_else(|| {
                SettlementError::Reservation("participant has no DeKYX binding".into())
            })?;
        self.capacities.insert((entity, 1), cash);
        self.capacities.insert((entity, 2), securities);
        Ok(())
    }

    fn reserved_for(
        &self,
        participant: Digest32,
        kind: ReservationKind,
    ) -> Result<u64, SettlementError> {
        self.records
            .values()
            .filter(|record| {
                record.participant_handle == participant
                    && record.kind == kind
                    && record.status == ReservationStatus::Active
            })
            .try_fold(0_u64, |total, record| total.checked_add(record.remaining))
            .ok_or_else(|| SettlementError::Reservation("reservation sum overflowed".into()))
    }

    fn reserve<O: SettlementOrderView + ?Sized>(
        &mut self,
        order: &O,
        reserve_commitment: RistrettoPoint,
    ) -> Result<ReservationReceipt, SettlementError> {
        if reserve_commitment == RistrettoPoint::default() {
            return Err(SettlementError::Reservation(
                "reservation commitment is the identity point".into(),
            ));
        }
        if self
            .participant_entities
            .get(&order.settlement_participant_handle())
            != Some(&order.settlement_dekyx_nullifier())
        {
            return Err(SettlementError::Reservation(
                "order participant is not bound to the presented DeKYX entity".into(),
            ));
        }
        let id = order.settlement_reservation_id();
        if self.records.contains_key(&id)
            || self
                .records
                .values()
                .any(|record| record.order_commitment == order.settlement_commitment().0)
        {
            return Err(SettlementError::Reservation(
                "reservation id or order commitment was already used".into(),
            ));
        }
        let kind = match order.settlement_side() {
            Side::Buy => ReservationKind::Cash,
            Side::Sell => ReservationKind::Securities,
        };
        let kind_tag = reservation_kind_tag(kind);
        let capacity = self
            .capacities
            .get(&(order.settlement_dekyx_nullifier(), kind_tag))
            .copied()
            .ok_or_else(|| {
                SettlementError::Reservation("entity has no canonical capacity".into())
            })?;
        let in_use = self
            .records
            .values()
            .filter(|record| {
                record.entity_nullifier == order.settlement_dekyx_nullifier()
                    && record.kind == kind
                    && record.status == ReservationStatus::Active
            })
            .try_fold(0_u64, |total, record| total.checked_add(record.remaining))
            .ok_or_else(|| SettlementError::Reservation("reservation sum overflowed".into()))?;
        if in_use
            .checked_add(order.settlement_reservation_limit())
            .is_none_or(|total| total > capacity)
        {
            return Err(SettlementError::Reservation(
                "the entity-wide cash, inventory, or guarantee capacity is exceeded".into(),
            ));
        }
        let record = ReservationRecord {
            reservation_id: id,
            order_commitment: order.settlement_commitment().0,
            participant_handle: order.settlement_participant_handle(),
            entity_nullifier: order.settlement_dekyx_nullifier(),
            market_id: order.settlement_market_id().to_owned(),
            kind,
            limit_price: order.settlement_limit_price(),
            time_in_force: order.settlement_time_in_force(),
            original_quantity: order.settlement_quantity(),
            remaining_quantity: order.settlement_quantity(),
            max_fee: order.settlement_max_fee(),
            expires_at: order.settlement_expires_at(),
            reserved: order.settlement_reservation_limit(),
            remaining: order.settlement_reservation_limit(),
            reserve_commitment,
            status: ReservationStatus::Active,
        };
        self.records.insert(id, record);
        Ok(ReservationReceipt {
            reservation_id: id,
            order_commitment: order.settlement_commitment().0,
            kind,
            reserved: order.settlement_reservation_limit(),
            state_root: self.root(),
            canonical_receipt_digest: [0; 32],
            canonical_height: 0,
            zkpi_digest: None,
            instruction_nullifier: None,
            proof_digest: None,
            avalanche_transaction_id: None,
            avalanche_block_id: None,
        })
    }

    fn validate_active_order<O: SettlementOrderView + ?Sized>(
        &self,
        order: &O,
    ) -> Result<(), SettlementError> {
        let record_id = self
            .record_id_for(order.settlement_commitment().0)
            .ok_or_else(|| SettlementError::Reservation("reservation is absent".into()))?;
        let record = self
            .records
            .get(&record_id)
            .ok_or_else(|| SettlementError::Reservation("reservation is absent".into()))?;
        let expected_kind = match order.settlement_side() {
            Side::Buy => ReservationKind::Cash,
            Side::Sell => ReservationKind::Securities,
        };
        if record.reservation_id != order.settlement_reservation_id()
            || record.order_commitment != order.settlement_commitment().0
            || record.participant_handle != order.settlement_participant_handle()
            || record.entity_nullifier != order.settlement_dekyx_nullifier()
            || record.market_id != order.settlement_market_id()
            || record.kind != expected_kind
            || record.limit_price != order.settlement_limit_price()
            || record.time_in_force != order.settlement_time_in_force()
            || record.original_quantity != order.settlement_quantity()
            || record.remaining_quantity != order.settlement_quantity()
            || record.max_fee != order.settlement_max_fee()
            || record.expires_at != order.settlement_expires_at()
            || record.reserved != order.settlement_reservation_limit()
            || record.remaining != order.settlement_reservation_limit()
            || record.status != ReservationStatus::Active
        {
            return Err(SettlementError::Reservation(
                "reservation candidate does not match the admitted order".into(),
            ));
        }
        Ok(())
    }

    fn consume_fill(
        &mut self,
        fill: &PublicFill,
        market_id: &str,
        now: u64,
    ) -> Result<ConsumedFill, SettlementError> {
        let cash = fill
            .price
            .checked_mul(fill.quantity)
            .ok_or_else(|| SettlementError::Reservation("cash fill overflowed".into()))?;
        let maker_id = self
            .record_id_for(fill.maker_order.0)
            .ok_or_else(|| SettlementError::Reservation("maker reservation is absent".into()))?;
        let taker_id = self
            .record_id_for(fill.taker_order.0)
            .ok_or_else(|| SettlementError::Reservation("taker reservation is absent".into()))?;
        if maker_id == taker_id {
            return Err(SettlementError::Reservation(
                "maker and taker cannot consume the same reservation".into(),
            ));
        }
        let maker = self.records.get(&maker_id).expect("looked up maker");
        let taker = self.records.get(&taker_id).expect("looked up taker");
        if maker.kind == taker.kind {
            return Err(SettlementError::Reservation(
                "a fill must join one cash reservation and one inventory reservation".into(),
            ));
        }
        if maker.market_id != market_id || taker.market_id != market_id {
            return Err(SettlementError::Reservation(
                "a fill cannot cross reservations from another market".into(),
            ));
        }
        if maker.expires_at < now || taker.expires_at < now {
            return Err(SettlementError::Reservation(
                "an expired reservation cannot be filled".into(),
            ));
        }
        if fill.quantity > maker.remaining_quantity || fill.quantity > taker.remaining_quantity {
            return Err(SettlementError::Reservation(
                "fill quantity exceeds an order remainder".into(),
            ));
        }
        for record in [maker, taker] {
            let respects_limit = match record.kind {
                ReservationKind::Cash => fill.price <= record.limit_price,
                ReservationKind::Securities => fill.price >= record.limit_price,
            };
            if !respects_limit {
                return Err(SettlementError::Reservation(
                    "fill price violates a committed order limit".into(),
                ));
            }
        }
        let maker_required = match maker.kind {
            ReservationKind::Cash => cash,
            ReservationKind::Securities => fill.quantity,
        };
        let taker_required = match taker.kind {
            ReservationKind::Cash => cash,
            ReservationKind::Securities => fill.quantity,
        };
        if maker.status != ReservationStatus::Active || maker.remaining < maker_required {
            return Err(SettlementError::Reservation(
                "maker reservation cannot cover the fill".into(),
            ));
        }
        if taker.status != ReservationStatus::Active || taker.remaining < taker_required {
            return Err(SettlementError::Reservation(
                "taker reservation cannot cover the fill".into(),
            ));
        }
        let (seller_handle, buyer_handle) = match maker.kind {
            ReservationKind::Securities => (maker.participant_handle, taker.participant_handle),
            ReservationKind::Cash => (taker.participant_handle, maker.participant_handle),
        };
        let maker_kind = maker.kind;
        let maker_reserve_commitment = maker.reserve_commitment;
        let taker_reserve_commitment = taker.reserve_commitment;

        let maker = self.records.get_mut(&maker_id).expect("looked up maker");
        consume_record(maker, maker_required, fill.quantity)?;
        let maker_remaining = maker.remaining;
        let taker = self.records.get_mut(&taker_id).expect("looked up taker");
        consume_record(taker, taker_required, fill.quantity)?;
        Ok(ConsumedFill {
            maker_reservation_id: maker_id,
            taker_reservation_id: taker_id,
            maker_kind,
            maker_reserve_commitment,
            taker_reserve_commitment,
            maker_remaining,
            taker_remaining: taker.remaining,
            seller_handle,
            buyer_handle,
        })
    }

    fn apply_collaborative_remainders(
        &mut self,
        consumed: ConsumedFill,
        securities_remainder: RistrettoPoint,
        cash_remainder: RistrettoPoint,
        maker_pool_remainder: RistrettoPoint,
    ) -> Result<(), SettlementError> {
        let (maker_remainder, taker_remainder) = match consumed.maker_kind {
            ReservationKind::Securities => (maker_pool_remainder, cash_remainder),
            ReservationKind::Cash => (maker_pool_remainder, securities_remainder),
        };
        let maker = self
            .records
            .get_mut(&consumed.maker_reservation_id)
            .ok_or_else(|| SettlementError::Reservation("maker reservation disappeared".into()))?;
        maker.reserve_commitment = maker_remainder;
        let taker = self
            .records
            .get_mut(&consumed.taker_reservation_id)
            .ok_or_else(|| SettlementError::Reservation("taker reservation disappeared".into()))?;
        taker.reserve_commitment = taker_remainder;
        Ok(())
    }

    fn reconcile_arriving<O: SettlementOrderView + ?Sized>(
        &mut self,
        order: &O,
        remaining_quantity: u64,
    ) -> Result<u64, SettlementError> {
        let id = self
            .record_id_for(order.settlement_commitment().0)
            .ok_or_else(|| SettlementError::Reservation("taker reservation is absent".into()))?;
        let required = if remaining_quantity == 0
            || order.settlement_time_in_force() == TimeInForce::ImmediateOrCancel
        {
            0
        } else {
            match order.settlement_side() {
                Side::Buy => order
                    .settlement_limit_price()
                    .checked_mul(remaining_quantity)
                    .and_then(|value| value.checked_add(order.settlement_max_fee()))
                    .ok_or_else(|| {
                        SettlementError::Reservation("remaining cash reservation overflowed".into())
                    })?,
                Side::Sell => remaining_quantity,
            }
        };
        let record = self.records.get_mut(&id).expect("looked up reservation");
        if remaining_quantity != record.remaining_quantity {
            return Err(SettlementError::Reservation(
                "reported arriving remainder differs from consumed fills".into(),
            ));
        }
        if record.remaining < required {
            return Err(SettlementError::Reservation(
                "remaining order is not covered by its reservation".into(),
            ));
        }
        let unused = record.remaining.saturating_sub(required);
        record.remaining = required;
        record.remaining_quantity = if required > 0 { remaining_quantity } else { 0 };
        record.status = if required > 0 {
            ReservationStatus::Active
        } else if unused > 0 {
            ReservationStatus::Released
        } else {
            ReservationStatus::Consumed
        };
        Ok(required)
    }

    /// Finalize the arriving reservation using only canonical reservation
    /// state. The MPC circuit has already applied every fill cumulatively, so
    /// no opened order body is needed after matching.
    fn reconcile_arriving_collaborative(
        &mut self,
        order_commitment: Digest32,
        remaining_quantity: u64,
    ) -> Result<u64, SettlementError> {
        let id = self
            .record_id_for(order_commitment)
            .ok_or_else(|| SettlementError::Reservation("taker reservation is absent".into()))?;
        let record = self.records.get_mut(&id).expect("looked up reservation");
        if remaining_quantity != record.remaining_quantity {
            return Err(SettlementError::Reservation(
                "reported arriving remainder differs from consumed fills".into(),
            ));
        }
        if remaining_quantity == 0 || record.time_in_force == TimeInForce::ImmediateOrCancel {
            record.remaining = 0;
            record.remaining_quantity = 0;
            record.status = if remaining_quantity == 0 {
                ReservationStatus::Consumed
            } else {
                ReservationStatus::Released
            };
            return Ok(0);
        }
        record.status = ReservationStatus::Active;
        Ok(record.remaining)
    }

    fn record_id_for(&self, commitment: Digest32) -> Option<Digest32> {
        self.records
            .values()
            .find(|record| record.order_commitment == commitment)
            .map(|record| record.reservation_id)
    }

    fn release_order(&mut self, commitment: Digest32) -> Result<(), SettlementError> {
        let id = self
            .record_id_for(commitment)
            .ok_or_else(|| SettlementError::Reservation("reservation is absent".into()))?;
        let record = self.records.get_mut(&id).expect("looked up reservation");
        if record.status != ReservationStatus::Active {
            return Err(SettlementError::Reservation(
                "reservation is already terminal".into(),
            ));
        }
        record.remaining = 0;
        record.remaining_quantity = 0;
        record.status = ReservationStatus::Released;
        Ok(())
    }

    fn root(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(b"OCLOB:DEFMI-RESERVATIONS:v3");
        for ((entity, kind), capacity) in &self.capacities {
            hash.update(entity);
            hash.update([*kind]);
            hash.update(capacity.to_be_bytes());
        }
        for (participant, entity) in &self.participant_entities {
            hash.update(participant);
            hash.update(entity);
        }
        for record in self.records.values() {
            hash.update(record.reservation_id);
            hash.update(record.order_commitment);
            hash.update(record.participant_handle);
            hash.update(record.entity_nullifier);
            hash.update((record.market_id.len() as u64).to_be_bytes());
            hash.update(record.market_id.as_bytes());
            hash.update([reservation_kind_tag(record.kind)]);
            hash.update(record.limit_price.to_be_bytes());
            hash.update([time_in_force_tag(record.time_in_force)]);
            hash.update(record.original_quantity.to_be_bytes());
            hash.update(record.remaining_quantity.to_be_bytes());
            hash.update(record.max_fee.to_be_bytes());
            hash.update(record.expires_at.to_be_bytes());
            hash.update(record.reserved.to_be_bytes());
            hash.update(record.remaining.to_be_bytes());
            hash.update(record.reserve_commitment.compress().as_bytes());
            hash.update([reservation_status_tag(record.status)]);
        }
        hash.finalize().into()
    }
}

fn consume_record(
    record: &mut ReservationRecord,
    spent: u64,
    filled_quantity: u64,
) -> Result<(), SettlementError> {
    let remaining_after_spend = record
        .remaining
        .checked_sub(spent)
        .ok_or_else(|| SettlementError::Reservation("reservation cannot cover the fill".into()))?;
    let remaining_quantity = record
        .remaining_quantity
        .checked_sub(filled_quantity)
        .ok_or_else(|| SettlementError::Reservation("fill exceeds the order remainder".into()))?;
    let required = if remaining_quantity == 0 {
        0
    } else {
        match record.kind {
            ReservationKind::Cash => record
                .limit_price
                .checked_mul(remaining_quantity)
                .and_then(|value| value.checked_add(record.max_fee))
                .ok_or_else(|| {
                    SettlementError::Reservation("remaining cash reservation overflowed".into())
                })?,
            ReservationKind::Securities => remaining_quantity,
        }
    };
    if remaining_after_spend < required {
        return Err(SettlementError::Reservation(
            "reservation no longer covers the committed order remainder".into(),
        ));
    }
    record.remaining_quantity = remaining_quantity;
    record.remaining = required;
    record.status = if remaining_quantity == 0 {
        ReservationStatus::Consumed
    } else {
        ReservationStatus::Active
    };
    Ok(())
}

#[derive(Clone, Copy)]
struct ConsumedFill {
    maker_reservation_id: Digest32,
    taker_reservation_id: Digest32,
    maker_kind: ReservationKind,
    maker_reserve_commitment: RistrettoPoint,
    taker_reserve_commitment: RistrettoPoint,
    maker_remaining: u64,
    taker_remaining: u64,
    seller_handle: Digest32,
    buyer_handle: Digest32,
}

#[derive(Clone, Copy)]
struct ConfidentialBalance {
    value: u64,
    commitment: RistrettoPoint,
    opening: Option<Scalar>,
}

impl ConfidentialBalance {
    fn opened(key: &Pedersen, value: u64, opening: Scalar) -> Self {
        Self {
            value,
            commitment: key.commit_u64(value, &opening),
            opening: Some(opening),
        }
    }

    fn commitment_only(value: u64, commitment: RistrettoPoint) -> Self {
        Self {
            value,
            commitment,
            opening: None,
        }
    }
}

#[derive(Clone, Copy)]
struct ParticipantBalances {
    handle: Handle,
    securities: ConfidentialBalance,
    cash: ConfidentialBalance,
}

pub struct SettlementEngine {
    key: Pedersen,
    signing_shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key: frost::keys::PublicKeyPackage,
    collaborative_public_key: Option<frost::keys::PublicKeyPackage>,
    participants: BTreeMap<Digest32, ParticipantBalances>,
    demo_handles: (Digest32, Digest32),
    reservations: ReservationBook,
    spent_instructions: BTreeSet<Digest32>,
    transition_committee_trust_root: Digest32,
    height: u64,
}

impl Clone for SettlementEngine {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            signing_shares: self.signing_shares.clone(),
            public_key: self.public_key.clone(),
            collaborative_public_key: self.collaborative_public_key.clone(),
            participants: self.participants.clone(),
            demo_handles: self.demo_handles,
            reservations: self.reservations.clone(),
            spent_instructions: self.spent_instructions.clone(),
            transition_committee_trust_root: self.transition_committee_trust_root,
            height: self.height,
        }
    }
}

impl SettlementEngine {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, SettlementError> {
        let committee = OrderingCommittee::deterministic_for_demo()
            .map_err(|error| SettlementError::Proof(error.to_string()))?;
        Self::new_with_transition_committee(rng, &committee.verifying_keys(), committee.policy())
    }

    pub fn new_with_transition_committee<R: RngCore + CryptoRng>(
        rng: &mut R,
        keys: &BTreeMap<u16, ed25519_dalek::VerifyingKey>,
        policy: CommitteePolicy,
    ) -> Result<Self, SettlementError> {
        let transition_committee_trust_root = committee_trust_root(keys, policy)
            .map_err(|error| SettlementError::Proof(error.to_string()))?;
        let key = Pedersen::new(b"qomm:defmi:v1");
        let (signing_shares, public_key) =
            distributed_key_generation(7, 3, rng).map_err(SettlementError::Cryptography)?;
        let first = Identity::from_seed([11; 32]).handle(VENUE_DOMAIN);
        let second = Identity::from_seed([22; 32]).handle(VENUE_DOMAIN);
        let first_securities = ConfidentialBalance::opened(&key, 10_000, Scalar::random(&mut *rng));
        let first_cash = ConfidentialBalance::opened(&key, 100_000_000, Scalar::random(&mut *rng));
        let second_securities =
            ConfidentialBalance::opened(&key, 10_000, Scalar::random(&mut *rng));
        let second_cash = ConfidentialBalance::opened(&key, 100_000_000, Scalar::random(&mut *rng));
        let first_handle = *first.point.compress().as_bytes();
        let second_handle = *second.point.compress().as_bytes();
        let participants = BTreeMap::from([
            (
                first_handle,
                ParticipantBalances {
                    handle: first,
                    securities: first_securities,
                    cash: first_cash,
                },
            ),
            (
                second_handle,
                ParticipantBalances {
                    handle: second,
                    securities: second_securities,
                    cash: second_cash,
                },
            ),
        ]);
        Ok(Self {
            key,
            signing_shares,
            public_key,
            collaborative_public_key: None,
            participants,
            demo_handles: (first_handle, second_handle),
            reservations: ReservationBook::default(),
            spent_instructions: BTreeSet::new(),
            transition_committee_trust_root,
            height: 0,
        })
    }

    /// Pin the public key of the MPC settlement committee before any DeFMI
    /// state exists. A proof-carried key is never accepted as its own trust
    /// root, and the pin cannot be rotated through an order submission.
    pub fn pin_collaborative_settlement_committee(
        &mut self,
        public_key: frost::keys::PublicKeyPackage,
    ) -> Result<(), SettlementError> {
        if self.height != 0
            || !self.reservations.records.is_empty()
            || !self.spent_instructions.is_empty()
        {
            return Err(SettlementError::Proof(
                "the MPC settlement committee must be pinned at DeFMI genesis".into(),
            ));
        }
        let encoded = public_key.serialize().map_err(|_| {
            SettlementError::Proof("MPC settlement public key is not serializable".into())
        })?;
        if encoded.is_empty() {
            return Err(SettlementError::Proof(
                "MPC settlement public key is empty".into(),
            ));
        }
        if let Some(existing) = &self.collaborative_public_key {
            let existing = existing.serialize().map_err(|_| {
                SettlementError::Proof("pinned MPC settlement key is not serializable".into())
            })?;
            if existing != encoded {
                return Err(SettlementError::Proof(
                    "the MPC settlement committee is already pinned".into(),
                ));
            }
            return Ok(());
        }
        self.collaborative_public_key = Some(public_key);
        Ok(())
    }

    pub fn reserve_order<O: SettlementOrderView + ?Sized>(
        &mut self,
        order: &O,
    ) -> Result<ReservationReceipt, SettlementError> {
        let commitment = self.key.commit_u64(
            order.settlement_reservation_limit(),
            &Scalar::random(&mut OsRng),
        );
        self.reserve_order_with_commitment(order, commitment)
    }

    /// Reserve an order under the exact VSS commitment accepted from the
    /// participant edge. The commitment becomes part of canonical reservation
    /// state and is the pre-state consumed by collaborative DvP proofs.
    pub fn reserve_order_with_commitment<O: SettlementOrderView + ?Sized>(
        &mut self,
        order: &O,
        reserve_commitment: RistrettoPoint,
    ) -> Result<ReservationReceipt, SettlementError> {
        let before_root = self.reservations.root();
        let mut staged = self.reservations.clone();
        let mut receipt = staged.reserve(order, reserve_commitment)?;
        let height = self
            .height
            .checked_add(1)
            .ok_or_else(|| SettlementError::Reservation("DeFMI height exhausted".into()))?;
        receipt.canonical_height = height;
        receipt.canonical_receipt_digest = reservation_receipt_digest(
            b"reserve",
            receipt.order_commitment,
            before_root,
            receipt.state_root,
            height,
        );
        self.reservations = staged;
        self.height = height;
        Ok(receipt)
    }

    /// Binds an anonymous DeKYX legal-entity nullifier to one settlement handle
    /// and exposes only that binding to the canonical reservation state.  A
    /// second handle cannot claim the same entity capacity, and one handle
    /// cannot switch entities after admission.
    pub fn bind_eligible_participant(
        &mut self,
        participant_handle: Digest32,
        entity_nullifier: Digest32,
    ) -> Result<(), SettlementError> {
        let balances = self
            .participants
            .get(&participant_handle)
            .copied()
            .ok_or_else(|| SettlementError::Reservation("participant account is absent".into()))?;
        self.reservations.bind_participant(
            participant_handle,
            entity_nullifier,
            balances.cash.value,
            balances.securities.value,
        )
    }

    pub fn release_order(
        &mut self,
        order_commitment: Digest32,
    ) -> Result<ReservationReleaseReceipt, SettlementError> {
        let before_root = self.reservations.root();
        let mut staged = self.reservations.clone();
        staged.release_order(order_commitment)?;
        let after_root = staged.root();
        let height = self
            .height
            .checked_add(1)
            .ok_or_else(|| SettlementError::Reservation("DeFMI height exhausted".into()))?;
        let canonical_receipt_digest = reservation_receipt_digest(
            b"release",
            order_commitment,
            before_root,
            after_root,
            height,
        );
        self.reservations = staged;
        self.height = height;
        Ok(ReservationReleaseReceipt {
            order_commitment,
            before_root,
            after_root,
            canonical_receipt_digest,
            canonical_height: height,
        })
    }

    pub fn release_orders_atomic(
        &mut self,
        order_commitments: &[Digest32],
    ) -> Result<ReservationBatchReleaseReceipt, SettlementError> {
        if order_commitments.is_empty() {
            return Err(SettlementError::Reservation(
                "reservation release batch cannot be empty".into(),
            ));
        }
        let before_root = self.reservations.root();
        let mut staged = self.reservations.clone();
        for commitment in order_commitments {
            staged.release_order(*commitment)?;
        }
        let after_root = staged.root();
        let height = self
            .height
            .checked_add(1)
            .ok_or_else(|| SettlementError::Reservation("DeFMI height exhausted".into()))?;
        let batch_id: Digest32 = Sha256::new()
            .chain_update(b"OCLOB:RESERVATION-RELEASE-BATCH:v1")
            .chain_update((order_commitments.len() as u64).to_be_bytes())
            .chain_update(
                order_commitments
                    .iter()
                    .flatten()
                    .copied()
                    .collect::<Vec<_>>(),
            )
            .finalize()
            .into();
        let canonical_receipt_digest =
            reservation_receipt_digest(b"release-batch", batch_id, before_root, after_root, height);
        self.reservations = staged;
        self.height = height;
        Ok(ReservationBatchReleaseReceipt {
            order_commitments: order_commitments.to_vec(),
            before_root,
            after_root,
            canonical_receipt_digest,
            canonical_height: height,
        })
    }

    pub fn demo_participant_handles(&self) -> (Digest32, Digest32) {
        self.demo_handles
    }

    pub fn state_snapshot(&self) -> SettlementStateSnapshot {
        let (securities, cash) = self.ledgers();
        SettlementStateSnapshot {
            securities_root: securities.snapshot(),
            cash_root: cash.snapshot(),
            reservation_root: self.reservations.root(),
            height: self.height,
        }
    }

    pub fn participant_portfolio(
        &self,
        participant_handle: Digest32,
    ) -> Result<ParticipantPortfolio, SettlementError> {
        let balances = self
            .participants
            .get(&participant_handle)
            .copied()
            .ok_or_else(|| SettlementError::Reservation("participant account is absent".into()))?;
        let reserved_securities = self
            .reservations
            .reserved_for(participant_handle, ReservationKind::Securities)?;
        let reserved_cash = self
            .reservations
            .reserved_for(participant_handle, ReservationKind::Cash)?;
        Ok(ParticipantPortfolio {
            securities: balances.securities.value,
            cash: balances.cash.value,
            reserved_securities,
            reserved_cash,
            available_securities: balances
                .securities
                .value
                .saturating_sub(reserved_securities),
            available_cash: balances.cash.value.saturating_sub(reserved_cash),
        })
    }

    /// Public commitment-only account bootstrap for canonical DeFMI. No
    /// balance opening, participant identity, price, quantity or blinding is
    /// returned.
    pub fn canonical_account_openings(
        &self,
        market_id: &str,
    ) -> Result<Vec<CanonicalAccountOpening>, SettlementError> {
        if market_id.is_empty() || market_id.len() > 64 {
            return Err(SettlementError::Reservation(
                "canonical market identifier is invalid".into(),
            ));
        }
        let (securities, cash) = self.ledgers();
        let securities_asset = canonical_securities_asset_id(market_id);
        let cash_asset = canonical_cash_asset_id();
        let mut accounts = Vec::with_capacity(self.participants.len() * 2 + 1);
        for balances in self.participants.values() {
            for (rail, asset_id, ledger) in [
                (SECURITIES_RAIL, securities_asset, &securities),
                (CASH_RAIL, cash_asset, &cash),
            ] {
                let raw_handle = account_of(&balances.handle.point, rail);
                let handle: Digest32 = raw_handle.try_into().map_err(|_| {
                    SettlementError::Finality("canonical account handle is not 32 bytes".into())
                })?;
                let commitment = ledger
                    .balance(&handle)
                    .ok_or(SettlementError::CanonicalDivergence)?
                    .compress()
                    .to_bytes();
                accounts.push(CanonicalAccountOpening {
                    handle,
                    asset_id,
                    commitment,
                });
            }
        }
        accounts.push(CanonicalAccountOpening {
            handle: canonical_reservation_state_handle(market_id),
            asset_id: canonical_reservation_state_asset_id(market_id),
            commitment: self.reservations.root(),
        });
        accounts.sort_by_key(|account| account.handle);
        if accounts
            .windows(2)
            .any(|pair| pair[0].handle == pair[1].handle)
        {
            return Err(SettlementError::CanonicalDivergence);
        }
        Ok(accounts)
    }

    fn ledgers(&self) -> (Ledger, Ledger) {
        ledgers_from_participants(&self.key, &self.participants)
    }

    /// Turn a staged no-fill order reservation into an exact canonical DeFMI
    /// compare-and-swap. The threshold zkPI authorizes the hidden maximum,
    /// while the only L1-visible state change is the reservation-ledger root.
    /// Neither the live engine nor the public book is mutated here.
    pub fn prepare_canonical_reservation<O: SettlementOrderView + ?Sized>(
        &self,
        candidate: SettlementEngine,
        mut receipt: ReservationReceipt,
        order: &O,
        certificate: &OrderCertificate,
        transition: &VerifiedTransitionProof,
        now: u64,
    ) -> Result<PreparedCanonicalTransition, SettlementError> {
        transition
            .verify_admission_binding(certificate, self.transition_committee_trust_root)
            .map_err(|error| SettlementError::Proof(error.to_string()))?;
        candidate.reservations.validate_active_order(order)?;
        let base_snapshot = self.state_snapshot();
        let candidate_snapshot = candidate.state_snapshot();
        if candidate_snapshot.height != base_snapshot.height.saturating_add(1)
            || receipt.order_commitment != order.settlement_commitment().0
            || receipt.reservation_id != order.settlement_reservation_id()
            || receipt.reserved != order.settlement_reservation_limit()
            || receipt.state_root != candidate_snapshot.reservation_root
            || candidate_snapshot.securities_root != base_snapshot.securities_root
            || candidate_snapshot.cash_root != base_snapshot.cash_root
        {
            return Err(SettlementError::CanonicalDivergence);
        }
        let account_openings = self.canonical_account_openings(order.settlement_market_id())?;
        let after_accounts = candidate.canonical_account_openings(order.settlement_market_id())?;
        let account_deltas = canonical_account_deltas(&account_openings, &after_accounts)?;
        if account_deltas.len() != 1
            || account_deltas[0].handle
                != canonical_reservation_state_handle(order.settlement_market_id())
            || account_deltas[0].asset_id
                != canonical_reservation_state_asset_id(order.settlement_market_id())
            || account_deltas[0].before_commitment != base_snapshot.reservation_root
            || account_deltas[0].after_commitment != candidate_snapshot.reservation_root
        {
            return Err(SettlementError::CanonicalDivergence);
        }
        let transition_digest = transition.digest();
        let (payment_instruction_digest, instruction_nullifier, range_proof_digest) =
            self.build_reservation_zkpi(order, transition_digest, now)?;
        let proof_digest = digest(
            b"OCLOB:DEFMI:RESERVATION-PROOF:v1",
            &[
                transition_digest.as_slice(),
                transition
                    .proof()
                    .statement
                    .eligibility_proof_digest
                    .as_slice(),
                range_proof_digest.as_slice(),
            ]
            .concat(),
        );
        let application_binding = oclob_manifest_v1()
            .digest()
            .map_err(|error| SettlementError::Finality(error.to_string()))?;
        let deadline = order.settlement_expires_at();
        let binding_digest = canonical_binding_digest(
            application_binding,
            receipt.order_commitment,
            transition_digest,
            payment_instruction_digest,
            proof_digest,
            base_snapshot.reservation_root,
            candidate_snapshot.reservation_root,
            &account_deltas,
        );
        receipt.zkpi_digest = Some(payment_instruction_digest);
        receipt.instruction_nullifier = Some(instruction_nullifier);
        receipt.proof_digest = Some(proof_digest);
        Ok(PreparedCanonicalTransition::Reservation(
            PreparedCanonicalReservation {
                candidate,
                base_snapshot,
                receipt,
                market_id: order.settlement_market_id().to_owned(),
                transition_digest,
                payment_instruction_digest,
                proof_digest,
                instruction_nullifier,
                application_binding,
                binding_digest,
                account_openings,
                account_deltas,
                deadline,
            },
        ))
    }

    fn build_reservation_zkpi<O: SettlementOrderView + ?Sized>(
        &self,
        order: &O,
        transition_digest: Digest32,
        now: u64,
    ) -> Result<(Digest32, Digest32, Digest32), SettlementError> {
        if order.settlement_expires_at() < now
            || order.settlement_expires_at() > now.saturating_add(3_600)
        {
            return Err(SettlementError::Reservation(
                "canonical reservation expiry is outside the one-hour zkPI horizon".into(),
            ));
        }
        let participant = self
            .participants
            .get(&order.settlement_participant_handle())
            .ok_or_else(|| SettlementError::Reservation("participant account is absent".into()))?;
        let mut rng = OsRng;
        let amount_blinding = Scalar::random(&mut rng);
        let price_blinding = Scalar::random(&mut rng);
        let amount = deal_bits(
            &self.key,
            order.settlement_reservation_limit(),
            &amount_blinding,
            RANGE_BITS,
            &PROOF_PARTIES,
            PROOF_THRESHOLD,
            &mut rng,
        )
        .map_err(SettlementError::Proof)?;
        let price = deal_bits(
            &self.key,
            1,
            &price_blinding,
            RANGE_BITS,
            &PROOF_PARTIES,
            PROOF_THRESHOLD,
            &mut rng,
        )
        .map_err(SettlementError::Proof)?;
        let amount_range = prove_range(&self.key, &amount, AMOUNT_RANGE_CONTEXT, &mut rng)?;
        let price_range = prove_range(&self.key, &price, PRICE_RANGE_CONTEXT, &mut rng)?;
        let asset_index = match order.settlement_side() {
            Side::Buy => 0,
            Side::Sell => ASSET_INDEX,
        };
        let asset_commitment = self
            .key
            .commit(&Scalar::from(asset_index as u64), &Scalar::random(&mut rng));
        let escrow_scalar = Scalar::from_bytes_mod_order(digest(
            b"OCLOB:DEFMI:RESERVATION-HANDLE:v1",
            &order.settlement_reservation_id(),
        ));
        let escrow_handle = self.key.g * escrow_scalar;
        let nonce = digest(
            b"OCLOB:ZKPI:RESERVATION-NONCE:v1",
            &[
                order.settlement_commitment().0.as_slice(),
                transition_digest.as_slice(),
            ]
            .concat(),
        );
        let bounds = Bounds {
            amount_bits: RANGE_BITS,
            price_bits: RANGE_BITS,
            max_horizon: 3_600,
        };
        let partial = PartialInstruction::from_threshold_ranges(
            &self.key,
            &bounds,
            amount.commitment,
            price.commitment,
            asset_commitment,
            amount_range,
            price_range,
            participant.handle.point,
            escrow_handle,
            order.settlement_expires_at(),
            nonce,
            transition_digest,
        )
        .map_err(SettlementError::Cryptography)?;
        let signature = sign_threshold(
            &self.signing_shares,
            &self.public_key,
            &partial.digest(),
            &mut rng,
        )?;
        let instruction = partial.sealed(signature);
        Venue::new(self.key.clone(), &bounds, self.public_key.clone())
            .require_threshold_ranges()
            .verify(&instruction, now)
            .map_err(SettlementError::Cryptography)?;
        let wire = qomm_zkpi::wire::encode(&instruction);
        let payment_instruction_digest = Sha256::digest(&wire).into();
        let range_proof_digest = digest(b"OCLOB:ZKPI:RESERVATION-RANGES:v1", &wire);
        Ok((
            payment_instruction_digest,
            instruction.nullifier(),
            range_proof_digest,
        ))
    }

    /// Verify a complete MPC-produced zkPI/DvP batch against an isolated clone
    /// and return a one-use candidate for Avalanche submission. No scalar
    /// witness is reconstructed or locally reproved on this path.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_canonical_batch_collaborative<O: SettlementOrderView + ?Sized>(
        &self,
        fills: &[PublicFill],
        proofs: &[collaborative::CollaborativeFillProof],
        round_id: Digest32,
        transition: &VerifiedTransitionProof,
        arriving: &O,
        arriving_remaining: u64,
        now: u64,
    ) -> Result<PreparedCanonicalBatch, SettlementError> {
        let base_snapshot = self.state_snapshot();
        let account_openings = self.canonical_account_openings(arriving.settlement_market_id())?;
        let mut candidate = self.clone();
        let receipt = candidate.settle_batch_collaborative(
            fills,
            proofs,
            round_id,
            transition,
            arriving.settlement_commitment(),
            arriving_remaining,
            now,
        )?;
        let after_accounts =
            candidate.canonical_account_openings(arriving.settlement_market_id())?;
        let account_deltas = canonical_account_deltas(&account_openings, &after_accounts)?;
        if account_deltas.is_empty() {
            return Err(SettlementError::CanonicalDivergence);
        }
        let transition_digest = transition.digest();
        let application_binding = oclob_manifest_v1()
            .digest()
            .map_err(|error| SettlementError::Finality(error.to_string()))?;
        let payment_instruction_digest =
            digest_member_field(b"OCLOB:ZKPI-BATCH:v1", &receipt.members, |member| {
                member.zkpi_digest
            });
        let proof_digest =
            digest_member_field(b"OCLOB:DVP-PROOF-BATCH:v1", &receipt.members, |member| {
                member.package_digest
            });
        let deadline = now
            .checked_add(600)
            .ok_or_else(|| SettlementError::Finality("settlement deadline overflowed".into()))?;
        let binding_digest = canonical_binding_digest(
            application_binding,
            receipt.batch_digest,
            transition_digest,
            payment_instruction_digest,
            proof_digest,
            receipt.reservation_before_root,
            receipt.reservation_after_root,
            &account_deltas,
        );
        Ok(PreparedCanonicalBatch {
            candidate,
            base_snapshot,
            receipt,
            market_id: arriving.settlement_market_id().to_owned(),
            transition_digest,
            payment_instruction_digest,
            proof_digest,
            application_binding,
            binding_digest,
            account_openings,
            account_deltas,
            deadline,
        })
    }

    /// Verify a complete zkPI/DvP batch against an isolated clone and return a
    /// one-use candidate for Avalanche submission. The live engine remains
    /// unchanged if proof construction, RPC submission or consensus fails.
    pub fn prepare_canonical_batch<O: SettlementOrderView + ?Sized>(
        &self,
        fills: &[PublicFill],
        transition: &VerifiedTransitionProof,
        arriving: &O,
        arriving_remaining: u64,
        now: u64,
    ) -> Result<PreparedCanonicalBatch, SettlementError> {
        let base_snapshot = self.state_snapshot();
        let account_openings = self.canonical_account_openings(arriving.settlement_market_id())?;
        let mut candidate = self.clone();
        let receipt =
            candidate.settle_batch(fills, transition, arriving, arriving_remaining, now)?;
        let after_accounts =
            candidate.canonical_account_openings(arriving.settlement_market_id())?;
        let account_deltas = canonical_account_deltas(&account_openings, &after_accounts)?;
        if account_deltas.is_empty() {
            return Err(SettlementError::CanonicalDivergence);
        }
        let transition_digest = transition.digest();
        let application_binding = oclob_manifest_v1()
            .digest()
            .map_err(|error| SettlementError::Finality(error.to_string()))?;
        let payment_instruction_digest =
            digest_member_field(b"OCLOB:ZKPI-BATCH:v1", &receipt.members, |member| {
                member.zkpi_digest
            });
        let proof_digest =
            digest_member_field(b"OCLOB:DVP-PROOF-BATCH:v1", &receipt.members, |member| {
                member.package_digest
            });
        let deadline = now
            .checked_add(600)
            .ok_or_else(|| SettlementError::Finality("settlement deadline overflowed".into()))?;
        let binding_digest = canonical_binding_digest(
            application_binding,
            receipt.batch_digest,
            transition_digest,
            payment_instruction_digest,
            proof_digest,
            receipt.reservation_before_root,
            receipt.reservation_after_root,
            &account_deltas,
        );
        Ok(PreparedCanonicalBatch {
            candidate,
            base_snapshot,
            receipt,
            market_id: arriving.settlement_market_id().to_owned(),
            transition_digest,
            payment_instruction_digest,
            proof_digest,
            application_binding,
            binding_digest,
            account_openings,
            account_deltas,
            deadline,
        })
    }

    /// Prepare one filled order as a single canonical transition beginning at
    /// the currently finalized DeFMI state. The caller supplies the isolated
    /// candidate produced while validating the order; its new reservation is
    /// verified here, then consumed together with all DvP fills. Consequently
    /// neither a taker reserve nor a book mutation exists unless the complete
    /// transition reaches Avalanche finality.
    pub fn prepare_canonical_admission_batch<O: SettlementOrderView + ?Sized>(
        &self,
        admission: CanonicalAdmissionBatch<'_, O>,
    ) -> Result<PreparedCanonicalTransition, SettlementError> {
        let CanonicalAdmissionBatch {
            reserved_candidate,
            reservation_receipt,
            fills,
            transition,
            certificate,
            arriving,
            arriving_remaining,
            now,
        } = admission;
        transition
            .verify_execution_binding(
                certificate,
                arriving.settlement_commitment(),
                fills,
                self.transition_committee_trust_root,
            )
            .map_err(|error| SettlementError::Proof(error.to_string()))?;
        reserved_candidate
            .reservations
            .validate_active_order(arriving)?;

        let base_snapshot = self.state_snapshot();
        let reserved_snapshot = reserved_candidate.state_snapshot();
        if reserved_snapshot.height != base_snapshot.height.saturating_add(1)
            || reserved_snapshot.securities_root != base_snapshot.securities_root
            || reserved_snapshot.cash_root != base_snapshot.cash_root
            || reservation_receipt.order_commitment != arriving.settlement_commitment().0
            || reservation_receipt.reservation_id != arriving.settlement_reservation_id()
            || reservation_receipt.reserved != arriving.settlement_reservation_limit()
            || reservation_receipt.state_root != reserved_snapshot.reservation_root
            || reserved_candidate.spent_instructions != self.spent_instructions
        {
            return Err(SettlementError::CanonicalDivergence);
        }

        let account_openings = self.canonical_account_openings(arriving.settlement_market_id())?;
        let reserved_accounts =
            reserved_candidate.canonical_account_openings(arriving.settlement_market_id())?;
        let reservation_delta = canonical_account_deltas(&account_openings, &reserved_accounts)?;
        if reservation_delta.len() != 1
            || reservation_delta[0].handle
                != canonical_reservation_state_handle(arriving.settlement_market_id())
            || reservation_delta[0].asset_id
                != canonical_reservation_state_asset_id(arriving.settlement_market_id())
        {
            return Err(SettlementError::CanonicalDivergence);
        }

        let transition_digest = transition.digest();
        let (reservation_zkpi_digest, reservation_nullifier, reservation_range_digest) =
            self.build_reservation_zkpi(arriving, transition_digest, now)?;
        let reservation_proof_digest = digest(
            b"OCLOB:DEFMI:ADMISSION-RESERVATION-PROOF:v1",
            &[
                transition_digest.as_slice(),
                certificate.digest().as_slice(),
                transition
                    .proof()
                    .statement
                    .eligibility_proof_digest
                    .as_slice(),
                reservation_range_digest.as_slice(),
            ]
            .concat(),
        );

        let mut prepared = reserved_candidate.prepare_canonical_batch(
            fills,
            transition,
            arriving,
            arriving_remaining,
            now,
        )?;
        let after_accounts = prepared
            .candidate
            .canonical_account_openings(arriving.settlement_market_id())?;
        let account_deltas = canonical_account_deltas(&account_openings, &after_accounts)?;
        if !account_deltas.iter().any(|delta| {
            delta.handle == canonical_reservation_state_handle(arriving.settlement_market_id())
                && delta.asset_id
                    == canonical_reservation_state_asset_id(arriving.settlement_market_id())
                && delta.before_commitment == base_snapshot.reservation_root
                && delta.after_commitment == prepared.receipt.reservation_after_root
        }) {
            return Err(SettlementError::CanonicalDivergence);
        }

        let dvp_payment_digest = prepared.payment_instruction_digest;
        let dvp_proof_digest = prepared.proof_digest;
        prepared.base_snapshot = base_snapshot;
        prepared.account_openings = account_openings;
        prepared.account_deltas = account_deltas;
        prepared.receipt.reservation_before_root = base_snapshot.reservation_root;
        prepared.receipt.arriving_reservation_zkpi_digest = Some(reservation_zkpi_digest);
        prepared.receipt.arriving_reservation_instruction_nullifier = Some(reservation_nullifier);
        prepared.receipt.arriving_reservation_proof_digest = Some(reservation_proof_digest);
        prepared.payment_instruction_digest = digest(
            b"OCLOB:ZKPI-ADMISSION-AND-DVP:v1",
            &[
                reservation_zkpi_digest.as_slice(),
                dvp_payment_digest.as_slice(),
            ]
            .concat(),
        );
        prepared.proof_digest = digest(
            b"OCLOB:ADMISSION-AND-DVP-PROOF:v1",
            &[
                reservation_proof_digest.as_slice(),
                dvp_proof_digest.as_slice(),
            ]
            .concat(),
        );
        prepared.deadline = prepared.deadline.min(arriving.settlement_expires_at());
        prepared.binding_digest = canonical_binding_digest(
            prepared.application_binding,
            prepared.receipt.batch_digest,
            prepared.transition_digest,
            prepared.payment_instruction_digest,
            prepared.proof_digest,
            prepared.receipt.reservation_before_root,
            prepared.receipt.reservation_after_root,
            &prepared.account_deltas,
        );
        Ok(PreparedCanonicalTransition::Settlement(prepared))
    }

    /// Production filled-admission path. The pre-trade reservation remains
    /// atomic with matching, while the DvP portion is accepted only from the
    /// pinned MPC settlement committee's verifier-complete proofs.
    pub fn prepare_canonical_admission_batch_collaborative<O: SettlementOrderView + ?Sized>(
        &self,
        admission: CollaborativeCanonicalAdmissionBatch<'_, O>,
    ) -> Result<PreparedCanonicalTransition, SettlementError> {
        let CollaborativeCanonicalAdmissionBatch {
            reserved_candidate,
            reservation_receipt,
            fills,
            proofs,
            round_id,
            transition,
            certificate,
            arriving,
            arriving_remaining,
            now,
        } = admission;
        transition
            .verify_execution_binding(
                certificate,
                arriving.settlement_commitment(),
                fills,
                self.transition_committee_trust_root,
            )
            .map_err(|error| SettlementError::Proof(error.to_string()))?;
        reserved_candidate
            .reservations
            .validate_active_order(arriving)?;

        let base_snapshot = self.state_snapshot();
        let reserved_snapshot = reserved_candidate.state_snapshot();
        if reserved_snapshot.height != base_snapshot.height.saturating_add(1)
            || reserved_snapshot.securities_root != base_snapshot.securities_root
            || reserved_snapshot.cash_root != base_snapshot.cash_root
            || reservation_receipt.order_commitment != arriving.settlement_commitment().0
            || reservation_receipt.reservation_id != arriving.settlement_reservation_id()
            || reservation_receipt.reserved != arriving.settlement_reservation_limit()
            || reservation_receipt.state_root != reserved_snapshot.reservation_root
            || reserved_candidate.spent_instructions != self.spent_instructions
        {
            return Err(SettlementError::CanonicalDivergence);
        }

        let account_openings = self.canonical_account_openings(arriving.settlement_market_id())?;
        let reserved_accounts =
            reserved_candidate.canonical_account_openings(arriving.settlement_market_id())?;
        let reservation_delta = canonical_account_deltas(&account_openings, &reserved_accounts)?;
        if reservation_delta.len() != 1
            || reservation_delta[0].handle
                != canonical_reservation_state_handle(arriving.settlement_market_id())
            || reservation_delta[0].asset_id
                != canonical_reservation_state_asset_id(arriving.settlement_market_id())
        {
            return Err(SettlementError::CanonicalDivergence);
        }

        let transition_digest = transition.digest();
        let (reservation_zkpi_digest, reservation_nullifier, reservation_range_digest) =
            self.build_reservation_zkpi(arriving, transition_digest, now)?;
        let reservation_proof_digest = digest(
            b"OCLOB:DEFMI:ADMISSION-RESERVATION-PROOF:v1",
            &[
                transition_digest.as_slice(),
                certificate.digest().as_slice(),
                transition
                    .proof()
                    .statement
                    .eligibility_proof_digest
                    .as_slice(),
                reservation_range_digest.as_slice(),
            ]
            .concat(),
        );

        let mut prepared = reserved_candidate.prepare_canonical_batch_collaborative(
            fills,
            proofs,
            round_id,
            transition,
            arriving,
            arriving_remaining,
            now,
        )?;
        let after_accounts = prepared
            .candidate
            .canonical_account_openings(arriving.settlement_market_id())?;
        let account_deltas = canonical_account_deltas(&account_openings, &after_accounts)?;
        if !account_deltas.iter().any(|delta| {
            delta.handle == canonical_reservation_state_handle(arriving.settlement_market_id())
                && delta.asset_id
                    == canonical_reservation_state_asset_id(arriving.settlement_market_id())
                && delta.before_commitment == base_snapshot.reservation_root
                && delta.after_commitment == prepared.receipt.reservation_after_root
        }) {
            return Err(SettlementError::CanonicalDivergence);
        }

        let dvp_payment_digest = prepared.payment_instruction_digest;
        let dvp_proof_digest = prepared.proof_digest;
        prepared.base_snapshot = base_snapshot;
        prepared.account_openings = account_openings;
        prepared.account_deltas = account_deltas;
        prepared.receipt.reservation_before_root = base_snapshot.reservation_root;
        prepared.receipt.arriving_reservation_zkpi_digest = Some(reservation_zkpi_digest);
        prepared.receipt.arriving_reservation_instruction_nullifier = Some(reservation_nullifier);
        prepared.receipt.arriving_reservation_proof_digest = Some(reservation_proof_digest);
        prepared.payment_instruction_digest = digest(
            b"OCLOB:ZKPI-ADMISSION-AND-DVP:v2",
            &[
                reservation_zkpi_digest.as_slice(),
                dvp_payment_digest.as_slice(),
            ]
            .concat(),
        );
        prepared.proof_digest = digest(
            b"OCLOB:ADMISSION-AND-COLLABORATIVE-DVP-PROOF:v1",
            &[
                reservation_proof_digest.as_slice(),
                dvp_proof_digest.as_slice(),
            ]
            .concat(),
        );
        prepared.deadline = prepared.deadline.min(arriving.settlement_expires_at());
        prepared.binding_digest = canonical_binding_digest(
            prepared.application_binding,
            prepared.receipt.batch_digest,
            prepared.transition_digest,
            prepared.payment_instruction_digest,
            prepared.proof_digest,
            prepared.receipt.reservation_before_root,
            prepared.receipt.reservation_after_root,
            &prepared.account_deltas,
        );
        Ok(PreparedCanonicalTransition::Settlement(prepared))
    }

    /// Settle an MPC-produced batch without reconstructing any amount, price,
    /// reserve, balance, or blinding witness at the coordinator. The signed
    /// public fill list remains the post-trade market record; the authoritative
    /// account transition is derived only from verifier-complete commitments
    /// and proofs emitted by the seven proof parties.
    #[allow(clippy::too_many_arguments)]
    pub fn settle_batch_collaborative(
        &mut self,
        fills: &[PublicFill],
        proofs: &[collaborative::CollaborativeFillProof],
        round_id: Digest32,
        transition: &VerifiedTransitionProof,
        arriving: OrderCommitment,
        arriving_remaining: u64,
        now: u64,
    ) -> Result<OclobSettlementReceipt, SettlementError> {
        if fills.is_empty()
            || fills.len() != proofs.len()
            || fills.len() > oclob_core::MAX_MATCH_SLOTS
            || round_id == [0; 32]
            || fills
                .iter()
                .any(|fill| fill.quantity == 0 || fill.price == 0)
            || fills.iter().any(|fill| fill.taker_order != arriving)
        {
            return Err(SettlementError::InvalidFill);
        }
        let arriving_id = self
            .reservations
            .record_id_for(arriving.0)
            .ok_or_else(|| SettlementError::Reservation("taker reservation is absent".into()))?;
        let arriving_record = self
            .reservations
            .records
            .get(&arriving_id)
            .cloned()
            .ok_or_else(|| SettlementError::Reservation("taker reservation is absent".into()))?;
        if arriving_record.status != ReservationStatus::Active || arriving_record.expires_at < now {
            return Err(SettlementError::Reservation(
                "an inactive or expired arriving reservation cannot settle".into(),
            ));
        }
        let filled_quantity = fills.iter().try_fold(0_u64, |total, fill| {
            total
                .checked_add(fill.quantity)
                .ok_or_else(|| SettlementError::Reservation("fill quantity overflowed".into()))
        })?;
        if filled_quantity
            .checked_add(arriving_remaining)
            .is_none_or(|total| total != arriving_record.original_quantity)
        {
            return Err(SettlementError::Reservation(
                "fills and arriving remainder do not conserve order quantity".into(),
            ));
        }
        let mut maker_orders = BTreeSet::new();
        if fills
            .iter()
            .any(|fill| !maker_orders.insert(fill.maker_order))
        {
            return Err(SettlementError::Reservation(
                "one resting order cannot appear twice in an atomic match batch".into(),
            ));
        }
        transition
            .verify_settlement_binding(
                &arriving_record.market_id,
                arriving,
                fills,
                self.transition_committee_trust_root,
            )
            .map_err(|error| SettlementError::Proof(error.to_string()))?;
        let market_proof_digest = transition.proof().statement.mpc_output_digest;
        if market_proof_digest == [0; 32] {
            return Err(SettlementError::Proof(
                "transition omitted the MPC public-output digest".into(),
            ));
        }
        let frost_public = self.collaborative_public_key.as_ref().ok_or_else(|| {
            SettlementError::Proof("MPC settlement committee is not pinned in DeFMI".into())
        })?;
        let reservation_before_root = self.reservations.root();
        let mut staged_reservations = self.reservations.clone();
        let mut staged_participants = self.participants.clone();
        let mut staged_spent = self.spent_instructions.clone();
        let mut members = Vec::with_capacity(fills.len());
        let (initial_securities, initial_cash) = self.ledgers();
        let securities_before = initial_securities.snapshot();
        let cash_before = initial_cash.snapshot();
        let transition_digest = transition.digest();

        for (index, (fill, proof)) in fills.iter().zip(proofs).enumerate() {
            let consumed =
                staged_reservations.consume_fill(fill, &arriving_record.market_id, now)?;
            if consumed.seller_handle == consumed.buyer_handle {
                return Err(SettlementError::Reservation(
                    "self-trading orders cannot produce a DvP between one account".into(),
                ));
            }
            let seller = staged_participants
                .get(&consumed.seller_handle)
                .copied()
                .ok_or_else(|| SettlementError::Reservation("seller account is absent".into()))?;
            let buyer = staged_participants
                .get(&consumed.buyer_handle)
                .copied()
                .ok_or_else(|| SettlementError::Reservation("buyer account is absent".into()))?;
            let (maker_handle, taker_handle, expected_direction) = match consumed.maker_kind {
                ReservationKind::Securities => (
                    seller.handle.point,
                    buyer.handle.point,
                    qomm_proofs::price_limit::PriceLimitDirection::MaximumBuyPrice,
                ),
                ReservationKind::Cash => (
                    buyer.handle.point,
                    seller.handle.point,
                    qomm_proofs::price_limit::PriceLimitDirection::MinimumSellPrice,
                ),
            };
            if proof.limit_direction != expected_direction {
                return Err(SettlementError::Proof(
                    "MPC limit proof has the opposite Taker direction".into(),
                ));
            }
            let expected_job_id =
                collaborative::collaborative_job_id(round_id, index, market_proof_digest)
                    .map_err(SettlementError::Proof)?;
            let package = proof
                .verify_for_settlement(
                    &self.key,
                    collaborative::CollaborativeSettlementContext {
                        expected_job_id,
                        market_proof_digest,
                        maker_handle,
                        taker_handle,
                        maker_reserve: consumed.maker_reserve_commitment,
                        taker_reserve: consumed.taker_reserve_commitment,
                        asset_id: canonical_securities_asset_id(&arriving_record.market_id),
                        frost_public,
                        now,
                    },
                )
                .map_err(SettlementError::Proof)?;
            staged_reservations.apply_collaborative_remainders(
                consumed,
                package.securities_remainder,
                package.cash_remainder,
                proof.maker_pool_remainder,
            )?;

            let package_digest = package.digest();
            let instruction_nullifier = package.instruction.nullifier();
            if !staged_spent.insert(instruction_nullifier) {
                return Err(SettlementError::ReplayAccepted);
            }
            let cash_value = fill
                .price
                .checked_mul(fill.quantity)
                .ok_or_else(|| SettlementError::Reservation("cash fill overflowed".into()))?;
            let seller_securities = checked_debit(seller.securities.value, fill.quantity)?;
            let buyer_cash = checked_debit(buyer.cash.value, cash_value)?;
            let mut seller_after = seller;
            seller_after.securities = ConfidentialBalance::commitment_only(
                seller_securities,
                seller.securities.commitment - package.instruction.amount_commitment,
            );
            seller_after.cash = ConfidentialBalance::commitment_only(
                checked_credit(seller.cash.value, cash_value)?,
                seller.cash.commitment + package.cash_commitment,
            );
            let mut buyer_after = buyer;
            buyer_after.cash = ConfidentialBalance::commitment_only(
                buyer_cash,
                buyer.cash.commitment - package.cash_commitment,
            );
            buyer_after.securities = ConfidentialBalance::commitment_only(
                checked_credit(buyer.securities.value, fill.quantity)?,
                buyer.securities.commitment + package.instruction.amount_commitment,
            );
            staged_participants.insert(consumed.seller_handle, seller_after);
            staged_participants.insert(consumed.buyer_handle, buyer_after);
            let (staged_securities, staged_cash) =
                ledgers_from_participants(&self.key, &staged_participants);
            if !staged_securities.conserved() || !staged_cash.conserved() {
                return Err(SettlementError::Insolvent);
            }
            let zkpi_digest: Digest32 =
                Sha256::digest(qomm_zkpi::wire::encode(&package.instruction)).into();
            members.push(OclobSettlementMemberReceipt {
                instruction_nullifier,
                zkpi_digest,
                package_digest,
                maker_order: fill.maker_order.0,
                taker_order: fill.taker_order.0,
                maker_reservation_remaining: consumed.maker_remaining,
                taker_reservation_remaining: consumed.taker_remaining,
            });
        }

        let taker_reservation_remaining =
            staged_reservations.reconcile_arriving_collaborative(arriving.0, arriving_remaining)?;
        if let Some(last) = members.last_mut() {
            last.taker_reservation_remaining = taker_reservation_remaining;
        }
        for (participant, balances) in &staged_participants {
            staged_reservations.refresh_capacity(
                *participant,
                balances.cash.value,
                balances.securities.value,
            )?;
        }
        let reservation_after_root = staged_reservations.root();
        let (final_securities, final_cash) =
            ledgers_from_participants(&self.key, &staged_participants);
        let securities_after = final_securities.snapshot();
        let cash_after = final_cash.snapshot();
        if !final_securities.conserved() || !final_cash.conserved() {
            return Err(SettlementError::Insolvent);
        }
        let replay_rejected = staged_spent.len() == self.spent_instructions.len() + fills.len();
        if !replay_rejected {
            return Err(SettlementError::ReplayAccepted);
        }
        let batch_digest = settlement_batch_digest(transition_digest, &members);
        let before_root = combined_root(securities_before, cash_before, reservation_before_root);
        let after_root = combined_root(securities_after, cash_after, reservation_after_root);
        self.height = self
            .height
            .checked_add(1)
            .ok_or_else(|| SettlementError::Reservation("DeFMI height exhausted".into()))?;
        let block_id = hex::encode(
            Sha256::new()
                .chain_update(b"OCLOB:DEFMI-BLOCK:v1")
                .chain_update(batch_digest)
                .chain_update(after_root)
                .finalize(),
        );
        let canonical = CanonicalTransition {
            transaction_id: hex::encode(batch_digest),
            block_id,
            height: self.height,
            statement: transition_digest,
            before_state_root: before_root,
            after_state_root: after_root,
        };
        let readbacks = [
            CanonicalReadback::new(
                ReadbackKind::Account,
                resource_id(b"OCLOB:SECURITIES-RAIL"),
                after_root,
            )
            .map_err(|error| SettlementError::Finality(error.to_string()))?,
            CanonicalReadback::new(
                ReadbackKind::Account,
                resource_id(b"OCLOB:CASH-RAIL"),
                after_root,
            )
            .map_err(|error| SettlementError::Finality(error.to_string()))?,
        ];
        let application_binding = oclob_manifest_v1()
            .digest()
            .map_err(|error| SettlementError::Finality(error.to_string()))?;
        let finality = accept_canonical_transition(
            application_binding,
            &canonical,
            transition_digest,
            before_root,
            &readbacks,
        )
        .map_err(|error| SettlementError::Finality(error.to_string()))?;
        self.reservations = staged_reservations;
        self.participants = staged_participants;
        self.spent_instructions = staged_spent;
        Ok(OclobSettlementReceipt {
            batch_digest,
            members,
            amount_range_is_threshold: true,
            price_range_is_threshold: true,
            settlement_authorization_quorum: 3,
            post_match_participant_signatures: 0,
            securities_before_root: securities_before,
            securities_after_root: securities_after,
            cash_before_root: cash_before,
            cash_after_root: cash_after,
            reservation_before_root,
            reservation_after_root,
            arriving_reservation_zkpi_digest: None,
            arriving_reservation_instruction_nullifier: None,
            arriving_reservation_proof_digest: None,
            canonical_state_root: after_root,
            canonical_receipt_digest: finality.receipt_digest,
            canonical_height: self.height,
            avalanche_transaction_id: None,
            avalanche_block_id: None,
            replay_rejected,
            solvent: true,
        })
    }

    /// Compatibility-only path for local fixtures that still hold every
    /// scalar opening. Production admission uses `settle_batch_collaborative`.
    /// Settle every fill produced by one arriving order as one atomic DeFMI
    /// transition.  Packages are constructed against an isolated state clone,
    /// then the generic DeFMI batch verifier replays the whole bundle into a
    /// second clone.  Live ledgers, reservations, balance openings, and height
    /// are replaced only after both views agree.
    pub fn settle_batch<O: SettlementOrderView + ?Sized>(
        &mut self,
        fills: &[PublicFill],
        transition: &VerifiedTransitionProof,
        arriving: &O,
        arriving_remaining: u64,
        now: u64,
    ) -> Result<OclobSettlementReceipt, SettlementError> {
        if fills.is_empty()
            || fills
                .iter()
                .any(|fill| fill.quantity == 0 || fill.price == 0)
        {
            return Err(SettlementError::InvalidFill);
        }
        if fills
            .iter()
            .any(|fill| fill.taker_order != arriving.settlement_commitment())
        {
            return Err(SettlementError::Reservation(
                "atomic batch contains a fill from another arriving order".into(),
            ));
        }
        if arriving.settlement_expires_at() < now {
            return Err(SettlementError::Reservation(
                "an expired arriving order cannot settle".into(),
            ));
        }
        let filled_quantity = fills.iter().try_fold(0_u64, |total, fill| {
            total
                .checked_add(fill.quantity)
                .ok_or_else(|| SettlementError::Reservation("fill quantity overflowed".into()))
        })?;
        if filled_quantity
            .checked_add(arriving_remaining)
            .is_none_or(|total| total != arriving.settlement_quantity())
        {
            return Err(SettlementError::Reservation(
                "fills and arriving remainder do not conserve order quantity".into(),
            ));
        }
        let mut maker_orders = BTreeSet::new();
        if fills
            .iter()
            .any(|fill| !maker_orders.insert(fill.maker_order))
        {
            return Err(SettlementError::Reservation(
                "one resting order cannot appear twice in an atomic match batch".into(),
            ));
        }
        transition
            .verify_settlement_binding(
                arriving.settlement_market_id(),
                arriving.settlement_commitment(),
                fills,
                self.transition_committee_trust_root,
            )
            .map_err(|error| SettlementError::Proof(error.to_string()))?;
        let mut rng = OsRng;
        let reservation_before_root = self.reservations.root();
        let mut staged_reservations = self.reservations.clone();
        let mut staged_participants = self.participants.clone();
        let mut staged_spent = self.spent_instructions.clone();
        let mut members = Vec::with_capacity(fills.len());
        let (initial_securities, initial_cash) = self.ledgers();
        let securities_before = initial_securities.snapshot();
        let cash_before = initial_cash.snapshot();
        let bounds = Bounds {
            amount_bits: RANGE_BITS,
            price_bits: RANGE_BITS,
            max_horizon: 3_600,
        };
        let transition_digest = transition.digest();
        for (index, fill) in fills.iter().enumerate() {
            let consumed =
                staged_reservations.consume_fill(fill, arriving.settlement_market_id(), now)?;
            if consumed.seller_handle == consumed.buyer_handle {
                return Err(SettlementError::Reservation(
                    "self-trading orders cannot produce a DvP between one account".into(),
                ));
            }
            let seller = staged_participants
                .get(&consumed.seller_handle)
                .copied()
                .ok_or_else(|| SettlementError::Reservation("seller account is absent".into()))?;
            let buyer = staged_participants
                .get(&consumed.buyer_handle)
                .copied()
                .ok_or_else(|| SettlementError::Reservation("buyer account is absent".into()))?;
            let amount_blinding = Scalar::random(&mut rng);
            let price_blinding = Scalar::random(&mut rng);
            let amount = deal_bits(
                &self.key,
                fill.quantity,
                &amount_blinding,
                RANGE_BITS,
                &PROOF_PARTIES,
                PROOF_THRESHOLD,
                &mut rng,
            )
            .map_err(SettlementError::Proof)?;
            let price = deal_bits(
                &self.key,
                fill.price,
                &price_blinding,
                RANGE_BITS,
                &PROOF_PARTIES,
                PROOF_THRESHOLD,
                &mut rng,
            )
            .map_err(SettlementError::Proof)?;
            let amount_range = prove_range(&self.key, &amount, AMOUNT_RANGE_CONTEXT, &mut rng)?;
            let price_range = prove_range(&self.key, &price, PRICE_RANGE_CONTEXT, &mut rng)?;
            let asset_blinding = Scalar::random(&mut rng);
            let asset_commitment = self
                .key
                .commit(&Scalar::from(ASSET_INDEX as u64), &asset_blinding);
            let nonce: Digest32 = Sha256::new()
                .chain_update(b"OCLOB:ZKPI-NONCE:v2")
                .chain_update(transition_digest)
                .chain_update((index as u64).to_be_bytes())
                .chain_update(fill.maker_order.0)
                .chain_update(fill.taker_order.0)
                .chain_update(fill.price.to_be_bytes())
                .chain_update(fill.quantity.to_be_bytes())
                .finalize()
                .into();
            let partial = PartialInstruction::from_threshold_ranges(
                &self.key,
                &bounds,
                amount.commitment,
                price.commitment,
                asset_commitment,
                amount_range,
                price_range,
                buyer.handle.point,
                seller.handle.point,
                now.saturating_add(600),
                nonce,
                transition_digest,
            )
            .map_err(SettlementError::Cryptography)?;
            let signature = sign_threshold(
                &self.signing_shares,
                &self.public_key,
                &partial.digest(),
                &mut rng,
            )?;
            let instruction = partial.sealed(signature);
            let zkpi_digest: Digest32 = Sha256::digest(instruction.digest()).into();
            if !instruction.ranges.is_threshold() {
                return Err(SettlementError::Proof(
                    "zkPI was not assembled from threshold range proofs".into(),
                ));
            }
            let openings = InstructionOpenings {
                amount: amount_blinding,
                price: price_blinding,
            };
            let seller_securities_opening = seller.securities.opening.ok_or_else(|| {
                SettlementError::Proof(
                    "legacy settlement cannot reopen an MPC-updated securities account".into(),
                )
            })?;
            let seller_cash_opening = seller.cash.opening.ok_or_else(|| {
                SettlementError::Proof(
                    "legacy settlement cannot reopen an MPC-updated cash account".into(),
                )
            })?;
            let buyer_cash_opening = buyer.cash.opening.ok_or_else(|| {
                SettlementError::Proof(
                    "legacy settlement cannot reopen an MPC-updated cash account".into(),
                )
            })?;
            let buyer_securities_opening = buyer.securities.opening.ok_or_else(|| {
                SettlementError::Proof(
                    "legacy settlement cannot reopen an MPC-updated securities account".into(),
                )
            })?;
            let (current_securities, current_cash) =
                ledgers_from_participants(&self.key, &staged_participants);
            let (package, carry) = build_package(
                &self.key,
                instruction,
                &current_securities,
                &current_cash,
                fill.quantity,
                fill.price,
                &Holdings {
                    securities_balance: seller.securities.value,
                    securities_blinding: seller_securities_opening,
                    cash_balance: buyer.cash.value,
                    cash_blinding: buyer_cash_opening,
                },
                &openings,
                None,
                &Scalar::ZERO,
                None,
                &Scalar::ZERO,
                &mut rng,
            )
            .map_err(SettlementError::Cryptography)?;
            let package_digest = package.digest();
            let instruction_nullifier = package.instruction.nullifier();
            if !staged_spent.insert(instruction_nullifier) {
                return Err(SettlementError::ReplayAccepted);
            }
            let venue = Venue::new(self.key.clone(), &bounds, self.public_key.clone())
                .require_threshold_ranges();
            let mut verifier =
                Defmi::new(self.key.clone(), current_securities, current_cash, venue);
            let build_receipt = verifier.settle(&package, now, &mut rng);
            build_receipt
                .status
                .map_err(SettlementError::Cryptography)?;
            let cash_value = fill
                .price
                .checked_mul(fill.quantity)
                .ok_or_else(|| SettlementError::Reservation("cash fill overflowed".into()))?;
            let mut seller_after = seller;
            seller_after.securities = ConfidentialBalance::opened(
                &self.key,
                carry.securities_balance,
                carry.securities_blinding,
            );
            seller_after.cash = ConfidentialBalance::opened(
                &self.key,
                checked_credit(seller.cash.value, cash_value)?,
                seller_cash_opening + carry.cash_amount_blinding,
            );
            let mut buyer_after = buyer;
            buyer_after.cash =
                ConfidentialBalance::opened(&self.key, carry.cash_balance, carry.cash_blinding);
            buyer_after.securities = ConfidentialBalance::opened(
                &self.key,
                checked_credit(buyer.securities.value, fill.quantity)?,
                buyer_securities_opening + carry.securities_amount_blinding,
            );
            staged_participants.insert(consumed.seller_handle, seller_after);
            staged_participants.insert(consumed.buyer_handle, buyer_after);
            let (expected_securities, expected_cash) =
                ledgers_from_participants(&self.key, &staged_participants);
            if build_receipt.securities_after != expected_securities.snapshot()
                || build_receipt.cash_after != expected_cash.snapshot()
            {
                return Err(SettlementError::CanonicalDivergence);
            }
            members.push(OclobSettlementMemberReceipt {
                instruction_nullifier,
                zkpi_digest,
                package_digest,
                maker_order: fill.maker_order.0,
                taker_order: fill.taker_order.0,
                maker_reservation_remaining: consumed.maker_remaining,
                taker_reservation_remaining: consumed.taker_remaining,
            });
        }
        let taker_reservation_remaining =
            staged_reservations.reconcile_arriving(arriving, arriving_remaining)?;
        if let Some(last) = members.last_mut() {
            last.taker_reservation_remaining = taker_reservation_remaining;
        }
        for (participant, balances) in &staged_participants {
            staged_reservations.refresh_capacity(
                *participant,
                balances.cash.value,
                balances.securities.value,
            )?;
        }
        let reservation_after_root = staged_reservations.root();

        let (final_securities, final_cash) =
            ledgers_from_participants(&self.key, &staged_participants);
        let securities_after = final_securities.snapshot();
        let cash_after = final_cash.snapshot();
        if !final_securities.conserved() || !final_cash.conserved() {
            return Err(SettlementError::Insolvent);
        }
        let replay_rejected = staged_spent.len() == self.spent_instructions.len() + fills.len();
        if !replay_rejected {
            return Err(SettlementError::ReplayAccepted);
        }

        let batch_digest = settlement_batch_digest(transition_digest, &members);
        let before_root = combined_root(securities_before, cash_before, reservation_before_root);
        let after_root = combined_root(securities_after, cash_after, reservation_after_root);
        self.height = self
            .height
            .checked_add(1)
            .ok_or_else(|| SettlementError::Reservation("DeFMI height exhausted".into()))?;
        let block_id = hex::encode(
            Sha256::new()
                .chain_update(b"OCLOB:DEFMI-BLOCK:v1")
                .chain_update(batch_digest)
                .chain_update(after_root)
                .finalize(),
        );
        let canonical = CanonicalTransition {
            transaction_id: hex::encode(batch_digest),
            block_id,
            height: self.height,
            statement: transition_digest,
            before_state_root: before_root,
            after_state_root: after_root,
        };
        let readbacks = [
            CanonicalReadback::new(
                ReadbackKind::Account,
                resource_id(b"OCLOB:SECURITIES-RAIL"),
                after_root,
            )
            .map_err(|error| SettlementError::Finality(error.to_string()))?,
            CanonicalReadback::new(
                ReadbackKind::Account,
                resource_id(b"OCLOB:CASH-RAIL"),
                after_root,
            )
            .map_err(|error| SettlementError::Finality(error.to_string()))?,
        ];
        let application_binding = oclob_manifest_v1()
            .digest()
            .map_err(|error| SettlementError::Finality(error.to_string()))?;
        let finality = accept_canonical_transition(
            application_binding,
            &canonical,
            transition_digest,
            before_root,
            &readbacks,
        )
        .map_err(|error| SettlementError::Finality(error.to_string()))?;
        self.reservations = staged_reservations;
        self.participants = staged_participants;
        self.spent_instructions = staged_spent;
        Ok(OclobSettlementReceipt {
            batch_digest,
            members,
            amount_range_is_threshold: true,
            price_range_is_threshold: true,
            settlement_authorization_quorum: PROOF_QUORUM.len(),
            post_match_participant_signatures: 0,
            securities_before_root: securities_before,
            securities_after_root: securities_after,
            cash_before_root: cash_before,
            cash_after_root: cash_after,
            reservation_before_root,
            reservation_after_root,
            arriving_reservation_zkpi_digest: None,
            arriving_reservation_instruction_nullifier: None,
            arriving_reservation_proof_digest: None,
            canonical_state_root: after_root,
            canonical_receipt_digest: finality.receipt_digest,
            canonical_height: self.height,
            avalanche_transaction_id: None,
            avalanche_block_id: None,
            replay_rejected,
            solvent: true,
        })
    }
}

fn ledgers_from_participants(
    key: &Pedersen,
    participants: &BTreeMap<Digest32, ParticipantBalances>,
) -> (Ledger, Ledger) {
    let mut securities = Ledger::new(key.clone(), RANGE_BITS);
    let mut cash = Ledger::new(key.clone(), RANGE_BITS);
    for balances in participants.values() {
        securities.open(
            &account_of(&balances.handle.point, SECURITIES_RAIL),
            balances.securities.commitment,
        );
        cash.open(
            &account_of(&balances.handle.point, CASH_RAIL),
            balances.cash.commitment,
        );
    }
    (securities, cash)
}

pub fn canonical_cash_asset_id() -> Digest32 {
    Sha256::new()
        .chain_update(b"OCLOB:DEFMI:ASSET:CASH:v1")
        .finalize()
        .into()
}

pub fn canonical_securities_asset_id(market_id: &str) -> Digest32 {
    Sha256::new()
        .chain_update(b"OCLOB:DEFMI:ASSET:SECURITIES:v1")
        .chain_update((market_id.len() as u64).to_be_bytes())
        .chain_update(market_id.as_bytes())
        .finalize()
        .into()
}

pub fn canonical_reservation_state_asset_id(market_id: &str) -> Digest32 {
    Sha256::new()
        .chain_update(b"OCLOB:DEFMI:ASSET:RESERVATION-STATE:v1")
        .chain_update((market_id.len() as u64).to_be_bytes())
        .chain_update(market_id.as_bytes())
        .finalize()
        .into()
}

pub fn canonical_reservation_state_handle(market_id: &str) -> Digest32 {
    Sha256::new()
        .chain_update(b"OCLOB:DEFMI:ACCOUNT:RESERVATION-STATE:v1")
        .chain_update((market_id.len() as u64).to_be_bytes())
        .chain_update(market_id.as_bytes())
        .finalize()
        .into()
}

fn canonical_account_deltas(
    before_accounts: &[CanonicalAccountOpening],
    after_accounts: &[CanonicalAccountOpening],
) -> Result<Vec<CanonicalAccountDelta>, SettlementError> {
    if before_accounts.len() != after_accounts.len() {
        return Err(SettlementError::CanonicalDivergence);
    }
    let mut deltas = Vec::new();
    for (before, after) in before_accounts.iter().zip(after_accounts) {
        if before.handle != after.handle || before.asset_id != after.asset_id {
            return Err(SettlementError::CanonicalDivergence);
        }
        if before.commitment != after.commitment {
            deltas.push(CanonicalAccountDelta {
                handle: before.handle,
                asset_id: before.asset_id,
                before_commitment: before.commitment,
                after_commitment: after.commitment,
            });
        }
    }
    Ok(deltas)
}

fn digest_member_field(
    domain: &[u8],
    members: &[OclobSettlementMemberReceipt],
    field: impl Fn(&OclobSettlementMemberReceipt) -> Digest32,
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((members.len() as u64).to_be_bytes());
    for member in members {
        hash.update(field(member));
    }
    hash.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn canonical_binding_digest(
    application_binding: Digest32,
    batch_digest: Digest32,
    transition_digest: Digest32,
    payment_instruction_digest: Digest32,
    proof_digest: Digest32,
    reservation_before_root: Digest32,
    reservation_after_root: Digest32,
    deltas: &[CanonicalAccountDelta],
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:DEFMI:CANONICAL-BINDING:v1");
    hash.update(application_binding);
    hash.update(batch_digest);
    hash.update(transition_digest);
    hash.update(payment_instruction_digest);
    hash.update(proof_digest);
    hash.update(reservation_before_root);
    hash.update(reservation_after_root);
    hash.update((deltas.len() as u64).to_be_bytes());
    for delta in deltas {
        hash.update(delta.handle);
        hash.update(delta.asset_id);
        hash.update(delta.before_commitment);
        hash.update(delta.after_commitment);
    }
    hash.finalize().into()
}

fn prove_range<R: RngCore + CryptoRng>(
    key: &Pedersen,
    value: &ValueShares,
    context: &[u8],
    rng: &mut R,
) -> Result<qomm_proofs::threshold_range::ThresholdRangeProof, SettlementError> {
    let contributions = PROOF_QUORUM
        .iter()
        .map(|party| {
            value
                .node_contribution(*party)
                .ok_or_else(|| SettlementError::Proof(format!("missing proof party {party}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    joint_prove_range_from_contributions(key, &contributions, &PROOF_QUORUM, context, rng)
        .map(|(proof, _)| proof)
        .map_err(SettlementError::Proof)
}

fn sign_threshold<R: RngCore + CryptoRng>(
    shares: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
    message: &[u8],
    rng: &mut R,
) -> Result<frost::Signature, SettlementError> {
    let selected = shares
        .keys()
        .take(PROOF_QUORUM.len())
        .copied()
        .collect::<Vec<_>>();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &selected {
        let (nonce, commitment) = frost::round1::commit(shares[id].signing_share(), &mut *rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let mut signature_shares = BTreeMap::new();
    for id in &selected {
        signature_shares.insert(
            *id,
            frost::round2::sign(&package, &nonces[id], &shares[id])
                .map_err(|_| SettlementError::Proof("FROST signer refused".into()))?,
        );
    }
    frost::aggregate(&package, &signature_shares, public)
        .map_err(|_| SettlementError::Proof("FROST aggregation failed".into()))
}

fn combined_root(securities: Digest32, cash: Digest32, reservations: Digest32) -> Digest32 {
    Sha256::new()
        .chain_update(b"OCLOB:DEFMI-CANONICAL-STATE:v1")
        .chain_update(securities)
        .chain_update(cash)
        .chain_update(reservations)
        .finalize()
        .into()
}

fn digest(domain: &[u8], body: &[u8]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((body.len() as u64).to_be_bytes());
    hash.update(body);
    hash.finalize().into()
}

fn reservation_receipt_digest(
    operation: &[u8],
    order_or_batch: Digest32,
    before_root: Digest32,
    after_root: Digest32,
    height: u64,
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:DEFMI-RESERVATION-RECEIPT:v1");
    hash.update((operation.len() as u64).to_be_bytes());
    hash.update(operation);
    hash.update(order_or_batch);
    hash.update(before_root);
    hash.update(after_root);
    hash.update(height.to_be_bytes());
    hash.finalize().into()
}

fn checked_credit(balance: u64, amount: u64) -> Result<u64, SettlementError> {
    let credited = balance
        .checked_add(amount)
        .ok_or_else(|| SettlementError::Reservation("credited balance overflowed".into()))?;
    if u128::from(credited) >= (1_u128 << RANGE_BITS) {
        return Err(SettlementError::Reservation(
            "credited balance exceeds the DeFMI range-proof domain".into(),
        ));
    }
    Ok(credited)
}

fn checked_debit(balance: u64, amount: u64) -> Result<u64, SettlementError> {
    balance
        .checked_sub(amount)
        .ok_or(SettlementError::Insolvent)
}

fn settlement_batch_digest(
    transition_digest: Digest32,
    members: &[OclobSettlementMemberReceipt],
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:DEFMI-ATOMIC-BATCH:v1");
    hash.update(transition_digest);
    hash.update((members.len() as u64).to_be_bytes());
    for member in members {
        hash.update(member.instruction_nullifier);
        hash.update(member.package_digest);
        hash.update(member.maker_order);
        hash.update(member.taker_order);
    }
    hash.finalize().into()
}

fn reservation_kind_tag(kind: ReservationKind) -> u8 {
    match kind {
        ReservationKind::Cash => 1,
        ReservationKind::Securities => 2,
    }
}

fn time_in_force_tag(value: TimeInForce) -> u8 {
    match value {
        TimeInForce::GoodTilCancelled => 1,
        TimeInForce::ImmediateOrCancel => 2,
    }
}

fn reservation_status_tag(status: ReservationStatus) -> u8 {
    match status {
        ReservationStatus::Active => 1,
        ReservationStatus::Consumed => 2,
        ReservationStatus::Released => 3,
    }
}

fn resource_id(name: &[u8]) -> Digest32 {
    Sha256::new()
        .chain_update(b"OCLOB:DEFMI-RESOURCE:v1")
        .chain_update(name)
        .finalize()
        .into()
}

#[derive(Debug, Error)]
pub enum SettlementError {
    #[error("fill is empty")]
    InvalidFill,
    #[error("cryptographic construction failed: {0}")]
    Cryptography(&'static str),
    #[error("distributed proof construction failed: {0}")]
    Proof(String),
    #[error("DeFMI accepted a replayed instruction")]
    ReplayAccepted,
    #[error("DeFMI conservation failed")]
    Insolvent,
    #[error("the independently built and committed DeFMI batch states diverged")]
    CanonicalDivergence,
    #[error("canonical readback failed: {0}")]
    Finality(String),
    #[error("canonical reservation failed: {0}")]
    Reservation(String),
}

impl Default for SettlementEngine {
    fn default() -> Self {
        Self::new(&mut OsRng).expect("static OCLOB demo settlement setup")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use oclob_core::{OrderCommitment, PublicFill};
    use oclob_ordering::OrderingCommittee;
    use oclob_proofs::{
        public_fills_digest, TransitionProof, TransitionStatement, VerifiedTransitionProof,
    };

    fn buy(handle: Digest32, nonce: u8, price: u64) -> SecretOrder {
        SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            price,
            1,
            TimeInForce::GoodTilCancelled,
            2_000,
            handle,
            [nonce; 32],
            [nonce.saturating_add(40); 32],
        )
        .unwrap()
    }

    fn sell(handle: Digest32, nonce: u8, quantity: u64, price: u64) -> SecretOrder {
        SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            price,
            quantity,
            TimeInForce::GoodTilCancelled,
            2_000,
            handle,
            [nonce; 32],
            [nonce.saturating_add(40); 32],
        )
        .unwrap()
    }

    fn engine() -> SettlementEngine {
        let mut engine = SettlementEngine::new(&mut OsRng).unwrap();
        let (first, second) = engine.demo_participant_handles();
        let first_probe = buy(first, 240, 1);
        let second_probe = buy(second, 241, 1);
        engine
            .bind_eligible_participant(first, first_probe.dekyx_nullifier())
            .unwrap();
        engine
            .bind_eligible_participant(second, second_probe.dekyx_nullifier())
            .unwrap();
        engine
    }

    fn transition(fills: &[PublicFill]) -> VerifiedTransitionProof {
        let committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let proof = TransitionProof::attest(
            TransitionStatement {
                market_id: "JGB10Y-JPY".into(),
                sequence: 3,
                order_certificate_digest: [1; 32],
                eligibility_proof_digest: [9; 32],
                private_before_root: [2; 32],
                private_after_root: [3; 32],
                public_before_root: [4; 32],
                public_after_root: [5; 32],
                mpc_program_digest: [6; 32],
                mpc_output_digest: [7; 32],
                fill_digest: public_fills_digest(fills),
            },
            &committee.transition_signers(),
            committee.policy(),
        )
        .unwrap();
        proof
            .into_verified(&committee.verifying_keys(), committee.policy())
            .unwrap()
    }

    fn rogue_transition(fills: &[PublicFill]) -> VerifiedTransitionProof {
        let policy = CommitteePolicy::seven_node();
        let signing_keys = (1_u16..=7)
            .map(|node_id| {
                (
                    node_id,
                    SigningKey::from_bytes(&[(node_id as u8).saturating_add(40); 32]),
                )
            })
            .collect::<Vec<_>>();
        let signer_refs = signing_keys
            .iter()
            .map(|(node_id, key)| (*node_id, key))
            .collect::<Vec<_>>();
        let verifying_keys = signing_keys
            .iter()
            .map(|(node_id, key)| (*node_id, key.verifying_key()))
            .collect::<BTreeMap<_, _>>();
        let statement = transition(fills).proof().statement.clone();
        TransitionProof::attest(statement, &signer_refs, policy)
            .unwrap()
            .into_verified(&verifying_keys, policy)
            .unwrap()
    }

    #[test]
    fn legal_entity_capacity_spans_multiple_anonymous_orders() {
        let mut engine = engine();
        let (_, buyer) = engine.demo_participant_handles();
        let first = buy(buyer, 1, 60_000_000);
        let second = buy(buyer, 2, 60_000_000);
        engine.reserve_order(&first).unwrap();
        assert!(matches!(
            engine.reserve_order(&second),
            Err(SettlementError::Reservation(_))
        ));
    }

    #[test]
    fn one_order_cannot_reserve_twice() {
        let mut engine = engine();
        let (_, buyer) = engine.demo_participant_handles();
        let order = buy(buyer, 3, 100);
        engine.reserve_order(&order).unwrap();
        assert!(engine.reserve_order(&order).is_err());
    }

    #[test]
    fn collaborative_committee_key_is_fixed_before_canonical_state() {
        let mut engine = engine();
        let pinned = engine.public_key.clone();
        engine
            .pin_collaborative_settlement_committee(pinned.clone())
            .unwrap();
        engine
            .pin_collaborative_settlement_committee(pinned)
            .unwrap();

        let (_, buyer) = engine.demo_participant_handles();
        engine.reserve_order(&buy(buyer, 4, 100)).unwrap();
        let (_, replacement) = distributed_key_generation(7, 3, &mut OsRng).unwrap();
        assert!(matches!(
            engine.pin_collaborative_settlement_committee(replacement),
            Err(SettlementError::Proof(_))
        ));
    }

    #[test]
    fn reservation_root_binds_exact_edge_commitment() {
        let base = engine();
        let (_, buyer) = base.demo_participant_handles();
        let order = buy(buyer, 5, 100);
        let first_commitment = base
            .key
            .commit_u64(order.settlement_reservation_limit(), &Scalar::from(7_u64));
        let second_commitment = base
            .key
            .commit_u64(order.settlement_reservation_limit(), &Scalar::from(8_u64));
        let mut first = base.clone();
        let mut second = base;
        let first_root = first
            .reserve_order_with_commitment(&order, first_commitment)
            .unwrap()
            .state_root;
        let second_root = second
            .reserve_order_with_commitment(&order, second_commitment)
            .unwrap()
            .state_root;
        assert_ne!(first_root, second_root);
    }

    #[test]
    fn fully_filled_buy_maker_releases_price_improvement() {
        let mut engine = engine();
        let (buyer, seller) = engine.demo_participant_handles();
        let maker = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            10,
            TimeInForce::GoodTilCancelled,
            2_000,
            buyer,
            [14; 32],
            [54; 32],
        )
        .unwrap();
        let arriving = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            100,
            10,
            TimeInForce::ImmediateOrCancel,
            2_000,
            seller,
            [15; 32],
            [55; 32],
        )
        .unwrap();
        engine.reserve_order(&maker).unwrap();
        engine.reserve_order(&arriving).unwrap();
        let fills = [PublicFill {
            maker_order: maker.commitment(),
            taker_order: arriving.commitment(),
            price: 100,
            quantity: 10,
        }];
        let receipt = engine
            .settle_batch(&fills, &transition(&fills), &arriving, 0, 1_000)
            .unwrap();
        assert_eq!(receipt.members[0].maker_reservation_remaining, 0);
        assert_eq!(
            engine.participant_portfolio(buyer).unwrap().reserved_cash,
            0
        );
    }

    #[test]
    fn partially_filled_buy_maker_keeps_only_worst_case_remainder() {
        let mut engine = engine();
        let (buyer, seller) = engine.demo_participant_handles();
        let maker = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            10,
            TimeInForce::GoodTilCancelled,
            2_000,
            buyer,
            [16; 32],
            [56; 32],
        )
        .unwrap();
        let arriving = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            100,
            4,
            TimeInForce::ImmediateOrCancel,
            2_000,
            seller,
            [17; 32],
            [57; 32],
        )
        .unwrap();
        engine.reserve_order(&maker).unwrap();
        engine.reserve_order(&arriving).unwrap();
        let fills = [PublicFill {
            maker_order: maker.commitment(),
            taker_order: arriving.commitment(),
            price: 100,
            quantity: 4,
        }];
        let receipt = engine
            .settle_batch(&fills, &transition(&fills), &arriving, 0, 1_000)
            .unwrap();
        assert_eq!(receipt.members[0].maker_reservation_remaining, 606);
        assert_eq!(
            engine.participant_portfolio(buyer).unwrap().reserved_cash,
            606
        );
    }

    #[test]
    fn settlement_rejects_non_conserving_or_limit_violating_fills() {
        let mut engine = engine();
        let (buyer, seller) = engine.demo_participant_handles();
        let maker = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            4,
            TimeInForce::GoodTilCancelled,
            2_000,
            buyer,
            [18; 32],
            [58; 32],
        )
        .unwrap();
        let arriving = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            100,
            4,
            TimeInForce::ImmediateOrCancel,
            2_000,
            seller,
            [19; 32],
            [59; 32],
        )
        .unwrap();
        engine.reserve_order(&maker).unwrap();
        engine.reserve_order(&arriving).unwrap();
        let short = [PublicFill {
            maker_order: maker.commitment(),
            taker_order: arriving.commitment(),
            price: 100,
            quantity: 3,
        }];
        let before = engine.state_snapshot();
        assert!(matches!(
            engine.settle_batch(&short, &transition(&short), &arriving, 0, 1_000),
            Err(SettlementError::Reservation(_))
        ));
        assert_eq!(engine.state_snapshot(), before);

        let outside_limit = [PublicFill {
            maker_order: maker.commitment(),
            taker_order: arriving.commitment(),
            price: 102,
            quantity: 4,
        }];
        assert!(matches!(
            engine.settle_batch(
                &outside_limit,
                &transition(&outside_limit),
                &arriving,
                0,
                1_000,
            ),
            Err(SettlementError::Reservation(_))
        ));
        assert_eq!(engine.state_snapshot(), before);
    }

    #[test]
    fn two_fills_commit_as_one_canonical_batch() {
        let mut engine = engine();
        let (seller, buyer) = engine.demo_participant_handles();
        let first = sell(seller, 4, 10, 100);
        let second = sell(seller, 5, 10, 101);
        let arriving = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            15,
            TimeInForce::ImmediateOrCancel,
            2_000,
            buyer,
            [6; 32],
            [46; 32],
        )
        .unwrap();
        for order in [&first, &second, &arriving] {
            engine.reserve_order(order).unwrap();
        }
        let fills = [
            PublicFill {
                maker_order: first.commitment(),
                taker_order: arriving.commitment(),
                price: 100,
                quantity: 10,
            },
            PublicFill {
                maker_order: second.commitment(),
                taker_order: arriving.commitment(),
                price: 101,
                quantity: 5,
            },
        ];
        let before = engine.state_snapshot();
        let receipt = engine
            .settle_batch(&fills, &transition(&fills), &arriving, 0, 1_000)
            .unwrap();
        let after = engine.state_snapshot();
        assert_eq!(receipt.members.len(), 2);
        assert_eq!(receipt.members[0].maker_reservation_remaining, 0);
        assert_eq!(receipt.members[1].maker_reservation_remaining, 5);
        assert_eq!(receipt.members[1].taker_reservation_remaining, 0);
        assert_ne!(before.securities_root, after.securities_root);
        assert_ne!(before.cash_root, after.cash_root);
        assert_ne!(before.reservation_root, after.reservation_root);
        assert_eq!(after.height, before.height + 1);
        assert_eq!(receipt.canonical_height, after.height);
        assert!(receipt.replay_rejected);
        assert!(receipt.solvent);
    }

    #[test]
    fn invalid_second_fill_cannot_partially_change_state() {
        let mut engine = engine();
        let (seller, buyer) = engine.demo_participant_handles();
        let resting = sell(seller, 7, 10, 100);
        let arriving = buy(buyer, 8, 100);
        engine.reserve_order(&resting).unwrap();
        engine.reserve_order(&arriving).unwrap();
        let fills = [
            PublicFill {
                maker_order: resting.commitment(),
                taker_order: arriving.commitment(),
                price: 100,
                quantity: 1,
            },
            PublicFill {
                maker_order: OrderCommitment([99; 32]),
                taker_order: arriving.commitment(),
                price: 100,
                quantity: 1,
            },
        ];
        let before = engine.state_snapshot();
        assert!(engine
            .settle_batch(&fills, &transition(&fills), &arriving, 0, 1_000)
            .is_err());
        assert_eq!(engine.state_snapshot(), before);
    }

    #[test]
    fn settlement_rejects_a_valid_quorum_from_an_untrusted_committee() {
        let mut engine = engine();
        let (seller, buyer) = engine.demo_participant_handles();
        let resting = sell(seller, 9, 10, 100);
        let arriving = buy(buyer, 10, 100);
        engine.reserve_order(&resting).unwrap();
        engine.reserve_order(&arriving).unwrap();
        let fills = [PublicFill {
            maker_order: resting.commitment(),
            taker_order: arriving.commitment(),
            price: 100,
            quantity: 1,
        }];
        let before = engine.state_snapshot();
        assert!(matches!(
            engine.settle_batch(&fills, &rogue_transition(&fills), &arriving, 0, 1_000),
            Err(SettlementError::Proof(_))
        ));
        assert_eq!(engine.state_snapshot(), before);
    }

    #[test]
    fn either_participant_can_buy_or_sell_across_successive_batches() {
        let mut engine = engine();
        let (first, second) = engine.demo_participant_handles();

        let first_sale = sell(first, 10, 10, 100);
        let second_purchase = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            100,
            10,
            TimeInForce::ImmediateOrCancel,
            2_000,
            second,
            [11; 32],
            [51; 32],
        )
        .unwrap();
        engine.reserve_order(&first_sale).unwrap();
        engine.reserve_order(&second_purchase).unwrap();
        let first_fills = [PublicFill {
            maker_order: first_sale.commitment(),
            taker_order: second_purchase.commitment(),
            price: 100,
            quantity: 10,
        }];
        engine
            .settle_batch(
                &first_fills,
                &transition(&first_fills),
                &second_purchase,
                0,
                1_000,
            )
            .unwrap();

        let first_purchase = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            5,
            TimeInForce::GoodTilCancelled,
            2_000,
            first,
            [12; 32],
            [52; 32],
        )
        .unwrap();
        let second_sale = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            101,
            5,
            TimeInForce::ImmediateOrCancel,
            2_000,
            second,
            [13; 32],
            [53; 32],
        )
        .unwrap();
        engine.reserve_order(&first_purchase).unwrap();
        engine.reserve_order(&second_sale).unwrap();
        let before_reverse = engine.state_snapshot();
        let reverse_fills = [PublicFill {
            maker_order: first_purchase.commitment(),
            taker_order: second_sale.commitment(),
            price: 101,
            quantity: 5,
        }];
        let reverse = engine
            .settle_batch(
                &reverse_fills,
                &transition(&reverse_fills),
                &second_sale,
                0,
                1_001,
            )
            .unwrap();
        let after_reverse = engine.state_snapshot();
        assert_eq!(reverse.members.len(), 1);
        assert_eq!(reverse.members[0].maker_reservation_remaining, 0);
        assert_eq!(reverse.members[0].taker_reservation_remaining, 0);
        assert_ne!(
            before_reverse.securities_root,
            after_reverse.securities_root
        );
        assert_ne!(before_reverse.cash_root, after_reverse.cash_root);
        assert_eq!(after_reverse.height, before_reverse.height + 1);
        assert_eq!(reverse.canonical_height, after_reverse.height);
        assert!(reverse.replay_rejected);
        assert!(reverse.solvent);
    }
}
