//! OCLOB fill settlement through the production zkPI and DeFMI verifiers.

#![forbid(unsafe_code)]

use curve25519_dalek::scalar::Scalar;
use oclob_core::{Digest32, PublicFill, SecretOrder, Side, TimeInForce};
use oclob_proofs::TransitionProof;
use qomm_defmi::assets::AssetRegistry;
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
use std::collections::BTreeMap;
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
    pub canonical_state_root: Digest32,
    pub canonical_receipt_digest: Digest32,
    pub canonical_height: u64,
    pub replay_rejected: bool,
    pub solvent: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OclobSettlementMemberReceipt {
    pub instruction_nullifier: Digest32,
    pub package_digest: Digest32,
    pub maker_order: Digest32,
    pub taker_order: Digest32,
    pub maker_reservation_remaining: u64,
    pub taker_reservation_remaining: u64,
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
    kind: ReservationKind,
    reserved: u64,
    remaining: u64,
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

    fn reserve(&mut self, order: &SecretOrder) -> Result<ReservationReceipt, SettlementError> {
        if self.participant_entities.get(&order.participant_handle())
            != Some(&order.dekyx_nullifier())
        {
            return Err(SettlementError::Reservation(
                "order participant is not bound to the presented DeKYX entity".into(),
            ));
        }
        let id = order.reservation_id();
        if self.records.contains_key(&id)
            || self
                .records
                .values()
                .any(|record| record.order_commitment == order.commitment().0)
        {
            return Err(SettlementError::Reservation(
                "reservation id or order commitment was already used".into(),
            ));
        }
        let kind = match order.side() {
            Side::Buy => ReservationKind::Cash,
            Side::Sell => ReservationKind::Securities,
        };
        let kind_tag = reservation_kind_tag(kind);
        let capacity = self
            .capacities
            .get(&(order.dekyx_nullifier(), kind_tag))
            .copied()
            .ok_or_else(|| {
                SettlementError::Reservation("entity has no canonical capacity".into())
            })?;
        let in_use = self
            .records
            .values()
            .filter(|record| {
                record.entity_nullifier == order.dekyx_nullifier()
                    && record.kind == kind
                    && record.status == ReservationStatus::Active
            })
            .try_fold(0_u64, |total, record| total.checked_add(record.remaining))
            .ok_or_else(|| SettlementError::Reservation("reservation sum overflowed".into()))?;
        if in_use
            .checked_add(order.reservation_limit())
            .is_none_or(|total| total > capacity)
        {
            return Err(SettlementError::Reservation(
                "the entity-wide cash, inventory, or guarantee capacity is exceeded".into(),
            ));
        }
        let record = ReservationRecord {
            reservation_id: id,
            order_commitment: order.commitment().0,
            participant_handle: order.participant_handle(),
            entity_nullifier: order.dekyx_nullifier(),
            kind,
            reserved: order.reservation_limit(),
            remaining: order.reservation_limit(),
            status: ReservationStatus::Active,
        };
        self.records.insert(id, record);
        Ok(ReservationReceipt {
            reservation_id: id,
            order_commitment: order.commitment().0,
            kind,
            reserved: order.reservation_limit(),
            state_root: self.root(),
            canonical_receipt_digest: [0; 32],
            canonical_height: 0,
        })
    }

    fn consume_fill(&mut self, fill: &PublicFill) -> Result<ConsumedFill, SettlementError> {
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

        let maker = self.records.get_mut(&maker_id).expect("looked up maker");
        maker.remaining -= maker_required;
        if maker.remaining == 0 {
            maker.status = ReservationStatus::Consumed;
        }
        let maker_remaining = maker.remaining;
        let taker = self.records.get_mut(&taker_id).expect("looked up taker");
        taker.remaining -= taker_required;
        if taker.remaining == 0 {
            taker.status = ReservationStatus::Consumed;
        }
        Ok(ConsumedFill {
            maker_remaining,
            taker_remaining: taker.remaining,
            seller_handle,
            buyer_handle,
        })
    }

    fn reconcile_arriving(
        &mut self,
        order: &SecretOrder,
        remaining_quantity: u64,
    ) -> Result<u64, SettlementError> {
        let id = self
            .record_id_for(order.commitment().0)
            .ok_or_else(|| SettlementError::Reservation("taker reservation is absent".into()))?;
        let required = if remaining_quantity == 0
            || order.time_in_force() == TimeInForce::ImmediateOrCancel
        {
            0
        } else {
            match order.side() {
                Side::Buy => order
                    .limit_price()
                    .checked_mul(remaining_quantity)
                    .and_then(|value| value.checked_add(order.max_fee()))
                    .ok_or_else(|| {
                        SettlementError::Reservation("remaining cash reservation overflowed".into())
                    })?,
                Side::Sell => remaining_quantity,
            }
        };
        let record = self.records.get_mut(&id).expect("looked up reservation");
        if record.remaining < required {
            return Err(SettlementError::Reservation(
                "remaining order is not covered by its reservation".into(),
            ));
        }
        let unused = record.remaining.saturating_sub(required);
        record.remaining = required;
        record.status = if required > 0 {
            ReservationStatus::Active
        } else if unused > 0 {
            ReservationStatus::Released
        } else {
            ReservationStatus::Consumed
        };
        Ok(required)
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
        record.status = ReservationStatus::Released;
        Ok(())
    }

    fn root(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(b"OCLOB:DEFMI-RESERVATIONS:v1");
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
            hash.update([reservation_kind_tag(record.kind)]);
            hash.update(record.reserved.to_be_bytes());
            hash.update(record.remaining.to_be_bytes());
            hash.update([reservation_status_tag(record.status)]);
        }
        hash.finalize().into()
    }
}

#[derive(Clone, Copy)]
struct ConsumedFill {
    maker_remaining: u64,
    taker_remaining: u64,
    seller_handle: Digest32,
    buyer_handle: Digest32,
}

#[derive(Clone, Copy)]
struct ParticipantBalances {
    handle: Handle,
    securities: (u64, Scalar),
    cash: (u64, Scalar),
}

#[derive(Clone)]
pub struct SettlementEngine {
    key: Pedersen,
    registry: AssetRegistry,
    defmi: Defmi,
    signing_shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key: frost::keys::PublicKeyPackage,
    participants: BTreeMap<Digest32, ParticipantBalances>,
    demo_handles: (Digest32, Digest32),
    reservations: ReservationBook,
    height: u64,
}

impl SettlementEngine {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, SettlementError> {
        let key = Pedersen::new(b"qomm:defmi:v1");
        let registry = AssetRegistry::new(key.clone(), 16);
        let (signing_shares, public_key) =
            distributed_key_generation(7, 3, rng).map_err(SettlementError::Cryptography)?;
        let bounds = Bounds {
            amount_bits: RANGE_BITS,
            price_bits: RANGE_BITS,
            max_horizon: 3_600,
        };
        let venue = Venue::new(key.clone(), &bounds, public_key.clone()).require_threshold_ranges();
        let first = Identity::from_seed([11; 32]).handle(VENUE_DOMAIN);
        let second = Identity::from_seed([22; 32]).handle(VENUE_DOMAIN);
        let first_securities = (10_000_u64, Scalar::random(&mut *rng));
        let first_cash = (100_000_000_u64, Scalar::random(&mut *rng));
        let second_securities = (10_000_u64, Scalar::random(&mut *rng));
        let second_cash = (100_000_000_u64, Scalar::random(&mut *rng));
        let mut securities = Ledger::new(key.clone(), RANGE_BITS);
        let mut cash = Ledger::new(key.clone(), RANGE_BITS);
        let asset_key = key.with_value_generator(registry.tags[ASSET_INDEX as usize]);
        securities.open(
            &account_of(&first.point, SECURITIES_RAIL),
            asset_key.commit_u64(first_securities.0, &first_securities.1),
        );
        securities.open(
            &account_of(&second.point, SECURITIES_RAIL),
            asset_key.commit_u64(second_securities.0, &second_securities.1),
        );
        cash.open(
            &account_of(&first.point, CASH_RAIL),
            key.commit_u64(first_cash.0, &first_cash.1),
        );
        cash.open(
            &account_of(&second.point, CASH_RAIL),
            key.commit_u64(second_cash.0, &second_cash.1),
        );
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
            defmi: Defmi::new(key.clone(), securities, cash, venue),
            key,
            registry,
            signing_shares,
            public_key,
            participants,
            demo_handles: (first_handle, second_handle),
            reservations: ReservationBook::default(),
            height: 0,
        })
    }

    pub fn reserve_order(
        &mut self,
        order: &SecretOrder,
    ) -> Result<ReservationReceipt, SettlementError> {
        let before_root = self.reservations.root();
        let mut staged = self.reservations.clone();
        let mut receipt = staged.reserve(order)?;
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
            balances.cash.0,
            balances.securities.0,
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
        SettlementStateSnapshot {
            securities_root: self.defmi.securities.snapshot(),
            cash_root: self.defmi.cash.snapshot(),
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
            securities: balances.securities.0,
            cash: balances.cash.0,
            reserved_securities,
            reserved_cash,
            available_securities: balances.securities.0.saturating_sub(reserved_securities),
            available_cash: balances.cash.0.saturating_sub(reserved_cash),
        })
    }

    /// Settle every fill produced by one arriving order as one atomic DeFMI
    /// transition.  Packages are constructed against an isolated state clone,
    /// then the generic DeFMI batch verifier replays the whole bundle into a
    /// second clone.  Live ledgers, reservations, balance openings, and height
    /// are replaced only after both views agree.
    pub fn settle_batch(
        &mut self,
        fills: &[PublicFill],
        transition: &TransitionProof,
        arriving: &SecretOrder,
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
            .any(|fill| fill.taker_order != arriving.commitment())
        {
            return Err(SettlementError::Reservation(
                "atomic batch contains a fill from another arriving order".into(),
            ));
        }
        let mut rng = OsRng;
        let reservation_before_root = self.reservations.root();
        let mut staged_reservations = self.reservations.clone();
        let mut builder_defmi = self.defmi.clone();
        let mut staged_participants = self.participants.clone();
        let mut packages = Vec::with_capacity(fills.len());
        let mut members = Vec::with_capacity(fills.len());
        let bounds = Bounds {
            amount_bits: RANGE_BITS,
            price_bits: RANGE_BITS,
            max_horizon: 3_600,
        };
        let transition_digest = transition.digest();
        for (index, fill) in fills.iter().enumerate() {
            let consumed = staged_reservations.consume_fill(fill)?;
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
            if !instruction.ranges.is_threshold() {
                return Err(SettlementError::Proof(
                    "zkPI was not assembled from threshold range proofs".into(),
                ));
            }
            let openings = InstructionOpenings {
                amount: amount_blinding,
                price: price_blinding,
            };
            let (tag, gamma) = self
                .registry
                .blind(ASSET_INDEX, false, &mut rng)
                .map_err(SettlementError::Cryptography)?;
            let (package, carry) = build_package(
                &self.key,
                instruction,
                &builder_defmi.securities,
                &builder_defmi.cash,
                fill.quantity,
                fill.price,
                &Holdings {
                    securities_balance: seller.securities.0,
                    securities_blinding: seller.securities.1,
                    cash_balance: buyer.cash.0,
                    cash_blinding: buyer.cash.1,
                },
                &openings,
                Some(&tag),
                &gamma,
                None,
                &Scalar::ZERO,
                &mut rng,
            )
            .map_err(SettlementError::Cryptography)?;
            let package_digest = package.digest();
            let instruction_nullifier = package.instruction.nullifier();
            let build_receipt = builder_defmi.settle(&package, now, &mut rng);
            build_receipt
                .status
                .map_err(SettlementError::Cryptography)?;
            let cash_value = fill
                .price
                .checked_mul(fill.quantity)
                .ok_or_else(|| SettlementError::Reservation("cash fill overflowed".into()))?;
            let mut seller_after = seller;
            seller_after.securities = (carry.securities_balance, carry.securities_blinding);
            seller_after.cash = (
                checked_credit(seller.cash.0, cash_value)?,
                seller.cash.1 + carry.cash_payee_delta,
            );
            let mut buyer_after = buyer;
            buyer_after.cash = (carry.cash_balance, carry.cash_blinding);
            buyer_after.securities = (
                checked_credit(buyer.securities.0, fill.quantity)?,
                buyer.securities.1 + carry.securities_payee_delta,
            );
            staged_participants.insert(consumed.seller_handle, seller_after);
            staged_participants.insert(consumed.buyer_handle, buyer_after);
            members.push(OclobSettlementMemberReceipt {
                instruction_nullifier,
                package_digest,
                maker_order: fill.maker_order.0,
                taker_order: fill.taker_order.0,
                maker_reservation_remaining: consumed.maker_remaining,
                taker_reservation_remaining: consumed.taker_remaining,
            });
            packages.push(package);
        }
        let taker_reservation_remaining =
            staged_reservations.reconcile_arriving(arriving, arriving_remaining)?;
        if let Some(last) = members.last_mut() {
            last.taker_reservation_remaining = taker_reservation_remaining;
        }
        for (participant, balances) in &staged_participants {
            staged_reservations.refresh_capacity(
                *participant,
                balances.cash.0,
                balances.securities.0,
            )?;
        }
        let reservation_after_root = staged_reservations.root();

        let mut committed_defmi = self.defmi.clone();
        let receipt = committed_defmi.settle_batch(&packages, now, &mut rng);
        receipt.status.map_err(SettlementError::Cryptography)?;
        if receipt.securities_after != builder_defmi.securities.snapshot()
            || receipt.cash_after != builder_defmi.cash.snapshot()
        {
            return Err(SettlementError::CanonicalDivergence);
        }
        let replay_rejected = packages.iter().all(|package| {
            let replay = committed_defmi.settle(package, now, &mut rng);
            replay.status.is_err()
                && replay.securities_before == replay.securities_after
                && replay.cash_before == replay.cash_after
        });
        if !replay_rejected {
            return Err(SettlementError::ReplayAccepted);
        }
        if !committed_defmi.solvent() {
            return Err(SettlementError::Insolvent);
        }

        let batch_digest = settlement_batch_digest(transition_digest, &members);
        let before_root = combined_root(
            receipt.securities_before,
            receipt.cash_before,
            reservation_before_root,
        );
        let after_root = combined_root(
            receipt.securities_after,
            receipt.cash_after,
            reservation_after_root,
        );
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
        self.defmi = committed_defmi;
        self.reservations = staged_reservations;
        self.participants = staged_participants;
        Ok(OclobSettlementReceipt {
            batch_digest,
            members,
            amount_range_is_threshold: true,
            price_range_is_threshold: true,
            settlement_authorization_quorum: PROOF_QUORUM.len(),
            post_match_participant_signatures: 0,
            securities_before_root: receipt.securities_before,
            securities_after_root: receipt.securities_after,
            cash_before_root: receipt.cash_before,
            cash_after_root: receipt.cash_after,
            reservation_before_root,
            reservation_after_root,
            canonical_state_root: after_root,
            canonical_receipt_digest: finality.receipt_digest,
            canonical_height: self.height,
            replay_rejected,
            solvent: true,
        })
    }
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
    use oclob_core::{OrderCommitment, PublicFill};
    use oclob_proofs::{TransitionProof, TransitionStatement};

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

    fn transition() -> TransitionProof {
        TransitionProof {
            statement: TransitionStatement {
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
                fill_digest: [8; 32],
            },
            attestations: Vec::new(),
        }
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
            .settle_batch(&fills, &transition(), &arriving, 0, 1_000)
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
            .settle_batch(&fills, &transition(), &arriving, 0, 1_000)
            .is_err());
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
        engine
            .settle_batch(
                &[PublicFill {
                    maker_order: first_sale.commitment(),
                    taker_order: second_purchase.commitment(),
                    price: 100,
                    quantity: 10,
                }],
                &transition(),
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
        let reverse = engine
            .settle_batch(
                &[PublicFill {
                    maker_order: first_purchase.commitment(),
                    taker_order: second_sale.commitment(),
                    price: 101,
                    quantity: 5,
                }],
                &transition(),
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
