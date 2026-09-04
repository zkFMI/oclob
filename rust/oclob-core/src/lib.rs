//! Canonical OCLOB orders and deterministic price-time state transitions.
//!
//! Plain order fields deliberately do not implement `Debug` or `Serialize`.
//! Public APIs expose only commitments, aggregate levels and post-match fills.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

const ORDER_COMMITMENT_DOMAIN: &[u8] = b"OCLOB:ORDER-COMMITMENT:v1";
const ORDER_AUTHORITY_DOMAIN: &[u8] = b"OCLOB:ORDER-AUTHORITY:v1";
const PRIVATE_BOOK_DOMAIN: &[u8] = b"OCLOB:PRIVATE-BOOK:v1";
const PUBLIC_BOOK_DOMAIN: &[u8] = b"OCLOB:PUBLIC-BOOK:v1";
const ORDER_CONTROL_DOMAIN: &[u8] = b"OCLOB:ORDER-CONTROL:v1";
const CANCELLATION_DOMAIN: &[u8] = b"OCLOB:CANCELLATION:v1";
const CANCELLATION_COMMITMENT_DOMAIN: &[u8] = b"OCLOB:CANCELLATION-COMMITMENT:v1";
const EXPIRY_COMMITMENT_DOMAIN: &[u8] = b"OCLOB:EXPIRY-COMMITMENT:v1";
const SECRET_ORDER_WIRE_MAGIC: &[u8; 8] = b"OCLOBOR1";
const MAX_SECRET_ORDER_WIRE_BYTES: usize = 512;

pub type Digest32 = [u8; 32];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    pub const fn wire(self) -> u8 {
        match self {
            Self::Buy => 0,
            Self::Sell => 1,
        }
    }

    pub const fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeInForce {
    GoodTilCancelled,
    ImmediateOrCancel,
}

impl TimeInForce {
    const fn wire(self) -> u8 {
        match self {
            Self::GoodTilCancelled => 1,
            Self::ImmediateOrCancel => 2,
        }
    }
}

/// Secret order material.  It is cloneable for secret sharing and state
/// transitions, but intentionally cannot be formatted or serialized.
#[derive(Clone)]
pub struct SecretOrder {
    version: u16,
    order_id: Digest32,
    ephemeral_public_key: Digest32,
    market_id: String,
    side: Side,
    limit_price: u64,
    quantity: u64,
    time_in_force: TimeInForce,
    expires_at: u64,
    participant_handle: Digest32,
    dekyx_nullifier: Digest32,
    reservation_id: Digest32,
    reservation_limit: u64,
    minimum_lot: u64,
    max_fee: u64,
    cancellation_secret_digest: Digest32,
    client_nonce: Digest32,
    salt: Digest32,
}

impl SecretOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        side: Side,
        limit_price: u64,
        quantity: u64,
        time_in_force: TimeInForce,
        expires_at: u64,
        participant_handle: Digest32,
        client_nonce: Digest32,
        salt: Digest32,
    ) -> Result<Self, OrderError> {
        Self::new_with_dekyx_nullifier(
            market_id,
            side,
            limit_price,
            quantity,
            time_in_force,
            expires_at,
            participant_handle,
            entity_scope_digest(&participant_handle),
            client_nonce,
            salt,
        )
    }

    /// Constructs an order bound to a DeKYX scope nullifier while deriving all
    /// one-use controls locally.  The nullifier comes from a verified anonymous
    /// presentation; it is stable for one legal entity in this market scope,
    /// whereas the participant handle and order key may rotate per order.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_dekyx_nullifier(
        market_id: impl Into<String>,
        side: Side,
        limit_price: u64,
        quantity: u64,
        time_in_force: TimeInForce,
        expires_at: u64,
        participant_handle: Digest32,
        dekyx_nullifier: Digest32,
        client_nonce: Digest32,
        salt: Digest32,
    ) -> Result<Self, OrderError> {
        let reservation_limit = match side {
            Side::Buy => limit_price
                .checked_mul(quantity)
                .ok_or(OrderError::Invalid("reservation limit overflows"))?,
            Side::Sell => quantity,
        };
        let controls = OrderControls {
            order_id: control_digest(b"order-id", &participant_handle, &client_nonce),
            ephemeral_public_key: control_digest(
                b"ephemeral-key",
                &participant_handle,
                &client_nonce,
            ),
            dekyx_nullifier,
            reservation_id: control_digest(b"reservation", &participant_handle, &client_nonce),
            reservation_limit,
            minimum_lot: 1,
            max_fee: 0,
            cancellation_secret_digest: cancellation_digest(&salt),
        };
        Self::new_with_controls(
            market_id,
            side,
            limit_price,
            quantity,
            time_in_force,
            expires_at,
            participant_handle,
            client_nonce,
            salt,
            controls,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_controls(
        market_id: impl Into<String>,
        side: Side,
        limit_price: u64,
        quantity: u64,
        time_in_force: TimeInForce,
        expires_at: u64,
        participant_handle: Digest32,
        client_nonce: Digest32,
        salt: Digest32,
        controls: OrderControls,
    ) -> Result<Self, OrderError> {
        let market_id = market_id.into();
        if market_id.is_empty() || market_id.len() > 64 {
            return Err(OrderError::Invalid("market id must contain 1-64 bytes"));
        }
        if limit_price == 0 || quantity == 0 || expires_at == 0 {
            return Err(OrderError::Invalid(
                "price, quantity and expiry must all be positive",
            ));
        }
        if participant_handle == [0; 32]
            || client_nonce == [0; 32]
            || salt == [0; 32]
            || controls.order_id == [0; 32]
            || controls.ephemeral_public_key == [0; 32]
            || controls.dekyx_nullifier == [0; 32]
            || controls.reservation_id == [0; 32]
            || controls.cancellation_secret_digest == [0; 32]
            || controls.minimum_lot == 0
            || !quantity.is_multiple_of(controls.minimum_lot)
        {
            return Err(OrderError::Invalid(
                "order controls, participant handle, nonce and commitment salt are required",
            ));
        }
        let required_reserve = match side {
            Side::Buy => limit_price
                .checked_mul(quantity)
                .and_then(|value| value.checked_add(controls.max_fee))
                .ok_or(OrderError::Invalid("reservation limit overflows"))?,
            Side::Sell => quantity,
        };
        if controls.reservation_limit < required_reserve {
            return Err(OrderError::Invalid(
                "reservation does not cover the worst permitted fill",
            ));
        }
        Ok(Self {
            version: 1,
            order_id: controls.order_id,
            ephemeral_public_key: controls.ephemeral_public_key,
            market_id,
            side,
            limit_price,
            quantity,
            time_in_force,
            expires_at,
            participant_handle,
            dekyx_nullifier: controls.dekyx_nullifier,
            reservation_id: controls.reservation_id,
            reservation_limit: controls.reservation_limit,
            minimum_lot: controls.minimum_lot,
            max_fee: controls.max_fee,
            cancellation_secret_digest: controls.cancellation_secret_digest,
            client_nonce,
            salt,
        })
    }

    pub fn market_id(&self) -> &str {
        &self.market_id
    }

    pub const fn side(&self) -> Side {
        self.side
    }

    pub const fn limit_price(&self) -> u64 {
        self.limit_price
    }

    pub const fn quantity(&self) -> u64 {
        self.quantity
    }

    pub const fn time_in_force(&self) -> TimeInForce {
        self.time_in_force
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub const fn participant_handle(&self) -> Digest32 {
        self.participant_handle
    }

    pub const fn order_id(&self) -> Digest32 {
        self.order_id
    }

    pub const fn dekyx_nullifier(&self) -> Digest32 {
        self.dekyx_nullifier
    }

    pub const fn reservation_id(&self) -> Digest32 {
        self.reservation_id
    }

    pub const fn reservation_limit(&self) -> u64 {
        self.reservation_limit
    }

    pub const fn minimum_lot(&self) -> u64 {
        self.minimum_lot
    }

    pub const fn max_fee(&self) -> u64 {
        self.max_fee
    }

    pub const fn cancellation_secret(&self) -> Digest32 {
        self.salt
    }

    /// Canonical private wire representation for an authenticated, encrypted
    /// corporate outbox. The returned bytes contain the full order and must
    /// never be logged, exposed through an operator API, or stored unencrypted.
    /// An explicit method is used instead of `Serialize` so a secret order
    /// cannot accidentally enter a public receipt or telemetry payload.
    pub fn to_secret_wire(&self) -> Vec<u8> {
        let payload = self.canonical_payload();
        let mut bytes = Vec::with_capacity(SECRET_ORDER_WIRE_MAGIC.len() + 8 + payload.len() + 32);
        bytes.extend_from_slice(SECRET_ORDER_WIRE_MAGIC);
        put_bytes(&mut bytes, &payload);
        bytes.extend_from_slice(&self.salt);
        bytes
    }

    /// Parses the strict canonical private wire format produced by
    /// [`Self::to_secret_wire`]. Unknown versions, non-canonical lengths and
    /// trailing bytes fail closed before reservation or MPC execution.
    pub fn from_secret_wire(bytes: &[u8]) -> Result<Self, OrderError> {
        if bytes.len() > MAX_SECRET_ORDER_WIRE_BYTES
            || bytes.len() < SECRET_ORDER_WIRE_MAGIC.len() + 8 + 32
            || bytes.get(..SECRET_ORDER_WIRE_MAGIC.len()) != Some(SECRET_ORDER_WIRE_MAGIC)
        {
            return Err(OrderError::Invalid("secret order wire is malformed"));
        }
        let mut wire = SecretWireCursor::new(&bytes[SECRET_ORDER_WIRE_MAGIC.len()..]);
        let payload_len = usize::try_from(wire.u64()?)
            .map_err(|_| OrderError::Invalid("secret order wire is malformed"))?;
        let payload = wire.bytes(payload_len)?;
        let salt = wire.digest()?;
        wire.finish()?;

        let mut payload = SecretWireCursor::new(payload);
        let version = payload.u16()?;
        if version != 1 {
            return Err(OrderError::Invalid(
                "secret order wire version is unsupported",
            ));
        }
        let order_id = payload.digest()?;
        let ephemeral_public_key = payload.digest()?;
        let market_len = usize::try_from(payload.u64()?)
            .map_err(|_| OrderError::Invalid("secret order wire is malformed"))?;
        let market_id = std::str::from_utf8(payload.bytes(market_len)?)
            .map_err(|_| OrderError::Invalid("secret order market is not UTF-8"))?
            .to_owned();
        let side = match payload.u8()? {
            0 => Side::Buy,
            1 => Side::Sell,
            _ => return Err(OrderError::Invalid("secret order side is invalid")),
        };
        let limit_price = payload.u64()?;
        let quantity = payload.u64()?;
        let time_in_force = match payload.u8()? {
            1 => TimeInForce::GoodTilCancelled,
            2 => TimeInForce::ImmediateOrCancel,
            _ => return Err(OrderError::Invalid("secret order time-in-force is invalid")),
        };
        let expires_at = payload.u64()?;
        let participant_handle = payload.digest()?;
        let dekyx_nullifier = payload.digest()?;
        let reservation_id = payload.digest()?;
        let reservation_limit = payload.u64()?;
        let minimum_lot = payload.u64()?;
        let max_fee = payload.u64()?;
        let cancellation_secret_digest = payload.digest()?;
        let client_nonce = payload.digest()?;
        payload.finish()?;

        Self::new_with_controls(
            market_id,
            side,
            limit_price,
            quantity,
            time_in_force,
            expires_at,
            participant_handle,
            client_nonce,
            salt,
            OrderControls {
                order_id,
                ephemeral_public_key,
                dekyx_nullifier,
                reservation_id,
                reservation_limit,
                minimum_lot,
                max_fee,
                cancellation_secret_digest,
            },
        )
    }

    pub fn validate_market_rules(&self, rules: MarketRules) -> Result<(), OrderError> {
        rules.validate()?;
        if !self.limit_price.is_multiple_of(rules.tick_size)
            || !self.quantity.is_multiple_of(rules.lot_size)
            || self.minimum_lot != rules.lot_size
            || self.max_fee > rules.maximum_fee
        {
            return Err(OrderError::Invalid(
                "order violates tick, lot, or fee rules",
            ));
        }
        Ok(())
    }

    pub fn commitment(&self) -> OrderCommitment {
        let mut hash = Sha256::new();
        hash.update(ORDER_COMMITMENT_DOMAIN);
        hash.update(self.salt);
        hash.update(self.canonical_payload());
        OrderCommitment(hash.finalize().into())
    }

    fn canonical_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(160);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.order_id);
        bytes.extend_from_slice(&self.ephemeral_public_key);
        put_bytes(&mut bytes, self.market_id.as_bytes());
        bytes.push(self.side.wire());
        bytes.extend_from_slice(&self.limit_price.to_be_bytes());
        bytes.extend_from_slice(&self.quantity.to_be_bytes());
        bytes.push(self.time_in_force.wire());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.participant_handle);
        bytes.extend_from_slice(&self.dekyx_nullifier);
        bytes.extend_from_slice(&self.reservation_id);
        bytes.extend_from_slice(&self.reservation_limit.to_be_bytes());
        bytes.extend_from_slice(&self.minimum_lot.to_be_bytes());
        bytes.extend_from_slice(&self.max_fee.to_be_bytes());
        bytes.extend_from_slice(&self.cancellation_secret_digest);
        bytes.extend_from_slice(&self.client_nonce);
        bytes
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderControls {
    pub order_id: Digest32,
    pub ephemeral_public_key: Digest32,
    pub dekyx_nullifier: Digest32,
    pub reservation_id: Digest32,
    pub reservation_limit: u64,
    pub minimum_lot: u64,
    pub max_fee: u64,
    pub cancellation_secret_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketRules {
    pub tick_size: u64,
    pub lot_size: u64,
    pub maximum_fee: u64,
    pub max_match_slots: usize,
}

impl MarketRules {
    pub const fn p1() -> Self {
        Self {
            tick_size: 1,
            lot_size: 1,
            maximum_fee: 0,
            max_match_slots: MAX_MATCH_SLOTS,
        }
    }

    pub fn validate(self) -> Result<(), OrderError> {
        if self.tick_size == 0 || self.lot_size == 0 || self.max_match_slots != MAX_MATCH_SLOTS {
            return Err(OrderError::Invalid(
                "tick, lot, and fixed matching capacity must be valid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OrderCommitment(pub Digest32);

impl OrderCommitment {
    pub fn hex(self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderAuthority {
    pub commitment: OrderCommitment,
    pub authorization_deadline: u64,
    pub verifying_key: Digest32,
    pub signature: Vec<u8>,
}

pub fn authorize_order(
    order: &SecretOrder,
    authorization_deadline: u64,
    signing_key: &SigningKey,
) -> Result<OrderAuthority, OrderError> {
    if authorization_deadline < order.expires_at() {
        return Err(OrderError::Invalid(
            "authorization expires before the order",
        ));
    }
    let commitment = order.commitment();
    let body = authority_body(commitment, authorization_deadline);
    Ok(OrderAuthority {
        commitment,
        authorization_deadline,
        verifying_key: signing_key.verifying_key().to_bytes(),
        signature: signing_key.sign(&body).to_bytes().to_vec(),
    })
}

impl OrderAuthority {
    pub fn verify(&self, order: &SecretOrder, now: u64) -> Result<(), OrderError> {
        if now > self.authorization_deadline
            || now > order.expires_at()
            || self.commitment != order.commitment()
        {
            return Err(OrderError::Authority);
        }
        let key =
            VerifyingKey::from_bytes(&self.verifying_key).map_err(|_| OrderError::Authority)?;
        let signature =
            Signature::try_from(self.signature.as_slice()).map_err(|_| OrderError::Authority)?;
        key.verify_strict(
            &authority_body(self.commitment, self.authorization_deadline),
            &signature,
        )
        .map_err(|_| OrderError::Authority)
    }
}

fn authority_body(commitment: OrderCommitment, deadline: u64) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(ORDER_AUTHORITY_DOMAIN);
    hash.update(commitment.0);
    hash.update(deadline.to_be_bytes());
    hash.finalize().to_vec()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum OrderError {
    #[error("invalid order: {0}")]
    Invalid(&'static str),
    #[error("order authority is expired, malformed, or bound to another order")]
    Authority,
    #[error("order commitment was already admitted")]
    Replay,
    #[error("MPC result does not describe the canonical price-time transition")]
    InvalidMpcResult,
    #[error("the order belongs to a different market")]
    WrongMarket,
    #[error("the target order is unknown or already terminal")]
    UnknownOrder,
    #[error("cancellation secret does not authorize the target order")]
    InvalidCancellation,
}

/// The smallest private input frame consumed by the matching circuit.
/// Deliberately has neither `Debug` nor serialization.
pub struct PrivateMatchInput {
    pub resting_side: Side,
    pub resting_price: u64,
    pub resting_quantity: u64,
    pub arriving_side: Side,
    pub arriving_price: u64,
    pub arriving_quantity: u64,
}

pub const MAX_MATCH_SLOTS: usize = 8;

/// Price-time ordered secret state for one fixed-shape MPC transition.
/// Individual resting quantities and ownership remain outside public receipts.
pub struct PrivateMatchBatch {
    pub resting: Vec<PrivateRestingInput>,
    pub arriving_side: Side,
    pub arriving_price: u64,
    pub arriving_quantity: u64,
    pub arriving_can_rest: bool,
}

pub struct PrivateRestingInput {
    pub commitment: OrderCommitment,
    pub side: Side,
    pub price: u64,
    pub quantity: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MpcSlotResult {
    pub matched: bool,
    pub trade_price: u64,
    pub trade_quantity: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MpcBatchResult {
    pub slots: Vec<MpcSlotResult>,
    pub arriving_remaining: u64,
}

/// A cancellation uses the same ordered confidential command stream as an
/// order. It deliberately cannot be formatted or serialized in plaintext.
#[derive(Clone)]
pub struct SecretCancellation {
    target: OrderCommitment,
    secret: Digest32,
    nonce: Digest32,
    salt: Digest32,
}

impl SecretCancellation {
    pub fn new(
        target: OrderCommitment,
        secret: Digest32,
        nonce: Digest32,
        salt: Digest32,
    ) -> Result<Self, OrderError> {
        if target.0 == [0; 32] || secret == [0; 32] || nonce == [0; 32] || salt == [0; 32] {
            return Err(OrderError::Invalid("cancellation fields are required"));
        }
        Ok(Self {
            target,
            secret,
            nonce,
            salt,
        })
    }

    pub const fn target(&self) -> OrderCommitment {
        self.target
    }

    pub fn commitment(&self) -> OrderCommitment {
        let mut hash = Sha256::new();
        hash.update(CANCELLATION_COMMITMENT_DOMAIN);
        hash.update(self.salt);
        hash.update(self.target.0);
        hash.update(self.secret);
        hash.update(self.nonce);
        OrderCommitment(hash.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MpcMatchResult {
    pub matched: bool,
    pub trade_price: u64,
    pub trade_quantity: u64,
    pub resting_remaining: u64,
    pub arriving_remaining: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicFill {
    pub maker_order: OrderCommitment,
    pub taker_order: OrderCommitment,
    pub price: u64,
    pub quantity: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicLevel {
    pub side: Side,
    pub price: u64,
    pub quantity: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicBookSnapshot {
    pub market_id: String,
    pub sequence: u64,
    pub levels: Vec<PublicLevel>,
    pub state_root: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BookTransition {
    pub sequence: u64,
    pub private_before_root: Digest32,
    pub private_after_root: Digest32,
    pub public_before_root: Digest32,
    pub public_after: PublicBookSnapshot,
    pub fill: Option<PublicFill>,
    pub fills: Vec<PublicFill>,
    pub arriving_remaining: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancellationTransition {
    pub sequence: u64,
    pub cancellation_commitment: OrderCommitment,
    pub target_commitment: OrderCommitment,
    pub released_quantity: u64,
    pub private_before_root: Digest32,
    pub private_after_root: Digest32,
    pub public_before_root: Digest32,
    pub public_after: PublicBookSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpiryTransition {
    pub sequence: u64,
    pub expiry_commitment: OrderCommitment,
    pub cutoff: u64,
    pub expired_orders: Vec<OrderCommitment>,
    pub released_quantity: u64,
    pub private_before_root: Digest32,
    pub private_after_root: Digest32,
    pub public_before_root: Digest32,
    pub public_after: PublicBookSnapshot,
}

#[derive(Clone)]
struct RestingOrder {
    secret: SecretOrder,
    authority: OrderAuthority,
    remaining: u64,
    sequence: u64,
}

#[derive(Clone)]
pub struct PrivateBook {
    market_id: String,
    sequence: u64,
    bids: BTreeMap<u64, VecDeque<RestingOrder>>,
    asks: BTreeMap<u64, VecDeque<RestingOrder>>,
    admitted: BTreeSet<OrderCommitment>,
}

impl PrivateBook {
    pub fn new(market_id: impl Into<String>) -> Result<Self, OrderError> {
        let market_id = market_id.into();
        if market_id.is_empty() || market_id.len() > 64 {
            return Err(OrderError::Invalid("market id must contain 1-64 bytes"));
        }
        Ok(Self {
            market_id,
            sequence: 0,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            admitted: BTreeSet::new(),
        })
    }

    pub fn insert_resting(
        &mut self,
        order: SecretOrder,
        authority: OrderAuthority,
        certificate_sequence: u64,
        now: u64,
    ) -> Result<(), OrderError> {
        authority.verify(&order, now)?;
        self.check_admission(&order, authority.commitment, certificate_sequence)?;
        if order.time_in_force() != TimeInForce::GoodTilCancelled {
            return Err(OrderError::Invalid("only GTC orders can rest"));
        }
        let commitment = authority.commitment;
        self.insert_record(RestingOrder {
            remaining: order.quantity(),
            secret: order,
            authority,
            sequence: certificate_sequence,
        });
        self.admitted.insert(commitment);
        self.sequence = certificate_sequence;
        Ok(())
    }

    pub fn private_match_input(
        &self,
        arriving: &SecretOrder,
    ) -> Result<Option<PrivateMatchInput>, OrderError> {
        if arriving.market_id() != self.market_id {
            return Err(OrderError::WrongMarket);
        }
        Ok(self
            .best_opposite(arriving)
            .map(|resting| PrivateMatchInput {
                resting_side: resting.secret.side(),
                resting_price: resting.secret.limit_price(),
                resting_quantity: resting.remaining,
                arriving_side: arriving.side(),
                arriving_price: arriving.limit_price(),
                arriving_quantity: arriving.quantity(),
            }))
    }

    pub fn private_match_batch(
        &self,
        arriving: &SecretOrder,
        now: u64,
    ) -> Result<PrivateMatchBatch, OrderError> {
        if arriving.market_id() != self.market_id {
            return Err(OrderError::WrongMarket);
        }
        let ordered = match arriving.side() {
            Side::Buy => self
                .asks
                .values()
                .flat_map(|queue| queue.iter())
                .collect::<Vec<_>>(),
            Side::Sell => self
                .bids
                .iter()
                .rev()
                .flat_map(|(_, queue)| queue.iter())
                .collect::<Vec<_>>(),
        };
        let resting = ordered
            .into_iter()
            .filter(|order| order.secret.expires_at() >= now)
            .take(MAX_MATCH_SLOTS)
            .map(|order| PrivateRestingInput {
                commitment: order.authority.commitment,
                side: order.secret.side(),
                price: order.secret.limit_price(),
                quantity: order.remaining,
            })
            .collect();
        Ok(PrivateMatchBatch {
            resting,
            arriving_side: arriving.side(),
            arriving_price: arriving.limit_price(),
            arriving_quantity: arriving.quantity(),
            arriving_can_rest: arriving.time_in_force() == TimeInForce::GoodTilCancelled,
        })
    }

    pub fn exceeds_fixed_match_capacity(&self, arriving: &SecretOrder, now: u64) -> bool {
        let ordered = match arriving.side() {
            Side::Buy => self
                .asks
                .values()
                .flat_map(|queue| queue.iter())
                .collect::<Vec<_>>(),
            Side::Sell => self
                .bids
                .iter()
                .rev()
                .flat_map(|(_, queue)| queue.iter())
                .collect::<Vec<_>>(),
        };
        let mut remaining = arriving.quantity();
        let mut matches = 0_usize;
        for resting in ordered
            .into_iter()
            .filter(|order| order.secret.expires_at() >= now)
        {
            let crossed = match arriving.side() {
                Side::Buy => arriving.limit_price() >= resting.secret.limit_price(),
                Side::Sell => arriving.limit_price() <= resting.secret.limit_price(),
            };
            if !crossed || remaining == 0 {
                break;
            }
            remaining -= remaining.min(resting.remaining);
            matches += 1;
            if matches > MAX_MATCH_SLOTS {
                return true;
            }
        }
        false
    }

    pub fn apply_mpc_result(
        &mut self,
        arriving: SecretOrder,
        authority: OrderAuthority,
        certificate_sequence: u64,
        now: u64,
        result: MpcMatchResult,
    ) -> Result<BookTransition, OrderError> {
        authority.verify(&arriving, now)?;
        self.check_admission(&arriving, authority.commitment, certificate_sequence)?;
        let private_before_root = self.private_root();
        let public_before_root = self.public_snapshot().state_root;
        let expected = self.expected_result(&arriving);
        if result != expected {
            return Err(OrderError::InvalidMpcResult);
        }
        let arriving_commitment = authority.commitment;

        let fill = if result.matched {
            let resting = self
                .best_opposite_mut(&arriving)
                .ok_or(OrderError::InvalidMpcResult)?;
            let maker_order = resting.authority.commitment;
            if result.resting_remaining == 0 {
                self.remove_best(&arriving);
            } else {
                let resting = self
                    .best_opposite_mut(&arriving)
                    .ok_or(OrderError::InvalidMpcResult)?;
                resting.remaining = result.resting_remaining;
            }
            Some(PublicFill {
                maker_order,
                taker_order: arriving_commitment,
                price: result.trade_price,
                quantity: result.trade_quantity,
            })
        } else {
            None
        };
        let fills = fill.iter().cloned().collect();

        if result.arriving_remaining > 0
            && arriving.time_in_force() == TimeInForce::GoodTilCancelled
        {
            self.insert_record(RestingOrder {
                remaining: result.arriving_remaining,
                secret: arriving,
                authority,
                sequence: certificate_sequence,
            });
        }
        self.admitted.insert(arriving_commitment);
        self.sequence = certificate_sequence;
        let public_after = self.public_snapshot();
        Ok(BookTransition {
            sequence: certificate_sequence,
            private_before_root,
            private_after_root: self.private_root(),
            public_before_root,
            public_after,
            fill,
            fills,
            arriving_remaining: result.arriving_remaining,
        })
    }

    pub fn apply_mpc_batch_result(
        &mut self,
        arriving: SecretOrder,
        authority: OrderAuthority,
        certificate_sequence: u64,
        now: u64,
        result: MpcBatchResult,
    ) -> Result<BookTransition, OrderError> {
        authority.verify(&arriving, now)?;
        self.check_admission(&arriving, authority.commitment, certificate_sequence)?;
        let batch = self.private_match_batch(&arriving, now)?;
        let expected = expected_batch(&batch);
        if result != expected {
            return Err(OrderError::InvalidMpcResult);
        }
        let private_before_root = self.private_root();
        let public_before_root = self.public_snapshot().state_root;
        let mut fills = Vec::new();
        for (resting, slot) in batch.resting.iter().zip(&result.slots) {
            if slot.matched {
                let resting_remaining = resting
                    .quantity
                    .checked_sub(slot.trade_quantity)
                    .ok_or(OrderError::InvalidMpcResult)?;
                update_remainder(
                    &mut self.bids,
                    &mut self.asks,
                    resting.commitment,
                    resting_remaining,
                )?;
                fills.push(PublicFill {
                    maker_order: resting.commitment,
                    taker_order: authority.commitment,
                    price: slot.trade_price,
                    quantity: slot.trade_quantity,
                });
            }
        }
        let arriving_commitment = authority.commitment;
        if result.arriving_remaining > 0
            && arriving.time_in_force() == TimeInForce::GoodTilCancelled
        {
            self.insert_record(RestingOrder {
                remaining: result.arriving_remaining,
                secret: arriving,
                authority,
                sequence: certificate_sequence,
            });
        }
        self.admitted.insert(arriving_commitment);
        self.sequence = certificate_sequence;
        let public_after = self.public_snapshot();
        Ok(BookTransition {
            sequence: certificate_sequence,
            private_before_root,
            private_after_root: self.private_root(),
            public_before_root,
            public_after,
            fill: fills.first().cloned(),
            fills,
            arriving_remaining: result.arriving_remaining,
        })
    }

    pub fn apply_cancellation(
        &mut self,
        cancellation: &SecretCancellation,
        certificate_sequence: u64,
    ) -> Result<CancellationTransition, OrderError> {
        if certificate_sequence != self.sequence + 1 {
            return Err(OrderError::Invalid("certificate sequence is not next"));
        }
        let command = cancellation.commitment();
        if self.admitted.contains(&command) {
            return Err(OrderError::Replay);
        }
        let record = find_record(&self.bids, &self.asks, cancellation.target)
            .ok_or(OrderError::UnknownOrder)?;
        if record.secret.cancellation_secret_digest != cancellation_digest(&cancellation.secret) {
            return Err(OrderError::InvalidCancellation);
        }
        let released_quantity = record.remaining;
        let private_before_root = self.private_root();
        let public_before_root = self.public_snapshot().state_root;
        remove_by_commitment(&mut self.bids, &mut self.asks, cancellation.target)?;
        self.admitted.insert(command);
        self.sequence = certificate_sequence;
        let public_after = self.public_snapshot();
        Ok(CancellationTransition {
            sequence: certificate_sequence,
            cancellation_commitment: command,
            target_commitment: cancellation.target,
            released_quantity,
            private_before_root,
            private_after_root: self.private_root(),
            public_before_root,
            public_after,
        })
    }

    pub fn expired_commitments(&self, cutoff: u64) -> Vec<OrderCommitment> {
        let mut commitments = self
            .bids
            .values()
            .chain(self.asks.values())
            .flat_map(|queue| queue.iter())
            .filter(|order| order.secret.expires_at() < cutoff)
            .map(|order| order.authority.commitment)
            .collect::<Vec<_>>();
        commitments.sort_unstable();
        commitments
    }

    pub fn apply_expiry(
        &mut self,
        cutoff: u64,
        command: OrderCommitment,
        certificate_sequence: u64,
    ) -> Result<ExpiryTransition, OrderError> {
        if certificate_sequence != self.sequence + 1 {
            return Err(OrderError::Invalid("certificate sequence is not next"));
        }
        if self.admitted.contains(&command) {
            return Err(OrderError::Replay);
        }
        let expired_orders = self.expired_commitments(cutoff);
        if expired_orders.is_empty()
            || command != expiry_commitment(&self.market_id, cutoff, &expired_orders)
        {
            return Err(OrderError::Invalid(
                "expiry command is empty or non-canonical",
            ));
        }
        let private_before_root = self.private_root();
        let public_before_root = self.public_snapshot().state_root;
        let mut released_quantity = 0_u64;
        for commitment in &expired_orders {
            let record =
                find_record(&self.bids, &self.asks, *commitment).ok_or(OrderError::UnknownOrder)?;
            released_quantity = released_quantity
                .checked_add(record.remaining)
                .ok_or(OrderError::Invalid("expired quantity overflowed"))?;
            remove_by_commitment(&mut self.bids, &mut self.asks, *commitment)?;
        }
        self.admitted.insert(command);
        self.sequence = certificate_sequence;
        let public_after = self.public_snapshot();
        Ok(ExpiryTransition {
            sequence: certificate_sequence,
            expiry_commitment: command,
            cutoff,
            expired_orders,
            released_quantity,
            private_before_root,
            private_after_root: self.private_root(),
            public_before_root,
            public_after,
        })
    }

    pub fn public_snapshot(&self) -> PublicBookSnapshot {
        let mut levels = Vec::new();
        for (price, queue) in self.bids.iter().rev() {
            levels.push(level(Side::Buy, *price, queue));
        }
        for (price, queue) in &self.asks {
            levels.push(level(Side::Sell, *price, queue));
        }
        let state_root = public_root(&self.market_id, self.sequence, &levels);
        PublicBookSnapshot {
            market_id: self.market_id.clone(),
            sequence: self.sequence,
            levels,
            state_root,
        }
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    fn check_admission(
        &self,
        order: &SecretOrder,
        commitment: OrderCommitment,
        certificate_sequence: u64,
    ) -> Result<(), OrderError> {
        if order.market_id() != self.market_id {
            return Err(OrderError::WrongMarket);
        }
        if self.admitted.contains(&commitment) {
            return Err(OrderError::Replay);
        }
        if certificate_sequence != self.sequence + 1 {
            return Err(OrderError::Invalid("certificate sequence is not next"));
        }
        Ok(())
    }

    fn insert_record(&mut self, record: RestingOrder) {
        let book = match record.secret.side() {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        book.entry(record.secret.limit_price())
            .or_default()
            .push_back(record);
    }

    fn best_opposite(&self, arriving: &SecretOrder) -> Option<&RestingOrder> {
        match arriving.side() {
            Side::Buy => self.asks.iter().next().and_then(|(_, queue)| queue.front()),
            Side::Sell => self
                .bids
                .iter()
                .next_back()
                .and_then(|(_, queue)| queue.front()),
        }
    }

    fn best_opposite_mut(&mut self, arriving: &SecretOrder) -> Option<&mut RestingOrder> {
        match arriving.side() {
            Side::Buy => self
                .asks
                .iter_mut()
                .next()
                .and_then(|(_, queue)| queue.front_mut()),
            Side::Sell => self
                .bids
                .iter_mut()
                .next_back()
                .and_then(|(_, queue)| queue.front_mut()),
        }
    }

    fn remove_best(&mut self, arriving: &SecretOrder) {
        let book = match arriving.side() {
            Side::Buy => &mut self.asks,
            Side::Sell => &mut self.bids,
        };
        let price = match arriving.side() {
            Side::Buy => book.keys().next().copied(),
            Side::Sell => book.keys().next_back().copied(),
        };
        if let Some(price) = price {
            if let Some(queue) = book.get_mut(&price) {
                queue.pop_front();
                if queue.is_empty() {
                    book.remove(&price);
                }
            }
        }
    }

    fn expected_result(&self, arriving: &SecretOrder) -> MpcMatchResult {
        let Some(resting) = self.best_opposite(arriving) else {
            return MpcMatchResult {
                matched: false,
                trade_price: 0,
                trade_quantity: 0,
                resting_remaining: 0,
                arriving_remaining: arriving.quantity(),
            };
        };
        let crossed = match arriving.side() {
            Side::Buy => arriving.limit_price() >= resting.secret.limit_price(),
            Side::Sell => arriving.limit_price() <= resting.secret.limit_price(),
        };
        let quantity = if crossed {
            arriving.quantity().min(resting.remaining)
        } else {
            0
        };
        MpcMatchResult {
            matched: crossed,
            trade_price: if crossed {
                resting.secret.limit_price()
            } else {
                0
            },
            trade_quantity: quantity,
            resting_remaining: resting.remaining - quantity,
            arriving_remaining: arriving.quantity() - quantity,
        }
    }

    fn private_root(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(PRIVATE_BOOK_DOMAIN);
        put_hash_bytes(&mut hash, self.market_id.as_bytes());
        hash.update(self.sequence.to_be_bytes());
        for book in [&self.bids, &self.asks] {
            for (price, queue) in book {
                hash.update(price.to_be_bytes());
                for order in queue {
                    hash.update(order.authority.commitment.0);
                    hash.update(order.remaining.to_be_bytes());
                    hash.update(order.sequence.to_be_bytes());
                }
            }
        }
        hash.finalize().into()
    }
}

pub fn expected_batch(batch: &PrivateMatchBatch) -> MpcBatchResult {
    let mut arriving_remaining = batch.arriving_quantity;
    let mut slots = Vec::with_capacity(batch.resting.len());
    for resting in &batch.resting {
        let crossed = resting.side != batch.arriving_side
            && match batch.arriving_side {
                Side::Buy => batch.arriving_price >= resting.price,
                Side::Sell => batch.arriving_price <= resting.price,
            }
            && arriving_remaining > 0
            && resting.quantity > 0;
        let trade_quantity = if crossed {
            arriving_remaining.min(resting.quantity)
        } else {
            0
        };
        arriving_remaining -= trade_quantity;
        slots.push(MpcSlotResult {
            matched: crossed,
            trade_price: if crossed { resting.price } else { 0 },
            trade_quantity,
        });
    }
    MpcBatchResult {
        slots,
        arriving_remaining: if batch.arriving_can_rest {
            arriving_remaining
        } else {
            0
        },
    }
}

fn update_remainder(
    bids: &mut BTreeMap<u64, VecDeque<RestingOrder>>,
    asks: &mut BTreeMap<u64, VecDeque<RestingOrder>>,
    commitment: OrderCommitment,
    remaining: u64,
) -> Result<(), OrderError> {
    for book in [bids, asks] {
        let keys = book.keys().copied().collect::<Vec<_>>();
        for price in keys {
            let Some(queue) = book.get_mut(&price) else {
                continue;
            };
            if let Some(index) = queue
                .iter()
                .position(|order| order.authority.commitment == commitment)
            {
                if remaining == 0 {
                    queue.remove(index);
                } else {
                    queue[index].remaining = remaining;
                }
                if queue.is_empty() {
                    book.remove(&price);
                }
                return Ok(());
            }
        }
    }
    Err(OrderError::InvalidMpcResult)
}

fn find_record<'a>(
    bids: &'a BTreeMap<u64, VecDeque<RestingOrder>>,
    asks: &'a BTreeMap<u64, VecDeque<RestingOrder>>,
    commitment: OrderCommitment,
) -> Option<&'a RestingOrder> {
    bids.values()
        .chain(asks.values())
        .flat_map(|queue| queue.iter())
        .find(|order| order.authority.commitment == commitment)
}

fn remove_by_commitment(
    bids: &mut BTreeMap<u64, VecDeque<RestingOrder>>,
    asks: &mut BTreeMap<u64, VecDeque<RestingOrder>>,
    commitment: OrderCommitment,
) -> Result<(), OrderError> {
    update_remainder(bids, asks, commitment, 0).map_err(|_| OrderError::UnknownOrder)
}

fn level(side: Side, price: u64, queue: &VecDeque<RestingOrder>) -> PublicLevel {
    PublicLevel {
        side,
        price,
        quantity: queue.iter().map(|order| order.remaining).sum(),
    }
}

fn public_root(market_id: &str, sequence: u64, levels: &[PublicLevel]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(PUBLIC_BOOK_DOMAIN);
    put_hash_bytes(&mut hash, market_id.as_bytes());
    hash.update(sequence.to_be_bytes());
    for level in levels {
        hash.update([level.side.wire()]);
        hash.update(level.price.to_be_bytes());
        hash.update(level.quantity.to_be_bytes());
    }
    hash.finalize().into()
}

struct SecretWireCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SecretWireCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], OrderError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(OrderError::Invalid("secret order wire is malformed"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(OrderError::Invalid("secret order wire is malformed"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, OrderError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, OrderError> {
        let bytes: [u8; 2] = self
            .bytes(2)?
            .try_into()
            .map_err(|_| OrderError::Invalid("secret order wire is malformed"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, OrderError> {
        let bytes: [u8; 8] = self
            .bytes(8)?
            .try_into()
            .map_err(|_| OrderError::Invalid("secret order wire is malformed"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn digest(&mut self) -> Result<Digest32, OrderError> {
        self.bytes(32)?
            .try_into()
            .map_err(|_| OrderError::Invalid("secret order wire is malformed"))
    }

    fn finish(self) -> Result<(), OrderError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(OrderError::Invalid(
                "secret order wire contains trailing bytes",
            ))
        }
    }
}

fn put_bytes(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    target.extend_from_slice(bytes);
}

fn put_hash_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn control_digest(label: &[u8], participant: &Digest32, nonce: &Digest32) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(ORDER_CONTROL_DOMAIN);
    put_hash_bytes(&mut hash, label);
    hash.update(participant);
    hash.update(nonce);
    hash.finalize().into()
}

fn entity_scope_digest(participant: &Digest32) -> Digest32 {
    Sha256::new()
        .chain_update(ORDER_CONTROL_DOMAIN)
        .chain_update(b"dekyx-entity-scope")
        .chain_update(participant)
        .finalize()
        .into()
}

pub fn cancellation_digest(secret: &Digest32) -> Digest32 {
    Sha256::new()
        .chain_update(CANCELLATION_DOMAIN)
        .chain_update(secret)
        .finalize()
        .into()
}

pub fn expiry_commitment(
    market_id: &str,
    cutoff: u64,
    expired_orders: &[OrderCommitment],
) -> OrderCommitment {
    let mut orders = expired_orders.to_vec();
    orders.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(EXPIRY_COMMITMENT_DOMAIN);
    put_hash_bytes(&mut hash, market_id.as_bytes());
    hash.update(cutoff.to_be_bytes());
    hash.update((orders.len() as u64).to_be_bytes());
    for order in orders {
        hash.update(order.0);
    }
    OrderCommitment(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(side: Side, price: u64, quantity: u64, tif: TimeInForce, nonce: u8) -> SecretOrder {
        SecretOrder::new(
            "JGB10Y-JPY",
            side,
            price,
            quantity,
            tif,
            2_000,
            [nonce + 10; 32],
            [nonce; 32],
            [nonce + 30; 32],
        )
        .unwrap()
    }

    #[test]
    fn canonical_transition_keeps_the_resting_price_and_remainder() {
        let maker_key = SigningKey::from_bytes(&[41; 32]);
        let taker_key = SigningKey::from_bytes(&[42; 32]);
        let resting = order(Side::Sell, 100, 100, TimeInForce::GoodTilCancelled, 1);
        let arriving = order(Side::Buy, 101, 40, TimeInForce::ImmediateOrCancel, 2);
        let mut book = PrivateBook::new("JGB10Y-JPY").unwrap();
        book.insert_resting(
            resting.clone(),
            authorize_order(&resting, 2_100, &maker_key).unwrap(),
            1,
            1_000,
        )
        .unwrap();
        let result = book.expected_result(&arriving);
        let transition = book
            .apply_mpc_result(
                arriving.clone(),
                authorize_order(&arriving, 2_100, &taker_key).unwrap(),
                2,
                1_000,
                result,
            )
            .unwrap();
        assert_eq!(transition.fill.unwrap().price, 100);
        assert_eq!(transition.public_after.levels[0].quantity, 60);
    }

    #[test]
    fn private_wire_round_trips_but_rejects_trailing_or_changed_bytes() {
        let original = order(Side::Buy, 101, 40, TimeInForce::ImmediateOrCancel, 2);
        let wire = original.to_secret_wire();
        let decoded = SecretOrder::from_secret_wire(&wire).unwrap();
        assert_eq!(decoded.commitment(), original.commitment());
        assert_eq!(decoded.participant_handle(), original.participant_handle());
        assert_eq!(decoded.dekyx_nullifier(), original.dekyx_nullifier());

        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(SecretOrder::from_secret_wire(&trailing).is_err());

        let mut changed_version = wire;
        changed_version[16] = 2;
        assert!(matches!(
            SecretOrder::from_secret_wire(&changed_version),
            Err(OrderError::Invalid(
                "secret order wire version is unsupported"
            ))
        ));
    }

    #[test]
    fn batch_uses_better_price_before_earlier_worse_price() {
        let maker_key = SigningKey::from_bytes(&[41; 32]);
        let taker_key = SigningKey::from_bytes(&[42; 32]);
        let worse = order(Side::Sell, 101, 100, TimeInForce::GoodTilCancelled, 3);
        let better = order(Side::Sell, 100, 100, TimeInForce::GoodTilCancelled, 4);
        let arriving = order(Side::Buy, 101, 150, TimeInForce::ImmediateOrCancel, 5);
        let mut book = PrivateBook::new("JGB10Y-JPY").unwrap();
        for (sequence, resting) in [(1, worse), (2, better)] {
            book.insert_resting(
                resting.clone(),
                authorize_order(&resting, 2_100, &maker_key).unwrap(),
                sequence,
                1_000,
            )
            .unwrap();
        }
        let batch = book.private_match_batch(&arriving, 1_000).unwrap();
        assert_eq!(batch.resting[0].price, 100);
        assert_eq!(batch.resting[1].price, 101);
        let transition = book
            .apply_mpc_batch_result(
                arriving.clone(),
                authorize_order(&arriving, 2_100, &taker_key).unwrap(),
                3,
                1_000,
                expected_batch(&batch),
            )
            .unwrap();
        assert_eq!(transition.fills.len(), 2);
        assert_eq!(transition.fills[0].price, 100);
        assert_eq!(transition.fills[0].quantity, 100);
        assert_eq!(transition.fills[1].price, 101);
        assert_eq!(transition.fills[1].quantity, 50);
    }

    #[test]
    fn same_price_keeps_certificate_order() {
        let maker_key = SigningKey::from_bytes(&[41; 32]);
        let first = order(Side::Sell, 100, 10, TimeInForce::GoodTilCancelled, 6);
        let second = order(Side::Sell, 100, 10, TimeInForce::GoodTilCancelled, 7);
        let arriving = order(Side::Buy, 100, 15, TimeInForce::ImmediateOrCancel, 8);
        let mut book = PrivateBook::new("JGB10Y-JPY").unwrap();
        for (sequence, resting) in [(1, first.clone()), (2, second.clone())] {
            book.insert_resting(
                resting.clone(),
                authorize_order(&resting, 2_100, &maker_key).unwrap(),
                sequence,
                1_000,
            )
            .unwrap();
        }
        let batch = book.private_match_batch(&arriving, 1_000).unwrap();
        assert_eq!(batch.resting[0].commitment, first.commitment());
        assert_eq!(batch.resting[1].commitment, second.commitment());
    }

    #[test]
    fn gtc_non_cross_rests_while_ioc_non_cross_does_not() {
        let maker_key = SigningKey::from_bytes(&[41; 32]);
        let buyer_key = SigningKey::from_bytes(&[42; 32]);
        let ask = order(Side::Sell, 110, 10, TimeInForce::GoodTilCancelled, 9);
        let gtc = order(Side::Buy, 100, 5, TimeInForce::GoodTilCancelled, 10);
        let mut book = PrivateBook::new("JGB10Y-JPY").unwrap();
        book.insert_resting(
            ask.clone(),
            authorize_order(&ask, 2_100, &maker_key).unwrap(),
            1,
            1_000,
        )
        .unwrap();
        let batch = book.private_match_batch(&gtc, 1_000).unwrap();
        let transition = book
            .apply_mpc_batch_result(
                gtc.clone(),
                authorize_order(&gtc, 2_100, &buyer_key).unwrap(),
                2,
                1_000,
                expected_batch(&batch),
            )
            .unwrap();
        assert!(transition.fills.is_empty());
        assert!(transition
            .public_after
            .levels
            .iter()
            .any(|level| level.side == Side::Buy && level.quantity == 5));

        let ioc = order(Side::Buy, 100, 7, TimeInForce::ImmediateOrCancel, 12);
        let batch = book.private_match_batch(&ioc, 1_000).unwrap();
        let result = expected_batch(&batch);
        assert_eq!(result.arriving_remaining, 0);
        let transition = book
            .apply_mpc_batch_result(
                ioc.clone(),
                authorize_order(&ioc, 2_100, &buyer_key).unwrap(),
                3,
                1_000,
                result,
            )
            .unwrap();
        assert_eq!(transition.arriving_remaining, 0);
        assert_eq!(
            transition
                .public_after
                .levels
                .iter()
                .filter(|level| level.side == Side::Buy)
                .map(|level| level.quantity)
                .sum::<u64>(),
            5
        );
    }

    #[test]
    fn tick_lot_fee_and_reservation_rules_fail_closed() {
        let handle = [21; 32];
        let controls = OrderControls {
            order_id: [1; 32],
            ephemeral_public_key: [2; 32],
            dekyx_nullifier: [3; 32],
            reservation_id: [4; 32],
            reservation_limit: 1_025,
            minimum_lot: 5,
            max_fee: 5,
            cancellation_secret_digest: [5; 32],
        };
        let valid = SecretOrder::new_with_controls(
            "JGB10Y-JPY",
            Side::Buy,
            102,
            10,
            TimeInForce::GoodTilCancelled,
            2_000,
            handle,
            [6; 32],
            [7; 32],
            controls,
        )
        .unwrap();
        assert_eq!(
            valid.validate_market_rules(MarketRules {
                tick_size: 5,
                lot_size: 5,
                maximum_fee: 5,
                max_match_slots: MAX_MATCH_SLOTS,
            }),
            Err(OrderError::Invalid(
                "order violates tick, lot, or fee rules"
            ))
        );
        assert_eq!(
            valid.validate_market_rules(MarketRules {
                tick_size: 1,
                lot_size: 10,
                maximum_fee: 4,
                max_match_slots: MAX_MATCH_SLOTS,
            }),
            Err(OrderError::Invalid(
                "order violates tick, lot, or fee rules"
            ))
        );
    }

    #[test]
    fn changed_mpc_result_cannot_mutate_the_book() {
        let maker_key = SigningKey::from_bytes(&[41; 32]);
        let taker_key = SigningKey::from_bytes(&[42; 32]);
        let resting = order(Side::Sell, 100, 10, TimeInForce::GoodTilCancelled, 13);
        let arriving = order(Side::Buy, 100, 5, TimeInForce::ImmediateOrCancel, 14);
        let mut book = PrivateBook::new("JGB10Y-JPY").unwrap();
        book.insert_resting(
            resting.clone(),
            authorize_order(&resting, 2_100, &maker_key).unwrap(),
            1,
            1_000,
        )
        .unwrap();
        let before = book.public_snapshot();
        let batch = book.private_match_batch(&arriving, 1_000).unwrap();
        let mut forged = expected_batch(&batch);
        forged.slots[0].trade_quantity = 6;
        assert_eq!(
            book.apply_mpc_batch_result(
                arriving.clone(),
                authorize_order(&arriving, 2_100, &taker_key).unwrap(),
                2,
                1_000,
                forged,
            ),
            Err(OrderError::InvalidMpcResult)
        );
        assert_eq!(book.public_snapshot(), before);
    }

    #[test]
    fn cancellation_competes_in_sequence_and_needs_the_committed_secret() {
        let maker_key = SigningKey::from_bytes(&[41; 32]);
        let resting = order(Side::Sell, 100, 10, TimeInForce::GoodTilCancelled, 11);
        let mut book = PrivateBook::new("JGB10Y-JPY").unwrap();
        book.insert_resting(
            resting.clone(),
            authorize_order(&resting, 2_100, &maker_key).unwrap(),
            1,
            1_000,
        )
        .unwrap();
        let wrong =
            SecretCancellation::new(resting.commitment(), [99; 32], [12; 32], [13; 32]).unwrap();
        assert_eq!(
            book.apply_cancellation(&wrong, 2),
            Err(OrderError::InvalidCancellation)
        );
        let valid = SecretCancellation::new(
            resting.commitment(),
            resting.cancellation_secret(),
            [12; 32],
            [13; 32],
        )
        .unwrap();
        let transition = book.apply_cancellation(&valid, 2).unwrap();
        assert_eq!(transition.released_quantity, 10);
        assert!(transition.public_after.levels.is_empty());
    }

    #[test]
    fn expiry_is_a_canonical_ordered_state_transition() {
        let maker_key = SigningKey::from_bytes(&[41; 32]);
        let expired = order(Side::Sell, 100, 10, TimeInForce::GoodTilCancelled, 15);
        let live = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            101,
            20,
            TimeInForce::GoodTilCancelled,
            3_000,
            [25; 32],
            [16; 32],
            [46; 32],
        )
        .unwrap();
        let mut book = PrivateBook::new("JGB10Y-JPY").unwrap();
        for (sequence, resting) in [(1, expired.clone()), (2, live.clone())] {
            book.insert_resting(
                resting.clone(),
                authorize_order(&resting, 3_100, &maker_key).unwrap(),
                sequence,
                1_000,
            )
            .unwrap();
        }
        let targets = book.expired_commitments(2_001);
        assert_eq!(targets, vec![expired.commitment()]);
        let command = expiry_commitment("JGB10Y-JPY", 2_001, &targets);
        let transition = book.apply_expiry(2_001, command, 3).unwrap();
        assert_eq!(transition.released_quantity, 10);
        assert_eq!(transition.expired_orders, targets);
        assert_eq!(transition.public_after.levels.len(), 1);
        assert_eq!(transition.public_after.levels[0].price, 101);
        assert_eq!(
            book.apply_expiry(2_001, command, 4),
            Err(OrderError::Replay)
        );
    }
}
