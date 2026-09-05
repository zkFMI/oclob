//! Participant-edge sharing for OCLOB orders.
//!
//! A corporate participant creates degree-two Shamir shares before any OCLOB
//! coordinator receives the order. Each MPC node receives exactly one share,
//! encrypted to that node. Pedersen VSS commitments let every node reject an
//! inconsistent share without exposing the small price, quantity or side.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{Digest32, OrderCommitment, SecretOrder, TimeInForce};
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::symm::{Cipher, Crypter, Mode};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::Handle;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;
use zkpi_defmi_sdk::admission::ReservationAdmission;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::reservation::ReservationPermit;

pub const MPC_PARTIES: usize = 7;
pub const MAX_CORRUPT_PARTIES: usize = 2;
pub const MATCH_FIELD_COUNT: usize = 6;
pub const SETTLEMENT_FIELD_COUNT: usize = 2;
pub const VSS_COEFFICIENTS: usize = MAX_CORRUPT_PARTIES + 1;
pub const SEALED_SHARE_CLEAR_BYTES: usize = 8_192;
pub const SETTLEMENT_KEY_THRESHOLD: usize = MAX_CORRUPT_PARTIES + 1;
pub const SETTLEMENT_KEY_COEFFICIENTS: usize = SETTLEMENT_KEY_THRESHOLD;
pub const SEALED_CAPABILITY_KEY_SHARE_CLEAR_BYTES: usize = 1_024;
pub const SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES: usize = 64 * 1_024;

const MANIFEST_DOMAIN: &[u8] = b"OCLOB:EDGE-MANIFEST:v1";
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"OCLOB:EDGE-MANIFEST-SIGNATURE:v1";
const SHARE_SIGNATURE_DOMAIN: &[u8] = b"OCLOB:EDGE-SHARE-SIGNATURE:v1";
const SHARE_ENVELOPE_DOMAIN: &[u8] = b"OCLOB:EDGE-SHARE-ENVELOPE:v1";
const SHARE_CLEAR_DOMAIN: &[u8] = b"OCLOB:EDGE-SHARE-CLEAR:v1";
const SETTLEMENT_CAPABILITY_COMMITMENT_DOMAIN: &[u8] = b"OCLOB:SETTLEMENT-CAPABILITY-COMMITMENT:v1";
const SETTLEMENT_CAPABILITY_SIGNATURE_DOMAIN: &[u8] = b"OCLOB:SETTLEMENT-CAPABILITY-SIGNATURE:v1";
const CAPABILITY_KEY_SHARE_SIGNATURE_DOMAIN: &[u8] = b"OCLOB:CAPABILITY-KEY-SHARE-SIGNATURE:v1";
const CAPABILITY_KEY_SHARE_DIGEST_DOMAIN: &[u8] = b"OCLOB:CAPABILITY-KEY-SHARE-DIGEST:v1";
const CAPABILITY_KEY_SHARE_ENVELOPE_DOMAIN: &[u8] = b"OCLOB:CAPABILITY-KEY-SHARE-ENVELOPE:v1";
const CAPABILITY_KEY_SHARE_CLEAR_DOMAIN: &[u8] = b"OCLOB:CAPABILITY-KEY-SHARE-CLEAR:v1";
const SETTLEMENT_CAPABILITY_ENVELOPE_DOMAIN: &[u8] = b"OCLOB:THRESHOLD-SETTLEMENT-CAPABILITY:v1";
const SETTLEMENT_CAPABILITY_CLEAR_DOMAIN: &[u8] = b"OCLOB:SETTLEMENT-CAPABILITY-CLEAR:v1";
const PREAUTHORIZED_SETTLEMENT_DOMAIN: &[u8] = b"OCLOB:PREAUTHORIZED-SETTLEMENT:v1";
const RESERVATION_AUTHORITY_CLEAR_DOMAIN: &[u8] = b"OCLOB:RESERVATION-AUTHORITY:v1";
const VERSION: u16 = 5;

/// Public information sent to the ordering coordinator. The field commitments
/// are hiding Pedersen commitments; they cannot be brute-forced like plain
/// `G * price` commitments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EdgeOrderManifest {
    pub version: u16,
    pub market_id: String,
    pub commitment: OrderCommitment,
    pub retention_deadline: u64,
    pub eligibility_commitment: Digest32,
    /// Commitment of the participant's salted private order, made before the
    /// VSS manifest is assembled. A DeFMI reservation permit names this value.
    #[serde(default)]
    pub source_order_commitment: Digest32,
    /// Digest of a redacted DeFMI admission delivered only inside each encrypted
    /// node share. Zero identifies the legacy post-match capability path.
    #[serde(default)]
    pub reservation_admission_digest: Digest32,
    pub settlement_capability_commitment: Digest32,
    #[serde(default)]
    pub settlement_key_commitments: [[u8; 32]; SETTLEMENT_KEY_COEFFICIENTS],
    pub field_commitments: [[[u8; 32]; VSS_COEFFICIENTS]; MATCH_FIELD_COUNT],
    /// VSS commitments for the venue-handle scalar and pre-authorized reserve.
    /// They are populated only by the settlement-capable constructor.
    #[serde(default)]
    pub settlement_proof_enabled: bool,
    #[serde(default)]
    pub settlement_field_commitments: [[[u8; 32]; VSS_COEFFICIENTS]; SETTLEMENT_FIELD_COUNT],
    pub signer: Digest32,
    pub signature: Vec<u8>,
}

impl EdgeOrderManifest {
    pub fn verify(&self, now: u64) -> Result<(), EdgeError> {
        if self.version != VERSION
            || self.market_id.is_empty()
            || self.market_id.len() > 64
            || self.retention_deadline < now
            || self.eligibility_commitment == [0; 32]
            || self.source_order_commitment == [0; 32]
            || self.settlement_capability_commitment == [0; 32]
            || self.commitment != self.derived_commitment()
        {
            return Err(EdgeError::Manifest);
        }
        if self.reservation_admission_digest != [0; 32]
            && (!self.settlement_proof_enabled
                || self.settlement_capability_commitment
                    != preauthorized_settlement_commitment(self.reservation_admission_digest))
        {
            return Err(EdgeError::Manifest);
        }
        for field in &self.field_commitments {
            for commitment in field {
                CompressedRistretto(*commitment)
                    .decompress()
                    .ok_or(EdgeError::Manifest)?;
            }
        }
        if self.settlement_proof_enabled {
            for field in &self.settlement_field_commitments {
                for commitment in field {
                    CompressedRistretto(*commitment)
                        .decompress()
                        .ok_or(EdgeError::Manifest)?;
                }
            }
            if CompressedRistretto(self.settlement_field_commitments[0][0]).decompress()
                == Some(RistrettoPoint::default())
            {
                return Err(EdgeError::Manifest);
            }
        } else if self
            .settlement_field_commitments
            .iter()
            .flatten()
            .any(|commitment| *commitment != [0; 32])
        {
            return Err(EdgeError::Manifest);
        }
        let mut settlement_key_points = Vec::with_capacity(SETTLEMENT_KEY_COEFFICIENTS);
        for commitment in &self.settlement_key_commitments {
            settlement_key_points.push(
                CompressedRistretto(*commitment)
                    .decompress()
                    .ok_or(EdgeError::Manifest)?,
            );
        }
        if settlement_key_points[0] == RistrettoPoint::default() {
            return Err(EdgeError::Manifest);
        }
        let key = VerifyingKey::from_bytes(&self.signer).map_err(|_| EdgeError::Signature)?;
        let signature =
            Signature::try_from(self.signature.as_slice()).map_err(|_| EdgeError::Signature)?;
        key.verify_strict(&manifest_signature_body(self.commitment), &signature)
            .map_err(|_| EdgeError::Signature)
    }

    fn derived_commitment(&self) -> OrderCommitment {
        OrderCommitment(Sha256::digest(self.unsigned_body()).into())
    }

    fn unsigned_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(MANIFEST_DOMAIN.len() + self.market_id.len() + 768);
        body.extend_from_slice(MANIFEST_DOMAIN);
        body.extend_from_slice(&self.version.to_be_bytes());
        body.extend_from_slice(&(self.market_id.len() as u16).to_be_bytes());
        body.extend_from_slice(self.market_id.as_bytes());
        body.extend_from_slice(&self.retention_deadline.to_be_bytes());
        body.extend_from_slice(&self.eligibility_commitment);
        body.extend_from_slice(&self.source_order_commitment);
        body.extend_from_slice(&self.reservation_admission_digest);
        body.extend_from_slice(&self.settlement_capability_commitment);
        for commitment in &self.settlement_key_commitments {
            body.extend_from_slice(commitment);
        }
        for field in &self.field_commitments {
            for commitment in field {
                body.extend_from_slice(commitment);
            }
        }
        body.push(u8::from(self.settlement_proof_enabled));
        for field in &self.settlement_field_commitments {
            for commitment in field {
                body.extend_from_slice(commitment);
            }
        }
        body.extend_from_slice(&self.signer);
        body
    }

    pub fn uses_pretrade_reservation(&self) -> bool {
        self.reservation_admission_digest != [0; 32]
    }
}

/// One node's VSS evaluation. Serialization exists only for the encrypted
/// node envelope. Debug output is deliberately redacted.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PartyOrderShare {
    version: u16,
    party: u16,
    commitment: OrderCommitment,
    value_shares: [[u8; 32]; MATCH_FIELD_COUNT],
    blinding_shares: [[u8; 32]; MATCH_FIELD_COUNT],
    #[serde(default)]
    settlement_value_shares: [[u8; 32]; SETTLEMENT_FIELD_COUNT],
    #[serde(default)]
    settlement_blinding_shares: [[u8; 32]; SETTLEMENT_FIELD_COUNT],
    /// Signed DeFMI authority is encrypted separately to each node. It binds
    /// the VSS constant terms without revealing the side to the coordinator.
    #[serde(default)]
    reservation_admission: String,
    signer: Digest32,
    signature: Vec<u8>,
}

impl fmt::Debug for PartyOrderShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartyOrderShare")
            .field("party", &self.party)
            .field("commitment", &self.commitment.hex())
            .field("values", &"[redacted]")
            .field("signature_bytes", &self.signature.len())
            .finish()
    }
}

impl PartyOrderShare {
    pub const fn party(&self) -> u16 {
        self.party
    }

    pub const fn commitment(&self) -> OrderCommitment {
        self.commitment
    }

    /// Canonical scalar bytes consumed only by one MPC-node adapter.
    pub const fn value_share_bytes(&self) -> &[[u8; 32]; MATCH_FIELD_COUNT] {
        &self.value_shares
    }

    /// Decimal MP-SPDZ field inputs. Call this only inside the node that owns
    /// the share; returning all parties' values to a coordinator would undo
    /// the participant-edge trust boundary.
    pub fn value_share_decimals(&self) -> [String; MATCH_FIELD_COUNT] {
        self.value_shares.map(scalar_le_bytes_to_decimal)
    }

    pub fn blinding_share_decimals(&self) -> [String; MATCH_FIELD_COUNT] {
        self.blinding_shares.map(scalar_le_bytes_to_decimal)
    }

    pub fn settlement_value_share_decimals(&self) -> [String; SETTLEMENT_FIELD_COUNT] {
        self.settlement_value_shares.map(scalar_le_bytes_to_decimal)
    }

    pub fn settlement_blinding_share_decimals(&self) -> [String; SETTLEMENT_FIELD_COUNT] {
        self.settlement_blinding_shares
            .map(scalar_le_bytes_to_decimal)
    }

    /// Verify the redacted DeFMI admission against the public VSS constant
    /// terms and the independently configured venue. Only the receiving node
    /// calls this; the full canonical-note permit is not present in this share.
    pub fn verified_reservation_admission(
        &self,
        manifest: &EdgeOrderManifest,
        expected_venue: Digest32,
        expected_defmi: Digest32,
        trusted_signer: &VerifyingKey,
        now: u64,
    ) -> Result<ReservationAdmission, EdgeError> {
        if !manifest.uses_pretrade_reservation() || self.reservation_admission.is_empty() {
            return Err(EdgeError::ReservationPermit);
        }
        let wire = BASE64
            .decode(&self.reservation_admission)
            .map_err(|_| EdgeError::ReservationPermit)?;
        let permit =
            ReservationAdmission::decode(&wire).map_err(|_| EdgeError::ReservationPermit)?;
        let application = oclob_manifest_v1()
            .digest()
            .map_err(|_| EdgeError::ReservationPermit)?;
        permit
            .verify(application, expected_defmi, trusted_signer, now)
            .map_err(|_| EdgeError::ReservationPermit)?;
        if permit.venue_id != expected_venue {
            return Err(EdgeError::ReservationPermit);
        }
        verify_admission_binding(&permit, manifest)?;
        Ok(permit)
    }

    pub fn verify(
        &self,
        manifest: &EdgeOrderManifest,
        expected_party: u16,
        now: u64,
    ) -> Result<(), EdgeError> {
        manifest.verify(now)?;
        if self.version != VERSION
            || self.party != expected_party
            || usize::from(self.party) >= MPC_PARTIES
            || self.commitment != manifest.commitment
            || self.signer != manifest.signer
        {
            return Err(EdgeError::Share);
        }
        let key = VerifyingKey::from_bytes(&self.signer).map_err(|_| EdgeError::Signature)?;
        let signature =
            Signature::try_from(self.signature.as_slice()).map_err(|_| EdgeError::Signature)?;
        key.verify_strict(&self.signature_body(), &signature)
            .map_err(|_| EdgeError::Signature)?;
        let x = Scalar::from(u64::from(self.party) + 1);
        let commitment_key = vss_key();
        for field in 0..MATCH_FIELD_COUNT {
            let value = canonical_scalar(self.value_shares[field])?;
            let blinding = canonical_scalar(self.blinding_shares[field])?;
            let left = commitment_key.commit(&value, &blinding);
            let mut right = RistrettoPoint::default();
            let mut power = Scalar::ONE;
            for coefficient in 0..VSS_COEFFICIENTS {
                let point = CompressedRistretto(manifest.field_commitments[field][coefficient])
                    .decompress()
                    .ok_or(EdgeError::Manifest)?;
                right += point * power;
                power *= x;
            }
            if left != right {
                return Err(EdgeError::Vss);
            }
        }
        if manifest.settlement_proof_enabled {
            for field in 0..SETTLEMENT_FIELD_COUNT {
                let value = canonical_scalar(self.settlement_value_shares[field])?;
                let blinding = canonical_scalar(self.settlement_blinding_shares[field])?;
                let left = commitment_key.commit(&value, &blinding);
                let mut right = RistrettoPoint::default();
                let mut power = Scalar::ONE;
                for coefficient in 0..VSS_COEFFICIENTS {
                    let point = CompressedRistretto(
                        manifest.settlement_field_commitments[field][coefficient],
                    )
                    .decompress()
                    .ok_or(EdgeError::Manifest)?;
                    right += point * power;
                    power *= x;
                }
                if left != right {
                    return Err(EdgeError::Vss);
                }
            }
        } else if self
            .settlement_value_shares
            .iter()
            .chain(self.settlement_blinding_shares.iter())
            .any(|share| *share != [0; 32])
        {
            return Err(EdgeError::Share);
        }
        Ok(())
    }

    fn signature_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(SHARE_SIGNATURE_DOMAIN.len() + 2 + 2 + 32 * 14);
        body.extend_from_slice(SHARE_SIGNATURE_DOMAIN);
        body.extend_from_slice(&self.version.to_be_bytes());
        body.extend_from_slice(&self.party.to_be_bytes());
        body.extend_from_slice(&self.commitment.0);
        for value in &self.value_shares {
            body.extend_from_slice(value);
        }
        for value in &self.blinding_shares {
            body.extend_from_slice(value);
        }
        for value in &self.settlement_value_shares {
            body.extend_from_slice(value);
        }
        for value in &self.settlement_blinding_shares {
            body.extend_from_slice(value);
        }
        body.extend_from_slice(&(self.reservation_admission.len() as u32).to_be_bytes());
        body.extend_from_slice(self.reservation_admission.as_bytes());
        body.extend_from_slice(&self.signer);
        body
    }
}

/// X25519 key retained by exactly one MPC node.
#[derive(Clone)]
pub struct NodeDecryptionKey(PKey<Private>);

/// Public X25519 key distributed in the signed venue configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeEncryptionKey(pub Digest32);

impl NodeDecryptionKey {
    pub fn generate() -> Result<Self, EdgeError> {
        PKey::generate_x25519()
            .map(Self)
            .map_err(|error| EdgeError::Crypto(error.to_string()))
    }

    pub fn from_raw(raw: Digest32) -> Result<Self, EdgeError> {
        PKey::private_key_from_raw_bytes(&raw, Id::X25519)
            .map(Self)
            .map_err(|error| EdgeError::Crypto(error.to_string()))
    }

    pub fn raw_private_key(&self) -> Result<Digest32, EdgeError> {
        self.0
            .raw_private_key()
            .map_err(|error| EdgeError::Crypto(error.to_string()))?
            .try_into()
            .map_err(|_| EdgeError::Crypto("X25519 private key is not 32 bytes".into()))
    }

    pub fn public_key(&self) -> Result<NodeEncryptionKey, EdgeError> {
        self.0
            .raw_public_key()
            .map_err(|error| EdgeError::Crypto(error.to_string()))?
            .try_into()
            .map(NodeEncryptionKey)
            .map_err(|_| EdgeError::Crypto("X25519 public key is not 32 bytes".into()))
    }
}

/// Fixed-size encrypted delivery for exactly one party. The clear payload and
/// padding length are independent of order values.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedPartyShare {
    pub version: u16,
    pub party: u16,
    pub commitment: OrderCommitment,
    pub recipient: Digest32,
    pub ephemeral_public: Digest32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedPartyShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedPartyShare")
            .field("party", &self.party)
            .field("commitment", &self.commitment.hex())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish()
    }
}

impl SealedPartyShare {
    pub fn wire_digest(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(SHARE_ENVELOPE_DOMAIN);
        hash.update(self.version.to_be_bytes());
        hash.update(self.party.to_be_bytes());
        hash.update(self.commitment.0);
        hash.update(self.recipient);
        hash.update(self.ephemeral_public);
        hash.update(self.nonce);
        hash.update((self.ciphertext.len() as u64).to_be_bytes());
        hash.update(&self.ciphertext);
        hash.finalize().into()
    }

    pub fn open(
        &self,
        key: &NodeDecryptionKey,
        manifest: &EdgeOrderManifest,
        expected_party: u16,
        now: u64,
    ) -> Result<PartyOrderShare, EdgeError> {
        if self.version != VERSION
            || self.party != expected_party
            || self.commitment != manifest.commitment
            || self.ciphertext.len() != SEALED_SHARE_CLEAR_BYTES + 16
            || key.public_key()?.0 != self.recipient
        {
            return Err(EdgeError::Envelope);
        }
        let ephemeral = PKey::public_key_from_raw_bytes(&self.ephemeral_public, Id::X25519)
            .map_err(|error| EdgeError::Crypto(error.to_string()))?;
        let shared = shared_secret(&key.0, &ephemeral)?;
        let derived = derive_envelope_key(
            &shared,
            self.party,
            self.commitment,
            self.recipient,
            self.ephemeral_public,
        );
        let clear = decrypt(&derived, &self.nonce, &self.ciphertext, &envelope_aad(self))?;
        let share = decode_fixed_clear(&clear)?;
        share.verify(manifest, expected_party, now)?;
        Ok(share)
    }
}

/// One Feldman-verifiable evaluation of the random capability key polynomial.
/// It is encrypted at rest on one MPC node and may cross the wire in clear only
/// inside a fixed-size mutually authenticated response after that node has
/// durably recorded an authorized MPC result.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityKeyShare {
    version: u16,
    party: u16,
    order_commitment: OrderCommitment,
    capability_commitment: Digest32,
    value: [u8; 32],
    signer: Digest32,
    signature: Vec<u8>,
}

impl fmt::Debug for CapabilityKeyShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityKeyShare")
            .field("party", &self.party)
            .field("order_commitment", &self.order_commitment.hex())
            .field("value", &"[redacted]")
            .field("signature_bytes", &self.signature.len())
            .finish()
    }
}

impl Drop for CapabilityKeyShare {
    fn drop(&mut self) {
        self.value.fill(0);
    }
}

impl CapabilityKeyShare {
    pub const fn party(&self) -> u16 {
        self.party
    }

    pub const fn order_commitment(&self) -> OrderCommitment {
        self.order_commitment
    }

    pub const fn capability_commitment(&self) -> Digest32 {
        self.capability_commitment
    }

    pub fn wire_digest(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(CAPABILITY_KEY_SHARE_DIGEST_DOMAIN);
        hash.update(self.signature_body());
        hash.update((self.signature.len() as u64).to_be_bytes());
        hash.update(&self.signature);
        hash.finalize().into()
    }

    pub fn verify(
        &self,
        manifest: &EdgeOrderManifest,
        expected_party: u16,
        now: u64,
    ) -> Result<(), EdgeError> {
        manifest.verify(now)?;
        if self.version != VERSION
            || self.party != expected_party
            || usize::from(self.party) >= MPC_PARTIES
            || self.order_commitment != manifest.commitment
            || self.capability_commitment != manifest.settlement_capability_commitment
            || self.signer != manifest.signer
        {
            return Err(EdgeError::CapabilityKeyShare);
        }
        let scalar = canonical_scalar(self.value).map_err(|_| EdgeError::CapabilityKeyShare)?;
        let x = Scalar::from(u64::from(self.party) + 1);
        let mut expected = RistrettoPoint::default();
        let mut power = Scalar::ONE;
        for commitment in &manifest.settlement_key_commitments {
            let point = CompressedRistretto(*commitment)
                .decompress()
                .ok_or(EdgeError::CapabilityKeyShare)?;
            expected += point * power;
            power *= x;
        }
        if RISTRETTO_BASEPOINT_POINT * scalar != expected {
            return Err(EdgeError::CapabilityKeyShare);
        }
        let key = VerifyingKey::from_bytes(&self.signer).map_err(|_| EdgeError::Signature)?;
        let signature =
            Signature::try_from(self.signature.as_slice()).map_err(|_| EdgeError::Signature)?;
        key.verify_strict(&self.signature_body(), &signature)
            .map_err(|_| EdgeError::Signature)
    }

    fn signature_body(&self) -> Vec<u8> {
        [
            CAPABILITY_KEY_SHARE_SIGNATURE_DOMAIN,
            &self.version.to_be_bytes(),
            &self.party.to_be_bytes(),
            &self.order_commitment.0,
            &self.capability_commitment,
            &self.value,
            &self.signer,
        ]
        .concat()
    }
}

/// Node-specific encryption of one capability-key share. No node can open a
/// different party's envelope, and two colluding nodes remain below threshold.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedCapabilityKeyShare {
    pub version: u16,
    pub party: u16,
    pub order_commitment: OrderCommitment,
    pub capability_commitment: Digest32,
    pub recipient: Digest32,
    pub ephemeral_public: Digest32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedCapabilityKeyShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedCapabilityKeyShare")
            .field("party", &self.party)
            .field("order_commitment", &self.order_commitment.hex())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish()
    }
}

impl SealedCapabilityKeyShare {
    pub fn wire_digest(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(CAPABILITY_KEY_SHARE_ENVELOPE_DOMAIN);
        hash.update(self.version.to_be_bytes());
        hash.update(self.party.to_be_bytes());
        hash.update(self.order_commitment.0);
        hash.update(self.capability_commitment);
        hash.update(self.recipient);
        hash.update(self.ephemeral_public);
        hash.update(self.nonce);
        hash.update((self.ciphertext.len() as u64).to_be_bytes());
        hash.update(&self.ciphertext);
        hash.finalize().into()
    }

    pub fn open(
        &self,
        key: &NodeDecryptionKey,
        manifest: &EdgeOrderManifest,
        expected_party: u16,
        now: u64,
    ) -> Result<CapabilityKeyShare, EdgeError> {
        if self.version != VERSION
            || self.party != expected_party
            || self.order_commitment != manifest.commitment
            || self.capability_commitment != manifest.settlement_capability_commitment
            || self.ciphertext.len() != SEALED_CAPABILITY_KEY_SHARE_CLEAR_BYTES + 16
            || key.public_key()?.0 != self.recipient
        {
            return Err(EdgeError::Envelope);
        }
        let ephemeral = PKey::public_key_from_raw_bytes(&self.ephemeral_public, Id::X25519)
            .map_err(|error| EdgeError::Crypto(error.to_string()))?;
        let shared = shared_secret(&key.0, &ephemeral)?;
        let derived = derive_capability_key_share_envelope_key(
            &shared,
            self.party,
            self.order_commitment,
            self.capability_commitment,
            self.recipient,
            self.ephemeral_public,
        );
        let mut clear = decrypt(
            &derived,
            &self.nonce,
            &self.ciphertext,
            &capability_key_share_envelope_aad(self),
        )?;
        let share = decode_capability_key_share_clear(&clear)?;
        clear.fill(0);
        share.verify(manifest, expected_party, now)?;
        Ok(share)
    }
}

/// Reconstructed only after three signed node releases. This type is neither
/// serializable nor printable and clears its key bytes on drop.
pub struct SettlementCapabilityKey([u8; 32]);

impl Drop for SettlementCapabilityKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Fixed-size encrypted order authority. Its symmetric key is Shamir-shared
/// 3-of-7 across the MPC nodes; no settlement-wide private key exists.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedSettlementCapability {
    pub version: u16,
    pub order_commitment: OrderCommitment,
    pub capability_commitment: Digest32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedSettlementCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedSettlementCapability")
            .field("order_commitment", &self.order_commitment.hex())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish()
    }
}

/// Private, locally verified settlement authority.  It deliberately has no
/// serialization or `Debug` implementation.  Settlement code can consume its
/// typed getters only after the participant signature, capability commitment,
/// encrypted recipient, and all six VSS constant terms have been checked.
pub struct VerifiedSettlementCapability {
    order: SecretOrder,
    order_commitment: OrderCommitment,
    eligibility_commitment: Digest32,
    eligibility_evidence: Vec<u8>,
}

impl VerifiedSettlementCapability {
    pub fn order(&self) -> &SecretOrder {
        &self.order
    }

    pub const fn order_commitment(&self) -> OrderCommitment {
        self.order_commitment
    }

    pub const fn eligibility_commitment(&self) -> Digest32 {
        self.eligibility_commitment
    }

    pub fn eligibility_evidence(&self) -> &[u8] {
        &self.eligibility_evidence
    }
}

#[derive(Deserialize, Serialize)]
struct SettlementCapabilityClear {
    version: u16,
    order_wire: Vec<u8>,
    eligibility_commitment: Digest32,
    eligibility_evidence: Vec<u8>,
    constant_blindings: [[u8; 32]; MATCH_FIELD_COUNT],
    signer: Digest32,
    signature: Vec<u8>,
}

impl SealedSettlementCapability {
    pub fn open(
        &self,
        key: &SettlementCapabilityKey,
        manifest: &EdgeOrderManifest,
        now: u64,
    ) -> Result<VerifiedSettlementCapability, EdgeError> {
        manifest.verify(now)?;
        if self.version != VERSION
            || self.order_commitment != manifest.commitment
            || self.capability_commitment != manifest.settlement_capability_commitment
            || self.ciphertext.len() != SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES + 16
        {
            return Err(EdgeError::Envelope);
        }
        let scalar = canonical_scalar(key.0).map_err(|_| EdgeError::CapabilityKeyShare)?;
        if (RISTRETTO_BASEPOINT_POINT * scalar).compress().to_bytes()
            != manifest.settlement_key_commitments[0]
        {
            return Err(EdgeError::CapabilityKeyShare);
        }
        let mut clear = decrypt(
            &key.0,
            &self.nonce,
            &self.ciphertext,
            &settlement_envelope_aad(self),
        )?;
        let capability = decode_settlement_clear(&clear)?;
        clear.fill(0);
        if capability.version != VERSION
            || capability.signer != manifest.signer
            || capability.eligibility_commitment != manifest.eligibility_commitment
            || capability.eligibility_evidence.is_empty()
        {
            return Err(EdgeError::Capability);
        }
        let order = SecretOrder::from_secret_wire(&capability.order_wire)
            .map_err(|_| EdgeError::Capability)?;
        if order.market_id() != manifest.market_id
            || order.expires_at() != manifest.retention_deadline
            || settlement_capability_commitment(&order, &capability.signer)
                != manifest.settlement_capability_commitment
        {
            return Err(EdgeError::Capability);
        }
        verify_constant_terms(&order, &capability.constant_blindings, manifest)?;
        let signature = Signature::try_from(capability.signature.as_slice())
            .map_err(|_| EdgeError::Signature)?;
        let signer =
            VerifyingKey::from_bytes(&capability.signer).map_err(|_| EdgeError::Signature)?;
        signer
            .verify_strict(
                &settlement_capability_signature_body(
                    manifest.commitment,
                    manifest.settlement_capability_commitment,
                    manifest.eligibility_commitment,
                    &capability.eligibility_evidence,
                    &capability.constant_blindings,
                ),
                &signature,
            )
            .map_err(|_| EdgeError::Signature)?;
        Ok(VerifiedSettlementCapability {
            order,
            order_commitment: manifest.commitment,
            eligibility_commitment: manifest.eligibility_commitment,
            eligibility_evidence: capability.eligibility_evidence,
        })
    }
}

/// Threshold-encrypted DeFMI authority. Its payload contains only the signed
/// admission and canonical note permit, never an order or its scalar openings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SealedReservationAuthority(SealedSettlementCapability);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationAuthorityClear {
    admission: ReservationAdmission,
    permit: ReservationPermit,
    reserve_reblinding: [u8; 32],
}

pub struct VerifiedReservationAuthority {
    pub admission: ReservationAdmission,
    pub permit: ReservationPermit,
    pub reserve_reblinding: Scalar,
}

impl SealedReservationAuthority {
    pub fn open(
        &self,
        key: &SettlementCapabilityKey,
        manifest: &EdgeOrderManifest,
        expected_venue: Digest32,
        expected_defmi: Digest32,
        trusted_signer: &VerifyingKey,
        now: u64,
    ) -> Result<VerifiedReservationAuthority, EdgeError> {
        manifest.verify(now)?;
        let envelope = &self.0;
        if !manifest.uses_pretrade_reservation()
            || envelope.version != VERSION
            || envelope.order_commitment != manifest.commitment
            || envelope.capability_commitment != manifest.settlement_capability_commitment
            || envelope.ciphertext.len() != SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES + 16
        {
            return Err(EdgeError::Envelope);
        }
        let scalar = canonical_scalar(key.0).map_err(|_| EdgeError::CapabilityKeyShare)?;
        if (RISTRETTO_BASEPOINT_POINT * scalar).compress().to_bytes()
            != manifest.settlement_key_commitments[0]
        {
            return Err(EdgeError::CapabilityKeyShare);
        }
        let mut clear = decrypt(
            &key.0,
            &envelope.nonce,
            &envelope.ciphertext,
            &settlement_envelope_aad(envelope),
        )?;
        let decoded = (|| {
            let prefix = RESERVATION_AUTHORITY_CLEAR_DOMAIN.len();
            if clear.len() != SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES
                || &clear[..prefix] != RESERVATION_AUTHORITY_CLEAR_DOMAIN
            {
                return Err(EdgeError::Envelope);
            }
            let length = u32::from_be_bytes(clear[prefix..prefix + 4].try_into().unwrap()) as usize;
            let end = (prefix + 4)
                .checked_add(length)
                .filter(|end| *end <= clear.len())
                .ok_or(EdgeError::Envelope)?;
            serde_json::from_slice::<ReservationAuthorityClear>(&clear[prefix + 4..end])
                .map_err(|_| EdgeError::Envelope)
        })();
        clear.fill(0);
        let decoded = decoded?;
        if decoded.admission.venue_id != expected_venue {
            return Err(EdgeError::ReservationPermit);
        }
        let application = oclob_manifest_v1()
            .digest()
            .map_err(|_| EdgeError::ReservationPermit)?;
        decoded
            .admission
            .verify(application, expected_defmi, trusted_signer, now)
            .map_err(|_| EdgeError::ReservationPermit)?;
        decoded
            .permit
            .verify(application, expected_defmi, trusted_signer, now)
            .map_err(|_| EdgeError::ReservationPermit)?;
        let reserve_reblinding = canonical_scalar(decoded.reserve_reblinding)?;
        decoded
            .admission
            .verify_authority(&decoded.permit, &reserve_reblinding)
            .map_err(|_| EdgeError::ReservationPermit)?;
        verify_admission_binding(&decoded.admission, manifest)?;
        Ok(VerifiedReservationAuthority {
            admission: decoded.admission,
            permit: decoded.permit,
            reserve_reblinding,
        })
    }
}

fn verify_admission_binding(
    admission: &ReservationAdmission,
    manifest: &EdgeOrderManifest,
) -> Result<(), EdgeError> {
    if admission
        .digest()
        .map_err(|_| EdgeError::ReservationPermit)?
        != manifest.reservation_admission_digest
        || admission.order_commitment != manifest.source_order_commitment
        || admission.participant_handle != manifest.settlement_field_commitments[0][0]
        || admission.amount_commitment != manifest.settlement_field_commitments[1][0]
        || admission.side_commitment != manifest.field_commitments[0][0]
        || admission.valid_until < manifest.retention_deadline
    {
        return Err(EdgeError::ReservationPermit);
    }
    Ok(())
}

/// Created only inside the participant/corporate module. It is deliberately
/// not serializable as one object, preventing accidental transmission of all
/// seven shares to a coordinator.
pub struct EdgeOrderBundle {
    manifest: EdgeOrderManifest,
    sealed_shares: [SealedPartyShare; MPC_PARTIES],
    sealed_capability_key_shares: [SealedCapabilityKeyShare; MPC_PARTIES],
    settlement_capability_key: SettlementCapabilityKey,
    constant_blindings: [[u8; 32]; MATCH_FIELD_COUNT],
}

struct PreauthorizedReservation<'a> {
    permit: &'a ReservationAdmission,
    trusted_signer: &'a VerifyingKey,
    side_blinding: Scalar,
    reserve_blinding: Scalar,
    now: u64,
}

impl EdgeOrderBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn create<R: RngCore + CryptoRng>(
        order: &SecretOrder,
        eligibility_commitment: Digest32,
        settlement_capability_commitment: Digest32,
        signer: &SigningKey,
        node_keys: &[NodeEncryptionKey; MPC_PARTIES],
        rng: &mut R,
    ) -> Result<Self, EdgeError> {
        Self::create_inner(
            order,
            None,
            None,
            eligibility_commitment,
            settlement_capability_commitment,
            signer,
            node_keys,
            rng,
        )
    }

    /// Build an order whose matched result can be turned into zkPI and DvP
    /// evidence by the same MPC committee. The handle secret and reserve
    /// opening are Shamir-shared here and never enter the public manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_settlement_handle<R: RngCore + CryptoRng>(
        order: &SecretOrder,
        handle: &Handle,
        eligibility_commitment: Digest32,
        settlement_capability_commitment: Digest32,
        signer: &SigningKey,
        node_keys: &[NodeEncryptionKey; MPC_PARTIES],
        rng: &mut R,
    ) -> Result<Self, EdgeError> {
        Self::create_inner(
            order,
            Some(handle),
            None,
            eligibility_commitment,
            settlement_capability_commitment,
            signer,
            node_keys,
            rng,
        )
    }

    /// Build an order from a redacted certificate for a canonical DeFMI note
    /// reservation. The participant signs before admission. The separate
    /// threshold-encrypted authority contains no order or reserve opening;
    /// opening it after matching does not require another participant signature.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_reservation_admission<R: RngCore + CryptoRng>(
        order: &SecretOrder,
        handle: &Handle,
        eligibility_commitment: Digest32,
        permit: &ReservationAdmission,
        trusted_signer: &VerifyingKey,
        side_blinding: Scalar,
        reserve_blinding: Scalar,
        signer: &SigningKey,
        node_keys: &[NodeEncryptionKey; MPC_PARTIES],
        now: u64,
        rng: &mut R,
    ) -> Result<Self, EdgeError> {
        let permit_digest = permit.digest().map_err(|_| EdgeError::ReservationPermit)?;
        Self::create_inner(
            order,
            Some(handle),
            Some(PreauthorizedReservation {
                permit,
                trusted_signer,
                side_blinding,
                reserve_blinding,
                now,
            }),
            eligibility_commitment,
            preauthorized_settlement_commitment(permit_digest),
            signer,
            node_keys,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_inner<R: RngCore + CryptoRng>(
        order: &SecretOrder,
        handle: Option<&Handle>,
        preauthorized: Option<PreauthorizedReservation<'_>>,
        eligibility_commitment: Digest32,
        settlement_capability_commitment: Digest32,
        signer: &SigningKey,
        node_keys: &[NodeEncryptionKey; MPC_PARTIES],
        rng: &mut R,
    ) -> Result<Self, EdgeError> {
        if eligibility_commitment == [0; 32]
            || settlement_capability_commitment == [0; 32]
            || node_keys.iter().any(|key| key.0 == [0; 32])
            || handle.is_some_and(|handle| {
                handle.point.compress().to_bytes() != order.participant_handle()
            })
            || (preauthorized.is_some() && handle.is_none())
            || handle.is_some()
                && (order.limit_price() > u64::from(u32::MAX)
                    || order.quantity() > u64::from(u32::MAX)
                    || order.reservation_limit() > u64::from(u32::MAX))
        {
            return Err(EdgeError::Input);
        }
        let application = oclob_manifest_v1()
            .digest()
            .map_err(|_| EdgeError::ReservationPermit)?;
        let reservation_admission = preauthorized
            .as_ref()
            .map(|value| {
                value
                    .permit
                    .verify(
                        application,
                        value.permit.defmi_id,
                        value.trusted_signer,
                        value.now,
                    )
                    .map_err(|_| EdgeError::ReservationPermit)?;
                if value.permit.order_commitment != order.commitment().0
                    || value.permit.participant_handle != order.participant_handle()
                    || value.permit.valid_until < order.expires_at()
                    || value.side_blinding == Scalar::ZERO
                    || value.reserve_blinding == Scalar::ZERO
                {
                    return Err(EdgeError::ReservationPermit);
                }
                value
                    .permit
                    .encode()
                    .map_err(|_| EdgeError::ReservationPermit)
            })
            .transpose()?
            .map(|wire| BASE64.encode(wire))
            .unwrap_or_default();
        let reservation_admission_digest = preauthorized
            .as_ref()
            .map(|value| {
                value
                    .permit
                    .digest()
                    .map_err(|_| EdgeError::ReservationPermit)
            })
            .transpose()?
            .unwrap_or([0; 32]);
        let values = order_values(order);
        let commitment_key = vss_key();
        let mut field_commitments = [[[0_u8; 32]; VSS_COEFFICIENTS]; MATCH_FIELD_COUNT];
        let mut value_evaluations = [[Scalar::ZERO; MATCH_FIELD_COUNT]; MPC_PARTIES];
        let mut blinding_evaluations = [[Scalar::ZERO; MATCH_FIELD_COUNT]; MPC_PARTIES];
        let mut constant_blindings = [[0_u8; 32]; MATCH_FIELD_COUNT];
        for field in 0..MATCH_FIELD_COUNT {
            let value_coefficients = [
                values[field],
                Scalar::random(&mut *rng),
                Scalar::random(&mut *rng),
            ];
            let constant_blinding = preauthorized
                .as_ref()
                .filter(|_| field == 0)
                .map_or_else(|| Scalar::random(&mut *rng), |value| value.side_blinding);
            let blinding_coefficients = [
                constant_blinding,
                Scalar::random(&mut *rng),
                Scalar::random(&mut *rng),
            ];
            constant_blindings[field] = blinding_coefficients[0].to_bytes();
            for coefficient in 0..VSS_COEFFICIENTS {
                field_commitments[field][coefficient] = commitment_key
                    .commit(
                        &value_coefficients[coefficient],
                        &blinding_coefficients[coefficient],
                    )
                    .compress()
                    .to_bytes();
            }
            for party in 0..MPC_PARTIES {
                let x = Scalar::from((party + 1) as u64);
                value_evaluations[party][field] = evaluate(&value_coefficients, x);
                blinding_evaluations[party][field] = evaluate(&blinding_coefficients, x);
            }
        }
        let mut settlement_field_commitments =
            [[[0_u8; 32]; VSS_COEFFICIENTS]; SETTLEMENT_FIELD_COUNT];
        let mut settlement_value_evaluations =
            [[Scalar::ZERO; SETTLEMENT_FIELD_COUNT]; MPC_PARTIES];
        let mut settlement_blinding_evaluations =
            [[Scalar::ZERO; SETTLEMENT_FIELD_COUNT]; MPC_PARTIES];
        if let Some(handle) = handle {
            let settlement_values = [handle.secret, Scalar::from(order.reservation_limit())];
            for field in 0..SETTLEMENT_FIELD_COUNT {
                let value_coefficients = [
                    settlement_values[field],
                    Scalar::random(&mut *rng),
                    Scalar::random(&mut *rng),
                ];
                let blinding_coefficients = if field == 0 {
                    [Scalar::ZERO; VSS_COEFFICIENTS]
                } else {
                    [
                        preauthorized.as_ref().map_or_else(
                            || Scalar::random(&mut *rng),
                            |value| value.reserve_blinding,
                        ),
                        Scalar::random(&mut *rng),
                        Scalar::random(&mut *rng),
                    ]
                };
                for coefficient in 0..VSS_COEFFICIENTS {
                    settlement_field_commitments[field][coefficient] = commitment_key
                        .commit(
                            &value_coefficients[coefficient],
                            &blinding_coefficients[coefficient],
                        )
                        .compress()
                        .to_bytes();
                }
                for party in 0..MPC_PARTIES {
                    let x = Scalar::from((party + 1) as u64);
                    settlement_value_evaluations[party][field] = evaluate(&value_coefficients, x);
                    settlement_blinding_evaluations[party][field] =
                        evaluate(&blinding_coefficients, x);
                }
            }
        }
        if let Some(value) = preauthorized.as_ref() {
            if value.permit.side_commitment != field_commitments[0][0]
                || value.permit.participant_handle != settlement_field_commitments[0][0]
                || value.permit.amount_commitment != settlement_field_commitments[1][0]
            {
                return Err(EdgeError::ReservationPermit);
            }
        }
        let settlement_key_scalar = random_nonzero_scalar(rng);
        let settlement_key_coefficients = [
            settlement_key_scalar,
            Scalar::random(&mut *rng),
            Scalar::random(&mut *rng),
        ];
        let settlement_key_commitments = settlement_key_coefficients.map(|coefficient| {
            (RISTRETTO_BASEPOINT_POINT * coefficient)
                .compress()
                .to_bytes()
        });
        let settlement_key_evaluations: [Scalar; MPC_PARTIES] = std::array::from_fn(|party| {
            evaluate(
                &settlement_key_coefficients,
                Scalar::from((party + 1) as u64),
            )
        });
        let signer_public = signer.verifying_key().to_bytes();
        let mut manifest = EdgeOrderManifest {
            version: VERSION,
            market_id: order.market_id().to_owned(),
            commitment: OrderCommitment([0; 32]),
            retention_deadline: order.expires_at(),
            eligibility_commitment,
            source_order_commitment: order.commitment().0,
            reservation_admission_digest,
            settlement_capability_commitment,
            settlement_key_commitments,
            field_commitments,
            settlement_proof_enabled: handle.is_some(),
            settlement_field_commitments,
            signer: signer_public,
            signature: Vec::new(),
        };
        manifest.commitment = manifest.derived_commitment();
        manifest.signature = signer
            .sign(&manifest_signature_body(manifest.commitment))
            .to_bytes()
            .to_vec();
        manifest.verify(0)?;
        let commitment = manifest.commitment;

        let mut sealed = Vec::with_capacity(MPC_PARTIES);
        let mut sealed_capability_keys = Vec::with_capacity(MPC_PARTIES);
        for party in 0..MPC_PARTIES {
            let mut share = PartyOrderShare {
                version: VERSION,
                party: party as u16,
                commitment,
                value_shares: value_evaluations[party].map(|value| value.to_bytes()),
                blinding_shares: blinding_evaluations[party].map(|value| value.to_bytes()),
                settlement_value_shares: settlement_value_evaluations[party]
                    .map(|value| value.to_bytes()),
                settlement_blinding_shares: settlement_blinding_evaluations[party]
                    .map(|value| value.to_bytes()),
                reservation_admission: reservation_admission.clone(),
                signer: signer_public,
                signature: Vec::new(),
            };
            share.signature = signer.sign(&share.signature_body()).to_bytes().to_vec();
            share.verify(&manifest, party as u16, 0)?;
            sealed.push(seal_share(&share, &node_keys[party], rng)?);
            let mut capability_key_share = CapabilityKeyShare {
                version: VERSION,
                party: party as u16,
                order_commitment: commitment,
                capability_commitment: settlement_capability_commitment,
                value: settlement_key_evaluations[party].to_bytes(),
                signer: signer_public,
                signature: Vec::new(),
            };
            capability_key_share.signature = signer
                .sign(&capability_key_share.signature_body())
                .to_bytes()
                .to_vec();
            capability_key_share.verify(&manifest, party as u16, 0)?;
            sealed_capability_keys.push(seal_capability_key_share(
                &capability_key_share,
                &node_keys[party],
                rng,
            )?);
        }
        Ok(Self {
            manifest,
            sealed_shares: sealed
                .try_into()
                .map_err(|_| EdgeError::Crypto("seven share envelopes were not produced".into()))?,
            sealed_capability_key_shares: sealed_capability_keys.try_into().map_err(|_| {
                EdgeError::Crypto("seven capability-key envelopes were not produced".into())
            })?,
            settlement_capability_key: SettlementCapabilityKey(settlement_key_scalar.to_bytes()),
            constant_blindings,
        })
    }

    pub fn manifest(&self) -> &EdgeOrderManifest {
        &self.manifest
    }

    pub fn seal_reservation_authority<R: RngCore + CryptoRng>(
        &self,
        permit: &ReservationPermit,
        admission: &ReservationAdmission,
        reserve_reblinding: Scalar,
        rng: &mut R,
    ) -> Result<SealedReservationAuthority, EdgeError> {
        if !self.manifest.uses_pretrade_reservation() {
            return Err(EdgeError::ReservationPermit);
        }
        verify_admission_binding(admission, &self.manifest)?;
        admission
            .verify_authority(permit, &reserve_reblinding)
            .map_err(|_| EdgeError::ReservationPermit)?;
        let mut encoded = serde_json::to_vec(&ReservationAuthorityClear {
            admission: admission.clone(),
            permit: permit.clone(),
            reserve_reblinding: reserve_reblinding.to_bytes(),
        })
        .map_err(|_| EdgeError::Envelope)?;
        let prefix = RESERVATION_AUTHORITY_CLEAR_DOMAIN.len();
        if encoded.len() + prefix + 4 > SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES {
            encoded.fill(0);
            return Err(EdgeError::Envelope);
        }
        let mut clear = vec![0; SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES];
        rng.fill_bytes(&mut clear);
        clear[..prefix].copy_from_slice(RESERVATION_AUTHORITY_CLEAR_DOMAIN);
        clear[prefix..prefix + 4].copy_from_slice(&(encoded.len() as u32).to_be_bytes());
        clear[prefix + 4..prefix + 4 + encoded.len()].copy_from_slice(&encoded);
        encoded.fill(0);
        let mut nonce = [0; 12];
        rng.fill_bytes(&mut nonce);
        let mut envelope = SealedSettlementCapability {
            version: VERSION,
            order_commitment: self.manifest.commitment,
            capability_commitment: self.manifest.settlement_capability_commitment,
            nonce,
            ciphertext: Vec::new(),
        };
        let ciphertext = encrypt(
            &self.settlement_capability_key.0,
            &nonce,
            &clear,
            &settlement_envelope_aad(&envelope),
        );
        clear.fill(0);
        envelope.ciphertext = ciphertext?;
        Ok(SealedReservationAuthority(envelope))
    }

    /// Encrypt the participant's pre-authorized settlement material under the
    /// random key whose shares were delivered to the seven MPC nodes. The VSS
    /// constant blindings prove that reservation and DvP values equal the MPC
    /// inputs. No cluster-wide decryption key is created.
    pub fn seal_settlement_capability<R: RngCore + CryptoRng>(
        &self,
        order: &SecretOrder,
        eligibility_commitment: Digest32,
        eligibility_evidence: &[u8],
        signer: &SigningKey,
        rng: &mut R,
    ) -> Result<SealedSettlementCapability, EdgeError> {
        if eligibility_commitment == [0; 32]
            || eligibility_evidence.is_empty()
            || eligibility_evidence.len() > SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES / 2
            || signer.verifying_key().to_bytes() != self.manifest.signer
            || self.manifest.uses_pretrade_reservation()
            || eligibility_commitment != self.manifest.eligibility_commitment
            || settlement_capability_commitment(order, &self.manifest.signer)
                != self.manifest.settlement_capability_commitment
            || order.market_id() != self.manifest.market_id
            || order.expires_at() != self.manifest.retention_deadline
        {
            return Err(EdgeError::Capability);
        }
        verify_constant_terms(order, &self.constant_blindings, &self.manifest)?;
        let signature_body = settlement_capability_signature_body(
            self.manifest.commitment,
            self.manifest.settlement_capability_commitment,
            eligibility_commitment,
            eligibility_evidence,
            &self.constant_blindings,
        );
        let clear = SettlementCapabilityClear {
            version: VERSION,
            order_wire: order.to_secret_wire(),
            eligibility_commitment,
            eligibility_evidence: eligibility_evidence.to_vec(),
            constant_blindings: self.constant_blindings,
            signer: self.manifest.signer,
            signature: signer.sign(&signature_body).to_bytes().to_vec(),
        };
        seal_settlement_clear(
            &clear,
            self.manifest.commitment,
            self.manifest.settlement_capability_commitment,
            &self.settlement_capability_key,
            rng,
        )
    }

    /// Move one encrypted order share and one encrypted capability-key share to
    /// each node. Callers cannot clone or serialize the bundle as a whole.
    pub fn into_deliveries(
        self,
    ) -> [(u16, SealedPartyShare, SealedCapabilityKeyShare); MPC_PARTIES] {
        self.sealed_shares
            .into_iter()
            .zip(self.sealed_capability_key_shares)
            .enumerate()
            .map(|(party, (share, capability_key_share))| {
                (party as u16, share, capability_key_share)
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("the bundle always contains seven deliveries")
    }
}

/// Hiding precommitment placed in the public manifest before DeKYX evidence is
/// created for that manifest.  `SecretOrder::to_secret_wire` includes fresh
/// nonce and salt material, so small price and quantity domains cannot be
/// enumerated from this digest.
pub fn settlement_capability_commitment(order: &SecretOrder, signer: &Digest32) -> Digest32 {
    let wire = order.to_secret_wire();
    Sha256::new()
        .chain_update(SETTLEMENT_CAPABILITY_COMMITMENT_DOMAIN)
        .chain_update((wire.len() as u64).to_be_bytes())
        .chain_update(wire)
        .chain_update(signer)
        .finalize()
        .into()
}

fn preauthorized_settlement_commitment(permit_digest: Digest32) -> Digest32 {
    Sha256::new()
        .chain_update(PREAUTHORIZED_SETTLEMENT_DOMAIN)
        .chain_update(permit_digest)
        .finalize()
        .into()
}

/// Reconstruct the one-order capability key from any three distinct,
/// participant-signed and Feldman-verified node shares. Two shares always fail.
pub fn reconstruct_settlement_capability_key(
    manifest: &EdgeOrderManifest,
    shares: &[CapabilityKeyShare],
    now: u64,
) -> Result<SettlementCapabilityKey, EdgeError> {
    manifest.verify(now)?;
    if shares.len() < SETTLEMENT_KEY_THRESHOLD || shares.len() > MPC_PARTIES {
        return Err(EdgeError::CapabilityKeyThreshold);
    }
    let mut parties = BTreeSet::new();
    for share in shares {
        if !parties.insert(share.party) {
            return Err(EdgeError::CapabilityKeyThreshold);
        }
        share.verify(manifest, share.party, now)?;
    }
    let mut secret = Scalar::ZERO;
    for share in shares {
        let x_i = Scalar::from(u64::from(share.party) + 1);
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for other in shares {
            if other.party == share.party {
                continue;
            }
            let x_j = Scalar::from(u64::from(other.party) + 1);
            numerator *= -x_j;
            denominator *= x_i - x_j;
        }
        let evaluation =
            canonical_scalar(share.value).map_err(|_| EdgeError::CapabilityKeyShare)?;
        secret += evaluation * numerator * denominator.invert();
    }
    if secret == Scalar::ZERO
        || (RISTRETTO_BASEPOINT_POINT * secret).compress().to_bytes()
            != manifest.settlement_key_commitments[0]
    {
        return Err(EdgeError::CapabilityKeyThreshold);
    }
    Ok(SettlementCapabilityKey(secret.to_bytes()))
}

fn order_values(order: &SecretOrder) -> [Scalar; MATCH_FIELD_COUNT] {
    [
        Scalar::from(u64::from(order.side().wire())),
        Scalar::from(order.limit_price()),
        Scalar::from(order.quantity()),
        Scalar::from(match order.time_in_force() {
            TimeInForce::GoodTilCancelled => 1_u64,
            TimeInForce::ImmediateOrCancel => 2_u64,
        }),
        Scalar::from(order.expires_at()),
        Scalar::from(u64::from(matches!(
            order.time_in_force(),
            TimeInForce::GoodTilCancelled
        ))),
    ]
}

fn evaluate(coefficients: &[Scalar; VSS_COEFFICIENTS], x: Scalar) -> Scalar {
    coefficients[0] + coefficients[1] * x + coefficients[2] * x * x
}

fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let value = Scalar::random(&mut *rng);
        if value != Scalar::ZERO {
            return value;
        }
    }
}

fn vss_key() -> Pedersen {
    // Settlement shares are consumed by DeFMI's threshold proof parties.
    // Using the same generators makes the signed edge-manifest constants the
    // public statements of the later zkPI, limit and reserve proofs.
    Pedersen::new(b"qomm:defmi:v1")
}

fn verify_constant_terms(
    order: &SecretOrder,
    blindings: &[[u8; 32]; MATCH_FIELD_COUNT],
    manifest: &EdgeOrderManifest,
) -> Result<(), EdgeError> {
    let key = vss_key();
    for (field, value) in order_values(order).into_iter().enumerate() {
        let blinding = canonical_scalar(blindings[field])?;
        let expected = key.commit(&value, &blinding).compress().to_bytes();
        if expected != manifest.field_commitments[field][0] {
            return Err(EdgeError::Capability);
        }
    }
    Ok(())
}

fn settlement_capability_signature_body(
    order_commitment: OrderCommitment,
    capability_commitment: Digest32,
    eligibility_commitment: Digest32,
    eligibility_evidence: &[u8],
    blindings: &[[u8; 32]; MATCH_FIELD_COUNT],
) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(SETTLEMENT_CAPABILITY_SIGNATURE_DOMAIN);
    hash.update(order_commitment.0);
    hash.update(capability_commitment);
    hash.update(eligibility_commitment);
    hash.update((eligibility_evidence.len() as u64).to_be_bytes());
    hash.update(eligibility_evidence);
    for blinding in blindings {
        hash.update(blinding);
    }
    hash.finalize().to_vec()
}

fn manifest_signature_body(commitment: OrderCommitment) -> Vec<u8> {
    [MANIFEST_SIGNATURE_DOMAIN, &commitment.0].concat()
}

fn canonical_scalar(bytes: [u8; 32]) -> Result<Scalar, EdgeError> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or(EdgeError::Share)
}

fn scalar_le_bytes_to_decimal(bytes: [u8; 32]) -> String {
    const BASE: u64 = 1_000_000_000;
    let mut limbs = vec![0_u32];
    for byte in bytes.into_iter().rev() {
        let mut carry = u64::from(byte);
        for limb in &mut limbs {
            let next = u64::from(*limb) * 256 + carry;
            *limb = (next % BASE) as u32;
            carry = next / BASE;
        }
        while carry != 0 {
            limbs.push((carry % BASE) as u32);
            carry /= BASE;
        }
    }
    while limbs.len() > 1 && limbs.last() == Some(&0) {
        limbs.pop();
    }
    let mut output = limbs.pop().unwrap_or_default().to_string();
    for limb in limbs.iter().rev() {
        output.push_str(&format!("{limb:09}"));
    }
    output
}

fn seal_share<R: RngCore + CryptoRng>(
    share: &PartyOrderShare,
    recipient: &NodeEncryptionKey,
    rng: &mut R,
) -> Result<SealedPartyShare, EdgeError> {
    let clear = encode_fixed_clear(share, rng)?;
    let ephemeral_private =
        PKey::generate_x25519().map_err(|error| EdgeError::Crypto(error.to_string()))?;
    let ephemeral_public: Digest32 = ephemeral_private
        .raw_public_key()
        .map_err(|error| EdgeError::Crypto(error.to_string()))?
        .try_into()
        .map_err(|_| EdgeError::Crypto("X25519 public key is not 32 bytes".into()))?;
    let recipient_key = PKey::public_key_from_raw_bytes(&recipient.0, Id::X25519)
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    let shared = shared_secret(&ephemeral_private, &recipient_key)?;
    let key = derive_envelope_key(
        &shared,
        share.party,
        share.commitment,
        recipient.0,
        ephemeral_public,
    );
    let mut nonce = [0_u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut envelope = SealedPartyShare {
        version: VERSION,
        party: share.party,
        commitment: share.commitment,
        recipient: recipient.0,
        ephemeral_public,
        nonce,
        ciphertext: Vec::new(),
    };
    envelope.ciphertext = encrypt(&key, &nonce, &clear, &envelope_aad(&envelope))?;
    Ok(envelope)
}

fn seal_capability_key_share<R: RngCore + CryptoRng>(
    share: &CapabilityKeyShare,
    recipient: &NodeEncryptionKey,
    rng: &mut R,
) -> Result<SealedCapabilityKeyShare, EdgeError> {
    let mut clear = encode_capability_key_share_clear(share, rng)?;
    let ephemeral_private =
        PKey::generate_x25519().map_err(|error| EdgeError::Crypto(error.to_string()))?;
    let ephemeral_public: Digest32 = ephemeral_private
        .raw_public_key()
        .map_err(|error| EdgeError::Crypto(error.to_string()))?
        .try_into()
        .map_err(|_| EdgeError::Crypto("X25519 public key is not 32 bytes".into()))?;
    let recipient_key = PKey::public_key_from_raw_bytes(&recipient.0, Id::X25519)
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    let shared = shared_secret(&ephemeral_private, &recipient_key)?;
    let key = derive_capability_key_share_envelope_key(
        &shared,
        share.party,
        share.order_commitment,
        share.capability_commitment,
        recipient.0,
        ephemeral_public,
    );
    let mut nonce = [0_u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut envelope = SealedCapabilityKeyShare {
        version: VERSION,
        party: share.party,
        order_commitment: share.order_commitment,
        capability_commitment: share.capability_commitment,
        recipient: recipient.0,
        ephemeral_public,
        nonce,
        ciphertext: Vec::new(),
    };
    envelope.ciphertext = encrypt(
        &key,
        &nonce,
        &clear,
        &capability_key_share_envelope_aad(&envelope),
    )?;
    clear.fill(0);
    Ok(envelope)
}

fn seal_settlement_clear<R: RngCore + CryptoRng>(
    capability: &SettlementCapabilityClear,
    order_commitment: OrderCommitment,
    capability_commitment: Digest32,
    key: &SettlementCapabilityKey,
    rng: &mut R,
) -> Result<SealedSettlementCapability, EdgeError> {
    let mut clear = encode_settlement_clear(capability, rng)?;
    let mut nonce = [0_u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut envelope = SealedSettlementCapability {
        version: VERSION,
        order_commitment,
        capability_commitment,
        nonce,
        ciphertext: Vec::new(),
    };
    envelope.ciphertext = encrypt(&key.0, &nonce, &clear, &settlement_envelope_aad(&envelope))?;
    clear.fill(0);
    Ok(envelope)
}

fn encode_fixed_clear<R: RngCore + CryptoRng>(
    share: &PartyOrderShare,
    rng: &mut R,
) -> Result<Vec<u8>, EdgeError> {
    let encoded = serde_json::to_vec(share).map_err(|error| EdgeError::Wire(error.to_string()))?;
    let header = SHARE_CLEAR_DOMAIN.len() + 4;
    if header + encoded.len() > SEALED_SHARE_CLEAR_BYTES {
        return Err(EdgeError::Wire(
            "party share exceeds fixed clear frame".into(),
        ));
    }
    let mut clear = vec![0_u8; SEALED_SHARE_CLEAR_BYTES];
    clear[..SHARE_CLEAR_DOMAIN.len()].copy_from_slice(SHARE_CLEAR_DOMAIN);
    clear[SHARE_CLEAR_DOMAIN.len()..header].copy_from_slice(&(encoded.len() as u32).to_be_bytes());
    clear[header..header + encoded.len()].copy_from_slice(&encoded);
    rng.fill_bytes(&mut clear[header + encoded.len()..]);
    Ok(clear)
}

fn decode_fixed_clear(clear: &[u8]) -> Result<PartyOrderShare, EdgeError> {
    if clear.len() != SEALED_SHARE_CLEAR_BYTES || !clear.starts_with(SHARE_CLEAR_DOMAIN) {
        return Err(EdgeError::Envelope);
    }
    let start = SHARE_CLEAR_DOMAIN.len();
    let length = u32::from_be_bytes(
        clear[start..start + 4]
            .try_into()
            .expect("four-byte fixed frame length"),
    ) as usize;
    let payload_start = start + 4;
    let payload_end = payload_start
        .checked_add(length)
        .filter(|end| *end <= clear.len())
        .ok_or(EdgeError::Envelope)?;
    serde_json::from_slice(&clear[payload_start..payload_end]).map_err(|_| EdgeError::Envelope)
}

fn encode_capability_key_share_clear<R: RngCore + CryptoRng>(
    share: &CapabilityKeyShare,
    rng: &mut R,
) -> Result<Vec<u8>, EdgeError> {
    let mut encoded =
        serde_json::to_vec(share).map_err(|error| EdgeError::Wire(error.to_string()))?;
    let header = CAPABILITY_KEY_SHARE_CLEAR_DOMAIN.len() + 4;
    if header + encoded.len() > SEALED_CAPABILITY_KEY_SHARE_CLEAR_BYTES {
        encoded.fill(0);
        return Err(EdgeError::Wire(
            "capability-key share exceeds fixed clear frame".into(),
        ));
    }
    let mut clear = vec![0_u8; SEALED_CAPABILITY_KEY_SHARE_CLEAR_BYTES];
    clear[..CAPABILITY_KEY_SHARE_CLEAR_DOMAIN.len()]
        .copy_from_slice(CAPABILITY_KEY_SHARE_CLEAR_DOMAIN);
    clear[CAPABILITY_KEY_SHARE_CLEAR_DOMAIN.len()..header]
        .copy_from_slice(&(encoded.len() as u32).to_be_bytes());
    clear[header..header + encoded.len()].copy_from_slice(&encoded);
    encoded.fill(0);
    rng.fill_bytes(&mut clear[header + encoded.len()..]);
    Ok(clear)
}

fn decode_capability_key_share_clear(clear: &[u8]) -> Result<CapabilityKeyShare, EdgeError> {
    if clear.len() != SEALED_CAPABILITY_KEY_SHARE_CLEAR_BYTES
        || !clear.starts_with(CAPABILITY_KEY_SHARE_CLEAR_DOMAIN)
    {
        return Err(EdgeError::Envelope);
    }
    let start = CAPABILITY_KEY_SHARE_CLEAR_DOMAIN.len();
    let length = u32::from_be_bytes(
        clear[start..start + 4]
            .try_into()
            .expect("four-byte fixed frame length"),
    ) as usize;
    let payload_start = start + 4;
    let payload_end = payload_start
        .checked_add(length)
        .filter(|end| *end <= clear.len())
        .ok_or(EdgeError::Envelope)?;
    serde_json::from_slice(&clear[payload_start..payload_end]).map_err(|_| EdgeError::Envelope)
}

fn encode_settlement_clear<R: RngCore + CryptoRng>(
    capability: &SettlementCapabilityClear,
    rng: &mut R,
) -> Result<Vec<u8>, EdgeError> {
    let encoded =
        serde_json::to_vec(capability).map_err(|error| EdgeError::Wire(error.to_string()))?;
    let header = SETTLEMENT_CAPABILITY_CLEAR_DOMAIN.len() + 4;
    if header + encoded.len() > SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES {
        return Err(EdgeError::Wire(
            "settlement capability exceeds fixed clear frame".into(),
        ));
    }
    let mut clear = vec![0_u8; SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES];
    clear[..SETTLEMENT_CAPABILITY_CLEAR_DOMAIN.len()]
        .copy_from_slice(SETTLEMENT_CAPABILITY_CLEAR_DOMAIN);
    clear[SETTLEMENT_CAPABILITY_CLEAR_DOMAIN.len()..header]
        .copy_from_slice(&(encoded.len() as u32).to_be_bytes());
    clear[header..header + encoded.len()].copy_from_slice(&encoded);
    rng.fill_bytes(&mut clear[header + encoded.len()..]);
    Ok(clear)
}

fn decode_settlement_clear(clear: &[u8]) -> Result<SettlementCapabilityClear, EdgeError> {
    if clear.len() != SEALED_SETTLEMENT_CAPABILITY_CLEAR_BYTES
        || !clear.starts_with(SETTLEMENT_CAPABILITY_CLEAR_DOMAIN)
    {
        return Err(EdgeError::Envelope);
    }
    let start = SETTLEMENT_CAPABILITY_CLEAR_DOMAIN.len();
    let length = u32::from_be_bytes(
        clear[start..start + 4]
            .try_into()
            .expect("four-byte fixed frame length"),
    ) as usize;
    let payload_start = start + 4;
    let payload_end = payload_start
        .checked_add(length)
        .filter(|end| *end <= clear.len())
        .ok_or(EdgeError::Envelope)?;
    serde_json::from_slice(&clear[payload_start..payload_end]).map_err(|_| EdgeError::Envelope)
}

fn shared_secret(private: &PKey<Private>, public: &PKey<Public>) -> Result<Vec<u8>, EdgeError> {
    let mut deriver =
        Deriver::new(private).map_err(|error| EdgeError::Crypto(error.to_string()))?;
    deriver
        .set_peer(public)
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    deriver
        .derive_to_vec()
        .map_err(|error| EdgeError::Crypto(error.to_string()))
}

fn derive_envelope_key(
    shared: &[u8],
    party: u16,
    commitment: OrderCommitment,
    recipient: Digest32,
    ephemeral_public: Digest32,
) -> Digest32 {
    let salt = [SHARE_ENVELOPE_DOMAIN, &commitment.0, &party.to_be_bytes()].concat();
    let pseudorandom = hmac_sha256(&salt, shared);
    let info = [
        SHARE_ENVELOPE_DOMAIN,
        &recipient,
        &ephemeral_public,
        &commitment.0,
        &[1_u8],
    ]
    .concat();
    hmac_sha256(&pseudorandom, &info)
}

fn derive_capability_key_share_envelope_key(
    shared: &[u8],
    party: u16,
    order_commitment: OrderCommitment,
    capability_commitment: Digest32,
    recipient: Digest32,
    ephemeral_public: Digest32,
) -> Digest32 {
    let salt = [
        CAPABILITY_KEY_SHARE_ENVELOPE_DOMAIN,
        &order_commitment.0,
        &capability_commitment,
        &party.to_be_bytes(),
    ]
    .concat();
    let pseudorandom = hmac_sha256(&salt, shared);
    let info = [
        CAPABILITY_KEY_SHARE_ENVELOPE_DOMAIN,
        &recipient,
        &ephemeral_public,
        &party.to_be_bytes(),
        &order_commitment.0,
        &capability_commitment,
        &[1_u8],
    ]
    .concat();
    hmac_sha256(&pseudorandom, &info)
}

fn capability_key_share_envelope_aad(envelope: &SealedCapabilityKeyShare) -> Vec<u8> {
    [
        CAPABILITY_KEY_SHARE_ENVELOPE_DOMAIN,
        &envelope.version.to_be_bytes(),
        &envelope.party.to_be_bytes(),
        &envelope.order_commitment.0,
        &envelope.capability_commitment,
        &envelope.recipient,
        &envelope.ephemeral_public,
    ]
    .concat()
}

fn envelope_aad(envelope: &SealedPartyShare) -> Vec<u8> {
    [
        SHARE_ENVELOPE_DOMAIN,
        &envelope.version.to_be_bytes(),
        &envelope.party.to_be_bytes(),
        &envelope.commitment.0,
        &envelope.recipient,
        &envelope.ephemeral_public,
    ]
    .concat()
}

fn settlement_envelope_aad(envelope: &SealedSettlementCapability) -> Vec<u8> {
    [
        SETTLEMENT_CAPABILITY_ENVELOPE_DOMAIN,
        &envelope.version.to_be_bytes(),
        &envelope.order_commitment.0,
        &envelope.capability_commitment,
    ]
    .concat()
}

fn hmac_sha256(key: &[u8], body: &[u8]) -> Digest32 {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..64 {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(body)
        .finalize();
    Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

fn encrypt(
    key: &Digest32,
    nonce: &[u8; 12],
    clear: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EdgeError> {
    let cipher = Cipher::chacha20_poly1305();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce))
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    crypter
        .aad_update(aad)
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    let mut output = vec![0_u8; clear.len() + cipher.block_size()];
    let mut written = crypter
        .update(clear, &mut output)
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    written += crypter
        .finalize(&mut output[written..])
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    output.truncate(written);
    let mut tag = [0_u8; 16];
    crypter
        .get_tag(&mut tag)
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    output.extend_from_slice(&tag);
    Ok(output)
}

fn decrypt(
    key: &Digest32,
    nonce: &[u8; 12],
    encrypted: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EdgeError> {
    if encrypted.len() < 16 {
        return Err(EdgeError::Envelope);
    }
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
    let cipher = Cipher::chacha20_poly1305();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    crypter
        .aad_update(aad)
        .map_err(|error| EdgeError::Crypto(error.to_string()))?;
    crypter.set_tag(tag).map_err(|_| EdgeError::Envelope)?;
    let mut output = vec![0_u8; ciphertext.len() + cipher.block_size()];
    let mut written = crypter
        .update(ciphertext, &mut output)
        .map_err(|_| EdgeError::Envelope)?;
    written += crypter
        .finalize(&mut output[written..])
        .map_err(|_| EdgeError::Envelope)?;
    output.truncate(written);
    Ok(output)
}

#[derive(Debug, Error)]
pub enum EdgeError {
    #[error("edge-order input is invalid")]
    Input,
    #[error("edge-order public manifest is invalid")]
    Manifest,
    #[error("edge-order signature is invalid")]
    Signature,
    #[error("party share is invalid")]
    Share,
    #[error("party share fails Pedersen VSS verification")]
    Vss,
    #[error("sealed party-share envelope is invalid")]
    Envelope,
    #[error("settlement capability is invalid or not bound to the MPC shares")]
    Capability,
    #[error("settlement capability-key share is invalid")]
    CapabilityKeyShare,
    #[error("at least three distinct valid capability-key shares are required")]
    CapabilityKeyThreshold,
    #[error("DeFMI reservation permit is invalid or not bound to the MPC shares")]
    ReservationPermit,
    #[error("edge-order wire failure: {0}")]
    Wire(String),
    #[error("edge-order cryptography failure: {0}")]
    Crypto(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use oclob_core::Side;
    use qomm_zkpi::handles::Identity;
    use zkpi_defmi_sdk::reservation::ReservationRole;

    fn sample_order() -> SecretOrder {
        SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            40,
            TimeInForce::ImmediateOrCancel,
            2_000_000_000,
            [7; 32],
            [8; 32],
            [9; 32],
        )
        .unwrap()
    }

    fn node_keys() -> (
        [NodeDecryptionKey; MPC_PARTIES],
        [NodeEncryptionKey; MPC_PARTIES],
    ) {
        let private = std::array::from_fn(|_| NodeDecryptionKey::generate().unwrap());
        let public = std::array::from_fn(|party| private[party].public_key().unwrap());
        (private, public)
    }

    #[test]
    fn edge_bundle_discloses_no_plain_order_and_each_node_opens_only_its_share() {
        let (private, public) = node_keys();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let bundle = EdgeOrderBundle::create(
            &sample_order(),
            [10; 32],
            [11; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let manifest_json = serde_json::to_string(bundle.manifest()).unwrap();
        assert!(!manifest_json.contains("limit_price"));
        assert!(!manifest_json.contains("quantity"));
        assert!(!manifest_json.contains("participant"));
        assert!(!manifest_json.contains("dekyx_nullifier"));
        let manifest = bundle.manifest().clone();
        let deliveries = bundle.into_deliveries();
        for (party, sealed, sealed_capability_key) in deliveries {
            assert_eq!(sealed.ciphertext.len(), SEALED_SHARE_CLEAR_BYTES + 16);
            let opened = sealed
                .open(
                    &private[usize::from(party)],
                    &manifest,
                    party,
                    1_900_000_000,
                )
                .unwrap();
            assert_eq!(opened.party(), party);
            let wrong = (usize::from(party) + 1) % MPC_PARTIES;
            assert!(sealed
                .open(&private[wrong], &manifest, party, 1_900_000_000)
                .is_err());
            assert_eq!(
                sealed_capability_key.ciphertext.len(),
                SEALED_CAPABILITY_KEY_SHARE_CLEAR_BYTES + 16
            );
            let capability_key_share = sealed_capability_key
                .open(
                    &private[usize::from(party)],
                    &manifest,
                    party,
                    1_900_000_000,
                )
                .unwrap();
            assert_eq!(capability_key_share.party(), party);
            assert!(sealed_capability_key
                .open(&private[wrong], &manifest, party, 1_900_000_000)
                .is_err());
        }
    }

    #[test]
    fn settlement_capability_requires_three_node_shares_and_is_bound_to_vss_values() {
        let (private, public) = node_keys();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let order = sample_order();
        let eligibility_commitment = [21; 32];
        let capability_commitment =
            settlement_capability_commitment(&order, &signer.verifying_key().to_bytes());
        let bundle = EdgeOrderBundle::create(
            &order,
            eligibility_commitment,
            capability_commitment,
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let envelope = bundle
            .seal_settlement_capability(
                &order,
                eligibility_commitment,
                b"anonymous-presentation",
                &signer,
                &mut rand::rngs::OsRng,
            )
            .unwrap();
        let manifest = bundle.manifest().clone();
        let deliveries = bundle.into_deliveries();
        let capability_key_shares = [0_usize, 3, 6]
            .map(|party| {
                deliveries[party]
                    .2
                    .open(&private[party], &manifest, party as u16, 1_900_000_000)
                    .unwrap()
            })
            .to_vec();
        assert!(reconstruct_settlement_capability_key(
            &manifest,
            &capability_key_shares[..2],
            1_900_000_000
        )
        .is_err());
        assert!(reconstruct_settlement_capability_key(
            &manifest,
            &[
                capability_key_shares[0].clone(),
                capability_key_shares[0].clone(),
                capability_key_shares[2].clone(),
            ],
            1_900_000_000,
        )
        .is_err());
        let mut tampered = capability_key_shares[0].clone();
        tampered.value = (canonical_scalar(tampered.value).unwrap() + Scalar::ONE).to_bytes();
        tampered.signature = signer.sign(&tampered.signature_body()).to_bytes().to_vec();
        assert!(tampered.verify(&manifest, 0, 1_900_000_000).is_err());
        let settlement_key =
            reconstruct_settlement_capability_key(&manifest, &capability_key_shares, 1_900_000_000)
                .unwrap();
        let opened = envelope
            .open(&settlement_key, &manifest, 1_900_000_000)
            .unwrap();
        assert_eq!(opened.order_commitment(), manifest.commitment);
        assert_eq!(opened.order().limit_price(), 101);
        assert_eq!(opened.order().quantity(), 40);
        assert_eq!(opened.eligibility_evidence(), b"anonymous-presentation");
    }

    #[test]
    fn any_three_verified_shamir_evaluations_reconstruct_the_order_fields() {
        let (private, public) = node_keys();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let bundle = EdgeOrderBundle::create(
            &sample_order(),
            [12; 32],
            [13; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let manifest = bundle.manifest().clone();
        let deliveries = bundle.into_deliveries();
        let selected = [0_usize, 3, 6].map(|party| {
            deliveries[party]
                .1
                .open(&private[party], &manifest, party as u16, 1_900_000_000)
                .unwrap()
        });
        let reconstructed: [u64; MATCH_FIELD_COUNT] = std::array::from_fn(|field| {
            let mut value = Scalar::ZERO;
            for (position, share) in selected.iter().enumerate() {
                let x_i = Scalar::from(u64::from(share.party()) + 1);
                let mut numerator = Scalar::ONE;
                let mut denominator = Scalar::ONE;
                for (other_position, other) in selected.iter().enumerate() {
                    if position == other_position {
                        continue;
                    }
                    let x_j = Scalar::from(u64::from(other.party()) + 1);
                    numerator *= -x_j;
                    denominator *= x_i - x_j;
                }
                let evaluation = canonical_scalar(share.value_shares[field]).unwrap();
                value += evaluation * numerator * denominator.invert();
            }
            let bytes = value.to_bytes();
            assert!(bytes[8..].iter().all(|byte| *byte == 0));
            u64::from_le_bytes(bytes[..8].try_into().unwrap())
        });
        assert_eq!(reconstructed, [0, 101, 40, 2, 2_000_000_000, 0]);
    }

    #[test]
    fn tampering_or_expired_manifest_fails_closed() {
        let (private, public) = node_keys();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let bundle = EdgeOrderBundle::create(
            &sample_order(),
            [14; 32],
            [15; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let manifest = bundle.manifest().clone();
        let mut deliveries = bundle.into_deliveries();
        deliveries[0].1.ciphertext[0] ^= 1;
        assert!(deliveries[0]
            .1
            .open(&private[0], &manifest, 0, 1_900_000_000)
            .is_err());
        assert!(manifest.verify(2_000_000_001).is_err());
    }

    #[test]
    fn node_decimal_rendering_is_canonical() {
        assert_eq!(scalar_le_bytes_to_decimal([0; 32]), "0");
        let mut one = [0_u8; 32];
        one[0] = 1;
        assert_eq!(scalar_le_bytes_to_decimal(one), "1");
        let scalar = Scalar::from(101_u64);
        assert_eq!(scalar_le_bytes_to_decimal(scalar.to_bytes()), "101");
    }

    #[test]
    fn pretrade_permit_binds_hidden_side_handle_and_reserve_without_later_capability() {
        let (private, public) = node_keys();
        let participant = Identity::from_seed([41; 32]).handle(b"defmi:oclob:v1");
        let order = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            101,
            40,
            TimeInForce::ImmediateOrCancel,
            2_000_000_000,
            participant.point.compress().to_bytes(),
            [42; 32],
            [43; 32],
        )
        .unwrap();
        let permit_signer = SigningKey::from_bytes(&[44; 32]);
        let order_signer = SigningKey::from_bytes(&[45; 32]);
        let side_blinding = Scalar::from(46_u64);
        let reserve_blinding = Scalar::from(47_u64);
        let key = vss_key();
        let permit = ReservationPermit {
            version: 2,
            role: ReservationRole::Taker,
            application_binding: oclob_manifest_v1().digest().unwrap(),
            venue_id: [48; 32],
            defmi_id: [49; 32],
            canonical_state_root: [50; 32],
            accepted_height: 7,
            order_commitment: order.commitment().0,
            participant_handle: order.participant_handle(),
            entity_commitment: [75; 32],
            reservation_id: [51; 32],
            facility_id: [52; 32],
            asset_id: [53; 32],
            amount_commitment: key
                .commit(&Scalar::from(order.reservation_limit()), &reserve_blinding)
                .compress()
                .to_bytes(),
            escrow_note_id: [76; 32],
            delegation_digest: [77; 32],
            side_commitment: key
                .commit(
                    &Scalar::from(u64::from(order.side().wire())),
                    &side_blinding,
                )
                .compress()
                .to_bytes(),
            authority_digest: [54; 32],
            reserve_receipt_digest: [55; 32],
            reservation_sequence: 3,
            valid_until: 2_000_000_001,
            signer_public: permit_signer.verifying_key().to_bytes(),
            signature: Vec::new(),
        }
        .sign(&permit_signer)
        .unwrap();
        let reblinding = Scalar::from(101_u64);
        let admission =
            ReservationAdmission::from_permit(&permit, &reblinding, &permit_signer).unwrap();
        let bundle = EdgeOrderBundle::create_with_reservation_admission(
            &order,
            &participant,
            [56; 32],
            &admission,
            &permit_signer.verifying_key(),
            side_blinding,
            reserve_blinding + reblinding,
            &order_signer,
            &public,
            1_900_000_000,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        assert!(bundle.manifest().uses_pretrade_reservation());
        assert_eq!(
            bundle.manifest().reservation_admission_digest,
            admission.digest().unwrap()
        );
        let manifest_json = serde_json::to_string(bundle.manifest()).unwrap();
        assert!(!manifest_json.contains("buy"));
        assert!(!manifest_json.contains("sell"));
        assert!(bundle
            .seal_settlement_capability(
                &order,
                [56; 32],
                b"must-not-be-used",
                &order_signer,
                &mut rand::rngs::OsRng,
            )
            .is_err());
        let authority = bundle
            .seal_reservation_authority(&permit, &admission, reblinding, &mut rand::rngs::OsRng)
            .unwrap();
        let manifest = bundle.manifest().clone();
        let mut key_shares = Vec::new();
        for (party, sealed, key_share) in bundle.into_deliveries() {
            let share = sealed
                .open(
                    &private[usize::from(party)],
                    &manifest,
                    party,
                    1_900_000_000,
                )
                .unwrap();
            let verified = share
                .verified_reservation_admission(
                    &manifest,
                    permit.venue_id,
                    [49; 32],
                    &permit_signer.verifying_key(),
                    1_900_000_000,
                )
                .unwrap();
            assert_eq!(verified, admission);
            let decoded: serde_json::Value =
                serde_json::from_slice(&verified.encode().unwrap()).unwrap();
            assert!(decoded.get("asset_id").is_none());
            assert!(decoded.get("reservation_id").is_none());
            assert!(decoded.get("escrow_note_id").is_none());
            key_shares.push(
                key_share
                    .open(
                        &private[usize::from(party)],
                        &manifest,
                        party,
                        1_900_000_000,
                    )
                    .unwrap(),
            );
        }
        assert!(
            reconstruct_settlement_capability_key(&manifest, &key_shares[..2], 1_900_000_000)
                .is_err()
        );
        let key = reconstruct_settlement_capability_key(&manifest, &key_shares[..3], 1_900_000_000)
            .unwrap();
        let opened = authority
            .open(
                &key,
                &manifest,
                permit.venue_id,
                [49; 32],
                &permit_signer.verifying_key(),
                1_900_000_000,
            )
            .unwrap();
        assert_eq!(opened.permit, permit);
        assert_eq!(opened.admission, admission);
        assert!(authority
            .open(
                &key,
                &manifest,
                permit.venue_id,
                [99; 32],
                &permit_signer.verifying_key(),
                1_900_000_000
            )
            .is_err());
        assert!(authority
            .open(
                &key,
                &manifest,
                [99; 32],
                [49; 32],
                &permit_signer.verifying_key(),
                1_900_000_000
            )
            .is_err());
        let mut corrupted = authority.clone();
        corrupted.0.ciphertext[12] ^= 1;
        assert!(corrupted
            .open(
                &key,
                &manifest,
                permit.venue_id,
                [49; 32],
                &permit_signer.verifying_key(),
                1_900_000_000
            )
            .is_err());
    }

    #[test]
    fn pretrade_permit_rejects_a_different_reserve_opening() {
        let (_, public) = node_keys();
        let participant = Identity::from_seed([61; 32]).handle(b"defmi:oclob:v1");
        let order = SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            100,
            20,
            TimeInForce::GoodTilCancelled,
            2_000_000_000,
            participant.point.compress().to_bytes(),
            [62; 32],
            [63; 32],
        )
        .unwrap();
        let permit_signer = SigningKey::from_bytes(&[64; 32]);
        let key = vss_key();
        let permit = ReservationPermit {
            version: 2,
            role: ReservationRole::Maker,
            application_binding: oclob_manifest_v1().digest().unwrap(),
            venue_id: [65; 32],
            defmi_id: [66; 32],
            canonical_state_root: [67; 32],
            accepted_height: 8,
            order_commitment: order.commitment().0,
            participant_handle: order.participant_handle(),
            entity_commitment: [75; 32],
            reservation_id: [68; 32],
            facility_id: [69; 32],
            asset_id: [70; 32],
            amount_commitment: key
                .commit(
                    &Scalar::from(order.reservation_limit()),
                    &Scalar::from(71_u64),
                )
                .compress()
                .to_bytes(),
            escrow_note_id: [76; 32],
            delegation_digest: [77; 32],
            side_commitment: key
                .commit(
                    &Scalar::from(u64::from(order.side().wire())),
                    &Scalar::from(72_u64),
                )
                .compress()
                .to_bytes(),
            authority_digest: [73; 32],
            reserve_receipt_digest: [74; 32],
            reservation_sequence: 1,
            valid_until: 2_000_000_001,
            signer_public: permit_signer.verifying_key().to_bytes(),
            signature: Vec::new(),
        }
        .sign(&permit_signer)
        .unwrap();
        let admission =
            ReservationAdmission::from_permit(&permit, &Scalar::from(102_u64), &permit_signer)
                .unwrap();
        assert!(EdgeOrderBundle::create_with_reservation_admission(
            &order,
            &participant,
            [75; 32],
            &admission,
            &permit_signer.verifying_key(),
            Scalar::from(72_u64),
            Scalar::from(99_u64),
            &SigningKey::from_bytes(&[76; 32]),
            &public,
            1_900_000_000,
            &mut rand::rngs::OsRng,
        )
        .is_err());
    }
}
