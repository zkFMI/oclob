//! Participant-edge sharing for OCLOB orders.
//!
//! A corporate participant creates degree-two Shamir shares before any OCLOB
//! coordinator receives the order. Each MPC node receives exactly one share,
//! encrypted to that node. Pedersen VSS commitments let every node reject an
//! inconsistent share without exposing the small price, quantity or side.

#![forbid(unsafe_code)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{Digest32, OrderCommitment, SecretOrder, TimeInForce};
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::symm::{Cipher, Crypter, Mode};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use thiserror::Error;

pub const MPC_PARTIES: usize = 7;
pub const MAX_CORRUPT_PARTIES: usize = 2;
pub const MATCH_FIELD_COUNT: usize = 6;
pub const VSS_COEFFICIENTS: usize = MAX_CORRUPT_PARTIES + 1;
pub const SEALED_SHARE_CLEAR_BYTES: usize = 2_048;

const MANIFEST_DOMAIN: &[u8] = b"OCLOB:EDGE-MANIFEST:v1";
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"OCLOB:EDGE-MANIFEST-SIGNATURE:v1";
const SHARE_SIGNATURE_DOMAIN: &[u8] = b"OCLOB:EDGE-SHARE-SIGNATURE:v1";
const SHARE_ENVELOPE_DOMAIN: &[u8] = b"OCLOB:EDGE-SHARE-ENVELOPE:v1";
const SHARE_CLEAR_DOMAIN: &[u8] = b"OCLOB:EDGE-SHARE-CLEAR:v1";
const VSS_SECOND_GENERATOR_DOMAIN: &[u8] = b"OCLOB:EDGE-VSS-H:v1";
const VERSION: u16 = 1;

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
    pub settlement_capability_commitment: Digest32,
    pub field_commitments: [[[u8; 32]; VSS_COEFFICIENTS]; MATCH_FIELD_COUNT],
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
            || self.settlement_capability_commitment == [0; 32]
            || self.commitment != self.derived_commitment()
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
        manifest_body(
            self.version,
            &self.market_id,
            self.retention_deadline,
            self.eligibility_commitment,
            self.settlement_capability_commitment,
            &self.field_commitments,
            self.signer,
        )
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
        let h = vss_second_generator();
        for field in 0..MATCH_FIELD_COUNT {
            let value = canonical_scalar(self.value_shares[field])?;
            let blinding = canonical_scalar(self.blinding_shares[field])?;
            let left = RISTRETTO_BASEPOINT_POINT * value + h * blinding;
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

/// Created only inside the participant/corporate module. It is deliberately
/// not serializable as one object, preventing accidental transmission of all
/// seven shares to a coordinator.
pub struct EdgeOrderBundle {
    manifest: EdgeOrderManifest,
    sealed_shares: [SealedPartyShare; MPC_PARTIES],
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
        if eligibility_commitment == [0; 32]
            || settlement_capability_commitment == [0; 32]
            || node_keys.iter().any(|key| key.0 == [0; 32])
        {
            return Err(EdgeError::Input);
        }
        let values = order_values(order);
        let h = vss_second_generator();
        let mut field_commitments = [[[0_u8; 32]; VSS_COEFFICIENTS]; MATCH_FIELD_COUNT];
        let mut value_evaluations = [[Scalar::ZERO; MATCH_FIELD_COUNT]; MPC_PARTIES];
        let mut blinding_evaluations = [[Scalar::ZERO; MATCH_FIELD_COUNT]; MPC_PARTIES];
        for field in 0..MATCH_FIELD_COUNT {
            let value_coefficients = [
                values[field],
                Scalar::random(&mut *rng),
                Scalar::random(&mut *rng),
            ];
            let blinding_coefficients = [
                Scalar::random(&mut *rng),
                Scalar::random(&mut *rng),
                Scalar::random(&mut *rng),
            ];
            for coefficient in 0..VSS_COEFFICIENTS {
                field_commitments[field][coefficient] = (RISTRETTO_BASEPOINT_POINT
                    * value_coefficients[coefficient]
                    + h * blinding_coefficients[coefficient])
                    .compress()
                    .to_bytes();
            }
            for party in 0..MPC_PARTIES {
                let x = Scalar::from((party + 1) as u64);
                value_evaluations[party][field] = evaluate(&value_coefficients, x);
                blinding_evaluations[party][field] = evaluate(&blinding_coefficients, x);
            }
        }
        let signer_public = signer.verifying_key().to_bytes();
        let body = manifest_body(
            VERSION,
            order.market_id(),
            order.expires_at(),
            eligibility_commitment,
            settlement_capability_commitment,
            &field_commitments,
            signer_public,
        );
        let commitment = OrderCommitment(Sha256::digest(body).into());
        let manifest = EdgeOrderManifest {
            version: VERSION,
            market_id: order.market_id().to_owned(),
            commitment,
            retention_deadline: order.expires_at(),
            eligibility_commitment,
            settlement_capability_commitment,
            field_commitments,
            signer: signer_public,
            signature: signer
                .sign(&manifest_signature_body(commitment))
                .to_bytes()
                .to_vec(),
        };
        manifest.verify(0)?;

        let mut sealed = Vec::with_capacity(MPC_PARTIES);
        for party in 0..MPC_PARTIES {
            let mut share = PartyOrderShare {
                version: VERSION,
                party: party as u16,
                commitment,
                value_shares: value_evaluations[party].map(|value| value.to_bytes()),
                blinding_shares: blinding_evaluations[party].map(|value| value.to_bytes()),
                signer: signer_public,
                signature: Vec::new(),
            };
            share.signature = signer.sign(&share.signature_body()).to_bytes().to_vec();
            share.verify(&manifest, party as u16, 0)?;
            sealed.push(seal_share(&share, &node_keys[party], rng)?);
        }
        Ok(Self {
            manifest,
            sealed_shares: sealed
                .try_into()
                .map_err(|_| EdgeError::Crypto("seven share envelopes were not produced".into()))?,
        })
    }

    pub fn manifest(&self) -> &EdgeOrderManifest {
        &self.manifest
    }

    /// Move one encrypted share to its node. Callers cannot clone or serialize
    /// the bundle as a whole.
    pub fn into_deliveries(self) -> [(u16, SealedPartyShare); MPC_PARTIES] {
        self.sealed_shares
            .into_iter()
            .enumerate()
            .map(|(party, share)| (party as u16, share))
            .collect::<Vec<_>>()
            .try_into()
            .expect("the bundle always contains seven deliveries")
    }
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

fn vss_second_generator() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(VSS_SECOND_GENERATOR_DOMAIN)
}

fn manifest_body(
    version: u16,
    market_id: &str,
    retention_deadline: u64,
    eligibility_commitment: Digest32,
    settlement_capability_commitment: Digest32,
    field_commitments: &[[[u8; 32]; VSS_COEFFICIENTS]; MATCH_FIELD_COUNT],
    signer: Digest32,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(MANIFEST_DOMAIN.len() + market_id.len() + 768);
    body.extend_from_slice(MANIFEST_DOMAIN);
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&(market_id.len() as u16).to_be_bytes());
    body.extend_from_slice(market_id.as_bytes());
    body.extend_from_slice(&retention_deadline.to_be_bytes());
    body.extend_from_slice(&eligibility_commitment);
    body.extend_from_slice(&settlement_capability_commitment);
    for field in field_commitments {
        for commitment in field {
            body.extend_from_slice(commitment);
        }
    }
    body.extend_from_slice(&signer);
    body
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
    #[error("edge-order wire failure: {0}")]
    Wire(String),
    #[error("edge-order cryptography failure: {0}")]
    Crypto(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use oclob_core::Side;

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
        for (party, sealed) in deliveries {
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
        }
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
}
