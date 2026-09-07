//! Closed OCLOB application authentication, wire version 2.
//!
//! The 32-byte verification identity is a domain-separated fingerprint of the
//! complete independently generated Ed25519 + ML-DSA-65 public key, suite and
//! purpose. It is never a raw Ed25519 public key. Every signature carries the
//! full key and both components, checked against the enrolled fingerprint.
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zkfmi_crypto::{
    backend::{Ed25519Signer, MlDsa65Signer},
    hybrid::signature::{HybridSigner, HybridVerifier},
    key::KeyPurpose,
    suite::{Suite, SuiteId},
    traits::{Signer as CryptoSigner, Verifier as CryptoVerifier},
};

const MAGIC: &[u8; 8] = b"OCLSIG02";
pub const SUITE: Suite = Suite::new(SuiteId::Ed25519MlDsa65);
pub const PURPOSE: KeyPurpose = KeyPurpose::Attestation;
pub const PUBLIC_KEY_BYTES: usize = 1984;
pub const SIGNATURE_BYTES: usize = 8 + 4 + 2 + PUBLIC_KEY_BYTES + 3373;
const KEY_OFFSET: usize = 14;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("invalid OCLOB v2 hybrid application key or signature; legacy Ed25519-only material requires explicit re-enrollment")]
pub struct SignatureError;

fn fingerprint(public: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"OCLOB:APPLICATION-KEY-FINGERPRINT:v2")
        .chain_update(SUITE.encode())
        .chain_update(PURPOSE.code().to_be_bytes())
        .chain_update(public)
        .finalize()
        .into()
}

pub struct SigningKey {
    seeds: Zeroizing<[u8; 64]>,
    signer: HybridSigner,
}
impl Clone for SigningKey {
    fn clone(&self) -> Self {
        Self::from_bytes(&self.seeds)
    }
}
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApplicationSigningKey([redacted])")
    }
}
impl SigningKey {
    /// Both seed halves are independent CSPRNG outputs. No public-input KDF.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seeds = Zeroizing::new([0; 64]);
        rng.fill_bytes(&mut seeds[..32]);
        rng.fill_bytes(&mut seeds[32..]);
        Self::from_bytes(&seeds)
    }
    /// Restore exactly the enrolled two-seed record. Callers must not replace a
    /// missing, legacy, expired or revoked persisted record with a fresh key.
    pub fn from_bytes(seeds: &[u8; 64]) -> Self {
        let classical: [u8; 32] = seeds[..32].try_into().expect("fixed seed half");
        let pq: [u8; 32] = seeds[32..].try_into().expect("fixed seed half");
        Self {
            seeds: Zeroizing::new(*seeds),
            signer: HybridSigner::new(
                Ed25519Signer::from_seed(&classical),
                MlDsa65Signer::from_seed(&pq),
            ),
        }
    }
    pub fn to_bytes(&self) -> [u8; 64] {
        *self.seeds
    }
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.seeds
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(fingerprint(&self.signer.public_key()))
    }
    pub fn hybrid_public_key(&self) -> Vec<u8> {
        self.signer.public_key()
    }
    /// Foundation protocols retain their own purpose and raw hybrid wire format.
    pub fn raw_hybrid_signer(&self) -> HybridSigner {
        HybridSigner::new(
            Ed25519Signer::from_seed(&self.seeds[..32].try_into().expect("fixed seed")),
            MlDsa65Signer::from_seed(&self.seeds[32..].try_into().expect("fixed seed")),
        )
    }
}

pub trait Signer {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, SignatureError>;
}
impl Signer for SigningKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        let mut encoded = MAGIC.to_vec();
        encoded.extend(SUITE.encode());
        encoded.extend(PURPOSE.code().to_be_bytes());
        encoded.extend(self.signer.public_key());
        encoded.extend(
            self.signer
                .sign(PURPOSE, message)
                .map_err(|_| SignatureError)?,
        );
        Ok(Signature(encoded))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct VerifyingKey([u8; 32]);
impl VerifyingKey {
    pub fn from_bytes(fingerprint: &[u8; 32]) -> Result<Self, SignatureError> {
        if *fingerprint == [0; 32] {
            return Err(SignatureError);
        }
        Ok(Self(*fingerprint))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        signature.validate()?;
        let public = &signature.0[KEY_OFFSET..KEY_OFFSET + PUBLIC_KEY_BYTES];
        if fingerprint(public) != self.0 {
            return Err(SignatureError);
        }
        HybridVerifier
            .verify(
                PURPOSE,
                public,
                message,
                &signature.0[KEY_OFFSET + PUBLIC_KEY_BYTES..],
            )
            .map_err(|_| SignatureError)
    }
}

#[derive(Clone, Debug)]
pub struct Signature(Vec<u8>);
impl Signature {
    /// Opaque constructor for unsigned request placeholders. Verification always
    /// validates the closed envelope, including values built with this method.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
    fn validate(&self) -> Result<(), SignatureError> {
        if self.0.len() != SIGNATURE_BYTES
            || &self.0[..8] != MAGIC
            || self.0[8..12] != SUITE.encode()
            || self.0[12..14] != PURPOSE.code().to_be_bytes()
        {
            return Err(SignatureError);
        }
        Ok(())
    }
}
impl TryFrom<&[u8]> for Signature {
    type Error = SignatureError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let value = Self(bytes.to_vec());
        value.validate()?;
        Ok(value)
    }
}

/// Exact 64-byte private records only, inside owner-only encrypted journals.
pub mod secret_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        Vec::<u8>::deserialize(deserializer)?.try_into().map_err(|_| serde::de::Error::custom("application custody requires 64 independent seed bytes; legacy signing keys require explicit migration"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        // Explicit public test material; production uses generate or exact restore.
        let mut seeds = [17; 64];
        seeds[32..].fill(93);
        SigningKey::from_bytes(&seeds)
    }

    #[test]
    fn mandatory_components_closed_envelope_and_domain() {
        let signer = key();
        let verifier = signer.verifying_key();
        let message = b"OCLOB:ORDER-AUTHORITY:v2:fixture";
        let signature = signer.try_sign(message).unwrap();
        verifier.verify_strict(message, &signature).unwrap();
        assert_eq!(signature.0.len(), SIGNATURE_BYTES);
        assert!(verifier
            .verify_strict(b"OCLOB:NATIVE-LIFECYCLE:v2:fixture", &signature)
            .is_err());
        for offset in [
            0,
            8,
            12,
            KEY_OFFSET,
            KEY_OFFSET + 32,
            KEY_OFFSET + PUBLIC_KEY_BYTES,
            KEY_OFFSET + PUBLIC_KEY_BYTES + 64,
        ] {
            let mut tampered = signature.clone();
            tampered.0[offset] ^= 1;
            assert!(verifier.verify_strict(message, &tampered).is_err());
        }
        for length in [64, 3373, SIGNATURE_BYTES - 1] {
            assert!(verifier
                .verify_strict(message, &Signature(signature.0[..length].to_vec()))
                .is_err());
        }
        let mut extended = signature.clone();
        extended.0.push(0);
        assert!(verifier.verify_strict(message, &extended).is_err());
    }

    #[test]
    fn raw_classical_identity_and_changed_pq_registration_are_rejected() {
        let signer = key();
        let public = signer.hybrid_public_key();
        let raw_classical: [u8; 32] = public[..32].try_into().unwrap();
        let signature = signer.try_sign(b"registration").unwrap();
        assert!(VerifyingKey::from_bytes(&raw_classical)
            .unwrap()
            .verify_strict(b"registration", &signature)
            .is_err());
        let mut seeds = signer.to_bytes();
        seeds[32] ^= 1;
        let rotated = SigningKey::from_bytes(&seeds);
        assert_ne!(signer.verifying_key(), rotated.verifying_key());
        assert!(signer
            .verifying_key()
            .verify_strict(b"registration", &rotated.try_sign(b"registration").unwrap())
            .is_err());
        let restored = SigningKey::from_bytes(&signer.to_bytes());
        assert_eq!(restored.verifying_key(), signer.verifying_key());
        restored
            .verifying_key()
            .verify_strict(b"registration", &signature)
            .unwrap();
    }

    #[test]
    fn wrong_common_key_purpose_fails_even_with_correct_envelope() {
        let signer = key();
        let mut encoded = signer.try_sign(b"purpose").unwrap().0;
        let wrong = signer
            .signer
            .sign(KeyPurpose::KeyRotation, b"purpose")
            .unwrap();
        encoded[KEY_OFFSET + PUBLIC_KEY_BYTES..].copy_from_slice(&wrong);
        assert!(signer
            .verifying_key()
            .verify_strict(b"purpose", &Signature(encoded))
            .is_err());
    }
}
