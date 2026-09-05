//! DeKYX verification at the OCLOB admission boundary.
//!
//! The adapter verifies an anonymous legal-entity credential against the exact
//! order commitment before the order is reserved or sequenced.  Only the
//! scope nullifier and proof digest leave this boundary; neither the credential
//! subject nor the issuer's private registry enters the order book.

#![forbid(unsafe_code)]

use curve25519_dalek::scalar::Scalar;
pub use dekyx_core::AnonymousPresentation;
use dekyx_core::{
    Credential, CredentialIssuer, CredentialRequest, CredentialWitness, EligibilityProvider,
    EligibilityRequirement, IssuerDefinition, IssuerDirectory, IssuerStatus, PresentationContext,
    PresentationLedger, Qualification, SubjectKind,
};
use ed25519_dalek::SigningKey;
use oclob_core::Digest32;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const ISSUER_EPOCH: u64 = 1;
const STATUS_EPOCH: u64 = 1;
const DEMO_VALID_UNTIL: u64 = u64::MAX - 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedOrderEligibility {
    pub subject_nullifier: Digest32,
    pub subject_line_id: Digest32,
    pub proof_digest: Digest32,
    pub valid_until: u64,
}

#[derive(Clone)]
pub struct OclobEligibilityVerifier {
    directory: IssuerDirectory,
    requirement: EligibilityRequirement,
    consumed: PresentationLedger,
    audience_digest: Digest32,
    action_digest: Digest32,
}

impl OclobEligibilityVerifier {
    /// Reuse the exact issuer/status anchors at DeFMI's private reservation
    /// boundary. The caller cannot replace these with request-supplied keys.
    pub fn directory(&self) -> &IssuerDirectory {
        &self.directory
    }

    pub fn requirement(&self) -> &EligibilityRequirement {
        &self.requirement
    }

    pub fn new(
        directory: IssuerDirectory,
        requirement: EligibilityRequirement,
        audience_digest: Digest32,
        action_digest: Digest32,
    ) -> Result<Self, EligibilityError> {
        if audience_digest == [0; 32]
            || action_digest == [0; 32]
            || requirement.subject_kind != SubjectKind::LegalEntity
        {
            return Err(EligibilityError::Configuration);
        }
        directory
            .verifier(&requirement.issuer_id, requirement.issuer_key_epoch)
            .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
        Ok(Self {
            directory,
            requirement,
            consumed: PresentationLedger::default(),
            audience_digest,
            action_digest,
        })
    }

    pub fn verify_order(
        &mut self,
        order_commitment: Digest32,
        order_nullifier: Digest32,
        order_expires_at: u64,
        evidence: &AnonymousPresentation,
        now: u64,
    ) -> Result<VerifiedOrderEligibility, EligibilityError> {
        if evidence.context.scope_digest != self.requirement.scope_digest
            || evidence.context.audience_digest != self.audience_digest
            || evidence.context.action_digest != self.action_digest
            || evidence.context.request_digest != order_commitment
            || evidence.context.valid_until < order_expires_at
            || evidence.nullifier != order_nullifier
        {
            return Err(EligibilityError::ContextMismatch);
        }
        let verifier = self
            .directory
            .verifier(
                &self.requirement.issuer_id,
                self.requirement.issuer_key_epoch,
            )
            .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
        let verified = verifier
            .verify_eligibility(&self.requirement, &evidence.context, evidence, now)
            .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
        self.consumed
            .consume(&verified.subject_nullifier, &evidence.context)
            .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
        Ok(VerifiedOrderEligibility {
            subject_nullifier: verified.subject_nullifier,
            subject_line_id: verified.subject_line_id,
            proof_digest: verified.proof_digest,
            valid_until: verified.valid_until,
        })
    }
}

pub struct DemoEligibilityIssuer {
    issuer: CredentialIssuer,
    definition: IssuerDefinition,
    scope_digest: Digest32,
    policy_digest: Digest32,
    qualification: Qualification,
    audience_digest: Digest32,
    action_digest: Digest32,
}

pub struct DemoEligibilityWallet {
    credential: Credential,
    witness: CredentialWitness,
    scope_digest: Digest32,
    qualification: Qualification,
    audience_digest: Digest32,
    action_digest: Digest32,
}

impl DemoEligibilityIssuer {
    pub fn issue_wallet<R: RngCore + CryptoRng>(
        &self,
        subject_seed: u64,
        credential_label: &[u8],
        rng: &mut R,
    ) -> Result<DemoEligibilityWallet, EligibilityError> {
        if subject_seed == 0 || credential_label.is_empty() {
            return Err(EligibilityError::Configuration);
        }
        let witness = CredentialWitness::from_scalars(
            Scalar::from(subject_seed),
            Scalar::random(&mut *rng),
            vec![self.qualification.clone()],
        )
        .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
        let request = CredentialRequest {
            credential_id: digest(b"OCLOB:DEMO:CREDENTIAL:v1", credential_label),
            issuer_id: self.definition.issuer_id,
            issuer_key_epoch: self.definition.key_epoch,
            subject_kind: SubjectKind::LegalEntity,
            subject_commitment: witness.subject_commitment(),
            scope_digest: self.scope_digest,
            policy_digest: self.policy_digest,
            qualifications: vec![self.qualification.clone()],
            status_epoch: STATUS_EPOCH,
            valid_from: 1,
            valid_until: DEMO_VALID_UNTIL,
        };
        let issuance = witness
            .prove_issuance(&request, &mut *rng)
            .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
        let credential = self
            .issuer
            .issue(request, issuance)
            .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
        Ok(DemoEligibilityWallet {
            credential,
            witness,
            scope_digest: self.scope_digest,
            qualification: self.qualification.clone(),
            audience_digest: self.audience_digest,
            action_digest: self.action_digest,
        })
    }
}

impl DemoEligibilityWallet {
    pub fn credential_digest(&self) -> Result<Digest32, EligibilityError> {
        self.credential
            .digest()
            .map_err(|error| EligibilityError::DeKyx(error.to_string()))
    }

    pub fn scope_digest(&self) -> Digest32 {
        self.scope_digest
    }

    /// The same DeKYX credential authorizes a signed pretrade mandate without
    /// exposing its witness or treating an order presentation as reusable consent.
    pub fn present_context<R: RngCore + CryptoRng>(
        &self,
        context: PresentationContext,
        rng: &mut R,
    ) -> Result<AnonymousPresentation, EligibilityError> {
        if context.scope_digest != self.scope_digest {
            return Err(EligibilityError::ContextMismatch);
        }
        AnonymousPresentation::create(
            self.credential.clone(),
            &self.witness,
            context,
            std::slice::from_ref(&self.qualification),
            rng,
        )
        .map_err(|error| EligibilityError::DeKyx(error.to_string()))
    }

    pub fn subject_nullifier(&self) -> Digest32 {
        self.witness.scope_nullifier(&self.scope_digest)
    }

    pub fn present<R: RngCore + CryptoRng>(
        &self,
        order_commitment: Digest32,
        challenge_nonce: Digest32,
        valid_until: u64,
        rng: &mut R,
    ) -> Result<AnonymousPresentation, EligibilityError> {
        let context = PresentationContext {
            scope_digest: self.scope_digest,
            audience_digest: self.audience_digest,
            action_digest: self.action_digest,
            request_digest: order_commitment,
            challenge_nonce,
            valid_until,
        };
        AnonymousPresentation::create(
            self.credential.clone(),
            &self.witness,
            context,
            std::slice::from_ref(&self.qualification),
            rng,
        )
        .map_err(|error| EligibilityError::DeKyx(error.to_string()))
    }
}

pub fn deterministic_demo_environment(
    market_id: &str,
) -> Result<(OclobEligibilityVerifier, DemoEligibilityIssuer), EligibilityError> {
    if market_id.is_empty() {
        return Err(EligibilityError::Configuration);
    }
    let signing_key = SigningKey::from_bytes(&[71; 32]);
    let definition = IssuerDefinition {
        issuer_id: digest(b"OCLOB:DEMO:ISSUER-ID:v1", market_id.as_bytes()),
        key_epoch: ISSUER_EPOCH,
        public_key: signing_key.verifying_key().to_bytes(),
        supported_subjects: BTreeSet::from([SubjectKind::LegalEntity]),
        namespace_digest: digest(b"OCLOB:DEMO:ISSUER-NAMESPACE:v1", market_id.as_bytes()),
        valid_from: 1,
        valid_until: DEMO_VALID_UNTIL,
        status: IssuerStatus::Active,
    };
    let scope_digest = digest(b"OCLOB:DEKYX:SCOPE:v1", market_id.as_bytes());
    let policy_digest = digest(b"OCLOB:DEKYX:POLICY:v1", market_id.as_bytes());
    let qualification = Qualification {
        namespace: "org.zkfmi.oclob.legal-entity-participant".into(),
        predicate_digest: digest(b"OCLOB:DEKYX:QUALIFICATION:v1", market_id.as_bytes()),
    };
    let audience_digest = digest(b"OCLOB:DEKYX:AUDIENCE:v1", market_id.as_bytes());
    let action_digest = digest(b"OCLOB:DEKYX:ACTION:SUBMIT-ORDER:v1", market_id.as_bytes());
    let issuer = CredentialIssuer::new(definition.clone(), signing_key)
        .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
    let mut directory = IssuerDirectory::default();
    directory
        .register_issuer(definition.clone())
        .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
    directory
        .publish_status_list(
            issuer
                .issue_status_list(STATUS_EPOCH, 1, DEMO_VALID_UNTIL, Vec::new())
                .map_err(|error| EligibilityError::DeKyx(error.to_string()))?,
        )
        .map_err(|error| EligibilityError::DeKyx(error.to_string()))?;
    let requirement = EligibilityRequirement {
        issuer_id: definition.issuer_id,
        issuer_key_epoch: definition.key_epoch,
        issuer_namespace_digest: definition.namespace_digest,
        subject_kind: SubjectKind::LegalEntity,
        scope_digest,
        policy_digest,
        required_qualifications: vec![qualification.clone()],
    };
    let verifier =
        OclobEligibilityVerifier::new(directory, requirement, audience_digest, action_digest)?;
    Ok((
        verifier,
        DemoEligibilityIssuer {
            issuer,
            definition,
            scope_digest,
            policy_digest,
            qualification,
            audience_digest,
            action_digest,
        },
    ))
}

fn digest(domain: &[u8], value: &[u8]) -> Digest32 {
    Sha256::new()
        .chain_update(domain)
        .chain_update((value.len() as u64).to_be_bytes())
        .chain_update(value)
        .finalize()
        .into()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EligibilityError {
    #[error("invalid OCLOB DeKYX configuration")]
    Configuration,
    #[error("anonymous qualification is not bound to this exact order")]
    ContextMismatch,
    #[error("DeKYX rejected the anonymous qualification: {0}")]
    DeKyx(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn proof_is_bound_to_one_order_and_one_use() {
        let (mut verifier, issuer) = deterministic_demo_environment("JGB10Y-JPY").unwrap();
        let wallet = issuer.issue_wallet(11, b"first", &mut OsRng).unwrap();
        let commitment = [8; 32];
        let proof = wallet
            .present(commitment, [9; 32], 2_000, &mut OsRng)
            .unwrap();
        let accepted = verifier
            .verify_order(commitment, wallet.subject_nullifier(), 2_000, &proof, 1_000)
            .unwrap();
        assert_eq!(accepted.subject_nullifier, wallet.subject_nullifier());
        assert!(verifier
            .verify_order(commitment, wallet.subject_nullifier(), 2_000, &proof, 1_000)
            .is_err());

        let (mut verifier, _) = deterministic_demo_environment("JGB10Y-JPY").unwrap();
        assert_eq!(
            verifier.verify_order([7; 32], wallet.subject_nullifier(), 2_000, &proof, 1_000),
            Err(EligibilityError::ContextMismatch)
        );
    }
}
