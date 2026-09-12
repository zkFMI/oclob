//! Public evidence binding one ordered secret input, MPC execution, and book
//! transition.  This committee proof is the P1 validity boundary; later proof
//! systems can replace it without changing the statement digest.

#![forbid(unsafe_code)]

pub mod optimistic;

use oclob_core::application_crypto::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{BookTransition, CancellationTransition, Digest32, ExpiryTransition, PublicFill};
use oclob_mpc::{MpcBatchReceipt, MpcReceipt};
use oclob_ordering::{CommitteePolicy, OrderCertificate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const STATEMENT_DOMAIN: &[u8] = b"OCLOB:TRANSITION-STATEMENT:v3";
const FILL_DOMAIN: &[u8] = b"OCLOB:PUBLIC-FILL:v2";
const COMMITTEE_TRUST_DOMAIN: &[u8] = b"OCLOB:TRANSITION-COMMITTEE:v2";
const CANCELLATION_STATEMENT_DOMAIN: &[u8] = b"OCLOB:CANCELLATION-STATEMENT:v2";
const EXPIRY_STATEMENT_DOMAIN: &[u8] = b"OCLOB:EXPIRY-STATEMENT:v2";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransitionStatement {
    pub market_id: String,
    pub sequence: u64,
    pub order_certificate_digest: Digest32,
    pub eligibility_proof_digest: Digest32,
    pub private_before_root: Digest32,
    pub private_after_root: Digest32,
    pub public_before_root: Digest32,
    pub public_after_root: Digest32,
    pub mpc_program_digest: Digest32,
    pub mpc_output_digest: Digest32,
    pub fill_digest: Digest32,
}

impl TransitionStatement {
    pub fn from_execution(
        certificate: &OrderCertificate,
        transition: &BookTransition,
        mpc: &MpcReceipt,
        eligibility_proof_digest: Digest32,
    ) -> Result<Self, ProofError> {
        if certificate.sequence != transition.sequence
            || certificate.market_id != transition.public_after.market_id
            || !mpc.all_parties_agreed
            || eligibility_proof_digest == [0; 32]
        {
            return Err(ProofError::StatementMismatch);
        }
        if let Some(fill) = &transition.fill {
            if fill.taker_order != certificate.commitment {
                return Err(ProofError::StatementMismatch);
            }
        }
        Ok(Self {
            market_id: certificate.market_id.clone(),
            sequence: certificate.sequence,
            order_certificate_digest: certificate.digest(),
            eligibility_proof_digest,
            private_before_root: transition.private_before_root,
            private_after_root: transition.private_after_root,
            public_before_root: transition.public_before_root,
            public_after_root: transition.public_after.state_root,
            mpc_program_digest: mpc.program_sha256,
            mpc_output_digest: mpc.public_output_sha256,
            fill_digest: public_fills_digest(&transition.fills),
        })
    }

    pub fn from_batch_execution(
        certificate: &OrderCertificate,
        transition: &BookTransition,
        mpc: &MpcBatchReceipt,
        eligibility_proof_digest: Digest32,
    ) -> Result<Self, ProofError> {
        if certificate.sequence != transition.sequence
            || certificate.market_id != transition.public_after.market_id
            || !mpc.all_parties_agreed
            || eligibility_proof_digest == [0; 32]
        {
            return Err(ProofError::StatementMismatch);
        }
        if transition
            .fills
            .iter()
            .any(|fill| fill.taker_order != certificate.commitment)
        {
            return Err(ProofError::StatementMismatch);
        }
        Ok(Self {
            market_id: certificate.market_id.clone(),
            sequence: certificate.sequence,
            order_certificate_digest: certificate.digest(),
            eligibility_proof_digest,
            private_before_root: transition.private_before_root,
            private_after_root: transition.private_after_root,
            public_before_root: transition.public_before_root,
            public_after_root: transition.public_after.state_root,
            mpc_program_digest: mpc.program_sha256,
            mpc_output_digest: mpc.public_output_sha256,
            fill_digest: public_fills_digest(&transition.fills),
        })
    }

    pub fn digest(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(STATEMENT_DOMAIN);
        put_bytes(&mut hash, self.market_id.as_bytes());
        hash.update(self.sequence.to_be_bytes());
        hash.update(self.order_certificate_digest);
        hash.update(self.eligibility_proof_digest);
        hash.update(self.private_before_root);
        hash.update(self.private_after_root);
        hash.update(self.public_before_root);
        hash.update(self.public_after_root);
        hash.update(self.mpc_program_digest);
        hash.update(self.mpc_output_digest);
        hash.update(self.fill_digest);
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransitionAttestation {
    pub node_id: u16,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransitionProof {
    pub statement: TransitionStatement,
    pub attestations: Vec<TransitionAttestation>,
}

/// Proof that has passed the frozen 5-of-7 OCLOB committee policy. The inner
/// proof is intentionally private and this type is not deserializable, so an
/// application cannot accidentally treat untrusted wire bytes as settlement
/// authority.
#[derive(Clone, Debug)]
pub struct VerifiedTransitionProof {
    proof: TransitionProof,
    committee_trust_root: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancellationStatement {
    pub market_id: String,
    pub sequence: u64,
    pub certificate_digest: Digest32,
    pub target_commitment: Digest32,
    pub private_before_root: Digest32,
    pub private_after_root: Digest32,
    pub public_before_root: Digest32,
    pub public_after_root: Digest32,
}

impl CancellationStatement {
    pub fn from_transition(
        certificate: &OrderCertificate,
        transition: &CancellationTransition,
    ) -> Result<Self, ProofError> {
        if certificate.sequence != transition.sequence
            || certificate.commitment != transition.cancellation_commitment
            || certificate.market_id != transition.public_after.market_id
        {
            return Err(ProofError::StatementMismatch);
        }
        Ok(Self {
            market_id: certificate.market_id.clone(),
            sequence: transition.sequence,
            certificate_digest: certificate.digest(),
            target_commitment: transition.target_commitment.0,
            private_before_root: transition.private_before_root,
            private_after_root: transition.private_after_root,
            public_before_root: transition.public_before_root,
            public_after_root: transition.public_after.state_root,
        })
    }

    pub fn digest(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(CANCELLATION_STATEMENT_DOMAIN);
        put_bytes(&mut hash, self.market_id.as_bytes());
        hash.update(self.sequence.to_be_bytes());
        hash.update(self.certificate_digest);
        hash.update(self.target_commitment);
        hash.update(self.private_before_root);
        hash.update(self.private_after_root);
        hash.update(self.public_before_root);
        hash.update(self.public_after_root);
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancellationProof {
    pub statement: CancellationStatement,
    pub attestations: Vec<TransitionAttestation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpiryStatement {
    pub market_id: String,
    pub sequence: u64,
    pub certificate_digest: Digest32,
    pub cutoff: u64,
    pub expired_orders: Vec<Digest32>,
    pub private_before_root: Digest32,
    pub private_after_root: Digest32,
    pub public_before_root: Digest32,
    pub public_after_root: Digest32,
}

impl ExpiryStatement {
    pub fn from_transition(
        certificate: &OrderCertificate,
        transition: &ExpiryTransition,
    ) -> Result<Self, ProofError> {
        if certificate.sequence != transition.sequence
            || certificate.commitment != transition.expiry_commitment
            || certificate.market_id != transition.public_after.market_id
        {
            return Err(ProofError::StatementMismatch);
        }
        Ok(Self {
            market_id: certificate.market_id.clone(),
            sequence: transition.sequence,
            certificate_digest: certificate.digest(),
            cutoff: transition.cutoff,
            expired_orders: transition
                .expired_orders
                .iter()
                .map(|commitment| commitment.0)
                .collect(),
            private_before_root: transition.private_before_root,
            private_after_root: transition.private_after_root,
            public_before_root: transition.public_before_root,
            public_after_root: transition.public_after.state_root,
        })
    }

    pub fn digest(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(EXPIRY_STATEMENT_DOMAIN);
        put_bytes(&mut hash, self.market_id.as_bytes());
        hash.update(self.sequence.to_be_bytes());
        hash.update(self.certificate_digest);
        hash.update(self.cutoff.to_be_bytes());
        hash.update((self.expired_orders.len() as u64).to_be_bytes());
        for order in &self.expired_orders {
            hash.update(order);
        }
        hash.update(self.private_before_root);
        hash.update(self.private_after_root);
        hash.update(self.public_before_root);
        hash.update(self.public_after_root);
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpiryProof {
    pub statement: ExpiryStatement,
    pub attestations: Vec<TransitionAttestation>,
}

impl ExpiryProof {
    pub fn attest(
        statement: ExpiryStatement,
        signers: &[(u16, &SigningKey)],
        policy: CommitteePolicy,
    ) -> Result<Self, ProofError> {
        policy
            .validate()
            .map_err(|_| ProofError::InvalidCommittee)?;
        if signers.len() < policy.ordering_quorum {
            return Err(ProofError::InsufficientQuorum);
        }
        let digest = statement.digest();
        Ok(Self {
            statement,
            attestations: signers
                .iter()
                .take(policy.ordering_quorum)
                .map(|(node_id, key)| {
                    Ok(TransitionAttestation {
                        node_id: *node_id,
                        signature: key
                            .try_sign(&digest)
                            .map_err(|_| ProofError::InvalidSignature)?
                            .to_bytes(),
                    })
                })
                .collect::<Result<Vec<_>, ProofError>>()?,
        })
    }

    pub fn verify(
        &self,
        keys: &BTreeMap<u16, VerifyingKey>,
        policy: CommitteePolicy,
    ) -> Result<(), ProofError> {
        policy
            .validate()
            .map_err(|_| ProofError::InvalidCommittee)?;
        let digest = self.statement.digest();
        let mut distinct = BTreeSet::new();
        for attestation in &self.attestations {
            if !distinct.insert(attestation.node_id) {
                return Err(ProofError::InvalidSignature);
            }
            let key = keys
                .get(&attestation.node_id)
                .ok_or(ProofError::InvalidSignature)?;
            let signature = Signature::try_from(attestation.signature.as_slice())
                .map_err(|_| ProofError::InvalidSignature)?;
            key.verify_strict(&digest, &signature)
                .map_err(|_| ProofError::InvalidSignature)?;
        }
        if distinct.len() < policy.ordering_quorum {
            return Err(ProofError::InsufficientQuorum);
        }
        Ok(())
    }
}

impl CancellationProof {
    pub fn attest(
        statement: CancellationStatement,
        signers: &[(u16, &SigningKey)],
        policy: CommitteePolicy,
    ) -> Result<Self, ProofError> {
        policy
            .validate()
            .map_err(|_| ProofError::InvalidCommittee)?;
        if signers.len() < policy.ordering_quorum {
            return Err(ProofError::InsufficientQuorum);
        }
        let digest = statement.digest();
        Ok(Self {
            statement,
            attestations: signers
                .iter()
                .take(policy.ordering_quorum)
                .map(|(node_id, key)| {
                    Ok(TransitionAttestation {
                        node_id: *node_id,
                        signature: key
                            .try_sign(&digest)
                            .map_err(|_| ProofError::InvalidSignature)?
                            .to_bytes(),
                    })
                })
                .collect::<Result<Vec<_>, ProofError>>()?,
        })
    }

    pub fn verify(
        &self,
        keys: &BTreeMap<u16, VerifyingKey>,
        policy: CommitteePolicy,
    ) -> Result<(), ProofError> {
        policy
            .validate()
            .map_err(|_| ProofError::InvalidCommittee)?;
        let digest = self.statement.digest();
        let mut distinct = BTreeSet::new();
        for attestation in &self.attestations {
            if !distinct.insert(attestation.node_id) {
                return Err(ProofError::InvalidSignature);
            }
            let key = keys
                .get(&attestation.node_id)
                .ok_or(ProofError::InvalidSignature)?;
            let signature = Signature::try_from(attestation.signature.as_slice())
                .map_err(|_| ProofError::InvalidSignature)?;
            key.verify_strict(&digest, &signature)
                .map_err(|_| ProofError::InvalidSignature)?;
        }
        if distinct.len() < policy.ordering_quorum {
            return Err(ProofError::InsufficientQuorum);
        }
        Ok(())
    }
}

impl TransitionProof {
    pub fn attest(
        statement: TransitionStatement,
        signers: &[(u16, &SigningKey)],
        policy: CommitteePolicy,
    ) -> Result<Self, ProofError> {
        policy
            .validate()
            .map_err(|_| ProofError::InvalidCommittee)?;
        if signers.len() < policy.ordering_quorum {
            return Err(ProofError::InsufficientQuorum);
        }
        let digest = statement.digest();
        let attestations = signers
            .iter()
            .take(policy.ordering_quorum)
            .map(|(node_id, key)| {
                Ok(TransitionAttestation {
                    node_id: *node_id,
                    signature: key
                        .try_sign(&digest)
                        .map_err(|_| ProofError::InvalidSignature)?
                        .to_bytes(),
                })
            })
            .collect::<Result<Vec<_>, ProofError>>()?;
        Ok(Self {
            statement,
            attestations,
        })
    }

    pub fn verify(
        &self,
        keys: &BTreeMap<u16, VerifyingKey>,
        policy: CommitteePolicy,
    ) -> Result<(), ProofError> {
        policy
            .validate()
            .map_err(|_| ProofError::InvalidCommittee)?;
        let digest = self.statement.digest();
        let mut distinct = BTreeSet::new();
        for attestation in &self.attestations {
            if !distinct.insert(attestation.node_id) {
                return Err(ProofError::InvalidSignature);
            }
            let key = keys
                .get(&attestation.node_id)
                .ok_or(ProofError::InvalidSignature)?;
            let signature = Signature::try_from(attestation.signature.as_slice())
                .map_err(|_| ProofError::InvalidSignature)?;
            key.verify_strict(&digest, &signature)
                .map_err(|_| ProofError::InvalidSignature)?;
        }
        if distinct.len() < policy.ordering_quorum {
            return Err(ProofError::InsufficientQuorum);
        }
        Ok(())
    }

    pub fn into_verified(
        self,
        keys: &BTreeMap<u16, VerifyingKey>,
        policy: CommitteePolicy,
    ) -> Result<VerifiedTransitionProof, ProofError> {
        self.verify(keys, policy)?;
        Ok(VerifiedTransitionProof {
            proof: self,
            committee_trust_root: committee_trust_root(keys, policy)?,
        })
    }

    pub fn digest(&self) -> Digest32 {
        self.statement.digest()
    }
}

impl VerifiedTransitionProof {
    pub fn digest(&self) -> Digest32 {
        self.proof.digest()
    }

    pub fn proof(&self) -> &TransitionProof {
        &self.proof
    }

    /// Bind a no-fill book admission to the exact certificate whose order
    /// commitment is about to receive a canonical pre-trade reservation.
    pub fn verify_admission_binding(
        &self,
        certificate: &OrderCertificate,
        expected_committee_trust_root: Digest32,
    ) -> Result<(), ProofError> {
        if self.committee_trust_root != expected_committee_trust_root
            || self.proof.statement.market_id != certificate.market_id
            || self.proof.statement.sequence != certificate.sequence
            || self.proof.statement.order_certificate_digest != certificate.digest()
            || self.proof.statement.fill_digest != public_fills_digest(&[])
        {
            return Err(ProofError::StatementMismatch);
        }
        Ok(())
    }

    /// Rebind the signed statement to the exact fills about to become zkPI.
    /// Signature verification alone is insufficient if a caller can swap a
    /// different public fill list after matching.
    pub fn verify_settlement_binding(
        &self,
        market_id: &str,
        arriving: oclob_core::OrderCommitment,
        fills: &[PublicFill],
        expected_committee_trust_root: Digest32,
    ) -> Result<(), ProofError> {
        if self.committee_trust_root != expected_committee_trust_root
            || self.proof.statement.market_id != market_id
            || self.proof.statement.fill_digest != public_fills_digest(fills)
            || fills.iter().any(|fill| fill.taker_order != arriving)
        {
            return Err(ProofError::StatementMismatch);
        }
        Ok(())
    }

    /// Bind a filled admission to both the exact ordering certificate and the
    /// exact MPC fill list. This is stronger than checking the fill digest in
    /// isolation because it prevents a valid transition from being attached to
    /// another certified admission at the same venue.
    pub fn verify_execution_binding(
        &self,
        certificate: &OrderCertificate,
        arriving: oclob_core::OrderCommitment,
        fills: &[PublicFill],
        expected_committee_trust_root: Digest32,
    ) -> Result<(), ProofError> {
        self.verify_settlement_binding(
            &certificate.market_id,
            arriving,
            fills,
            expected_committee_trust_root,
        )?;
        if self.proof.statement.sequence != certificate.sequence
            || self.proof.statement.order_certificate_digest != certificate.digest()
        {
            return Err(ProofError::StatementMismatch);
        }
        Ok(())
    }
}

/// Stable trust anchor for the full configured committee, not merely the
/// subset that signed one transition. A proof verified under attacker-chosen
/// keys therefore cannot be re-used by a settlement engine configured for a
/// different committee.
pub fn committee_trust_root(
    keys: &BTreeMap<u16, VerifyingKey>,
    policy: CommitteePolicy,
) -> Result<Digest32, ProofError> {
    policy
        .validate()
        .map_err(|_| ProofError::InvalidCommittee)?;
    if keys.len() != policy.nodes || keys.keys().any(|node_id| *node_id == 0) {
        return Err(ProofError::InvalidCommittee);
    }
    let mut hash = Sha256::new();
    hash.update(COMMITTEE_TRUST_DOMAIN);
    for value in [
        policy.nodes,
        policy.max_corrupt_nodes,
        policy.reconstruction_quorum,
        policy.ordering_quorum,
        policy.settlement_authorization_quorum,
    ] {
        hash.update((value as u64).to_be_bytes());
    }
    for (node_id, key) in keys {
        hash.update(node_id.to_be_bytes());
        hash.update(key.as_bytes());
    }
    Ok(hash.finalize().into())
}

pub fn public_fills_digest(fills: &[PublicFill]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(FILL_DOMAIN);
    hash.update((fills.len() as u64).to_be_bytes());
    for fill in fills {
        hash.update(fill.maker_order.0);
        hash.update(fill.taker_order.0);
        hash.update(fill.price.to_be_bytes());
        hash.update(fill.quantity.to_be_bytes());
    }
    hash.finalize().into()
}

fn put_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProofError {
    #[error("the ordered input, MPC receipt and book transition disagree")]
    StatementMismatch,
    #[error("the transition proof has fewer than five independent attestations")]
    InsufficientQuorum,
    #[error("the transition proof contains an invalid or duplicate signature")]
    InvalidSignature,
    #[error("the committee profile is not the frozen OCLOB profile")]
    InvalidCommittee,
}
