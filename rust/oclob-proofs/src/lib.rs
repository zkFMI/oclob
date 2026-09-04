//! Public evidence binding one ordered secret input, MPC execution, and book
//! transition.  This committee proof is the P1 validity boundary; later proof
//! systems can replace it without changing the statement digest.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{BookTransition, CancellationTransition, Digest32, ExpiryTransition, PublicFill};
use oclob_mpc::{MpcBatchReceipt, MpcReceipt};
use oclob_ordering::{CommitteePolicy, OrderCertificate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const STATEMENT_DOMAIN: &[u8] = b"OCLOB:TRANSITION-STATEMENT:v2";
const FILL_DOMAIN: &[u8] = b"OCLOB:PUBLIC-FILL:v1";
const CANCELLATION_STATEMENT_DOMAIN: &[u8] = b"OCLOB:CANCELLATION-STATEMENT:v1";
const EXPIRY_STATEMENT_DOMAIN: &[u8] = b"OCLOB:EXPIRY-STATEMENT:v1";

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
            fill_digest: fills_digest(&transition.fills),
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
            fill_digest: fills_digest(&transition.fills),
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
                .map(|(node_id, key)| TransitionAttestation {
                    node_id: *node_id,
                    signature: key.sign(&digest).to_bytes().to_vec(),
                })
                .collect(),
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
                .map(|(node_id, key)| TransitionAttestation {
                    node_id: *node_id,
                    signature: key.sign(&digest).to_bytes().to_vec(),
                })
                .collect(),
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
            .map(|(node_id, key)| TransitionAttestation {
                node_id: *node_id,
                signature: key.sign(&digest).to_bytes().to_vec(),
            })
            .collect();
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

    pub fn digest(&self) -> Digest32 {
        self.statement.digest()
    }
}

fn fills_digest(fills: &[PublicFill]) -> Digest32 {
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
