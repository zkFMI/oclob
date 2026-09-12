//! OCLOB's verifier adapter for the shared zkpi-optimistic protocol.
//! The fallback remains the existing frozen committee validity boundary;
//! it is not represented as a mathematical zero-knowledge transition proof.

use super::{committee_trust_root, TransitionProof, TransitionStatement};
use oclob_core::application_crypto::VerifyingKey;
use oclob_ordering::CommitteePolicy;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub use zkpi_committee::optimistic::{AssuranceMode, OptimisticPolicy, OptimisticState};
use zkpi_committee::optimistic::{ChallengeVerifier, Digest32, ExecutionContext};

/// Construct only from the host's canonical committee registry. Proof bytes
/// cannot supply keys, quorum policy or the identity of the trusted verifier.
#[derive(Clone)]
pub struct TransitionChallengeVerifier {
    keys: BTreeMap<u16, VerifyingKey>,
    policy: CommitteePolicy,
    identity: Digest32,
    trust_root: Digest32,
}

impl TransitionChallengeVerifier {
    pub fn new(keys: BTreeMap<u16, VerifyingKey>, policy: CommitteePolicy) -> Result<Self, String> {
        let trust_root = committee_trust_root(&keys, policy).map_err(|e| e.to_string())?;
        let identity = Sha256::new()
            .chain_update(b"OCLOB:optimistic:transition-verifier:v1")
            .chain_update(trust_root)
            .finalize()
            .into();
        Ok(Self {
            keys,
            policy,
            identity,
            trust_root,
        })
    }

    pub fn verify_settlement_reference(
        &self,
        reference: &zkpi_defmi_sdk::defmi::application_settlement::OptimisticSettlementReference,
        mpc_result: Digest32,
    ) -> Result<(), String> {
        if reference.public_output.len() > 1024 * 1024 {
            return Err("OCLOB public output exceeds its bound".into());
        }
        let statement: TransitionStatement =
            serde_json::from_slice(&reference.public_output).map_err(|e| e.to_string())?;
        if reference.context.verifier != self.identity
            || reference.context.input_root != transition_input_root(&statement)
            || reference.output_root != statement.digest()
            || mpc_result != statement.mpc_output_digest
        {
            return Err(
                "OCLOB settlement differs from the finalized input or public output".into(),
            );
        }
        Ok(())
    }
}

/// Deliberately distinct from VerifiedTransitionProof. Its authority is the
/// finalized canonical optimistic claim, not an invented committee proof.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FinalizedOptimisticTransition {
    statement: TransitionStatement,
    trust_root: Digest32,
    reference: zkpi_defmi_sdk::defmi::application_settlement::OptimisticSettlementReference,
}

impl FinalizedOptimisticTransition {
    pub fn from_canonical(
        finality: &zkpi_defmi_sdk::optimistic::CanonicalOptimisticFinality,
        statement: TransitionStatement,
        verifier: &TransitionChallengeVerifier,
    ) -> Result<Self, String> {
        let claim = finality.claim();
        if claim.policy.verifier != verifier.identity
            || claim.proposal.context.input_root != transition_input_root(&statement)
            || claim.proposal.output_root != statement.digest()
        {
            return Err("OCLOB canonical finality belongs to another transition".into());
        }
        let reference =
            zkpi_defmi_sdk::defmi::application_settlement::OptimisticSettlementReference {
                claim: claim.proposal.id()?,
                context: claim.proposal.context.clone(),
                output_root: claim.proposal.output_root,
                public_output: serde_json::to_vec(&statement).map_err(|e| e.to_string())?,
            };
        Ok(Self {
            statement,
            trust_root: verifier.trust_root,
            reference,
        })
    }
    pub fn reference(
        &self,
    ) -> &zkpi_defmi_sdk::defmi::application_settlement::OptimisticSettlementReference {
        &self.reference
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::super::VerifiedTransitionProof {}
    impl Sealed for super::FinalizedOptimisticTransition {}
}

/// Both supported assurance modes share the same certificate/fill binding
/// rules. External callers cannot implement this authority from raw bytes.
pub trait TransitionAuthorization: sealed::Sealed + std::fmt::Debug {
    fn statement(&self) -> &TransitionStatement;
    fn trust_root(&self) -> Digest32;
    fn optimistic_reference(
        &self,
    ) -> Option<&zkpi_defmi_sdk::defmi::application_settlement::OptimisticSettlementReference> {
        None
    }
    fn digest(&self) -> Digest32 {
        self.statement().digest()
    }
    fn verify_admission_binding(
        &self,
        certificate: &oclob_ordering::OrderCertificate,
        expected: Digest32,
    ) -> Result<(), super::ProofError> {
        let s = self.statement();
        if self.trust_root() != expected
            || s.market_id != certificate.market_id
            || s.sequence != certificate.sequence
            || s.order_certificate_digest != certificate.digest()
            || s.fill_digest != super::public_fills_digest(&[])
        {
            return Err(super::ProofError::StatementMismatch);
        }
        Ok(())
    }
    fn verify_settlement_binding(
        &self,
        market: &str,
        arriving: oclob_core::OrderCommitment,
        fills: &[oclob_core::PublicFill],
        expected: Digest32,
    ) -> Result<(), super::ProofError> {
        let s = self.statement();
        if self.trust_root() != expected
            || s.market_id != market
            || s.fill_digest != super::public_fills_digest(fills)
            || fills.iter().any(|fill| fill.taker_order != arriving)
        {
            return Err(super::ProofError::StatementMismatch);
        }
        Ok(())
    }
    fn verify_execution_binding(
        &self,
        certificate: &oclob_ordering::OrderCertificate,
        arriving: oclob_core::OrderCommitment,
        fills: &[oclob_core::PublicFill],
        expected: Digest32,
    ) -> Result<(), super::ProofError> {
        self.verify_settlement_binding(&certificate.market_id, arriving, fills, expected)?;
        if self.statement().sequence != certificate.sequence
            || self.statement().order_certificate_digest != certificate.digest()
        {
            return Err(super::ProofError::StatementMismatch);
        }
        Ok(())
    }
}

impl TransitionAuthorization for super::VerifiedTransitionProof {
    fn statement(&self) -> &TransitionStatement {
        &self.proof.statement
    }
    fn trust_root(&self) -> Digest32 {
        self.committee_trust_root
    }
}
impl TransitionAuthorization for FinalizedOptimisticTransition {
    fn statement(&self) -> &TransitionStatement {
        &self.statement
    }
    fn trust_root(&self) -> Digest32 {
        self.trust_root
    }
    fn optimistic_reference(
        &self,
    ) -> Option<&zkpi_defmi_sdk::defmi::application_settlement::OptimisticSettlementReference> {
        Some(&self.reference)
    }
}

impl ChallengeVerifier for TransitionChallengeVerifier {
    fn verifier_id(&self) -> Digest32 {
        self.identity
    }

    fn verify(&self, context: &ExecutionContext, proof: &[u8]) -> Result<Digest32, String> {
        if proof.len() > 1024 * 1024 {
            return Err("OCLOB challenge proof exceeds its bound".into());
        }
        let proof: TransitionProof = serde_json::from_slice(proof).map_err(|e| e.to_string())?;
        if context.verifier != self.identity
            || transition_input_root(&proof.statement) != context.input_root
        {
            return Err("OCLOB challenge names another canonical input or committee".into());
        }
        proof
            .verify(&self.keys, self.policy)
            .map_err(|e| e.to_string())?;
        Ok(proof.statement.digest())
    }
}

/// Input-only binding: output roots are deliberately excluded so a valid
/// contradictory transition for the SAME input can disprove the proposal.
pub fn transition_input_root(statement: &TransitionStatement) -> Digest32 {
    Sha256::new()
        .chain_update(b"OCLOB:optimistic:transition-input:v1")
        .chain_update((statement.market_id.len() as u64).to_be_bytes())
        .chain_update(statement.market_id.as_bytes())
        .chain_update(statement.sequence.to_be_bytes())
        .chain_update(statement.order_certificate_digest)
        .chain_update(statement.eligibility_proof_digest)
        .chain_update(statement.private_before_root)
        .chain_update(statement.public_before_root)
        .chain_update(statement.mpc_program_digest)
        .finalize()
        .into()
}

/// Canonical hosts call this immediately before applying the book/settlement
/// transition. A serialized client-side status is never settlement authority.
pub fn require_finalized_transition<'a>(
    state: &'a OptimisticState,
    claim: Digest32,
    context: &ExecutionContext,
    statement: &TransitionStatement,
    verifier: &TransitionChallengeVerifier,
) -> Result<&'a zkpi_committee::optimistic::Claim, String> {
    if context.verifier != verifier.verifier_id()
        || context.input_root != transition_input_root(statement)
    {
        return Err("OCLOB finalized transition has another input or verifier".into());
    }
    state.require_finalized(claim, context, statement.digest())
}
