//! Optional optimistic execution using the common node signer and canonical
//! challenge client. The ordinary service methods retain joint-proof behavior.
use super::*;
use oclob_proofs::optimistic::{
    transition_input_root, FinalizedOptimisticTransition, TransitionChallengeVerifier,
};
use zkpi_defmi_sdk::optimistic::ProofParty;
use zkpi_defmi_sdk::optimistic::{
    CanonicalOptimisticFinality, ChallengeVerifier, NodeExecutionAdmission, OptimisticClient,
    Proposal,
};

/// A real MPC execution whose book/reservation changes remain provisional.
/// Secret staged state is never serialized as public dispute evidence.
pub struct PendingOclobSubmission {
    base_book_root: Digest32,
    base_settlement: SettlementStateSnapshot,
    staged: StagedSubmission<Proposal, TransitionStatement>,
    verifier: TransitionChallengeVerifier,
}

impl PendingOclobSubmission {
    pub fn proposal(&self) -> &Proposal {
        &self.staged.transition_proof
    }
    pub fn book_transition(&self) -> &BookTransition {
        &self.staged.book_transition
    }
    pub fn public_statement(&self) -> &TransitionStatement {
        &self.staged.verified_transition
    }

    /// The existing 5-of-7 transition evidence is generated on a challenge,
    /// not during the successful optimistic path.
    pub fn challenge_proof(&self) -> Result<TransitionProof, ServiceError> {
        TransitionProof::attest(
            self.staged.verified_transition.clone(),
            &self.staged.staged_ordering.transition_signers(),
            self.staged.staged_ordering.policy(),
        )
        .map_err(|e| ServiceError::Proof(e.to_string()))
    }

    pub fn finalize(
        self,
        service: &OclobService,
        finality: &CanonicalOptimisticFinality,
        now: u64,
    ) -> Result<PreparedOclobSubmission<FinalizedOptimisticTransition>, ServiceError> {
        if service.book.public_snapshot().state_root != self.base_book_root
            || service.settlement.state_snapshot() != self.base_settlement
        {
            return Err(ServiceError::Settlement(
                "provisional OCLOB execution is stale against the current book".into(),
            ));
        }
        if finality.claim().proposal != *self.proposal() {
            return Err(ServiceError::Settlement(
                "canonical finality names another provisional execution".into(),
            ));
        }
        let StagedSubmission {
            settlement_order,
            staged_book,
            staged_ordering,
            staged_settlement,
            staged_eligibility,
            certificate,
            reservation,
            eligibility,
            mpc,
            book_transition,
            verified_transition,
            ..
        } = self.staged;
        let authorization = FinalizedOptimisticTransition::from_canonical(
            finality,
            verified_transition,
            &self.verifier,
        )
        .map_err(ServiceError::Settlement)?;
        service.prepare_staged(
            StagedSubmission {
                settlement_order,
                staged_book,
                staged_ordering,
                staged_settlement,
                staged_eligibility,
                certificate,
                reservation,
                eligibility,
                mpc,
                book_transition,
                transition_proof: authorization.clone(),
                verified_transition: authorization,
            },
            now,
        )
    }
}

impl OclobService {
    /// Execute the real matcher, register its admitted inputs through the host
    /// callback, and submit one node's proposal. Returning this object does not
    /// mutate the book or move reserved customer assets.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_optimistic_submit(
        &mut self,
        order: SecretOrder,
        authority: OrderAuthority,
        eligibility: AnonymousPresentation,
        now: u64,
        proposer: &mut ProofParty,
        client: &OptimisticClient<'_>,
        admit: impl FnOnce(
            &TransitionStatement,
            &TransitionChallengeVerifier,
        ) -> Result<NodeExecutionAdmission, String>,
    ) -> Result<PendingOclobSubmission, ServiceError> {
        if !self.book.expired_commitments(now).is_empty() {
            return Err(ServiceError::Settlement(
                "expired reservations must reach canonical finality first".into(),
            ));
        }
        let base_book_root = self.book.public_snapshot().state_root;
        let base_settlement = self.settlement.state_snapshot();
        let verifier = TransitionChallengeVerifier::new(
            self.ordering.verifying_keys(),
            self.ordering.policy(),
        )
        .map_err(ServiceError::Proof)?;
        let staged =
            self.stage_with_assurance(order, authority, eligibility, now, |statement, _| {
                let admission = admit(&statement, &verifier).map_err(ServiceError::Settlement)?;
                if admission.execution.context.input_root != transition_input_root(&statement)
                    || admission.execution.context.verifier != verifier.verifier_id()
                {
                    return Err(ServiceError::Proof(
                        "canonical admission differs from the executed OCLOB input".into(),
                    ));
                }
                let proposal = proposer
                    .sign_admitted_optimistic_execution(&admission, statement.digest())
                    .map_err(ServiceError::Proof)?;
                client
                    .propose(&proposal)
                    .map_err(ServiceError::Settlement)?;
                Ok((proposal, statement))
            })?;
        Ok(PendingOclobSubmission {
            base_book_root,
            base_settlement,
            staged,
            verifier,
        })
    }
}
