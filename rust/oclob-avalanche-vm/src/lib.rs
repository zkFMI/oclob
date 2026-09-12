//! Application-owned adapter. All protocol state, clocks, bonds and consensus
//! execution remain in the common DeFMI/zkpi-optimistic host.
use defmi_avalanche_vm::{
    application::{ApplicationRuntime, NoApplications},
    state::State,
};
use oclob_core::application_crypto::VerifyingKey;
use oclob_ordering::CommitteePolicy;
use oclob_proofs::optimistic::TransitionChallengeVerifier;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use zkpi_committee::optimistic::ChallengeVerifier;

pub struct OclobRuntime {
    verifier: TransitionChallengeVerifier,
}
impl OclobRuntime {
    pub fn new(keys: BTreeMap<u16, VerifyingKey>, policy: CommitteePolicy) -> Result<Self, String> {
        Ok(Self {
            verifier: TransitionChallengeVerifier::new(keys, policy)?,
        })
    }
}
impl ApplicationRuntime for OclobRuntime {
    fn validate_state(&self, state: &State) -> Result<(), String> {
        NoApplications.validate_state(state)
    }
    fn execute(
        &self,
        _state: &mut State,
        _params: &Map<String, Value>,
        _authorizer: &defmi::facility::QuorumAuthorizer,
        _timestamp: u64,
    ) -> Result<[u8; 32], String> {
        Err("OCLOB uses the canonical application reservation and fill endpoints".into())
    }
    fn optimistic_verifier(&self, id: [u8; 32]) -> Result<Box<dyn ChallengeVerifier + '_>, String> {
        if id != self.verifier.verifier_id() {
            return Err("OCLOB challenge verifier is not installed".into());
        }
        Ok(Box::new(self.verifier.clone()))
    }
    fn verify_optimistic_settlement(
        &self,
        reference: &defmi::application_settlement::OptimisticSettlementReference,
        result: [u8; 32],
    ) -> Result<(), String> {
        self.verifier.verify_settlement_reference(reference, result)
    }
    fn verify_optimistic_transition(
        &self,
        reference: &defmi::application_settlement::OptimisticSettlementReference,
    ) -> Result<(), String> {
        if reference.public_output.len() > 1024 * 1024 {
            return Err("OCLOB output exceeds its bound".into());
        }
        let statement: oclob_proofs::TransitionStatement =
            serde_json::from_slice(&reference.public_output).map_err(|e| e.to_string())?;
        self.verifier
            .verify_settlement_reference(reference, statement.mpc_output_digest)
    }
}
