//! Canonical OCLOB settlement over the standalone DeFMI Avalanche adapter.
//!
//! The application verifies zkPI and DvP evidence before this boundary. The
//! DeFMI committee then authorizes only their digests and the exact net account
//! compare-and-swap; AvalancheGo supplies ordering and finality.

use crate::{
    canonical_cash_asset_id, canonical_reservation_state_asset_id, canonical_securities_asset_id,
    CanonicalAccountOpening, CanonicalSettlementAcceptance, PreparedCanonicalTransition,
    SettlementError,
};
#[cfg(test)]
use ed25519_dalek::SigningKey;
use qomm_defmi::avalanche::{AvalancheClient, FacilityAvalancheBridge};
use qomm_defmi::facility::{
    AccountOpening, AssetDefinition, AssetKind, DefmiFacility, QuorumApproval, SettlementOrder,
    StateLeg,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

const ROOT_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(30);
const ROOT_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Live canonical gateway. The private committee keys are accepted only as a
/// reference so production callers can place each signer in its own process
/// and replace this laboratory provider without changing the settlement plan.
/// A separate distributed signer implementation is used by the node path.
pub struct AvalancheCanonicalGateway<'a, C: AvalancheClient> {
    facility: &'a DefmiFacility,
    clients: &'a [C],
    approval_keys: &'a BTreeMap<String, qomm_defmi::governance::GovernanceSigner>,
}

impl<'a, C: AvalancheClient> AvalancheCanonicalGateway<'a, C> {
    pub fn new(
        facility: &'a DefmiFacility,
        clients: &'a [C],
        approval_keys: &'a BTreeMap<String, qomm_defmi::governance::GovernanceSigner>,
    ) -> Result<Self, SettlementError> {
        if clients.len() < 3 || approval_keys.len() < 3 {
            return Err(SettlementError::Finality(
                "canonical settlement requires at least three RPC peers and three signers".into(),
            ));
        }
        Ok(Self {
            facility,
            clients,
            approval_keys,
        })
    }

    /// Register the cash, security and reservation-state assets plus every
    /// commitment-only account needed by the
    /// prepared candidate. Each operation is accepted by Avalanche before the
    /// local SQLite projection advances.
    pub fn bootstrap(
        &self,
        prepared: &PreparedCanonicalTransition,
    ) -> Result<[u8; 32], SettlementError> {
        self.require_root_agreement()?;
        let bridge = FacilityAvalancheBridge::new(self.facility, &self.clients[0]);
        for asset in asset_definitions(prepared.market_id()) {
            let before = self.facility.state_root().map_err(finality)?;
            let approval = self.approval(asset.statement().map_err(finality)?, before)?;
            bridge.register_asset(&asset, &approval).map_err(finality)?;
        }
        for account in prepared.account_openings() {
            let opening = account_opening(*account, prepared.application_binding());
            let before = self.facility.state_root().map_err(finality)?;
            let approval = self.approval(opening.statement().map_err(finality)?, before)?;
            bridge.open_account(&opening, &approval).map_err(finality)?;
        }
        self.wait_for_root(self.facility.state_root().map_err(finality)?)
    }

    /// Submit one locally verified atomic batch and wait until every supplied
    /// validator endpoint reports the accepted state root.
    pub fn settle(
        &self,
        prepared: &PreparedCanonicalTransition,
        now: u64,
    ) -> Result<CanonicalSettlementAcceptance, SettlementError> {
        if now > prepared.deadline() {
            return Err(SettlementError::Finality(
                "prepared canonical settlement expired".into(),
            ));
        }
        let canonical_before = self.require_root_agreement()?;
        let local_before = self.facility.state_root().map_err(finality)?;
        if local_before != canonical_before {
            return Err(SettlementError::Finality(
                "local DeFMI projection is not at the canonical root".into(),
            ));
        }
        let order = build_settlement_order(self.facility, prepared)?;
        let statement = order.statement().map_err(finality)?;
        let approval = self.approval(statement, local_before)?;
        let bridge = FacilityAvalancheBridge::new(self.facility, &self.clients[0]);
        let (receipt, accepted) = bridge.settle(&order, &approval, now).map_err(finality)?;
        if !receipt.verify(&self.facility.receipt_public_key)
            || receipt.statement != statement
            || receipt.before_root != accepted.before_root
            || receipt.after_root != accepted.after_root
            || !self.facility.verify_receipt_chain().map_err(finality)?
        {
            return Err(SettlementError::Finality(
                "canonical DeFMI receipt failed local verification".into(),
            ));
        }
        self.wait_for_root(accepted.after_root)?;
        Ok(CanonicalSettlementAcceptance {
            transaction_id: accepted.tx_id,
            block_id: accepted.block_id,
            height: accepted.height,
            statement,
            before_state_root: accepted.before_root,
            after_state_root: accepted.after_root,
            receipt_digest: receipt.digest().map_err(finality)?,
            application_binding: prepared.application_binding(),
            binding_digest: prepared.binding_digest(),
        })
    }

    fn approval(
        &self,
        statement: [u8; 32],
        before: [u8; 32],
    ) -> Result<QuorumApproval, SettlementError> {
        let quorum = self
            .approval_keys
            .iter()
            .take(crate::PROOF_QUORUM.len())
            .map(|(node, key)| (node.clone(), key.clone()))
            .collect::<BTreeMap<_, _>>();
        self.facility
            .authorizer
            .approve(statement, before, &quorum)
            .map_err(finality)
    }

    fn require_root_agreement(&self) -> Result<[u8; 32], SettlementError> {
        let roots = self
            .clients
            .iter()
            .map(AvalancheClient::state_root)
            .collect::<Result<Vec<_>, _>>()
            .map_err(finality)?;
        let first = *roots
            .first()
            .ok_or_else(|| SettlementError::Finality("no Avalanche root was returned".into()))?;
        if roots.iter().any(|root| *root != first) {
            return Err(SettlementError::Finality(
                "Avalanche validators disagree on canonical state".into(),
            ));
        }
        Ok(first)
    }

    fn wait_for_root(&self, expected: [u8; 32]) -> Result<[u8; 32], SettlementError> {
        let deadline = Instant::now() + ROOT_CONVERGENCE_TIMEOUT;
        loop {
            if self
                .require_root_agreement()
                .is_ok_and(|root| root == expected)
            {
                return Ok(expected);
            }
            if Instant::now() >= deadline {
                return Err(SettlementError::Finality(format!(
                    "Avalanche validators did not converge to {}",
                    hex::encode(expected)
                )));
            }
            thread::sleep(ROOT_POLL_INTERVAL);
        }
    }
}

fn asset_definitions(market_id: &str) -> Vec<AssetDefinition> {
    vec![
        AssetDefinition {
            asset_id: canonical_cash_asset_id(),
            code: "JPY".into(),
            kind: AssetKind::Cash,
            decimals: 0,
            terms_digest: digest(b"OCLOB:DEFMI:CASH-TERMS:v1", b"JPY"),
        },
        AssetDefinition {
            asset_id: canonical_securities_asset_id(market_id),
            code: market_id.to_owned(),
            kind: AssetKind::Security,
            decimals: 0,
            terms_digest: digest(b"OCLOB:DEFMI:SECURITIES-TERMS:v1", market_id.as_bytes()),
        },
        AssetDefinition {
            asset_id: canonical_reservation_state_asset_id(market_id),
            code: format!(
                "OCLOB-RESERVE-{}",
                hex::encode(
                    &digest(b"OCLOB:DEFMI:RESERVATION-CODE:v1", market_id.as_bytes(),)[..6]
                )
            ),
            kind: AssetKind::Other,
            decimals: 0,
            terms_digest: digest(
                b"OCLOB:DEFMI:RESERVATION-STATE-TERMS:v1",
                market_id.as_bytes(),
            ),
        },
    ]
}

fn account_opening(
    account: CanonicalAccountOpening,
    application_binding: [u8; 32],
) -> AccountOpening {
    let mut nonce_body = Vec::with_capacity(96);
    nonce_body.extend_from_slice(&application_binding);
    nonce_body.extend_from_slice(&account.handle);
    nonce_body.extend_from_slice(&account.asset_id);
    AccountOpening {
        handle: account.handle,
        asset_id: account.asset_id,
        commitment: account.commitment,
        issuance_nonce: digest(b"OCLOB:DEFMI:ACCOUNT-OPENING:v1", &nonce_body),
    }
}

fn build_settlement_order(
    facility: &DefmiFacility,
    prepared: &PreparedCanonicalTransition,
) -> Result<SettlementOrder, SettlementError> {
    let mut legs = Vec::with_capacity(prepared.account_deltas().len());
    for delta in prepared.account_deltas() {
        let (asset_id, commitment, sequence) =
            facility
                .account(&delta.handle)
                .map_err(finality)?
                .ok_or_else(|| SettlementError::Finality("canonical account is absent".into()))?;
        if asset_id != delta.asset_id || commitment != delta.before_commitment {
            return Err(SettlementError::Finality(
                "prepared settlement is stale against canonical DeFMI".into(),
            ));
        }
        legs.push(StateLeg {
            handle: delta.handle,
            asset_id: delta.asset_id,
            before_commitment: delta.before_commitment,
            after_commitment: delta.after_commitment,
            before_sequence: sequence,
        });
    }
    Ok(SettlementOrder {
        operation_id: prepared.operation_id(),
        nullifier: prepared.nullifier(),
        deadline: prepared.deadline(),
        payment_instruction_digest: prepared.payment_instruction_digest(),
        proof_digest: prepared.proof_digest(),
        market_statement_digest: prepared.transition_digest(),
        legs,
    })
}

fn digest(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((body.len() as u64).to_be_bytes());
    hash.update(body);
    hash.finalize().into()
}

fn finality(error: String) -> SettlementError {
    SettlementError::Finality(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SettlementEngine;
    use oclob_core::{OrderCommitment, PublicFill, SecretOrder, Side, TimeInForce};
    use oclob_ordering::OrderingCommittee;
    use oclob_proofs::{
        public_fills_digest, TransitionProof, TransitionStatement, VerifiedTransitionProof,
    };
    use qomm_defmi::facility::QuorumAuthorizer;
    use rand::rngs::OsRng;
    use std::fs;

    fn h(label: &[u8]) -> [u8; 32] {
        Sha256::digest(label).into()
    }

    fn order(
        side: Side,
        price: u64,
        quantity: u64,
        participant: [u8; 32],
        seed: u8,
    ) -> SecretOrder {
        SecretOrder::new(
            "JGB10Y-JPY",
            side,
            price,
            quantity,
            if side == Side::Sell {
                TimeInForce::GoodTilCancelled
            } else {
                TimeInForce::ImmediateOrCancel
            },
            2_000_000_000,
            participant,
            [seed; 32],
            [seed.wrapping_add(1); 32],
        )
        .unwrap()
    }

    fn transition(fills: &[PublicFill]) -> VerifiedTransitionProof {
        let committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let proof = TransitionProof::attest(
            TransitionStatement {
                market_id: "JGB10Y-JPY".into(),
                sequence: 2,
                order_certificate_digest: h(b"order-certificate"),
                eligibility_proof_digest: h(b"eligibility-proof"),
                private_before_root: h(b"private-before"),
                private_after_root: h(b"private-after"),
                public_before_root: h(b"public-before"),
                public_after_root: h(b"public-after"),
                mpc_program_digest: h(b"mpc-program"),
                mpc_output_digest: h(b"mpc-output"),
                fill_digest: public_fills_digest(fills),
            },
            &committee.transition_signers(),
            committee.policy(),
        )
        .unwrap();
        proof
            .into_verified(&committee.verifying_keys(), committee.policy())
            .unwrap()
    }

    #[test]
    fn prepared_batch_is_opaque_and_binds_net_account_changes() {
        let mut engine = SettlementEngine::new(&mut OsRng).unwrap();
        let (seller, buyer) = engine.demo_participant_handles();
        let maker = order(Side::Sell, 100, 60, seller, 31);
        let taker = order(Side::Buy, 101, 40, buyer, 41);
        engine
            .bind_eligible_participant(seller, maker.dekyx_nullifier())
            .unwrap();
        engine
            .bind_eligible_participant(buyer, taker.dekyx_nullifier())
            .unwrap();
        engine.reserve_order(&maker).unwrap();
        engine.reserve_order(&taker).unwrap();
        let before = engine.state_snapshot();
        let fills = [PublicFill {
            maker_order: maker.commitment(),
            taker_order: taker.commitment(),
            price: 100,
            quantity: 40,
        }];
        let prepared = PreparedCanonicalTransition::Settlement(
            engine
                .prepare_canonical_batch(&fills, &transition(&fills), &taker, 0, 1_900_000_000)
                .unwrap(),
        );
        assert_eq!(engine.state_snapshot(), before);
        assert_eq!(prepared.account_deltas().len(), 5);
        assert_ne!(prepared.binding_digest(), [0; 32]);
        assert_ne!(prepared.payment_instruction_digest(), [0; 32]);
        assert_ne!(prepared.proof_digest(), [0; 32]);
    }

    #[test]
    fn canonical_order_uses_current_account_sequences_and_exact_digests() {
        let mut engine = SettlementEngine::new(&mut OsRng).unwrap();
        let (seller, buyer) = engine.demo_participant_handles();
        let maker = order(Side::Sell, 100, 60, seller, 51);
        let taker = order(Side::Buy, 101, 40, buyer, 61);
        engine
            .bind_eligible_participant(seller, maker.dekyx_nullifier())
            .unwrap();
        engine
            .bind_eligible_participant(buyer, taker.dekyx_nullifier())
            .unwrap();
        engine.reserve_order(&maker).unwrap();
        engine.reserve_order(&taker).unwrap();
        let fills = [PublicFill {
            maker_order: maker.commitment(),
            taker_order: taker.commitment(),
            price: 100,
            quantity: 40,
        }];
        let prepared = PreparedCanonicalTransition::Settlement(
            engine
                .prepare_canonical_batch(&fills, &transition(&fills), &taker, 0, 1_900_000_000)
                .unwrap(),
        );

        let root =
            std::env::temp_dir().join(format!("oclob-avalanche-unit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let keys = (0_u8..7)
            .map(|node| {
                (
                    format!("node-{node}"),
                    qomm_defmi::governance::GovernanceSigner::generate(
                        &format!("node-{node}"),
                        0,
                        i64::MAX as u64,
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let nodes = keys
            .iter()
            .map(|(name, key)| (name.clone(), key.verifying_key()))
            .collect();
        let facility = DefmiFacility::open(
            root.join("projection.sqlite3"),
            QuorumAuthorizer::new(nodes, 3, 1, "unit-chain").unwrap(),
            SigningKey::from_bytes(&[99; 32]),
        )
        .unwrap();
        for asset in asset_definitions(prepared.market_id()) {
            let before = facility.state_root().unwrap();
            let approval = facility
                .authorizer
                .approve(asset.statement().unwrap(), before, &keys)
                .unwrap();
            facility.register_asset(&asset, &approval).unwrap();
        }
        for account in prepared.account_openings() {
            let opening = account_opening(*account, prepared.application_binding());
            let before = facility.state_root().unwrap();
            let approval = facility
                .authorizer
                .approve(opening.statement().unwrap(), before, &keys)
                .unwrap();
            facility.open_account(&opening, &approval).unwrap();
        }
        let canonical = build_settlement_order(&facility, &prepared).unwrap();
        assert_eq!(canonical.legs.len(), 5);
        assert!(canonical.legs.iter().all(|leg| leg.before_sequence == 0));
        assert_eq!(
            canonical.payment_instruction_digest,
            prepared.payment_instruction_digest()
        );
        assert_eq!(canonical.proof_digest, prepared.proof_digest());
        assert_eq!(
            canonical.market_statement_digest,
            prepared.transition_digest()
        );
        drop(facility);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepared_candidate_rejects_wrong_application_binding() {
        let mut engine = SettlementEngine::new(&mut OsRng).unwrap();
        let (seller, buyer) = engine.demo_participant_handles();
        let maker = order(Side::Sell, 100, 60, seller, 71);
        let taker = order(Side::Buy, 101, 40, buyer, 81);
        engine
            .bind_eligible_participant(seller, maker.dekyx_nullifier())
            .unwrap();
        engine
            .bind_eligible_participant(buyer, taker.dekyx_nullifier())
            .unwrap();
        engine.reserve_order(&maker).unwrap();
        engine.reserve_order(&taker).unwrap();
        let before = engine.state_snapshot();
        let fills = [PublicFill {
            maker_order: maker.commitment(),
            taker_order: taker.commitment(),
            price: 100,
            quantity: 40,
        }];
        let prepared = PreparedCanonicalTransition::Settlement(
            engine
                .prepare_canonical_batch(&fills, &transition(&fills), &taker, 0, 1_900_000_000)
                .unwrap(),
        );
        let acceptance = CanonicalSettlementAcceptance {
            transaction_id: "tx".into(),
            block_id: "block".into(),
            height: 1,
            statement: h(b"statement"),
            before_state_root: h(b"before"),
            after_state_root: h(b"after"),
            receipt_digest: h(b"receipt"),
            application_binding: h(b"wrong-app"),
            binding_digest: h(b"wrong-binding"),
        };
        assert!(prepared.accept(&mut engine, acceptance).is_err());
        assert_eq!(engine.state_snapshot(), before);
    }

    #[test]
    fn operation_identifiers_are_application_bound() {
        let first = digest(b"OCLOB:DEFMI:SETTLEMENT-OPERATION:v1", &[1; 32]);
        let second = digest(b"OCLOB:DEFMI:SETTLEMENT-OPERATION:v1", &[2; 32]);
        assert_ne!(first, second);
        assert_ne!(first, OrderCommitment([1; 32]).0);
    }
}
