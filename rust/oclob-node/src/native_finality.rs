//! Node-owned canonical observation. No caller-supplied endpoint, receipt or
//! `verified` flag can advance a native private book. This trusts the configured
//! DeFMI read service; it is not a validator light-client proof.

use crate::executor::{NodeExecutionReceipt, ProofSlotMetadata};
use crate::{NodeError, NodeShareStore, PrivateStateFinality};
use oclob_core::Digest32;
use oclob_settlement::native::{
    NativeFillAuthorizationRequest, NativeFillVerifier, NativeReservationTrust,
};
use oclob_settlement::pretrade::PrivateAdmissionClient;
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::application_settlement::ApplicationNoteFillBatch;
use qomm_defmi::avalanche::{AcceptedTransition, AvalancheClient};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFinalityRequest {
    pub authorization: NativeFillAuthorizationRequest,
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<ApplicationNoteFillBatch>,
}

/// The handle can be cloned into the proof listener but has no public method
/// for inserting a purported canonical record.
#[derive(Clone)]
pub struct NativeFinalityHandle {
    store: Arc<Mutex<NodeShareStore>>,
}

impl NativeFinalityHandle {
    pub(crate) fn matched_slots(
        &self,
        round: Digest32,
        output: Digest32,
    ) -> Result<Vec<usize>, String> {
        let receipt = self
            .store
            .lock()
            .map_err(|_| "node store lock is poisoned")?
            .completed_round(round)
            .ok_or("node has not completed the native round")?;
        if receipt.public_output_sha256 != output {
            return Err("native request has another completed output".into());
        }
        Ok(receipt
            .result
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.matched)
            .map(|(index, _)| index)
            .collect())
    }

    pub(crate) fn new(store: Arc<Mutex<NodeShareStore>>) -> Self {
        Self { store }
    }

    pub(crate) fn record(
        &self,
        verified: VerifiedNativeFinality,
    ) -> Result<NativeFinalityRecord, String> {
        let record = verified.0;
        self.store
            .lock()
            .map_err(|_| "node store lock is poisoned")?
            .record_native_finality(record.clone())
            .map_err(|e| e.to_string())?;
        Ok(record)
    }
}

/// Only this module's actual configured read path can construct this token.
pub(crate) struct VerifiedNativeFinality(NativeFinalityRecord);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFinalityRecord {
    pub round_id: Digest32,
    pub slot: u16,
    pub public_output_sha256: Digest32,
    pub maker_order: Digest32,
    pub taker_order: Digest32,
    pub transaction_id: String,
    pub block_id: String,
    pub height: u64,
    pub statement: Digest32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_statement: Option<Digest32>,
    pub before_root: Digest32,
    pub after_root: Digest32,
}

impl NativeFinalityRecord {
    pub(crate) fn validate(&self, receipt: &NodeExecutionReceipt) -> Result<(), String> {
        if self.round_id != receipt.round_id
            || self.public_output_sha256 != receipt.public_output_sha256
            || !receipt
                .result
                .slots
                .get(usize::from(self.slot))
                .is_some_and(|s| s.matched)
            || self.maker_order == [0; 32]
            || self.taker_order == [0; 32]
            || self.maker_order == self.taker_order
            || self.transaction_id.is_empty()
            || self.transaction_id.len() > 128
            || self.block_id.is_empty()
            || self.block_id.len() > 128
            || self.height == 0
            || self.statement == [0; 32]
            || self.batch_statement == Some([0; 32])
            || self.before_root == [0; 32]
            || self.after_root == [0; 32]
            || self.before_root == self.after_root
        {
            return Err(
                "canonical observation is incomplete or names another executed slot".into(),
            );
        }
        Ok(())
    }
}

pub(crate) fn observe(
    client: &PrivateAdmissionClient,
    trust: &NativeReservationTrust,
    request: &NativeFinalityRequest,
    metadata: &ProofSlotMetadata,
    matched_slots: &[usize],
) -> Result<VerifiedNativeFinality, String> {
    let authorization = &request.authorization;
    let fill = &authorization.fill;
    let execution = metadata
        .native_fill
        .as_ref()
        .ok_or("no native executed pair at this slot")?;
    if request.transaction_id.is_empty()
        || request.transaction_id.len() > 128
        || authorization.round_id != metadata.round_id
        || authorization.slot != usize::from(metadata.slot)
        || fill.mpc_result_digest != metadata.public_output_sha256
    {
        return Err("native finality request differs from this node's signed execution".into());
    }
    // Lazily connects using this node's own mTLS identity and configured peer.
    let scope: ApplicationReserveScope =
        serde_json::from_value(client.call("scope", json!({}))?)
            .map_err(|_| "configured DeFMI returned a malformed application scope")?;
    if scope != fill.scope || scope.venue_id != trust.venue_id || scope.defmi_id != trust.defmi_id {
        return Err("canonical finality scope differs from the configured deployment".into());
    }
    let accepted = client.chain()?.wait_accepted(
        &request.transaction_id,
        Duration::from_secs(10),
        Duration::from_millis(100),
    )?;
    let batch_statement = match (&fill.batch, &request.batch) {
        (None, None) => None,
        (Some(binding), Some(batch)) => {
            let statement = batch.statement()?;
            if batch.fills.get(usize::from(binding.index)) != Some(fill) {
                return Err("confirmed batch does not contain this exact signed fill".into());
            }
            Some(statement)
        }
        _ => return Err("native finality is missing the complete signed group".into()),
    };
    validate_accepted(
        &request.transaction_id,
        batch_statement.unwrap_or(fill.signing_message()?),
        fill.before_root,
        &accepted,
    )?;
    // Receipt RPC has no block timestamp. Verify all cryptography at the
    // signed deadline (an in-range anchor), NOT at today's wall clock: a valid
    // old settlement must remain recoverable. Actual execution time is checked
    // by the canonical VM, whose exact statement was just observed above.
    let deadline = qomm_zkpi::wire::decode(&fill.instruction)
        .map_err(|e| e.to_string())?
        .deadline;
    if deadline == 0 {
        return Err("native instruction has no validity interval".into());
    }
    fill.verify(&scope, deadline)?;
    NativeFillVerifier {
        request: authorization,
        execution,
        trust,
        matched_slots,
        now: deadline,
    }
    .verify_finalized_execution()?;
    Ok(VerifiedNativeFinality(NativeFinalityRecord {
        round_id: metadata.round_id,
        slot: metadata.slot,
        public_output_sha256: metadata.public_output_sha256,
        maker_order: execution.maker.order_commitment,
        taker_order: execution.taker.order_commitment,
        transaction_id: accepted.tx_id,
        block_id: accepted.block_id,
        height: accepted.height,
        statement: fill.signing_message()?,
        batch_statement,
        before_root: accepted.before_root,
        after_root: accepted.after_root,
    }))
}

// Matches the pinned AvalancheNoteBridge receipt invariants. Do not require
// current state_root == after_root: unrelated later transactions are legal.
fn validate_accepted(
    tx: &str,
    statement: Digest32,
    before: Digest32,
    accepted: &AcceptedTransition,
) -> Result<(), String> {
    if tx.is_empty()
        || accepted.tx_id != tx
        || accepted.statement != statement
        || statement == [0; 32]
        || accepted.before_root != before
        || before == [0; 32]
        || accepted.after_root == [0; 32]
        || accepted.after_root == before
        || accepted.height == 0
        || accepted.block_id.is_empty()
        || accepted.block_id.len() > 128
    {
        return Err("configured DeFMI has not confirmed this exact native fill".into());
    }
    Ok(())
}

/// Canonical ordered aggregation shared by the node's gate and the client.
/// One fill retains the existing wire convention; multiple fills bind every
/// slot, accepted statement/root/block and height in sorted slot order.
pub fn aggregate_finality(
    records: &BTreeMap<u16, NativeFinalityRecord>,
) -> Result<PrivateStateFinality, String> {
    let first = records.values().next().ok_or("no confirmed native fills")?;
    if let Some(statement) = first.batch_statement {
        let mut individual = std::collections::BTreeSet::new();
        for (slot, record) in records {
            if *slot != record.slot
                || record.round_id != first.round_id
                || record.public_output_sha256 != first.public_output_sha256
                || record.batch_statement != Some(statement)
                || statement == [0; 32]
                || record.transaction_id != first.transaction_id
                || record.block_id != first.block_id
                || record.height != first.height
                || record.before_root != first.before_root
                || record.after_root != first.after_root
                || !individual.insert(record.statement)
            {
                return Err("native observations do not belong to one atomic group".into());
            }
        }
        return Ok(PrivateStateFinality {
            round_id: first.round_id,
            public_output_sha256: first.public_output_sha256,
            transition_digest: statement,
            canonical_receipt_digest: statement,
            canonical_height: first.height,
        });
    }
    let mut hash = Sha256::new()
        .chain_update(b"OCLOB:NATIVE-ROUND-FINALITY:v1")
        .chain_update((records.len() as u16).to_be_bytes());
    let mut height = 0;
    let mut transactions = std::collections::BTreeSet::new();
    for (slot, record) in records {
        if *slot != record.slot
            || record.round_id != first.round_id
            || record.public_output_sha256 != first.public_output_sha256
            || record.batch_statement.is_some()
            || !transactions.insert(&record.transaction_id)
        {
            return Err(
                "native round finality contains another round or duplicate transaction".into(),
            );
        }
        hash.update(serde_json::to_vec(record).map_err(|e| e.to_string())?);
        height = height.max(record.height);
    }
    let digest = if records.len() == 1 {
        first.statement
    } else {
        hash.finalize().into()
    };
    Ok(PrivateStateFinality {
        round_id: first.round_id,
        public_output_sha256: first.public_output_sha256,
        transition_digest: digest,
        canonical_receipt_digest: digest,
        canonical_height: height,
    })
}

pub(crate) fn require_complete(
    receipt: &NodeExecutionReceipt,
    records: &BTreeMap<u16, NativeFinalityRecord>,
    finality: &PrivateStateFinality,
) -> Result<(), NodeError> {
    let slots = receipt
        .result
        .slots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.matched)
        .map(|(i, _)| i as u16)
        .collect::<Vec<_>>();
    if slots.is_empty() || records.keys().copied().collect::<Vec<_>>() != slots {
        return Err(NodeError::PrivateState(
            "not every matched slot has node-observed canonical finality".into(),
        ));
    }
    for record in records.values() {
        record.validate(receipt).map_err(NodeError::PrivateState)?;
    }
    if &aggregate_finality(records).map_err(NodeError::PrivateState)? != finality {
        return Err(NodeError::PrivateState(
            "coordinator finality differs from node-observed canonical transactions".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn fixture(
        slots: &[usize],
    ) -> (NodeExecutionReceipt, BTreeMap<u16, NativeFinalityRecord>) {
        let mut result = oclob_core::MpcBatchResult {
            slots: vec![
                oclob_core::MpcSlotResult {
                    matched: false,
                    trade_price: 0,
                    trade_quantity: 0
                };
                oclob_core::MAX_MATCH_SLOTS
            ],
            arriving_remaining: 0,
        };
        for &slot in slots {
            result.slots[slot] = oclob_core::MpcSlotResult {
                matched: true,
                trade_price: 100,
                trade_quantity: 1,
            };
        }
        let receipt = NodeExecutionReceipt {
            version: 1,
            party: 0,
            round_id: [1; 32],
            generation: 0,
            round_commitment: [2; 32],
            program_sha256: [3; 32],
            artifact_sha256: [4; 32],
            private_parent_digest: [5; 32],
            private_state_sha256: [6; 32],
            public_output_sha256: oclob_mpc::public_output_digest(&result),
            result,
            execution_ms: 1,
            signer: [7; 32],
            signature: vec![8; 64],
        };
        let records = slots
            .iter()
            .map(|&slot| {
                (
                    slot as u16,
                    NativeFinalityRecord {
                        round_id: receipt.round_id,
                        slot: slot as u16,
                        public_output_sha256: receipt.public_output_sha256,
                        maker_order: [slot as u8 + 9; 32],
                        taker_order: [20; 32],
                        transaction_id: format!("tx-{slot}"),
                        block_id: format!("block-{slot}"),
                        height: slot as u64 + 1,
                        statement: [slot as u8 + 30; 32],
                        batch_statement: None,
                        before_root: [slot as u8 + 40; 32],
                        after_root: [slot as u8 + 41; 32],
                    },
                )
            })
            .collect();
        (receipt, records)
    }

    #[test]
    fn every_matched_slot_is_required_and_coordinator_digest_cannot_replace_it() {
        // Synthetic deterministic gate fixture, not a real multiple-fill run.
        let (receipt, records) = fixture(&[0, 2]);
        let expected = aggregate_finality(&records).unwrap();
        assert!(require_complete(&receipt, &records, &expected).is_ok());
        let partial = BTreeMap::from([(0, records[&0].clone())]);
        assert!(
            require_complete(&receipt, &partial, &aggregate_finality(&partial).unwrap()).is_err()
        );
        assert!(require_complete(&receipt, &BTreeMap::new(), &expected).is_err());
        let mut forged = expected.clone();
        forged.transition_digest[0] ^= 1;
        assert!(require_complete(&receipt, &records, &forged).is_err());
        forged = expected.clone();
        forged.canonical_height += 1;
        assert!(require_complete(&receipt, &records, &forged).is_err());
        let mut duplicate = records.clone();
        duplicate.get_mut(&2).unwrap().transaction_id = records[&0].transaction_id.clone();
        assert!(aggregate_finality(&duplicate).is_err());
        let mut other_round = records.clone();
        other_round.get_mut(&2).unwrap().round_id[0] ^= 1;
        assert!(aggregate_finality(&other_round).is_err());
        let mut unexecuted = records;
        let mut extra = unexecuted[&0].clone();
        extra.slot = 1;
        unexecuted.insert(1, extra);
        assert!(require_complete(&receipt, &unexecuted, &expected).is_err());
    }

    #[test]
    fn observation_persists_exactly_and_conflicting_retry_does_not_modify_store() {
        let directory =
            std::env::temp_dir().join(format!("oclob-finality-unit-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("shares.bin");
        let key = oclob_edge::NodeDecryptionKey::generate().unwrap();
        let (receipt, records) = fixture(&[0, 2]);
        let mut store = NodeShareStore::open(&path, 0, key.clone()).unwrap();
        store.record_completed_round(receipt.clone()).unwrap();
        store.record_native_finality(records[&0].clone()).unwrap();
        let once = store.status().unwrap();
        store.record_native_finality(records[&0].clone()).unwrap();
        assert_eq!(once, store.status().unwrap());
        let mut conflicting = records[&0].clone();
        conflicting.statement[0] ^= 1;
        assert!(store.record_native_finality(conflicting).is_err());
        assert_eq!(once, store.status().unwrap());
        drop(store);
        let mut reopened = NodeShareStore::open(&path, 0, key).unwrap();
        assert_eq!(once, reopened.status().unwrap());
        let round = hex::encode(receipt.round_id);
        assert!(require_complete(
            &receipt,
            &reopened.state.native_finalities[&round],
            &aggregate_finality(&records).unwrap()
        )
        .is_err());
        reopened
            .record_native_finality(records[&2].clone())
            .unwrap();
        assert_eq!(reopened.state.native_finalities[&round], records);
        assert!(require_complete(
            &receipt,
            &reopened.state.native_finalities[&round],
            &aggregate_finality(&records).unwrap()
        )
        .is_ok());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn finalization_schema_cannot_default_missing_native_requirement_to_legacy() {
        let mut value = serde_json::to_value(crate::PrivateRoundFinalization {
            native_finality_required: true,
            public_output_sha256: [1; 32],
            transition_digest: [2; 32],
            canonical_receipt_digest: [2; 32],
            canonical_height: 1,
        })
        .unwrap();
        assert!(serde_json::from_value::<crate::PrivateRoundFinalization>(value.clone()).is_ok());
        value
            .as_object_mut()
            .unwrap()
            .remove("native_finality_required");
        assert!(serde_json::from_value::<crate::PrivateRoundFinalization>(value).is_err());
    }

    #[test]
    fn v7_finalized_private_state_is_not_silently_promoted_to_observed_finality() {
        let directory = std::env::temp_dir().join(format!(
            "oclob-finality-migration-unit-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("shares.bin");
        let key = oclob_edge::NodeDecryptionKey::generate().unwrap();
        let mut store = NodeShareStore::open(&path, 0, key.clone()).unwrap();
        store.state.version = 7;
        store.persist().unwrap();
        let migrated = NodeShareStore::open(&path, 0, key.clone()).unwrap();
        assert_eq!(migrated.state.version, 8);
        drop(migrated);
        store.state.finalized_private_rounds.insert(
            hex::encode([1; 32]),
            crate::PrivateRoundFinalization {
                native_finality_required: false,
                public_output_sha256: [2; 32],
                transition_digest: [3; 32],
                canonical_receipt_digest: [4; 32],
                canonical_height: 1,
            },
        );
        store.persist().unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(NodeShareStore::open(&path, 0, key).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn accepted_receipt_requires_exact_statement_transaction_parent_and_nonempty_block() {
        let accepted = AcceptedTransition {
            tx_id: "tx".into(),
            block_id: "block".into(),
            height: 1,
            statement: [1; 32],
            before_root: [2; 32],
            after_root: [3; 32],
        };
        assert!(validate_accepted("tx", [1; 32], [2; 32], &accepted).is_ok());
        assert!(validate_accepted("other", [1; 32], [2; 32], &accepted).is_err());
        assert!(validate_accepted("tx", [4; 32], [2; 32], &accepted).is_err());
        assert!(validate_accepted("tx", [1; 32], [4; 32], &accepted).is_err());
        for changed in [
            AcceptedTransition {
                height: 0,
                ..accepted.clone()
            },
            AcceptedTransition {
                block_id: String::new(),
                ..accepted.clone()
            },
            AcceptedTransition {
                after_root: [2; 32],
                ..accepted.clone()
            },
            AcceptedTransition {
                after_root: [0; 32],
                ..accepted.clone()
            },
        ] {
            assert!(validate_accepted("tx", [1; 32], [2; 32], &changed).is_err());
        }
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    fn fixture() -> (NodeExecutionReceipt, BTreeMap<u16, NativeFinalityRecord>) {
        let (receipt, mut records) = super::tests::fixture(&[0, 2]);
        let first = records[&0].clone();
        for record in records.values_mut() {
            record.batch_statement = Some([90; 32]);
            record.transaction_id = first.transaction_id.clone();
            record.block_id = first.block_id.clone();
            record.height = first.height;
            record.before_root = first.before_root;
            record.after_root = first.after_root;
        }
        (receipt, records)
    }

    #[test]
    fn one_atomic_transaction_still_requires_every_executed_slot() {
        let (receipt, records) = fixture();
        let finality = aggregate_finality(&records).unwrap();
        assert_eq!(finality.transition_digest, [90; 32]);
        assert!(require_complete(&receipt, &records, &finality).is_ok());
        let partial = BTreeMap::from([(0, records[&0].clone())]);
        assert!(require_complete(&receipt, &partial, &finality).is_err());
        for change in 0..7 {
            let mut bad = records.clone();
            let record = bad.get_mut(&2).unwrap();
            match change {
                0 => record.batch_statement = None,
                1 => record.batch_statement = Some([91; 32]),
                2 => record.transaction_id.push('x'),
                3 => record.block_id.push('x'),
                4 => record.height += 1,
                5 => record.after_root[0] ^= 1,
                _ => record.statement = records[&0].statement,
            }
            assert!(aggregate_finality(&bad).is_err(), "mutation {change}");
        }
    }

    #[test]
    fn atomic_membership_survives_reopen_without_promoting_a_partial_observation() {
        let directory = std::env::temp_dir().join(format!(
            "oclob-batch-finality-unit-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("shares.bin");
        let key = oclob_edge::NodeDecryptionKey::generate().unwrap();
        let (receipt, records) = fixture();
        let finality = aggregate_finality(&records).unwrap();
        let mut store = NodeShareStore::open(&path, 0, key.clone()).unwrap();
        store.record_completed_round(receipt.clone()).unwrap();
        store.record_native_finality(records[&0].clone()).unwrap();
        let partial_status = store.status().unwrap();
        drop(store);
        let mut store = NodeShareStore::open(&path, 0, key.clone()).unwrap();
        assert_eq!(partial_status, store.status().unwrap());
        let round = hex::encode(receipt.round_id);
        assert!(
            require_complete(&receipt, &store.state.native_finalities[&round], &finality).is_err()
        );
        store.record_native_finality(records[&2].clone()).unwrap();
        let complete_status = store.status().unwrap();
        store.record_native_finality(records[&2].clone()).unwrap();
        assert_eq!(complete_status, store.status().unwrap());
        drop(store);
        let store = NodeShareStore::open(&path, 0, key).unwrap();
        assert!(
            require_complete(&receipt, &store.state.native_finalities[&round], &finality).is_ok()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
