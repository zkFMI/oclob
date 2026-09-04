//! Node-local OCLOB share custody and MP-SPDZ input preparation.
//!
//! Each instance is permanently assigned one party index and one X25519 key.
//! Its durable file contains only public manifests plus ciphertext addressed to
//! that node. Clear shares exist in memory only while verifying admission or
//! preparing one MP-SPDZ input file.

#![forbid(unsafe_code)]

pub mod edge_client;
pub mod executor;
pub mod network;

use oclob_core::{Digest32, OrderCommitment, MAX_MATCH_SLOTS};
use oclob_edge::{
    CapabilityKeyShare, EdgeOrderManifest, NodeDecryptionKey, SealedCapabilityKeyShare,
    SealedPartyShare, MPC_PARTIES,
};
use oclob_mpc::public_output_digest;
use oclob_ordering::{vote_digest, CommitteePolicy, OrderCertificate};
use qomm_mpc::persistence::{from_montgomery, read as read_persistence};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

const STORE_MAGIC: &[u8; 8] = b"OCLOBN01";
const STORE_VERSION: u16 = 5;
const LEGACY_STORE_VERSION_V4: u16 = 4;
const LEGACY_STORE_VERSION_V3: u16 = 3;
const LEGACY_STORE_VERSION_V2: u16 = 2;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredRecord {
    manifest: EdgeOrderManifest,
    sealed: SealedPartyShare,
    #[serde(default)]
    sealed_capability_key_share: Option<SealedCapabilityKeyShare>,
    admitted_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredOrderVote {
    statement_digest: Digest32,
    expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoreState {
    version: u16,
    party: u16,
    generation: u64,
    records: BTreeMap<String, StoredRecord>,
    completed_rounds: BTreeMap<String, executor::NodeExecutionReceipt>,
    ordering_sequence: u64,
    ordering_head: Digest32,
    ordering_votes: BTreeMap<u64, StoredOrderVote>,
    ordered_commitments: BTreeSet<String>,
    /// Public pointers into this node's own private Persistence files. Values
    /// and shares never enter the JSON store.
    #[serde(default)]
    private_heads: BTreeMap<String, PrivateBookStateRef>,
    #[serde(default)]
    finalized_private_rounds: BTreeMap<String, PrivateRoundFinalization>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PrivateBookStateRef {
    round_id: Digest32,
    private_state_sha256: Digest32,
    wire_offset: u16,
    transition_digest: Digest32,
    canonical_receipt_digest: Digest32,
    canonical_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PrivateRoundFinalization {
    public_output_sha256: Digest32,
    transition_digest: Digest32,
    canonical_receipt_digest: Digest32,
    canonical_height: u64,
}

#[derive(Deserialize)]
struct LegacyStoreStateV2 {
    version: u16,
    party: u16,
    generation: u64,
    records: BTreeMap<String, StoredRecord>,
    #[serde(rename = "completed_rounds")]
    _completed_rounds: BTreeMap<String, executor::NodeExecutionReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeStoreStatus {
    pub party: u16,
    pub generation: u64,
    pub record_count: usize,
    pub completed_round_count: usize,
    pub private_head_count: usize,
    pub finalized_private_round_count: usize,
    pub ordering_sequence: u64,
    pub ordering_head: Digest32,
    pub state_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngestOutcome {
    Stored { generation: u64 },
    AlreadyPresent { generation: u64 },
}

/// Public DeFMI finality binding required before a node advances its private
/// book head. The coordinator cannot use an MPC result speculatively and then
/// overwrite a later state: the exact parent and output are fixed in the
/// node's signed execution receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateStateFinality {
    pub round_id: Digest32,
    pub public_output_sha256: Digest32,
    pub transition_digest: Digest32,
    pub canonical_receipt_digest: Digest32,
    pub canonical_height: u64,
}

impl PrivateStateFinality {
    fn validate(&self) -> Result<(), NodeError> {
        if self.round_id == [0; 32]
            || self.public_output_sha256 == [0; 32]
            || self.transition_digest == [0; 32]
            || self.canonical_receipt_digest == [0; 32]
            || self.canonical_height == 0
        {
            return Err(NodeError::PrivateState(
                "canonical finality binding is incomplete".into(),
            ));
        }
        Ok(())
    }
}

/// A node-owned input file. The material intentionally has no `Debug`,
/// serialization or clear-value accessor.
pub struct PreparedPartyInput {
    party: u16,
    generation: u64,
    round_commitment: Digest32,
    private_parent_digest: Digest32,
    contents: Vec<u8>,
}

impl PreparedPartyInput {
    pub const fn party(&self) -> u16 {
        self.party
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn round_commitment(&self) -> Digest32 {
        self.round_commitment
    }

    pub const fn private_parent_digest(&self) -> Digest32 {
        self.private_parent_digest
    }

    /// Write the node-local MP-SPDZ input with owner-only permissions. The
    /// caller must delete the round directory after execution.
    pub fn write_exclusive(&self, path: impl AsRef<Path>) -> Result<(), NodeError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(NodeError::UnsafePath(
                "party input destination already exists".into(),
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&self.contents)?;
        file.sync_all()?;
        Ok(())
    }
}

pub struct NodeShareStore {
    path: PathBuf,
    key: NodeDecryptionKey,
    state: StoreState,
    private_state_root: Option<PathBuf>,
}

impl NodeShareStore {
    pub fn open(
        path: impl Into<PathBuf>,
        party: u16,
        key: NodeDecryptionKey,
    ) -> Result<Self, NodeError> {
        if usize::from(party) >= MPC_PARTIES {
            return Err(NodeError::Party);
        }
        let path = path.into();
        reject_symlink(&path)?;
        let existed = path.exists();
        let (state, migrated) = if existed {
            read_state(&path, party)?
        } else {
            (empty_state(party), false)
        };
        let mut store = Self {
            path,
            key,
            state,
            private_state_root: None,
        };
        if !existed || migrated {
            store.persist()?;
        }
        Ok(store)
    }

    pub fn status(&self) -> Result<NodeStoreStatus, NodeError> {
        Ok(NodeStoreStatus {
            party: self.state.party,
            generation: self.state.generation,
            record_count: self.state.records.len(),
            completed_round_count: self.state.completed_rounds.len(),
            private_head_count: self.state.private_heads.len(),
            finalized_private_round_count: self.state.finalized_private_rounds.len(),
            ordering_sequence: self.state.ordering_sequence,
            ordering_head: self.state.ordering_head,
            state_digest: state_digest(&self.state)?,
        })
    }

    /// Bind this store to the owner-only directory managed by its local
    /// `PartyExecutor`. The path is runtime configuration and is deliberately
    /// not serialized into the durable public-index store.
    pub(crate) fn bind_private_state_root(
        &mut self,
        root: impl Into<PathBuf>,
    ) -> Result<(), NodeError> {
        let root = root.into();
        reject_symlink(&root)?;
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        self.private_state_root = Some(root);
        Ok(())
    }

    pub fn ingest(
        &mut self,
        manifest: EdgeOrderManifest,
        sealed: SealedPartyShare,
        sealed_capability_key_share: SealedCapabilityKeyShare,
        now: u64,
    ) -> Result<IngestOutcome, NodeError> {
        sealed
            .open(&self.key, &manifest, self.state.party, now)
            .map_err(|error| NodeError::Admission(error.to_string()))?;
        sealed_capability_key_share
            .open(&self.key, &manifest, self.state.party, now)
            .map_err(|error| NodeError::Admission(error.to_string()))?;
        let key = manifest.commitment.hex();
        let incoming = StoredRecord {
            manifest,
            sealed,
            sealed_capability_key_share: Some(sealed_capability_key_share),
            admitted_at: now,
        };
        if let Some(existing) = self.state.records.get(&key) {
            return if existing.manifest == incoming.manifest
                && existing.sealed == incoming.sealed
                && existing.sealed_capability_key_share == incoming.sealed_capability_key_share
            {
                Ok(IngestOutcome::AlreadyPresent {
                    generation: self.state.generation,
                })
            } else {
                Err(NodeError::Conflict)
            };
        }
        let previous = self.state.clone();
        self.state.records.insert(key, incoming);
        self.state.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(NodeError::Generation)?;
        if let Err(error) = self.persist() {
            self.state = previous;
            return Err(error);
        }
        Ok(IngestOutcome::Stored {
            generation: self.state.generation,
        })
    }

    /// Persist one node's anti-equivocation decision before returning its
    /// ordering signature. A coordinator can retry the same statement, but it
    /// cannot obtain a second vote for the same live sequence from this node.
    pub fn record_order_vote(
        &mut self,
        market_id: &str,
        sequence: u64,
        commitment: OrderCommitment,
        previous_certificate: Digest32,
        expires_at: u64,
        now: u64,
    ) -> Result<Digest32, NodeError> {
        let expected_sequence = self
            .state
            .ordering_sequence
            .checked_add(1)
            .ok_or(NodeError::Generation)?;
        let record = self
            .state
            .records
            .get(&commitment.hex())
            .ok_or(NodeError::UnknownOrder)?;
        if market_id.is_empty()
            || market_id.len() > 64
            || sequence != expected_sequence
            || previous_certificate != self.state.ordering_head
            || now > expires_at
            || record.manifest.market_id != market_id
            || expires_at > record.manifest.retention_deadline
            || self.state.ordered_commitments.contains(&commitment.hex())
        {
            return Err(NodeError::Ordering(
                "vote does not extend the node's admitted-order chain".into(),
            ));
        }
        let statement_digest = vote_digest(
            market_id,
            sequence,
            commitment,
            previous_certificate,
            expires_at,
        );
        if let Some(existing) = self.state.ordering_votes.get(&sequence) {
            if existing.statement_digest == statement_digest {
                return Ok(statement_digest);
            }
            if now <= existing.expires_at {
                return Err(NodeError::Ordering(
                    "node refuses an equivocal vote for a live sequence".into(),
                ));
            }
        }
        let previous = self.state.clone();
        self.state.ordering_votes.insert(
            sequence,
            StoredOrderVote {
                statement_digest,
                expires_at,
            },
        );
        if let Err(error) = self.bump_generation() {
            self.state = previous;
            return Err(error);
        }
        if let Err(error) = self.persist() {
            self.state = previous;
            return Err(error);
        }
        Ok(statement_digest)
    }

    /// Accept and durably advance one complete 5-of-7 ordering certificate.
    /// The certificate is checked against pinned node keys, the local admitted
    /// order, any prior local vote, and the node's previous certificate head.
    pub fn accept_order_certificate(
        &mut self,
        certificate: &OrderCertificate,
        policy: CommitteePolicy,
        keys: &BTreeMap<u16, ed25519_dalek::VerifyingKey>,
        now: u64,
    ) -> Result<u64, NodeError> {
        certificate
            .verify(policy, keys, now)
            .map_err(|error| NodeError::Ordering(error.to_string()))?;
        let digest = certificate.digest();
        let commitment_key = certificate.commitment.hex();
        if certificate.sequence == self.state.ordering_sequence {
            return if self.state.ordering_head == digest
                && self.state.ordered_commitments.contains(&commitment_key)
            {
                Ok(self.state.generation)
            } else {
                Err(NodeError::Ordering(
                    "certificate conflicts with the accepted chain head".into(),
                ))
            };
        }
        let expected_sequence = self
            .state
            .ordering_sequence
            .checked_add(1)
            .ok_or(NodeError::Generation)?;
        let record = self
            .state
            .records
            .get(&commitment_key)
            .ok_or(NodeError::UnknownOrder)?;
        let statement = vote_digest(
            &certificate.market_id,
            certificate.sequence,
            certificate.commitment,
            certificate.previous_certificate,
            certificate.expires_at,
        );
        if certificate.sequence != expected_sequence
            || certificate.previous_certificate != self.state.ordering_head
            || record.manifest.market_id != certificate.market_id
            || certificate.expires_at > record.manifest.retention_deadline
            || self.state.ordered_commitments.contains(&commitment_key)
            || self
                .state
                .ordering_votes
                .get(&certificate.sequence)
                .is_some_and(|vote| vote.statement_digest != statement && now <= vote.expires_at)
        {
            return Err(NodeError::Ordering(
                "certificate does not extend the node's accepted chain".into(),
            ));
        }
        let previous = self.state.clone();
        self.state.ordering_sequence = certificate.sequence;
        self.state.ordering_head = digest;
        self.state.ordered_commitments.insert(commitment_key);
        self.state.ordering_votes.remove(&certificate.sequence);
        if let Err(error) = self.bump_generation() {
            self.state = previous;
            return Err(error);
        }
        if let Err(error) = self.persist() {
            self.state = previous;
            return Err(error);
        }
        Ok(self.state.generation)
    }

    /// Assemble the fixed OCLOB matching frame from commitments only. Resting
    /// sequence is public; side, price, quantity and participant identity are
    /// never supplied by the coordinator.
    pub fn prepare_round(
        &self,
        market_id: &str,
        resting: &[OrderCommitment],
        arriving: OrderCommitment,
        now: u64,
    ) -> Result<PreparedPartyInput, NodeError> {
        let mut unique = resting.to_vec();
        unique.sort_unstable();
        unique.dedup();
        if market_id.is_empty()
            || market_id.len() > 64
            || resting.len() > MAX_MATCH_SLOTS
            || resting.contains(&arriving)
            || unique.len() != resting.len()
        {
            return Err(NodeError::Round(
                "round market or order commitments are invalid".into(),
            ));
        }
        let arriving_share = self.open_record(arriving, market_id, now)?;
        let arriving_values = arriving_share.value_share_decimals();
        let mut fields = Vec::with_capacity(MAX_MATCH_SLOTS * 4 + 4);
        for slot in 0..MAX_MATCH_SLOTS {
            if let Some(commitment) = resting.get(slot) {
                fields.extend(self.private_match_fields(*commitment, market_id, now)?);
            } else {
                fields.extend([
                    "0".to_owned(),
                    "0".to_owned(),
                    "0".to_owned(),
                    "0".to_owned(),
                ]);
            }
        }
        fields.extend([
            arriving_values[0].clone(),
            arriving_values[1].clone(),
            arriving_values[2].clone(),
            arriving_values[5].clone(),
        ]);
        debug_assert_eq!(fields.len(), MAX_MATCH_SLOTS * 4 + 4);
        let mut contents = fields.join(" ").into_bytes();
        contents.push(b'\n');
        let round_commitment = round_commitment(
            self.state.party,
            self.state.generation,
            resting,
            arriving,
            &contents,
        );
        let private_parent_digest = self.private_parent_digest(resting, arriving);
        Ok(PreparedPartyInput {
            party: self.state.party,
            generation: self.state.generation,
            round_commitment,
            private_parent_digest,
            contents,
        })
    }

    pub fn remove_terminal(&mut self, commitment: OrderCommitment) -> Result<bool, NodeError> {
        let key = commitment.hex();
        if !self.state.records.contains_key(&key) {
            return Ok(false);
        }
        let previous = self.state.clone();
        self.state.records.remove(&key);
        self.state.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(NodeError::Generation)?;
        if let Err(error) = self.persist() {
            self.state = previous;
            return Err(error);
        }
        Ok(true)
    }

    pub fn completed_round(&self, round_id: Digest32) -> Option<executor::NodeExecutionReceipt> {
        self.state
            .completed_rounds
            .get(&hex::encode(round_id))
            .cloned()
    }

    /// Persist the signed public receipt before acknowledging the coordinator.
    /// Retrying the same round returns the byte-identical receipt and cannot
    /// cause a second MPC execution.
    pub(crate) fn record_completed_round(
        &mut self,
        receipt: executor::NodeExecutionReceipt,
    ) -> Result<(), NodeError> {
        if receipt.party != self.state.party
            || receipt.round_id == [0; 32]
            || receipt.round_commitment == [0; 32]
            || receipt.program_sha256 == [0; 32]
            || receipt.artifact_sha256 == [0; 32]
            || receipt.private_parent_digest == [0; 32]
            || receipt.private_state_sha256 == [0; 32]
            || receipt.result.slots.len() != MAX_MATCH_SLOTS
            || receipt.public_output_sha256 != public_output_digest(&receipt.result)
            || receipt.signer == [0; 32]
            || receipt.signature.len() != 64
        {
            return Err(NodeError::Round(
                "execution receipt is not a complete party result".into(),
            ));
        }
        let key = hex::encode(receipt.round_id);
        if let Some(existing) = self.state.completed_rounds.get(&key) {
            return if existing == &receipt {
                Ok(())
            } else {
                Err(NodeError::Conflict)
            };
        }
        let previous = self.state.clone();
        self.state.completed_rounds.insert(key, receipt);
        self.state.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(NodeError::Generation)?;
        if let Err(error) = self.persist() {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Advance every order's node-local secret-share head only after the exact
    /// MPC output has canonical DeFMI finality. No order field or share is
    /// supplied by the settlement coordinator.
    pub(crate) fn finalize_private_round(
        &mut self,
        plan: &executor::RoundPlan,
        finality: &PrivateStateFinality,
    ) -> Result<u64, NodeError> {
        finality.validate()?;
        if finality.round_id != plan.round_id {
            return Err(NodeError::PrivateState(
                "finality refers to another MPC round".into(),
            ));
        }
        let receipt = self
            .completed_round(plan.round_id)
            .ok_or_else(|| NodeError::PrivateState("MPC round is not complete".into()))?;
        if receipt.public_output_sha256 != finality.public_output_sha256 {
            return Err(NodeError::PrivateState(
                "canonical finality does not bind this MPC output".into(),
            ));
        }
        let key = hex::encode(plan.round_id);
        let candidate = PrivateRoundFinalization {
            public_output_sha256: finality.public_output_sha256,
            transition_digest: finality.transition_digest,
            canonical_receipt_digest: finality.canonical_receipt_digest,
            canonical_height: finality.canonical_height,
        };
        if let Some(existing) = self.state.finalized_private_rounds.get(&key) {
            return if existing == &candidate {
                Ok(self.state.generation)
            } else {
                Err(NodeError::Conflict)
            };
        }
        if receipt.private_parent_digest != self.private_parent_digest(&plan.resting, plan.arriving)
        {
            return Err(NodeError::PrivateState(
                "private book parent advanced before this round finalized".into(),
            ));
        }
        self.verify_private_state_file(plan.round_id, receipt.private_state_sha256)?;

        let previous = self.state.clone();
        for (slot, commitment) in plan.resting.iter().enumerate() {
            self.state.private_heads.insert(
                commitment.hex(),
                PrivateBookStateRef {
                    round_id: plan.round_id,
                    private_state_sha256: receipt.private_state_sha256,
                    wire_offset: u16::try_from(slot * 4).map_err(|_| {
                        NodeError::PrivateState("private wire offset overflowed".into())
                    })?,
                    transition_digest: finality.transition_digest,
                    canonical_receipt_digest: finality.canonical_receipt_digest,
                    canonical_height: finality.canonical_height,
                },
            );
        }
        if receipt.result.arriving_remaining > 0 {
            self.state.private_heads.insert(
                plan.arriving.hex(),
                PrivateBookStateRef {
                    round_id: plan.round_id,
                    private_state_sha256: receipt.private_state_sha256,
                    wire_offset: u16::try_from(MAX_MATCH_SLOTS * 4).map_err(|_| {
                        NodeError::PrivateState("private wire offset overflowed".into())
                    })?,
                    transition_digest: finality.transition_digest,
                    canonical_receipt_digest: finality.canonical_receipt_digest,
                    canonical_height: finality.canonical_height,
                },
            );
        } else {
            self.state.private_heads.remove(&plan.arriving.hex());
        }
        self.state.finalized_private_rounds.insert(key, candidate);
        if let Err(error) = self.bump_generation().and_then(|_| self.persist()) {
            self.state = previous;
            return Err(error);
        }
        Ok(self.state.generation)
    }

    /// Open this node's capability-key share only after the exact signed round
    /// has completed and its public result authorizes settlement or book entry
    /// for the requested order. An unmatched IOC is deliberately not released.
    pub(crate) fn release_capability_key_share(
        &self,
        plan: &executor::RoundPlan,
        order_commitment: OrderCommitment,
        now: u64,
    ) -> Result<(CapabilityKeyShare, Digest32), NodeError> {
        let receipt = self
            .completed_round(plan.round_id)
            .ok_or_else(|| NodeError::Release("matching round is not complete".into()))?;
        let authorized = if order_commitment == plan.arriving {
            receipt.result.arriving_remaining > 0
                || receipt.result.slots.iter().any(|slot| slot.matched)
        } else {
            plan.resting
                .iter()
                .position(|commitment| *commitment == order_commitment)
                .and_then(|position| receipt.result.slots.get(position))
                .is_some_and(|slot| slot.matched)
        };
        if !authorized {
            return Err(NodeError::Release(
                "public MPC result does not authorize capability release".into(),
            ));
        }
        let record = self
            .state
            .records
            .get(&order_commitment.hex())
            .ok_or(NodeError::UnknownOrder)?;
        let sealed = record
            .sealed_capability_key_share
            .as_ref()
            .ok_or_else(|| NodeError::Release("legacy order has no capability-key share".into()))?;
        let share = sealed
            .open(&self.key, &record.manifest, self.state.party, now)
            .map_err(|error| NodeError::Release(error.to_string()))?;
        Ok((share, receipt.public_output_sha256))
    }

    pub fn prune_expired(&mut self, now: u64) -> Result<usize, NodeError> {
        let expired = self
            .state
            .records
            .iter()
            .filter_map(|(key, record)| {
                (record.manifest.retention_deadline < now).then_some(key.clone())
            })
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return Ok(0);
        }
        let previous = self.state.clone();
        for key in &expired {
            self.state.records.remove(key);
        }
        self.state.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(NodeError::Generation)?;
        if let Err(error) = self.persist() {
            self.state = previous;
            return Err(error);
        }
        Ok(expired.len())
    }

    fn open_record(
        &self,
        commitment: OrderCommitment,
        market_id: &str,
        now: u64,
    ) -> Result<oclob_edge::PartyOrderShare, NodeError> {
        let record = self
            .state
            .records
            .get(&commitment.hex())
            .ok_or(NodeError::UnknownOrder)?;
        if record.manifest.market_id != market_id {
            return Err(NodeError::Round(
                "round market differs from the committed order market".into(),
            ));
        }
        record
            .sealed
            .open(&self.key, &record.manifest, self.state.party, now)
            .map_err(|error| NodeError::Admission(error.to_string()))
    }

    fn private_match_fields(
        &self,
        commitment: OrderCommitment,
        market_id: &str,
        now: u64,
    ) -> Result<[String; 4], NodeError> {
        let share = self.open_record(commitment, market_id, now)?;
        let original = share.value_share_decimals();
        let Some(head) = self.state.private_heads.get(&commitment.hex()) else {
            return Ok([
                "1".to_owned(),
                original[0].clone(),
                original[1].clone(),
                original[2].clone(),
            ]);
        };
        let root = self
            .private_state_root
            .as_ref()
            .ok_or_else(|| NodeError::PrivateState("private state root is not bound".into()))?;
        let path = root
            .join(hex::encode(head.round_id))
            .join(format!("Transactions-P{}.data", self.state.party));
        self.verify_private_state_file(head.round_id, head.private_state_sha256)?;
        let file = read_persistence(&path, usize::from(self.state.party))
            .map_err(|error| NodeError::PrivateState(error.to_string()))?;
        let start = usize::from(head.wire_offset);
        let end = start
            .checked_add(4)
            .filter(|end| *end <= file.shares.len())
            .ok_or_else(|| {
                NodeError::PrivateState("private state wire offset is invalid".into())
            })?;
        let mut decoded = Vec::with_capacity(4);
        for stored in &file.shares[start..end] {
            let value = if file.montgomery {
                from_montgomery(stored, &file.prime, file.element_bytes)
                    .map_err(|error| NodeError::PrivateState(error.to_string()))?
            } else {
                stored.clone()
            };
            decoded.push(value.to_string());
        }
        decoded
            .try_into()
            .map_err(|_| NodeError::PrivateState("private state wire count is invalid".into()))
    }

    fn verify_private_state_file(
        &self,
        round_id: Digest32,
        expected_digest: Digest32,
    ) -> Result<(), NodeError> {
        let root = self
            .private_state_root
            .as_ref()
            .ok_or_else(|| NodeError::PrivateState("private state root is not bound".into()))?;
        let path = root
            .join(hex::encode(round_id))
            .join(format!("Transactions-P{}.data", self.state.party));
        reject_symlink(&path)?;
        let metadata = fs::metadata(&path)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 16 * 1024 * 1024 {
            return Err(NodeError::PrivateState(
                "party-local private state file has an unsafe size or type".into(),
            ));
        }
        let bytes = fs::read(&path)?;
        let digest: Digest32 = Sha256::digest(&bytes).into();
        if digest != expected_digest {
            return Err(NodeError::PrivateState(
                "party-local private state digest changed".into(),
            ));
        }
        let file = read_persistence(&path, usize::from(self.state.party))
            .map_err(|error| NodeError::PrivateState(error.to_string()))?;
        let expected = MAX_MATCH_SLOTS * 4 + 4;
        if file.shares.len() != expected {
            return Err(NodeError::PrivateState(format!(
                "private state contains {} shares; expected {expected}",
                file.shares.len()
            )));
        }
        Ok(())
    }

    fn private_parent_digest(
        &self,
        resting: &[OrderCommitment],
        arriving: OrderCommitment,
    ) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(b"OCLOB:PRIVATE-BOOK-PARENTS:v1");
        hash.update((resting.len() as u64).to_be_bytes());
        for commitment in resting {
            hash.update(commitment.0);
            if let Some(head) = self.state.private_heads.get(&commitment.hex()) {
                hash.update([1]);
                hash.update(head.round_id);
                hash.update(head.private_state_sha256);
                hash.update(head.wire_offset.to_be_bytes());
            } else {
                hash.update([0]);
            }
        }
        hash.update(arriving.0);
        hash.finalize().into()
    }

    fn persist(&mut self) -> Result<(), NodeError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        reject_symlink(&self.path)?;
        let payload =
            serde_json::to_vec(&self.state).map_err(|error| NodeError::State(error.to_string()))?;
        if payload.len() > MAX_STORE_BYTES {
            return Err(NodeError::State(
                "node share store exceeds size limit".into(),
            ));
        }
        let checksum: Digest32 = Sha256::digest(&payload).into();
        let mut encoded = Vec::with_capacity(8 + 8 + payload.len() + 32);
        encoded.extend_from_slice(STORE_MAGIC);
        encoded.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        encoded.extend_from_slice(&payload);
        encoded.extend_from_slice(&checksum);
        let temp = self.path.with_extension(format!(
            "tmp-{}-{:016x}",
            std::process::id(),
            randless_nonce(&payload)
        ));
        reject_symlink(&temp)?;
        let result = (|| -> Result<(), NodeError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
            fs::rename(&temp, &self.path)?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
            if let Some(parent) = self.path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn bump_generation(&mut self) -> Result<(), NodeError> {
        self.state.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(NodeError::Generation)?;
        Ok(())
    }
}

fn empty_state(party: u16) -> StoreState {
    StoreState {
        version: STORE_VERSION,
        party,
        generation: 0,
        records: BTreeMap::new(),
        completed_rounds: BTreeMap::new(),
        ordering_sequence: 0,
        ordering_head: [0; 32],
        ordering_votes: BTreeMap::new(),
        ordered_commitments: BTreeSet::new(),
        private_heads: BTreeMap::new(),
        finalized_private_rounds: BTreeMap::new(),
    }
}

fn read_state(path: &Path, expected_party: u16) -> Result<(StoreState, bool), NodeError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() as usize > MAX_STORE_BYTES + 48 {
        return Err(NodeError::State(
            "node share store has unsafe type or size".into(),
        ));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.read_to_end(&mut encoded)?;
    if encoded.len() < 48 || &encoded[..8] != STORE_MAGIC {
        return Err(NodeError::State(
            "node share store header is invalid".into(),
        ));
    }
    let length = u64::from_be_bytes(encoded[8..16].try_into().expect("eight-byte length"));
    let length = usize::try_from(length)
        .map_err(|_| NodeError::State("node share store length is invalid".into()))?;
    let end = 16_usize
        .checked_add(length)
        .filter(|end| end.checked_add(32) == Some(encoded.len()))
        .ok_or_else(|| NodeError::State("node share store length is invalid".into()))?;
    let expected: Digest32 = Sha256::digest(&encoded[16..end]).into();
    if encoded[end..] != expected {
        return Err(NodeError::State("node share store checksum failed".into()));
    }
    let value: serde_json::Value = serde_json::from_slice(&encoded[16..end])
        .map_err(|_| NodeError::State("node share store payload is invalid".into()))?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| NodeError::State("node share store version is invalid".into()))?;
    let (state, migrated) = match version {
        STORE_VERSION => (
            serde_json::from_value(value)
                .map_err(|_| NodeError::State("node share store payload is invalid".into()))?,
            false,
        ),
        LEGACY_STORE_VERSION_V4 => {
            let mut legacy: StoreState = serde_json::from_value(value)
                .map_err(|_| NodeError::State("legacy v4 node store payload is invalid".into()))?;
            if legacy.version != LEGACY_STORE_VERSION_V4 {
                return Err(NodeError::State(
                    "legacy v4 node store version is invalid".into(),
                ));
            }
            // V4 receipts predate durable party-local post-match state. They
            // must not authorize capability release after this migration.
            legacy.completed_rounds.clear();
            legacy.version = STORE_VERSION;
            (legacy, true)
        }
        LEGACY_STORE_VERSION_V3 => {
            let mut legacy: StoreState = serde_json::from_value(value)
                .map_err(|_| NodeError::State("legacy v3 node store payload is invalid".into()))?;
            if legacy.version != LEGACY_STORE_VERSION_V3 {
                return Err(NodeError::State(
                    "legacy v3 node store version is invalid".into(),
                ));
            }
            legacy.completed_rounds.clear();
            legacy.version = STORE_VERSION;
            (legacy, true)
        }
        LEGACY_STORE_VERSION_V2 => {
            let legacy: LegacyStoreStateV2 = serde_json::from_value(value)
                .map_err(|_| NodeError::State("legacy node store payload is invalid".into()))?;
            if legacy.version != LEGACY_STORE_VERSION_V2 {
                return Err(NodeError::State(
                    "legacy node store version is invalid".into(),
                ));
            }
            (
                StoreState {
                    version: STORE_VERSION,
                    party: legacy.party,
                    generation: legacy.generation,
                    records: legacy.records,
                    // V2 receipts have no durable party-local post-match
                    // state and cannot authorize a V5 settlement transition.
                    completed_rounds: BTreeMap::new(),
                    ordering_sequence: 0,
                    ordering_head: [0; 32],
                    ordering_votes: BTreeMap::new(),
                    ordered_commitments: BTreeSet::new(),
                    private_heads: BTreeMap::new(),
                    finalized_private_rounds: BTreeMap::new(),
                },
                true,
            )
        }
        _ => {
            return Err(NodeError::State(
                "node share store belongs to an unsupported version".into(),
            ))
        }
    };
    if state.party != expected_party
        || (state.ordering_sequence == 0) != (state.ordering_head == [0; 32])
        || u64::try_from(state.ordered_commitments.len()).ok() != Some(state.ordering_sequence)
        || state.ordering_votes.len() > 1
        || state.ordering_votes.iter().any(|(sequence, vote)| {
            *sequence != state.ordering_sequence.saturating_add(1)
                || vote.statement_digest == [0; 32]
                || vote.expires_at == 0
        })
    {
        return Err(NodeError::State(
            "node share store has an invalid party or ordering chain".into(),
        ));
    }
    for (key, record) in &state.records {
        if key != &record.manifest.commitment.hex()
            || record.manifest.commitment != record.sealed.commitment
            || record.sealed.party != expected_party
            || record
                .sealed_capability_key_share
                .as_ref()
                .is_some_and(|share| {
                    share.order_commitment != record.manifest.commitment
                        || share.capability_commitment
                            != record.manifest.settlement_capability_commitment
                        || share.party != expected_party
                })
        {
            return Err(NodeError::State(
                "node share store contains a misbound record".into(),
            ));
        }
    }
    for (key, receipt) in &state.completed_rounds {
        if key != &hex::encode(receipt.round_id)
            || receipt.party != expected_party
            || receipt.round_id == [0; 32]
            || receipt.round_commitment == [0; 32]
            || receipt.program_sha256 == [0; 32]
            || receipt.artifact_sha256 == [0; 32]
            || receipt.private_parent_digest == [0; 32]
            || receipt.private_state_sha256 == [0; 32]
            || receipt.result.slots.len() != MAX_MATCH_SLOTS
            || receipt.public_output_sha256 != public_output_digest(&receipt.result)
            || receipt.signer == [0; 32]
            || receipt.signature.len() != 64
        {
            return Err(NodeError::State(
                "node share store contains a misbound completed round".into(),
            ));
        }
    }
    for (commitment, head) in &state.private_heads {
        let round_key = hex::encode(head.round_id);
        let receipt = state.completed_rounds.get(&round_key);
        let finalization = state.finalized_private_rounds.get(&round_key);
        if !state.records.contains_key(commitment)
            || head.round_id == [0; 32]
            || head.private_state_sha256 == [0; 32]
            || usize::from(head.wire_offset) > MAX_MATCH_SLOTS * 4
            || usize::from(head.wire_offset) % 4 != 0
            || head.transition_digest == [0; 32]
            || head.canonical_receipt_digest == [0; 32]
            || head.canonical_height == 0
            || receipt
                .is_none_or(|receipt| receipt.private_state_sha256 != head.private_state_sha256)
            || finalization.is_none_or(|finalization| {
                finalization.transition_digest != head.transition_digest
                    || finalization.canonical_receipt_digest != head.canonical_receipt_digest
                    || finalization.canonical_height != head.canonical_height
            })
        {
            return Err(NodeError::State(
                "node share store contains a misbound private-state head".into(),
            ));
        }
    }
    for (round, finalization) in &state.finalized_private_rounds {
        let receipt = state.completed_rounds.get(round);
        if finalization.public_output_sha256 == [0; 32]
            || finalization.transition_digest == [0; 32]
            || finalization.canonical_receipt_digest == [0; 32]
            || finalization.canonical_height == 0
            || receipt.is_none_or(|receipt| {
                receipt.public_output_sha256 != finalization.public_output_sha256
            })
        {
            return Err(NodeError::State(
                "node share store contains a misbound private-state finalization".into(),
            ));
        }
    }
    Ok((state, migrated))
}

fn reject_symlink(path: &Path) -> Result<(), NodeError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(NodeError::UnsafePath("symlink paths are rejected".into()));
        }
    }
    Ok(())
}

fn state_digest(state: &StoreState) -> Result<Digest32, NodeError> {
    serde_json::to_vec(state)
        .map(|payload| Sha256::digest(payload).into())
        .map_err(|error| NodeError::State(error.to_string()))
}

fn round_commitment(
    party: u16,
    generation: u64,
    resting: &[OrderCommitment],
    arriving: OrderCommitment,
    contents: &[u8],
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:NODE-ROUND:v1");
    hash.update(party.to_be_bytes());
    hash.update(generation.to_be_bytes());
    hash.update((resting.len() as u16).to_be_bytes());
    for commitment in resting {
        hash.update(commitment.0);
    }
    hash.update(arriving.0);
    hash.update(Sha256::digest(contents));
    hash.finalize().into()
}

fn randless_nonce(payload: &[u8]) -> u64 {
    u64::from_be_bytes(
        Sha256::digest(payload)[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    )
}

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("MPC party index is invalid")]
    Party,
    #[error("share admission failed: {0}")]
    Admission(String),
    #[error("another ciphertext already exists for the same order commitment")]
    Conflict,
    #[error("node share store generation overflowed")]
    Generation,
    #[error("round references an unknown order")]
    UnknownOrder,
    #[error("round plan is invalid: {0}")]
    Round(String),
    #[error("ordering state is invalid: {0}")]
    Ordering(String),
    #[error("settlement capability release rejected: {0}")]
    Release(String),
    #[error("party-local private book state is invalid: {0}")]
    PrivateState(String),
    #[error("node state is invalid: {0}")]
    State(String),
    #[error("unsafe node-store path: {0}")]
    UnsafePath(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use oclob_core::{MpcBatchResult, MpcSlotResult, SecretOrder, Side, TimeInForce};
    use oclob_edge::{EdgeOrderBundle, NodeEncryptionKey};
    use oclob_ordering::OrderingCommittee;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "oclob-node-{label}-{}-{:016x}/shares.bin",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    fn order(price: u64, quantity: u64, nonce: u8) -> SecretOrder {
        SecretOrder::new(
            "JGB10Y-JPY",
            Side::Sell,
            price,
            quantity,
            TimeInForce::GoodTilCancelled,
            2_000_000_000,
            [1; 32],
            [nonce; 32],
            [nonce.wrapping_add(1); 32],
        )
        .unwrap()
    }

    fn ioc_order(price: u64, quantity: u64, nonce: u8) -> SecretOrder {
        SecretOrder::new(
            "JGB10Y-JPY",
            Side::Buy,
            price,
            quantity,
            TimeInForce::ImmediateOrCancel,
            2_000_000_000,
            [2; 32],
            [nonce; 32],
            [nonce.wrapping_add(1); 32],
        )
        .unwrap()
    }

    fn keyset() -> (
        [NodeDecryptionKey; MPC_PARTIES],
        [NodeEncryptionKey; MPC_PARTIES],
    ) {
        let private = std::array::from_fn(|_| NodeDecryptionKey::generate().unwrap());
        let public = std::array::from_fn(|party| private[party].public_key().unwrap());
        (private, public)
    }

    #[test]
    fn each_store_accepts_only_its_ciphertext_and_survives_restart() {
        let (private, public) = keyset();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let bundle = EdgeOrderBundle::create(
            &order(100, 40, 3),
            [4; 32],
            [5; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let manifest = bundle.manifest().clone();
        let deliveries = bundle.into_deliveries();
        let path = temp_path("restart");
        let key_raw = private[0].raw_private_key().unwrap();
        let mut store = NodeShareStore::open(&path, 0, private[0].clone()).unwrap();
        assert_eq!(
            store
                .ingest(
                    manifest.clone(),
                    deliveries[0].1.clone(),
                    deliveries[0].2.clone(),
                    1_900_000_000,
                )
                .unwrap(),
            IngestOutcome::Stored { generation: 1 }
        );
        assert_eq!(
            store
                .ingest(
                    manifest.clone(),
                    deliveries[0].1.clone(),
                    deliveries[0].2.clone(),
                    1_900_000_000,
                )
                .unwrap(),
            IngestOutcome::AlreadyPresent { generation: 1 }
        );
        assert!(store
            .ingest(
                manifest.clone(),
                deliveries[1].1.clone(),
                deliveries[1].2.clone(),
                1_900_000_000,
            )
            .is_err());
        drop(store);
        let reopened =
            NodeShareStore::open(&path, 0, NodeDecryptionKey::from_raw(key_raw).unwrap()).unwrap();
        assert_eq!(reopened.status().unwrap().record_count, 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn node_builds_only_its_fixed_party_input_from_commitments() {
        let (private, public) = keyset();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let first = EdgeOrderBundle::create(
            &order(100, 60, 6),
            [7; 32],
            [8; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let second = EdgeOrderBundle::create(
            &order(101, 40, 9),
            [10; 32],
            [11; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let first_manifest = first.manifest().clone();
        let second_manifest = second.manifest().clone();
        let first_deliveries = first.into_deliveries();
        let second_deliveries = second.into_deliveries();
        let first_delivery = first_deliveries[0].1.clone();
        let first_key_delivery = first_deliveries[0].2.clone();
        let second_delivery = second_deliveries[0].1.clone();
        let second_key_delivery = second_deliveries[0].2.clone();
        let path = temp_path("round");
        let mut store = NodeShareStore::open(&path, 0, private[0].clone()).unwrap();
        store
            .ingest(
                first_manifest.clone(),
                first_delivery,
                first_key_delivery,
                1_900_000_000,
            )
            .unwrap();
        store
            .ingest(
                second_manifest.clone(),
                second_delivery,
                second_key_delivery,
                1_900_000_000,
            )
            .unwrap();
        let prepared = store
            .prepare_round(
                "JGB10Y-JPY",
                &[first_manifest.commitment],
                second_manifest.commitment,
                1_900_000_000,
            )
            .unwrap();
        assert_eq!(prepared.party(), 0);
        let input_path = path.parent().unwrap().join("Input-P0-0");
        prepared.write_exclusive(&input_path).unwrap();
        let text = fs::read_to_string(&input_path).unwrap();
        assert_eq!(text.split_whitespace().count(), MAX_MATCH_SLOTS * 4 + 4);
        assert!(!text.contains("JGB10Y-JPY"));
        assert!(!text.contains(&first_manifest.commitment.hex()));
        assert!(prepared.write_exclusive(&input_path).is_err());
        assert!(store
            .prepare_round(
                "USD-JPY",
                &[first_manifest.commitment],
                second_manifest.commitment,
                1_900_000_000,
            )
            .is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn corrupted_store_and_expired_records_fail_closed() {
        let (private, public) = keyset();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let bundle = EdgeOrderBundle::create(
            &order(100, 40, 12),
            [13; 32],
            [14; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let manifest = bundle.manifest().clone();
        let deliveries = bundle.into_deliveries();
        let delivery = deliveries[0].1.clone();
        let key_delivery = deliveries[0].2.clone();
        let path = temp_path("corrupt");
        let key_raw = private[0].raw_private_key().unwrap();
        let mut store = NodeShareStore::open(&path, 0, private[0].clone()).unwrap();
        store
            .ingest(manifest, delivery, key_delivery, 1_900_000_000)
            .unwrap();
        assert_eq!(store.prune_expired(2_000_000_001).unwrap(), 1);
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(
            NodeShareStore::open(&path, 0, NodeDecryptionKey::from_raw(key_raw).unwrap()).is_err()
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn capability_key_share_is_released_only_after_an_authorized_completed_round() {
        let (private, public) = keyset();
        let participant = SigningKey::generate(&mut rand::rngs::OsRng);
        let coordinator = SigningKey::generate(&mut rand::rngs::OsRng);
        let resting_order = order(100, 40, 31);
        let resting_bundle = EdgeOrderBundle::create(
            &resting_order,
            [32; 32],
            [33; 32],
            &participant,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let resting_manifest = resting_bundle.manifest().clone();
        let resting_deliveries = resting_bundle.into_deliveries();
        let path = temp_path("capability-release");
        let mut store = NodeShareStore::open(&path, 0, private[0].clone()).unwrap();
        store
            .ingest(
                resting_manifest.clone(),
                resting_deliveries[0].1.clone(),
                resting_deliveries[0].2.clone(),
                1_900_000_000,
            )
            .unwrap();

        let mut committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let resting_certificate = committee
            .certify(
                "JGB10Y-JPY",
                resting_manifest.commitment,
                1_900_000_100,
                1_900_000_000,
            )
            .unwrap();
        let resting_plan = executor::RoundPlan::sign(
            resting_certificate,
            vec![],
            1_900_000_000,
            1_900_000_100,
            &coordinator,
        )
        .unwrap();
        assert!(
            store
                .release_capability_key_share(
                    &resting_plan,
                    resting_manifest.commitment,
                    1_900_000_000,
                )
                .is_err()
        );

        let resting_result = MpcBatchResult {
            slots: vec![
                MpcSlotResult {
                    matched: false,
                    trade_price: 0,
                    trade_quantity: 0,
                };
                MAX_MATCH_SLOTS
            ],
            arriving_remaining: 40,
        };
        let resting_output = public_output_digest(&resting_result);
        let resting_generation = store.status().unwrap().generation;
        store
            .record_completed_round(executor::NodeExecutionReceipt {
                version: 1,
                party: 0,
                round_id: resting_plan.round_id,
                generation: resting_generation,
                round_commitment: [34; 32],
                program_sha256: [35; 32],
                artifact_sha256: [36; 32],
                private_parent_digest: [37; 32],
                private_state_sha256: [40; 32],
                public_output_sha256: resting_output,
                result: resting_result,
                execution_ms: 1,
                signer: [38; 32],
                signature: vec![39; 64],
            })
            .unwrap();
        let (released, output) = store
            .release_capability_key_share(&resting_plan, resting_manifest.commitment, 1_900_000_000)
            .unwrap();
        released
            .verify(&resting_manifest, 0, 1_900_000_000)
            .unwrap();
        assert_eq!(output, resting_output);

        let ioc = ioc_order(99, 20, 40);
        let ioc_bundle = EdgeOrderBundle::create(
            &ioc,
            [41; 32],
            [42; 32],
            &participant,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let ioc_manifest = ioc_bundle.manifest().clone();
        let ioc_deliveries = ioc_bundle.into_deliveries();
        store
            .ingest(
                ioc_manifest.clone(),
                ioc_deliveries[0].1.clone(),
                ioc_deliveries[0].2.clone(),
                1_900_000_000,
            )
            .unwrap();
        let mut ioc_committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let ioc_certificate = ioc_committee
            .certify(
                "JGB10Y-JPY",
                ioc_manifest.commitment,
                1_900_000_100,
                1_900_000_000,
            )
            .unwrap();
        let ioc_plan = executor::RoundPlan::sign(
            ioc_certificate,
            vec![resting_manifest.commitment],
            1_900_000_000,
            1_900_000_100,
            &coordinator,
        )
        .unwrap();
        let ioc_result = MpcBatchResult {
            slots: vec![
                MpcSlotResult {
                    matched: false,
                    trade_price: 0,
                    trade_quantity: 0,
                };
                MAX_MATCH_SLOTS
            ],
            arriving_remaining: 0,
        };
        let ioc_output = public_output_digest(&ioc_result);
        let ioc_generation = store.status().unwrap().generation;
        store
            .record_completed_round(executor::NodeExecutionReceipt {
                version: 1,
                party: 0,
                round_id: ioc_plan.round_id,
                generation: ioc_generation,
                round_commitment: [43; 32],
                program_sha256: [44; 32],
                artifact_sha256: [45; 32],
                private_parent_digest: [46; 32],
                private_state_sha256: [49; 32],
                public_output_sha256: ioc_output,
                result: ioc_result,
                execution_ms: 1,
                signer: [47; 32],
                signature: vec![48; 64],
            })
            .unwrap();
        assert!(store
            .release_capability_key_share(&ioc_plan, ioc_manifest.commitment, 1_900_000_000,)
            .is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn ordering_vote_and_certificate_chain_survive_restart() {
        let (private, public) = keyset();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let first = EdgeOrderBundle::create(
            &order(100, 60, 21),
            [22; 32],
            [23; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let second = EdgeOrderBundle::create(
            &order(101, 40, 24),
            [25; 32],
            [26; 32],
            &signer,
            &public,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let first_manifest = first.manifest().clone();
        let second_manifest = second.manifest().clone();
        let first_deliveries = first.into_deliveries();
        let second_deliveries = second.into_deliveries();
        let first_delivery = first_deliveries[0].1.clone();
        let first_key_delivery = first_deliveries[0].2.clone();
        let second_delivery = second_deliveries[0].1.clone();
        let second_key_delivery = second_deliveries[0].2.clone();
        let path = temp_path("ordering");
        let key_raw = private[0].raw_private_key().unwrap();
        let mut store = NodeShareStore::open(&path, 0, private[0].clone()).unwrap();
        store
            .ingest(
                first_manifest.clone(),
                first_delivery,
                first_key_delivery,
                1_900_000_000,
            )
            .unwrap();
        store
            .ingest(
                second_manifest.clone(),
                second_delivery,
                second_key_delivery,
                1_900_000_000,
            )
            .unwrap();
        let mut committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let first_certificate = committee
            .certify(
                "JGB10Y-JPY",
                first_manifest.commitment,
                1_900_000_100,
                1_900_000_000,
            )
            .unwrap();
        store
            .record_order_vote(
                "JGB10Y-JPY",
                1,
                first_manifest.commitment,
                [0; 32],
                1_900_000_100,
                1_900_000_000,
            )
            .unwrap();
        assert!(store
            .record_order_vote(
                "JGB10Y-JPY",
                1,
                second_manifest.commitment,
                [0; 32],
                1_900_000_100,
                1_900_000_000,
            )
            .is_err());
        store
            .accept_order_certificate(
                &first_certificate,
                committee.policy(),
                &committee.verifying_keys(),
                1_900_000_000,
            )
            .unwrap();
        let first_head = first_certificate.digest();
        assert_eq!(store.status().unwrap().ordering_sequence, 1);
        assert_eq!(store.status().unwrap().ordering_head, first_head);
        drop(store);

        let mut reopened =
            NodeShareStore::open(&path, 0, NodeDecryptionKey::from_raw(key_raw).unwrap()).unwrap();
        assert_eq!(reopened.status().unwrap().ordering_head, first_head);
        let second_certificate = committee
            .certify(
                "JGB10Y-JPY",
                second_manifest.commitment,
                1_900_000_100,
                1_900_000_000,
            )
            .unwrap();
        reopened
            .record_order_vote(
                "JGB10Y-JPY",
                2,
                second_manifest.commitment,
                first_head,
                1_900_000_100,
                1_900_000_000,
            )
            .unwrap();
        reopened
            .accept_order_certificate(
                &second_certificate,
                committee.policy(),
                &committee.verifying_keys(),
                1_900_000_000,
            )
            .unwrap();
        assert_eq!(reopened.status().unwrap().ordering_sequence, 2);
        assert_eq!(
            reopened.status().unwrap().ordering_head,
            second_certificate.digest()
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
