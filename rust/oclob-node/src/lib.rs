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
use oclob_edge::{EdgeOrderManifest, NodeDecryptionKey, SealedPartyShare, MPC_PARTIES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

const STORE_MAGIC: &[u8; 8] = b"OCLOBN01";
const STORE_VERSION: u16 = 2;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredRecord {
    manifest: EdgeOrderManifest,
    sealed: SealedPartyShare,
    admitted_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoreState {
    version: u16,
    party: u16,
    generation: u64,
    records: BTreeMap<String, StoredRecord>,
    completed_rounds: BTreeMap<String, executor::NodeExecutionReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeStoreStatus {
    pub party: u16,
    pub generation: u64,
    pub record_count: usize,
    pub completed_round_count: usize,
    pub state_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngestOutcome {
    Stored { generation: u64 },
    AlreadyPresent { generation: u64 },
}

/// A node-owned input file. The material intentionally has no `Debug`,
/// serialization or clear-value accessor.
pub struct PreparedPartyInput {
    party: u16,
    generation: u64,
    round_commitment: Digest32,
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
        let state = if path.exists() {
            read_state(&path, party)?
        } else {
            StoreState {
                version: STORE_VERSION,
                party,
                generation: 0,
                records: BTreeMap::new(),
                completed_rounds: BTreeMap::new(),
            }
        };
        let mut store = Self { path, key, state };
        if !store.path.exists() {
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
            state_digest: state_digest(&self.state)?,
        })
    }

    pub fn ingest(
        &mut self,
        manifest: EdgeOrderManifest,
        sealed: SealedPartyShare,
        now: u64,
    ) -> Result<IngestOutcome, NodeError> {
        sealed
            .open(&self.key, &manifest, self.state.party, now)
            .map_err(|error| NodeError::Admission(error.to_string()))?;
        let key = manifest.commitment.hex();
        let incoming = StoredRecord {
            manifest,
            sealed,
            admitted_at: now,
        };
        if let Some(existing) = self.state.records.get(&key) {
            return if existing == &incoming {
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

    /// Assemble the fixed OCLOB matching frame from commitments only. Resting
    /// sequence is public; side, price, quantity and participant identity are
    /// never supplied by the coordinator.
    pub fn prepare_round(
        &self,
        resting: &[OrderCommitment],
        arriving: OrderCommitment,
        now: u64,
    ) -> Result<PreparedPartyInput, NodeError> {
        if resting.len() > MAX_MATCH_SLOTS || resting.contains(&arriving) {
            return Err(NodeError::Round(
                "round has too many or duplicate order commitments".into(),
            ));
        }
        let arriving_share = self.open_record(arriving, now)?;
        let arriving_values = arriving_share.value_share_decimals();
        let mut fields = Vec::with_capacity(MAX_MATCH_SLOTS * 4 + 4);
        for slot in 0..MAX_MATCH_SLOTS {
            if let Some(commitment) = resting.get(slot) {
                let share = self.open_record(*commitment, now)?;
                let values = share.value_share_decimals();
                fields.push("1".to_owned());
                fields.extend([values[0].clone(), values[1].clone(), values[2].clone()]);
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
        Ok(PreparedPartyInput {
            party: self.state.party,
            generation: self.state.generation,
            round_commitment,
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
    pub fn record_completed_round(
        &mut self,
        receipt: executor::NodeExecutionReceipt,
    ) -> Result<(), NodeError> {
        if receipt.party != self.state.party {
            return Err(NodeError::Round(
                "execution receipt belongs to another party".into(),
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
        now: u64,
    ) -> Result<oclob_edge::PartyOrderShare, NodeError> {
        let record = self
            .state
            .records
            .get(&commitment.hex())
            .ok_or(NodeError::UnknownOrder)?;
        record
            .sealed
            .open(&self.key, &record.manifest, self.state.party, now)
            .map_err(|error| NodeError::Admission(error.to_string()))
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
}

fn read_state(path: &Path, expected_party: u16) -> Result<StoreState, NodeError> {
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
    let state: StoreState = serde_json::from_slice(&encoded[16..end])
        .map_err(|_| NodeError::State("node share store payload is invalid".into()))?;
    if state.version != STORE_VERSION || state.party != expected_party {
        return Err(NodeError::State(
            "node share store belongs to another version or party".into(),
        ));
    }
    for (key, record) in &state.records {
        if key != &record.manifest.commitment.hex()
            || record.manifest.commitment != record.sealed.commitment
            || record.sealed.party != expected_party
        {
            return Err(NodeError::State(
                "node share store contains a misbound record".into(),
            ));
        }
    }
    Ok(state)
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
    use oclob_core::{SecretOrder, Side, TimeInForce};
    use oclob_edge::{EdgeOrderBundle, NodeEncryptionKey};

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
                .ingest(manifest.clone(), deliveries[0].1.clone(), 1_900_000_000)
                .unwrap(),
            IngestOutcome::Stored { generation: 1 }
        );
        assert_eq!(
            store
                .ingest(manifest.clone(), deliveries[0].1.clone(), 1_900_000_000)
                .unwrap(),
            IngestOutcome::AlreadyPresent { generation: 1 }
        );
        assert!(store
            .ingest(manifest.clone(), deliveries[1].1.clone(), 1_900_000_000)
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
        let first_delivery = first.into_deliveries()[0].1.clone();
        let second_delivery = second.into_deliveries()[0].1.clone();
        let path = temp_path("round");
        let mut store = NodeShareStore::open(&path, 0, private[0].clone()).unwrap();
        store
            .ingest(first_manifest.clone(), first_delivery, 1_900_000_000)
            .unwrap();
        store
            .ingest(second_manifest.clone(), second_delivery, 1_900_000_000)
            .unwrap();
        let prepared = store
            .prepare_round(
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
        let delivery = bundle.into_deliveries()[0].1.clone();
        let path = temp_path("corrupt");
        let key_raw = private[0].raw_private_key().unwrap();
        let mut store = NodeShareStore::open(&path, 0, private[0].clone()).unwrap();
        store.ingest(manifest, delivery, 1_900_000_000).unwrap();
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
}
