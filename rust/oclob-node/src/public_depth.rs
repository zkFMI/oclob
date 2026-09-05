//! Redacted price-level publication. No order identity, slot or authority is
//! serialized here. Node signatures attest the actual MPC output; a matched
//! round additionally requires every node's canonical private-state receipt.
use crate::edge_client::AgreedRoundExecution;
use crate::executor::RoundPlan;
use crate::network::{ClusterPublicConfig, NodePrivateStateReceipt};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{validate_public_levels, Digest32, MpcBatchResult, MpcPriceLevel};
use oclob_mpc::{matching_program, public_depth_digest, public_output_digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DepthAttestation {
    pub version: u16,
    pub party: u16,
    pub market_id: String,
    pub sequence: u64,
    pub round_id: Digest32,
    pub book_digest: Digest32,
    pub public_output_sha256: Digest32,
    pub program_sha256: Digest32,
    /// Hiding commitment to a random node-local Shamir share, not the share.
    pub state_commitment: Digest32,
    pub issued_at: u64,
    pub valid_until: u64,
    pub settlement_required: bool,
    pub signer: Digest32,
    pub signature: Vec<u8>,
}
impl DepthAttestation {
    pub(crate) fn sign(
        party: u16,
        plan: &RoundPlan,
        result: &MpcBatchResult,
        state: Digest32,
        key: &SigningKey,
    ) -> Result<Self, String> {
        let levels = result.public_levels.as_ref().ok_or("MPC depth absent")?;
        validate_public_levels(levels)?;
        let mut value = Self {
            version: 1,
            party,
            market_id: plan.market_id.clone(),
            sequence: plan.sequence,
            round_id: plan.round_id,
            book_digest: public_depth_digest(levels),
            public_output_sha256: public_output_digest(result),
            program_sha256: Sha256::digest(matching_program().map_err(err)?.as_bytes()).into(),
            state_commitment: state,
            issued_at: plan.issued_at,
            valid_until: plan.expires_at,
            settlement_required: result.slots.iter().any(|v| v.matched),
            signer: key.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        value.signature = key.sign(&value.body()?).to_bytes().to_vec();
        Ok(value)
    }
    fn body(&self) -> Result<Vec<u8>, String> {
        // Fixed tuple excludes signature; domain separates this from all other receipts.
        Ok([
            b"OCLOB:PUBLIC-DEPTH-ATTESTATION:v1".as_slice(),
            &serde_json::to_vec(&(
                self.version,
                self.party,
                &self.market_id,
                self.sequence,
                self.round_id,
                self.book_digest,
                self.public_output_sha256,
                self.program_sha256,
                self.state_commitment,
                self.issued_at,
                self.valid_until,
                self.settlement_required,
                self.signer,
            ))
            .map_err(err)?,
        ]
        .concat())
    }
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), String> {
        if self.version != 1
            || self.party >= 7
            || self.market_id.is_empty()
            || self.market_id.len() > 64
            || self.sequence == 0
            || self.round_id == [0; 32]
            || self.state_commitment == [0; 32]
            || self.valid_until < self.issued_at
            || self.valid_until - self.issued_at > 300
            || self.signer != key.to_bytes()
        {
            return Err("invalid public depth attestation".into());
        }
        key.verify_strict(
            &self.body()?,
            &Signature::try_from(self.signature.as_slice()).map_err(err)?,
        )
        .map_err(err)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedPublicBook {
    pub version: u16,
    pub market_id: String,
    pub sequence: u64,
    pub round_id: Digest32,
    pub levels: Vec<MpcPriceLevel>,
    pub attestations: Vec<DepthAttestation>,
    pub finality_receipts: Vec<NodePrivateStateReceipt>,
}
impl FinalizedPublicBook {
    pub fn from_execution(
        cluster: &ClusterPublicConfig,
        plan: &RoundPlan,
        execution: &AgreedRoundExecution,
        finality_receipts: Vec<NodePrivateStateReceipt>,
    ) -> Result<Self, String> {
        for (node, receipt) in cluster.nodes.iter().zip(&execution.receipts) {
            receipt
                .verify(
                    plan,
                    node.party,
                    &VerifyingKey::from_bytes(&node.receipt_verifying_key).map_err(err)?,
                )
                .map_err(err)?;
            if receipt.result != execution.result {
                return Err("depth execution disagreement".into());
            }
        }
        let book = Self {
            version: 1,
            market_id: plan.market_id.clone(),
            sequence: plan.sequence,
            round_id: plan.round_id,
            levels: execution
                .result
                .public_levels
                .clone()
                .ok_or("MPC depth absent")?,
            attestations: execution
                .receipts
                .iter()
                .map(|r| {
                    r.depth_attestation
                        .clone()
                        .ok_or("unsigned MPC depth".into())
                })
                .collect::<Result<_, String>>()?,
            finality_receipts,
        };
        book.verify(cluster, plan.issued_at, plan.sequence)?;
        Ok(book)
    }
    /// A client must retain its highest observed sequence. Expiry is checked
    /// separately from authenticity: an old signed snapshot is not a fresh book.
    pub fn verify(
        &self,
        cluster: &ClusterPublicConfig,
        at: u64,
        minimum_sequence: u64,
    ) -> Result<(), String> {
        cluster.validate().map_err(err)?;
        validate_public_levels(&self.levels)?;
        if self.version != 1
            || self.market_id != cluster.market_id
            || self.sequence < minimum_sequence
            || self.attestations.len() != cluster.nodes.len()
        {
            return Err("incomplete public book".into());
        }
        let first = self
            .attestations
            .first()
            .ok_or("public depth signatures absent")?;
        let program: Digest32 = Sha256::digest(matching_program().map_err(err)?.as_bytes()).into();
        let digest = public_depth_digest(&self.levels);
        if self.finality_receipts.len()
            != if first.settlement_required {
                cluster.nodes.len()
            } else {
                0
            }
        {
            return Err("public book missing canonical finality".into());
        }
        for (node, a) in cluster.nodes.iter().zip(&self.attestations) {
            let key = VerifyingKey::from_bytes(&node.receipt_verifying_key).map_err(err)?;
            a.verify(&key)?;
            if a.party != node.party
                || a.market_id != self.market_id
                || a.sequence != self.sequence
                || a.round_id != self.round_id
                || a.book_digest != digest
                || a.public_output_sha256 != first.public_output_sha256
                || a.program_sha256 != program
                || a.issued_at != first.issued_at
                || a.valid_until != first.valid_until
                || a.settlement_required != first.settlement_required
                || at < a.issued_at
                || at > a.valid_until
            {
                return Err("public depth binding or freshness invalid".into());
            }
            if first.settlement_required {
                let f = &self.finality_receipts[usize::from(node.party)];
                let first_f = &self.finality_receipts[0];
                f.verify_public_signature(&key).map_err(err)?;
                if f.party != node.party
                    || f.round_id != a.round_id
                    || f.private_state_sha256 != a.state_commitment
                    || f.canonical_height != first_f.canonical_height
                    || f.canonical_receipt_digest != first_f.canonical_receipt_digest
                    || f.transition_digest != first_f.transition_digest
                {
                    return Err("public depth finality disagrees with execution".into());
                }
            }
        }
        Ok(())
    }
}

/// Atomic replacement exposes only redacted, verified completed rounds. A
/// crash before rename leaves the previous file. Reconciliation from the done
/// journal repairs a crash between durable completion and this public export.
pub fn publish(path: &Path, book: &FinalizedPublicBook) -> Result<(), String> {
    let bytes = serde_json::to_vec(book).map_err(err)?;
    if bytes.len() > 128 * 1024 {
        return Err("public book exceeds size bound".into());
    }
    if fs::read(path).ok().as_deref() == Some(&bytes) {
        return Ok(());
    }
    let mut nonce = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let tmp = path.with_extension(format!("{}.pending", hex::encode(nonce)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(err)?;
    file.write_all(&bytes).map_err(err)?;
    file.sync_all().map_err(err)?;
    fs::rename(&tmp, path).map_err(err)?;
    File::open(path.parent().ok_or("public book parent absent")?)
        .map_err(err)?
        .sync_all()
        .map_err(err)
}
pub fn read(path: &Path) -> Result<Option<FinalizedPublicBook>, String> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(err(e)),
    };
    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() > 128 * 1024 {
        return Err("public book exceeds size bound".into());
    }
    serde_json::from_slice(&bytes).map(Some).map_err(err)
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
