//! One-party MP-SPDZ execution and signed, public-only receipts.

use crate::PreparedPartyInput;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{Digest32, MpcBatchResult, OrderCommitment, MAX_MATCH_SLOTS};
use oclob_mpc::{
    matching_program, parse_result, public_output_digest, MAX_CORRUPT_NODES, MPC_PARTIES,
    PERSISTENCE_WIRES, PRIVATE_BOOK_WIRES, SETTLEMENT_PROOF_WIRES_PER_FILL, SHAMIR_FIELD_ORDER,
};
use oclob_ordering::{CommitteePolicy, OrderCertificate};
use oclob_settlement::native::{ExecutedReservationBinding, NativeFillExecution};
use qomm_mpc::persistence::parse_header;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

const ROUND_PLAN_DOMAIN: &[u8] = b"OCLOB:DISTRIBUTED-ROUND-PLAN:v1";
const PARTY_RECEIPT_DOMAIN: &[u8] = b"OCLOB:DISTRIBUTED-PARTY-RECEIPT:v1";
const ARTIFACT_DOMAIN: &[u8] = b"OCLOB:MP-SPDZ-ARTIFACT:v1";
const PROOF_SLOT_METADATA_DOMAIN: &[u8] = b"OCLOB:PROOF-SLOT-METADATA:v1";
const VERSION: u16 = 1;
const PROOF_SLOT_METADATA_VERSION: u16 = 2;
const MAX_LOG_BYTES: u64 = 1024 * 1024;

/// Owner-only binding between an extracted proof handoff and the exact public
/// result emitted by the same MP-SPDZ execution.  The proof RPC validates this
/// sidecar before it lets an untrusted coordinator open a proof job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProofSlotMetadata {
    pub version: u16,
    pub party: u16,
    pub round_id: Digest32,
    pub slot: u16,
    pub public_output_sha256: Digest32,
    pub private_state_sha256: Digest32,
    pub persistence_sha256: Digest32,
    pub proof_wires: usize,
    pub signer: Digest32,
    pub signature: Vec<u8>,
    #[serde(default)]
    pub native_fill: Option<NativeFillExecution>,
}

impl ProofSlotMetadata {
    fn signature_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(192);
        body.extend_from_slice(PROOF_SLOT_METADATA_DOMAIN);
        body.extend_from_slice(&self.version.to_be_bytes());
        body.extend_from_slice(&self.party.to_be_bytes());
        body.extend_from_slice(&self.round_id);
        body.extend_from_slice(&self.slot.to_be_bytes());
        body.extend_from_slice(&self.public_output_sha256);
        body.extend_from_slice(&self.private_state_sha256);
        body.extend_from_slice(&self.persistence_sha256);
        body.extend_from_slice(&(self.proof_wires as u64).to_be_bytes());
        body.extend_from_slice(&self.signer);
        if self.version >= 2 {
            body.extend_from_slice(
                &self
                    .native_fill
                    .as_ref()
                    .map(NativeFillExecution::digest)
                    .unwrap_or([0; 32]),
            );
        }
        body
    }

    pub(crate) fn verify_signature(&self, expected_signer: Digest32) -> bool {
        if self.signer != expected_signer || self.signature.len() != 64 {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(&expected_signer) else {
            return false;
        };
        let Ok(signature) = Signature::try_from(self.signature.as_slice()) else {
            return false;
        };
        key.verify_strict(&self.signature_body(), &signature)
            .is_ok()
    }

    pub(crate) fn sign(&mut self, key: &SigningKey) {
        self.signer = key.verifying_key().to_bytes();
        self.signature = key.sign(&self.signature_body()).to_bytes().to_vec();
    }
}

/// Public, coordinator-signed input to a matching round. It contains only the
/// previously fixed order commitments and their certified sequence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoundPlan {
    pub version: u16,
    pub market_id: String,
    pub sequence: u64,
    pub ordering_certificate: OrderCertificate,
    pub resting: Vec<OrderCommitment>,
    pub arriving: OrderCommitment,
    pub issued_at: u64,
    pub expires_at: u64,
    pub coordinator: Digest32,
    pub round_id: Digest32,
    pub signature: Vec<u8>,
}

impl RoundPlan {
    pub fn sign(
        ordering_certificate: OrderCertificate,
        resting: Vec<OrderCommitment>,
        issued_at: u64,
        expires_at: u64,
        coordinator: &SigningKey,
    ) -> Result<Self, PartyExecutionError> {
        let mut plan = Self {
            version: VERSION,
            market_id: ordering_certificate.market_id.clone(),
            sequence: ordering_certificate.sequence,
            arriving: ordering_certificate.commitment,
            ordering_certificate,
            resting,
            issued_at,
            expires_at,
            coordinator: coordinator.verifying_key().to_bytes(),
            round_id: [0; 32],
            signature: Vec::new(),
        };
        plan.round_id = plan.derived_round_id();
        plan.signature = coordinator.sign(&plan.signature_body()).to_bytes().to_vec();
        plan.verify(issued_at)?;
        Ok(plan)
    }

    pub fn verify(&self, now: u64) -> Result<(), PartyExecutionError> {
        if self.version != VERSION
            || self.market_id.is_empty()
            || self.market_id.len() > 64
            || self.sequence == 0
            || self.ordering_certificate.market_id != self.market_id
            || self.ordering_certificate.sequence != self.sequence
            || self.ordering_certificate.commitment != self.arriving
            || self.expires_at > self.ordering_certificate.expires_at
            || self.coordinator == [0; 32]
            || self.arriving.0 == [0; 32]
            || self.resting.len() > MAX_MATCH_SLOTS
            || self.resting.contains(&self.arriving)
            || self.issued_at > now
            || now > self.expires_at
            || self.expires_at.saturating_sub(self.issued_at) > 300
            || self.round_id != self.derived_round_id()
        {
            return Err(PartyExecutionError::Plan);
        }
        let mut unique = self.resting.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != self.resting.len() {
            return Err(PartyExecutionError::Plan);
        }
        let key =
            VerifyingKey::from_bytes(&self.coordinator).map_err(|_| PartyExecutionError::Plan)?;
        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|_| PartyExecutionError::Plan)?;
        key.verify_strict(&self.signature_body(), &signature)
            .map_err(|_| PartyExecutionError::Plan)
    }

    /// Verify the coordinator signature and the complete quorum certificate.
    /// A digest alone is deliberately insufficient: every executor pins the
    /// seven ordering identities and checks the 5-of-7 proof itself.
    pub fn verify_ordering(
        &self,
        policy: CommitteePolicy,
        keys: &std::collections::BTreeMap<u16, VerifyingKey>,
        now: u64,
    ) -> Result<(), PartyExecutionError> {
        self.verify(now)?;
        self.ordering_certificate
            .verify(policy, keys, now)
            .map_err(|_| PartyExecutionError::Plan)
    }

    fn derived_round_id(&self) -> Digest32 {
        Sha256::digest(self.unsigned_body()).into()
    }

    fn signature_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(ROUND_PLAN_DOMAIN.len() + 32);
        body.extend_from_slice(ROUND_PLAN_DOMAIN);
        body.extend_from_slice(&self.round_id);
        body
    }

    fn unsigned_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(256 + self.resting.len() * 32);
        body.extend_from_slice(ROUND_PLAN_DOMAIN);
        body.extend_from_slice(&self.version.to_be_bytes());
        put_bytes(&mut body, self.market_id.as_bytes());
        body.extend_from_slice(&self.sequence.to_be_bytes());
        body.extend_from_slice(&self.ordering_certificate.digest());
        body.extend_from_slice(&(self.resting.len() as u16).to_be_bytes());
        for commitment in &self.resting {
            body.extend_from_slice(&commitment.0);
        }
        body.extend_from_slice(&self.arriving.0);
        body.extend_from_slice(&self.issued_at.to_be_bytes());
        body.extend_from_slice(&self.expires_at.to_be_bytes());
        body.extend_from_slice(&self.coordinator);
        body
    }
}

/// Signed by exactly one independently operated MPC party. The receipt has no
/// order values other than the matching result that the protocol intentionally
/// opens after the order sequence is fixed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeExecutionReceipt {
    pub version: u16,
    pub party: u16,
    pub round_id: Digest32,
    pub generation: u64,
    pub round_commitment: Digest32,
    pub program_sha256: Digest32,
    pub artifact_sha256: Digest32,
    /// Commitment to the exact prior private-state heads used as this round's
    /// input. It prevents a delayed finalization from overwriting a newer head.
    #[serde(default)]
    pub private_parent_digest: Digest32,
    /// Digest of this node's durable Shamir share of the post-match private
    /// book. The file itself never leaves the node and cannot be reconstructed
    /// from this public receipt.
    #[serde(default)]
    pub private_state_sha256: Digest32,
    pub public_output_sha256: Digest32,
    pub result: MpcBatchResult,
    pub execution_ms: u64,
    pub signer: Digest32,
    pub signature: Vec<u8>,
}

impl NodeExecutionReceipt {
    pub fn verify(
        &self,
        plan: &RoundPlan,
        expected_party: u16,
        expected_signer: &VerifyingKey,
    ) -> Result<(), PartyExecutionError> {
        let expected_program: Digest32 = Sha256::digest(matching_program()?.as_bytes()).into();
        if self.version != VERSION
            || self.party != expected_party
            || usize::from(self.party) >= MPC_PARTIES
            || self.round_id != plan.round_id
            || self.program_sha256 != expected_program
            || self.private_parent_digest == [0; 32]
            || self.private_state_sha256 == [0; 32]
            || self.public_output_sha256 != public_output_digest(&self.result)
            || self.result.slots.len() != MAX_MATCH_SLOTS
            || self.signer != expected_signer.to_bytes()
        {
            return Err(PartyExecutionError::Receipt);
        }
        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|_| PartyExecutionError::Receipt)?;
        expected_signer
            .verify_strict(&self.signature_body(), &signature)
            .map_err(|_| PartyExecutionError::Receipt)
    }

    fn signature_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(512);
        body.extend_from_slice(PARTY_RECEIPT_DOMAIN);
        body.extend_from_slice(&self.version.to_be_bytes());
        body.extend_from_slice(&self.party.to_be_bytes());
        body.extend_from_slice(&self.round_id);
        body.extend_from_slice(&self.generation.to_be_bytes());
        body.extend_from_slice(&self.round_commitment);
        body.extend_from_slice(&self.program_sha256);
        body.extend_from_slice(&self.artifact_sha256);
        body.extend_from_slice(&self.private_parent_digest);
        body.extend_from_slice(&self.private_state_sha256);
        body.extend_from_slice(&self.public_output_sha256);
        body.extend_from_slice(&(self.result.slots.len() as u16).to_be_bytes());
        for slot in &self.result.slots {
            body.push(u8::from(slot.matched));
            body.extend_from_slice(&slot.trade_price.to_be_bytes());
            body.extend_from_slice(&slot.trade_quantity.to_be_bytes());
        }
        body.extend_from_slice(&self.result.arriving_remaining.to_be_bytes());
        body.extend_from_slice(&self.execution_ms.to_be_bytes());
        body.extend_from_slice(&self.signer);
        body
    }
}

/// Runtime owned by one MPC operator. It launches only that operator's party
/// and never reads another party's input file.
pub struct PartyExecutor {
    party: u16,
    root: PathBuf,
    work_root: PathBuf,
    program: String,
    hosts: String,
    timeout: Duration,
    signing_key: SigningKey,
    program_sha256: Digest32,
    artifact_sha256: Digest32,
}

impl PartyExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        party: u16,
        root: impl Into<PathBuf>,
        work_root: impl Into<PathBuf>,
        program: impl Into<String>,
        hosts: impl Into<String>,
        timeout: Duration,
        signing_key: SigningKey,
    ) -> Result<Self, PartyExecutionError> {
        if usize::from(party) >= MPC_PARTIES
            || timeout.is_zero()
            || timeout > Duration::from_secs(600)
        {
            return Err(PartyExecutionError::Config);
        }
        let root = root.into();
        let work_root = work_root.into();
        let program = program.into();
        if program.is_empty()
            || !program
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(PartyExecutionError::Config);
        }
        let hosts = hosts.into();
        let lines = hosts.lines().collect::<Vec<_>>();
        if lines.len() != MPC_PARTIES
            || lines.iter().any(|line| {
                line.is_empty()
                    || line.len() > 255
                    || line.bytes().any(|byte| byte.is_ascii_whitespace())
                    || !line.contains(':')
            })
        {
            return Err(PartyExecutionError::Config);
        }
        reject_symlink(&root)?;
        reject_symlink(&work_root)?;
        qomm_mpc::engine_policy::verify(&root).map_err(oclob_mpc::MpcError::Setup)?;
        let binary = root.join("malicious-shamir-party.x");
        if !binary.is_file() {
            return Err(PartyExecutionError::Config);
        }
        let expected_source = matching_program()?;
        let source_path = root.join("Programs/Source").join(format!("{program}.mpc"));
        let source = read_bounded(&source_path, 1024 * 1024)?;
        if source != expected_source.as_bytes() {
            return Err(PartyExecutionError::ProgramMismatch);
        }
        let program_sha256 = Sha256::digest(&source).into();
        let artifact_sha256 = artifact_digest(&root, &program)?;
        fs::create_dir_all(&work_root)?;
        fs::set_permissions(&work_root, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            party,
            root,
            work_root,
            program,
            hosts,
            timeout,
            signing_key,
            program_sha256,
            artifact_sha256,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub(crate) fn private_state_root(&self) -> PathBuf {
        self.work_root.join("private-state")
    }

    pub fn execute(
        &mut self,
        prepared: &PreparedPartyInput,
        plan: &RoundPlan,
    ) -> Result<NodeExecutionReceipt, PartyExecutionError> {
        qomm_mpc::engine_policy::verify(&self.root).map_err(oclob_mpc::MpcError::Setup)?;
        if prepared.party() != self.party {
            return Err(PartyExecutionError::PartyBinding);
        }
        let round = self
            .work_root
            .join(format!("round-{}", hex::encode(plan.round_id)));
        reject_symlink(&round)?;
        fs::create_dir(&round).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                PartyExecutionError::Replay
            } else {
                PartyExecutionError::Io(error)
            }
        })?;
        fs::set_permissions(&round, fs::Permissions::from_mode(0o700))?;
        let cleanup = RoundCleanup(round.clone());
        prepare_runtime_view(&self.root, &round, self.party)?;
        let persistence_directory = round.join("Persistence");
        fs::create_dir(&persistence_directory)?;
        fs::set_permissions(&persistence_directory, fs::Permissions::from_mode(0o700))?;
        let input_prefix = round.join("Input");
        prepared.write_exclusive(round.join(format!("Input-P{}-0", self.party)))?;
        let hosts_path = round.join("hosts");
        write_exclusive(&hosts_path, self.hosts.as_bytes())?;
        let log_path = round.join("party.log");
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log_path)?;
        let stderr = stdout.try_clone()?;
        let started = Instant::now();
        let mut child = Command::new(self.root.join("malicious-shamir-party.x"))
            // MP-SPDZ writes protocol-local files below PREP_DIR. Keep the
            // pinned program read-only, but give this one party an isolated,
            // writable runtime view containing only its own TLS private key.
            .current_dir(&round)
            .arg(self.party.to_string())
            .arg(&self.program)
            .args(["-N", &MPC_PARTIES.to_string()])
            .args(["-T", &MAX_CORRUPT_NODES.to_string()])
            .args(["-P", SHAMIR_FIELD_ORDER])
            .arg("-ip")
            .arg(&hosts_path)
            .arg("-IF")
            .arg(&input_prefix)
            .arg("-OF")
            // MP-SPDZ documents `.` as stdout for every party. The process
            // stdout is already captured in this node's owner-only log and
            // parsed through the public-output allowlist below.
            .arg(".")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        wait_child(&mut child, self.timeout)?;
        let execution_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let output = read_bounded(&log_path, MAX_LOG_BYTES)?;
        let output = std::str::from_utf8(&output).map_err(|_| PartyExecutionError::Output)?;
        let result = parse_result(output).map_err(|_| PartyExecutionError::Output)?;
        let public_output_sha256 = public_output_digest(&result);
        let private_state_sha256 = self.retain_private_state(
            &round,
            plan.round_id,
            public_output_sha256,
            prepared,
            &result,
        )?;
        let mut receipt = NodeExecutionReceipt {
            version: VERSION,
            party: self.party,
            round_id: plan.round_id,
            generation: prepared.generation(),
            round_commitment: prepared.round_commitment(),
            program_sha256: self.program_sha256,
            artifact_sha256: self.artifact_sha256,
            private_parent_digest: prepared.private_parent_digest(),
            private_state_sha256,
            public_output_sha256,
            result,
            execution_ms,
            signer: self.signing_key.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        receipt.signature = self
            .signing_key
            .sign(&receipt.signature_body())
            .to_bytes()
            .to_vec();
        receipt.verify(plan, self.party, &self.signing_key.verifying_key())?;
        drop(cleanup);
        Ok(receipt)
    }

    /// Move the party-local MP-SPDZ Persistence output out of the ephemeral
    /// execution directory. Only a digest is returned to the coordinator.
    fn retain_private_state(
        &self,
        round: &Path,
        round_id: Digest32,
        public_output_sha256: Digest32,
        prepared: &PreparedPartyInput,
        result: &MpcBatchResult,
    ) -> Result<Digest32, PartyExecutionError> {
        let source = round
            .join("Persistence")
            .join(format!("Transactions-P{}.data", self.party));
        let bytes = read_bounded(&source, 16 * 1024 * 1024)?;
        let digest: Digest32 = Sha256::digest(&bytes).into();
        let private_root = self.work_root.join("private-state");
        reject_symlink(&private_root)?;
        fs::create_dir_all(&private_root)?;
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))?;
        let destination_directory = private_root.join(hex::encode(round_id));
        reject_symlink(&destination_directory)?;
        fs::create_dir(&destination_directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                PartyExecutionError::Replay
            } else {
                PartyExecutionError::Io(error)
            }
        })?;
        fs::set_permissions(&destination_directory, fs::Permissions::from_mode(0o700))?;
        let private_cleanup = RoundCleanup(destination_directory.clone());
        let destination = destination_directory.join(format!("Transactions-P{}.data", self.party));
        reject_symlink(&destination)?;
        fs::rename(&source, &destination)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
        let header = parse_header(&bytes).map_err(|_| PartyExecutionError::Output)?;
        let expected_bytes = header
            .element_bytes
            .checked_mul(PERSISTENCE_WIRES)
            .and_then(|body| header.data_offset.checked_add(body))
            .ok_or(PartyExecutionError::Output)?;
        if bytes.len() != expected_bytes {
            return Err(PartyExecutionError::Output);
        }
        for slot in 0..MAX_MATCH_SLOTS {
            let proof_directory = destination_directory.join(format!("proof-slot-{slot}"));
            reject_symlink(&proof_directory)?;
            fs::create_dir(&proof_directory)?;
            fs::set_permissions(&proof_directory, fs::Permissions::from_mode(0o700))?;
            let first_share = PRIVATE_BOOK_WIRES
                .checked_add(slot * SETTLEMENT_PROOF_WIRES_PER_FILL)
                .ok_or(PartyExecutionError::Output)?;
            let start = header
                .data_offset
                .checked_add(
                    first_share
                        .checked_mul(header.element_bytes)
                        .ok_or(PartyExecutionError::Output)?,
                )
                .ok_or(PartyExecutionError::Output)?;
            let end = start
                .checked_add(
                    SETTLEMENT_PROOF_WIRES_PER_FILL
                        .checked_mul(header.element_bytes)
                        .ok_or(PartyExecutionError::Output)?,
                )
                .filter(|end| *end <= bytes.len())
                .ok_or(PartyExecutionError::Output)?;
            let mut proof = Vec::with_capacity(header.data_offset + end - start);
            proof.extend_from_slice(&bytes[..header.data_offset]);
            proof.extend_from_slice(&bytes[start..end]);
            let proof_path = proof_directory.join(format!("Transactions-P{}.data", self.party));
            write_exclusive(&proof_path, &proof)?;
            let mut metadata = ProofSlotMetadata {
                version: PROOF_SLOT_METADATA_VERSION,
                party: self.party,
                round_id,
                slot: u16::try_from(slot).map_err(|_| PartyExecutionError::Output)?,
                public_output_sha256,
                private_state_sha256: digest,
                persistence_sha256: Sha256::digest(&proof).into(),
                proof_wires: SETTLEMENT_PROOF_WIRES_PER_FILL,
                signer: self.signing_key.verifying_key().to_bytes(),
                signature: Vec::new(),
                native_fill: result
                    .slots
                    .get(slot)
                    .filter(|fill| fill.matched)
                    .and_then(|_| {
                        Some(NativeFillExecution {
                            maker: ExecutedReservationBinding::from_manifest(
                                prepared.resting_manifests.get(slot)?,
                            )?,
                            taker: ExecutedReservationBinding::from_manifest(
                                &prepared.arriving_manifest,
                            )?,
                            taker_may_close: result.arriving_remaining == 0
                                && result.slots.iter().rposition(|fill| fill.matched) == Some(slot),
                        })
                    }),
            };
            metadata.sign(&self.signing_key);
            let encoded = serde_json::to_vec(&metadata).map_err(|_| PartyExecutionError::Output)?;
            write_exclusive(&proof_directory.join("metadata.json"), &encoded)?;
        }
        std::mem::forget(private_cleanup);
        Ok(digest)
    }
}

fn prepare_runtime_view(root: &Path, round: &Path, party: u16) -> Result<(), PartyExecutionError> {
    let programs = root.join("Programs");
    if !programs.is_dir() {
        return Err(PartyExecutionError::ProgramMismatch);
    }
    symlink(&programs, round.join("Programs"))?;

    let source = root.join("Player-Data");
    reject_symlink(&source)?;
    if !source.is_dir() {
        return Err(PartyExecutionError::Config);
    }
    let destination = round.join("Player-Data");
    fs::create_dir(&destination)?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
    let own_key = format!("P{party}.key");
    for entry in fs::read_dir(&source)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_text = name.to_string_lossy();
        let is_public_certificate = name_text.ends_with(".pem") || name_text.ends_with(".0");
        if name_text != own_key && !is_public_certificate {
            continue;
        }
        let entry_type = entry.file_type()?;
        let bytes = if entry_type.is_symlink() {
            if !name_text.ends_with(".0") {
                return Err(PartyExecutionError::UnsafePath);
            }
            let link = fs::read_link(entry.path())?;
            let link_name = link
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or(PartyExecutionError::UnsafePath)?;
            if link.components().count() != 1
                || !link_name.starts_with('P')
                || !link_name.ends_with(".pem")
            {
                return Err(PartyExecutionError::UnsafePath);
            }
            read_bounded(&source.join(link), MAX_LOG_BYTES)?
        } else if entry_type.is_file() {
            read_bounded(&entry.path(), MAX_LOG_BYTES)?
        } else {
            return Err(PartyExecutionError::UnsafePath);
        };
        let target = destination.join(&name);
        write_exclusive(&target, &bytes)?;
        fs::set_permissions(
            &target,
            fs::Permissions::from_mode(if name_text == own_key { 0o600 } else { 0o644 }),
        )?;
    }
    if !destination.join(&own_key).is_file()
        || (0..MPC_PARTIES).any(|index| !destination.join(format!("P{index}.pem")).is_file())
    {
        return Err(PartyExecutionError::Config);
    }
    Ok(())
}

fn artifact_digest(root: &Path, program: &str) -> Result<Digest32, PartyExecutionError> {
    let mut paths = vec![
        root.join("malicious-shamir-party.x"),
        root.join("Programs/Schedules")
            .join(format!("{program}.sch")),
    ];
    let prefix = format!("{program}-");
    for entry in fs::read_dir(root.join("Programs/Bytecode"))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) && name.ends_with(".bc") {
            paths.push(entry.path());
        }
    }
    paths.sort();
    if paths.len() < 3 || paths.iter().any(|path| !path.is_file()) {
        return Err(PartyExecutionError::ProgramMismatch);
    }
    let mut hash = Sha256::new();
    hash.update(ARTIFACT_DOMAIN);
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| PartyExecutionError::Config)?;
        put_bytes_hash(&mut hash, relative.as_os_str().as_encoded_bytes());
        let bytes = read_bounded(&path, 512 * 1024 * 1024)?;
        put_bytes_hash(&mut hash, &bytes);
    }
    Ok(hash.finalize().into())
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, PartyExecutionError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max {
        return Err(PartyExecutionError::UnsafePath);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(PartyExecutionError::UnsafePath);
    }
    Ok(bytes)
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), PartyExecutionError> {
    reject_symlink(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<(), PartyExecutionError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                return Err(PartyExecutionError::PartyFailed(
                    status.code().unwrap_or(-1),
                ))
            }
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(PartyExecutionError::Timeout);
            }
        }
    }
}

fn reject_symlink(path: &Path) -> Result<(), PartyExecutionError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(PartyExecutionError::UnsafePath);
        }
    }
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_bytes_hash(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

struct RoundCleanup(PathBuf);

impl Drop for RoundCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Error)]
pub enum PartyExecutionError {
    #[error("distributed round plan is invalid")]
    Plan,
    #[error("distributed party receipt is invalid")]
    Receipt,
    #[error("party runtime configuration is invalid")]
    Config,
    #[error("compiled MP-SPDZ program does not match the canonical source")]
    ProgramMismatch,
    #[error("party input belongs to another node")]
    PartyBinding,
    #[error("round identifier was already used")]
    Replay,
    #[error("MP-SPDZ party exited with status {0}")]
    PartyFailed(i32),
    #[error("MP-SPDZ party timed out")]
    Timeout,
    #[error("MP-SPDZ public output is malformed")]
    Output,
    #[error("unsafe runtime path or file")]
    UnsafePath,
    #[error(transparent)]
    Node(#[from] crate::NodeError),
    #[error(transparent)]
    Mpc(#[from] oclob_mpc::MpcError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use oclob_ordering::OrderingCommittee;

    #[test]
    fn round_plan_is_commitment_only_and_tamper_evident() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let mut ordering = OrderingCommittee::deterministic_for_demo().unwrap();
        let certificate = ordering
            .certify("JGB10Y-JPY", OrderCommitment([4; 32]), 1_060, 1_000)
            .unwrap();
        let plan = RoundPlan::sign(
            certificate,
            vec![OrderCommitment([1; 32]), OrderCommitment([2; 32])],
            1_000,
            1_060,
            &key,
        )
        .unwrap();
        plan.verify(1_030).unwrap();
        plan.verify_ordering(ordering.policy(), &ordering.verifying_keys(), 1_030)
            .unwrap();
        let encoded = serde_json::to_string(&plan).unwrap();
        assert!(!encoded.contains("price"));
        assert!(!encoded.contains("quantity"));
        assert!(!encoded.contains("participant"));
        let mut tampered = plan;
        tampered.sequence += 1;
        assert!(tampered.verify(1_030).is_err());
    }

    #[test]
    fn coordinator_cannot_make_a_four_vote_certificate_executable() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let mut ordering = OrderingCommittee::deterministic_for_demo().unwrap();
        let mut certificate = ordering
            .certify("JGB10Y-JPY", OrderCommitment([4; 32]), 1_060, 1_000)
            .unwrap();
        certificate.votes.truncate(4);
        let plan = RoundPlan::sign(certificate, vec![], 1_000, 1_060, &key).unwrap();
        assert!(plan
            .verify_ordering(ordering.policy(), &ordering.verifying_keys(), 1_030)
            .is_err());
    }
}
