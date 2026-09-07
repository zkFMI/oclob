//! Rust orchestration for the OCLOB MP-SPDZ matching circuit.

#![forbid(unsafe_code)]

use oclob_core::{
    MpcBatchResult, MpcMatchResult, MpcSlotResult, OrderCommitment, PrivateMatchBatch,
    PrivateMatchInput, PrivateRestingInput, MAX_MATCH_SLOTS,
};
use qomm_mpc::compiler::OfficialCompiler;
use qomm_mpc::engine_policy::EnginePin;
use qomm_mpc::inputs::build_shamir_party_files_secure;
use qomm_mpc::program::{ed25519_lagrange_at_zero, ED25519_ORDER};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpListener;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MPC_PARTIES: usize = 7;
pub const MAX_CORRUPT_NODES: usize = 2;
pub const PRIVATE_ORDER_WIRES: usize = 8;
pub const PRIVATE_BOOK_WIRES: usize = (MAX_MATCH_SLOTS + 1) * PRIVATE_ORDER_WIRES;
pub const SETTLEMENT_PROOF_WIRES_PER_FILL: usize = 616;
pub const PERSISTENCE_WIRES: usize =
    PRIVATE_BOOK_WIRES + MAX_MATCH_SLOTS * SETTLEMENT_PROOF_WIRES_PER_FILL;
pub const SHAMIR_FIELD_ORDER: &str = ED25519_ORDER;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MpcReceipt {
    pub protocol: String,
    pub parties: usize,
    pub max_corrupt_nodes: usize,
    pub program_sha256: [u8; 32],
    pub public_output_sha256: [u8; 32],
    pub compile_ms: f64,
    pub execution_ms: f64,
    pub all_parties_agreed: bool,
    pub result: MpcMatchResult,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MpcBatchReceipt {
    pub protocol: String,
    pub parties: usize,
    pub max_corrupt_nodes: usize,
    pub program_sha256: [u8; 32],
    pub public_output_sha256: [u8; 32],
    pub compile_ms: f64,
    pub execution_ms: f64,
    pub all_parties_agreed: bool,
    pub result: MpcBatchResult,
}

pub struct MpcRunner {
    root: PathBuf,
    engine: EnginePin,
    binary: PathBuf,
    program: String,
    program_sha256: [u8; 32],
    compile_ms: f64,
    work: TempRoot,
    rounds: u64,
    /// The seven parties stay alive between rounds; see [`ServiceMesh`].
    mesh: Option<ServiceMesh>,
    meshes: u64,
}

/// How long one round may take before the mesh is torn down and rebuilt.
const ROUND_TIMEOUT: Duration = Duration::from_secs(300);

/// Marker every party prints after each served round.
pub const ROUND_END_MARKER: &str = "OCLOB_ROUND_END";

/// The one body line the resident form leaves out (see `matching_service_program`).
const PERSISTENCE_WRITE: &str =
    "sint.write_to_file(private_book_wires + settlement_proof_wires)";

impl MpcRunner {
    pub fn compile(root: impl AsRef<Path>) -> Result<Self, MpcError> {
        let compiler = OfficialCompiler::from_checkout(root)
            .map_err(|error| MpcError::Setup(error.to_string()))?;
        let root = compiler.root().to_path_buf();
        // The full receipt check (45 MB of hashing) runs once here; each
        // round re-checks the artifact identities and re-hashes only if they
        // changed, so the engine stays fail-closed without paying the hash
        // per order.
        let engine = EnginePin::verify(&root).map_err(MpcError::Setup)?;
        let binary = root.join("malicious-shamir-party.x");
        if !binary.is_file() {
            return Err(MpcError::Setup(format!(
                "{} is absent; OCLOB never falls back to a clear matcher",
                binary.display()
            )));
        }
        let source = matching_service_program()?;
        let program_sha256 = Sha256::digest(source.as_bytes()).into();
        let work = TempRoot::new()?;
        let program = format!(
            "oclob_match_{}_{:016x}",
            std::process::id(),
            rand::random::<u64>()
        );
        let source_path = root.join("Programs/Source").join(format!("{program}.mpc"));
        fs::create_dir_all(
            source_path
                .parent()
                .ok_or_else(|| MpcError::Setup("MP-SPDZ source path has no parent".into()))?,
        )?;
        fs::write(&source_path, source)?;
        let started = Instant::now();
        let output = compiler
            .compile_field(253, &program)
            .map_err(|error| MpcError::Setup(error.to_string()))?;
        if !output.status.success() {
            return Err(MpcError::Compile(
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .rev()
                    .take(4_000)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect(),
            ));
        }
        Ok(Self {
            root,
            engine,
            binary,
            program,
            program_sha256,
            compile_ms: started.elapsed().as_secs_f64() * 1_000.0,
            work,
            rounds: 0,
            mesh: None,
            meshes: 0,
        })
    }

    pub fn execute(&mut self, input: &PrivateMatchInput) -> Result<MpcReceipt, MpcError> {
        let batch = PrivateMatchBatch {
            resting: vec![PrivateRestingInput {
                commitment: OrderCommitment([0; 32]),
                side: input.resting_side,
                price: input.resting_price,
                quantity: input.resting_quantity,
            }],
            arriving_side: input.arriving_side,
            arriving_price: input.arriving_price,
            arriving_quantity: input.arriving_quantity,
            arriving_can_rest: true,
        };
        let receipt = self.execute_batch(&batch)?;
        let slot = receipt.result.slots[0];
        Ok(MpcReceipt {
            protocol: receipt.protocol,
            parties: receipt.parties,
            max_corrupt_nodes: receipt.max_corrupt_nodes,
            program_sha256: receipt.program_sha256,
            public_output_sha256: receipt.public_output_sha256,
            compile_ms: receipt.compile_ms,
            execution_ms: receipt.execution_ms,
            all_parties_agreed: receipt.all_parties_agreed,
            result: MpcMatchResult {
                matched: slot.matched,
                trade_price: slot.trade_price,
                trade_quantity: slot.trade_quantity,
                resting_remaining: input.resting_quantity - slot.trade_quantity,
                arriving_remaining: receipt.result.arriving_remaining,
            },
        })
    }

    pub fn execute_batch(
        &mut self,
        input: &PrivateMatchBatch,
    ) -> Result<MpcBatchReceipt, MpcError> {
        self.engine.recheck().map_err(MpcError::Setup)?;
        if input.resting.len() > MAX_MATCH_SLOTS {
            return Err(MpcError::Input(format!(
                "a batch supports at most {MAX_MATCH_SLOTS} resting slots"
            )));
        }
        let values = compatibility_private_values(input)?;
        let mut sharing_rng = OsRng;
        let party_files = build_shamir_party_files_secure(
            &values,
            MPC_PARTIES,
            MAX_CORRUPT_NODES,
            &mut sharing_rng,
        )
        .map_err(|error| MpcError::Input(error.to_string()))?;
        // One long-lived mesh serves every round. Spawning the seven parties
        // per round cost a process start, the program load, the preprocessing
        // and 42 mutually authenticated TLS handshakes (about 13 ms of
        // ML-DSA-65 signing alone) on every order; measured on 2026-09-08 the
        // whole round was about 720 ms, of which the circuit itself is a
        // small part. A failed or timed-out round tears the mesh down so the
        // next round starts from a clean set of processes.
        if self.mesh.is_none() {
            self.meshes += 1;
            let dir = self.work.0.join(format!("mesh-{}", self.meshes));
            self.mesh = Some(ServiceMesh::spawn(
                &dir,
                &self.root,
                &self.binary,
                &self.program,
            )?);
        }
        let started = Instant::now();
        let outcome = self
            .mesh
            .as_mut()
            .ok_or(MpcError::NoOutput)
            .and_then(|mesh| mesh.serve_round(&party_files, ROUND_TIMEOUT));
        let outputs = match outcome {
            Ok(outputs) => outputs,
            Err(error) => {
                // Drop kills the children; the next round respawns them.
                self.mesh = None;
                return Err(error);
            }
        };
        let execution_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let parsed = outputs
            .iter()
            .enumerate()
            .map(|(party, output)| {
                parse_result(output).map_err(|message| MpcError::Party(party, message))
            })
            .collect::<Result<Vec<_>, _>>();
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                self.mesh = None;
                return Err(error);
            }
        };
        let mut first = parsed.first().cloned().ok_or(MpcError::NoOutput)?;
        if parsed.iter().any(|result| result != &first) {
            self.mesh = None;
            return Err(MpcError::Disagreement);
        }
        first.slots.truncate(input.resting.len());
        self.rounds += 1;
        let public_output_sha256 = public_output_digest(&first);
        Ok(MpcBatchReceipt {
            protocol: "MP-SPDZ malicious-shamir".into(),
            parties: MPC_PARTIES,
            max_corrupt_nodes: MAX_CORRUPT_NODES,
            program_sha256: self.program_sha256,
            public_output_sha256,
            compile_ms: self.compile_ms,
            execution_ms,
            all_parties_agreed: true,
            result: first,
        })
    }
}

/// Seven `malicious-shamir-party.x` processes running the service form of
/// the matching program: they connect once, then loop, reading each round's
/// shares from named pipes and printing the public result followed by
/// [`ROUND_END_MARKER`]. Dropping the mesh kills the processes.
struct ServiceMesh {
    children: Vec<Child>,
    /// Write ends of the input pipes, opened read-write so the parties never
    /// observe end of file between rounds.
    inputs: Vec<File>,
    logs: Vec<PathBuf>,
    consumed: Vec<u64>,
}

impl ServiceMesh {
    fn spawn(dir: &Path, root: &Path, binary: &Path, program: &str) -> Result<Self, MpcError> {
        fs::create_dir_all(dir)?;
        fs::create_dir(dir.join("Persistence"))?;
        symlink(root.join("Programs"), dir.join("Programs"))?;
        symlink(root.join("Player-Data"), dir.join("Player-Data"))?;
        let port = free_port_block(MPC_PARTIES)?;
        let hosts = (0..MPC_PARTIES)
            .map(|party| format!("127.0.0.1:{}\n", port + party as u16))
            .collect::<String>();
        let mut inputs = Vec::with_capacity(MPC_PARTIES);
        for party in 0..MPC_PARTIES {
            fs::write(dir.join(format!("hosts-P{party}")), &hosts)?;
            let pipe = dir.join(format!("Input-P{party}-0"));
            let status = Command::new("mkfifo")
                .arg("-m")
                .arg("600")
                .arg(&pipe)
                .status()
                .map_err(|error| MpcError::Setup(format!("mkfifo: {error}")))?;
            if !status.success() {
                return Err(MpcError::Setup(format!(
                    "could not create the input pipe for party {party}"
                )));
            }
            // Opened before the party starts, so its blocking open of the
            // read end returns at once and it never sees end of file.
            inputs.push(OpenOptions::new().read(true).write(true).open(&pipe)?);
        }
        let input_prefix = dir.join("Input");
        let mut children = Vec::with_capacity(MPC_PARTIES);
        let mut logs = Vec::with_capacity(MPC_PARTIES);
        for party in 0..MPC_PARTIES {
            let log_path = dir.join(format!("party-{party}.log"));
            let stdout = File::create(&log_path)?;
            let stderr = stdout.try_clone()?;
            let spawned = Command::new(binary)
                .current_dir(dir)
                .arg(party.to_string())
                .arg(program)
                .args(["-N", &MPC_PARTIES.to_string()])
                .args(["-T", &MAX_CORRUPT_NODES.to_string()])
                .args(["-P", ED25519_ORDER])
                .arg("-ip")
                .arg(dir.join(format!("hosts-P{party}")))
                .arg("-IF")
                .arg(&input_prefix)
                .args(["-OF", "."])
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .spawn();
            match spawned {
                Ok(child) => children.push(child),
                Err(error) => {
                    for child in &mut children {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    return Err(MpcError::Party(party, error.to_string()));
                }
            }
            logs.push(log_path);
        }
        Ok(Self {
            children,
            inputs,
            logs,
            consumed: vec![0; MPC_PARTIES],
        })
    }

    /// Feed one round and return each party's output for that round only.
    fn serve_round(
        &mut self,
        party_files: &[String],
        timeout: Duration,
    ) -> Result<Vec<String>, MpcError> {
        if party_files.len() != MPC_PARTIES {
            return Err(MpcError::Input("one input file per party is required".into()));
        }
        // Party 0 carries the control word (1 = serve another round) in the
        // same batch as its shares; the compiler merges all inputs of the
        // loop body into one round, so the word must arrive with them.
        for (party, contents) in party_files.iter().enumerate() {
            let pipe = &mut self.inputs[party];
            if party == 0 {
                pipe.write_all(b"1\n")?;
            }
            pipe.write_all(contents.as_bytes())?;
            pipe.flush()?;
        }
        let deadline = Instant::now() + timeout;
        let mut outputs: Vec<Option<String>> = vec![None; MPC_PARTIES];
        loop {
            for party in 0..MPC_PARTIES {
                if outputs[party].is_some() {
                    continue;
                }
                if let Some(status) = self.children[party].try_wait()? {
                    return Err(MpcError::Party(
                        party,
                        format!("exited with {}", status.code().unwrap_or(-1)),
                    ));
                }
                let mut file = File::open(&self.logs[party])?;
                file.seek(SeekFrom::Start(self.consumed[party]))?;
                let mut pending = String::new();
                file.read_to_string(&mut pending)?;
                let marker = format!("{ROUND_END_MARKER}\n");
                if let Some(end) = pending.find(&marker) {
                    let segment_len = end + marker.len();
                    self.consumed[party] += segment_len as u64;
                    outputs[party] = Some(pending[..segment_len].to_string());
                }
            }
            if outputs.iter().all(Option::is_some) {
                return Ok(outputs.into_iter().flatten().collect());
            }
            if Instant::now() >= deadline {
                return Err(MpcError::Timeout);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for ServiceMesh {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for MpcRunner {
    fn drop(&mut self) {
        let _ = fs::remove_file(
            self.root
                .join("Programs/Source")
                .join(format!("{}.mpc", self.program)),
        );
        let _ = fs::remove_file(
            self.root
                .join("Programs/Schedules")
                .join(format!("{}.sch", self.program)),
        );
        if let Ok(entries) = fs::read_dir(self.root.join("Programs/Bytecode")) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(&format!("{}-", self.program)) && name.ends_with(".bc") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// Canonical OCLOB matching source compiled by the official MP-SPDZ compiler.
/// Distributed parties must all pin the digest of these exact bytes.
pub fn matching_program() -> Result<String, MpcError> {
    let (header, body) = matching_program_parts()?;
    Ok(header + &body)
}

/// The same circuit inside one long-lived loop, for the resident runner.
/// Every round reads a control word from party 0 together with the shares,
/// runs the body, prints the public result and [`ROUND_END_MARKER`], then
/// continues while the control word is non-zero.
pub fn matching_service_program() -> Result<String, MpcError> {
    let (header, body) = matching_program_parts()?;
    let mut source = header;
    source.push_str(
        "# Service form: the identical body inside one loop. The control word is\n# read in the same input batch as the round values, because the compiler\n# merges every input instruction of a basic block into one round.\n@do_while\ndef _():\n    control = sint.get_input_from(0)\n",
    );
    for line in body.lines() {
        if line == PERSISTENCE_WRITE {
            // The single-shot form keeps the owner-local share file for the
            // node executor. The resident runner never reads it, and one
            // append per round (5,000 shares, 160 KB per party) would grow
            // without bound over the life of the mesh.
            source.push_str("    # Persistence is kept by the single-shot form only.\n");
            continue;
        }
        if !line.is_empty() {
            source.push_str("    ");
            source.push_str(line);
        }
        source.push('\n');
    }
    source.push_str(&format!(
        "    print_ln('{ROUND_END_MARKER}')\n    return regint(control.reveal())\n"
    ));
    Ok(source)
}

fn matching_program_parts() -> Result<(String, String), MpcError> {
    let lagrange = ed25519_lagrange_at_zero(MPC_PARTIES)
        .map_err(|error| MpcError::Setup(error.to_string()))?
        .join(", ");
    let header = format!(
        r#"# OCLOB fixed-shape multi-fill matching circuit; generated by Rust.
program.set_bit_length(64)
N_PARTIES = 7
MAX_SLOTS = {MAX_MATCH_SLOTS}
LAGRANGE = [{lagrange}]

def secret_input():
    total = None
    for party in range(N_PARTIES):
        share = LAGRANGE[party] * sint.get_input_from(party)
        total = share if total is None else total + share
    return total

"#
    );
    let mut source = String::new();
    for slot in 0..MAX_MATCH_SLOTS {
        source.push_str(&format!(
            "active_{slot} = secret_input()\nresting_side_{slot} = secret_input()\nresting_price_{slot} = secret_input()\nresting_quantity_{slot} = secret_input()\nresting_price_blinding_{slot} = secret_input()\nresting_reserve_{slot} = secret_input()\nresting_reserve_blinding_{slot} = secret_input()\nresting_handle_{slot} = secret_input()\n"
        ));
    }
    source.push_str(
        "arriving_side = secret_input()\narriving_price = secret_input()\narriving_quantity = secret_input()\narriving_can_rest = secret_input()\narriving_price_blinding = secret_input()\narriving_reserve = secret_input()\narriving_reserve_blinding = secret_input()\narriving_handle = secret_input()\nremaining = arriving_quantity\narriving_reserve_remaining = arriving_reserve\narriving_reserve_blinding_remaining = arriving_reserve_blinding\nprivate_book_wires = []\nsettlement_proof_wires = []\n",
    );
    // Same price/time rule as the canonical book, evaluated on secret values.
    // Keep each source slot in place: proofs, private state and reservation
    // authorities must stay bound to that original order. A secret prefix over
    // better eligible prices (or an earlier equal-price slot) determines how
    // much of the arriving order can reach this slot; no public sorting oracle.
    for slot in 0..MAX_MATCH_SLOTS {
        source.push_str(&format!(
            "eligible_{slot} = active_{slot} * (resting_side_{slot} != arriving_side) * arriving_side.if_else(resting_price_{slot} >= arriving_price, arriving_price >= resting_price_{slot}) * (resting_quantity_{slot} > 0)\n"
        ));
    }
    for slot in 0..MAX_MATCH_SLOTS {
        source.push_str(&format!("higher_quantity_{slot} = sint(0)\n"));
        for other in 0..MAX_MATCH_SLOTS {
            if other == slot {
                continue;
            }
            let earlier = u8::from(other < slot);
            source.push_str(&format!(
                "better_{slot}_{other} = arriving_side.if_else(resting_price_{other} > resting_price_{slot}, resting_price_{other} < resting_price_{slot}) + (resting_price_{other} == resting_price_{slot}) * {earlier}\nhigher_quantity_{slot} += eligible_{other} * better_{slot}_{other} * resting_quantity_{other}\n"
            ));
        }
        source.push_str(&format!("available_{slot} = (arriving_quantity > higher_quantity_{slot}).if_else(arriving_quantity - higher_quantity_{slot}, 0)\n"));
    }
    for slot in 0..MAX_MATCH_SLOTS {
        source.push_str(&format!(
            "opposite_{slot} = resting_side_{slot} != arriving_side\n\
price_cross_{slot} = arriving_side.if_else(resting_price_{slot} >= arriving_price, arriving_price >= resting_price_{slot})\n\
positive_{slot} = (resting_quantity_{slot} > 0) * (available_{slot} > 0)\n\
matched_{slot} = active_{slot} * opposite_{slot} * price_cross_{slot} * positive_{slot}\n\
minimum_{slot} = (resting_quantity_{slot} <= available_{slot}).if_else(resting_quantity_{slot}, available_{slot})\n\
trade_quantity_{slot} = matched_{slot} * minimum_{slot}\n\
trade_price_{slot} = matched_{slot} * resting_price_{slot}\n\
trade_price_blinding_{slot} = matched_{slot} * resting_price_blinding_{slot}\n\
resting_remaining_{slot} = resting_quantity_{slot} - trade_quantity_{slot}\n\
remaining = remaining - trade_quantity_{slot}\n\
fill_quantity_blinding_{slot} = sint.get_random()\n\
cash_{slot} = trade_quantity_{slot} * trade_price_{slot}\n\
cash_blinding_{slot} = sint.get_random()\n\
product_cross_{slot} = cash_blinding_{slot} - fill_quantity_blinding_{slot} * trade_price_{slot}\n\
limit_difference_{slot} = matched_{slot} * arriving_side.if_else(trade_price_{slot} - arriving_price, arriving_price - trade_price_{slot})\n\
limit_difference_blinding_{slot} = matched_{slot} * arriving_side.if_else(trade_price_blinding_{slot} - arriving_price_blinding, arriving_price_blinding - trade_price_blinding_{slot})\n\
securities_reserve_{slot} = arriving_side.if_else(arriving_reserve_remaining, resting_reserve_{slot})\n\
securities_reserve_blinding_{slot} = arriving_side.if_else(arriving_reserve_blinding_remaining, resting_reserve_blinding_{slot})\n\
cash_reserve_{slot} = arriving_side.if_else(resting_reserve_{slot}, arriving_reserve_remaining)\n\
cash_reserve_blinding_{slot} = arriving_side.if_else(resting_reserve_blinding_{slot}, arriving_reserve_blinding_remaining)\n\
securities_remainder_{slot} = securities_reserve_{slot} - trade_quantity_{slot}\n\
securities_remainder_blinding_{slot} = securities_reserve_blinding_{slot} - fill_quantity_blinding_{slot}\n\
cash_remainder_{slot} = cash_reserve_{slot} - cash_{slot}\n\
cash_remainder_blinding_{slot} = cash_reserve_blinding_{slot} - cash_blinding_{slot}\n\
maker_delivery_{slot} = resting_side_{slot}.if_else(trade_quantity_{slot}, cash_{slot})\n\
maker_delivery_blinding_{slot} = matched_{slot} * resting_side_{slot}.if_else(fill_quantity_blinding_{slot}, cash_blinding_{slot})\n\
maker_pool_remainder_{slot} = resting_reserve_{slot} - maker_delivery_{slot}\n\
maker_pool_remainder_blinding_{slot} = resting_reserve_blinding_{slot} - maker_delivery_blinding_{slot}\n\
arriving_delivery_{slot} = arriving_side.if_else(trade_quantity_{slot}, cash_{slot})\n\
arriving_delivery_blinding_{slot} = matched_{slot} * arriving_side.if_else(fill_quantity_blinding_{slot}, cash_blinding_{slot})\n\
arriving_reserve_remaining = arriving_reserve_remaining - arriving_delivery_{slot}\n\
arriving_reserve_blinding_remaining = arriving_reserve_blinding_remaining - arriving_delivery_blinding_{slot}\n\
resting_active_next_{slot} = active_{slot} * (resting_remaining_{slot} > 0)\n\
private_book_wires += [resting_active_next_{slot}, resting_side_{slot}, resting_price_{slot}, resting_remaining_{slot}, resting_price_blinding_{slot}, maker_pool_remainder_{slot}, maker_pool_remainder_blinding_{slot}, resting_handle_{slot}]\n\
qty_bits_{slot} = trade_quantity_{slot}.bit_decompose(32)\n\
price_bits_{slot} = trade_price_{slot}.bit_decompose(32)\n\
limit_bits_{slot} = limit_difference_{slot}.bit_decompose(32)\n\
securities_remainder_bits_{slot} = securities_remainder_{slot}.bit_decompose(32)\n\
cash_remainder_bits_{slot} = cash_remainder_{slot}.bit_decompose(32)\n\
maker_pool_remainder_bits_{slot} = maker_pool_remainder_{slot}.bit_decompose(32)\n\
qty_bit_blindings_{slot} = [sint.get_random() for _ in range(32)]\n\
price_bit_blindings_{slot} = [sint.get_random() for _ in range(32)]\n\
limit_bit_blindings_{slot} = [sint.get_random() for _ in range(32)]\n\
securities_remainder_bit_blindings_{slot} = [sint.get_random() for _ in range(32)]\n\
cash_remainder_bit_blindings_{slot} = [sint.get_random() for _ in range(32)]\n\
maker_pool_remainder_bit_blindings_{slot} = [sint.get_random() for _ in range(32)]\n\
proof_{slot} = [sint({slot_plus_one}), trade_quantity_{slot}] + [sint(0) for _ in range(23)]\n\
proof_{slot} += [matched_{slot} * resting_handle_{slot}, trade_price_{slot}, fill_quantity_blinding_{slot}, trade_price_blinding_{slot}]\n\
proof_{slot} += [item for _b in range(32) for item in [qty_bits_{slot}[_b], qty_bit_blindings_{slot}[_b], qty_bit_blindings_{slot}[_b] * (1 - qty_bits_{slot}[_b])]]\n\
proof_{slot} += [item for _b in range(32) for item in [price_bits_{slot}[_b], price_bit_blindings_{slot}[_b], price_bit_blindings_{slot}[_b] * (1 - price_bits_{slot}[_b])]]\n\
proof_{slot} += [limit_difference_{slot}, limit_difference_blinding_{slot}]\n\
proof_{slot} += [item for _b in range(32) for item in [limit_bits_{slot}[_b], limit_bit_blindings_{slot}[_b], limit_bit_blindings_{slot}[_b] * (1 - limit_bits_{slot}[_b])]]\n\
proof_{slot} += [cash_{slot}, cash_blinding_{slot}, product_cross_{slot}, securities_remainder_{slot}, securities_remainder_blinding_{slot}]\n\
proof_{slot} += [item for _b in range(32) for item in [securities_remainder_bits_{slot}[_b], securities_remainder_bit_blindings_{slot}[_b], securities_remainder_bit_blindings_{slot}[_b] * (1 - securities_remainder_bits_{slot}[_b])]]\n\
proof_{slot} += [cash_remainder_{slot}, cash_remainder_blinding_{slot}]\n\
proof_{slot} += [item for _b in range(32) for item in [cash_remainder_bits_{slot}[_b], cash_remainder_bit_blindings_{slot}[_b], cash_remainder_bit_blindings_{slot}[_b] * (1 - cash_remainder_bits_{slot}[_b])]]\n\
proof_{slot} += [maker_pool_remainder_{slot}, maker_pool_remainder_blinding_{slot}]\n\
proof_{slot} += [item for _b in range(32) for item in [maker_pool_remainder_bits_{slot}[_b], maker_pool_remainder_bit_blindings_{slot}[_b], maker_pool_remainder_bit_blindings_{slot}[_b] * (1 - maker_pool_remainder_bits_{slot}[_b])]]\n\
settlement_proof_wires += proof_{slot}\n\
print_ln('OCLOB_SLOT_{slot}_MATCHED=%s', matched_{slot}.reveal())\n\
print_ln('OCLOB_SLOT_{slot}_PRICE=%s', trade_price_{slot}.reveal())\n\
print_ln('OCLOB_SLOT_{slot}_QUANTITY=%s', trade_quantity_{slot}.reveal())\n"
            , slot_plus_one = slot + 1
        ));
    }
    source.push_str(
        "published_remaining = remaining * arriving_can_rest\narriving_active_next = arriving_can_rest * (published_remaining > 0)\nprivate_book_wires += [arriving_active_next, arriving_side, arriving_price, published_remaining, arriving_price_blinding, arriving_reserve_remaining, arriving_reserve_blinding_remaining, arriving_handle]\nsint.write_to_file(private_book_wires + settlement_proof_wires)\nprint_ln('OCLOB_ARRIVING_REMAINING=%s', published_remaining.reveal())\n",
    );
    // Domain adapter only: the sorting network is the pinned upstream
    // Compiler.library.loopy_odd_even_merge_sort, not a local sorting core.
    source.push_str(
        "from Compiler.library import loopy_odd_even_merge_sort\ndepth = sint.Matrix(16, 4)\n",
    );
    for i in 0..=MAX_MATCH_SLOTS {
        source.push_str(&format!("depth_active_{i} = private_book_wires[{i} * 8] * (private_book_wires[{i} * 8 + 3] > 0)\ndepth_first_{i} = depth_active_{i}\ndepth_quantity_{i} = sint(0)\n"));
    }
    for i in 0..=MAX_MATCH_SLOTS {
        for j in 0..=MAX_MATCH_SLOTS {
            source.push_str(&format!("depth_same_{i}_{j} = depth_active_{j} * (private_book_wires[{i} * 8 + 1] == private_book_wires[{j} * 8 + 1]) * (private_book_wires[{i} * 8 + 2] == private_book_wires[{j} * 8 + 2])\ndepth_quantity_{i} += depth_same_{i}_{j} * private_book_wires[{j} * 8 + 3]\n"));
            if j < i {
                source.push_str(&format!("depth_first_{i} *= 1 - depth_same_{i}_{j}\n"));
            }
        }
        source.push_str(&format!("depth[{i}][1] = depth_first_{i} * private_book_wires[{i} * 8 + 1]\ndepth[{i}][2] = depth_first_{i} * private_book_wires[{i} * 8 + 2]\ndepth[{i}][3] = depth_first_{i} * depth_quantity_{i}\ndepth[{i}][0] = (1 - depth_first_{i}) * 2**34 + depth[{i}][1] * 2**33 + depth[{i}][1].if_else(depth[{i}][2], 2**32 - 1 - depth[{i}][2])\n"));
    }
    for i in MAX_MATCH_SLOTS + 1..16 {
        source.push_str(&format!(
            "depth[{i}] = [sint(2**34 + 2**32 - 1), sint(0), sint(0), sint(0)]\n"
        ));
    }
    source.push_str("loopy_odd_even_merge_sort(depth, key_indices=[0])\n");
    for i in 0..=MAX_MATCH_SLOTS {
        source.push_str(&format!("print_ln('OCLOB_LEVEL_{i}_SIDE=%s', depth[{i}][1].reveal())\nprint_ln('OCLOB_LEVEL_{i}_PRICE=%s', depth[{i}][2].reveal())\nprint_ln('OCLOB_LEVEL_{i}_QUANTITY=%s', depth[{i}][3].reveal())\n"));
    }
    Ok((header, source))
}

/// Parse and validate only the deliberately public matching result. Callers
/// must never forward the complete MP-SPDZ stdout because it could contain
/// diagnostics added by an unsafe local build.
pub fn parse_result(output: &str) -> Result<MpcBatchResult, String> {
    let value = |name: &str| -> Result<u64, String> {
        let prefix = format!("{name}=");
        let mut found = output
            .lines()
            .filter_map(|line| line.trim().strip_prefix(&prefix));
        let item = found.next().ok_or_else(|| format!("missing {name}"))?;
        if found.next().is_some() {
            return Err(format!("duplicate {name}"));
        }
        item.trim()
            .parse::<u64>()
            .map_err(|error| format!("invalid {name}: {error}"))
    };
    let mut slots = Vec::with_capacity(MAX_MATCH_SLOTS);
    for slot in 0..MAX_MATCH_SLOTS {
        let matched = value(&format!("OCLOB_SLOT_{slot}_MATCHED"))?;
        if matched > 1 {
            return Err(format!("slot {slot} match bit is outside zero or one"));
        }
        slots.push(MpcSlotResult {
            matched: matched == 1,
            trade_price: value(&format!("OCLOB_SLOT_{slot}_PRICE"))?,
            trade_quantity: value(&format!("OCLOB_SLOT_{slot}_QUANTITY"))?,
        });
    }
    let mut levels = Vec::new();
    let mut padding = false;
    for index in 0..=MAX_MATCH_SLOTS {
        let side = value(&format!("OCLOB_LEVEL_{index}_SIDE"))?;
        let price = value(&format!("OCLOB_LEVEL_{index}_PRICE"))?;
        let quantity = value(&format!("OCLOB_LEVEL_{index}_QUANTITY"))?;
        if quantity == 0 {
            if side != 0 || price != 0 {
                return Err("noncanonical public depth padding".into());
            }
            padding = true;
            continue;
        }
        if padding {
            return Err("active public level after padding".into());
        }
        let side = match side {
            0 => oclob_core::Side::Buy,
            1 => oclob_core::Side::Sell,
            _ => return Err("invalid public depth side".into()),
        };
        levels.push(oclob_core::MpcPriceLevel {
            side,
            price,
            quantity,
        });
    }
    oclob_core::validate_public_levels(&levels)?;
    Ok(MpcBatchResult {
        slots,
        arriving_remaining: value("OCLOB_ARRIVING_REMAINING")?,
        public_levels: Some(levels),
    })
}

/// Populate the settlement-only inputs required by the canonical circuit when
/// the legacy single-process runner is used by the browser demo or reference
/// state-machine tests. Distributed execution instead receives the actual
/// participant-generated VSS shares for all eight fields.
fn compatibility_private_values(input: &PrivateMatchBatch) -> Result<Vec<i128>, MpcError> {
    let reserve = |side: oclob_core::Side, price: u64, quantity: u64| {
        let value = match side {
            oclob_core::Side::Sell => quantity,
            oclob_core::Side::Buy => price
                .checked_mul(quantity)
                .ok_or_else(|| MpcError::Input("compatibility reserve overflowed".into()))?,
        };
        Ok::<i128, MpcError>(i128::from(value))
    };
    let mut values = Vec::with_capacity((MAX_MATCH_SLOTS + 1) * PRIVATE_ORDER_WIRES);
    for slot in 0..MAX_MATCH_SLOTS {
        if let Some(resting) = input.resting.get(slot) {
            values.extend([
                1,
                i128::from(resting.side.wire()),
                i128::from(resting.price),
                i128::from(resting.quantity),
                0,
                reserve(resting.side, resting.price, resting.quantity)?,
                0,
                (slot + 1) as i128,
            ]);
        } else {
            values.extend([0; PRIVATE_ORDER_WIRES]);
        }
    }
    values.extend([
        i128::from(input.arriving_side.wire()),
        i128::from(input.arriving_price),
        i128::from(input.arriving_quantity),
        i128::from(input.arriving_can_rest),
        0,
        reserve(
            input.arriving_side,
            input.arriving_price,
            input.arriving_quantity,
        )?,
        0,
        (MAX_MATCH_SLOTS + 1) as i128,
    ]);
    if values.len() != PRIVATE_BOOK_WIRES {
        return Err(MpcError::Input(
            "compatibility input does not match the canonical circuit width".into(),
        ));
    }
    Ok(values)
}

/// Domain-separated commitment to the public matching result.
pub fn public_output_digest(result: &MpcBatchResult) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(if result.public_levels.is_some() {
        b"OCLOB:MPC-PUBLIC-OUTPUT:v2"
    } else {
        b"OCLOB:MPC-PUBLIC-OUTPUT:v1"
    });
    for slot in &result.slots {
        hash.update([u8::from(slot.matched)]);
        hash.update(slot.trade_price.to_be_bytes());
        hash.update(slot.trade_quantity.to_be_bytes());
    }
    hash.update(result.arriving_remaining.to_be_bytes());
    if let Some(levels) = &result.public_levels {
        hash.update(public_depth_digest(levels));
    }
    hash.finalize().into()
}

pub fn public_depth_digest(levels: &[oclob_core::MpcPriceLevel]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:PUBLIC-PRICE-LEVELS:v1");
    hash.update((levels.len() as u64).to_be_bytes());
    for level in levels {
        hash.update([level.side.wire()]);
        hash.update(level.price.to_be_bytes());
        hash.update(level.quantity.to_be_bytes());
    }
    hash.finalize().into()
}

fn free_port_block(parties: usize) -> Result<u16, MpcError> {
    for _ in 0..128 {
        let base = 20_000 + rand::random::<u16>() % 35_000;
        let listeners = (0..parties)
            .map(|offset| TcpListener::bind(("127.0.0.1", base + offset as u16)))
            .collect::<Result<Vec<_>, _>>();
        if listeners.is_ok() {
            return Ok(base);
        }
    }
    Err(MpcError::Setup(
        "could not reserve a contiguous seven-port block".into(),
    ))
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Result<Self, MpcError> {
        let path = std::env::temp_dir().join(format!(
            "oclob-mpc-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Error)]
pub enum MpcError {
    #[error("MP-SPDZ setup failed: {0}")]
    Setup(String),
    #[error("MP-SPDZ compiler failed: {0}")]
    Compile(String),
    #[error("private input sharing failed: {0}")]
    Input(String),
    #[error("MP-SPDZ party {0} failed: {1}")]
    Party(usize, String),
    #[error("MP-SPDZ emitted no result")]
    NoOutput,
    #[error("the seven MP-SPDZ parties disagreed")]
    Disagreement,
    #[error("the MP-SPDZ round exceeded 300 seconds")]
    Timeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_mpc_prioritizes_secret_prices_then_original_time_in_both_directions() {
        use oclob_core::Side::{Buy, Sell};
        let root = std::env::var("MP_SPDZ_ROOT")
            .expect("real MPC regression requires the approved remote Docker image");
        let mut runner = MpcRunner::compile(root).unwrap();
        let cases = vec![
            (vec![(Sell, 101, 60), (Sell, 100, 60)], Buy, 101, 90, false),
            (vec![(Buy, 100, 60), (Buy, 101, 60)], Sell, 100, 90, false),
            (vec![(Sell, 100, 60), (Sell, 100, 60)], Buy, 101, 90, false),
            (vec![(Buy, 101, 60), (Buy, 101, 60)], Sell, 100, 90, false),
            (
                vec![
                    (Sell, 99, 50),
                    (Buy, 101, 20),
                    (Sell, 105, 80),
                    (Buy, 100, 10),
                ],
                Sell,
                100,
                25,
                false,
            ),
            (
                vec![(Buy, 105, 60), (Sell, 103, 60), (Sell, 100, 0)],
                Buy,
                101,
                90,
                true,
            ),
            (vec![(Sell, 100, 60)], Buy, 101, 90, true),
            (vec![(Sell, 100, 60)], Buy, 101, 90, false),
            (vec![], Buy, 101, 90, true),
            (
                vec![
                    (Sell, 105, 10),
                    (Sell, 100, 10),
                    (Sell, 102, 10),
                    (Sell, 103, 10),
                    (Sell, 101, 10),
                    (Sell, 100, 10),
                    (Sell, 107, 10),
                    (Sell, 104, 10),
                ],
                Buy,
                104,
                35,
                false,
            ),
        ];
        for (values, side, limit, quantity, can_rest) in cases {
            let input = PrivateMatchBatch {
                resting: values
                    .iter()
                    .enumerate()
                    .map(|(i, (side, price, quantity))| PrivateRestingInput {
                        commitment: OrderCommitment([i as u8 + 1; 32]),
                        side: *side,
                        price: *price,
                        quantity: *quantity,
                    })
                    .collect(),
                arriving_side: side,
                arriving_price: limit,
                arriving_quantity: quantity,
                arriving_can_rest: can_rest,
            };
            // Independent, clear unit oracle: stable price sorting followed by
            // ordinary greedy matching, not the circuit's pairwise formula.
            let mut priority = values
                .iter()
                .enumerate()
                .filter(|(_, v)| {
                    v.0 != side
                        && v.2 > 0
                        && if side == Buy {
                            v.1 <= limit
                        } else {
                            v.1 >= limit
                        }
                })
                .collect::<Vec<_>>();
            priority.sort_by(|(i, a), (j, b)| {
                if side == Buy {
                    a.1.cmp(&b.1).then(i.cmp(j))
                } else {
                    b.1.cmp(&a.1).then(i.cmp(j))
                }
            });
            let mut expected = vec![
                MpcSlotResult {
                    matched: false,
                    trade_price: 0,
                    trade_quantity: 0
                };
                values.len()
            ];
            let mut remaining = quantity;
            for (slot, (_, price, available)) in priority {
                let fill = remaining.min(*available);
                remaining -= fill;
                if fill > 0 {
                    expected[slot] = MpcSlotResult {
                        matched: true,
                        trade_price: *price,
                        trade_quantity: fill,
                    };
                }
            }
            let actual = runner.execute_batch(&input).unwrap();
            assert!(actual.all_parties_agreed);
            let mut depth = std::collections::BTreeMap::<(u8, u64), u64>::new();
            for ((side, price, quantity), fill) in values.iter().zip(&expected) {
                if *quantity > fill.trade_quantity {
                    *depth.entry((side.wire(), *price)).or_default() +=
                        quantity - fill.trade_quantity;
                }
            }
            if can_rest && remaining > 0 {
                *depth.entry((side.wire(), limit)).or_default() += remaining;
            }
            let mut levels = depth
                .into_iter()
                .map(|((side, price), quantity)| oclob_core::MpcPriceLevel {
                    side: if side == 0 { Buy } else { Sell },
                    price,
                    quantity,
                })
                .collect::<Vec<_>>();
            levels.sort_by_key(|v| {
                (
                    v.side.wire(),
                    if v.side == Buy {
                        u64::MAX - v.price
                    } else {
                        v.price
                    },
                )
            });
            assert_eq!(
                actual.result,
                MpcBatchResult {
                    slots: expected,
                    arriving_remaining: if can_rest { remaining } else { 0 },
                    public_levels: Some(levels),
                }
            );
        }
    }

    #[test]
    fn generated_program_has_no_public_order_input() {
        let source = matching_program().unwrap();
        assert_eq!(source.matches("sint.get_input_from").count(), 1);
        assert!(!source.contains("public_input"));
        assert!(!source.contains("malicious"));
        assert!(!source.contains("SLOT_0_REMAINING"));
        assert!(source.contains("published_remaining"));
        assert!(source.contains("sint.write_to_file(private_book_wires + settlement_proof_wires)"));
        let service = matching_service_program().unwrap();
        assert!(service.contains("@do_while\ndef _():\n    control = sint.get_input_from(0)\n"));
        assert!(service.ends_with(&format!(
            "    print_ln('{ROUND_END_MARKER}')\n    return regint(control.reveal())\n"
        )));
        let (header, body) = matching_program_parts().unwrap();
        assert_eq!(source, format!("{header}{body}"));
        // Every body line sits inside the loop body.
        let loop_start = service.find("def _():").unwrap();
        for line in service[loop_start..].lines().skip(1) {
            assert!(line.is_empty() || line.starts_with("    "), "{line}");
        }
        assert!(!service.contains("write_to_file"));
        assert!(service.contains("    # Persistence is kept by the single-shot form only.\n"));
        assert!(source.contains("resting_remaining_0"));
        assert!(source.contains("maker_pool_remainder_0"));
        assert!(source.contains("matched_0 * resting_handle_0"));
        assert_eq!(PRIVATE_BOOK_WIRES, 72);
        assert_eq!(SETTLEMENT_PROOF_WIRES_PER_FILL, 616);
        assert_eq!(PERSISTENCE_WIRES, 5_000);
    }

    #[test]
    fn compatibility_input_matches_eight_wire_order_schema() {
        let input = PrivateMatchBatch {
            resting: vec![PrivateRestingInput {
                commitment: OrderCommitment([1; 32]),
                side: oclob_core::Side::Sell,
                price: 100,
                quantity: 60,
            }],
            arriving_side: oclob_core::Side::Buy,
            arriving_price: 101,
            arriving_quantity: 40,
            arriving_can_rest: false,
        };
        let values = compatibility_private_values(&input).unwrap();
        assert_eq!(values.len(), PRIVATE_BOOK_WIRES);
        assert_eq!(values[5], 60);
        assert_eq!(values[MAX_MATCH_SLOTS * PRIVATE_ORDER_WIRES + 5], 4_040);
    }
}
