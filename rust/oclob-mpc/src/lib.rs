//! Rust orchestration for the OCLOB MP-SPDZ matching circuit.

#![forbid(unsafe_code)]

use oclob_core::{
    MpcBatchResult, MpcMatchResult, MpcSlotResult, OrderCommitment, PrivateMatchBatch,
    PrivateMatchInput, PrivateRestingInput, MAX_MATCH_SLOTS,
};
use qomm_mpc::compiler::OfficialCompiler;
use qomm_mpc::inputs::build_shamir_party_files_secure;
use qomm_mpc::program::{ed25519_lagrange_at_zero, ED25519_ORDER};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MPC_PARTIES: usize = 7;
pub const MAX_CORRUPT_NODES: usize = 2;

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
    binary: PathBuf,
    program: String,
    program_sha256: [u8; 32],
    compile_ms: f64,
    work: TempRoot,
    rounds: u64,
}

impl MpcRunner {
    pub fn compile(root: impl AsRef<Path>) -> Result<Self, MpcError> {
        let compiler = OfficialCompiler::from_checkout(root)
            .map_err(|error| MpcError::Setup(error.to_string()))?;
        let root = compiler.root().to_path_buf();
        let binary = root.join("malicious-shamir-party.x");
        if !binary.is_file() {
            return Err(MpcError::Setup(format!(
                "{} is absent; OCLOB never falls back to a clear matcher",
                binary.display()
            )));
        }
        let source = matching_program()?;
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
            binary,
            program,
            program_sha256,
            compile_ms: started.elapsed().as_secs_f64() * 1_000.0,
            work,
            rounds: 0,
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
        if input.resting.len() > MAX_MATCH_SLOTS {
            return Err(MpcError::Input(format!(
                "a batch supports at most {MAX_MATCH_SLOTS} resting slots"
            )));
        }
        let mut values = Vec::with_capacity(MAX_MATCH_SLOTS * 4 + 4);
        for slot in 0..MAX_MATCH_SLOTS {
            if let Some(resting) = input.resting.get(slot) {
                values.extend([
                    1,
                    i128::from(resting.side.wire()),
                    i128::from(resting.price),
                    i128::from(resting.quantity),
                ]);
            } else {
                values.extend([0, 0, 0, 0]);
            }
        }
        values.extend([
            i128::from(input.arriving_side.wire()),
            i128::from(input.arriving_price),
            i128::from(input.arriving_quantity),
            i128::from(input.arriving_can_rest),
        ]);
        let mut sharing_rng = OsRng;
        let party_files = build_shamir_party_files_secure(
            &values,
            MPC_PARTIES,
            MAX_CORRUPT_NODES,
            &mut sharing_rng,
        )
        .map_err(|error| MpcError::Input(error.to_string()))?;
        let round = self.work.0.join(format!("round-{}", self.rounds));
        fs::create_dir_all(&round)?;
        let input_prefix = round.join("Input");
        for (party, contents) in party_files.iter().enumerate() {
            fs::write(round.join(format!("Input-P{party}-0")), contents)?;
        }
        let port = free_port_block(MPC_PARTIES)?;
        let hosts = (0..MPC_PARTIES)
            .map(|party| format!("127.0.0.1:{}\n", port + party as u16))
            .collect::<String>();
        for party in 0..MPC_PARTIES {
            fs::write(round.join(format!("hosts-P{party}")), &hosts)?;
        }

        let started = Instant::now();
        let mut children = Vec::with_capacity(MPC_PARTIES);
        let mut logs = Vec::with_capacity(MPC_PARTIES);
        for party in 0..MPC_PARTIES {
            let log_path = round.join(format!("party-{party}.log"));
            let stdout = File::create(&log_path)?;
            let stderr = stdout.try_clone()?;
            let mut command = Command::new(&self.binary);
            command
                .current_dir(&self.root)
                .arg(party.to_string())
                .arg(&self.program)
                .args(["-N", &MPC_PARTIES.to_string()])
                .args(["-T", &MAX_CORRUPT_NODES.to_string()])
                .args(["-P", ED25519_ORDER])
                .arg("-ip")
                .arg(round.join(format!("hosts-P{party}")))
                .arg("-IF")
                .arg(&input_prefix)
                .args(["-OF", "."])
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr));
            children.push(
                command
                    .spawn()
                    .map_err(|error| MpcError::Party(party, error.to_string()))?,
            );
            logs.push(log_path);
        }
        wait_all(&mut children, Duration::from_secs(300))?;
        let execution_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let outputs = logs
            .iter()
            .map(|path| fs::read_to_string(path).map_err(MpcError::Io))
            .collect::<Result<Vec<_>, _>>()?;
        let parsed = outputs
            .iter()
            .enumerate()
            .map(|(party, output)| {
                parse_result(output).map_err(|message| MpcError::Party(party, message))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut first = parsed.first().cloned().ok_or(MpcError::NoOutput)?;
        if parsed.iter().any(|result| result != &first) {
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

fn matching_program() -> Result<String, MpcError> {
    let lagrange = ed25519_lagrange_at_zero(MPC_PARTIES)
        .map_err(|error| MpcError::Setup(error.to_string()))?
        .join(", ");
    let mut source = format!(
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
    for slot in 0..MAX_MATCH_SLOTS {
        source.push_str(&format!(
            "active_{slot} = secret_input()\nresting_side_{slot} = secret_input()\nresting_price_{slot} = secret_input()\nresting_quantity_{slot} = secret_input()\n"
        ));
    }
    source.push_str(
        "arriving_side = secret_input()\narriving_price = secret_input()\narriving_quantity = secret_input()\narriving_can_rest = secret_input()\nremaining = arriving_quantity\n",
    );
    for slot in 0..MAX_MATCH_SLOTS {
        source.push_str(&format!(
            "opposite_{slot} = resting_side_{slot} != arriving_side\n\
price_cross_{slot} = arriving_side.if_else(resting_price_{slot} >= arriving_price, arriving_price >= resting_price_{slot})\n\
positive_{slot} = (resting_quantity_{slot} > 0) * (remaining > 0)\n\
matched_{slot} = active_{slot} * opposite_{slot} * price_cross_{slot} * positive_{slot}\n\
minimum_{slot} = (resting_quantity_{slot} <= remaining).if_else(resting_quantity_{slot}, remaining)\n\
trade_quantity_{slot} = matched_{slot} * minimum_{slot}\n\
trade_price_{slot} = matched_{slot} * resting_price_{slot}\n\
remaining = remaining - trade_quantity_{slot}\n\
print_ln('OCLOB_SLOT_{slot}_MATCHED=%s', matched_{slot}.reveal())\n\
print_ln('OCLOB_SLOT_{slot}_PRICE=%s', trade_price_{slot}.reveal())\n\
print_ln('OCLOB_SLOT_{slot}_QUANTITY=%s', trade_quantity_{slot}.reveal())\n"
        ));
    }
    source.push_str(
        "published_remaining = remaining * arriving_can_rest\nprint_ln('OCLOB_ARRIVING_REMAINING=%s', published_remaining.reveal())\n",
    );
    Ok(source)
}

fn parse_result(output: &str) -> Result<MpcBatchResult, String> {
    let value = |name: &str| -> Result<u64, String> {
        let prefix = format!("{name}=");
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix))
            .ok_or_else(|| format!("missing {name}"))?
            .trim()
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
    Ok(MpcBatchResult {
        slots,
        arriving_remaining: value("OCLOB_ARRIVING_REMAINING")?,
    })
}

fn public_output_digest(result: &MpcBatchResult) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:MPC-PUBLIC-OUTPUT:v1");
    for slot in &result.slots {
        hash.update([u8::from(slot.matched)]);
        hash.update(slot.trade_price.to_be_bytes());
        hash.update(slot.trade_quantity.to_be_bytes());
    }
    hash.update(result.arriving_remaining.to_be_bytes());
    hash.finalize().into()
}

fn wait_all(children: &mut [Child], timeout: Duration) -> Result<(), MpcError> {
    let deadline = Instant::now() + timeout;
    let mut finished = vec![false; children.len()];
    loop {
        let mut remaining = 0;
        for (party, child) in children.iter_mut().enumerate() {
            if finished[party] {
                continue;
            }
            match child.try_wait()? {
                Some(status) if status.success() => finished[party] = true,
                Some(status) => {
                    for child in children.iter_mut() {
                        let _ = child.kill();
                    }
                    return Err(MpcError::Party(
                        party,
                        format!("exited with {}", status.code().unwrap_or(-1)),
                    ));
                }
                None => remaining += 1,
            }
        }
        if remaining == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            for child in children.iter_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(MpcError::Timeout);
        }
        thread::sleep(Duration::from_millis(10));
    }
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
    fn generated_program_has_no_public_order_input() {
        let source = matching_program().unwrap();
        assert_eq!(source.matches("sint.get_input_from").count(), 1);
        assert!(!source.contains("public_input"));
        assert!(!source.contains("malicious"));
        assert!(!source.contains("SLOT_0_REMAINING"));
        assert!(source.contains("published_remaining"));
    }
}
