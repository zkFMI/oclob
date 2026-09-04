//! Materialize the canonical circuit and invoke MP-SPDZ's official compiler.

use oclob_mpc::matching_program;
use qomm_mpc::compiler::OfficialCompiler;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("oclob-compile-program failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 4 || args[0] != "--root" || args[2] != "--program" {
        return Err("usage: oclob-compile-program --root MP_SPDZ --program NAME".into());
    }
    let root = PathBuf::from(&args[1]);
    let program = args[3]
        .to_str()
        .ok_or_else(|| "program name is not UTF-8".to_owned())?;
    if program.is_empty()
        || !program
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("program name is unsafe".into());
    }
    let compiler = OfficialCompiler::from_checkout(&root).map_err(|error| error.to_string())?;
    let source = matching_program().map_err(|error| error.to_string())?;
    let source_path = root.join("Programs/Source").join(format!("{program}.mpc"));
    fs::write(&source_path, source.as_bytes()).map_err(|error| error.to_string())?;
    let output = compiler
        .compile_field(253, program)
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .chars()
            .rev()
            .take(4_000)
            .collect::<String>()
            .chars()
            .rev()
            .collect());
    }
    let digest: [u8; 32] = Sha256::digest(source.as_bytes()).into();
    println!(
        "{{\"program\":\"{program}\",\"source_sha256\":\"{}\",\"compiler\":\"official MP-SPDZ compile.py\"}}",
        hex::encode(digest)
    );
    Ok(())
}
