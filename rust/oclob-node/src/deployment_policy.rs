//! Deployment-wide cryptographic policy and persistent-state admission guard.
//!
//! The policy comes from the operator-controlled cluster configuration.  It is
//! not negotiated by peers and it cannot be attached to an existing state tree.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zkfmi_crypto::mode::{DeploymentCryptoPolicy, ProofSecurity};

const MAX_POLICY_BYTES: u64 = 512;
pub const STATE_POLICY_FILE: &str = "deployment-crypto-policy.bin";

/// Require two independently supplied configurations to name the exact same
/// deployment policy.  The shared type owns the canonical equality rules.
pub fn require_same(
    expected: &DeploymentCryptoPolicy,
    actual: &DeploymentCryptoPolicy,
) -> Result<(), String> {
    expected
        .require_same(actual)
        .map_err(|_| "deployment cryptographic policies do not match".to_owned())
}

/// Existing OCLOB proof issuance is Pedersen/Bulletproofs/FROST based.  Every
/// current dispatch site calls this with `Classical`; an `On` deployment must
/// therefore stop before any proof state, key, or financial journal is opened.
/// A future backend must pass its reviewed security class from the actual
/// dispatch implementation rather than changing a configuration flag.
pub fn require_proof_backend(
    policy: &DeploymentCryptoPolicy,
    security: ProofSecurity,
) -> Result<(), String> {
    policy.require_proof_security(security).map_err(|_| {
        concat!(
            "deployment requires a post-quantum proof backend; ",
            "the selected OCLOB proof backend is not eligible"
        )
        .to_owned()
    })
}

pub fn marker_next_to(state: &Path) -> Result<PathBuf, String> {
    let parent = state
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "persistent state path has no parent".to_owned())?;
    Ok(parent.join(STATE_POLICY_FILE))
}

/// Provision a marker only for a genuinely fresh state boundary.  A missing
/// marker next to any pre-existing protected artifact is an explicit migration
/// requirement, never permission to retrofit the policy.
pub fn initialize_fresh_state(
    marker: &Path,
    policy: &DeploymentCryptoPolicy,
    protected: &[&Path],
) -> Result<(), String> {
    let expected = canonical(policy)?;
    if marker.exists() {
        return verify_marker_bytes(marker, &expected);
    }
    reject_symlink(marker)?;
    for path in protected {
        reject_symlink(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(format!(
                    concat!(
                        "policy-less existing state at {}; ",
                        "explicit authenticated migration is required"
                    ),
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    let parent = marker
        .parent()
        .ok_or_else(|| "deployment policy marker has no parent".to_owned())?;
    reject_symlink(parent)?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    reject_symlink(parent)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(marker)
        .map_err(|error| error.to_string())?;
    output
        .write_all(&expected)
        .map_err(|error| error.to_string())?;
    output.sync_all().map_err(|error| error.to_string())?;
    drop(output);
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    verify_marker_bytes(marker, &expected)
}

/// Normal restart path.  Absence is rejected even when the data file happens
/// to be absent: only the explicit fresh-state path may create this marker.
pub fn require_existing_state(
    marker: &Path,
    policy: &DeploymentCryptoPolicy,
) -> Result<(), String> {
    let expected = canonical(policy)?;
    if !marker.exists() {
        return Err(concat!(
            "persistent state has no deployment cryptographic policy; ",
            "explicit fresh provisioning or authenticated migration is required"
        )
        .to_owned());
    }
    verify_marker_bytes(marker, &expected)
}

fn canonical(policy: &DeploymentCryptoPolicy) -> Result<Vec<u8>, String> {
    policy
        .encode()
        .map_err(|_| "deployment cryptographic policy is invalid".to_owned())
}

fn verify_marker_bytes(marker: &Path, expected: &[u8]) -> Result<(), String> {
    reject_symlink(marker)?;
    let metadata = fs::metadata(marker).map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_POLICY_BYTES
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("deployment policy marker has unsafe type, size, or permissions".to_owned());
    }
    let mut actual = Vec::with_capacity(metadata.len() as usize);
    File::open(marker)
        .and_then(|mut file| file.read_to_end(&mut actual))
        .map_err(|error| error.to_string())?;
    if actual != expected {
        return Err(
            "persisted deployment cryptographic policy does not match startup policy".to_owned(),
        );
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("deployment policy paths must not be symbolic links".to_owned());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_policy() -> DeploymentCryptoPolicy {
    DeploymentCryptoPolicy {
        version: zkfmi_crypto::suite::Version::V1,
        deployment_id: "oclob-unit-deployment".into(),
        mode: zkfmi_crypto::mode::PqcMode::Off,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkfmi_crypto::mode::PqcMode;

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn temp() -> Temp {
        let path = std::env::temp_dir().join(format!(
            "oclob-deployment-policy-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        Temp(path)
    }

    #[test]
    fn exact_policy_survives_restart_and_rejects_changes() {
        let temp = temp();
        let marker = temp.0.join(STATE_POLICY_FILE);
        let state = temp.0.join("shares.bin");
        let off = test_policy();
        initialize_fresh_state(&marker, &off, &[&state]).unwrap();
        require_existing_state(&marker, &off).unwrap();
        let mut changed = off.clone();
        changed.mode = PqcMode::On;
        assert!(require_existing_state(&marker, &changed).is_err());
        changed = off.clone();
        changed.deployment_id = "another-deployment".into();
        assert!(require_existing_state(&marker, &changed).is_err());
    }

    #[test]
    fn policy_cannot_be_added_to_existing_state() {
        let temp = temp();
        let marker = temp.0.join(STATE_POLICY_FILE);
        let state = temp.0.join("shares.bin");
        fs::write(&state, b"preserved legacy state").unwrap();
        assert!(initialize_fresh_state(&marker, &test_policy(), &[&state]).is_err());
        assert!(!marker.exists());
    }

    #[test]
    fn post_quantum_mode_refuses_current_classical_proof_backend() {
        let off = test_policy();
        require_proof_backend(&off, ProofSecurity::Classical).unwrap();
        let mut on = off;
        on.mode = PqcMode::On;
        assert!(require_proof_backend(&on, ProofSecurity::Classical).is_err());
        require_proof_backend(&on, ProofSecurity::PostQuantum).unwrap();
    }
}
