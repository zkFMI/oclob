//! Real lab-provision process checks. These prove startup admission and generated
//! configuration binding, not a seven-party financial settlement or PQ proof.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use zkfmi_crypto::mode::{DeploymentCryptoPolicy, PqcMode};
use zkfmi_crypto::suite::Version;

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "oclob-policy-cli-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn provision(path: &Path, mode: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oclob-lab-provision"));
    command.arg("--out").arg(path).stdin(Stdio::null());
    if let Some(mode) = mode {
        command.args(["--deployment-id", "oclob-cli-check", "--pqc-mode", mode]);
    }
    command.output().unwrap()
}

#[test]
fn on_and_missing_policy_fail_without_creating_a_cluster() {
    let temp = Temp::new();
    let output = temp.0.join("cluster");
    let missing = provision(&output, None);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("usage: oclob-lab-provision"));
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);

    let on = provision(&output, Some("on"));
    assert!(!on.status.success());
    assert!(String::from_utf8_lossy(&on.stderr).contains(
        "deployment requires a post-quantum proof backend; the selected OCLOB proof backend is not eligible"
    ));
    assert!(!output.exists());
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
}

#[test]
fn off_provisioning_binds_every_generated_configuration_to_one_policy() {
    let temp = Temp::new();
    let output = temp.0.join("cluster");
    let result = provision(&output, Some("off"));
    // Never put the generated native wallet configuration or key material in
    // assertion output, including when a future implementation changes stdout.
    assert!(result.status.success(), "Off lab provisioning failed");
    let expected = DeploymentCryptoPolicy {
        version: Version::V1,
        deployment_id: "oclob-cli-check".into(),
        mode: PqcMode::Off,
    };
    let marker = output.join(oclob_node::deployment_policy::STATE_POLICY_FILE);
    let original_marker = fs::read(&marker).unwrap();
    assert!(original_marker == expected.encode().unwrap());
    assert_eq!(
        fs::metadata(&marker).unwrap().permissions().mode() & 0o077,
        0
    );

    let mut configurations = vec![
        output.join("public/cluster.json"),
        output.join("public/market.json"),
        output.join("maker/native.json"),
        output.join("taker/native.json"),
    ];
    configurations.extend((0..7).map(|party| output.join(format!("node-{party}/config.json"))));
    for path in configurations {
        let config: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let policy: DeploymentCryptoPolicy = serde_json::from_value(
            config
                .get("deployment_crypto_policy")
                .expect("generated policy missing")
                .clone(),
        )
        .unwrap();
        assert!(policy == expected, "generated policy mismatch");
    }

    let repeated = provision(&output, Some("off"));
    assert!(!repeated.status.success());
    assert!(fs::read(marker).unwrap() == original_marker);
}
