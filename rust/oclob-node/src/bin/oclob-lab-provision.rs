//! Create an isolated seven-container OCLOB lab trust domain.
//!
//! This command is intentionally labelled `lab`: production operators create
//! their private keys independently and submit CSRs to an offline authority.

use ed25519_dalek::SigningKey;
use oclob_edge::{NodeDecryptionKey, MPC_PARTIES, SETTLEMENT_KEY_THRESHOLD};
use oclob_node::network::{
    certificate_fingerprint, ClientIdentityConfig, ClusterNodePublic, ClusterPublicConfig,
    PeerRole, Principal,
};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const PROGRAM: &str = "oclob_match_v1";
const MARKET: &str = "JGB10Y-JPY";
const RPC_PORT: u16 = 7443;
const PROOF_PORT: u16 = 8443;
const MPC_PORT: u16 = 5000;

fn main() {
    if let Err(error) = run() {
        eprintln!("oclob-lab-provision failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let output = parse_output()?;
    reject_existing(&output)?;
    let parent = output
        .parent()
        .ok_or_else(|| "output directory requires a parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = parent.join(format!(
        ".oclob-provision-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    reject_existing(&temporary)?;
    fs::create_dir(&temporary).map_err(|error| error.to_string())?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let cleanup = Cleanup(temporary.clone());
    provision(&temporary)?;
    fs::rename(&temporary, &output).map_err(|error| error.to_string())?;
    std::mem::forget(cleanup);
    println!(
        "{}",
        json!({
            "status": "provisioned",
            "nodes": MPC_PARTIES,
            "market": MARKET,
            "program": PROGRAM,
            "output": output,
            "warning": "lab authority generated all keys; production operators must generate node keys independently"
        })
    );
    Ok(())
}

fn provision(root: &Path) -> Result<(), String> {
    let public_dir = create_private_dir(root.join("public"))?;
    let maker_dir = create_private_dir(root.join("maker"))?;
    let taker_dir = create_private_dir(root.join("taker"))?;
    let coordinator_dir = create_private_dir(root.join("coordinator"))?;
    let settlement_dir = create_private_dir(root.join("settlement"))?;
    let (ca_key, ca_cert) = create_ca()?;
    write_public(&public_dir.join("ca.pem"), &ca_cert.to_pem().map_err(err)?)?;

    let maker_app = SigningKey::generate(&mut rand::rngs::OsRng);
    let taker_app = SigningKey::generate(&mut rand::rngs::OsRng);
    let coordinator_app = SigningKey::generate(&mut rand::rngs::OsRng);
    let settlement_app = SigningKey::generate(&mut rand::rngs::OsRng);
    let (maker_tls_key, maker_cert) = issue_leaf(&ca_key, &ca_cert, "oclob-maker", &[], false)?;
    let (taker_tls_key, taker_cert) = issue_leaf(&ca_key, &ca_cert, "oclob-taker", &[], false)?;
    let (coordinator_tls_key, coordinator_cert) =
        issue_leaf(&ca_key, &ca_cert, "oclob-coordinator", &[], false)?;
    let (settlement_tls_key, settlement_cert) =
        issue_leaf(&ca_key, &ca_cert, "oclob-settlement", &[], false)?;
    write_identity(
        &maker_dir,
        "/identity",
        &maker_tls_key,
        &maker_cert,
        maker_app.as_bytes(),
    )?;
    write_identity(
        &taker_dir,
        "/identity",
        &taker_tls_key,
        &taker_cert,
        taker_app.as_bytes(),
    )?;
    write_identity(
        &coordinator_dir,
        "/identity",
        &coordinator_tls_key,
        &coordinator_cert,
        coordinator_app.as_bytes(),
    )?;
    write_identity(
        &settlement_dir,
        "/settlement",
        &settlement_tls_key,
        &settlement_cert,
        settlement_app.as_bytes(),
    )?;
    let maker_fingerprint = certificate_fingerprint(&maker_cert.to_der().map_err(err)?);
    let taker_fingerprint = certificate_fingerprint(&taker_cert.to_der().map_err(err)?);
    let coordinator_fingerprint = certificate_fingerprint(&coordinator_cert.to_der().map_err(err)?);
    let settlement_fingerprint = certificate_fingerprint(&settlement_cert.to_der().map_err(err)?);
    let principals = vec![
        Principal {
            certificate_sha256: maker_fingerprint,
            role: PeerRole::Participant,
            application_key: maker_app.verifying_key().to_bytes(),
        },
        Principal {
            certificate_sha256: taker_fingerprint,
            role: PeerRole::Participant,
            application_key: taker_app.verifying_key().to_bytes(),
        },
        Principal {
            certificate_sha256: coordinator_fingerprint,
            role: PeerRole::Coordinator,
            application_key: coordinator_app.verifying_key().to_bytes(),
        },
        Principal {
            certificate_sha256: settlement_fingerprint,
            role: PeerRole::Settlement,
            application_key: settlement_app.verifying_key().to_bytes(),
        },
    ];
    let hosts = (0..MPC_PARTIES)
        .map(|party| format!("oclob-node-{party}:{MPC_PORT}"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let mut public_nodes = Vec::with_capacity(MPC_PARTIES);
    for party in 0..MPC_PARTIES {
        let name = format!("oclob-node-{party}");
        let node_dir = create_private_dir(root.join(format!("node-{party}")))?;
        let (tls_key, tls_cert) = issue_leaf(&ca_key, &ca_cert, &name, &[&name], true)?;
        let share_key = NodeDecryptionKey::generate().map_err(|error| error.to_string())?;
        let receipt_key = SigningKey::generate(&mut rand::rngs::OsRng);
        write_private(
            &node_dir.join("tls-key.pem"),
            &tls_key.private_key_to_pem_pkcs8().map_err(err)?,
        )?;
        write_public(&node_dir.join("tls.pem"), &tls_cert.to_pem().map_err(err)?)?;
        write_private(
            &node_dir.join("share-key.raw"),
            &share_key
                .raw_private_key()
                .map_err(|error| error.to_string())?,
        )?;
        write_private(&node_dir.join("receipt-key.raw"), receipt_key.as_bytes())?;
        let mut proof_state_passphrase = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut proof_state_passphrase);
        write_private(
            &node_dir.join("proof-state-passphrase.raw"),
            &proof_state_passphrase,
        )?;
        let defmi_receipt_secret: [u8; 32] =
            Sha256::digest(b"oclob-integrated-receipt-key-v1").into();
        let defmi_receipt_key = SigningKey::from_bytes(&defmi_receipt_secret);
        let trusted_defmi_id: [u8; 32] = Sha256::digest(b"oclob-integrated-defmi-v1").into();
        let config = json!({
            "version": 2,
            "party": party,
            "listen": format!("0.0.0.0:{RPC_PORT}"),
            "tls_certificate": "/node/tls.pem",
            "tls_private_key": "/node/tls-key.pem",
            "tls_ca": "/public/ca.pem",
            "principals": principals.clone(),
            "share_private_key": "/node/share-key.raw",
            "receipt_signing_key": "/node/receipt-key.raw",
            "cluster_public_config": "/public/cluster.json",
            "share_store": "/state/shares.bin",
            "ready_file": "/state/ready.json",
            "mp_spdz_root": "/opt/MP-SPDZ",
            "mpc_work_root": "/state/mpc",
            "program": PROGRAM,
            "mpc_hosts": hosts.clone(),
            "execution_timeout_seconds": 300,
            "rpc_timeout_seconds": 360,
            "max_connections": 64,
            "minimum_response_millis": 10,
            "proof_listen": format!("0.0.0.0:{PROOF_PORT}"),
            "proof_state_file": "/state/mpc/private-state/proof-state.qps",
            "proof_state_passphrase": "/node/proof-state-passphrase.raw",
            "trusted_defmi_id": hex::encode(trusted_defmi_id),
            "trusted_defmi_receipt_public": hex::encode(defmi_receipt_key.verifying_key().to_bytes())
        });
        write_json(&node_dir.join("config.json"), &config, 0o600)?;
        public_nodes.push(ClusterNodePublic {
            party: party as u16,
            host: name.clone(),
            rpc_port: RPC_PORT,
            proof_port: PROOF_PORT,
            server_name: name,
            tls_certificate_sha256: certificate_fingerprint(&tls_cert.to_der().map_err(err)?),
            share_encryption_key: share_key.public_key().map_err(|error| error.to_string())?,
            receipt_verifying_key: receipt_key.verifying_key().to_bytes(),
        });
    }
    let public = ClusterPublicConfig {
        version: 3,
        market_id: MARKET.into(),
        program: PROGRAM.into(),
        settlement_release_threshold: SETTLEMENT_KEY_THRESHOLD,
        nodes: public_nodes,
    };
    public.validate().map_err(|error| error.to_string())?;
    write_json(
        &public_dir.join("cluster.json"),
        &serde_json::to_value(public).map_err(err)?,
        0o644,
    )?;
    Ok(())
}

fn write_identity(
    directory: &Path,
    container_directory: &str,
    tls_key: &PKey<Private>,
    certificate: &X509,
    application_key: &[u8; 32],
) -> Result<(), String> {
    write_private(
        &directory.join("tls-key.pem"),
        &tls_key.private_key_to_pem_pkcs8().map_err(err)?,
    )?;
    write_public(
        &directory.join("tls.pem"),
        &certificate.to_pem().map_err(err)?,
    )?;
    write_private(&directory.join("application-key.raw"), application_key)?;
    let identity = ClientIdentityConfig {
        version: 1,
        tls_certificate: PathBuf::from(format!("{container_directory}/tls.pem")),
        tls_private_key: PathBuf::from(format!("{container_directory}/tls-key.pem")),
        tls_ca: PathBuf::from("/public/ca.pem"),
        application_signing_key: PathBuf::from(format!(
            "{container_directory}/application-key.raw"
        )),
    };
    identity.validate().map_err(|error| error.to_string())?;
    write_json(
        &directory.join("client.json"),
        &serde_json::to_value(identity).map_err(err)?,
        0o600,
    )
}

fn create_ca() -> Result<(PKey<Private>, X509), String> {
    let key = PKey::generate_ed25519().map_err(err)?;
    let mut name = X509NameBuilder::new().map_err(err)?;
    name.append_entry_by_nid(Nid::COMMONNAME, "OCLOB lab root")
        .map_err(err)?;
    let name = name.build();
    let mut builder = X509::builder().map_err(err)?;
    builder.set_version(2).map_err(err)?;
    set_serial(&mut builder)?;
    builder.set_subject_name(&name).map_err(err)?;
    builder.set_issuer_name(&name).map_err(err)?;
    builder.set_pubkey(&key).map_err(err)?;
    let not_before = Asn1Time::days_from_now(0).map_err(err)?;
    let not_after = Asn1Time::days_from_now(30).map_err(err)?;
    builder.set_not_before(&not_before).map_err(err)?;
    builder.set_not_after(&not_after).map_err(err)?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .map_err(err)?,
        )
        .map_err(err)?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(err)?,
        )
        .map_err(err)?;
    let subject = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .map_err(err)?;
    builder.append_extension(subject).map_err(err)?;
    builder.sign(&key, MessageDigest::null()).map_err(err)?;
    Ok((key, builder.build()))
}

fn issue_leaf(
    ca_key: &PKey<Private>,
    ca_cert: &X509,
    common_name: &str,
    dns_names: &[&str],
    server: bool,
) -> Result<(PKey<Private>, X509), String> {
    let key = PKey::generate_ed25519().map_err(err)?;
    let mut name = X509NameBuilder::new().map_err(err)?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .map_err(err)?;
    let name = name.build();
    let mut builder = X509::builder().map_err(err)?;
    builder.set_version(2).map_err(err)?;
    set_serial(&mut builder)?;
    builder.set_subject_name(&name).map_err(err)?;
    builder
        .set_issuer_name(ca_cert.subject_name())
        .map_err(err)?;
    builder.set_pubkey(&key).map_err(err)?;
    let not_before = Asn1Time::days_from_now(0).map_err(err)?;
    let not_after = Asn1Time::days_from_now(30).map_err(err)?;
    builder.set_not_before(&not_before).map_err(err)?;
    builder.set_not_after(&not_after).map_err(err)?;
    builder
        .append_extension(BasicConstraints::new().critical().build().map_err(err)?)
        .map_err(err)?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .map_err(err)?,
        )
        .map_err(err)?;
    let mut usage = ExtendedKeyUsage::new();
    usage.client_auth();
    if server {
        usage.server_auth();
    }
    builder
        .append_extension(usage.build().map_err(err)?)
        .map_err(err)?;
    if !dns_names.is_empty() {
        let mut names = SubjectAlternativeName::new();
        for dns in dns_names {
            names.dns(dns);
        }
        let extension = names
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .map_err(err)?;
        builder.append_extension(extension).map_err(err)?;
    }
    let authority = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .map_err(err)?;
    builder.append_extension(authority).map_err(err)?;
    builder.sign(ca_key, MessageDigest::null()).map_err(err)?;
    Ok((key, builder.build()))
}

fn set_serial(builder: &mut X509Builder) -> Result<(), String> {
    let mut serial = BigNum::new().map_err(err)?;
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .map_err(err)?;
    let serial = serial.to_asn1_integer().map_err(err)?;
    builder.set_serial_number(&serial).map_err(err)
}

fn create_private_dir(path: PathBuf) -> Result<PathBuf, String> {
    fs::create_dir(&path).map_err(|error| error.to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    Ok(path)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_bytes(path, bytes, 0o600)
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_bytes(path, bytes, 0o644)
}

fn write_json(path: &Path, value: &Value, mode: u32) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(err)?;
    bytes.push(b'\n');
    write_bytes(path, &bytes, mode)
}

fn write_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn reject_existing(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("refusing to overwrite {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn parse_output() -> Result<PathBuf, String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || args[0] != "--out" {
        return Err("usage: oclob-lab-provision --out DIRECTORY".into());
    }
    let output = PathBuf::from(&args[1]);
    if !output.is_absolute() {
        return Err("provisioning output must be an absolute path".into());
    }
    Ok(output)
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
