//! Create an isolated seven-container OCLOB lab trust domain.
//!
//! This command is intentionally labelled `lab`: production operators create
//! their private keys independently and submit CSRs to an offline authority.

use curve25519_dalek::scalar::Scalar;
use defmi::note_chain::NoteOutput;
use defmi::notes::{NoteLedger, Wallet};
use oclob_core::application_crypto::SigningKey;
use oclob_edge::{
    ClaimAuthorizationEndpoint, NodeDecryptionKey, MPC_PARTIES, SETTLEMENT_KEY_THRESHOLD,
};
use oclob_node::corporate::CorporateNativeConfig;
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
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zkfmi_zk::pedersen::Pedersen;
use zkpi::handles::Identity;

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
    let defmi_dir = create_private_dir(root.join("defmi"))?;
    let market_dir = create_private_dir(root.join("market"))?;
    create_private_dir(market_dir.join("state"))?;
    create_private_dir(root.join("market-public"))?;
    let book_dir = create_private_dir(root.join("public-book"))?;
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
    let mut claim_authorization_endpoints = BTreeMap::new();
    for (directory, role, fingerprint) in [
        (&maker_dir, "maker", maker_fingerprint),
        (&taker_dir, "taker", taker_fingerprint),
    ] {
        let hostname = format!("oclob-{role}-api");
        let (key, certificate) = issue_leaf(&ca_key, &ca_cert, &hostname, &[&hostname], true)?;
        write_private(
            &directory.join("api-tls-key.pem"),
            &key.private_key_to_pem_pkcs8().map_err(err)?,
        )?;
        write_public(
            &directory.join("api-tls.pem"),
            &certificate.to_pem().map_err(err)?,
        )?;
        let certificate_sha256 = certificate_fingerprint(&certificate.to_der().map_err(err)?);
        let endpoint = oclob_node::market_network::MarketEndpoint {
            host: hostname.clone(),
            port: 9890,
            server_name: hostname.clone(),
            certificate_sha256,
        };
        let api = oclob_node::corporate_api::CorporateApiConfig {
            endpoint,
            clients: vec![fingerprint],
            claim_authorization_clients: vec![coordinator_fingerprint],
        };
        claim_authorization_endpoints.insert(
            role,
            ClaimAuthorizationEndpoint {
                host: hostname.clone(),
                port: 9890,
                server_name: hostname,
                certificate_sha256,
            },
        );
        write_json(
            &public_dir.join(format!("{role}-api.json")),
            &serde_json::to_value(api).map_err(err)?,
            0o644,
        )?;
    }
    let settlement_fingerprint = certificate_fingerprint(&settlement_cert.to_der().map_err(err)?);
    let (market_tls_key, market_cert) =
        issue_leaf(&ca_key, &ca_cert, "oclob-market", &["oclob-market"], true)?;
    write_private(
        &market_dir.join("tls-key.pem"),
        &market_tls_key.private_key_to_pem_pkcs8().map_err(err)?,
    )?;
    write_public(
        &market_dir.join("tls.pem"),
        &market_cert.to_pem().map_err(err)?,
    )?;
    let mut market_journal_key = [0u8; 32];
    let (book_key, book_cert) = issue_leaf(
        &ca_key,
        &ca_cert,
        "oclob-public-book",
        &["oclob-public-book"],
        true,
    )?;
    write_private(
        &book_dir.join("tls-key.pem"),
        &book_key.private_key_to_pem_pkcs8().map_err(err)?,
    )?;
    write_public(&book_dir.join("tls.pem"), &book_cert.to_pem().map_err(err)?)?;
    write_json(
        &public_dir.join("book-endpoint.json"),
        &serde_json::to_value(oclob_node::market_network::MarketEndpoint {
            host: "oclob-public-book".into(),
            port: 9446,
            server_name: "oclob-public-book".into(),
            certificate_sha256: certificate_fingerprint(&book_cert.to_der().map_err(err)?),
        })
        .map_err(err)?,
        0o644,
    )?;
    rand::rngs::OsRng.fill_bytes(&mut market_journal_key);
    write_private(&market_dir.join("journal-key.raw"), &market_journal_key)?;
    let market_config = oclob_node::market_network::MarketServiceConfig {
        endpoint: oclob_node::market_network::MarketEndpoint {
            host: "oclob-market".into(),
            port: 9445,
            server_name: "oclob-market".into(),
            certificate_sha256: certificate_fingerprint(&market_cert.to_der().map_err(err)?),
        },
        participants: vec![maker_fingerprint, taker_fingerprint],
        journal: PathBuf::from("/market/state.enc"),
        journal_key: PathBuf::from("/market-identity/journal-key.raw"),
        base_asset: oclob_settlement::canonical_securities_asset_id(MARKET),
        quote_asset: oclob_settlement::canonical_cash_asset_id(),
    };
    write_json(
        &public_dir.join("market.json"),
        &serde_json::to_value(market_config).map_err(err)?,
        0o644,
    )?;
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
    let native_receipt_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut private_tag_key = zeroize::Zeroizing::new([0; 32]);
    rand::rngs::OsRng.fill_bytes(private_tag_key.as_mut());
    write_private(
        &defmi_dir.join("admission-tag-key.raw"),
        private_tag_key.as_ref(),
    )?;
    write_private(
        &defmi_dir.join("receipt-key.raw"),
        &native_receipt_key.to_bytes(),
    )?;
    write_json(
        &public_dir.join("native-issuer.json"),
        &json!(native_receipt_key.hybrid_public_key()),
        0o644,
    )?;
    let (defmi_tls_key, defmi_tls_cert) =
        issue_leaf(&ca_key, &ca_cert, "oclob-defmi", &["oclob-defmi"], true)?;
    write_private(
        &defmi_dir.join("tls-key.pem"),
        &defmi_tls_key.private_key_to_pem_pkcs8().map_err(err)?,
    )?;
    write_public(
        &defmi_dir.join("tls.pem"),
        &defmi_tls_cert.to_pem().map_err(err)?,
    )?;
    let mut defmi_principals = principals.clone();
    let key = Pedersen::new(b"qomm:defmi:v1");
    let (_, issuer) = oclob_dekyx::deterministic_demo_environment(MARKET).map_err(err)?;
    let mut funding = Vec::new();
    let mut corporate_journals = Vec::new();
    for (directory, role, seed, label, asset, amount) in [
        (
            &maker_dir,
            "maker",
            11,
            "distributed-maker",
            oclob_settlement::canonical_securities_asset_id(MARKET),
            120_u64,
        ),
        (
            &taker_dir,
            "taker",
            22,
            "distributed-taker",
            oclob_settlement::canonical_cash_asset_id(),
            10_000_u64,
        ),
    ] {
        let mut identity_seed = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut identity_seed);
        let handle = Identity::from_seed(identity_seed).handle(b"defmi:oclob:v1");
        let spend = Scalar::random(&mut rand::rngs::OsRng);
        let mut opening_seed = zeroize::Zeroizing::new([0; 96]);
        rand::rngs::OsRng.fill_bytes(opening_seed.as_mut());
        let mut custody_seed = zeroize::Zeroizing::new([0; 96]);
        rand::rngs::OsRng.fill_bytes(custody_seed.as_mut());
        let wallet = Wallet::from_parts(
            handle.secret,
            spend,
            zkfmi_crypto::hybrid::kem::HybridKemKey::from_seed(&opening_seed),
        );
        let capacity_blind = Scalar::random(&mut rand::rngs::OsRng);
        let facility: [u8; 32] =
            Sha256::digest([b"OCLOB:LAB:NATIVE-FACILITY:v1".as_slice(), label.as_bytes()].concat())
                .into();
        let config = CorporateNativeConfig {
            host: "oclob-defmi".into(),
            port: 9443,
            server_name: "oclob-defmi".into(),
            claim_authorization_endpoint: claim_authorization_endpoints
                .get(role)
                .ok_or("corporate claim authorization endpoint is absent")?
                .clone(),
            venue_id: Sha256::digest(b"defmi:oclob:v1").into(),
            defmi_id: Sha256::digest(b"oclob-integrated-defmi-v1").into(),
            issuer_public: native_receipt_key.hybrid_public_key(),
            facility_id: facility,
            asset_id: asset,
            facility_values: [amount, 0, 0],
            facility_blindings: [capacity_blind.to_bytes(), [0; 32], [0; 32]],
            wallet_spend_secret: spend.to_bytes(),
            wallet_opening_seed: opening_seed.to_vec(),
            credential_custody_seed: custody_seed.to_vec(),
            identity_seed,
        };
        write_json(
            &directory.join("native.json"),
            &serde_json::to_value(&config).map_err(err)?,
            0o600,
        )?;
        let mut journal_key = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut journal_key);
        write_private(&directory.join("outbox-key.raw"), &journal_key)?;
        create_private_dir(directory.join("queue"))?;
        write_json(
            &directory.join("queue/queued-expiry-order.json"),
            &json!({"side": "sell", "limit_price": 102, "quantity": 5,
                "time_in_force": "good_til_cancelled", "valid_for_seconds": 45}),
            0o600,
        )?;
        write_json(
            &directory.join("queue/cycle-order.json"),
            &json!({
                "side": "buy", "limit_price": 104, "quantity": 90,
                "time_in_force": "immediate_or_cancel", "valid_for_seconds": 1200
            }),
            0o600,
        )?;
        // Owner-private, production-shaped orders for the separate two-fill
        // acceptance. The first maker request remains the original 60 @ 100.
        write_json(
            &directory.join("queue/multifill-order.json"),
            &json!({
                "side": if seed == 11 { "sell" } else { "buy" },
                "limit_price": 101, "quantity": if seed == 11 { 60 } else { 90 },
                "time_in_force": if seed == 11 { "good_til_cancelled" } else { "immediate_or_cancel" },
                "valid_for_seconds": 600
            }),
            0o600,
        )?;
        // The API signing client has its own durable outbox, never a mount of
        // the service's journal, dispatch queue, or reservation history.
        let client_name = if seed == 11 {
            "maker-client"
        } else {
            "taker-client"
        };
        let client_dir = create_private_dir(root.join(client_name))?;
        let client_state = create_private_dir(root.join(format!("{client_name}-state")))?;
        for name in [
            "tls.pem",
            "tls-key.pem",
            "application-key.raw",
            "client.json",
            "native.json",
        ] {
            write_private(
                &client_dir.join(name),
                &fs::read(directory.join(name)).map_err(err)?,
            )?;
        }
        let mut client_journal_key = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_journal_key);
        write_private(&client_dir.join("outbox-key.raw"), &client_journal_key)?;
        for (name, price, quantity) in if seed == 11 {
            vec![
                ("depth-high-order.json", 101, 30),
                ("depth-low1-order.json", 100, 30),
                ("depth-low2-order.json", 100, 60),
            ]
        } else {
            vec![("depth-buy-order.json", 101, 75)]
        } {
            write_json(
                &directory.join("queue").join(name),
                &json!({"side":if seed == 11 {"sell"} else {"buy"},
                "limit_price":price,"quantity":quantity,"time_in_force":if seed == 11 {"good_til_cancelled"} else {"immediate_or_cancel"},
                "valid_for_seconds":1200}),
                0o600,
            )?;
            write_private(
                &client_state.join(name),
                &fs::read(directory.join("queue").join(name)).map_err(err)?,
            )?;
        }
        if seed == 11 {
            for (name, price) in [
                ("market-high-order.json", 101),
                ("market-low-order.json", 100),
            ] {
                write_json(
                    &directory.join("queue").join(name),
                    &json!({"side":"sell","limit_price":price,"quantity":60,
                    "time_in_force":"good_til_cancelled","valid_for_seconds":1200}),
                    0o600,
                )?;
            }
        }
        write_json(
            &directory.join("queue/over-capacity-order.json"),
            &json!({"side":"sell", "limit_price":101, "quantity":70,
                "time_in_force":"good_til_cancelled", "valid_for_seconds":600}),
            0o600,
        )?;
        let credential = issuer
            .issue_wallet(seed, label.as_bytes(), &mut rand::rngs::OsRng)
            .map_err(err)?;
        let encrypted_credential = credential
            .seal_custody(&zkfmi_crypto::traits::KemDecapsulator::public_key(
                &config.credential_custody_key()?,
            ))
            .map_err(err)?;
        corporate_journals.push((
            client_state.join("outbox.enc"),
            client_journal_key,
            config.clone(),
            credential.scope_digest(),
            encrypted_credential.clone(),
            false,
        ));
        corporate_journals.push((
            directory.join("queue/outbox.enc"),
            journal_key,
            config,
            credential.scope_digest(),
            encrypted_credential,
            true,
        ));
        let enrollment = credential
            .present([31; 32], [32; 32], 253_402_300_798, &mut rand::rngs::OsRng)
            .map_err(err)?;
        let ledger = NoteLedger::new(key.clone(), 32);
        let decoy = Wallet::new(&mut rand::rngs::OsRng);
        let notes = [(&wallet.address, amount), (&decoy.address, 25)]
            .into_iter()
            .map(|(address, value)| {
                let blind = Scalar::random(&mut rand::rngs::OsRng);
                let note = ledger.build_note(
                    address,
                    value,
                    key.commit_u64(value, &blind),
                    &blind,
                    &mut rand::rngs::OsRng,
                )?;
                NoteOutput::from_note(&note, asset, [0; 32])?.body()
            })
            .collect::<Result<Vec<_>, String>>()?;
        funding.push(json!({"asset": asset, "facility": facility,
            "entity": enrollment.subject_line_id().map_err(err)?,
            "capacity": key.commit_u64(amount, &capacity_blind).compress().to_bytes(), "notes": notes}));
    }
    write_json(&defmi_dir.join("funding.json"), &json!(funding), 0o600)?;
    let hosts = (0..MPC_PARTIES)
        .map(|party| format!("oclob-node-{party}:{MPC_PORT}"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let recipient_opening_keys = corporate_journals
        .iter()
        .filter(|journal| journal.5)
        .map(|(_, _, config, _, _, _)| {
            let view = Identity::from_seed(config.identity_seed)
                .handle(b"defmi:oclob:v1")
                .point
                .compress()
                .to_bytes();
            Ok(zkpi_committee::proof_party::RecipientOpeningKey {
                view,
                public: zkfmi_crypto::traits::KemDecapsulator::public_key(
                    &config.note_opening_key()?,
                ),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if recipient_opening_keys.len() != 2
        || recipient_opening_keys[0].view == recipient_opening_keys[1].view
    {
        return Err(
            "recipient opening directory must contain one distinct key per custody service".into(),
        );
    }
    let mut public_nodes = Vec::with_capacity(MPC_PARTIES);
    for party in 0..MPC_PARTIES {
        let name = format!("oclob-node-{party}");
        let node_dir = create_private_dir(root.join(format!("node-{party}")))?;
        let (tls_key, tls_cert) = issue_leaf(&ca_key, &ca_cert, &name, &[&name], true)?;
        let share_key = NodeDecryptionKey::generate().map_err(|error| error.to_string())?;
        let receipt_key = SigningKey::generate(&mut rand::rngs::OsRng);
        // Each MPC node observes finality with its own certificate. Operator
        // has read access only; these identities cannot submit chain writes.
        defmi_principals.push(Principal {
            certificate_sha256: certificate_fingerprint(&tls_cert.to_der().map_err(err)?),
            role: PeerRole::Operator,
            application_key: receipt_key.verifying_key().to_bytes(),
        });
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
        let trusted_defmi_id: [u8; 32] = Sha256::digest(b"oclob-integrated-defmi-v1").into();
        let trusted_venue_id: [u8; 32] = Sha256::digest(b"defmi:oclob:v1").into();
        let config = json!({
            "version": 4,
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
            "recipient_opening_keys": recipient_opening_keys,
            "proof_state_passphrase": "/node/proof-state-passphrase.raw",
            "trusted_defmi_id": hex::encode(trusted_defmi_id),
            "native_finality_endpoint": { "host": "oclob-defmi", "port": 9443, "server_name": "oclob-defmi" },
            "trusted_reservation_venue_id": hex::encode(trusted_venue_id),
            "trusted_defmi_receipt_public": hex::encode(native_receipt_key.hybrid_public_key()),
            "qomm_pretrade_ack_fingerprint": null
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
    write_json(
        &defmi_dir.join("principals.json"),
        &serde_json::to_value(&defmi_principals).map_err(err)?,
        0o600,
    )?;
    let public = ClusterPublicConfig {
        version: 5,
        market_id: MARKET.into(),
        program: PROGRAM.into(),
        settlement_release_threshold: SETTLEMENT_KEY_THRESHOLD,
        nodes: public_nodes,
    };
    public.validate().map_err(|error| error.to_string())?;
    write_json(
        &public_dir.join("cluster.json"),
        &serde_json::to_value(&public).map_err(err)?,
        0o644,
    )?;
    for (path, key, config, scope, credential, dispatch) in corporate_journals {
        if dispatch {
            oclob_node::corporate_dispatch::NativeCorporateDispatch::initialize(
                path.with_file_name("dispatch.enc"),
                &key,
            )?;
        }
        let journal = oclob_node::corporate_journal::NativeCorporateJournal::initialize(
            path, &key, &config, &public,
        )?;
        journal.enroll_eligibility(&config, scope, &credential)?;
    }
    Ok(())
}

fn write_identity(
    directory: &Path,
    container_directory: &str,
    tls_key: &PKey<Private>,
    certificate: &X509,
    application_key: &[u8; 64],
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
        version: 2,
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
    let key = zkfmi_crypto::tls::generate_authentication_key().map_err(err)?;
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
    let key = zkfmi_crypto::tls::generate_authentication_key().map_err(err)?;
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
