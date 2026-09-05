//! Unit fixtures sign with local test keys. These do not substitute for the
//! native Docker acceptance against actual financial state and validators.
use crate::edge_client::{receipt_digest, EdgeAdmissionReceipt};
use crate::market_journal::MarketJournal;
use crate::market_network::MarketIngress;
use crate::network::{ClusterNodePublic, ClusterPublicConfig, NodeAdmissionReceipt};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use oclob_core::{SecretOrder, Side, TimeInForce};
use oclob_edge::{EdgeOrderBundle, NodeDecryptionKey, NodeEncryptionKey};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::Identity;
use std::fs;
use std::path::PathBuf;
use zkpi_defmi_sdk::admission::ReservationAdmission;
use zkpi_defmi_sdk::reservation::{ReservationPermit, ReservationRole};

pub(crate) fn fixture() -> (ClusterPublicConfig, MarketIngress, SigningKey) {
    let at = crate::market_runtime::now().unwrap();
    let node_keys: [NodeEncryptionKey; 7] =
        std::array::from_fn(|_| NodeDecryptionKey::generate().unwrap().public_key().unwrap());
    let signers: [SigningKey; 7] =
        std::array::from_fn(|i| SigningKey::from_bytes(&[i as u8 + 51; 32]));
    let cluster = ClusterPublicConfig {
        version: 4,
        market_id: "JGB10Y-JPY".into(),
        program: "oclob_match_v1".into(),
        settlement_release_threshold: 3,
        nodes: (0..7)
            .map(|i| ClusterNodePublic {
                party: i as u16,
                host: format!("unit-node-{i}"),
                rpc_port: 7443,
                proof_port: 8443,
                server_name: format!("unit-node-{i}"),
                tls_certificate_sha256: [i as u8 + 1; 32],
                share_encryption_key: node_keys[i].clone(),
                receipt_verifying_key: signers[i].verifying_key().to_bytes(),
            })
            .collect(),
    };
    let participant = Identity::from_seed([41; 32]).handle(b"defmi:oclob:v1");
    let order = SecretOrder::new(
        "JGB10Y-JPY",
        Side::Buy,
        101,
        40,
        TimeInForce::ImmediateOrCancel,
        at + 600,
        participant.point.compress().to_bytes(),
        [42; 32],
        [43; 32],
    )
    .unwrap();
    let issuer = SigningKey::from_bytes(&[44; 32]);
    let signer = SigningKey::from_bytes(&[45; 32]);
    let side_blinding = Scalar::from(46u64);
    let reserve_blinding = Scalar::from(47u64);
    let key = Pedersen::new(b"qomm:defmi:v1");
    let permit = ReservationPermit {
        version: 2,
        role: ReservationRole::Application,
        application_binding: zkpi_defmi_sdk::application::oclob_manifest_v1()
            .digest()
            .unwrap(),
        venue_id: [48; 32],
        defmi_id: [49; 32],
        canonical_state_root: [50; 32],
        accepted_height: 7,
        order_commitment: order.commitment().0,
        participant_handle: order.participant_handle(),
        entity_commitment: [75; 32],
        reservation_id: [51; 32],
        facility_id: [52; 32],
        asset_id: [53; 32],
        amount_commitment: key
            .commit(&Scalar::from(order.reservation_limit()), &reserve_blinding)
            .compress()
            .to_bytes(),
        escrow_note_id: [76; 32],
        delegation_digest: [77; 32],
        side_commitment: key
            .commit(
                &Scalar::from(u64::from(order.side().wire())),
                &side_blinding,
            )
            .compress()
            .to_bytes(),
        authority_digest: [54; 32],
        reserve_receipt_digest: [55; 32],
        reservation_sequence: 3,
        valid_until: at + 601,
        signer_public: issuer.verifying_key().to_bytes(),
        signature: Vec::new(),
    }
    .sign(&issuer)
    .unwrap();
    let reblinding = Scalar::from(101u64);
    let admission = ReservationAdmission::from_permit(&permit, &reblinding, &issuer).unwrap();
    let bundle = EdgeOrderBundle::create_with_reservation_admission(
        &order,
        &participant,
        [56; 32],
        &admission,
        &issuer.verifying_key(),
        side_blinding,
        reserve_blinding + reblinding,
        &signer,
        &node_keys,
        at,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let authority = bundle
        .seal_reservation_authority(&permit, &admission, reblinding, &mut rand::rngs::OsRng)
        .unwrap();
    let manifest = bundle.manifest().clone();
    let deliveries = bundle.into_deliveries();
    let shares = std::array::from_fn(|i| deliveries[i].1.wire_digest());
    let keys = std::array::from_fn(|i| deliveries[i].2.wire_digest());
    let generations = [1; 7];
    let receipts = (0..7)
        .map(|i| {
            NodeAdmissionReceipt::sign(
                i as u16,
                &manifest,
                shares[i],
                keys[i],
                1,
                [91; 32],
                &signers[i],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let receipt = EdgeAdmissionReceipt {
        version: 2,
        receipt_digest: receipt_digest(&manifest, &generations, &shares, &keys, &receipts),
        manifest,
        node_generations: generations,
        order_share_digests: shares,
        capability_key_share_digests: keys,
        node_receipts: receipts,
    };
    receipt.verify(&cluster, at).unwrap();
    (
        cluster,
        MarketIngress::sign(receipt, authority, &signer).unwrap(),
        signer,
    )
}
struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "oclob-market-unit-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("market.enc")
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exact_market_intake_survives_restart_and_late_ack_without_new_order() {
    let files = Files::new();
    let (cluster, input, _) = fixture();
    let at = crate::market_runtime::now().unwrap();
    assert!(MarketJournal::open(&files.path(), &[31; 32], &cluster, false).is_err());
    let journal = MarketJournal::open(&files.path(), &[31; 32], &cluster, true).unwrap();
    let sequence = journal.accept(&input, &cluster, at).unwrap();
    assert!(sequence > 0);
    let encrypted = fs::read(files.path()).unwrap();
    let signature = &input.signature;
    assert!(!encrypted.windows(signature.len()).any(|w| w == signature));
    drop(journal);
    let reopened = MarketJournal::open(&files.path(), &[31; 32], &cluster, false).unwrap();
    assert_eq!(
        reopened
            .accept(
                &input,
                &cluster,
                input.receipt.manifest.retention_deadline + 1
            )
            .unwrap(),
        sequence
    );
    assert_eq!(
        reopened.next().unwrap().unwrap().digest().unwrap(),
        input.digest().unwrap()
    );
    assert!(reopened.completed().unwrap().is_empty());
    assert!(MarketJournal::open(&files.path(), &[32; 32], &cluster, false).is_err());
    let mut other = cluster.clone();
    other.nodes[0].rpc_port += 1;
    assert!(MarketJournal::open(&files.path(), &[31; 32], &other, false).is_err());
}
#[test]
fn market_intake_rejects_tampering_missing_node_and_fresh_expired_receipt() {
    let files = Files::new();
    let (cluster, input, signer) = fixture();
    let at = crate::market_runtime::now().unwrap();
    let journal = MarketJournal::open(&files.path(), &[31; 32], &cluster, true).unwrap();
    let mut bad = input.clone();
    bad.signature[0] ^= 1;
    assert!(journal.accept(&bad, &cluster, at).is_err());
    let mut partial = input.receipt.clone();
    partial.node_receipts.pop();
    let bad = MarketIngress::sign(partial, input.authority.clone(), &signer).unwrap();
    assert!(journal.accept(&bad, &cluster, at).is_err());
    let mut value = serde_json::to_value(&input).unwrap();
    value["authority"]["ciphertext"][0] =
        serde_json::json!(value["authority"]["ciphertext"][0].as_u64().unwrap() ^ 1);
    let bad: MarketIngress = serde_json::from_value(value).unwrap();
    assert!(journal.accept(&bad, &cluster, at).is_err());
    assert!(journal
        .accept(
            &input,
            &cluster,
            input.receipt.manifest.retention_deadline + 1
        )
        .is_err());
    for field in ["capability_commitment", "order_commitment"] {
        let mut value = serde_json::to_value(&input.authority).unwrap();
        value[field] = serde_json::json!(vec![0; 32]);
        let wrong = MarketIngress::sign(
            input.receipt.clone(),
            serde_json::from_value(value).unwrap(),
            &signer,
        )
        .unwrap();
        assert!(journal.accept(&wrong, &cluster, at).is_err());
    }
    let mut value = serde_json::to_value(&input.authority).unwrap();
    value["ciphertext"].as_array_mut().unwrap().pop();
    let short = MarketIngress::sign(
        input.receipt.clone(),
        serde_json::from_value(value).unwrap(),
        &signer,
    )
    .unwrap();
    assert!(journal.accept(&short, &cluster, at).is_err());
    assert!(journal.next().unwrap().is_none());
}
#[test]
fn valid_order_key_cannot_replace_acknowledged_market_payload() {
    let files = Files::new();
    let (cluster, input, signer) = fixture();
    let at = crate::market_runtime::now().unwrap();
    let journal = MarketJournal::open(&files.path(), &[31; 32], &cluster, true).unwrap();
    journal.accept(&input, &cluster, at).unwrap();
    let mut value = serde_json::to_value(&input.authority).unwrap();
    value["ciphertext"][0] = serde_json::json!(value["ciphertext"][0].as_u64().unwrap() ^ 1);
    let other = MarketIngress::sign(
        input.receipt.clone(),
        serde_json::from_value(value).unwrap(),
        &signer,
    )
    .unwrap();
    assert!(journal.accept(&other, &cluster, at).is_err());
    assert_eq!(
        journal
            .ingress(input.receipt.commitment())
            .unwrap()
            .digest()
            .unwrap(),
        input.digest().unwrap()
    );
}
#[test]
fn market_worker_lock_and_first_saved_signed_request_survive_reopen() {
    let files = Files::new();
    let (cluster, _, _) = fixture();
    let first = MarketJournal::open(&files.path(), &[31; 32], &cluster, true).unwrap();
    let lock = first.acquire_worker().unwrap();
    let second = MarketJournal::open(&files.path(), &[31; 32], &cluster, false).unwrap();
    assert!(second.acquire_worker().is_err());
    assert_eq!(
        first
            .put("signed:unit", &vec![1u8, 2, 3], 1, u64::MAX)
            .unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(
        second
            .put("signed:unit", &vec![9u8, 8, 7], 1, u64::MAX)
            .unwrap(),
        vec![1, 2, 3]
    );
    drop(lock);
    assert!(second.acquire_worker().is_ok());
}
