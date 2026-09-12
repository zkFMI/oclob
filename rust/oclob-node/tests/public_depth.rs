//! Unit-level verifier regressions using captured public MPC fields re-signed
//! with current hybrid application keys. These are not deployment evidence.
use oclob_core::application_crypto::{Signer, SigningKey, SIGNATURE_BYTES};
use oclob_mpc::{matching_program, public_depth_digest};
use oclob_node::network::{ClusterNodePublic, ClusterPublicConfig};
use oclob_node::public_depth::{publish, read, FinalizedPublicBook, MAX_PUBLIC_BOOK_BYTES};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Fixture {
    book: FinalizedPublicBook,
}
fn captured_book() -> FinalizedPublicBook {
    let f: Fixture =
        serde_json::from_str(include_str!("fixtures/public_depth_rough001.json")).unwrap();
    f.book
}

fn cluster_for(book: &FinalizedPublicBook) -> ClusterPublicConfig {
    ClusterPublicConfig {
        version: 6,
        deployment_crypto_policy: zkfmi_crypto::mode::DeploymentCryptoPolicy {
            version: zkfmi_crypto::suite::Version::V1,
            deployment_id: "public-depth-unit".into(),
            mode: zkfmi_crypto::mode::PqcMode::Off,
        },
        market_id: book.market_id.clone(),
        program: "oclob_match_v1".into(),
        settlement_release_threshold: 3,
        nodes: book
            .attestations
            .iter()
            .map(|a| ClusterNodePublic {
                party: a.party,
                host: "unit-test.invalid".into(),
                rpc_port: 7443,
                proof_port: 8443,
                server_name: "unit-test.invalid".into(),
                tls_certificate_sha256: [1; 32],
                share_encryption_key: oclob_edge::NodeDecryptionKey::generate()
                    .unwrap()
                    .public_key()
                    .unwrap(),
                receipt_verifying_key: a.signer,
            })
            .collect(),
    }
}

fn current_fixture(settlement_required: bool) -> (ClusterPublicConfig, FinalizedPublicBook, u64) {
    let mut book = captured_book();
    book.version = 2;
    if !settlement_required {
        book.finality_receipts.clear();
    }
    let book_digest = public_depth_digest(&book.levels);
    let program_sha256: [u8; 32] = Sha256::digest(matching_program().unwrap().as_bytes()).into();
    let keys = (0..book.attestations.len())
        .map(|party| {
            let mut seeds = [party as u8 + 1; 64];
            seeds[32..].fill(party as u8 + 101);
            SigningKey::from_bytes(&seeds)
        })
        .collect::<Vec<_>>();
    for (party, attestation) in book.attestations.iter_mut().enumerate() {
        let key = &keys[party];
        attestation.version = 2;
        attestation.book_digest = book_digest;
        attestation.program_sha256 = program_sha256;
        attestation.settlement_required = settlement_required;
        attestation.signer = key.verifying_key().to_bytes();
        let encoded = serde_json::to_vec(&(
            attestation.version,
            attestation.party,
            &attestation.market_id,
            attestation.sequence,
            attestation.round_id,
            attestation.book_digest,
            attestation.public_output_sha256,
            attestation.program_sha256,
            attestation.state_commitment,
            attestation.issued_at,
            attestation.valid_until,
            attestation.settlement_required,
            attestation.signer,
        ))
        .unwrap();
        attestation.signature = key
            .try_sign(&[b"OCLOB:PUBLIC-DEPTH-ATTESTATION:v2".as_slice(), &encoded].concat())
            .unwrap()
            .to_bytes();
    }
    for (party, receipt) in book.finality_receipts.iter_mut().enumerate() {
        let key = &keys[party];
        receipt.version = 4;
        receipt.signer = key.verifying_key().to_bytes();
        receipt.signature = key
            .try_sign(
                &[
                    b"OCLOB:NODE-PRIVATE-STATE-RECEIPT:v2".as_slice(),
                    &receipt.version.to_be_bytes(),
                    &receipt.party.to_be_bytes(),
                    &receipt.round_id,
                    &receipt.private_state_sha256,
                    &receipt.transition_digest,
                    &receipt.canonical_receipt_digest,
                    &receipt.canonical_height.to_be_bytes(),
                    &receipt.generation.to_be_bytes(),
                    &receipt.state_digest,
                    &receipt.signer,
                ]
                .concat(),
            )
            .unwrap()
            .to_bytes();
    }
    let cluster = cluster_for(&book);
    let at = book.attestations[0].issued_at;
    (cluster, book, at)
}

fn fixture() -> (ClusterPublicConfig, FinalizedPublicBook, u64) {
    current_fixture(true)
}

#[test]
fn captured_ed25519_fixture_is_legacy_and_rejected() {
    let book = captured_book();
    assert_eq!(book.version, 1);
    assert!(book
        .attestations
        .iter()
        .all(|value| value.signature.len() == 64));
    assert!(book
        .finality_receipts
        .iter()
        .all(|value| value.signature.len() == 64));
    let cluster = cluster_for(&book);
    assert!(book
        .verify(&cluster, book.attestations[0].issued_at, 4)
        .is_err());
}

#[test]
fn current_hybrid_unmatched_and_matched_books_fit_the_shared_cap() {
    let (unmatched_cluster, unmatched, unmatched_at) = current_fixture(false);
    let (matched_cluster, matched, matched_at) = current_fixture(true);
    unmatched
        .verify(&unmatched_cluster, unmatched_at, 4)
        .unwrap();
    matched.verify(&matched_cluster, matched_at, 4).unwrap();
    assert!(unmatched
        .attestations
        .iter()
        .all(|value| value.signature.len() == SIGNATURE_BYTES));
    assert!(matched
        .finality_receipts
        .iter()
        .all(|value| value.signature.len() == SIGNATURE_BYTES));
    let unmatched_wire = serde_json::to_vec(&unmatched).unwrap();
    let matched_wire = serde_json::to_vec(&matched).unwrap();
    assert!(unmatched_wire.len() > 128 * 1024);
    assert!(matched_wire.len() > 256 * 1024);
    assert!(unmatched_wire.len() <= MAX_PUBLIC_BOOK_BYTES);
    assert!(matched_wire.len() <= MAX_PUBLIC_BOOK_BYTES);
}

#[test]
fn captured_mpc_fields_authenticate_with_current_hybrid_signatures() {
    let (cluster, book, at) = fixture();
    book.verify(&cluster, at, 4).unwrap();
    assert_eq!(
        book.levels
            .iter()
            .map(|v| (v.price, v.quantity))
            .collect::<Vec<_>>(),
        vec![(100, 15), (101, 30)]
    );
    assert_eq!(book.finality_receipts.len(), 7);
}
#[test]
fn public_book_rejects_tamper_missing_duplicate_or_mismatched_signers() {
    let (cluster, book, at) = fixture();
    let mut candidates = Vec::new();
    let mut b = book.clone();
    b.levels[0].quantity += 1;
    candidates.push(b);
    let mut b = book.clone();
    b.levels.swap(0, 1);
    candidates.push(b);
    let mut b = book.clone();
    b.levels.push(b.levels[0].clone());
    candidates.push(b);
    let mut b = book.clone();
    b.attestations.pop();
    candidates.push(b);
    let mut b = book.clone();
    b.attestations[1] = b.attestations[0].clone();
    candidates.push(b);
    let mut b = book.clone();
    b.sequence += 1;
    candidates.push(b);
    let mut b = book.clone();
    b.market_id.push('x');
    candidates.push(b);
    let mut b = book.clone();
    b.attestations[0].program_sha256[0] ^= 1;
    candidates.push(b);
    let mut b = book.clone();
    b.attestations[0].public_output_sha256[0] ^= 1;
    candidates.push(b);
    let mut b = book.clone();
    b.attestations[0].signature[0] ^= 1;
    candidates.push(b);
    for b in candidates {
        assert!(b.verify(&cluster, at, 4).is_err());
    }
    let mut other = cluster.clone();
    other.nodes[0].receipt_verifying_key =
        oclob_core::application_crypto::SigningKey::from_bytes(&[77; 64])
            .verifying_key()
            .to_bytes();
    assert!(book.verify(&other, at, 4).is_err());
}
#[test]
fn matched_book_requires_complete_bound_canonical_finality() {
    let (cluster, book, at) = fixture();
    let mut candidates = Vec::new();
    let mut b = book.clone();
    b.finality_receipts.clear();
    candidates.push(b);
    let mut b = book.clone();
    b.finality_receipts.pop();
    candidates.push(b);
    let mut b = book.clone();
    b.finality_receipts[1] = b.finality_receipts[0].clone();
    candidates.push(b);
    let mut b = book.clone();
    b.finality_receipts[0].canonical_height += 1;
    candidates.push(b);
    let mut b = book.clone();
    b.finality_receipts[0].canonical_receipt_digest[0] ^= 1;
    candidates.push(b);
    let mut b = book.clone();
    b.finality_receipts[0].private_state_sha256[0] ^= 1;
    candidates.push(b);
    let mut b = book.clone();
    b.attestations[0].settlement_required = false;
    candidates.push(b);
    for b in candidates {
        assert!(b.verify(&cluster, at, 4).is_err());
    }
}
#[test]
fn stale_future_and_rolled_back_public_books_are_not_current_data() {
    let (cluster, book, at) = fixture();
    assert!(book.verify(&cluster, at - 1, 4).is_err());
    assert!(book
        .verify(&cluster, book.attestations[0].valid_until + 1, 4)
        .is_err());
    assert!(book.verify(&cluster, at, 5).is_err());
    let mut wire = serde_json::to_value(&book).unwrap();
    wire["participant_id"] = "not allowed".into();
    assert!(serde_json::from_value::<FinalizedPublicBook>(wire).is_err());
}
#[test]
fn atomic_export_round_trip_is_idempotent_and_missing_is_not_empty_book() {
    let (_, book, _) = fixture();
    let root = std::env::temp_dir().join(format!(
        "oclob-public-depth-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("current.json");
    assert!(read(&path).unwrap().is_none());
    publish(&path, &book).unwrap();
    let first = std::fs::read(&path).unwrap();
    publish(&path, &book).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), first);
    assert_eq!(read(&path).unwrap().as_ref(), Some(&book));
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn public_book_publish_and_read_reject_oversized_wires() {
    let (_, mut book, _) = fixture();
    book.attestations[0].signature = vec![0; MAX_PUBLIC_BOOK_BYTES];
    let root = std::env::temp_dir().join(format!(
        "oclob-public-depth-bound-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    let publish_path = root.join("publish.json");
    assert!(publish(&publish_path, &book)
        .unwrap_err()
        .contains("size bound"));
    assert!(!publish_path.exists());

    let read_path = root.join("read.json");
    std::fs::write(&read_path, vec![0; MAX_PUBLIC_BOOK_BYTES + 1]).unwrap();
    assert!(read(&read_path).unwrap_err().contains("size bound"));
    std::fs::remove_dir_all(root).unwrap();
}
