//! Unit-level verifier regressions using a real captured public MPC result.
//! Synthetic transport endpoints below are not runtime/deployment evidence.
use oclob_node::network::{ClusterNodePublic, ClusterPublicConfig};
use oclob_node::public_depth::{publish, read, FinalizedPublicBook};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    book: FinalizedPublicBook,
}
fn fixture() -> (ClusterPublicConfig, FinalizedPublicBook, u64) {
    let f: Fixture =
        serde_json::from_str(include_str!("fixtures/public_depth_rough001.json")).unwrap();
    let cluster = ClusterPublicConfig {
        version: 3,
        market_id: f.book.market_id.clone(),
        program: "oclob_match_v1".into(),
        settlement_release_threshold: 3,
        nodes: f
            .book
            .attestations
            .iter()
            .map(|a| ClusterNodePublic {
                party: a.party,
                host: "unit-test.invalid".into(),
                rpc_port: 7443,
                proof_port: 8443,
                server_name: "unit-test.invalid".into(),
                tls_certificate_sha256: [1; 32],
                share_encryption_key: oclob_edge::NodeEncryptionKey([1; 32]),
                receipt_verifying_key: a.signer,
            })
            .collect(),
    };
    let at = f.book.attestations[0].issued_at;
    (cluster, f.book, at)
}
#[test]
fn real_public_snapshot_authenticates_without_private_execution_record() {
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
    other.nodes[0].receipt_verifying_key = ed25519_dalek::SigningKey::from_bytes(&[77; 32])
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
