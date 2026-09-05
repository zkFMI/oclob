//! Deterministic real-signature/store tests, not a substitute for live MPC.
use super::*;
use crate::native_lifecycle::LifecycleCommand;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use oclob_core::{SecretOrder, Side, TimeInForce};
use oclob_edge::{EdgeOrderBundle, NodeEncryptionKey};
use oclob_ordering::OrderingCommittee;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::Identity;
use zkpi_defmi_sdk::reservation::{ReservationPermit, ReservationRole};

fn fixture() -> (
    NodeShareStore,
    EdgeOrderManifest,
    SigningKey,
    NodeDecryptionKey,
) {
    let keys: [NodeDecryptionKey; MPC_PARTIES] =
        std::array::from_fn(|_| NodeDecryptionKey::generate().unwrap());
    let public: [NodeEncryptionKey; MPC_PARTIES] =
        std::array::from_fn(|i| keys[i].public_key().unwrap());
    let path = std::env::temp_dir()
        .join(format!("oclob-lifecycle-{:016x}", rand::random::<u64>()))
        .join("shares.bin");
    let owner = SigningKey::generate(&mut rand::rngs::OsRng);
    let issuer = SigningKey::from_bytes(&[42; 32]);
    let identity = Identity::from_seed([41; 32]).handle(b"defmi:oclob:v1");
    let order = SecretOrder::new(
        "JGB10Y-JPY",
        Side::Sell,
        100,
        29,
        TimeInForce::GoodTilCancelled,
        2_000_000_000,
        identity.point.compress().to_bytes(),
        [43; 32],
        [44; 32],
    )
    .unwrap();
    let key = Pedersen::new(b"qomm:defmi:v1");
    let side_blind = Scalar::from(5_u64);
    let reserve_blind = Scalar::from(6_u64);
    let delta = Scalar::from(7_u64);
    let permit = ReservationPermit {
        version: 2,
        role: ReservationRole::Application,
        application_binding: zkpi_defmi_sdk::application::oclob_manifest_v1()
            .digest()
            .unwrap(),
        venue_id: [45; 32],
        defmi_id: [46; 32],
        canonical_state_root: [47; 32],
        accepted_height: 10,
        order_commitment: order.commitment().0,
        participant_handle: order.participant_handle(),
        entity_commitment: [48; 32],
        reservation_id: [49; 32],
        facility_id: [50; 32],
        asset_id: [51; 32],
        amount_commitment: key
            .commit(&Scalar::from(order.reservation_limit()), &reserve_blind)
            .compress()
            .to_bytes(),
        escrow_note_id: [52; 32],
        delegation_digest: [53; 32],
        side_commitment: key
            .commit(&Scalar::from(u64::from(order.side().wire())), &side_blind)
            .compress()
            .to_bytes(),
        authority_digest: [54; 32],
        reserve_receipt_digest: [55; 32],
        reservation_sequence: 1,
        valid_until: 2_000_000_000,
        signer_public: issuer.verifying_key().to_bytes(),
        signature: Vec::new(),
    }
    .sign(&issuer)
    .unwrap();
    let admission =
        zkpi_defmi_sdk::admission::ReservationAdmission::from_permit(&permit, &delta, &issuer)
            .unwrap();
    let bundle = EdgeOrderBundle::create_with_reservation_admission(
        &order,
        &identity,
        [56; 32],
        &admission,
        &issuer.verifying_key(),
        side_blind,
        reserve_blind + delta,
        &owner,
        &public,
        1_900_000_000,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let manifest = bundle.manifest().clone();
    let deliveries = bundle.into_deliveries();
    let mut store = NodeShareStore::open(&path, 0, keys[0].clone()).unwrap();
    store
        .pin_reservation_trust(permit.venue_id, permit.defmi_id, issuer.verifying_key())
        .unwrap();
    store
        .ingest(
            manifest.clone(),
            deliveries[0].1.clone(),
            deliveries[0].2.clone(),
            1_900_000_000,
        )
        .unwrap();
    (store, manifest, owner, keys[0].clone())
}

#[test]
fn owner_authorization_and_real_expiry_are_distinct() {
    let (store, manifest, owner, _) = fixture();
    let command =
        LifecycleCommand::cancel(&manifest, 1_900_000_001, 1_900_000_100, [57; 32], &owner)
            .unwrap();
    let mut changed = command.clone();
    changed.target.0[0] ^= 1;
    assert!(changed.verify(&manifest, 1_900_000_002).is_err());
    assert!(LifecycleCommand::cancel(
        &manifest,
        1_900_000_001,
        1_900_000_100,
        [57; 32],
        &SigningKey::from_bytes(&[58; 32])
    )
    .is_err());
    assert!(LifecycleCommand::expire(
        &manifest,
        manifest.retention_deadline,
        manifest.retention_deadline + 10
    )
    .is_err());
    let expired = LifecycleCommand::expire(
        &manifest,
        manifest.retention_deadline + 1,
        manifest.retention_deadline + 10,
    )
    .unwrap();
    assert!(expired.signature.is_empty());
    fs::remove_dir_all(store.path.parent().unwrap()).unwrap();
}

#[test]
fn ordered_lifecycle_blocks_matching_and_survives_reopen() {
    let (mut store, manifest, owner, key) = fixture();
    let mut committee = OrderingCommittee::deterministic_for_demo().unwrap();
    let initial = committee
        .certify(
            &manifest.market_id,
            manifest.commitment,
            1_900_000_100,
            1_900_000_001,
        )
        .unwrap();
    store
        .accept_order_certificate(
            &initial,
            committee.policy(),
            &committee.verifying_keys(),
            1_900_000_001,
        )
        .unwrap();
    let command =
        LifecycleCommand::cancel(&manifest, 1_900_000_002, 1_900_000_100, [59; 32], &owner)
            .unwrap();
    let digest = store
        .register_lifecycle(command.clone(), 1_900_000_002)
        .unwrap();
    assert!(store.lifecycle_share(digest).is_err());
    let cert = committee
        .certify(
            &manifest.market_id,
            OrderCommitment(digest),
            command.expires_at,
            1_900_000_002,
        )
        .unwrap();
    store
        .accept_order_certificate(
            &cert,
            committee.policy(),
            &committee.verifying_keys(),
            1_900_000_002,
        )
        .unwrap();
    assert!(store.lifecycle_share(digest).is_ok());
    assert!(store.require_lifecycle_barrier().is_err());
    assert!(store
        .prepare_round(&manifest.market_id, &[], manifest.commitment, 1_900_000_003)
        .is_err());
    assert!(store.remove_terminal(manifest.commitment).is_err());
    assert_eq!(
        store
            .prune_expired(manifest.retention_deadline + 1)
            .unwrap(),
        0
    );
    let path = store.path.clone();
    let status = store.status().unwrap();
    drop(store);
    let store = NodeShareStore::open(&path, 0, key).unwrap();
    assert_eq!(store.status().unwrap(), status);
    assert!(store.require_lifecycle_barrier().is_err());
    assert!(store.lifecycle_blocks(manifest.commitment));
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn v9_requires_lifecycle_history_and_v8_has_explicit_empty_upgrade() {
    let (mut store, _, _, key) = fixture();
    let path = store.path.clone();
    let mut state = serde_json::to_value(&store.state).unwrap();
    state.as_object_mut().unwrap().remove("lifecycle");
    assert!(serde_json::from_value::<StoreState>(state.clone()).is_err());
    state["version"] = serde_json::json!(8);
    let bytes = serde_json::to_vec(&state).unwrap();
    let encoded = [
        STORE_MAGIC.as_slice(),
        &(bytes.len() as u64).to_be_bytes(),
        &bytes,
        Sha256::digest(&bytes).as_slice(),
    ]
    .concat();
    fs::write(&path, encoded).unwrap();
    drop(store);
    store = NodeShareStore::open(&path, 0, key).unwrap();
    assert_eq!(store.state.version, 9);
    assert!(store.state.lifecycle.is_empty());
    assert_eq!(store.state.records.len(), 1);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn a_completed_unsettled_match_blocks_cancel_before_any_state_change() {
    let (mut store, manifest, owner, _) = fixture();
    let mut committee = OrderingCommittee::deterministic_for_demo().unwrap();
    let initial = committee
        .certify(
            &manifest.market_id,
            manifest.commitment,
            1_900_000_100,
            1_900_000_001,
        )
        .unwrap();
    store
        .accept_order_certificate(
            &initial,
            committee.policy(),
            &committee.verifying_keys(),
            1_900_000_001,
        )
        .unwrap();
    let result = oclob_core::MpcBatchResult {
        slots: (0..MAX_MATCH_SLOTS)
            .map(|i| oclob_core::MpcSlotResult {
                matched: i == 0,
                trade_price: if i == 0 { 100 } else { 0 },
                trade_quantity: u64::from(i == 0),
            })
            .collect(),
        arriving_remaining: 0,
    };
    // Unit-local state fixture. Live acceptance separately executes MP-SPDZ.
    store.state.completed_rounds.insert(
        hex::encode([61; 32]),
        executor::NodeExecutionReceipt {
            version: 1,
            party: 0,
            round_id: [61; 32],
            generation: 1,
            round_commitment: [62; 32],
            program_sha256: [63; 32],
            artifact_sha256: [64; 32],
            private_parent_digest: [65; 32],
            private_state_sha256: [66; 32],
            public_output_sha256: public_output_digest(&result),
            result,
            execution_ms: 1,
            signer: owner.verifying_key().to_bytes(),
            signature: vec![0; 64],
        },
    );
    let command =
        LifecycleCommand::cancel(&manifest, 1_900_000_002, 1_900_000_100, [67; 32], &owner)
            .unwrap();
    let before = store.status().unwrap();
    assert!(store.register_lifecycle(command, 1_900_000_002).is_err());
    assert_eq!(store.status().unwrap(), before);
    assert!(store.state.lifecycle.is_empty());
    fs::remove_dir_all(store.path.parent().unwrap()).unwrap();
}
