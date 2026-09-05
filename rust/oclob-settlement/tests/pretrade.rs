//! Unit-level real-cryptography checks; live chain evidence is a separate gate.
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use oclob_dekyx::deterministic_demo_environment;
use oclob_settlement::pretrade::{select_funding_ring, CorporateFunding, PrivateReserveRequest};
use qomm_defmi::application_reservation::ApplicationReserveMandate;
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::avalanche::CanonicalCreditFacility;
use qomm_defmi::facility::{CreditFacilitySnapshot, CreditFacilityStatus};
use qomm_defmi::note_chain::NoteOutput;
use qomm_defmi::notes::{decode_spend_proof, NoteLedger, Wallet};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use std::collections::BTreeSet;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::reservation::order_authorization_commitment;

fn request(reserve: u64, source_index: usize, cap: u64) -> Result<PrivateReserveRequest, String> {
    request_with_pool(reserve, source_index, cap, 2)
}

fn request_with_pool(
    reserve: u64,
    source_index: usize,
    cap: u64,
    pool_size: usize,
) -> Result<PrivateReserveRequest, String> {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let commit = |v, b| key.commit_u64(v, &Scalar::from(b)).compress().to_bytes();
    let wallet = Wallet::new(&mut OsRng);
    let decoy = Wallet::new(&mut OsRng);
    let mut ledger = NoteLedger::new(key.clone(), 32);
    for (owner, value) in [(&decoy.address, 25), (&wallet.address, 100)] {
        ledger.add(ledger.build_note(
            owner,
            value,
            key.commit_u64(value, &Scalar::from(9_u64)),
            &Scalar::from(9_u64),
            &mut OsRng,
        ));
    }
    for _ in 2..pool_size {
        let blind = Scalar::random(&mut OsRng);
        ledger.add(ledger.build_note(
            &decoy.address,
            25,
            key.commit_u64(25, &blind),
            &blind,
            &mut OsRng,
        ));
    }
    let notes = ledger
        .notes
        .iter()
        .map(|note| NoteOutput::from_note(note, [7; 32], [0; 32]))
        .collect::<Result<Vec<_>, _>>()?;
    let (_, issuer) = deterministic_demo_environment("PRETRADE-UNIT").map_err(err)?;
    let identity = issuer.issue_wallet(13, b"unit", &mut OsRng).map_err(err)?;
    let enrollment = identity
        .present([12; 32], [13; 32], 1000, &mut OsRng)
        .map_err(err)?;
    let entity = enrollment.subject_line_id().map_err(err)?;
    let signer = SigningKey::generate(&mut OsRng);
    let mandate = ApplicationReserveMandate {
        version: 1,
        scope: ApplicationReserveScope {
            application_binding: oclob_manifest_v1().digest().map_err(err)?,
            venue_id: [1; 32],
            defmi_id: [2; 32],
            committee_key_digest: [3; 32],
            pq_committee_digest: [231; 32],
            committee_epoch: 1,
            amount_bits: 32,
        },
        request_commitment: order_authorization_commitment([4; 32], [5; 32]).map_err(err)?,
        facility_id: [6; 32],
        hold_id: [8; 32],
        asset_id: [7; 32],
        amount_commitment: commit(reserve, 10_u64),
        participant_handle: wallet.address.view.compress().to_bytes(),
        entity_commitment: entity,
        credential_digest: identity.credential_digest().map_err(err)?,
        settlement_terms_commitment: commit(1, 11_u64),
        valid_from: 100,
        valid_until: 1000,
        participant_public: signer.verifying_key().to_bytes(),
        signature: vec![],
    }
    .sign(&signer)?;
    let presentation = identity
        .present_context(
            mandate.identity_context(identity.scope_digest())?,
            &mut OsRng,
        )
        .map_err(err)?;
    let facility = CanonicalCreditFacility {
        state_root: [14; 32],
        facility: CreditFacilitySnapshot {
            facility_id: [6; 32],
            guarantor_id: [15; 32],
            beneficiary_commitment: entity,
            rail_asset_id: [7; 32],
            cap_commitment: commit(cap, 20_u64),
            available_commitment: commit(cap, 20_u64),
            held_commitment: [0; 32],
            outstanding_commitment: [0; 32],
            overlimit_commitment: [0; 32],
            collateral_commitment: commit(cap, 21_u64),
            risk_policy_digest: [16; 32],
            valid_from: 1,
            valid_until: 2000,
            status: CreditFacilityStatus::Active,
            sequence: 0,
        },
    };
    // Deliberately send reverse public-ID order to exercise normalization in
    // the actual proof builder, irrespective of which source the caller owns.
    let mut ring = (0..pool_size).collect::<Vec<_>>();
    ring.sort_unstable_by_key(|&index| std::cmp::Reverse(notes[index].note_id));
    let request = PrivateReserveRequest::build(
        mandate,
        [4; 32],
        [5; 32],
        Scalar::from(19_u64),
        presentation,
        CorporateFunding {
            wallet: &wallet,
            ledger: &ledger,
            canonical_notes: &notes,
            ring: &ring,
            source_index,
            facility: &facility,
            facility_values: [cap, 0, 0],
            facility_blindings: [Scalar::from(20_u64), Scalar::ZERO, Scalar::ZERO],
            reserve_value: reserve,
            reserve_blinding: Scalar::from(10_u64),
        },
        100,
        &mut OsRng,
    )?;
    // Reconstruct the verifier's exact input order from the public request;
    // successful proof generation alone must not mask an order mismatch.
    let verifier_ring = request
        .ring
        .iter()
        .map(|id| notes.iter().position(|note| note.note_id == *id).unwrap())
        .collect::<Vec<_>>();
    ledger
        .check_spend(
            &verifier_ring,
            &decode_spend_proof(&request.spend_proof)?,
            &request.mandate.spend_context()?,
            &mut OsRng,
        )
        .map_err(err)?;
    Ok(request)
}

#[test]
fn corporate_pretrade_proof_uses_real_note_owner_and_never_serializes_openings() {
    let request = request(40, 1, 200).unwrap();
    let wire = serde_json::to_value(&request).unwrap();
    for field in [
        "raw_order",
        "price",
        "quantity",
        "wallet",
        "source_index",
        "facility_values",
        "facility_blindings",
        "reserve_blinding",
    ] {
        assert!(
            wire.get(field).is_none(),
            "private field {field} escaped corporate process"
        );
    }
    let decoded: PrivateReserveRequest = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        decoded.mandate.binding().unwrap(),
        request.mandate.binding().unwrap()
    );
    let proof = decode_spend_proof(&decoded.spend_proof).unwrap();
    assert_eq!(proof.outputs.len(), 2);
    let locked = NoteOutput::from_body(&decoded.outputs[0]).unwrap();
    assert_eq!(locked.lock_id, decoded.mandate.hold_id);
    assert_eq!(locked.value_commitment, decoded.mandate.amount_commitment);
    let mut injected = wire;
    injected["verified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PrivateReserveRequest>(injected).is_err());
}

#[test]
fn corporate_pretrade_rejects_foreign_note_and_both_kinds_of_overdraw() {
    assert!(request(40, 0, 200).err().unwrap().contains("does not own"));
    assert!(request(40, 1, 20)
        .err()
        .unwrap()
        .contains("exceeds available"));
    assert!(request(140, 1, 200)
        .err()
        .unwrap()
        .contains("exceeds the selected"));
}

#[test]
fn corporate_pretrade_canonicalizes_public_ring_before_proving() {
    let request = request(40, 1, 200).unwrap();
    assert!(request.ring.windows(2).all(|pair| pair[0] < pair[1]));
    decode_spend_proof(&request.spend_proof).unwrap();
}

#[test]
fn corporate_pretrade_proves_and_verifies_larger_candidate_rings() {
    for size in [4, 8] {
        let request = request_with_pool(40, 1, 200, size).unwrap();
        assert_eq!(request.ring.len(), size);
        assert!(request.ring.windows(2).all(|pair| pair[0] < pair[1]));
    }
}

fn note_pool(size: usize) -> Vec<NoteOutput> {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let mut rng = StdRng::seed_from_u64(2906);
    let wallet = Wallet::new(&mut rng);
    let ledger = NoteLedger::new(key.clone(), 32);
    (0..size)
        .map(|_| {
            let blind = Scalar::random(&mut rng);
            let note = ledger.build_note(
                &wallet.address,
                100,
                key.commit_u64(100, &blind),
                &blind,
                &mut rng,
            );
            NoteOutput::from_note(&note, [7; 32], [0; 32]).unwrap()
        })
        .collect()
}

#[test]
fn funding_ring_public_order_does_not_mark_the_real_source() {
    let notes = note_pool(2);
    let first = select_funding_ring(&notes, 0, &mut StdRng::seed_from_u64(0)).unwrap();
    let second = select_funding_ring(&notes, 1, &mut StdRng::seed_from_u64(1)).unwrap();
    assert_eq!(first, second);
    assert!(notes[first[0]].note_id < notes[first[1]].note_id);
}

#[test]
fn funding_ring_samples_alternatives_instead_of_a_fixed_first_decoy() {
    let notes = note_pool(5);
    for source in 0..notes.len() {
        let mut seen = BTreeSet::new();
        let mut alternatives = BTreeSet::new();
        for seed in 0..64 {
            let ring =
                select_funding_ring(&notes, source, &mut StdRng::seed_from_u64(seed)).unwrap();
            assert_eq!(ring.len(), 4);
            assert!(ring.contains(&source));
            assert!(ring
                .windows(2)
                .all(|pair| notes[pair[0]].note_id < notes[pair[1]].note_id));
            alternatives.extend(ring.iter().copied().filter(|&i| i != source));
            seen.insert(ring);
        }
        // Deterministic coverage assertions, not a statistical anonymity claim.
        assert!(seen.len() > 1);
        assert_eq!(alternatives.len(), 4);
    }
}

#[test]
fn funding_ring_bounds_and_filters_candidates() {
    let mut notes = note_pool(70);
    let mut rng = StdRng::seed_from_u64(1);
    assert_eq!(select_funding_ring(&notes, 69, &mut rng).unwrap().len(), 64);
    for note in &mut notes[..10] {
        note.lock_id = [1; 32];
    }
    for note in &mut notes[10..20] {
        note.asset_id = [8; 32];
    }
    let ring = select_funding_ring(&notes, 69, &mut rng).unwrap();
    assert_eq!(ring.len(), 32);
    assert!(ring.contains(&69));
    assert!(ring.iter().all(|&index| index >= 20));
    assert!(select_funding_ring(&notes, 0, &mut rng).is_err());
    assert!(select_funding_ring(&notes, 70, &mut rng).is_err());
    assert!(select_funding_ring(&notes[69..], 0, &mut rng).is_err());
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
