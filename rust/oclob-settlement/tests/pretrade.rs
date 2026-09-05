//! Unit-level real-cryptography checks; live chain evidence is a separate gate.
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use oclob_dekyx::deterministic_demo_environment;
use oclob_settlement::pretrade::{CorporateFunding, PrivateReserveRequest};
use qomm_defmi::application_reservation::ApplicationReserveMandate;
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::avalanche::CanonicalCreditFacility;
use qomm_defmi::facility::{CreditFacilitySnapshot, CreditFacilityStatus};
use qomm_defmi::note_chain::NoteOutput;
use qomm_defmi::notes::{decode_spend_proof, NoteLedger, Wallet};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::reservation::order_authorization_commitment;

fn request(reserve: u64, source_index: usize, cap: u64) -> Result<PrivateReserveRequest, String> {
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
    PrivateReserveRequest::build(
        mandate,
        [4; 32],
        [5; 32],
        Scalar::from(19_u64),
        presentation,
        CorporateFunding {
            wallet: &wallet,
            ledger: &ledger,
            canonical_notes: &notes,
            ring: &[1, 0],
            source_index,
            facility: &facility,
            facility_values: [cap, 0, 0],
            facility_blindings: [Scalar::from(20_u64), Scalar::ZERO, Scalar::ZERO],
            reserve_value: reserve,
            reserve_blinding: Scalar::from(10_u64),
        },
        100,
        &mut OsRng,
    )
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

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
