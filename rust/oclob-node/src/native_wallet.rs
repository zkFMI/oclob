//! Corporate-side recovery of native claims and the private facility witness.
//! All amounts, wallet secrets and decrypted openings stay in this process.

use crate::corporate::{private_client, CorporateNativeConfig, FacilityWitness};
use crate::corporate_journal::NativeCorporateJournal;
use crate::network::ClientIdentityConfig;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge, CanonicalNoteClaim};
use qomm_defmi::claim_redemption::redeem_claim;
use qomm_defmi::facility::QuorumAuthorizer;
use qomm_defmi::note_chain::{NoteClaimKind, NoteOutput};
use qomm_defmi::notes::Wallet;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::Identity;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Corporate-only result. Do not serialize/log the private witness. The
/// canonical note IDs can be used privately to select the next funding input.
pub struct RecoveredCorporateWallet {
    pub facility: FacilityWitness,
    pub notes: Vec<NoteOutput>,
    pub own_asset_refund: Option<[u8; 32]>,
    pub unfilled_releases_recovered: usize,
    pub after_root: [u8; 32],
}

pub fn recover_wallet(
    config: &CorporateNativeConfig,
    identity: &ClientIdentityConfig,
    journal: &NativeCorporateJournal,
) -> Result<RecoveredCorporateWallet, String> {
    let client = private_client(config, identity)?.chain()?;
    let authorizer = QuorumAuthorizer::read_only();
    let bridge = AvalancheNoteBridge::new(&authorizer, &client);
    let network = client.call("defmivm.network", serde_json::json!({}))?;
    let domain = network
        .get("chainID")
        .and_then(|v| v.as_str())
        .ok_or("DeFMI omitted its chain identity")?;
    let handle = Identity::from_seed(config.identity_seed).handle(b"defmi:oclob:v1");
    let wallet = Wallet::from_parts(handle.secret, scalar(config.wallet_spend_secret)?);
    let key = Pedersen::new(b"qomm:defmi:v1");
    let claims = recipient_claims(&client, wallet.address.view.compress().to_bytes())?;
    let mut notes = Vec::new();
    let mut refund_ids = std::collections::BTreeSet::new();
    for snapshot in &claims {
        let claim = snapshot.claim()?;
        let redemption = match journal.claim_redemption(claim.claim_id)? {
            Some(saved) => saved,
            None => {
                if snapshot.status != "active" {
                    return Err(
                        "a redeemed claim has no local ownership record; reconcile explicitly"
                            .into(),
                    );
                }
                let operation = Sha256::new()
                    .chain_update(b"OCLOB:NATIVE:CLAIM-REDEEM:v1")
                    .chain_update(config.defmi_id)
                    .chain_update(claim.claim_id)
                    .finalize()
                    .into();
                let quorum = claim
                    .opening_envelope
                    .shares
                    .iter()
                    .take(claim.opening_envelope.threshold)
                    .map(|s| s.party)
                    .collect::<Vec<_>>();
                let request = redeem_claim(
                    &claim,
                    &key,
                    32,
                    &handle.secret,
                    &wallet.address,
                    &quorum,
                    domain,
                    client.state_root()?,
                    operation,
                    &mut rand::rngs::OsRng,
                )?;
                // Save the exact signature/output before a state-changing RPC.
                journal.save_claim_redemption(&request)?
            }
        };
        redemption.verify(&claim, domain)?;
        let current = client.note_claim_snapshot(claim.claim_id)?;
        if current.status == "active" {
            bridge.redeem_note_claim(&redemption)?;
        }
        let current = client.note_claim_snapshot(claim.claim_id)?;
        let note = bridge.note(redemption.output.note_id)?;
        if current.status != "materialized"
            || current.materialization != redemption.signing_message()?
            || current.claim()? != claim
            || note.output != redemption.output
        {
            return Err("claim redemption did not produce the exact canonical wallet note".into());
        }
        if claim.asset_id == config.asset_id && claim.kind == NoteClaimKind::Refund {
            refund_ids.insert(note.output.note_id);
        }
        notes.push(note.output);
    }
    let facility = recover_facility(config, &client, journal)?;
    let (root, ledger, outputs) = bridge.note_ledger(config.asset_id, key.clone(), 32, 4096)?;
    let mut available = BTreeMap::new();
    let mut owned = BTreeMap::new();
    for (index, opening) in ledger.scan(&wallet, &key) {
        owned.insert(outputs[index].note_id, opening.value);
        if outputs[index].lock_id != [0; 32] || opening.value == 0 {
            continue;
        }
        let serial = qomm_defmi::notes::note_nullifier(&opening.serial)
            .compress()
            .to_bytes();
        let status = bridge.note_serial(serial)?;
        if status.state_root != root {
            return Err("refund selection crossed canonical generations".into());
        }
        if !status.spent {
            available.insert(outputs[index].note_id, opening.value);
        }
    }
    // Cumulative claim history contains zero and already-spent refunds too.
    // The convenience funding ID must name an actually spendable positive note.
    let own_asset_refund = refund_ids.into_iter().find(|id| available.contains_key(id));
    let mut unfilled_releases_recovered = 0;
    for prepared in journal.reservations()? {
        let head = client.application_reservation_snapshot(prepared.request.mandate.hold_id)?;
        if head.state_root != root {
            return Err("released-note recovery crossed canonical generations".into());
        }
        if head.status == "released" && head.sequence == 1 {
            let mut unlocked = client.note_snapshot(head.escrow_note_id)?.output;
            unlocked.lock_id = [0; 32];
            unlocked.note_id = unlocked.derived_id()?;
            let note = client.note_snapshot(unlocked.note_id)?;
            let original =
                oclob_core::SecretOrder::from_secret_wire(&prepared.order_wire).map_err(err)?;
            if note.output != unlocked
                || owned.get(&unlocked.note_id) != Some(&original.reservation_limit())
            {
                return Err(
                    "unfilled reservation did not return its exact spendable corporate note".into(),
                );
            }
            if available.contains_key(&unlocked.note_id) {
                unfilled_releases_recovered += 1;
            }
        }
    }
    if client.state_root()? != root {
        return Err("corporate recovery changed before completion".into());
    }
    journal.save_funding_witness(&facility)?;
    Ok(RecoveredCorporateWallet {
        facility,
        notes,
        own_asset_refund,
        unfilled_releases_recovered,
        after_root: client.state_root()?,
    })
}

fn recipient_claims<C: AvalancheClient>(
    client: &C,
    recipient: [u8; 32],
) -> Result<Vec<CanonicalNoteClaim>, String> {
    let root = client.state_root()?;
    let mut after = None;
    let mut claims = Vec::new();
    loop {
        let page = client.note_claim_recipient_page(recipient, after, 128)?;
        if page.state_root != root {
            return Err("claim scan crossed canonical generations; retry".into());
        }
        if claims.len() + page.claims.len() > 4096 {
            return Err("claim scan exceeds its recovery bound".into());
        }
        for claim in page.claims {
            if claim.opening_envelope.recipient_view.compress().to_bytes() != recipient {
                return Err("claim scan returned another recipient".into());
            }
            claim.claim()?;
            claims.push(claim);
        }
        match page.next {
            Some(next) if Some(next) != after => after = Some(next),
            None => break,
            _ => return Err("claim scan cursor did not advance".into()),
        }
    }
    if client.state_root()? != root {
        return Err("claim scan changed before completion".into());
    }
    Ok(claims)
}

/// Rebuild from the locally recorded initial witness and every canonical
/// native reserve head. Unexpected external facility writes fail the final
/// generation/commitment equality check; they are never guessed or ignored.
pub fn recover_facility<C: AvalancheClient>(
    config: &CorporateNativeConfig,
    client: &C,
    journal: &NativeCorporateJournal,
) -> Result<FacilityWitness, String> {
    let mut reserves = journal.reservations()?;
    reserves.sort_by_key(|r| r.request.before_sequence);
    let first = reserves
        .first()
        .ok_or("facility recovery needs its original reserved witness")?;
    let mut witness = FacilityWitness {
        facility_id: config.facility_id,
        sequence: first.request.before_sequence,
        values: config.facility_values,
        blindings: config.facility_blindings,
    };
    if witness.commitments()? != first.request.before {
        return Err("initial corporate witness does not match the first recorded reserve".into());
    }
    let handle = Identity::from_seed(config.identity_seed).handle(b"defmi:oclob:v1");
    let key = Pedersen::new(b"qomm:defmi:v1");
    let root = client.state_root()?;
    for prepared in reserves {
        prepared.validate(config)?;
        let head = client.application_reservation_snapshot(prepared.request.mandate.hold_id)?;
        if head.state_root != root || head.binding != prepared.request.mandate.binding()? {
            return Err("native reserve recovery crossed or changed canonical context".into());
        }
        let order = oclob_core::SecretOrder::from_secret_wire(&prepared.order_wire).map_err(err)?;
        let original = order.reservation_limit();
        let original_blind = scalar(prepared.reserve_blinding)?;
        let (remaining, remaining_blind) =
            if head.sequence == 0 || (head.sequence == 1 && head.status == "released") {
                (original, original_blind)
            } else if let Some(opening) = &head.remaining_opening {
                let envelope = opening.domain()?;
                let quorum = envelope
                    .shares
                    .iter()
                    .take(envelope.threshold)
                    .map(|s| s.party)
                    .collect::<Vec<_>>();
                envelope.decrypt_u64(&handle.secret, &quorum, 32)?
            } else {
                let page = client.note_claim_page(head.binding.hold_id, None, 128)?;
                if page.state_root != root || page.next.is_some() {
                    return Err("refund recovery crossed state or page bound".into());
                }
                let claim = page
                    .claims
                    .iter()
                    .find(|c| {
                        c.kind == NoteClaimKind::Refund
                            && c.value_commitment == head.remaining_commitment
                            && c.opening_envelope.recipient_view == handle.point
                    })
                    .ok_or("closed reserve has no recoverable current refund")?;
                let envelope = &claim.opening_envelope;
                let quorum = envelope
                    .shares
                    .iter()
                    .take(envelope.threshold)
                    .map(|s| s.party)
                    .collect::<Vec<_>>();
                envelope.decrypt_u64(&handle.secret, &quorum, 32)?
            };
        if key
            .commit_u64(remaining, &remaining_blind)
            .compress()
            .to_bytes()
            != head.remaining_commitment
        {
            return Err("decrypted remainder differs from the canonical reserve".into());
        }
        apply_reserve_movement(
            &mut witness,
            original,
            original_blind,
            remaining,
            remaining_blind,
            &head.status,
            head.sequence,
        )?;
    }
    let canonical = client.credit_facility_snapshot(config.facility_id)?;
    if canonical.state_root != root
        || client.state_root()? != root
        || canonical.facility.facility_id != config.facility_id
        || canonical.facility.sequence != witness.sequence
        || witness.commitments()?
            != [
                canonical.facility.available_commitment,
                canonical.facility.held_commitment,
                canonical.facility.outstanding_commitment,
            ]
    {
        return Err(
            "reconstructed facility does not match canonical balances and generation".into(),
        );
    }
    Ok(witness)
}

/// Pure arithmetic only; the caller still authenticates every head/opening and
/// compares the complete result to one canonical facility generation.
fn apply_reserve_movement(
    witness: &mut FacilityWitness,
    original: u64,
    original_blind: Scalar,
    remaining: u64,
    remaining_blind: Scalar,
    status: &str,
    sequence: u64,
) -> Result<(), String> {
    if !matches!(status, "active" | "consumed" | "released") {
        return Err("unknown canonical reserve status".into());
    }
    let mut next = witness.clone();
    let consumed = original
        .checked_sub(remaining)
        .ok_or("reserve remainder exceeds its original amount")?;
    let consumed_blind = original_blind - remaining_blind;
    let active = status == "active";
    let unavailable = consumed
        .checked_add(if active { remaining } else { 0 })
        .ok_or("capacity overflow")?;
    let unavailable_blind = consumed_blind
        + if active {
            remaining_blind
        } else {
            Scalar::ZERO
        };
    next.values[0] = next.values[0]
        .checked_sub(unavailable)
        .ok_or("available capacity underflow")?;
    next.blindings[0] = (scalar(next.blindings[0])? - unavailable_blind).to_bytes();
    if active {
        next.values[1] = next.values[1]
            .checked_add(remaining)
            .ok_or("held capacity overflow")?;
        next.blindings[1] = (scalar(next.blindings[1])? + remaining_blind).to_bytes();
    }
    next.values[2] = next.values[2]
        .checked_add(consumed)
        .ok_or("outstanding capacity overflow")?;
    next.blindings[2] = (scalar(next.blindings[2])? + consumed_blind).to_bytes();
    next.sequence = next
        .sequence
        .checked_add(1)
        .and_then(|s| s.checked_add(sequence))
        .ok_or("facility sequence overflow")?;
    next.commitments()?;
    *witness = next;
    Ok(())
}

fn scalar(value: [u8; 32]) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(value))
        .ok_or("corporate scalar is not canonical".into())
}

/// Acceptance and callers can check the exact *selected* source, not merely
/// that some note appeared in a ring. The comparison never leaves this process.
pub fn verify_selected_funding_spent(
    config: &CorporateNativeConfig,
    identity: &ClientIdentityConfig,
    prepared: &crate::corporate::PreparedCorporateReserve,
    source: [u8; 32],
) -> Result<(), String> {
    prepared.validate(config)?;
    let client = private_client(config, identity)?.chain()?;
    let output = client.note_snapshot(source)?.output;
    if output.note_id != source
        || output.asset_id != config.asset_id
        || !prepared.request.ring.contains(&source)
    {
        return Err("saved reserve did not select the requested funding note".into());
    }
    let handle = Identity::from_seed(config.identity_seed).handle(b"defmi:oclob:v1");
    let wallet = Wallet::from_parts(handle.secret, scalar(config.wallet_spend_secret)?);
    let serial = qomm_defmi::notes::note_nullifier(&wallet.serial(&output.to_note()?.ephemeral))
        .compress()
        .to_bytes();
    let proof = qomm_defmi::notes::decode_spend_proof(&prepared.request.spend_proof)?;
    let spent = client.note_serial_snapshot(serial)?;
    if proof.serial_point.compress().to_bytes() != serial
        || spent.serial_point != serial
        || !spent.spent
    {
        return Err("selected recovered note was not the canonical consumed input".into());
    }
    Ok(())
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial() -> FacilityWitness {
        FacilityWitness {
            facility_id: [1; 32],
            sequence: 0,
            values: [120, 0, 0],
            blindings: [Scalar::from(9u64).to_bytes(), [0; 32], [0; 32]],
        }
    }

    #[test]
    fn partial_fill_recovery_preserves_capacity_and_all_commitments() {
        let mut witness = initial();
        let before = witness.commitments().unwrap();
        apply_reserve_movement(
            &mut witness,
            60,
            Scalar::from(3u64),
            20,
            Scalar::from(2u64),
            "active",
            1,
        )
        .unwrap();
        assert_eq!(witness.values, [60, 20, 40]);
        assert_eq!(witness.sequence, 2);
        let key = Pedersen::new(b"qomm:defmi:v1");
        assert_eq!(
            witness.commitments().unwrap(),
            [
                key.commit_u64(60, &Scalar::from(6u64))
                    .compress()
                    .to_bytes(),
                key.commit_u64(20, &Scalar::from(2u64))
                    .compress()
                    .to_bytes(),
                key.commit_u64(40, &Scalar::ONE).compress().to_bytes(),
            ]
        );
        let sum = |items: [[u8; 32]; 3]| {
            items
                .iter()
                .map(|c| {
                    curve25519_dalek::ristretto::CompressedRistretto(*c)
                        .decompress()
                        .unwrap()
                })
                .sum::<curve25519_dalek::ristretto::RistrettoPoint>()
        };
        assert_eq!(sum(before), sum(witness.commitments().unwrap()));
    }

    #[test]
    fn closure_and_release_return_only_unused_capacity() {
        for status in ["consumed", "released"] {
            let mut witness = initial();
            apply_reserve_movement(
                &mut witness,
                60,
                Scalar::from(3u64),
                20,
                Scalar::from(2u64),
                status,
                2,
            )
            .unwrap();
            assert_eq!(witness.values, [80, 0, 40]);
            assert_eq!(witness.sequence, 3);
            assert_eq!(
                witness.blindings,
                [
                    Scalar::from(8u64).to_bytes(),
                    Scalar::ZERO.to_bytes(),
                    Scalar::ONE.to_bytes()
                ]
            );
        }
        let mut untouched = initial();
        apply_reserve_movement(
            &mut untouched,
            60,
            Scalar::from(3u64),
            60,
            Scalar::from(3u64),
            "released",
            1,
        )
        .unwrap();
        assert_eq!(untouched.values, initial().values);
        assert_eq!(untouched.blindings, initial().blindings);
        assert_eq!(untouched.sequence, 2);
    }

    #[test]
    fn subsequent_reserve_uses_recovered_free_capacity() {
        let mut witness = initial();
        apply_reserve_movement(
            &mut witness,
            60,
            Scalar::from(3u64),
            20,
            Scalar::from(2u64),
            "consumed",
            1,
        )
        .unwrap();
        apply_reserve_movement(
            &mut witness,
            40,
            Scalar::from(4u64),
            40,
            Scalar::from(4u64),
            "active",
            0,
        )
        .unwrap();
        assert_eq!(witness.values, [40, 40, 40]);
        assert_eq!(witness.sequence, 3);
        assert_eq!(
            witness.blindings,
            [
                Scalar::from(4u64).to_bytes(),
                Scalar::from(4u64).to_bytes(),
                Scalar::ONE.to_bytes()
            ]
        );
    }

    #[test]
    fn malformed_recovery_does_not_partially_mutate_private_witness() {
        let mut cases = vec![
            (initial(), 121, 20, "active", 1),
            (initial(), 60, 61, "consumed", 1),
            (initial(), 60, 20, "closed", 1),
            (initial(), 60, 20, "unknown", 1),
        ];
        let mut overflow = initial();
        overflow.sequence = u64::MAX;
        cases.push((overflow, 60, 20, "active", 1));
        let mut invalid = initial();
        invalid.blindings[2] = [255; 32];
        cases.push((invalid, 60, 20, "active", 1));
        for (mut witness, original, remaining, status, sequence) in cases {
            let before = serde_json::to_vec(&witness).unwrap();
            assert!(apply_reserve_movement(
                &mut witness,
                original,
                Scalar::ONE,
                remaining,
                Scalar::ONE,
                status,
                sequence
            )
            .is_err());
            assert_eq!(serde_json::to_vec(&witness).unwrap(), before);
        }
    }
}
