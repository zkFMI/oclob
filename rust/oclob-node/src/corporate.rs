//! Pretrade path owned by the corporate participant, not the coordinator.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use oclob_core::SecretOrder;
use oclob_dekyx::DemoEligibilityWallet;
use oclob_edge::{EdgeOrderBundle, NodeEncryptionKey, SealedReservationAuthority, MPC_PARTIES};
use oclob_settlement::pretrade::{CorporateFunding, PrivateAdmissionClient, PrivateReserveRequest};
use qomm_defmi::application_reservation::{ApplicationReserveMandate, ApplicationReserveScope};
use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge};
use qomm_defmi::facility::QuorumAuthorizer;
use qomm_defmi::notes::Wallet;
use qomm_transport::node_service::client_ssl_context;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::Handle;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::reservation::order_authorization_commitment;

/// Owner-only corporate configuration. Never mount this file in an MPC node
/// or coordinator container. Facility witness order: available, held, outstanding.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorporateNativeConfig {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub issuer_public: [u8; 32],
    pub facility_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub facility_values: [u64; 3],
    pub facility_blindings: [[u8; 32]; 3],
    pub wallet_spend_secret: [u8; 32],
    pub identity_seed: [u8; 32],
}

/// Returns only encrypted envelopes and the public order manifest, and only
/// after an actual canonical reserve exists. No fallback to post-match reserve.
#[allow(clippy::too_many_arguments)]
pub fn reserve_and_share(
    config: &CorporateNativeConfig,
    identity: &crate::network::ClientIdentityConfig,
    eligibility: &DemoEligibilityWallet,
    order: &SecretOrder,
    handle: &Handle,
    eligibility_commitment: [u8; 32],
    signer: &SigningKey,
    node_keys: &[NodeEncryptionKey; MPC_PARTIES],
    now: u64,
) -> Result<(EdgeOrderBundle, SealedReservationAuthority), String> {
    let tls = client_ssl_context(
        &identity.tls_certificate,
        &identity.tls_private_key,
        &identity.tls_ca,
    )?;
    let private = PrivateAdmissionClient::new(
        &config.host,
        config.port,
        &config.server_name,
        tls,
        Duration::from_secs(120),
    )?;
    let scope: ApplicationReserveScope =
        serde_json::from_value(private.call("scope", serde_json::json!({}))?).map_err(err)?;
    if scope.venue_id != config.venue_id
        || scope.defmi_id != config.defmi_id
        || scope.application_binding != oclob_manifest_v1().digest().map_err(err)?
        || scope.amount_bits != 32
    {
        return Err("DeFMI returned another configured application scope".into());
    }
    let issuer = VerifyingKey::from_bytes(&config.issuer_public).map_err(err)?;
    // Read methods do not use governance approvals. This key-only authorizer
    // cannot sign or create any canonical transition in the corporate process.
    let readonly = QuorumAuthorizer::new(
        BTreeMap::from([("read-only".into(), issuer)]),
        1,
        1,
        "read-only",
    )?;
    let client = private.chain()?;
    let bridge = AvalancheNoteBridge::new(&readonly, &client);
    let key = Pedersen::new(b"qomm:defmi:v1");
    let (root, ledger, notes) = bridge.note_ledger(config.asset_id, key.clone(), 32, 4096)?;
    let facility = bridge.credit_facility(config.facility_id)?;
    if facility.state_root != root || client.state_root()? != root {
        return Err("canonical funding changed; rebuild the same request before submission".into());
    }
    let wallet = Wallet::from_parts(handle.secret, scalar(config.wallet_spend_secret)?);
    let source = ledger
        .scan(&wallet, &key)
        .into_iter()
        .find(|(index, opening)| {
            notes[*index].lock_id == [0; 32] && opening.value >= order.reservation_limit()
        })
        .map(|(index, _)| index)
        .ok_or("corporate wallet has no sufficient unlocked funding note")?;
    let decoy = notes
        .iter()
        .enumerate()
        .find_map(|(index, note)| (index != source && note.lock_id == [0; 32]).then_some(index))
        .ok_or("funding pool has fewer than two unlocked notes")?;
    let enrollment = eligibility
        .present(
            random(),
            random(),
            order.expires_at(),
            &mut rand::rngs::OsRng,
        )
        .map_err(err)?;
    let salt = random();
    let reserve_blinding = Scalar::random(&mut rand::rngs::OsRng);
    let delta = Scalar::random(&mut rand::rngs::OsRng);
    let side_blinding = Scalar::random(&mut rand::rngs::OsRng);
    let side = match order.side() {
        oclob_core::Side::Buy => 0,
        oclob_core::Side::Sell => 1,
    };
    let mandate = ApplicationReserveMandate {
        version: 1,
        scope: scope.clone(),
        request_commitment: order_authorization_commitment(order.commitment().0, salt)
            .map_err(err)?,
        facility_id: config.facility_id,
        hold_id: order.reservation_id(),
        asset_id: config.asset_id,
        amount_commitment: key
            .commit_u64(order.reservation_limit(), &reserve_blinding)
            .compress()
            .to_bytes(),
        participant_handle: handle.point.compress().to_bytes(),
        entity_commitment: enrollment.subject_line_id().map_err(err)?,
        credential_digest: eligibility.credential_digest().map_err(err)?,
        settlement_terms_commitment: key.commit_u64(side, &side_blinding).compress().to_bytes(),
        valid_from: now,
        valid_until: order.expires_at(),
        participant_public: signer.verifying_key().to_bytes(),
        signature: vec![],
    }
    .sign(signer)?;
    let presentation = eligibility
        .present_context(
            mandate.identity_context(eligibility.scope_digest())?,
            &mut rand::rngs::OsRng,
        )
        .map_err(err)?;
    let request = PrivateReserveRequest::build(
        mandate,
        order.commitment().0,
        salt,
        delta,
        presentation,
        CorporateFunding {
            wallet: &wallet,
            ledger: &ledger,
            canonical_notes: &notes,
            ring: &[source, decoy],
            source_index: source,
            facility: &facility,
            facility_values: config.facility_values,
            facility_blindings: [
                scalar(config.facility_blindings[0])?,
                scalar(config.facility_blindings[1])?,
                scalar(config.facility_blindings[2])?,
            ],
            reserve_value: order.reservation_limit(),
            reserve_blinding,
        },
        now,
        &mut rand::rngs::OsRng,
    )?;
    let finalized = private.reserve(&request)?;
    finalized
        .permit
        .verify(scope.application_binding, config.defmi_id, &issuer, now)
        .map_err(err)?;
    finalized
        .admission
        .verify_authority(&finalized.permit, &delta)
        .map_err(err)?;
    // Re-read the exact canonical reserve ourselves; issuer signature alone is
    // insufficient to cause us to distribute a spendable order.
    let canonical = client.application_reservation_snapshot(request.mandate.hold_id)?;
    if canonical.binding != request.mandate.binding()?
        || canonical.status != "active"
        || canonical.accepted_height == 0
        || canonical.sequence != 0
        || canonical.escrow_note_id != finalized.permit.escrow_note_id
        || canonical.reserve_receipt_digest != finalized.permit.reserve_receipt_digest
    {
        return Err("corporate canonical reserve readback differs from the issued permit".into());
    }
    let bundle = EdgeOrderBundle::create_with_reservation_admission(
        order,
        handle,
        eligibility_commitment,
        &finalized.admission,
        &issuer,
        side_blinding,
        reserve_blinding + delta,
        signer,
        node_keys,
        now,
        &mut rand::rngs::OsRng,
    )
    .map_err(err)?;
    let authority = bundle
        .seal_reservation_authority(
            &finalized.permit,
            &finalized.admission,
            delta,
            &mut rand::rngs::OsRng,
        )
        .map_err(err)?;
    Ok((bundle, authority))
}

fn scalar(bytes: [u8; 32]) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or("corporate scalar encoding is invalid".into())
}
fn random() -> [u8; 32] {
    let mut value = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut value);
    value
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
