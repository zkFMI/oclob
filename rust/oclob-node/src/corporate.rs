//! Pretrade path owned by the corporate participant, not the coordinator.

use curve25519_dalek::scalar::Scalar;
use oclob_core::application_crypto::SigningKey;
use oclob_core::SecretOrder;
use oclob_dekyx::DemoEligibilityWallet;
use oclob_edge::{
    ClaimAuthorizationEndpoint, EdgeOrderBundle, NodeEncryptionKey, SealedReservationAuthority,
    MPC_PARTIES,
};
use oclob_settlement::pretrade::{
    select_funding_ring, CorporateFunding, FinalizedReservation, PrivateAdmissionClient,
    PrivateReserveRequest,
};
use qomm_defmi::application_reservation::{ApplicationReserveMandate, ApplicationReserveScope};
use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge};
use qomm_defmi::facility::QuorumAuthorizer;
use qomm_defmi::notes::Wallet;
use qomm_transport::node_service::client_ssl_context;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::Handle;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::reservation::order_authorization_commitment;

/// Owner-only corporate configuration. Never mount this file in an MPC node
/// or coordinator container. Facility witness order: available, held, outstanding.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorporateNativeConfig {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub claim_authorization_endpoint: ClaimAuthorizationEndpoint,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub issuer_public: Vec<u8>,
    pub facility_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub facility_values: [u64; 3],
    pub facility_blindings: [[u8; 32]; 3],
    pub wallet_spend_secret: [u8; 32],
    /// Independent X25519 and ML-KEM seeds; required on backup and restore.
    pub wallet_opening_seed: Vec<u8>,
    /// Separate recipient key for encrypted DeKYX holder custody.
    pub credential_custody_seed: Vec<u8>,
    pub identity_seed: [u8; 32],
}

/// Private witness of one canonical facility generation. Only the encrypted
/// corporate journal stores these values, and commitment readback validates them.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FacilityWitness {
    pub facility_id: [u8; 32],
    pub sequence: u64,
    pub values: [u64; 3],
    pub blindings: [[u8; 32]; 3],
}

impl FacilityWitness {
    pub fn commitments(&self) -> Result<[[u8; 32]; 3], String> {
        let key = Pedersen::new(b"qomm:defmi:v1");
        let mut result = [[0; 32]; 3];
        for (i, item) in result.iter_mut().enumerate() {
            *item = key
                .commit_u64(self.values[i], &scalar(self.blindings[i])?)
                .compress()
                .to_bytes();
        }
        Ok(result)
    }
}

/// Persist encrypted BEFORE the first reserve RPC. These bytes cannot be sent
/// to the issuer, coordinator, logs or nodes; only `request` crosses to DeFMI.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedCorporateReserve {
    pub request: PrivateReserveRequest,
    pub order_wire: Vec<u8>,
    #[serde(with = "oclob_core::application_crypto::secret_serde")]
    pub signing_key: [u8; 64],
    pub eligibility_commitment: [u8; 32],
    pub side_blinding: [u8; 32],
    pub reserve_blinding: [u8; 32],
    pub facility_after: FacilityWitness,
}

impl PreparedCorporateReserve {
    pub fn validate(&self, config: &CorporateNativeConfig) -> Result<(), String> {
        let order = SecretOrder::from_secret_wire(&self.order_wire).map_err(err)?;
        let mandate = &self.request.mandate;
        let key = Pedersen::new(b"qomm:defmi:v1");
        let side = match order.side() {
            oclob_core::Side::Buy => 0,
            oclob_core::Side::Sell => 1,
        };
        if mandate.scope.application_binding != oclob_manifest_v1().digest().map_err(err)?
            || mandate.scope.venue_id != config.venue_id
            || mandate.scope.defmi_id != config.defmi_id
            || mandate.facility_id != config.facility_id
            || mandate.asset_id != config.asset_id
            || mandate.hold_id != order.reservation_id()
            || self.request.order_commitment != order.commitment().0
            || mandate.participant_public
                != SigningKey::from_bytes(&self.signing_key).hybrid_public_key()
            || mandate.request_commitment
                != order_authorization_commitment(
                    order.commitment().0,
                    self.request.order_authorization_salt,
                )
                .map_err(err)?
            || mandate.amount_commitment
                != key
                    .commit_u64(order.reservation_limit(), &scalar(self.reserve_blinding)?)
                    .compress()
                    .to_bytes()
            || mandate.settlement_terms_commitment
                != key
                    .commit_u64(side, &scalar(self.side_blinding)?)
                    .compress()
                    .to_bytes()
            || self.facility_after.facility_id != config.facility_id
            || Some(self.facility_after.sequence) != self.request.before_sequence.checked_add(1)
            || self.facility_after.commitments()? != self.request.after
        {
            return Err(
                "saved corporate reserve does not match the configured order or funding witness"
                    .into(),
            );
        }
        scalar(self.request.reserve_reblinding)?;
        Ok(())
    }
}

pub(crate) fn private_client(
    config: &CorporateNativeConfig,
    identity: &crate::network::ClientIdentityConfig,
) -> Result<PrivateAdmissionClient, String> {
    let tls = client_ssl_context(
        &identity.tls_certificate,
        &identity.tls_private_key,
        &identity.tls_ca,
    )?;
    PrivateAdmissionClient::new(
        &config.host,
        config.port,
        &config.server_name,
        tls,
        Duration::from_secs(120),
    )
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
    let prepared = prepare_reservation(
        config,
        identity,
        eligibility,
        order,
        handle,
        eligibility_commitment,
        signer,
        now,
    )?;
    let finalized = finalize_reservation(config, identity, &prepared, now)?;
    build_reserved_delivery(config, &prepared, &finalized, handle, node_keys, now)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_reservation(
    config: &CorporateNativeConfig,
    identity: &crate::network::ClientIdentityConfig,
    eligibility: &DemoEligibilityWallet,
    order: &SecretOrder,
    handle: &Handle,
    eligibility_commitment: [u8; 32],
    signer: &SigningKey,
    now: u64,
) -> Result<PreparedCorporateReserve, String> {
    prepare_reservation_from_note(
        config,
        identity,
        eligibility,
        order,
        handle,
        eligibility_commitment,
        signer,
        now,
        None,
    )
}

/// An explicitly selected recovered note must be used, never silently replaced
/// by another funding input if it is missing, spent or too small.
#[allow(clippy::too_many_arguments)]
pub fn prepare_reservation_from_note(
    config: &CorporateNativeConfig,
    identity: &crate::network::ClientIdentityConfig,
    eligibility: &DemoEligibilityWallet,
    order: &SecretOrder,
    handle: &Handle,
    eligibility_commitment: [u8; 32],
    signer: &SigningKey,
    now: u64,
    source_note: Option<[u8; 32]>,
) -> Result<PreparedCorporateReserve, String> {
    let private = private_client(config, identity)?;
    let scope: ApplicationReserveScope =
        serde_json::from_value(private.call("scope", serde_json::json!({}))?).map_err(err)?;
    if scope.venue_id != config.venue_id
        || scope.defmi_id != config.defmi_id
        || scope.application_binding != oclob_manifest_v1().digest().map_err(err)?
        || scope.amount_bits != 32
    {
        return Err("DeFMI returned another configured application scope".into());
    }
    // This read-only bridge carries no governance signing authority.
    let readonly = QuorumAuthorizer::read_only();
    let client = private.chain()?;
    let bridge = AvalancheNoteBridge::new(&readonly, &client);
    let key = Pedersen::new(b"qomm:defmi:v1");
    let (root, ledger, notes) = bridge.note_ledger(config.asset_id, key.clone(), 32, 4096)?;
    let facility = bridge.credit_facility(config.facility_id)?;
    if facility.state_root != root || client.state_root()? != root {
        return Err("canonical funding changed; rebuild the same request before submission".into());
    }
    let wallet = Wallet::from_parts(
        handle.secret,
        scalar(config.wallet_spend_secret)?,
        config.note_opening_key()?,
    );
    let mut source = None;
    for (index, opening) in ledger.scan(&wallet, &key) {
        if notes[index].lock_id != [0; 32]
            || opening.value < order.reservation_limit()
            || source_note.is_some_and(|id| id != notes[index].note_id)
        {
            continue;
        }
        let serial = qomm_defmi::notes::note_nullifier(&opening.serial)
            .compress()
            .to_bytes();
        let spent = bridge.note_serial(serial)?;
        if spent.state_root != root {
            return Err("funding state changed during note selection".into());
        }
        if !spent.spent {
            source = Some(index);
            break;
        }
    }
    let source =
        source.ok_or("corporate wallet has no sufficient selected unspent funding note")?;
    let ring = select_funding_ring(&notes, source, &mut rand::rngs::OsRng)?;
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
        version: 2,
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
        participant_public: signer.hybrid_public_key(),
        signature: vec![],
    }
    .sign(&signer.raw_hybrid_signer())?;
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
            ring: &ring,
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
    let facility_after = FacilityWitness {
        facility_id: config.facility_id,
        sequence: request
            .before_sequence
            .checked_add(1)
            .ok_or("facility sequence exhausted")?,
        values: [
            config.facility_values[0]
                .checked_sub(order.reservation_limit())
                .ok_or("facility underflow")?,
            config.facility_values[1]
                .checked_add(order.reservation_limit())
                .ok_or("facility overflow")?,
            config.facility_values[2],
        ],
        blindings: [
            (scalar(config.facility_blindings[0])? - reserve_blinding).to_bytes(),
            (scalar(config.facility_blindings[1])? + reserve_blinding).to_bytes(),
            config.facility_blindings[2],
        ],
    };
    Ok(PreparedCorporateReserve {
        request,
        order_wire: order.to_secret_wire(),
        signing_key: signer.to_bytes(),
        eligibility_commitment,
        side_blinding: side_blinding.to_bytes(),
        reserve_blinding: reserve_blinding.to_bytes(),
        facility_after,
    })
}

/// The same signed request is safe to retry even if the first response was
/// lost: the issuer recovers an already finalized hold before re-verification.
pub fn finalize_reservation(
    config: &CorporateNativeConfig,
    identity: &crate::network::ClientIdentityConfig,
    prepared: &PreparedCorporateReserve,
    now: u64,
) -> Result<FinalizedReservation, String> {
    prepared.validate(config)?;
    let private = private_client(config, identity)?;
    let finalized = private.reserve(&prepared.request)?;
    verify_finalized(config, identity, prepared, &finalized, now)?;
    Ok(finalized)
}

pub fn verify_finalized(
    config: &CorporateNativeConfig,
    identity: &crate::network::ClientIdentityConfig,
    prepared: &PreparedCorporateReserve,
    finalized: &FinalizedReservation,
    now: u64,
) -> Result<(), String> {
    prepared.validate(config)?;
    let request = &prepared.request;
    let scope = &request.mandate.scope;
    let issuer = &config.issuer_public;
    let delta = scalar(request.reserve_reblinding)?;
    finalized
        .permit
        .verify(scope.application_binding, config.defmi_id, issuer, now)
        .map_err(err)?;
    finalized
        .admission
        .verify_authority(&finalized.permit, &delta)
        .map_err(err)?;
    // Re-read the exact canonical reserve ourselves; issuer signature alone is
    // insufficient to cause us to distribute a spendable order.
    let client = private_client(config, identity)?.chain()?;
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
    // Do not advance a private witness merely because an RPC returned success.
    let witness = &prepared.facility_after;
    let facility = client.credit_facility_snapshot(witness.facility_id)?;
    let commitments = witness.commitments()?;
    if facility.facility.sequence < witness.sequence
        || (facility.facility.sequence == witness.sequence
            && [
                facility.facility.available_commitment,
                facility.facility.held_commitment,
                facility.facility.outstanding_commitment,
            ] != commitments)
    {
        return Err("canonical facility differs from the reserved witness generation".into());
    }
    Ok(())
}

pub fn build_reserved_delivery(
    config: &CorporateNativeConfig,
    prepared: &PreparedCorporateReserve,
    finalized: &FinalizedReservation,
    handle: &Handle,
    node_keys: &[NodeEncryptionKey; MPC_PARTIES],
    now: u64,
) -> Result<(EdgeOrderBundle, SealedReservationAuthority), String> {
    prepared.validate(config)?;
    let order = SecretOrder::from_secret_wire(&prepared.order_wire).map_err(err)?;
    let signer = SigningKey::from_bytes(&prepared.signing_key);
    let issuer = &config.issuer_public;
    let delta = scalar(prepared.request.reserve_reblinding)?;
    let bundle = EdgeOrderBundle::create_with_reservation_admission(
        &order,
        handle,
        prepared.eligibility_commitment,
        &finalized.admission,
        issuer,
        scalar(prepared.side_blinding)?,
        scalar(prepared.reserve_blinding)? + delta,
        &signer,
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
            &config.claim_authorization_endpoint,
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

impl CorporateNativeConfig {
    pub fn credential_custody_key(
        &self,
    ) -> Result<zkfmi_crypto::hybrid::kem::HybridKemKey, String> {
        let seed: &[u8; 96] = self
            .credential_custody_seed
            .as_slice()
            .try_into()
            .map_err(|_| "corporate credential custody requires its independent 96-byte seed")?;
        if self.credential_custody_seed == self.wallet_opening_seed {
            return Err("credential custody and note delivery require separate keys".into());
        }
        Ok(zkfmi_crypto::hybrid::kem::HybridKemKey::from_seed(seed))
    }

    pub fn note_opening_key(&self) -> Result<zkfmi_crypto::hybrid::kem::HybridKemKey, String> {
        let seed: &[u8; 96] = self
            .wallet_opening_seed
            .as_slice()
            .try_into()
            .map_err(|_| "corporate wallet requires its independent 96-byte opening seed")?;
        Ok(zkfmi_crypto::hybrid::kem::HybridKemKey::from_seed(seed))
    }
}
