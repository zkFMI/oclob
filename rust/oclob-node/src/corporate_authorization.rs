//! Signed corporate terms are durable before funding preparation. The worker
//! needs neither a credential issuer key nor a credential witness to resume.

use crate::corporate::{
    private_client, CorporateNativeConfig, FacilityWitness, PreparedCorporateReserve,
};
use crate::network::ClientIdentityConfig;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use oclob_core::{SecretOrder, Side};
use oclob_dekyx::{AnonymousPresentation, DemoEligibilityWallet};
use oclob_settlement::pretrade::{select_funding_ring, CorporateFunding, PrivateReserveRequest};
use qomm_defmi::application_reservation::{ApplicationReserveMandate, ApplicationReserveScope};
use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge};
use qomm_defmi::facility::QuorumAuthorizer;
use qomm_defmi::notes::Wallet;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::{Handle, Identity};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::reservation::order_authorization_commitment;

/// Private, encrypted corporate-journal material, never a public RPC payload.
/// Only the existing DeKYX presentation and original mandate cross to DeFMI.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorporateReserveAuthorization {
    pub mandate: ApplicationReserveMandate,
    pub order_wire: Vec<u8>,
    pub signing_key: [u8; 32],
    pub eligibility_commitment: [u8; 32],
    pub order_authorization_salt: [u8; 32],
    pub reserve_reblinding: [u8; 32],
    pub reserve_blinding: [u8; 32],
    pub side_blinding: [u8; 32],
    pub identity: AnonymousPresentation,
}

impl CorporateReserveAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        config: &CorporateNativeConfig,
        scope: ApplicationReserveScope,
        eligibility: &DemoEligibilityWallet,
        order: &SecretOrder,
        handle: &Handle,
        eligibility_commitment: [u8; 32],
        signer: &SigningKey,
        now: u64,
    ) -> Result<Self, String> {
        validate_scope(config, &scope)?;
        let key = Pedersen::new(b"qomm:defmi:v1");
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
        let side = u64::from(order.side() == Side::Sell);
        let mandate = ApplicationReserveMandate {
            version: 1,
            scope,
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
            signature: Vec::new(),
        }
        .sign(signer)?;
        let identity = eligibility
            .present_context(
                mandate.identity_context(eligibility.scope_digest())?,
                &mut rand::rngs::OsRng,
            )
            .map_err(err)?;
        let result = Self {
            mandate,
            order_wire: order.to_secret_wire(),
            signing_key: signer.to_bytes(),
            eligibility_commitment,
            order_authorization_salt: salt,
            reserve_reblinding: delta.to_bytes(),
            reserve_blinding: reserve_blinding.to_bytes(),
            side_blinding: side_blinding.to_bytes(),
            identity,
        };
        result.validate(config)?;
        Ok(result)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(b"OCLOB:CORPORATE-AUTHORIZATION:v1")
            .chain_update(serde_json::to_vec(self).map_err(err)?)
            .finalize()
            .into())
    }

    pub fn validate(&self, config: &CorporateNativeConfig) -> Result<(), String> {
        let order = SecretOrder::from_secret_wire(&self.order_wire).map_err(err)?;
        let mandate = &self.mandate;
        validate_scope(config, &mandate.scope)?;
        mandate.verify(&mandate.scope, mandate.valid_from)?;
        let key = Pedersen::new(b"qomm:defmi:v1");
        let handle = Identity::from_seed(config.identity_seed).handle(b"defmi:oclob:v1");
        if mandate.facility_id != config.facility_id
            || mandate.asset_id != config.asset_id
            || mandate.hold_id != order.reservation_id()
            || mandate.valid_until != order.expires_at()
            || mandate.participant_handle != handle.point.compress().to_bytes()
            || mandate.participant_handle != order.participant_handle()
            || mandate.participant_public
                != SigningKey::from_bytes(&self.signing_key)
                    .verifying_key()
                    .to_bytes()
            || mandate.request_commitment
                != order_authorization_commitment(
                    order.commitment().0,
                    self.order_authorization_salt,
                )
                .map_err(err)?
            || mandate.amount_commitment
                != key
                    .commit_u64(order.reservation_limit(), &scalar(self.reserve_blinding)?)
                    .compress()
                    .to_bytes()
            || mandate.settlement_terms_commitment
                != key
                    .commit_u64(
                        u64::from(order.side() == Side::Sell),
                        &scalar(self.side_blinding)?,
                    )
                    .compress()
                    .to_bytes()
            || mandate.entity_commitment != self.identity.subject_line_id().map_err(err)?
            || mandate.credential_digest != self.identity.credential.digest().map_err(err)?
            || self.identity.nullifier != order.dekyx_nullifier()
            || self.identity.context
                != mandate.identity_context(self.identity.context.scope_digest)?
        {
            return Err(
                "corporate authorization differs from the immutable order or deployment".into(),
            );
        }
        scalar(self.reserve_reblinding)?;
        Ok(())
    }
}

pub(crate) fn validate_scope(
    config: &CorporateNativeConfig,
    scope: &ApplicationReserveScope,
) -> Result<(), String> {
    scope.validate()?;
    if scope.venue_id != config.venue_id
        || scope.defmi_id != config.defmi_id
        || scope.application_binding != oclob_manifest_v1().digest().map_err(err)?
        || scope.amount_bits != 32
    {
        return Err("DeFMI returned another configured application scope".into());
    }
    Ok(())
}

pub fn read_authorization_scope(
    config: &CorporateNativeConfig,
    identity: &ClientIdentityConfig,
) -> Result<ApplicationReserveScope, String> {
    let scope = serde_json::from_value(
        private_client(config, identity)?.call("scope", serde_json::json!({}))?,
    )
    .map_err(err)?;
    validate_scope(config, &scope)?;
    Ok(scope)
}

#[derive(Debug)]
pub enum PreparationError {
    Retry(String),
    InsufficientFunding,
}
impl From<String> for PreparationError {
    fn from(value: String) -> Self {
        Self::Retry(value)
    }
}
impl std::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry(message) => f.write_str(message),
            Self::InsufficientFunding => {
                f.write_str("corporate order exceeds currently available selected funding")
            }
        }
    }
}

/// Reuse the existing DeFMI funding proof builder, never a replacement mandate
/// or new credential. Prepared bytes are persisted before the first send.
pub fn prepare_authorized_reservation(
    config: &CorporateNativeConfig,
    identity: &ClientIdentityConfig,
    authorization: &CorporateReserveAuthorization,
    now: u64,
    source_note: Option<[u8; 32]>,
) -> Result<PreparedCorporateReserve, PreparationError> {
    authorization.validate(config)?;
    let scope = read_authorization_scope(config, identity)?;
    authorization.mandate.verify(&scope, now)?;
    let order = SecretOrder::from_secret_wire(&authorization.order_wire).map_err(err)?;
    let handle = Identity::from_seed(config.identity_seed).handle(b"defmi:oclob:v1");
    let private = private_client(config, identity)?;
    let readonly = QuorumAuthorizer::new(
        BTreeMap::from([(
            "read-only".into(),
            VerifyingKey::from_bytes(&config.issuer_public).map_err(err)?,
        )]),
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
        return Err(PreparationError::Retry(
            "canonical funding changed during preparation".into(),
        ));
    }
    let before = FacilityWitness {
        facility_id: config.facility_id,
        sequence: facility.facility.sequence,
        values: config.facility_values,
        blindings: config.facility_blindings,
    };
    if before.commitments()?
        != [
            facility.facility.available_commitment,
            facility.facility.held_commitment,
            facility.facility.outstanding_commitment,
        ]
    {
        return Err(PreparationError::Retry(
            "corporate funding witness is not the current canonical generation".into(),
        ));
    }
    if config.facility_values[0] < order.reservation_limit() {
        return Err(PreparationError::InsufficientFunding);
    }
    let wallet = Wallet::from_parts(handle.secret, scalar(config.wallet_spend_secret)?);
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
            return Err(PreparationError::Retry(
                "funding state changed during note selection".into(),
            ));
        }
        if !spent.spent {
            source = Some(index);
            break;
        }
    }
    let source = source.ok_or(PreparationError::InsufficientFunding)?;
    let ring = select_funding_ring(&notes, source, &mut rand::rngs::OsRng)?;
    let reserve_blinding = scalar(authorization.reserve_blinding)?;
    let request = PrivateReserveRequest::build(
        authorization.mandate.clone(),
        order.commitment().0,
        authorization.order_authorization_salt,
        scalar(authorization.reserve_reblinding)?,
        authorization.identity.clone(),
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
            .ok_or_else(|| "facility sequence exhausted".to_string())?,
        values: [
            config.facility_values[0]
                .checked_sub(order.reservation_limit())
                .ok_or_else(|| "facility underflow".to_string())?,
            config.facility_values[1]
                .checked_add(order.reservation_limit())
                .ok_or_else(|| "facility overflow".to_string())?,
            config.facility_values[2],
        ],
        blindings: [
            (scalar(config.facility_blindings[0])? - reserve_blinding).to_bytes(),
            (scalar(config.facility_blindings[1])? + reserve_blinding).to_bytes(),
            config.facility_blindings[2],
        ],
    };
    let result = PreparedCorporateReserve {
        request,
        order_wire: authorization.order_wire.clone(),
        signing_key: authorization.signing_key,
        eligibility_commitment: authorization.eligibility_commitment,
        side_blinding: authorization.side_blinding,
        reserve_blinding: authorization.reserve_blinding,
        facility_after,
    };
    result.validate(config)?;
    Ok(result)
}

fn scalar(bytes: [u8; 32]) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or("non-canonical corporate scalar".into())
}
fn random() -> [u8; 32] {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
