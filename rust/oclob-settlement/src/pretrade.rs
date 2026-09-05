//! Corporate-owned note proofs and the private DeFMI admission boundary.
//!
//! No order, amount opening or wallet key is sent to the approval service.
//! A successful proof check is not admission: the issuer reads the finalized
//! reservation from its own chain client before returning a signed permit.

use curve25519_dalek::scalar::Scalar;
use dekyx_core::{AnonymousPresentation, DeKyxVerifier, EligibilityRequirement};
use ed25519_dalek::SigningKey;
use qomm_defmi::application_reservation::{
    ApplicationIdentityEvidence, ApplicationReserveMandate, ApplicationReserveScope,
    VerifiedApplicationNoteReservation,
};
use qomm_defmi::avalanche::{AvalancheClient, AvalancheNoteBridge, CanonicalCreditFacility};
use qomm_defmi::facility::{
    CreditFacilityRelationProof, CreditFacilityStatus, CreditFacilityTransition,
    CreditTransitionKind, QuorumApproval, ZERO,
};
use qomm_defmi::note_chain::NoteOutput;
use qomm_defmi::notes::{decode_spend_proof, encode_spend_proof, NoteLedger, Wallet};
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zkpi_defmi_sdk::admission::ReservationAdmission;
use zkpi_defmi_sdk::application::oclob_manifest_v1;
use zkpi_defmi_sdk::reservation::{
    order_authorization_commitment, ApplicationReservationPermitIssue, ReservationPermit,
};

pub const MAX_PRETRADE_BYTES: usize = 1024 * 1024;

/// Reuses the pinned resident-service mTLS client and bounded message codec.
/// The ingress accepts only named pretrade operations and public chain RPCs;
/// it is not an arbitrary-signature or arbitrary-HTTP forwarding service.
#[derive(Clone)]
pub struct PrivateAdmissionClient {
    rpc: Arc<Mutex<qomm_transport::proof_client::ProofPartyTlsClient>>,
    endpoint: String,
    timeout: Duration,
}

impl PrivateAdmissionClient {
    pub fn new(
        host: &str,
        port: u16,
        server_name: &str,
        tls: qomm_transport::node_service::ClientTlsConfig,
        timeout: Duration,
    ) -> Result<Self, String> {
        if host.is_empty() || server_name.is_empty() || port == 0 || timeout.is_zero() {
            return Err("private DeFMI endpoint is incomplete".into());
        }
        Ok(Self {
            rpc: Arc::new(Mutex::new(
                qomm_transport::proof_client::ProofPartyTlsClient::new(
                    host,
                    port,
                    tls,
                    server_name,
                    timeout,
                ),
            )),
            endpoint: format!("https://{server_name}:{port}/defmi"),
            timeout,
        })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        if serde_json::to_vec(&params).map_err(err)?.len() > MAX_PRETRADE_BYTES {
            return Err("private DeFMI request exceeds its wire bound".into());
        }
        let mut rpc = self
            .rpc
            .lock()
            .map_err(|_| "private DeFMI client is poisoned")?;
        let response = rpc.call(method, params);
        // Do not retry a state-changing request on a new connection. Recovery
        // explicitly asks for its finalized permit using the same mandate.
        if response.is_err() {
            rpc.close();
        }
        response
    }

    pub fn chain(&self) -> Result<qomm_defmi::avalanche::AvalancheRpcClient, String> {
        let transport = self.clone();
        qomm_defmi::avalanche::AvalancheRpcClient::with_transport(
            &self.endpoint,
            self.timeout,
            false,
            move |body, _| {
                let response =
                    transport.call("chain", serde_json::from_slice(body).map_err(err)?)?;
                serde_json::to_vec(&response).map_err(err)
            },
        )
    }

    pub fn reserve(&self, request: &PrivateReserveRequest) -> Result<FinalizedReservation, String> {
        request.validate_shape()?;
        serde_json::from_value(self.call("reserve", serde_json::to_value(request).map_err(err)?)?)
            .map_err(err)
    }
}

/// Private request to the configured DeFMI issuer, never to the order router.
/// Array order: available, held, outstanding. Only hiding commitments cross
/// this boundary; the corresponding values and blindings do not.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateReserveRequest {
    pub mandate: ApplicationReserveMandate,
    pub order_commitment: [u8; 32],
    pub order_authorization_salt: [u8; 32],
    pub reserve_reblinding: [u8; 32],
    pub operation_id: [u8; 32],
    pub before_sequence: u64,
    pub before: [[u8; 32]; 3],
    pub after: [[u8; 32]; 3],
    pub ring: Vec<[u8; 32]>,
    pub outputs: Vec<Value>,
    pub relation_proof: Vec<u8>,
    pub relation_proof_digest: [u8; 32],
    pub spend_proof: Vec<u8>,
    pub identity: AnonymousPresentation,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedReservation {
    pub permit: ReservationPermit,
    pub admission: ReservationAdmission,
}

/// Stays exclusively in the corporate process. Deliberately no serialization
/// or Debug implementation. Wallet keys also control the covenant output, so
/// expiry before the first fill does not require the MPC committee to recover it.
pub struct CorporateFunding<'a> {
    pub wallet: &'a Wallet,
    pub ledger: &'a NoteLedger,
    pub canonical_notes: &'a [NoteOutput],
    pub ring: &'a [usize],
    pub source_index: usize,
    pub facility: &'a CanonicalCreditFacility,
    pub facility_values: [u64; 3],
    pub facility_blindings: [Scalar; 3],
    pub reserve_value: u64,
    pub reserve_blinding: Scalar,
}

impl PrivateReserveRequest {
    /// Build proofs from the participant's actual canonical notes. DeKYX
    /// evidence is produced after the mandate was signed, avoiding a circular
    /// signature/presentation dependency.
    #[allow(clippy::too_many_arguments)]
    pub fn build<R: RngCore + CryptoRng>(
        mandate: ApplicationReserveMandate,
        order_commitment: [u8; 32],
        order_authorization_salt: [u8; 32],
        reserve_reblinding: Scalar,
        identity: AnonymousPresentation,
        funding: CorporateFunding<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Self, String> {
        mandate.verify(&mandate.scope, now)?;
        let key = Pedersen::new(b"qomm:defmi:v1");
        let commit = |value, blind: Scalar| key.commit_u64(value, &blind).compress().to_bytes();
        let facility = &funding.facility.facility;
        let before = [
            facility.available_commitment,
            facility.held_commitment,
            facility.outstanding_commitment,
        ];
        if funding.facility.state_root == ZERO
            || facility.status != CreditFacilityStatus::Active
            || facility.facility_id != mandate.facility_id
            || facility.rail_asset_id != mandate.asset_id
            || facility.beneficiary_commitment != mandate.entity_commitment
            || facility.valid_from > now
            || facility.valid_until < mandate.valid_until
            || funding.ledger.bits != usize::from(mandate.scope.amount_bits)
            || funding.ledger.key.g != key.g
            || funding.ledger.key.h != key.h
            || funding.ledger.notes.len() != funding.canonical_notes.len()
            || funding.ring.len() < 2
            || funding.ring.len() > 64
            || !funding.ring.len().is_power_of_two()
            || !funding.ring.contains(&funding.source_index)
            || funding.ring.iter().copied().collect::<BTreeSet<_>>().len() != funding.ring.len()
            || funding.reserve_value == 0
            || before
                != std::array::from_fn(|i| {
                    commit(funding.facility_values[i], funding.facility_blindings[i])
                })
            || mandate.amount_commitment != commit(funding.reserve_value, funding.reserve_blinding)
            || mandate.request_commitment
                != order_authorization_commitment(order_commitment, order_authorization_salt)
                    .map_err(err)?
        {
            return Err(
                "corporate funding does not match the canonical facility or signed mandate".into(),
            );
        }
        let mut ring_ids = Vec::new();
        for &index in funding.ring {
            let output = funding
                .canonical_notes
                .get(index)
                .ok_or("ring index is outside canonical notes")?;
            let local =
                NoteOutput::from_note(&funding.ledger.notes[index], mandate.asset_id, ZERO)?;
            if output != &local {
                return Err("ring contains a locked, foreign or substituted note".into());
            }
            ring_ids.push(output.note_id);
        }
        let available = funding.facility_values[0]
            .checked_sub(funding.reserve_value)
            .ok_or("reservation exceeds available facility")?;
        let held = funding.facility_values[1]
            .checked_add(funding.reserve_value)
            .ok_or("held facility overflow")?;
        let after_values = [available, held, funding.facility_values[2]];
        let after_blindings = [
            funding.facility_blindings[0] - funding.reserve_blinding,
            funding.facility_blindings[1] + funding.reserve_blinding,
            funding.facility_blindings[2],
        ];
        let after = std::array::from_fn(|i| commit(after_values[i], after_blindings[i]));
        let mut operation_id = [0; 32];
        rng.fill_bytes(&mut operation_id);
        let mut request = Self {
            mandate,
            order_commitment,
            order_authorization_salt,
            reserve_reblinding: reserve_reblinding.to_bytes(),
            operation_id,
            before_sequence: facility.sequence,
            before,
            after,
            ring: ring_ids,
            outputs: vec![],
            relation_proof: vec![],
            relation_proof_digest: ZERO,
            spend_proof: vec![],
            identity,
        };
        let mut transition = request.transition(ZERO);
        let relation = CreditFacilityRelationProof::prove(
            &mut transition,
            [
                after_values[0],
                after_values[1],
                after_values[2],
                funding.reserve_value,
            ],
            [
                after_blindings[0],
                after_blindings[1],
                after_blindings[2],
                funding.reserve_blinding,
            ],
            [0; 2],
            [Scalar::ZERO; 2],
            rng,
        )?;
        request.relation_proof = relation.to_bytes()?;
        request.relation_proof_digest = transition.relation_proof_digest;
        let opening = funding
            .ledger
            .scan(funding.wallet, &key)
            .into_iter()
            .find_map(|(index, value)| (index == funding.source_index).then_some(value))
            .ok_or("corporate wallet does not own the selected funding note")?;
        let change = opening
            .value
            .checked_sub(funding.reserve_value)
            .ok_or("reservation exceeds the selected funding note")?;
        let spend = funding.ledger.build_spend_constrained_with_blindings(
            funding.ring,
            funding.source_index,
            &opening,
            &key.g,
            &Scalar::ZERO,
            &[
                (funding.wallet.address, funding.reserve_value),
                (funding.wallet.address, change),
            ],
            &[funding.reserve_blinding, Scalar::random(&mut *rng)],
            &[true; 2],
            &request.mandate.spend_context()?,
            rng,
        )?;
        request.spend_proof = encode_spend_proof(&spend.proof)?;
        request.outputs = spend
            .notes
            .iter()
            .enumerate()
            .map(|(index, note)| {
                NoteOutput::from_note(
                    note,
                    request.mandate.asset_id,
                    if index == 0 {
                        request.mandate.hold_id
                    } else {
                        ZERO
                    },
                )?
                .body()
            })
            .collect::<Result<_, String>>()?;
        request.validate_shape()?;
        Ok(request)
    }

    fn transition(&self, relation_proof_digest: [u8; 32]) -> CreditFacilityTransition {
        CreditFacilityTransition {
            operation_id: self.operation_id,
            facility_id: self.mandate.facility_id,
            hold_id: self.mandate.hold_id,
            kind: CreditTransitionKind::Hold,
            query_commitment: self.mandate.request_commitment,
            amount_commitment: self.mandate.amount_commitment,
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: self.before[0],
            after_available_commitment: self.after[0],
            before_held_commitment: self.before[1],
            after_held_commitment: self.after[1],
            before_outstanding_commitment: self.before[2],
            after_outstanding_commitment: self.after[2],
            before_sequence: self.before_sequence,
            expires_at: self.mandate.valid_until,
            settlement_digest: ZERO,
            relation_proof_digest,
        }
    }

    fn validate_shape(&self) -> Result<(), String> {
        if self.ring.len() < 2
            || self.ring.len() > 64
            || !self.ring.len().is_power_of_two()
            || self.ring.iter().copied().collect::<BTreeSet<_>>().len() != self.ring.len()
            || self.outputs.len() != 2
            || self.relation_proof.is_empty()
            || self.spend_proof.is_empty()
            || self.relation_proof.len() > MAX_PRETRADE_BYTES / 4
            || self.spend_proof.len() > MAX_PRETRADE_BYTES / 4
            || serde_json::to_vec(self).map_err(err)?.len() > MAX_PRETRADE_BYTES
            || Option::<Scalar>::from(Scalar::from_canonical_bytes(self.reserve_reblinding))
                .is_none()
        {
            return Err("private reservation request is outside its bounded wire format".into());
        }
        Ok(())
    }

    /// The issuer reconstructs every note from its own canonical client. It
    /// never accepts a caller-provided ledger or a purported verification flag.
    pub fn verify<C: AvalancheClient, R: RngCore + CryptoRng>(
        &self,
        bridge: &AvalancheNoteBridge<'_, C>,
        scope: &ApplicationReserveScope,
        verifier: &DeKyxVerifier<'_>,
        requirement: &EligibilityRequirement,
        now: u64,
        rng: &mut R,
    ) -> Result<VerifiedApplicationNoteReservation, String> {
        self.validate_shape()?;
        if self.mandate.scope != *scope
            || self.mandate.request_commitment
                != order_authorization_commitment(
                    self.order_commitment,
                    self.order_authorization_salt,
                )
                .map_err(err)?
        {
            return Err("private reservation names another configured deployment or order".into());
        }
        let before = bridge.client.state_root()?;
        let mut ledger = NoteLedger::new(
            Pedersen::new(b"qomm:defmi:v1"),
            usize::from(scope.amount_bits),
        );
        for note_id in &self.ring {
            let note = bridge.note(*note_id)?;
            if note.state_root != before
                || note.output.asset_id != self.mandate.asset_id
                || note.output.lock_id != ZERO
            {
                return Err("issuer read a stale, locked or foreign ring note".into());
            }
            ledger.add(note.output.to_note()?);
        }
        let facility = bridge.credit_facility(self.mandate.facility_id)?;
        if facility.state_root != before
            || bridge.client.state_root()? != before
            || facility.facility.sequence != self.before_sequence
            || [
                facility.facility.available_commitment,
                facility.facility.held_commitment,
                facility.facility.outstanding_commitment,
            ] != self.before
        {
            return Err("reservation proof is stale relative to canonical facility state".into());
        }
        let relation = CreditFacilityRelationProof::from_bytes(&self.relation_proof)?;
        let transition = self.transition(self.relation_proof_digest);
        let outputs = self
            .outputs
            .iter()
            .map(NoteOutput::from_body)
            .collect::<Result<Vec<_>, _>>()?;
        let notes = outputs
            .iter()
            .map(NoteOutput::to_note)
            .collect::<Result<Vec<_>, _>>()?;
        let locks = outputs.iter().map(|note| note.lock_id).collect::<Vec<_>>();
        VerifiedApplicationNoteReservation::verify(
            self.mandate.clone(),
            transition,
            &relation,
            scope,
            &ApplicationIdentityEvidence {
                verifier,
                requirement,
                presentation: &self.identity,
            },
            &ledger,
            &(0..self.ring.len()).collect::<Vec<_>>(),
            &decode_spend_proof(&self.spend_proof)?,
            &notes,
            &vec![ZERO; self.ring.len()],
            &locks,
            now,
            rng,
        )
    }

    /// Submit exact approved bytes, wait for chain acceptance, then attest to
    /// the finalized hold. Approval construction belongs to the issuer service.
    pub fn finalize<C: AvalancheClient>(
        &self,
        bridge: &AvalancheNoteBridge<'_, C>,
        verified: &VerifiedApplicationNoteReservation,
        approval: &QuorumApproval,
        issuer: &SigningKey,
        now: u64,
    ) -> Result<FinalizedReservation, String> {
        if verified.reservation().binding != self.mandate.binding()? {
            return Err("verified reserve belongs to another private request".into());
        }
        bridge.reserve_application(verified, approval)?;
        self.recover_finalized(bridge.client, issuer, now)
    }

    /// Explicit recovery after a lost reply, not a silent retry with new funds.
    pub fn recover_finalized<C: AvalancheClient>(
        &self,
        client: &C,
        issuer: &SigningKey,
        now: u64,
    ) -> Result<FinalizedReservation, String> {
        self.validate_shape()?;
        let permit = ReservationPermit::issue_from_application_reservation(
            client,
            ApplicationReservationPermitIssue {
                application: &oclob_manifest_v1(),
                scope: &self.mandate.scope,
                mandate: &self.mandate,
                order_commitment: self.order_commitment,
                order_authorization_salt: self.order_authorization_salt,
                observed_at: now,
            },
            issuer,
        )
        .map_err(err)?;
        let delta = Option::<Scalar>::from(Scalar::from_canonical_bytes(self.reserve_reblinding))
            .ok_or("invalid reserve reblinding")?;
        let admission = ReservationAdmission::from_permit(&permit, &delta, issuer).map_err(err)?;
        Ok(FinalizedReservation { permit, admission })
    }
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
