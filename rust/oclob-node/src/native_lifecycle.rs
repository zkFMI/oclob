//! Ordered native reservation termination. An owner signs with the original
//! one-time order key, never by revealing the order's cancellation salt.
//! A command is not permission to remove shares: canonical release must be
//! independently observed by this node before it forgets the active order.

use crate::{NodeError, NodeShareStore};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{Digest32, OrderCommitment};
use oclob_edge::EdgeOrderManifest;
use oclob_ordering::OrderCertificate;
use oclob_settlement::native::{NativeReservationAuthority, NativeReservationTrust};
use oclob_settlement::pretrade::PrivateAdmissionClient;
use qomm_defmi::application_reservation::ApplicationReserveScope;
use qomm_defmi::application_settlement::ApplicationNoteRelease;
use qomm_defmi::application_settlement::ApplicationReleaseReason;
use qomm_defmi::avalanche::{AvalancheClient, CanonicalApplicationReservation};
use qomm_transport::proof_party::{ApplicationControlAuthorization, ApplicationControlVerifier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReleaseRequest {
    pub command: Digest32,
    pub release: ApplicationNoteRelease,
    pub authority: NativeReservationAuthority,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReleaseConfirmation {
    pub authorization: NativeReleaseRequest,
    pub transaction_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommand {
    pub version: u16,
    pub market_id: String,
    pub target: OrderCommitment,
    pub reason: ApplicationReleaseReason,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: Digest32,
    pub signature: Vec<u8>,
}

impl LifecycleCommand {
    pub fn cancel(
        manifest: &EdgeOrderManifest,
        now: u64,
        expires_at: u64,
        nonce: Digest32,
        key: &SigningKey,
    ) -> Result<Self, String> {
        let mut command = Self {
            version: 1,
            market_id: manifest.market_id.clone(),
            target: manifest.commitment,
            reason: ApplicationReleaseReason::Cancelled,
            issued_at: now,
            expires_at,
            nonce,
            signature: Vec::new(),
        };
        command.signature = key.sign(&command.digest()?).to_bytes().to_vec();
        command.verify(manifest, now)?;
        Ok(command)
    }

    pub fn expire(manifest: &EdgeOrderManifest, now: u64, expires_at: u64) -> Result<Self, String> {
        let command = Self {
            version: 1,
            market_id: manifest.market_id.clone(),
            target: manifest.commitment,
            reason: ApplicationReleaseReason::Expired,
            issued_at: now,
            expires_at,
            nonce: [0; 32],
            signature: Vec::new(),
        };
        command.verify(manifest, now)?;
        Ok(command)
    }

    pub fn digest(&self) -> Result<Digest32, String> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(Sha256::new()
            .chain_update(b"OCLOB:NATIVE-LIFECYCLE:v1")
            .chain_update(serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?)
            .finalize()
            .into())
    }

    pub fn verify(&self, manifest: &EdgeOrderManifest, now: u64) -> Result<(), String> {
        // Expiry recovery still authenticates the original manifest at its
        // signed deadline. It does not pretend the order is valid today.
        manifest
            .verify(manifest.retention_deadline)
            .map_err(|e| e.to_string())?;
        if self.version != 1
            || self.market_id != manifest.market_id
            || self.target != manifest.commitment
            || !manifest.uses_pretrade_reservation()
            || self.issued_at > now
            || now > self.expires_at
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 1800
        {
            return Err("lifecycle command is outside its order or validity interval".into());
        }
        match self.reason {
            ApplicationReleaseReason::Cancelled => {
                if self.nonce == [0; 32] || self.expires_at > manifest.retention_deadline {
                    return Err("cancellation needs a fresh nonce and a live order".into());
                }
                let key = VerifyingKey::from_bytes(&manifest.signer).map_err(|e| e.to_string())?;
                let signature =
                    Signature::try_from(self.signature.as_slice()).map_err(|e| e.to_string())?;
                key.verify_strict(&self.digest()?, &signature)
                    .map_err(|_| "cancellation owner signature is invalid")?;
            }
            ApplicationReleaseReason::Expired => {
                if self.issued_at <= manifest.retention_deadline
                    || self.nonce != [0; 32]
                    || !self.signature.is_empty()
                {
                    return Err(
                        "expiry must follow the actual deadline without an owner signature".into(),
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredLifecycle {
    pub command: LifecycleCommand,
    pub manifest: EdgeOrderManifest,
    pub certificate: Option<OrderCertificate>,
    pub finality: Option<LifecycleFinality>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleFinality {
    pub command: Digest32,
    pub target: OrderCommitment,
    pub transaction_id: String,
    pub block_id: String,
    pub height: u64,
    pub statement: Digest32,
    pub before_root: Digest32,
    pub after_root: Digest32,
    pub released_sequence: u64,
}

impl NodeShareStore {
    pub(crate) fn require_lifecycle_barrier(&self) -> Result<(), NodeError> {
        if self
            .state
            .lifecycle
            .values()
            .any(|entry| entry.certificate.is_some() && entry.finality.is_none())
            || self.state.completed_rounds.iter().any(|(round, receipt)| {
                receipt.result.slots.iter().any(|slot| slot.matched)
                    && !self.state.finalized_private_rounds.contains_key(round)
            })
        {
            return Err(NodeError::Ordering(
                "earlier matching or release still awaits canonical finality".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn lifecycle_blocks(&self, target: OrderCommitment) -> bool {
        self.state
            .lifecycle
            .values()
            .any(|entry| entry.command.target == target && entry.certificate.is_some())
    }

    pub(crate) fn register_lifecycle(
        &mut self,
        command: LifecycleCommand,
        now: u64,
    ) -> Result<Digest32, NodeError> {
        let digest = command.digest().map_err(NodeError::Ordering)?;
        if let Some(entry) = self.state.lifecycle.get(&hex::encode(digest)) {
            return if entry.command == command {
                Ok(digest)
            } else {
                Err(NodeError::Conflict)
            };
        }
        self.require_lifecycle_barrier()?;
        if self.lifecycle_blocks(command.target) {
            return Err(NodeError::Conflict);
        }
        let record = self
            .state
            .records
            .get(&command.target.hex())
            .ok_or(NodeError::UnknownOrder)?;
        command
            .verify(&record.manifest, now)
            .map_err(NodeError::Ordering)?;
        if !self
            .state
            .ordered_commitments
            .contains(&command.target.hex())
        {
            return Err(NodeError::Ordering(
                "lifecycle target has not entered the ordered market".into(),
            ));
        }
        let previous = self.state.clone();
        self.state.lifecycle.insert(
            hex::encode(digest),
            StoredLifecycle {
                command,
                manifest: record.manifest.clone(),
                certificate: None,
                finality: None,
            },
        );
        if let Err(error) = self.bump_generation().and_then(|_| self.persist()) {
            self.state = previous;
            return Err(error);
        }
        Ok(digest)
    }

    pub(crate) fn ordering_admission(
        &self,
        commitment: OrderCommitment,
        now: u64,
    ) -> Result<(&str, u64), NodeError> {
        if let Some(record) = self.state.records.get(&commitment.hex()) {
            if self.lifecycle_blocks(commitment) {
                return Err(NodeError::Conflict);
            }
            return Ok((
                &record.manifest.market_id,
                record.manifest.retention_deadline,
            ));
        }
        let entry = self
            .state
            .lifecycle
            .get(&commitment.hex())
            .ok_or(NodeError::UnknownOrder)?;
        entry
            .command
            .verify(&entry.manifest, now)
            .map_err(NodeError::Ordering)?;
        self.require_lifecycle_barrier()?;
        Ok((&entry.command.market_id, entry.command.expires_at))
    }

    pub(crate) fn lifecycle_entry(&self, digest: Digest32) -> Result<&StoredLifecycle, NodeError> {
        let entry = self
            .state
            .lifecycle
            .get(&hex::encode(digest))
            .ok_or(NodeError::UnknownOrder)?;
        if entry.certificate.is_none() {
            return Err(NodeError::Ordering(
                "lifecycle command has no accepted ordering certificate".into(),
            ));
        }
        Ok(entry)
    }

    pub(crate) fn lifecycle_share(
        &self,
        digest: Digest32,
    ) -> Result<oclob_edge::CapabilityKeyShare, NodeError> {
        let entry = self.lifecycle_entry(digest)?;
        if entry.finality.is_some() {
            return Err(NodeError::Conflict);
        }
        let record = self
            .state
            .records
            .get(&entry.command.target.hex())
            .ok_or(NodeError::UnknownOrder)?;
        // This is authority metadata, not order fields. The ordered lifecycle
        // gate remains necessary even when opening at the original intake time.
        record
            .sealed_capability_key_share
            .as_ref()
            .ok_or(NodeError::UnknownOrder)?
            .open(
                &self.key,
                &record.manifest,
                self.state.party,
                record.admitted_at,
            )
            .map_err(|e| NodeError::Release(e.to_string()))
    }
}

/// Validate against a copy made from this node's accepted command, not a
/// caller-provided manifest or claim of committee approval.
fn verify_authority(
    request: &NativeReleaseRequest,
    entry: &StoredLifecycle,
    trust: &NativeReservationTrust,
    head: &CanonicalApplicationReservation,
) -> Result<(), String> {
    let release = &request.release;
    let authority = &request.authority;
    let manifest = &entry.manifest;
    let anchor = manifest.retention_deadline;
    entry.command.verify(manifest, entry.command.issued_at)?;
    authority
        .admission
        .verify(
            release.scope.application_binding,
            trust.defmi_id,
            &trust.issuer,
            anchor,
        )
        .map_err(|e| e.to_string())?;
    authority
        .permit
        .verify(
            release.scope.application_binding,
            trust.defmi_id,
            &trust.issuer,
            anchor,
        )
        .map_err(|e| e.to_string())?;
    let delta = Option::<curve25519_dalek::scalar::Scalar>::from(
        curve25519_dalek::scalar::Scalar::from_canonical_bytes(authority.reserve_reblinding),
    )
    .ok_or("release authority reblinding is not canonical")?;
    authority
        .admission
        .verify_authority(&authority.permit, &delta)
        .map_err(|e| e.to_string())?;
    if entry.command.digest()? != request.command
        || release.operation_id != request.command
        || release.reason != entry.command.reason
        || release.scope.venue_id != trust.venue_id
        || release.scope.defmi_id != trust.defmi_id
        || head.binding.scope != release.scope
        || release.hold_id != head.binding.hold_id
        || release.hold_id != authority.permit.reservation_id
        || authority.permit.role != zkpi_defmi_sdk::reservation::ReservationRole::Application
        || authority.permit.venue_id != trust.venue_id
        || authority.admission.digest().map_err(|e| e.to_string())?
            != manifest.reservation_admission_digest
        || authority.admission.order_commitment != manifest.source_order_commitment
        || authority.admission.participant_handle != manifest.settlement_field_commitments[0][0]
        || authority.admission.amount_commitment != manifest.settlement_field_commitments[1][0]
        || authority.admission.side_commitment != manifest.field_commitments[0][0]
        || head.binding.amount_commitment != authority.permit.amount_commitment
        || head.binding.asset_id != authority.permit.asset_id
        || head.reserve_receipt_digest != authority.permit.reserve_receipt_digest
        || head.binding.valid_until != manifest.retention_deadline
    {
        return Err("release authority differs from this node's ordered reservation".into());
    }
    Ok(())
}

struct VerifiedControl<'a> {
    request: &'a NativeReleaseRequest,
}

impl ApplicationControlVerifier for VerifiedControl<'_> {
    fn verify(
        &self,
        public: &qomm_zkpi::frost::keys::PublicKeyPackage,
    ) -> Result<ApplicationControlAuthorization, String> {
        let release = &self.request.release;
        if release.reason != ApplicationReleaseReason::Cancelled
            || !release.signature.is_empty()
            || release.pq_authorization.is_some()
            || release.committee_public != public.serialize().map_err(|e| e.to_string())?
            || <Digest32>::from(Sha256::digest(&release.committee_public))
                != release.scope.committee_key_digest
        {
            return Err("cancel signing does not name this initialized committee".into());
        }
        release.scope.verify_committee(
            &release.committee_public,
            release
                .pq_committee
                .as_ref()
                .ok_or("cancellation lacks its PQ committee")?,
        )?;
        let mut action = release.clone();
        action.before_root = [1; 32]; // Only unrelated canonical parent activity may change.
        Ok(ApplicationControlAuthorization {
            control_id: self.request.command,
            message: release.signing_message()?,
            action_digest: action.signing_message()?,
        })
    }
}

impl crate::native_finality::NativeFinalityHandle {
    pub(crate) fn authorize_release(
        &self,
        client: &PrivateAdmissionClient,
        trust: &NativeReservationTrust,
        request: &NativeReleaseRequest,
        party: &mut qomm_transport::proof_party::ProofParty,
        now: u64,
    ) -> Result<Digest32, String> {
        // Holding the local store lock keeps authorization serialized with
        // terminal observation; no later matching can start while pending.
        let store = self
            .store
            .lock()
            .map_err(|_| "node store lock is poisoned")?;
        let entry = store
            .lifecycle_entry(request.command)
            .map_err(|e| e.to_string())?;
        if entry.finality.is_some() {
            return Err("native release is already final".into());
        }
        entry.command.verify(&entry.manifest, now)?;
        let scope: ApplicationReserveScope =
            serde_json::from_value(client.call("scope", json!({}))?)
                .map_err(|_| "native release scope is malformed")?;
        let head = client
            .chain()?
            .application_reservation_snapshot(request.release.hold_id)?;
        verify_authority(request, entry, trust, &head)?;
        if scope != request.release.scope
            || head.status != "active"
            || head.state_root != request.release.before_root
            || head.sequence != request.release.sequence
            || head.head_receipt != request.release.previous_receipt
        {
            return Err("native release names a stale canonical reservation head".into());
        }
        party.authorize_application_control(&VerifiedControl { request })
    }

    pub(crate) fn confirm_release(
        &self,
        client: &PrivateAdmissionClient,
        trust: &NativeReservationTrust,
        confirmation: &NativeReleaseConfirmation,
    ) -> Result<LifecycleFinality, String> {
        let request = &confirmation.authorization;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "node store lock is poisoned")?;
        let entry = store
            .lifecycle_entry(request.command)
            .map_err(|e| e.to_string())?
            .clone();
        let scope: ApplicationReserveScope =
            serde_json::from_value(client.call("scope", json!({}))?)
                .map_err(|_| "native release scope is malformed")?;
        let chain = client.chain()?;
        let accepted = chain.wait_accepted(
            &confirmation.transaction_id,
            Duration::from_secs(10),
            Duration::from_millis(100),
        )?;
        let head = chain.application_reservation_snapshot(request.release.hold_id)?;
        verify_authority(request, &entry, trust, &head)?;
        let release = &request.release;
        // Exact accepted bytes establish real VM enforcement of time. This
        // anchor checks old signatures without expiring a final receipt.
        let anchor = head
            .binding
            .valid_until
            .checked_add(1)
            .ok_or("release deadline overflow")?;
        let statement = release.verify(&scope, head.binding.valid_until, anchor)?;
        crate::native_finality::validate_accepted(
            &confirmation.transaction_id,
            statement,
            release.before_root,
            &accepted,
        )?;
        if head.status != "released"
            || head.sequence
                != release
                    .sequence
                    .checked_add(1)
                    .ok_or("release sequence overflow")?
            || head.head_receipt != statement
            || head.remaining_opening.is_some()
        {
            return Err("canonical release has not terminated this reservation".into());
        }
        let record = LifecycleFinality {
            command: request.command,
            target: entry.command.target,
            transaction_id: accepted.tx_id,
            block_id: accepted.block_id,
            height: accepted.height,
            statement,
            before_root: accepted.before_root,
            after_root: accepted.after_root,
            released_sequence: head.sequence,
        };
        if let Some(existing) = &entry.finality {
            return if existing == &record {
                Ok(record)
            } else {
                Err("release finality changed".into())
            };
        }
        let previous = store.state.clone();
        store
            .state
            .lifecycle
            .get_mut(&hex::encode(request.command))
            .ok_or("release entry disappeared")?
            .finality = Some(record.clone());
        store.state.private_heads.remove(&record.target.hex());
        store.state.records.remove(&record.target.hex());
        if let Err(error) = store.bump_generation().and_then(|_| store.persist()) {
            store.state = previous;
            return Err(error.to_string());
        }
        Ok(record)
    }
}

pub fn certify_native_release<T: qomm_transport::proof_client::ProofPartyRpc>(
    parties: &mut [T],
    request: &NativeReleaseRequest,
) -> Result<ApplicationNoteRelease, String> {
    if parties.len() != 7 || request.release.reason != ApplicationReleaseReason::Cancelled {
        return Err("ordered cancellation requires the seven-node committee".into());
    }
    let message = request.release.signing_message()?;
    let quorum = [1, 4, 7]; // Same configured 3-of-7 committee as native fills.
    for index in quorum {
        let response = parties[index - 1].call(
            "authorize_oclob_native_release",
            serde_json::to_value(request).map_err(|e| e.to_string())?,
        )?;
        if response["message"].as_str() != Some(&hex::encode(message)) {
            return Err("node authorized another release".into());
        }
    }
    let public =
        qomm_zkpi::frost::keys::PublicKeyPackage::deserialize(&request.release.committee_public)
            .map_err(|e| e.to_string())?;
    let signed = qomm_transport::frost_coordinator::distributed_hybrid_sign(
        parties,
        &quorum,
        &message,
        &public,
        request
            .release
            .pq_committee
            .as_ref()
            .ok_or("cancellation lacks its PQ committee")?,
    )?;
    let mut release = request.release.clone();
    release.signature = signed.classical.serialize().map_err(|e| e.to_string())?;
    release.pq_authorization = Some(signed.pq);
    Ok(release)
}

pub fn order_lifecycle(
    cluster: &crate::network::ClusterPublicConfig,
    coordinator_tls: crate::network::ClientTlsConfig,
    settlement_tls: crate::network::ClientTlsConfig,
    manifest: &EdgeOrderManifest,
    command: &LifecycleCommand,
    previous: &OrderCertificate,
) -> Result<
    (
        OrderCertificate,
        crate::edge_client::ThresholdCapabilityRelease,
    ),
    String,
> {
    cluster.validate().map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    command.verify(manifest, now)?;
    for node in &cluster.nodes {
        crate::network::NodeRpcClient::new(
            node.endpoint(),
            coordinator_tls.clone(),
            Duration::from_secs(30),
        )
        .map_err(|e| e.to_string())?
        .stage_lifecycle(command.clone())
        .map_err(|e| e.to_string())?;
    }
    let certificate = crate::edge_client::collect_order_certificate(
        cluster,
        &coordinator_tls,
        Some(previous),
        OrderCommitment(command.digest()?),
        command.expires_at,
        Duration::from_secs(30),
    )
    .map_err(|e| e.to_string())?;
    let releases = cluster
        .nodes
        .iter()
        .map(|node| {
            crate::network::NodeRpcClient::new(
                node.endpoint(),
                settlement_tls.clone(),
                Duration::from_secs(30),
            )
            .and_then(|client| client.apply_lifecycle(manifest, certificate.clone()))
            .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keys = crate::edge_client::ThresholdCapabilityRelease::from_lifecycle(manifest, releases)
        .map_err(|e| e.to_string())?;
    Ok((certificate, keys))
}
