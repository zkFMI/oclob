//! Resume the exact corporate-owned reservation and seven-node delivery.
//! Credential issuance and new order construction are deliberately outside
//! this worker path: it can only send an already signed, durable instruction.

use crate::corporate::{
    build_reserved_delivery, finalize_reservation, verify_finalized, CorporateNativeConfig,
    PreparedCorporateReserve,
};
use crate::corporate_journal::{NativeCorporateJournal, StoredCorporateDelivery};
use crate::edge_client::{EdgeAdmissionReceipt, EdgeDistributor, PreparedEdgeDelivery};
use crate::network::{client_tls_context, ClientIdentityConfig, ClusterPublicConfig};
use oclob_edge::{NodeEncryptionKey, SealedReservationAuthority, MPC_PARTIES};
use oclob_settlement::pretrade::FinalizedReservation;
use qomm_zkpi::handles::Identity;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SubmissionCheckpoint {
    ReserveObservedBeforeJournal,
    NodesAcknowledgedBeforeJournal,
}

pub struct CompletedNativeSubmission {
    pub receipt: EdgeAdmissionReceipt,
    pub authority: SealedReservationAuthority,
    pub reused_completed_receipt: bool,
}

pub fn reserve_digest(prepared: &PreparedCorporateReserve) -> Result<[u8; 32], String> {
    Ok(Sha256::digest(serde_json::to_vec(&prepared.request).map_err(err)?).into())
}

/// An observer may stop the local process at a durable checkpoint. It receives
/// no secret material and cannot replace a financial request or acknowledgement.
/// Normal callers pass a no-op; laboratory crash tests terminate the process.
pub fn complete_native_submission(
    config: &CorporateNativeConfig,
    identity: &ClientIdentityConfig,
    cluster: &ClusterPublicConfig,
    journal: &NativeCorporateJournal,
    request_id: &str,
    source_note: Option<[u8; 32]>,
    mut observe: impl FnMut(SubmissionCheckpoint) -> Result<(), String>,
) -> Result<CompletedNativeSubmission, String> {
    journal.require_turn(request_id)?;
    let intent = journal
        .intent(request_id)?
        .ok_or("submission has no durable intent")?;
    let prepared: PreparedCorporateReserve = journal
        .stage(request_id, "reserve")?
        .ok_or("submission has no durable signed reserve")?;
    prepared.validate(config)?;
    if prepared.order_wire != intent.order_wire
        || prepared.signing_key != intent.signing_key
        || prepared.eligibility_commitment != intent.eligibility_commitment
    {
        return Err("saved reserve belongs to another durable corporate intent".into());
    }
    let digest = reserve_digest(&prepared)?;
    let completed: Option<EdgeAdmissionReceipt> = journal.stage(request_id, "receipt")?;
    let delivery: StoredCorporateDelivery = if let Some(saved) =
        journal.stage(request_id, "delivery")?
    {
        saved
    } else {
        let finalized: FinalizedReservation =
            if let Some(saved) = journal.stage(request_id, "admission")? {
                verify_finalized(config, identity, &prepared, &saved, now()?)?;
                saved
            } else {
                // The reserve endpoint reconciles the exact hold before verifying
                // a repeated request. Never create new proof/random bytes here.
                let finalized = finalize_reservation(config, identity, &prepared, now()?)?;
                observe(SubmissionCheckpoint::ReserveObservedBeforeJournal)?;
                journal.save_stage(request_id, "admission", &finalized, &intent)?
            };
        journal.save_reserved_witness(&prepared)?;
        let node_keys: [NodeEncryptionKey; MPC_PARTIES] = cluster
            .nodes
            .iter()
            .map(|node| node.share_encryption_key.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "cluster must have seven node keys")?;
        let handle = Identity::from_seed(config.identity_seed).handle(b"defmi:oclob:v1");
        let (bundle, authority) =
            build_reserved_delivery(config, &prepared, &finalized, &handle, &node_keys, now()?)?;
        journal.save_stage(
            request_id,
            "delivery",
            &StoredCorporateDelivery {
                reserve_digest: digest,
                delivery: PreparedEdgeDelivery::from_bundle(bundle),
                authority,
            },
            &intent,
        )?
    };
    if delivery.reserve_digest != digest {
        return Err("saved ciphertexts name another reserve request".into());
    }
    let reused_completed_receipt = completed.is_some();
    let receipt = if let Some(receipt) = completed {
        receipt
    } else {
        let tls = client_tls_context(
            &identity.tls_certificate,
            &identity.tls_private_key,
            &identity.tls_ca,
        )
        .map_err(err)?;
        let distributor =
            EdgeDistributor::new(cluster.clone(), tls, Duration::from_secs(30)).map_err(err)?;
        let receipt = distributor
            .submit_prepared(&delivery.delivery)
            .map_err(err)?;
        observe(SubmissionCheckpoint::NodesAcknowledgedBeforeJournal)?;
        journal.save_receipt(request_id, &receipt, &delivery, cluster, &intent)?
    };
    journal.verify_receipt(&receipt, &delivery, cluster, intent.accepted_at)?;
    if let Some(source) = source_note {
        crate::native_wallet::verify_selected_funding_spent(config, identity, &prepared, source)?;
    }
    Ok(CompletedNativeSubmission {
        receipt,
        authority: delivery.authority,
        reused_completed_receipt,
    })
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(err)
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
