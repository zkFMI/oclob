//! Corporate-edge fan-out that never gives all seven shares to a coordinator.

use crate::executor::{NodeExecutionReceipt, RoundPlan};
use crate::network::{
    ClientTlsConfig, ClusterPublicConfig, NetworkError, NodeAdmissionReceipt,
    NodeCapabilityRelease, NodePrivateStateReceipt, NodeRpcClient,
};
use crate::PrivateStateFinality;
use ed25519_dalek::VerifyingKey;
use oclob_core::{Digest32, MpcBatchResult, OrderCommitment};
use oclob_edge::{
    reconstruct_settlement_capability_key, EdgeOrderBundle, EdgeOrderManifest,
    SealedCapabilityKeyShare, SealedPartyShare, SealedSettlementCapability,
    SettlementCapabilityKey, VerifiedSettlementCapability, MPC_PARTIES, SETTLEMENT_KEY_THRESHOLD,
};
use oclob_ordering::{CommitteePolicy, OrderCertificate, OrderVote};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EdgeAdmissionReceipt {
    pub version: u16,
    pub manifest: EdgeOrderManifest,
    pub node_generations: [u64; MPC_PARTIES],
    pub order_share_digests: [Digest32; MPC_PARTIES],
    pub capability_key_share_digests: [Digest32; MPC_PARTIES],
    pub node_receipts: Vec<NodeAdmissionReceipt>,
    pub receipt_digest: Digest32,
}

impl EdgeAdmissionReceipt {
    pub const fn commitment(&self) -> OrderCommitment {
        self.manifest.commitment
    }

    pub fn verify(&self, cluster: &ClusterPublicConfig, now: u64) -> Result<(), EdgeClientError> {
        cluster.validate()?;
        if self.version != 2
            || self.manifest.market_id != cluster.market_id
            || self.node_generations.contains(&0)
            || self.order_share_digests.contains(&[0; 32])
            || self.capability_key_share_digests.contains(&[0; 32])
            || self.node_receipts.len() != MPC_PARTIES
            || self.receipt_digest
                != receipt_digest(
                    &self.manifest,
                    &self.node_generations,
                    &self.order_share_digests,
                    &self.capability_key_share_digests,
                    &self.node_receipts,
                )
        {
            return Err(EdgeClientError::Receipt);
        }
        self.manifest
            .verify(now)
            .map_err(|_| EdgeClientError::Receipt)?;
        for (party, (node, receipt)) in cluster.nodes.iter().zip(&self.node_receipts).enumerate() {
            let signer = VerifyingKey::from_bytes(&node.receipt_verifying_key)
                .map_err(|_| EdgeClientError::Receipt)?;
            receipt
                .verify(
                    &self.manifest,
                    party as u16,
                    self.order_share_digests[party],
                    self.capability_key_share_digests[party],
                    &signer,
                )
                .map_err(|_| EdgeClientError::Receipt)?;
            if receipt.generation != self.node_generations[party] {
                return Err(EdgeClientError::Receipt);
            }
        }
        Ok(())
    }
}

pub struct EdgeDistributor {
    cluster: ClusterPublicConfig,
    tls: ClientTlsConfig,
    timeout: Duration,
}

/// Participant-only durable delivery payload. All seven values here are
/// recipient-encrypted; the raw bundle and its one-order decryption key are
/// deliberately not serializable. Never send this aggregate to a coordinator.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEdgeDelivery {
    pub manifest: EdgeOrderManifest,
    pub deliveries: [(u16, SealedPartyShare, SealedCapabilityKeyShare); MPC_PARTIES],
}

impl PreparedEdgeDelivery {
    pub fn from_bundle(bundle: EdgeOrderBundle) -> Self {
        Self {
            manifest: bundle.manifest().clone(),
            deliveries: bundle.into_deliveries(),
        }
    }

    pub fn validate(&self, cluster: &ClusterPublicConfig, now: u64) -> Result<(), EdgeClientError> {
        cluster.validate()?;
        self.manifest
            .verify(now)
            .map_err(|_| EdgeClientError::Receipt)?;
        if self.manifest.market_id != cluster.market_id {
            return Err(EdgeClientError::Configuration);
        }
        for (node, (party, share, key)) in cluster.nodes.iter().zip(&self.deliveries) {
            if *party != node.party
                || share.party != *party
                || key.party != *party
                || share.commitment != self.manifest.commitment
                || key.order_commitment != self.manifest.commitment
                || key.capability_commitment != self.manifest.settlement_capability_commitment
                || share.recipient != node.share_encryption_key.0
                || key.recipient != node.share_encryption_key.0
            {
                return Err(EdgeClientError::Receipt);
            }
        }
        Ok(())
    }
}

impl EdgeDistributor {
    pub fn new(
        cluster: ClusterPublicConfig,
        tls: ClientTlsConfig,
        timeout: Duration,
    ) -> Result<Self, EdgeClientError> {
        cluster.validate()?;
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(EdgeClientError::Configuration);
        }
        Ok(Self {
            cluster,
            tls,
            timeout,
        })
    }

    /// Deliver all shares concurrently, one encrypted envelope per node. A
    /// partial fan-out is not admitted: the caller receives a public receipt
    /// only after all seven independently authenticated nodes acknowledge.
    pub fn submit(&self, bundle: EdgeOrderBundle) -> Result<EdgeAdmissionReceipt, EdgeClientError> {
        self.submit_prepared(&PreparedEdgeDelivery::from_bundle(bundle))
    }

    /// Retry the exact ciphertexts after a partial delivery or lost response.
    /// Generating a fresh bundle here would change the node admission identity.
    pub fn submit_prepared(
        &self,
        prepared: &PreparedEdgeDelivery,
    ) -> Result<EdgeAdmissionReceipt, EdgeClientError> {
        prepared.validate(
            &self.cluster,
            unix_seconds().ok_or(EdgeClientError::Configuration)?,
        )?;
        let manifest = prepared.manifest.clone();
        let cluster = self.cluster.clone();
        let deliveries = prepared.deliveries.clone();
        let handles = deliveries
            .into_iter()
            .zip(self.cluster.nodes.iter().cloned())
            .map(|((party, sealed, sealed_capability_key_share), node)| {
                let manifest = manifest.clone();
                let tls = self.tls.clone();
                let timeout = self.timeout;
                thread::spawn(
                    move || -> Result<
                        (usize, NodeAdmissionReceipt, Digest32, Digest32),
                        NetworkError,
                    > {
                        if party != node.party {
                            return Err(NetworkError::Configuration);
                        }
                        let order_share_digest = sealed.wire_digest();
                        let capability_key_share_digest = sealed_capability_key_share.wire_digest();
                        let client = NodeRpcClient::new(node.endpoint(), tls, timeout)?;
                        let receipt =
                            client.ingest(manifest, sealed, sealed_capability_key_share)?;
                        Ok((
                            usize::from(party),
                            receipt,
                            order_share_digest,
                            capability_key_share_digest,
                        ))
                    },
                )
            })
            .collect::<Vec<_>>();
        let mut generations = [0_u64; MPC_PARTIES];
        let mut order_share_digests = [[0_u8; 32]; MPC_PARTIES];
        let mut capability_key_share_digests = [[0_u8; 32]; MPC_PARTIES];
        let mut node_receipts = Vec::with_capacity(MPC_PARTIES);
        for handle in handles {
            let (party, node_receipt, order_share_digest, capability_key_share_digest) = handle
                .join()
                .map_err(|_| EdgeClientError::Worker)?
                .map_err(EdgeClientError::Network)?;
            generations[party] = node_receipt.generation;
            order_share_digests[party] = order_share_digest;
            capability_key_share_digests[party] = capability_key_share_digest;
            node_receipts.push(node_receipt);
        }
        node_receipts.sort_by_key(|receipt| receipt.party);
        let receipt = EdgeAdmissionReceipt {
            version: 2,
            receipt_digest: receipt_digest(
                &manifest,
                &generations,
                &order_share_digests,
                &capability_key_share_digests,
                &node_receipts,
            ),
            manifest,
            node_generations: generations,
            order_share_digests,
            capability_key_share_digests,
            node_receipts,
        };
        let now = unix_seconds().ok_or(EdgeClientError::Configuration)?;
        receipt.verify(&cluster, now)?;
        Ok(receipt)
    }
}

/// Output accepted only after all seven independently authenticated node
/// receipts agree on the program bytes and public MPC result.
pub struct AgreedRoundExecution {
    pub receipts: Vec<NodeExecutionReceipt>,
    pub result: MpcBatchResult,
}

/// Advance all seven party-local private book heads after the same canonical
/// DeFMI receipt. Only public digests cross the RPC boundary.
pub fn finalize_agreed_private_state(
    cluster: &ClusterPublicConfig,
    settlement_tls: &ClientTlsConfig,
    plan: &RoundPlan,
    execution: &AgreedRoundExecution,
    finality: PrivateStateFinality,
    timeout: Duration,
) -> Result<Vec<NodePrivateStateReceipt>, EdgeClientError> {
    if timeout.is_zero()
        || timeout > Duration::from_secs(120)
        || execution.receipts.len() != cluster.nodes.len()
        || execution
            .receipts
            .first()
            .is_none_or(|receipt| receipt.public_output_sha256 != finality.public_output_sha256)
    {
        return Err(EdgeClientError::Configuration);
    }
    let handles = cluster
        .nodes
        .iter()
        .cloned()
        .zip(execution.receipts.iter().cloned())
        .map(|(node, execution_receipt)| {
            let tls = settlement_tls.clone();
            let plan = plan.clone();
            let finality = finality.clone();
            thread::spawn(move || {
                NodeRpcClient::new(node.endpoint(), tls, timeout)?.finalize_private_state(
                    plan,
                    finality,
                    &execution_receipt,
                )
            })
        })
        .collect::<Vec<_>>();
    handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| EdgeClientError::Worker)?
                .map_err(EdgeClientError::Network)
        })
        .collect()
}

/// Settlement-side holder for a reconstructed one-order key. It cannot be
/// serialized or printed. The clear order becomes available only through
/// `open` after three node releases have been verified.
pub struct ThresholdCapabilityRelease {
    releases: Vec<NodeCapabilityRelease>,
    key: SettlementCapabilityKey,
}

impl ThresholdCapabilityRelease {
    /// All responses must already be verified against the same locally
    /// accepted lifecycle certificate. No caller-supplied threshold override.
    pub(crate) fn from_lifecycle(
        manifest: &EdgeOrderManifest,
        releases: Vec<NodeCapabilityRelease>,
    ) -> Result<Self, EdgeClientError> {
        let shares = releases
            .iter()
            .map(|r| r.capability_key_share.clone())
            .collect::<Vec<_>>();
        let key =
            reconstruct_settlement_capability_key(manifest, &shares, manifest.retention_deadline)
                .map_err(|_| EdgeClientError::SettlementThreshold)?;
        Ok(Self { releases, key })
    }
    /// Open only the confidential canonical-note authority after the same
    /// threshold release checks used for settlement. This path contains no
    /// plaintext order, price, quantity, or original order blinding.
    pub fn open_reservation(
        &self,
        envelope: &oclob_edge::SealedReservationAuthority,
        manifest: &EdgeOrderManifest,
        expected_venue: Digest32,
        expected_defmi: Digest32,
        trusted_signer: &VerifyingKey,
        now: u64,
    ) -> Result<oclob_edge::VerifiedReservationAuthority, EdgeClientError> {
        envelope
            .open(
                &self.key,
                manifest,
                expected_venue,
                expected_defmi,
                trusted_signer,
                now,
            )
            .map_err(|_| EdgeClientError::SettlementThreshold)
    }

    pub fn release_count(&self) -> usize {
        self.releases.len()
    }

    pub fn releasing_parties(&self) -> Vec<u16> {
        self.releases.iter().map(|release| release.party).collect()
    }

    pub fn open(
        &self,
        envelope: &SealedSettlementCapability,
        manifest: &EdgeOrderManifest,
        now: u64,
    ) -> Result<VerifiedSettlementCapability, EdgeClientError> {
        envelope
            .open(&self.key, manifest, now)
            .map_err(|_| EdgeClientError::SettlementThreshold)
    }
}

/// Ask the seven independently authenticated node services to order one
/// already-admitted commitment. The returned certificate carries every vote
/// received and is accepted only when at least five pinned signatures agree.
pub fn collect_order_certificate(
    cluster: &ClusterPublicConfig,
    tls: &ClientTlsConfig,
    previous: Option<&OrderCertificate>,
    commitment: OrderCommitment,
    expires_at: u64,
    timeout: Duration,
) -> Result<OrderCertificate, EdgeClientError> {
    if timeout.is_zero() || timeout > Duration::from_secs(120) {
        return Err(EdgeClientError::Configuration);
    }
    cluster.validate()?;
    let now = unix_seconds().ok_or(EdgeClientError::Configuration)?;
    if now > expires_at {
        return Err(EdgeClientError::Configuration);
    }
    let (sequence, previous_certificate) = match previous {
        Some(certificate)
            if certificate.market_id == cluster.market_id
                && certificate.commitment != commitment =>
        {
            (
                certificate
                    .sequence
                    .checked_add(1)
                    .ok_or(EdgeClientError::Configuration)?,
                certificate.digest(),
            )
        }
        Some(_) => return Err(EdgeClientError::Configuration),
        None => (1, [0; 32]),
    };
    let handles = cluster
        .nodes
        .iter()
        .cloned()
        .map(|node| {
            let tls = tls.clone();
            let market_id = cluster.market_id.clone();
            thread::spawn(move || {
                NodeRpcClient::new(node.endpoint(), tls, timeout)?.vote(
                    &market_id,
                    sequence,
                    commitment,
                    previous_certificate,
                    expires_at,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut votes = Vec::<OrderVote>::with_capacity(MPC_PARTIES);
    for handle in handles {
        if let Ok(Ok(vote)) = handle.join() {
            votes.push(vote);
        }
    }
    votes.sort_by_key(|vote| vote.node_id);
    let certificate = OrderCertificate {
        market_id: cluster.market_id.clone(),
        sequence,
        commitment,
        previous_certificate,
        expires_at,
        votes,
    };
    let policy = CommitteePolicy::seven_node();
    certificate
        .verify(policy, &cluster.ordering_verifying_keys()?, now)
        .map_err(|_| EdgeClientError::OrderingQuorum)?;
    Ok(certificate)
}

pub fn execute_agreed_round(
    cluster: &ClusterPublicConfig,
    tls: &ClientTlsConfig,
    plan: &RoundPlan,
    timeout: Duration,
) -> Result<AgreedRoundExecution, EdgeClientError> {
    if timeout.is_zero() || timeout > Duration::from_secs(600) {
        return Err(EdgeClientError::Configuration);
    }
    cluster.validate()?;
    let now = unix_seconds().ok_or(EdgeClientError::Configuration)?;
    plan.verify_ordering(
        CommitteePolicy::seven_node(),
        &cluster.ordering_verifying_keys()?,
        now,
    )
    .map_err(|_| EdgeClientError::Configuration)?;
    if plan.market_id != cluster.market_id {
        return Err(EdgeClientError::Configuration);
    }
    let handles = cluster
        .nodes
        .iter()
        .cloned()
        .map(|node| {
            let tls = tls.clone();
            let plan = plan.clone();
            thread::spawn(move || -> Result<NodeExecutionReceipt, NetworkError> {
                let deadline = Instant::now() + timeout;
                loop {
                    let client = NodeRpcClient::new(node.endpoint(), tls.clone(), timeout)?;
                    match client.execute(plan.clone()) {
                        Ok(receipt) => return Ok(receipt),
                        Err(_)
                            if Instant::now() < deadline
                                && unix_seconds().is_some_and(|now| now < plan.expires_at) =>
                        {
                            thread::sleep(Duration::from_millis(250));
                        }
                        Err(error) => return Err(error),
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    let receipts = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| EdgeClientError::Worker)?
                .map_err(EdgeClientError::Network)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if receipts.len() != cluster.nodes.len() {
        return Err(EdgeClientError::Receipt);
    }
    for (party, (node, receipt)) in cluster.nodes.iter().zip(&receipts).enumerate() {
        let key = VerifyingKey::from_bytes(&node.receipt_verifying_key)
            .map_err(|_| EdgeClientError::Receipt)?;
        receipt
            .verify(plan, party as u16, &key)
            .map_err(|_| EdgeClientError::Receipt)?;
    }
    let first = receipts.first().ok_or(EdgeClientError::Receipt)?;
    if receipts.iter().any(|receipt| {
        receipt.result != first.result
            || receipt.public_output_sha256 != first.public_output_sha256
            || receipt.program_sha256 != first.program_sha256
            || receipt.artifact_sha256 != first.artifact_sha256
    }) {
        return Err(EdgeClientError::Receipt);
    }
    Ok(AgreedRoundExecution {
        result: first.result.clone(),
        receipts,
    })
}

/// Collect node-local capability-key shares only after a completed, agreed MPC
/// round authorizes this order. Up to two unavailable or corrupt nodes reveal
/// nothing and cannot fabricate the third participant-signed share.
#[allow(clippy::too_many_arguments)]
pub fn collect_threshold_capability_release(
    cluster: &ClusterPublicConfig,
    settlement_tls: &ClientTlsConfig,
    plan: &RoundPlan,
    execution: &AgreedRoundExecution,
    manifest: &EdgeOrderManifest,
    order_commitment: OrderCommitment,
    timeout: Duration,
) -> Result<ThresholdCapabilityRelease, EdgeClientError> {
    if timeout.is_zero() || timeout > Duration::from_secs(120) {
        return Err(EdgeClientError::Configuration);
    }
    cluster.validate()?;
    let now = unix_seconds().ok_or(EdgeClientError::Configuration)?;
    manifest
        .verify(now)
        .map_err(|_| EdgeClientError::SettlementThreshold)?;
    plan.verify_ordering(
        CommitteePolicy::seven_node(),
        &cluster.ordering_verifying_keys()?,
        now,
    )
    .map_err(|_| EdgeClientError::SettlementThreshold)?;
    if manifest.commitment != order_commitment
        || plan.market_id != manifest.market_id
        || execution.receipts.len() != cluster.nodes.len()
        || !capability_release_permitted(plan, &execution.result, order_commitment)
    {
        return Err(EdgeClientError::SettlementThreshold);
    }
    let first = execution
        .receipts
        .first()
        .ok_or(EdgeClientError::SettlementThreshold)?;
    for (party, (node, receipt)) in cluster.nodes.iter().zip(&execution.receipts).enumerate() {
        let signer = VerifyingKey::from_bytes(&node.receipt_verifying_key)
            .map_err(|_| EdgeClientError::SettlementThreshold)?;
        receipt
            .verify(plan, party as u16, &signer)
            .map_err(|_| EdgeClientError::SettlementThreshold)?;
        if receipt.result != execution.result
            || receipt.public_output_sha256 != first.public_output_sha256
            || receipt.program_sha256 != first.program_sha256
            || receipt.artifact_sha256 != first.artifact_sha256
        {
            return Err(EdgeClientError::SettlementThreshold);
        }
    }
    let expected_output = first.public_output_sha256;
    let handles = cluster
        .nodes
        .iter()
        .cloned()
        .map(|node| {
            let tls = settlement_tls.clone();
            let plan = plan.clone();
            let manifest = manifest.clone();
            thread::spawn(move || {
                NodeRpcClient::new(node.endpoint(), tls, timeout)?.release_capability_key_share(
                    &manifest,
                    plan,
                    order_commitment,
                    expected_output,
                    now,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut releases = Vec::with_capacity(MPC_PARTIES);
    for handle in handles {
        if let Ok(Ok(release)) = handle.join() {
            releases.push(release);
        }
    }
    releases.sort_by_key(|release| release.party);
    releases.dedup_by_key(|release| release.party);
    if releases.len() < cluster.settlement_release_threshold
        || releases.len() < SETTLEMENT_KEY_THRESHOLD
    {
        return Err(EdgeClientError::SettlementThreshold);
    }
    let shares = releases
        .iter()
        .map(|release| release.capability_key_share.clone())
        .collect::<Vec<_>>();
    let key = reconstruct_settlement_capability_key(manifest, &shares, now)
        .map_err(|_| EdgeClientError::SettlementThreshold)?;
    Ok(ThresholdCapabilityRelease { releases, key })
}

fn capability_release_permitted(
    plan: &RoundPlan,
    result: &MpcBatchResult,
    order_commitment: OrderCommitment,
) -> bool {
    if order_commitment == plan.arriving {
        result.arriving_remaining > 0 || result.slots.iter().any(|slot| slot.matched)
    } else {
        plan.resting
            .iter()
            .position(|commitment| *commitment == order_commitment)
            .and_then(|position| result.slots.get(position))
            .is_some_and(|slot| slot.matched)
    }
}

fn unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn receipt_digest(
    manifest: &EdgeOrderManifest,
    generations: &[u64; MPC_PARTIES],
    order_share_digests: &[Digest32; MPC_PARTIES],
    capability_key_share_digests: &[Digest32; MPC_PARTIES],
    node_receipts: &[NodeAdmissionReceipt],
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:EDGE-ADMISSION-RECEIPT:v2");
    hash.update(manifest.commitment.0);
    hash.update(manifest.signer);
    for (party, generation) in generations.iter().enumerate() {
        hash.update((party as u16).to_be_bytes());
        hash.update(generation.to_be_bytes());
        hash.update(order_share_digests[party]);
        hash.update(capability_key_share_digests[party]);
    }
    hash.update((node_receipts.len() as u64).to_be_bytes());
    for receipt in node_receipts {
        hash.update(receipt.party.to_be_bytes());
        hash.update(receipt.order_commitment.0);
        hash.update(receipt.manifest_signer);
        hash.update(receipt.order_share_digest);
        hash.update(receipt.capability_key_share_digest);
        hash.update(receipt.generation.to_be_bytes());
        hash.update(receipt.state_digest);
        hash.update(receipt.signer);
        hash.update((receipt.signature.len() as u64).to_be_bytes());
        hash.update(&receipt.signature);
    }
    hash.finalize().into()
}

#[derive(Debug, Error)]
pub enum EdgeClientError {
    #[error("edge distributor configuration is invalid")]
    Configuration,
    #[error("one node delivery worker failed")]
    Worker,
    #[error("edge admission receipt is invalid")]
    Receipt,
    #[error("five valid ordering votes were not obtained")]
    OrderingQuorum,
    #[error("three valid post-match capability releases were not obtained")]
    SettlementThreshold,
    #[error(transparent)]
    Network(#[from] NetworkError),
}
