//! Corporate-edge fan-out that never gives all seven shares to a coordinator.

use crate::executor::{NodeExecutionReceipt, RoundPlan};
use crate::network::{
    ClientTlsConfig, ClusterPublicConfig, NetworkError, NodeAdmissionReceipt, NodeRpcClient,
};
use ed25519_dalek::VerifyingKey;
use oclob_core::{Digest32, MpcBatchResult, OrderCommitment};
use oclob_edge::{EdgeOrderBundle, EdgeOrderManifest, MPC_PARTIES};
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
    pub node_receipts: Vec<NodeAdmissionReceipt>,
    pub receipt_digest: Digest32,
}

impl EdgeAdmissionReceipt {
    pub const fn commitment(&self) -> OrderCommitment {
        self.manifest.commitment
    }

    pub fn verify(&self, cluster: &ClusterPublicConfig, now: u64) -> Result<(), EdgeClientError> {
        cluster.validate()?;
        if self.version != 1
            || self.manifest.market_id != cluster.market_id
            || self.node_generations.contains(&0)
            || self.node_receipts.len() != MPC_PARTIES
            || self.receipt_digest
                != receipt_digest(&self.manifest, &self.node_generations, &self.node_receipts)
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
                .verify(&self.manifest, party as u16, &signer)
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
        let manifest = bundle.manifest().clone();
        let cluster = self.cluster.clone();
        let deliveries = bundle.into_deliveries();
        let handles = deliveries
            .into_iter()
            .zip(self.cluster.nodes.iter().cloned())
            .map(|((party, sealed), node)| {
                let manifest = manifest.clone();
                let tls = self.tls.clone();
                let timeout = self.timeout;
                thread::spawn(
                    move || -> Result<(usize, NodeAdmissionReceipt), NetworkError> {
                        if party != node.party {
                            return Err(NetworkError::Configuration);
                        }
                        let client = NodeRpcClient::new(node.endpoint(), tls, timeout)?;
                        let receipt = client.ingest(manifest, sealed)?;
                        Ok((usize::from(party), receipt))
                    },
                )
            })
            .collect::<Vec<_>>();
        let mut generations = [0_u64; MPC_PARTIES];
        let mut node_receipts = Vec::with_capacity(MPC_PARTIES);
        for handle in handles {
            let (party, node_receipt) = handle
                .join()
                .map_err(|_| EdgeClientError::Worker)?
                .map_err(EdgeClientError::Network)?;
            generations[party] = node_receipt.generation;
            node_receipts.push(node_receipt);
        }
        node_receipts.sort_by_key(|receipt| receipt.party);
        let receipt = EdgeAdmissionReceipt {
            version: 1,
            receipt_digest: receipt_digest(&manifest, &generations, &node_receipts),
            manifest,
            node_generations: generations,
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

fn unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn receipt_digest(
    manifest: &EdgeOrderManifest,
    generations: &[u64; MPC_PARTIES],
    node_receipts: &[NodeAdmissionReceipt],
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:EDGE-ADMISSION-RECEIPT:v1");
    hash.update(manifest.commitment.0);
    hash.update(manifest.signer);
    for (party, generation) in generations.iter().enumerate() {
        hash.update((party as u16).to_be_bytes());
        hash.update(generation.to_be_bytes());
    }
    hash.update((node_receipts.len() as u64).to_be_bytes());
    for receipt in node_receipts {
        hash.update(receipt.party.to_be_bytes());
        hash.update(receipt.order_commitment.0);
        hash.update(receipt.manifest_signer);
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
    #[error(transparent)]
    Network(#[from] NetworkError),
}
