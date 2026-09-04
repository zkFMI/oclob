//! Corporate-edge fan-out that never gives all seven shares to a coordinator.

use crate::network::{ClientTlsConfig, ClusterPublicConfig, NetworkError, NodeRpcClient};
use oclob_core::{Digest32, OrderCommitment};
use oclob_edge::{EdgeOrderBundle, EdgeOrderManifest, MPC_PARTIES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EdgeAdmissionReceipt {
    pub version: u16,
    pub manifest: EdgeOrderManifest,
    pub node_generations: [u64; MPC_PARTIES],
    pub receipt_digest: Digest32,
}

impl EdgeAdmissionReceipt {
    pub const fn commitment(&self) -> OrderCommitment {
        self.manifest.commitment
    }

    pub fn verify(&self) -> Result<(), EdgeClientError> {
        if self.version != 1
            || self.node_generations.contains(&0)
            || self.receipt_digest != receipt_digest(&self.manifest, &self.node_generations)
        {
            return Err(EdgeClientError::Receipt);
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
        let deliveries = bundle.into_deliveries();
        let handles = deliveries
            .into_iter()
            .zip(self.cluster.nodes.iter().cloned())
            .map(|((party, sealed), node)| {
                let manifest = manifest.clone();
                let tls = self.tls.clone();
                let timeout = self.timeout;
                thread::spawn(move || -> Result<(usize, u64), NetworkError> {
                    if party != node.party {
                        return Err(NetworkError::Configuration);
                    }
                    let client = NodeRpcClient::new(node.endpoint(), tls, timeout)?;
                    let generation = client.ingest(manifest, sealed)?;
                    Ok((usize::from(party), generation))
                })
            })
            .collect::<Vec<_>>();
        let mut generations = [0_u64; MPC_PARTIES];
        for handle in handles {
            let (party, generation) = handle
                .join()
                .map_err(|_| EdgeClientError::Worker)?
                .map_err(EdgeClientError::Network)?;
            generations[party] = generation;
        }
        let receipt = EdgeAdmissionReceipt {
            version: 1,
            receipt_digest: receipt_digest(&manifest, &generations),
            manifest,
            node_generations: generations,
        };
        receipt.verify()?;
        Ok(receipt)
    }
}

fn receipt_digest(manifest: &EdgeOrderManifest, generations: &[u64; MPC_PARTIES]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"OCLOB:EDGE-ADMISSION-RECEIPT:v1");
    hash.update(manifest.commitment.0);
    hash.update(manifest.signer);
    for (party, generation) in generations.iter().enumerate() {
        hash.update((party as u16).to_be_bytes());
        hash.update(generation.to_be_bytes());
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
    #[error(transparent)]
    Network(#[from] NetworkError),
}
