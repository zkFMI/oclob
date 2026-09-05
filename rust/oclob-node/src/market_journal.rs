//! Resident market progress uses the pinned crash-atomic encrypted outbox.
//! No participant signing key, credential or plaintext order belongs here.

use crate::market_network::MarketIngress;
use crate::network::ClusterPublicConfig;
use oclob_core::OrderCommitment;
use oclob_ordering::OrderCertificate;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::{Path, PathBuf};
use zkpi_defmi_sdk::corporate::CorporateOutbox;

#[derive(Clone, Deserialize, Serialize)]
pub struct MarketBookEntry {
    pub commitment: OrderCommitment,
    /// Intentionally disclosed only by the certified MPC result.
    pub remaining: u64,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MarketCompletedRound {
    pub certificate: OrderCertificate,
    pub result: oclob_core::MpcBatchResult,
    pub book: Vec<MarketBookEntry>,
    pub transaction_id: Option<String>,
    pub canonical_root: Option<[u8; 32]>,
    pub finality_observations: usize,
}

#[derive(Deserialize, Serialize)]
struct Bound<T> {
    context: [u8; 32],
    body: T,
}

pub struct MarketJournal {
    path: PathBuf,
    context: [u8; 32],
    outbox: CorporateOutbox,
}

impl MarketJournal {
    pub fn open(
        path: &Path,
        secret: &[u8; 32],
        cluster: &ClusterPublicConfig,
        initialize: bool,
    ) -> Result<Self, String> {
        if *secret == [0; 32] {
            return Err("empty market journal key".into());
        }
        cluster.validate().map_err(err)?;
        let context = Sha256::new()
            .chain_update(b"OCLOB:MARKET-JOURNAL:v1")
            .chain_update(serde_json::to_vec(cluster).map_err(err)?)
            .finalize()
            .into();
        let outbox = CorporateOutbox::new(path, secret, 8192, 8 * 1024 * 1024)?;
        if initialize {
            outbox.initialize()?;
        } else {
            outbox.summaries()?;
        }
        let result = Self {
            path: path.to_owned(),
            context,
            outbox,
        };
        let stored: [u8; 32] = result.put("context", &context, 1, u64::MAX)?;
        if stored != context {
            return Err("market journal belongs to another deployment".into());
        }
        Ok(result)
    }
    pub fn acquire_worker(&self) -> Result<File, String> {
        crate::corporate_dispatch::acquire_corporate_lock(
            &self.path.with_extension("worker.lock"),
            false,
        )
    }
    pub fn put<T: Serialize + DeserializeOwned>(
        &self,
        id: &str,
        value: &T,
        at: u64,
        expires: u64,
    ) -> Result<T, String> {
        let body = serde_json::to_vec(&Bound {
            context: self.context,
            body: value,
        })
        .map_err(err)?;
        let outcome = self.outbox.enqueue_first_seen(id, &body, at, expires);
        if let Some(saved) = self.get(id)? {
            return Ok(saved);
        }
        outcome?;
        Err("market journal insertion was not durable".into())
    }
    pub fn get<T: DeserializeOwned>(&self, id: &str) -> Result<Option<T>, String> {
        let Some(entry) = self
            .outbox
            .summaries()?
            .into_iter()
            .find(|e| e.request_id == id)
        else {
            return Ok(None);
        };
        let wire = self.outbox.signed_request(id, entry.request_digest)?;
        let value: Bound<T> = serde_json::from_slice(&wire).map_err(err)?;
        if value.context != self.context {
            return Err("market record belongs to another deployment".into());
        }
        Ok(Some(value.body))
    }
    pub fn accept(
        &self,
        input: &MarketIngress,
        cluster: &ClusterPublicConfig,
        now: u64,
    ) -> Result<u64, String> {
        let id = format!("input:{}", input.receipt.commitment().hex());
        if let Some(entry) = self
            .outbox
            .summaries()?
            .into_iter()
            .find(|e| e.request_id == id)
        {
            let saved: MarketIngress = self.get(&id)?.ok_or("market input disappeared")?;
            if saved.digest()? != input.digest()? {
                return Err("market commitment already has another envelope".into());
            }
            return Ok(entry.sequence);
        }
        input.verify(cluster, now)?;
        let saved: MarketIngress = self.put(&id, input, now, u64::MAX)?;
        if saved.digest()? != input.digest()? {
            return Err("market commitment already has another envelope".into());
        }
        self.outbox
            .summaries()?
            .into_iter()
            .find(|e| e.request_id == id)
            .map(|e| e.sequence)
            .ok_or("market input disappeared".into())
    }
    pub fn ingress(&self, commitment: OrderCommitment) -> Result<MarketIngress, String> {
        self.get(&format!("input:{}", commitment.hex()))?
            .ok_or("market order has no durable intake".into())
    }
    pub fn next(&self) -> Result<Option<MarketIngress>, String> {
        let mut entries = self.outbox.summaries()?;
        entries.sort_by_key(|e| e.sequence);
        for entry in entries {
            if let Some(id) = entry.request_id.strip_prefix("input:") {
                if self
                    .get::<MarketCompletedRound>(&format!("done:{id}"))?
                    .is_none()
                {
                    return self.get(&entry.request_id);
                }
            }
        }
        Ok(None)
    }
    pub fn completed(&self) -> Result<Vec<MarketCompletedRound>, String> {
        let mut entries = self.outbox.summaries()?;
        entries.sort_by_key(|e| e.sequence);
        entries
            .into_iter()
            .filter(|e| e.request_id.starts_with("done:"))
            .map(|e| {
                self.get(&e.request_id)?
                    .ok_or("market completion disappeared".into())
            })
            .collect()
    }
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
