//! Native account adapter for optimistic service submissions. Canonical RPC
//! supplies account sequences and roots, including dispute/escrow state; the
//! older account-only SQLite projection is not used for this mode.
use super::*;
use defmi::application_settlement::OptimisticAccountSettlement;
use defmi::avalanche::AvalancheRpcClient;
use defmi::facility::QuorumAuthorizer;
use serde_json::{json, Value};
use zkpi_defmi_sdk::optimistic::OptimisticClient;

pub struct OptimisticAvalancheGateway<'a> {
    clients: &'a [AvalancheRpcClient],
    authorizer: &'a QuorumAuthorizer,
    keys: &'a BTreeMap<String, defmi::governance::GovernanceSigner>,
}
impl<'a> OptimisticAvalancheGateway<'a> {
    pub fn new(
        clients: &'a [AvalancheRpcClient],
        authorizer: &'a QuorumAuthorizer,
        keys: &'a BTreeMap<String, defmi::governance::GovernanceSigner>,
    ) -> Result<Self, String> {
        if clients.len() < 3 || keys.len() < 3 {
            return Err(
                "optimistic account gateway requires three native peers and governance signers"
                    .into(),
            );
        }
        Ok(Self {
            clients,
            authorizer,
            keys,
        })
    }
    fn roots(&self) -> Result<[u8; 32], String> {
        let values = self
            .clients
            .iter()
            .map(AvalancheClient::state_root)
            .collect::<Result<Vec<_>, _>>()?;
        let root = values[0];
        if values.iter().any(|r| *r != root) {
            return Err("native peers disagree on the canonical root".into());
        }
        Ok(root)
    }
    fn wait_root(&self, root: [u8; 32]) -> Result<(), String> {
        let deadline = Instant::now() + ROOT_CONVERGENCE_TIMEOUT;
        loop {
            if self.roots() == Ok(root) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("native peers did not converge to the accepted root".into());
            }
            thread::sleep(ROOT_POLL_INTERVAL);
        }
    }
    fn approval(&self, statement: [u8; 32], root: [u8; 32]) -> Result<QuorumApproval, String> {
        let signers = self
            .keys
            .iter()
            .take(crate::PROOF_QUORUM.len())
            .map(|(n, k)| (n.clone(), k.clone()))
            .collect();
        self.authorizer.approve(statement, root, &signers)
    }
    fn account(&self, handle: [u8; 32]) -> Result<Value, String> {
        self.clients[0].call("defmivm.account", json!({"handle":hex::encode(handle)}))
    }

    /// Existing synthetic/service account bootstrap, authenticated by native
    /// governance. Repeated calls compare exact public account/asset values.
    pub fn bootstrap(&self, prepared: &PreparedCanonicalTransition) -> Result<(), String> {
        let rpc = &self.clients[0];
        for asset in asset_definitions(prepared.market_id()) {
            match rpc.call(
                "defmivm.asset",
                json!({"assetID":hex::encode(asset.asset_id)}),
            ) {
                Ok(existing) => {
                    if existing["code"] != asset.code
                        || existing["kind"] != asset.kind.as_str()
                        || existing["decimals"] != asset.decimals
                        || existing["termsDigest"] != hex::encode(asset.terms_digest)
                        || existing["active"] != true
                    {
                        return Err("canonical asset differs from the prepared market".into());
                    }
                }
                Err(error) if error.contains("asset was not found") => {
                    let root = self.roots()?;
                    let approval = self.approval(asset.statement()?, root)?;
                    let tx = rpc.issue_asset(&asset, &approval, root)?;
                    let accepted = rpc.wait_accepted(&tx, Duration::MAX, ROOT_POLL_INTERVAL)?;
                    if accepted.before_root != root || accepted.statement != asset.statement()? {
                        return Err("native asset receipt differs from the requested asset".into());
                    }
                    self.wait_root(accepted.after_root)?;
                }
                Err(error) => return Err(error),
            }
        }
        for value in prepared.account_openings() {
            match self.account(value.handle) {
                Ok(existing) => {
                    if existing["assetID"] != hex::encode(value.asset_id)
                        || existing["commitment"] != hex::encode(value.commitment)
                    {
                        return Err(
                            "canonical account differs from the prepared service state".into()
                        );
                    }
                }
                Err(error) if error.contains("account was not found") => {
                    let root = self.roots()?;
                    let opening = account_opening(*value, prepared.application_binding());
                    let approval = self.approval(opening.statement()?, root)?;
                    let tx = rpc.issue_account(&opening, &approval, root)?;
                    let accepted = rpc.wait_accepted(&tx, Duration::MAX, ROOT_POLL_INTERVAL)?;
                    if accepted.before_root != root || accepted.statement != opening.statement()? {
                        return Err(
                            "native account receipt differs from the requested opening".into()
                        );
                    }
                    self.wait_root(accepted.after_root)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn settle(
        &self,
        prepared: &PreparedCanonicalTransition,
        now: u64,
    ) -> Result<CanonicalSettlementAcceptance, String> {
        if now > prepared.deadline() {
            return Err("prepared optimistic settlement has expired".into());
        }
        let reference = prepared.optimistic_reference();
        let client = OptimisticClient {
            rpc: &self.clients[0],
        };
        if let Some(reference) = reference {
            client.finalized(reference.claim, &reference.context, reference.output_root)?;
        }
        let root = self.roots()?;
        let mut legs = vec![];
        for delta in prepared.account_deltas() {
            let account = self.account(delta.handle)?;
            if account["stateRoot"] != hex::encode(root)
                || account["assetID"] != hex::encode(delta.asset_id)
                || account["commitment"] != hex::encode(delta.before_commitment)
            {
                return Err(
                    "prepared optimistic settlement is stale against the canonical account".into(),
                );
            }
            legs.push(StateLeg {
                handle: delta.handle,
                asset_id: delta.asset_id,
                before_commitment: delta.before_commitment,
                after_commitment: delta.after_commitment,
                before_sequence: account["sequence"]
                    .as_u64()
                    .ok_or("canonical account sequence is absent")?,
            });
        }
        let order = SettlementOrder {
                operation_id: prepared.operation_id(),
                nullifier: prepared.nullifier(),
                deadline: prepared.deadline(),
                payment_instruction_digest: prepared.payment_instruction_digest(),
                proof_digest: prepared.proof_digest(),
                market_statement_digest: prepared.transition_digest(),
                legs,
        };
        let (statement, accepted) = if let Some(reference) = reference {
            let settlement = OptimisticAccountSettlement {order:order.clone(), reference:reference.clone()};
            let statement = settlement.statement()?;
            let approval = self.approval(statement, root)?;
            (statement, client.settle_accounts(&settlement, &approval)?)
        } else {
            let statement = order.statement()?;
            let approval = self.approval(statement, root)?;
            let tx = self.clients[0].issue_settlement(&order, &approval, root)?;
            (statement, self.clients[0].wait_accepted(&tx, Duration::MAX, ROOT_POLL_INTERVAL)?)
        };
        if accepted.statement != statement || accepted.before_root != root {
            return Err("native settlement accepted another statement or parent".into());
        }
        self.wait_root(accepted.after_root)?;
        for leg in &order.legs {
            let account = self.account(leg.handle)?;
            if account["stateRoot"] != hex::encode(accepted.after_root)
                || account["commitment"] != hex::encode(leg.after_commitment)
                || account["sequence"].as_u64() != leg.before_sequence.checked_add(1)
            {
                return Err(
                    "native account readback differs from the accepted optimistic settlement"
                        .into(),
                );
            }
        }
        let receipt_digest = Sha256::new()
            .chain_update(b"OCLOB:OPTIMISTIC:NATIVE-RECEIPT:v1")
            .chain_update(accepted.tx_id.as_bytes())
            .chain_update(accepted.block_id.as_bytes())
            .chain_update(accepted.statement)
            .chain_update(accepted.before_root)
            .chain_update(accepted.after_root)
            .finalize()
            .into();
        Ok(CanonicalSettlementAcceptance {
            transaction_id: accepted.tx_id,
            block_id: accepted.block_id,
            height: accepted.height,
            statement,
            before_state_root: accepted.before_root,
            after_state_root: accepted.after_root,
            receipt_digest,
            application_binding: prepared.application_binding(),
            binding_digest: prepared.binding_digest(),
        })
    }
}
