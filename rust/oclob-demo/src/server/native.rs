//! Browser demo adapter to the real native ledger. Public development keys
//! and synthetic assets are explicit; there is no local settlement fallback.
use super::*;
use curve25519_dalek::Scalar;
use defmi::{
    avalanche::{AvalancheClient, AvalancheRpcClient},
    facility::{AccountOpening, AssetDefinition, AssetKind, QuorumAuthorizer},
    governance::GovernanceSigner,
};
use oclob_core::Digest32;
use oclob_core::OrderAuthority;
use oclob_dekyx::AnonymousPresentation;
use oclob_service::ServiceError;
use oclob_settlement::avalanche::OptimisticAvalancheGateway;
use std::time::{Duration, Instant};
use zkfmi_zk::pedersen::Pedersen;
use zkpi_committee::application_crypto::SigningKey;
use zkpi_committee::{
    optimistic::*,
    proof_party::{ProofParty, ProofPartyConfig},
};
use zkpi_defmi_sdk::optimistic::OptimisticClient;

pub struct NativeSettlement {
    pub clients: Arc<Vec<AvalancheRpcClient>>,
    authorizer: QuorumAuthorizer,
    signers: BTreeMap<String, GovernanceSigner>,
    proposer: ProofParty,
    admission: SigningKey,
    policy: OptimisticPolicy,
    pub progress: Arc<Mutex<Value>>,
    pub private_progress: Arc<Mutex<BTreeMap<String, Value>>>,
    directory: PathBuf,
    pub mode: String,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn hash(s: &str) -> Digest32 {
    Sha256::digest(s.as_bytes()).into()
}

impl NativeSettlement {
    pub fn new(directory: &Path, passphrase: &[u8]) -> Result<Self, String> {
        if std::env::var("OCLOB_PUBLIC_DEVELOPMENT_NATIVE").as_deref() != Ok("1") {
            return Err("OCLOB_PUBLIC_DEVELOPMENT_NATIVE=1 and five native validators are required; the local demo settlement route has been removed".into());
        }
        // The HTTP coordinator's private book is process-local. Never restart
        // against a funded chain with a freshly initialized private projection.
        let marker = directory.join("native-browser-session");
        let mut session = fs::OpenOptions::new().write(true).create_new(true).open(&marker)
            .map_err(|_| "native browser state cannot be reused: preserve this directory for reconciliation and launch a new isolated development network".to_string())?;
        session.write_all(b"private coordinator recovery is not implemented; do not reset against this chain\n").map_err(err)?;
        session.sync_all().map_err(err)?;
        fs::File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(err)?;
        let committee = oclob_ordering::OrderingCommittee::deterministic_for_demo().map_err(err)?;
        fs::write(directory.join("verifier.json"), serde_json::to_vec_pretty(&json!({"keys":committee.verifying_keys().iter().map(|(i,k)|(i.to_string(),hex::encode(k.as_bytes()))).collect::<BTreeMap<_,_>>(),"policy":committee.policy()})).map_err(err)?).map_err(err)?;
        let signers = defmi::governance::public_development_keys().map_err(err)?;
        let genesis = defmi_avalanche_vm::genesis::Genesis {
            timestamp: unix_now()?.saturating_sub(1) as i64,
            epoch: 1,
            threshold: 3,
            members: signers
                .iter()
                .map(|(n, k)| defmi_avalanche_vm::genesis::CommitteeMember {
                    node_id: n.clone(),
                    key: k.verifying_key(),
                })
                .collect(),
            deployment_crypto_policy: None,
        };
        if !directory.join("genesis.bin").exists() {
            fs::write(directory.join("genesis.bin"), genesis.encode()?).map_err(err)?;
        }
        let deadline = Instant::now() + Duration::from_secs(300);
        while !directory.join("network.json").exists() {
            let chains = fs::read_to_string(directory.join("network-logs/chains.log"));
            let uris = fs::read_to_string(directory.join("network-logs/uris.log"));
            if let (Ok(chains), Ok(uris)) = (chains, uris) {
                // The pinned runner writes these records only after health.
                // Strip terminal colour sequences before parsing its labels.
                let clean = |text: &str| {
                    let mut escape = false;
                    text.chars()
                        .filter(|c| {
                            if *c == '\u{1b}' {
                                escape = true;
                                return false;
                            }
                            if escape {
                                if *c == 'm' {
                                    escape = false;
                                }
                                return false;
                            }
                            true
                        })
                        .collect::<String>()
                };
                let chains = clean(&chains);
                let uris = clean(&uris);
                if let (Some(chain), Some(list)) = (
                    chains
                        .split("Blockchain ID: ")
                        .nth(1)
                        .and_then(|v| v.split_whitespace().next()),
                    uris.split("URIs: [")
                        .nth(1)
                        .and_then(|v| v.split(']').next()),
                ) {
                    let nodes = list.split_whitespace().collect::<Vec<_>>();
                    if nodes.len() == 5 {
                        fs::write(
                            directory.join("network.json"),
                            serde_json::to_vec_pretty(&json!({"chain_id":chain,"node_uris":nodes}))
                                .map_err(err)?,
                        )
                        .map_err(err)?;
                        break;
                    }
                }
            }
            if Instant::now() > deadline {
                return Err("five-validator native network did not become ready".into());
            }
            thread::sleep(Duration::from_millis(200));
        }
        let network: Value =
            serde_json::from_slice(&fs::read(directory.join("network.json")).map_err(err)?)
                .map_err(err)?;
        let chain = network["chain_id"]
            .as_str()
            .ok_or("native chain ID missing")?;
        let uris = network["node_uris"]
            .as_array()
            .filter(|uris| uris.len() == 5)
            .ok_or("exactly five native validator RPCs required")?;
        let clients = Arc::new(
            uris.iter()
                .map(|uri| {
                    AvalancheRpcClient::new(
                        &format!("{}/ext/bc/{chain}", uri.as_str().ok_or("invalid RPC")?),
                        Duration::from_secs(30),
                        true,
                    )
                })
                .collect::<Result<Vec<_>, String>>()?,
        );
        let authorizer = QuorumAuthorizer::new(
            signers
                .iter()
                .map(|(n, k)| (n.clone(), k.verifying_key()))
                .collect(),
            3,
            1,
            chain,
        )?;
        let admission = SigningKey::from_bytes(&[90; 64]);
        let private = directory.join("proposer");
        fs::create_dir_all(&private).map_err(err)?;
        let proposer = ProofParty::new(ProofPartyConfig {
            recipient_opening_keys: vec![],
            node: 0,
            allowed_root: private.clone(),
            state_file: private.join("state.bin"),
            state_passphrase: passphrase.to_vec(),
            n_mm: 4,
            n_parties: 7,
            threshold: 2,
            amount_bits: 32,
            price_bits: 32,
            remainder_bits: 64,
            complete_quote_proof: true,
            quote_eligibility_bits: 16,
            quote_span_bits: 16,
            trusted_defmi_receipt_public: Some(admission.verifying_key().to_bytes()),
            allow_health_signing: false,
        })?;
        let verifier = oclob_proofs::optimistic::TransitionChallengeVerifier::new(
            committee.verifying_keys(),
            committee.policy(),
        )?;
        let policy = OptimisticPolicy {
            network: hash(chain),
            application: hash("JGB10Y-JPY:native-browser:v1"),
            verifier: verifier.verifier_id(),
            proposer: proposer.application_verifying_key().to_bytes(),
            bond_asset: hash("OCLOB:NATIVE:BROWSER:SYNTHETIC-COLLATERAL:v1"),
            proposer_bond: 100,
            challenger_bond: 10,
            challenge_window_seconds: 30,
            response_window_seconds: 45,
        };
        let mode_path = directory.join("assurance.json");
        let mode = if mode_path.exists() {
            serde_json::from_slice(&fs::read(mode_path).map_err(err)?).map_err(err)?
        } else {
            "joint_proof".to_string()
        };
        if mode != "joint_proof" && mode != "optimistic" {
            return Err("invalid persisted assurance mode".into());
        }
        let runtime = Self {
            clients,
            authorizer,
            signers,
            proposer,
            admission,
            policy,
            progress: Arc::new(Mutex::new(json!({"active":false}))),
            private_progress: Arc::new(Mutex::new(BTreeMap::new())),
            directory: directory.to_path_buf(),
            mode,
        };
        runtime.bootstrap()?;
        Ok(runtime)
    }
    fn approve(&self, statement: Digest32) -> Result<defmi::facility::QuorumApproval, String> {
        self.authorizer
            .approve(statement, self.clients[0].state_root()?, &self.signers)
    }
    fn bootstrap(&self) -> Result<(), String> {
        let rpc = &self.clients[0];
        let client = OptimisticClient { rpc };
        // Existing policy enrollment is read back; never mint more on restart.
        if client.policy(self.policy.digest()?).is_ok() {
            return Ok(());
        }
        let asset = AssetDefinition {
            asset_id: self.policy.bond_asset,
            code: "OPT-BROWSER".into(),
            kind: AssetKind::Cash,
            decimals: 0,
            terms_digest: hash("synthetic public-development collateral; no economic value"),
        };
        let approval = self.approve(asset.statement()?)?;
        let tx = rpc.issue_asset(&asset, &approval, approval.before_root)?;
        rpc.wait_accepted(&tx, Duration::MAX, Duration::from_millis(100))?;
        for owner in [
            self.policy.proposer,
            SigningKey::from_bytes(&[91; 64]).verifying_key().to_bytes(),
        ] {
            let opening = AccountOpening {
                handle: owner,
                asset_id: asset.asset_id,
                commitment: Pedersen::new(b"qomm:defmi:v1")
                    .commit(&Scalar::from(10000u64), &Scalar::ZERO)
                    .compress()
                    .to_bytes(),
                issuance_nonce: hash(&format!("native-browser:{}", hex::encode(owner))),
            };
            let approval = self.approve(opening.statement()?)?;
            let tx = rpc.issue_account(&opening, &approval, approval.before_root)?;
            rpc.wait_accepted(&tx, Duration::MAX, Duration::from_millis(100))?;
            let transfer = BondTransfer {
                owner,
                asset: asset.asset_id,
                amount: 2000,
                before_balance: 10000,
                blinding: Scalar::ZERO.to_bytes(),
                withdraw: false,
            };
            client.transfer_bond(
                &transfer,
                &self.approve(command_digest("bond", &transfer)?)?,
            )?;
        }
        client.enroll(
            &self.policy,
            &self.approve(command_digest("enroll", &self.policy)?)?,
        )?;
        Ok(())
    }
    pub fn set_mode(&mut self, mode: &str) -> Result<(), String> {
        if !matches!(mode, "joint_proof" | "optimistic") {
            return Err("unknown assurance mode".into());
        }
        let temporary = self.directory.join("assurance.tmp");
        fs::write(&temporary, serde_json::to_vec(mode).map_err(err)?).map_err(err)?;
        fs::File::open(&temporary)
            .and_then(|f| f.sync_all())
            .map_err(err)?;
        fs::rename(temporary, self.directory.join("assurance.json")).map_err(err)?;
        fs::File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(err)?;
        self.mode = mode.into();
        Ok(())
    }
    pub fn execute(
        &mut self,
        role: &str,
        service: &mut OclobService,
        order: SecretOrder,
        authority: OrderAuthority,
        eligibility: AnonymousPresentation,
        now: u64,
    ) -> Result<OclobExecutionReceipt<Value>, ServiceError> {
        let result = (|| -> Result<OclobExecutionReceipt<Value>, String> {
            *self.progress.lock().map_err(err)? =
                json!({"active":true,"mode":self.mode,"stage":"mpc"});
            let gateway =
                OptimisticAvalancheGateway::new(&self.clients, &self.authorizer, &self.signers)?;
            if self.mode == "joint_proof" {
                let prepared = service
                    .prepare_canonical_submit(order, authority, eligibility, now)
                    .map_err(err)?;
                gateway.bootstrap(prepared.canonical_transition())?;
                let accepted = gateway.settle(prepared.canonical_transition(), unix_now()?)?;
                return serde_json::from_value(
                    serde_json::to_value(prepared.accept(service, accepted).map_err(err)?)
                        .map_err(err)?,
                )
                .map_err(err);
            }
            let client = OptimisticClient {
                rpc: &self.clients[0],
            };
            let policy = self.policy.clone();
            let rpc = &self.clients[0];
            let authorizer = &self.authorizer;
            let signers = &self.signers;
            let admission = &self.admission;
            let pending = service
                .prepare_optimistic_submit(
                    order,
                    authority,
                    eligibility,
                    now,
                    &mut self.proposer,
                    &client,
                    |statement, verifier| {
                        let execution = RegisteredExecution {
                            policy: policy.digest()?,
                            context: ExecutionContext {
                                network: policy.network,
                                application: policy.application,
                                verifier: verifier.verifier_id(),
                                job: statement.order_certificate_digest,
                                input_root: oclob_proofs::optimistic::transition_input_root(
                                    statement,
                                ),
                                before_state: rpc.state_root()?,
                            },
                            valid_until: unix_now()? + 600,
                        };
                        let approval = authorizer.approve(
                            command_digest("register", &execution)?,
                            rpc.state_root()?,
                            signers,
                        )?;
                        let accepted = client.register(&execution, &approval)?;
                        NodeExecutionAdmission {
                            policy: policy.clone(),
                            execution,
                            accepted_state: accepted.after_root,
                            accepted_height: accepted.height,
                            signature: vec![],
                        }
                        .sign(admission)
                    },
                )
                .map_err(err)?;
            let proposal = pending.proposal().clone();
            *self.private_progress.lock().map_err(err)? = BTreeMap::from([(
                role.to_string(),
                json!({"fills":pending.book_transition().fills.iter().map(|fill|json!({"price":fill.price,"quantity":fill.quantity})).collect::<Vec<_>>(),"settled":false}),
            )]);
            let finality=client.await_finality(&proposal,||serde_json::to_vec(&pending.challenge_proof().map_err(err)?).map_err(err),|claim|{
                // Only public claim metadata. Never serialize the private staged book.
                *self.progress.lock().expect("native progress lock")=json!({"active":true,"mode":"optimistic","stage":"assurance","claim_id":claim.proposal.id().map(hex::encode).ok(),"challenge_deadline":claim.challenge_deadline,"status":claim.status});
            })?;
            let prepared = pending
                .finalize(service, &finality, unix_now()?)
                .map_err(err)?;
            gateway.bootstrap(prepared.canonical_transition())?;
            let accepted = gateway.settle(prepared.canonical_transition(), unix_now()?)?;
            serde_json::from_value(
                serde_json::to_value(prepared.accept(service, accepted).map_err(err)?)
                    .map_err(err)?,
            )
            .map_err(err)
        })();
        let mut progress = self.progress.lock().expect("native progress lock");
        progress["active"] = json!(false);
        progress["settled"] = json!(result.is_ok());
        if result.is_err() {
            progress["stage"] = json!("failed");
        }
        result.map_err(ServiceError::CanonicalUncertain)
    }
}
