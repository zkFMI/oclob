//! Rough native protocol observation with real QOMM/OCLOB verifiers and
//! hybrid keys. Synthetic inputs, one host/process; not a matching-service or
//! production acceptance claim. All collateral enters via native transactions.
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use curve25519_dalek::Scalar;
use defmi::{
    facility::{AccountOpening, AssetDefinition, AssetKind, QuorumAuthorizer},
    governance::GovernanceSigner,
};
use defmi_avalanche_vm::{
    recovery::ApprovalWire,
    state::{id_key, State},
    transaction::TransactionEnvelope,
};
use oclob_avalanche_vm::OclobRuntime;
use oclob_ordering::OrderingCommittee;
use oclob_proofs::{TransitionProof, TransitionStatement};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf, time::Instant};
use zkfmi_zk::pedersen::Pedersen;
use zkpi_committee::{application_crypto::SigningKey, optimistic::*};
use zkpi_proofs::{
    quote_proof::{MakerWitness, QuoteCircuit, Registered},
    threshold_quote::{deal_quote_shares, joint_prove_quote},
};
#[path = "shared-optimistic/native.rs"]
mod native;

fn hash(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}
struct Run {
    state: State,
    authority: QuorumAuthorizer,
    signers: BTreeMap<String, GovernanceSigner>,
    runtime: OclobRuntime,
    output: PathBuf,
    events: Vec<Value>,
    network: Option<native::Network>,
}
impl Run {
    fn submit(
        &mut self,
        method: &str,
        mut params: Value,
        approval: Option<[u8; 32]>,
        now: u64,
    ) -> Result<(), String> {
        let now = native::moment(now);
        if method == "defmivm.issueOptimisticAdvance" || method == "defmivm.issueOptimisticAnswer" {
            params["attempt"] = json!(hash(&format!(
                "attempt:{}:{now}:{method}",
                self.events.len()
            )));
        }
        if let Some(statement) = approval {
            let signed =
                self.authority
                    .at(now)
                    .approve(statement, self.state.root(), &self.signers)?;
            params["approval"] =
                serde_json::to_value(ApprovalWire::from(&signed)).map_err(|e| e.to_string())?;
            params["expectedBeforeRoot"] = json!(hex::encode(self.state.root()));
        }
        let tx = TransactionEnvelope::new(method, params)?.encode()?;
        let (timestamp, network_receipt) = if let Some(network) = &self.network {
            let (block, bytes, receipt) = network.accept(&TransactionEnvelope::decode(&tx)?)?;
            fs::write(
                self.output
                    .join(format!("{:03}-block.bin", self.events.len())),
                bytes,
            )
            .map_err(|e| e.to_string())?;
            (
                u64::try_from(block.timestamp).map_err(|_| "negative native timestamp")?,
                Some(receipt),
            )
        } else {
            (now, None)
        };
        let receipt =
            self.state
                .apply_with_application(&tx, &self.authority, timestamp, &self.runtime)?;
        if method.starts_with("defmivm.issueOptimistic")
            && receipt.before_root == receipt.after_root
        {
            return Err("optimistic transition was omitted from the canonical state root".into());
        }
        let roots = if let Some(network) = &self.network {
            network.roots(receipt.after_root)?
        } else {
            vec![]
        };
        let n = self.events.len();
        fs::write(self.output.join(format!("{n:03}-transaction.json")), &tx)
            .map_err(|e| e.to_string())?;
        self.events.push(json!({"method":method,"timestamp":timestamp,"before":hex::encode(receipt.before_root),"after":hex::encode(receipt.after_root),"statement":hex::encode(receipt.statement),"network_receipt":network_receipt,"validator_roots":roots}));
        Ok(())
    }
    fn account(&mut self, owner: [u8; 32], asset: [u8; 32], now: u64) -> Result<(), String> {
        let key = Pedersen::new(b"qomm:defmi:v1");
        let opening = AccountOpening {
            handle: owner,
            asset_id: asset,
            commitment: key
                .commit(&Scalar::from(1000u64), &Scalar::ZERO)
                .compress()
                .to_bytes(),
            issuance_nonce: hash(&hex::encode(owner)),
        };
        self.submit("defmivm.issueAccount",json!({"opening":{"handle":hex::encode(owner),"assetID":hex::encode(asset),"commitment":hex::encode(opening.commitment),"issuanceNonce":hex::encode(opening.issuance_nonce)}}),Some(opening.statement()?),now)?;
        let transfer = BondTransfer {
            owner,
            asset,
            amount: 200,
            before_balance: 1000,
            blinding: Scalar::ZERO.to_bytes(),
            withdraw: false,
        };
        self.submit(
            "defmivm.issueOptimisticBond",
            json!({"transfer":transfer}),
            Some(command_digest("bond", &transfer)?),
            now,
        )?;
        let actual = self
            .state
            .accounts
            .get(&id_key(&owner))
            .ok_or("funding account disappeared")?;
        if actual.commitment
            != key
                .commit(&Scalar::from(800u64), &Scalar::ZERO)
                .compress()
                .to_bytes()
        {
            return Err("collateral was not debited from the real account".into());
        }
        Ok(())
    }
    fn case(
        &mut self,
        label: &str,
        verifier: [u8; 32],
        input: [u8; 32],
        correct: [u8; 32],
        proof: &[u8],
        kind: &str,
        now: u64,
    ) -> Result<Value, String> {
        let now = native::moment(now);
        let proposer = SigningKey::generate(&mut OsRng);
        let challenger = SigningKey::generate(&mut OsRng);
        let asset = hash("optimistic-collateral");
        self.account(proposer.identity(), asset, now)?;
        self.account(challenger.identity(), asset, now)?;
        let policy = OptimisticPolicy {
            network: hash("native-smoke"),
            application: hash(label),
            verifier,
            proposer: proposer.identity(),
            bond_asset: asset,
            proposer_bond: 100,
            challenger_bond: 10,
            challenge_window_seconds: if native::enabled() { 30 } else { 10 },
            response_window_seconds: if native::enabled() { 30 } else { 5 },
        };
        self.submit(
            "defmivm.issueOptimisticPolicy",
            json!({"policy":policy}),
            Some(command_digest("enroll", &policy)?),
            now,
        )?;
        let context = ExecutionContext {
            network: policy.network,
            application: policy.application,
            verifier,
            job: hash(&format!("{label}:{kind}")),
            input_root: input,
            before_state: self.state.root(),
        };
        let execution = RegisteredExecution {
            policy: policy.digest()?,
            context: context.clone(),
            valid_until: now + 600,
        };
        self.submit(
            "defmivm.issueOptimisticExecution",
            json!({"execution":execution}),
            Some(command_digest("register", &execution)?),
            now,
        )?;
        let claimed = if kind == "fraud" {
            hash("incorrect-result")
        } else {
            correct
        };
        let proposal = Proposal::signed(&policy, context.clone(), claimed, now + 300, &proposer)?;
        let id = proposal.id()?;
        self.submit(
            "defmivm.issueOptimisticProposal",
            json!({"proposal":proposal}),
            None,
            now,
        )?;
        let provisional_root = self.state.root();
        if self
            .state
            .optimistic
            .require_finalized(id, &context, claimed)
            .is_ok()
        {
            return Err("provisional result authorized settlement".into());
        }
        let raw = self.state.encode()?;
        let restored = State::decode(&raw)?;
        if restored.root() != provisional_root
            || restored.optimistic.bond(asset, proposer.identity()).locked != 100
        {
            return Err("pending claim or collateral did not survive snapshot readback".into());
        }
        self.state = restored;
        if let Some(network) = &self.network {
            if native::wall() + 2
                >= self
                    .state
                    .optimistic
                    .claim(&id)
                    .ok_or("missing claim")?
                    .challenge_deadline
            {
                return Err("native setup exhausted the early-rejection observation window".into());
            }
            let client = zkpi_defmi_sdk::optimistic::OptimisticClient {
                rpc: &network.clients[0],
            };
            if client.finalized(id, &context, claimed).is_ok() {
                return Err("canonical SDK authorized a provisional result".into());
            }
            let provisional = client.claim(id)?;
            fs::write(
                self.output
                    .join(format!("{}-{kind}-provisional-readback.json", label)),
                serde_json::to_vec_pretty(&provisional).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        }
        if kind != "unchallenged" {
            let request = Challenge::signed(id, &challenger)?;
            self.submit(
                "defmivm.issueOptimisticChallenge",
                json!({"challenge":request}),
                None,
                now + 1,
            )?;
            if kind != "timeout" {
                let before = self.state.root();
                let invalid=TransactionEnvelope::new("defmivm.issueOptimisticAnswer",json!({"claim":id,"proof":BASE64.encode(b"invalid proof"),"attempt":hash("invalid-answer-attempt")}))?.encode()?;
                if let Some(network) = &self.network {
                    let error = self
                        .state
                        .apply_with_application(
                            &invalid,
                            &self.authority,
                            native::wall(),
                            &self.runtime,
                        )
                        .expect_err("invalid proof must reject");
                    network.reject(&invalid, &error, before)?;
                }
                if self
                    .state
                    .apply_with_application(&invalid, &self.authority, now + 2, &self.runtime)
                    .is_ok()
                    || self.state.root() != before
                {
                    return Err("invalid answer changed canonical state".into());
                }
                self.submit(
                    "defmivm.issueOptimisticAnswer",
                    json!({"claim":id,"proof":BASE64.encode(proof)}),
                    None,
                    now + 2,
                )?;
            }
        }
        if kind == "timeout" {
            if let ClaimStatus::Challenged {
                response_deadline, ..
            } = self
                .state
                .optimistic
                .claim(&id)
                .ok_or("missing claim")?
                .status
            {
                native::wait_until(response_deadline);
            }
            self.submit(
                "defmivm.issueOptimisticAdvance",
                json!({"claim":id}),
                None,
                now + 6,
            )?;
        }
        if kind == "unchallenged" || kind == "defended" {
            if self
                .state
                .optimistic
                .require_finalized(id, &context, claimed)
                .is_ok()
            {
                return Err("defense accelerated selected challenge window".into());
            }
            native::wait_until(
                self.state
                    .optimistic
                    .claim(&id)
                    .ok_or("missing claim")?
                    .challenge_deadline,
            );
            self.submit(
                "defmivm.issueOptimisticAdvance",
                json!({"claim":id}),
                None,
                now + 10,
            )?;
            self.state
                .optimistic
                .require_finalized(id, &context, correct)?;
        } else if self
            .state
            .optimistic
            .require_finalized(id, &context, claimed)
            .is_ok()
        {
            return Err("rejected claim authorized settlement".into());
        }
        let proposer_balance = self.state.optimistic.bond(asset, proposer.identity());
        let challenger_balance = self.state.optimistic.bond(asset, challenger.identity());
        let expected = match kind {
            "unchallenged" => (200, 200),
            "defended" => (210, 190),
            _ => (100, 300),
        };
        if (proposer_balance.available, challenger_balance.available) != expected
            || proposer_balance.locked != 0
            || challenger_balance.locked != 0
        {
            return Err("native penalty/escrow readback differs from the protocol".into());
        }
        Ok(
            json!({"application":label,"case":kind,"claim":hex::encode(id),"provisional_root":hex::encode(provisional_root),"status":self.state.optimistic.claim(&id).ok_or("claim disappeared")?.status,"proposer":proposer_balance,"challenger":challenger_balance,"funding_accounts_each":800,"early_settlement":"rejected","snapshot_readback":"same_root_and_locked_bond"}),
        )
    }
}

fn main() -> Result<(), String> {
    let output = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: shared-optimistic OUTPUT_DIR")?,
    );
    fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    let signers = (1..=5)
        .map(|i| {
            let n = format!("optimistic-validator-{i}");
            Ok((
                n.clone(),
                GovernanceSigner::generate(&n, 1, native::moment(100_000) + 10_000)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let committee = OrderingCommittee::deterministic_for_demo().map_err(|e| e.to_string())?;
    let runtime = OclobRuntime::new(committee.verifying_keys(), committee.policy())?;
    let verifier_config = json!({"keys":committee.verifying_keys().iter().map(|(i,k)| (i.to_string(),hex::encode(k.as_bytes()))).collect::<BTreeMap<_,_>>(),"policy":committee.policy()});
    fs::write(
        output.join("verifier.json"),
        serde_json::to_vec_pretty(&verifier_config).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let network = native::Network::connect(&output, &signers)?;
    let domain = network
        .as_ref()
        .map(|n| n.chain_id.as_str())
        .unwrap_or("optimistic-native-smoke");
    let authority = QuorumAuthorizer::new(
        signers
            .iter()
            .map(|(n, k)| (n.clone(), k.verifying_key()))
            .collect(),
        3,
        1,
        domain,
    )?;
    let mut run = Run {
        state: State::default(),
        authority,
        signers,
        runtime,
        output,
        events: vec![],
        network,
    };
    let asset = AssetDefinition {
        asset_id: hash("optimistic-collateral"),
        code: "OPT-BOND".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: hash("synthetic-collateral-terms"),
    };
    run.submit("defmivm.issueAsset",json!({"asset":{"assetID":hex::encode(asset.asset_id),"code":asset.code,"kind":asset.kind.as_str(),"decimals":asset.decimals,"termsDigest":hex::encode(asset.terms_digest)}}),Some(asset.statement()?),1)?;
    let started = Instant::now();
    let circuit = QuoteCircuit::try_new(16, 16).map_err(str::to_string)?;
    let makers = [10, 12]
        .into_iter()
        .map(|ask| MakerWitness {
            ask_level: ask,
            spread: 1,
            slope: 0,
            invcoef: 0,
            inv: 0,
            maxqty: 10,
            expiry: 100,
            active: true,
            blindings: Registered::fresh(&mut OsRng),
        })
        .collect::<Vec<_>>();
    let (nodes, public) = deal_quote_shares(
        &circuit,
        &makers,
        1,
        0,
        10,
        1000,
        2,
        &[1, 2, 3, 4, 5, 6, 7],
        2,
        hash("quote-market"),
        1,
        &mut OsRng,
    )?;
    let transcript = hash("quote-transcript");
    let (proof, _) = joint_prove_quote(
        &circuit,
        &nodes,
        &public,
        &[1, 4, 7],
        &transcript,
        &mut OsRng,
    )?;
    let bundle = zkpi_committee::proof_codec::QuoteVerificationBundle {
        context: transcript,
        eligibility_bits: 16,
        span_bits: 16,
        public,
        proof,
    };
    let quote_bytes = zkpi_committee::proof_codec::encode_quote_verification(&bundle)?;
    let quote_input = quote_input_root(&bundle.public, transcript, 16, 16)?;
    let quote_output = quote_output_root(bundle.proof.winner_index, bundle.proof.winner_value);
    let statement = TransitionStatement {
        market_id: "optimistic-smoke".into(),
        sequence: 1,
        order_certificate_digest: hash("ordered-input"),
        eligibility_proof_digest: hash("eligibility"),
        private_before_root: hash("private-before"),
        private_after_root: hash("private-after"),
        public_before_root: hash("public-before"),
        public_after_root: hash("public-after"),
        mpc_program_digest: hash("mpc-program"),
        mpc_output_digest: hash("mpc-output"),
        fill_digest: hash("fills"),
    };
    let oclob_proof = TransitionProof::attest(
        statement.clone(),
        &committee.transition_signers(),
        committee.policy(),
    )
    .map_err(|e| e.to_string())?;
    let oclob_verifier = oclob_proofs::optimistic::TransitionChallengeVerifier::new(
        committee.verifying_keys(),
        committee.policy(),
    )?;
    let mut results = vec![];
    for (i, kind) in ["unchallenged", "defended", "fraud", "timeout"]
        .iter()
        .enumerate()
    {
        results.push(run.case(
            "QOMM",
            QuoteChallengeVerifier.verifier_id(),
            quote_input,
            quote_output,
            &quote_bytes,
            kind,
            10 + (i as u64) * 100,
        )?);
        results.push(run.case(
            "OCLOB",
            oclob_verifier.verifier_id(),
            oclob_proofs::optimistic::transition_input_root(&statement),
            statement.digest(),
            &serde_json::to_vec(&oclob_proof).map_err(|e| e.to_string())?,
            kind,
            50 + (i as u64) * 100,
        )?);
    }
    fs::write(run.output.join("canonical-state.json"), run.state.encode()?)
        .map_err(|e| e.to_string())?;
    let readback = State::decode(
        &fs::read(run.output.join("canonical-state.json")).map_err(|e| e.to_string())?,
    )?;
    if readback.root() != run.state.root() {
        return Err("final persisted root changed".into());
    }
    let environment = if native::enabled() {
        "five AvalancheGo validators, native RPC and exact accepted-block replay; synthetic collateral and inputs"
    } else {
        "native State::apply_with_application, one process, synthetic collateral and public inputs"
    };
    let outcome = json!({"verdict":"smoke_only","environment":environment,"live_consensus":native::enabled(),"limitations":["no QOMM/OCLOB matching service invocation","OCLOB uses a constructed transition statement","no product UI or deployment acceptance"],"elapsed_ms":started.elapsed().as_millis(),"final_root":hex::encode(readback.root()),"cases":results,"events":run.events});
    fs::write(
        run.output.join("outcome.json"),
        serde_json::to_vec_pretty(&outcome).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&outcome).map_err(|e| e.to_string())?
    );
    Ok(())
}
