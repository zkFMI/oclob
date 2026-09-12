//! Isolated live MPC -> optimistic claim -> native account settlement example.
//! Synthetic orders and development credentials; all matching uses MP-SPDZ,
//! all admission/challenge/collateral/settlement operations use native RPC.
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use curve25519_dalek::Scalar;
use defmi::{
    avalanche::AvalancheClient,
    facility::{
        AccountOpening, AssetDefinition, AssetKind, QuorumAuthorizer, SettlementOrder, StateLeg,
    },
    governance::GovernanceSigner,
};
use defmi_avalanche_vm::{state::State, transaction::TransactionEnvelope};
use oclob_core::{authorize_order, SecretOrder, Side, TimeInForce};
use oclob_ordering::OrderingCommittee;
use oclob_service::OclobService;
use oclob_settlement::avalanche::OptimisticAvalancheGateway;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};
use zkfmi_zk::pedersen::Pedersen;
use zkpi_committee::{
    application_crypto::SigningKey,
    optimistic::*,
    proof_party::{ProofParty, ProofPartyConfig},
};
use zkpi_defmi_sdk::optimistic::OptimisticClient;
#[path = "shared-optimistic/native.rs"]
mod native;
fn hash(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn main() -> Result<(), String> {
    if !native::enabled() {
        return Err(
            "this example requires ZKPI_OPTIMISTIC_NATIVE=1 and five live validators".into(),
        );
    }
    let output = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: optimistic-service OUTPUT_DIR")?,
    );
    fs::create_dir_all(&output).map_err(err)?;
    let started = Instant::now();
    let signers = (1..=5)
        .map(|i| {
            let n = format!("optimistic-service-{i}");
            Ok((
                n.clone(),
                GovernanceSigner::generate(&n, 1, native::wall() + 7200)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let committee = OrderingCommittee::deterministic_for_demo().map_err(err)?;
    let config = json!({"keys":committee.verifying_keys().iter().map(|(i,k)|(i.to_string(),hex::encode(k.as_bytes()))).collect::<BTreeMap<_,_>>(),"policy":committee.policy()});
    fs::write(
        output.join("verifier.json"),
        serde_json::to_vec_pretty(&config).map_err(err)?,
    )
    .map_err(err)?;
    let network = native::Network::connect(&output, &signers)?.ok_or("native network missing")?;
    let authority = QuorumAuthorizer::new(
        signers
            .iter()
            .map(|(n, k)| (n.clone(), k.verifying_key()))
            .collect(),
        3,
        1,
        &network.chain_id,
    )?;
    let rpc = &network.clients[0];
    let client = OptimisticClient { rpc };
    let approve = |statement| authority.approve(statement, rpc.state_root()?, &signers);
    let mut bootstrap_receipts = vec![];
    let observe = |r: defmi::avalanche::AcceptedTransition| -> Result<Value, String> {
        network.roots(r.after_root)?;
        Ok(
            json!({"tx_id":r.tx_id,"block_id":r.block_id,"height":r.height,"statement":hex::encode(r.statement),"before_root":hex::encode(r.before_root),"after_root":hex::encode(r.after_root)}),
        )
    };
    let asset = AssetDefinition {
        asset_id: hash("OCLOB:OPTIMISTIC:SERVICE:COLLATERAL"),
        code: "OPT-SERVICE".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: hash("Synthetic public collateral without economic value"),
    };
    let approval = approve(asset.statement()?)?;
    let tx = rpc.issue_asset(&asset, &approval, approval.before_root)?;
    bootstrap_receipts.push(observe(
        rpc.wait_accepted(&tx, Duration::MAX, Duration::from_millis(100))?,
    )?);
    let admission_key = SigningKey::generate(&mut OsRng);
    let private = output.join("node-private");
    fs::create_dir_all(&private).map_err(err)?;
    let mut passphrase = vec![0; 32];
    OsRng.fill_bytes(&mut passphrase);
    let mut proposer = ProofParty::new(ProofPartyConfig {
        recipient_opening_keys: vec![],
        node: 0,
        allowed_root: private.clone(),
        state_file: private.join("state.bin"),
        state_passphrase: passphrase,
        n_mm: 4,
        n_parties: 7,
        threshold: 2,
        amount_bits: 32,
        price_bits: 32,
        remainder_bits: 64,
        complete_quote_proof: true,
        quote_eligibility_bits: 16,
        quote_span_bits: 16,
        trusted_defmi_receipt_public: Some(admission_key.verifying_key().to_bytes()),
        allow_health_signing: false,
    })?;
    let challenger = SigningKey::generate(&mut OsRng);
    let owner = proposer.application_verifying_key().to_bytes();
    for identity in [owner, challenger.verifying_key().to_bytes()] {
        let opening = AccountOpening {
            handle: identity,
            asset_id: asset.asset_id,
            commitment: Pedersen::new(b"qomm:defmi:v1")
                .commit(&Scalar::from(1000u64), &Scalar::ZERO)
                .compress()
                .to_bytes(),
            issuance_nonce: hash(&hex::encode(identity)),
        };
        let approval = approve(opening.statement()?)?;
        let tx = rpc.issue_account(&opening, &approval, approval.before_root)?;
        bootstrap_receipts.push(observe(
            rpc.wait_accepted(&tx, Duration::MAX, Duration::from_millis(100))?,
        )?);
        let transfer = BondTransfer {
            owner: identity,
            asset: asset.asset_id,
            amount: 200,
            before_balance: 1000,
            blinding: Scalar::ZERO.to_bytes(),
            withdraw: false,
        };
        bootstrap_receipts.push(observe(
            client.transfer_bond(&transfer, &approve(command_digest("bond", &transfer)?)?)?,
        )?);
    }
    let verifier = oclob_proofs::optimistic::TransitionChallengeVerifier::new(
        committee.verifying_keys(),
        committee.policy(),
    )?;
    let policy = OptimisticPolicy {
        network: hash(&network.chain_id),
        application: hash("JGB10Y-JPY:optimistic-service"),
        verifier: verifier.verifier_id(),
        proposer: owner,
        bond_asset: asset.asset_id,
        proposer_bond: 100,
        challenger_bond: 10,
        challenge_window_seconds: 20,
        response_window_seconds: 30,
    };
    bootstrap_receipts.push(observe(
        client.enroll(&policy, &approve(command_digest("enroll", &policy)?)?)?,
    )?);
    let (eligibility, issuer) =
        oclob_dekyx::deterministic_demo_environment("JGB10Y-JPY").map_err(err)?;
    let seller_wallet = issuer
        .issue_wallet(11, b"optimistic-seller", &mut OsRng)
        .map_err(err)?;
    let buyer_wallet = issuer
        .issue_wallet(22, b"optimistic-buyer", &mut OsRng)
        .map_err(err)?;
    let mut service = OclobService::new(
        "JGB10Y-JPY",
        std::env::var("MP_SPDZ_ROOT").unwrap_or_else(|_| "/opt/MP-SPDZ".into()),
        eligibility,
    )
    .map_err(err)?;
    let (seller, buyer) = service.demo_participant_handles();
    let gateway = OptimisticAvalancheGateway::new(&network.clients, &authority, &signers)?;
    let mut results = vec![];
    for (i, (side, price, quantity, tif, handle, wallet)) in [
        (
            Side::Sell,
            100,
            100,
            TimeInForce::GoodTilCancelled,
            seller,
            &seller_wallet,
        ),
        (
            Side::Buy,
            101,
            40,
            TimeInForce::ImmediateOrCancel,
            buyer,
            &buyer_wallet,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let now = native::wall();
        let expires = now + 3600;
        let order = SecretOrder::new_with_dekyx_nullifier(
            "JGB10Y-JPY",
            side,
            price,
            quantity,
            tif,
            expires,
            handle,
            wallet.subject_nullifier(),
            hash(&format!("order:{i}")),
            hash(&format!("salt:{i}")),
        )
        .map_err(err)?;
        let auth = authorize_order(
            &order,
            expires + 60,
            &oclob_core::application_crypto::SigningKey::generate(&mut OsRng),
        )
        .map_err(err)?;
        let evidence = wallet
            .present(
                order.commitment().0,
                hash(&format!("eligibility:{i}")),
                expires,
                &mut OsRng,
            )
            .map_err(err)?;
        let book_before = service.public_book();
        let balances_before = service.settlement_state();
        let pending = service
            .prepare_optimistic_submit(
                order,
                auth,
                evidence,
                now,
                &mut proposer,
                &client,
                |statement, installed| {
                    let context = ExecutionContext {
                        network: policy.network,
                        application: policy.application,
                        verifier: installed.verifier_id(),
                        job: statement.order_certificate_digest,
                        input_root: oclob_proofs::optimistic::transition_input_root(statement),
                        before_state: rpc.state_root()?,
                    };
                    let execution = RegisteredExecution {
                        policy: policy.digest()?,
                        context,
                        valid_until: native::wall() + 600,
                    };
                    let accepted = client.register(
                        &execution,
                        &approve(command_digest("register", &execution)?)?,
                    )?;
                    NodeExecutionAdmission {
                        policy: policy.clone(),
                        execution,
                        accepted_state: accepted.after_root,
                        accepted_height: accepted.height,
                        signature: vec![],
                    }
                    .sign(&admission_key)
                },
            )
            .map_err(err)?;
        if service.public_book() != book_before || service.settlement_state() != balances_before {
            return Err("provisional MPC result changed the live book or assets".into());
        }
        let proposal = pending.proposal().clone();
        let provisional = client.claim(proposal.id()?)?;
        if !matches!(provisional.status, ClaimStatus::Pending) {
            return Err("proposal did not return during the provisional phase".into());
        }
        let reference = defmi::application_settlement::OptimisticSettlementReference {
            claim: proposal.id()?,
            context: proposal.context.clone(),
            output_root: proposal.output_root,
            public_output: serde_json::to_vec(pending.public_statement()).map_err(err)?,
        };
        // Real governance-authorized account mutation, rejected specifically
        // at the canonical optimistic gate before any commitment can change.
        let account = rpc.call("defmivm.account", json!({"handle":hex::encode(owner)}))?;
        let early = defmi::application_settlement::OptimisticAccountSettlement {
            order: SettlementOrder {
                operation_id: hash(&format!("early-operation:{i}")),
                nullifier: hash(&format!("early-nullifier:{i}")),
                deadline: expires,
                payment_instruction_digest: hash("early-payment"),
                proof_digest: hash("early-proof"),
                market_statement_digest: proposal.output_root,
                legs: vec![StateLeg {
                    handle: owner,
                    asset_id: asset.asset_id,
                    before_commitment: Pedersen::new(b"qomm:defmi:v1")
                        .commit(&Scalar::from(800u64), &Scalar::ZERO)
                        .compress()
                        .to_bytes(),
                    after_commitment: Pedersen::new(b"qomm:defmi:v1")
                        .commit(&Scalar::from(799u64), &Scalar::ZERO)
                        .compress()
                        .to_bytes(),
                    before_sequence: account["sequence"]
                        .as_u64()
                        .ok_or("missing account sequence")?,
                }],
            },
            reference,
        };
        let before = rpc.state_root()?;
        let early_error = client
            .settle_accounts(&early, &approve(early.statement()?)?)
            .expect_err("provisional settlement must reject");
        if !early_error.contains("not finalized") || rpc.state_root()? != before {
            return Err(format!(
                "early account mutation reached another boundary: {early_error}"
            ));
        }
        if i == 1 {
            client.challenge(&Challenge::signed(proposal.id()?, &challenger)?)?;
        }
        let mut proof_requested = false;
        let finality = client.await_finality(
            &proposal,
            || {
                proof_requested = true;
                serde_json::to_vec(&pending.challenge_proof().map_err(err)?).map_err(err)
            },
            |_| {},
        )?;
        if proof_requested != (i == 1) {
            return Err("challenge evidence was generated on the wrong path".into());
        }
        let prepared = pending
            .finalize(&service, &finality, native::wall())
            .map_err(err)?;
        if service.public_book() != book_before || service.settlement_state() != balances_before {
            return Err("financial proof preparation committed service state".into());
        }
        gateway.bootstrap(prepared.canonical_transition())?;
        let acceptance = gateway.settle(prepared.canonical_transition(), native::wall())?;
        let native_receipt = json!({"transaction_id":acceptance.transaction_id(),"block_id":acceptance.block_id(),"height":acceptance.height(),"after_root":hex::encode(acceptance.after_state_root())});
        let execution = prepared.accept(&mut service, acceptance).map_err(err)?;
        if i == 1
            && (execution.book_transition.fills.len() != 1
                || execution.book_transition.fills[0].price != 100
                || execution.book_transition.fills[0].quantity != 40)
        {
            return Err("real optimistic MPC trade differs from 40 at 100".into());
        }
        results.push(json!({"order":i,"provisional":provisional,"early_account_rejection":early_error,"challenge_proof_requested":proof_requested,"final_claim":client.claim(proposal.id()?)?,"native_settlement":native_receipt,"fills":execution.book_transition.fills,"mpc_parties":execution.mpc.parties,"mpc_all_parties_agreed":execution.mpc.all_parties_agreed,"mpc_program":hex::encode(execution.mpc.program_sha256),"mpc_output":hex::encode(execution.mpc.public_output_sha256),"book_after":service.public_book(),"settlement_after":service.settlement_state()}));
    }
    let root = rpc.state_root()?;
    let roots = network.roots(root)?;
    let outcome = json!({"verdict":"smoke_only","environment":"real MP-SPDZ seven-party service, real hybrid/DeKYX authentication and five native Avalanche validators; synthetic orders and collateral","elapsed_ms":started.elapsed().as_millis(),"final_root":hex::encode(root),"validator_roots":roots,"bootstrap":bootstrap_receipts,"orders":results,"limitations":["isolated research service API; public OCLOB HTTP selector is not enabled","synthetic participants and assets; no production economic claims"]});
    fs::write(
        output.join("outcome.json"),
        serde_json::to_vec_pretty(&outcome).map_err(err)?,
    )
    .map_err(err)?;
    println!("observed service outcome saved");
    Ok(())
}
