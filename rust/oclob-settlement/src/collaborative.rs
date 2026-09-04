//! OCLOB-specific collaborative zkPI and DvP proof assembly.
//!
//! The coordinator relays public points, seals, challenges and responses. Each
//! [`ProofPartyRpc`] reads only its own extracted MP-SPDZ Persistence block;
//! no API in this module accepts or returns a raw Shamir share.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_proofs::opening_envelope::{opening_context, EncryptedOpeningShare, OpeningEnvelope};
use qomm_proofs::price_limit::{
    from_threshold as threshold_price_limit, threshold_context as price_limit_context,
    PriceLimitDirection,
};
use qomm_proofs::threshold_gadgets::coefficient_commitments_from_evaluations;
use qomm_proofs::threshold_range::{verify_threshold_range, ThresholdRangeProof};
use qomm_transport::dvp_issuer::{
    assemble_proofs as assemble_dvp_proofs, make_challenge as make_dvp_challenge,
    relation_statements_from_evaluations as dvp_relation_statements,
    statements_from_evaluations as dvp_statements, DvpProofs, DVP_CASH_REMAINDER_CONTEXT,
    DVP_PRODUCT_CONTEXT, DVP_SECURITIES_REMAINDER_CONTEXT,
};
use qomm_transport::dvp_wire::{
    decode as decode_dvp, encode as encode_dvp, Envelope as DvpEnvelope, Message as DvpMessage,
};
use qomm_transport::frost_coordinator::{
    distributed_frost_setup, distributed_frost_sign, frost_signing_job,
};
use qomm_transport::limit_issuer::{
    assemble as assemble_limit, challenge as make_limit_challenge,
    relation_from_evaluations as limit_relations, statement_from_evaluations as limit_statement,
};
use qomm_transport::limit_wire::{
    decode as decode_limit, encode as encode_limit, Envelope as LimitEnvelope,
    Message as LimitMessage,
};
use qomm_transport::product_proof_coordinator::prove_standing_pool_remainder;
use qomm_transport::proof_client::ProofPartyRpc;
use qomm_transport::proof_codec::encode_threshold_range;
use qomm_transport::zkpi_issuer::{
    assemble_ranges, build_partial_instruction, make_challenge as make_zkpi_challenge,
    relation_statements_from_evaluations as zkpi_relation_statements,
    statements_from_evaluations as zkpi_statements, ZkpiRangeProofs, ZkpiStatements,
};
use qomm_transport::zkpi_wire::{
    decode as decode_zkpi, encode as encode_zkpi, Envelope as ZkpiEnvelope, Message as ZkpiMessage,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::verify_product;
use qomm_zkpi::{asset_scalar, frost, Bounds, Instruction, QuoteBinding, Venue};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const COMMITTEE_SIZE: usize = 7;
const SHAMIR_THRESHOLD: usize = 2;
const SIGNING_QUORUM: [usize; 3] = [1, 4, 7];
const AMOUNT_BITS: usize = 32;
const PRICE_BITS: usize = 32;
const MAX_PUBLIC_WIRE_BYTES: usize = 1 << 20;

pub struct CollaborativeFillRequest {
    pub job_id: [u8; 32],
    /// Digest of the OCLOB ordering and matching proof accepted by DeFMI.
    pub market_proof_digest: [u8; 32],
    pub limit_direction: PriceLimitDirection,
    pub limit_commitment: RistrettoPoint,
    pub limit_context: [u8; 32],
    /// Obtained from the Taker's pre-trade DeFMI reservation, not from an
    /// operator-readable order body.
    pub taker_handle: RistrettoPoint,
    pub asset_id: [u8; 32],
    pub deadline: u64,
    pub now: u64,
}

pub struct CollaborativeFillProof {
    pub job_id: [u8; 32],
    pub instruction: Instruction,
    pub frost_public: frost::keys::PublicKeyPackage,
    pub maker_handle: RistrettoPoint,
    pub price_limit_proof: ThresholdRangeProof,
    pub dvp_proofs: DvpProofs,
    pub cash_commitment: RistrettoPoint,
    pub securities_remainder: RistrettoPoint,
    pub cash_remainder: RistrettoPoint,
    pub maker_pool_remainder: RistrettoPoint,
    pub maker_pool_remainder_proof: ThresholdRangeProof,
    pub securities_delivery_opening: OpeningEnvelope,
    pub securities_refund_opening: OpeningEnvelope,
    pub cash_delivery_opening: OpeningEnvelope,
    pub cash_refund_opening: OpeningEnvelope,
    pub asset_blinding: Scalar,
}

/// Stable one-use proof identifier for one public OCLOB fill slot.
pub fn collaborative_job_id(
    round_id: [u8; 32],
    slot: usize,
    public_output_digest: [u8; 32],
) -> Result<[u8; 32], String> {
    if slot >= 8 || round_id == [0; 32] || public_output_digest == [0; 32] {
        return Err("collaborative fill identity is outside its fixed bounds".into());
    }
    Ok(Sha256::new()
        .chain_update(b"OCLOB:COLLABORATIVE-FILL:v1")
        .chain_update(round_id)
        .chain_update((slot as u16).to_be_bytes())
        .chain_update(public_output_digest)
        .finalize()
        .into())
}

/// Bind every proof node to its own extracted 616-wire fill handoff.
pub fn load_fill<T: ProofPartyRpc>(
    parties: &mut [T],
    round_id: [u8; 32],
    slot: usize,
    job_id: [u8; 32],
    market_proof_digest: [u8; 32],
) -> Result<(), String> {
    if parties.len() != COMMITTEE_SIZE
        || slot >= 8
        || job_id == [0; 32]
        || market_proof_digest == [0; 32]
    {
        return Err("collaborative fill load is outside its fixed bounds".into());
    }
    for (node, party) in parties.iter_mut().enumerate() {
        let relative = format!(
            "{}/proof-slot-{slot}/Transactions-P{node}.data",
            hex::encode(round_id)
        );
        let response = party.call(
            "load",
            json!({
                "job_id": hex::encode(job_id),
                "persistence": relative,
                "quote_digest": hex::encode(market_proof_digest),
            }),
        )?;
        if response.get("party").and_then(Value::as_u64) != Some(node as u64 + 1) {
            return Err("proof node loaded another node's fill persistence".into());
        }
    }
    Ok(())
}

pub fn setup_frost<T: ProofPartyRpc>(
    parties: &mut [T],
    session: [u8; 32],
) -> Result<frost::keys::PublicKeyPackage, String> {
    distributed_frost_setup(parties, session)
}

pub fn prove_fill<T: ProofPartyRpc>(
    parties: &mut [T],
    frost_public: frost::keys::PublicKeyPackage,
    request: CollaborativeFillRequest,
) -> Result<CollaborativeFillProof, String> {
    validate_request(parties, &request)?;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let bounds = Bounds {
        amount_bits: AMOUNT_BITS,
        price_bits: PRICE_BITS,
        max_horizon: 3_600,
    };
    let (maker_handle, handle_evaluations) = maker_handle(parties, request.job_id)?;
    if maker_handle == request.taker_handle {
        return Err("Maker and Taker settlement handles are identical".into());
    }

    let (zkpi_statements, zkpi_proofs) =
        prove_zkpi_ranges(parties, request.job_id, &key, &handle_evaluations)?;
    let amount_range_wire = encode_threshold_range(&zkpi_proofs.amount)?;
    let price_range_wire = encode_threshold_range(&zkpi_proofs.price)?;
    let asset_blinding = Scalar::random(&mut OsRng);
    let asset_commitment = key.commit(&asset_scalar(&request.asset_id), &asset_blinding);
    let (payer, payee) = match request.limit_direction {
        PriceLimitDirection::MaximumBuyPrice => (request.taker_handle, maker_handle),
        PriceLimitDirection::MinimumSellPrice => (maker_handle, request.taker_handle),
    };
    let partial = build_partial_instruction(
        &key,
        &bounds,
        &zkpi_statements,
        zkpi_proofs,
        asset_commitment,
        payer,
        payee,
        request.deadline,
        request.job_id,
        request.market_proof_digest,
    )?;
    authorize_zkpi(
        parties,
        request.job_id,
        &partial,
        &amount_range_wire,
        &price_range_wire,
    )?;
    let signature =
        distributed_frost_sign(parties, &SIGNING_QUORUM, &partial.digest(), &frost_public)?;
    let instruction = partial.sealed(signature);
    Venue::new(key.clone(), &bounds, frost_public.clone())
        .require_threshold_ranges()
        .verify(&instruction, request.now)
        .map_err(str::to_string)?;

    let price_limit_proof = prove_limit(
        parties,
        request.job_id,
        &key,
        &instruction,
        request.limit_direction,
        request.limit_commitment,
        request.limit_context,
    )?;
    let (dvp_proofs, cash_commitment, securities_remainder, cash_remainder) =
        prove_dvp(parties, request.job_id, &key, &instruction)?;
    let (maker_pool_remainder, maker_pool_remainder_proof) =
        prove_standing_pool_remainder(parties, &key, request.job_id)?;

    let securities_delivery_opening = collect_opening(
        parties,
        request.job_id,
        "securities_delivery",
        instruction.payer_handle,
    )?;
    let securities_refund_opening = collect_opening(
        parties,
        request.job_id,
        "securities_refund",
        instruction.payee_handle,
    )?;
    let cash_delivery_opening = collect_opening(
        parties,
        request.job_id,
        "cash_delivery",
        instruction.payee_handle,
    )?;
    let cash_refund_opening = collect_opening(
        parties,
        request.job_id,
        "cash_refund",
        instruction.payer_handle,
    )?;

    Ok(CollaborativeFillProof {
        job_id: request.job_id,
        instruction,
        frost_public,
        maker_handle,
        price_limit_proof,
        dvp_proofs,
        cash_commitment,
        securities_remainder,
        cash_remainder,
        maker_pool_remainder,
        maker_pool_remainder_proof,
        securities_delivery_opening,
        securities_refund_opening,
        cash_delivery_opening,
        cash_refund_opening,
        asset_blinding,
    })
}

fn validate_request<T: ProofPartyRpc>(
    parties: &[T],
    request: &CollaborativeFillRequest,
) -> Result<(), String> {
    if parties.len() != COMMITTEE_SIZE
        || request.job_id == [0; 32]
        || request.market_proof_digest == [0; 32]
        || request.limit_context == [0; 32]
        || request.asset_id == [0; 32]
        || request.limit_commitment == RistrettoPoint::default()
        || request.taker_handle == RistrettoPoint::default()
        || request.deadline < request.now
        || request.deadline > request.now.saturating_add(3_600)
    {
        return Err("collaborative fill request is outside its fixed bounds".into());
    }
    Ok(())
}

fn maker_handle<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
) -> Result<(RistrettoPoint, Vec<Value>), String> {
    let evaluations = parties
        .iter_mut()
        .map(|party| {
            party.call(
                "maker_handle_evaluation",
                json!({"job_id": hex::encode(job_id)}),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut points = BTreeMap::new();
    for value in &evaluations {
        let party = value
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| "Maker handle evaluation has an invalid party".to_owned())?;
        let point = point(value.get("point"), "Maker handle evaluation")?;
        if !(1..=COMMITTEE_SIZE).contains(&party) || points.insert(party, point).is_some() {
            return Err("Maker handle evaluations omit or duplicate a party".into());
        }
    }
    let handle = coefficient_commitments_from_evaluations(&points, SHAMIR_THRESHOLD)?
        .first()
        .copied()
        .ok_or_else(|| "Maker handle coefficient ladder is empty".to_owned())?;
    if handle == RistrettoPoint::default() {
        return Err("Maker handle is the identity point".into());
    }
    Ok((handle, evaluations))
}

fn prove_zkpi_ranges<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
    key: &Pedersen,
    handle_evaluations: &[Value],
) -> Result<(ZkpiStatements, ZkpiRangeProofs), String> {
    let evaluation_wires = parties
        .iter_mut()
        .map(|party| call_wire(party, "zkpi_evaluations", job_id, "zkPI evaluation"))
        .collect::<Result<Vec<_>, _>>()?;
    let evaluations = evaluation_wires
        .iter()
        .map(
            |raw| match decode_zkpi(raw).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::Evaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("proof node returned another zkPI evaluation".into()),
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let statements = zkpi_statements(&evaluations, SHAMIR_THRESHOLD)?;
    let relation_wires = parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "zkpi_bind",
                json!({
                    "job_id": hex::encode(job_id),
                    "evaluations": wire_array(&evaluation_wires),
                    "maker_handle_evaluations": handle_evaluations,
                }),
            )?;
            public_wire(&value, "zkPI relation")
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relation_evaluations = relation_wires
        .iter()
        .map(
            |raw| match decode_zkpi(raw).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::RelationEvaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("proof node returned another zkPI relation".into()),
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let relations = zkpi_relation_statements(&statements, &relation_evaluations)?;

    let mut seals = Vec::with_capacity(SIGNING_QUORUM.len());
    let mut rounds = Vec::with_capacity(SIGNING_QUORUM.len());
    for party in SIGNING_QUORUM {
        let value =
            parties[party - 1].call("zkpi_round1", json!({"job_id": hex::encode(job_id)}))?;
        let seal = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "proof node omitted zkPI round-one seal".to_owned())?,
            "zkPI round-one seal",
        )?;
        let round = public_wire(
            value
                .get("round")
                .ok_or_else(|| "proof node omitted zkPI round one".to_owned())?,
            "zkPI round one",
        )?;
        seals.push(
            match decode_zkpi(&seal).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::Round1Seal(value),
                } if wire_job == job_id => value,
                _ => return Err("proof node returned another zkPI seal".into()),
            },
        );
        rounds.push(
            match decode_zkpi(&round).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::Round1(value),
                } if wire_job == job_id => value,
                _ => return Err("proof node returned another zkPI round".into()),
            },
        );
    }
    let challenge = make_zkpi_challenge(&statements, &rounds, &seals, &SIGNING_QUORUM)?;
    let challenge_wire = encode_zkpi(&ZkpiEnvelope {
        job_id,
        message: ZkpiMessage::Challenge(challenge),
    })
    .map_err(|error| error.to_string())?;
    let responses = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let value = parties[*party - 1].call(
                "zkpi_round2",
                json!({
                    "job_id": hex::encode(job_id),
                    "challenge": BASE64.encode(&challenge_wire),
                }),
            )?;
            let raw = public_wire(&value, "zkPI round two")?;
            match decode_zkpi(&raw).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::Round2(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("proof node returned another zkPI response".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let proofs = assemble_ranges(
        key,
        &statements,
        &relations,
        &rounds,
        &seals,
        &responses,
        &SIGNING_QUORUM,
    )?;
    Ok((statements, proofs))
}

fn authorize_zkpi<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
    partial: &qomm_zkpi::PartialInstruction,
    amount_range: &[u8],
    price_range: &[u8],
) -> Result<(), String> {
    let quote_digest = match partial.quote_binding {
        QuoteBinding::ProofDigest(value) => value,
        QuoteBinding::LegacyPackedKey(_) => {
            return Err("collaborative proof refuses a legacy quote key".into())
        }
    };
    let message = partial.digest();
    let signing_job = frost_signing_job(&message);
    for party in SIGNING_QUORUM {
        let value = parties[party - 1].call(
            "authorize_zkpi",
            json!({
                "job_id": hex::encode(job_id),
                "signing_job_id": hex::encode(signing_job),
                "message": BASE64.encode(message),
                "amount_range": BASE64.encode(amount_range),
                "price_range": BASE64.encode(price_range),
                "asset_commitment": hex::encode(partial.asset_commitment.compress().to_bytes()),
                "payer_handle": hex::encode(partial.payer_handle.compress().to_bytes()),
                "payee_handle": hex::encode(partial.payee_handle.compress().to_bytes()),
                "deadline": partial.deadline,
                "nonce": hex::encode(partial.nonce),
                "quote_digest": hex::encode(quote_digest),
            }),
        )?;
        if value.get("authorized").and_then(Value::as_bool) != Some(true) {
            return Err("proof node did not authorize the MPC-derived zkPI".into());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove_limit<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
    key: &Pedersen,
    instruction: &Instruction,
    direction: PriceLimitDirection,
    limit_commitment: RistrettoPoint,
    limit_context: [u8; 32],
) -> Result<ThresholdRangeProof, String> {
    let evaluation_wires = parties
        .iter_mut()
        .map(|party| call_wire(party, "limit_evaluations", job_id, "limit evaluation"))
        .collect::<Result<Vec<_>, _>>()?;
    let evaluations = evaluation_wires
        .iter()
        .map(|raw| match decode_limit(raw)? {
            LimitEnvelope {
                job_id: wire_job,
                message: LimitMessage::Evaluations(value),
            } if wire_job == job_id => Ok(value),
            _ => Err("proof node returned another limit evaluation".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let statement = limit_statement(&evaluations, SHAMIR_THRESHOLD)?;
    let expected = match direction {
        PriceLimitDirection::MaximumBuyPrice => limit_commitment - instruction.price_commitment,
        PriceLimitDirection::MinimumSellPrice => instruction.price_commitment - limit_commitment,
    };
    if statement.commitment.compress() != expected.compress() {
        return Err("MPC limit witness differs from the signed Taker limit".into());
    }
    let relation_evaluations = parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "limit_bind",
                json!({
                    "job_id": hex::encode(job_id),
                    "evaluations": wire_array(&evaluation_wires),
                }),
            )?;
            let raw = public_wire(&value, "limit relation")?;
            match decode_limit(&raw)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::RelationEvaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("proof node returned another limit relation".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relations = limit_relations(&statement, &relation_evaluations)?;
    let context = price_limit_context(
        direction,
        PRICE_BITS,
        &instruction.price_commitment,
        &limit_commitment,
        &limit_context,
    );
    let mut seals = Vec::with_capacity(SIGNING_QUORUM.len());
    let mut rounds = Vec::with_capacity(SIGNING_QUORUM.len());
    for party in SIGNING_QUORUM {
        let value = parties[party - 1].call(
            "limit_round1",
            json!({"job_id": hex::encode(job_id), "context": hex::encode(context)}),
        )?;
        let seal = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "proof node omitted limit seal".to_owned())?,
            "limit seal",
        )?;
        let round = public_wire(
            value
                .get("round")
                .ok_or_else(|| "proof node omitted limit round".to_owned())?,
            "limit round",
        )?;
        seals.push(match decode_limit(&seal)? {
            LimitEnvelope {
                job_id: wire_job,
                message: LimitMessage::Round1Seal(value),
            } if wire_job == job_id => value,
            _ => return Err("proof node returned another limit seal".into()),
        });
        rounds.push(match decode_limit(&round)? {
            LimitEnvelope {
                job_id: wire_job,
                message: LimitMessage::Round1(value),
            } if wire_job == job_id => value,
            _ => return Err("proof node returned another limit round".into()),
        });
    }
    let challenge = make_limit_challenge(&statement, &rounds, &seals, &SIGNING_QUORUM, &context)?;
    let challenge_wire = encode_limit(&LimitEnvelope {
        job_id,
        message: LimitMessage::Challenge(challenge),
    })?;
    let responses = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let value = parties[*party - 1].call(
                "limit_round2",
                json!({
                    "job_id": hex::encode(job_id),
                    "challenge": BASE64.encode(&challenge_wire),
                }),
            )?;
            let raw = public_wire(&value, "limit response")?;
            match decode_limit(&raw)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::Round2(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("proof node returned another limit response".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let proof = assemble_limit(
        key,
        &statement,
        &relations,
        &rounds,
        &seals,
        &responses,
        &SIGNING_QUORUM,
        &context,
    )?;
    threshold_price_limit(
        key,
        &instruction.price_commitment,
        &limit_commitment,
        direction,
        PRICE_BITS,
        &limit_context,
        proof.clone(),
    )?;
    Ok(proof)
}

fn prove_dvp<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
    key: &Pedersen,
    instruction: &Instruction,
) -> Result<(DvpProofs, RistrettoPoint, RistrettoPoint, RistrettoPoint), String> {
    let evaluation_wires = parties
        .iter_mut()
        .map(|party| call_wire(party, "dvp_evaluations", job_id, "DvP evaluation"))
        .collect::<Result<Vec<_>, _>>()?;
    let evaluations = evaluation_wires
        .iter()
        .map(
            |raw| match decode_dvp(raw).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::Evaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("proof node returned another DvP evaluation".into()),
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let constant = |values: BTreeMap<usize, RistrettoPoint>| -> Result<RistrettoPoint, String> {
        coefficient_commitments_from_evaluations(&values, SHAMIR_THRESHOLD).and_then(|ladder| {
            ladder
                .first()
                .copied()
                .ok_or_else(|| "DvP coefficient ladder is empty".into())
        })
    };
    let cash_commitment = constant(
        evaluations
            .iter()
            .map(|node| (node.party, node.product.relation))
            .collect(),
    )?;
    let securities_remainder = constant(
        evaluations
            .iter()
            .map(|node| (node.party, node.securities_remainder.value))
            .collect(),
    )?;
    let cash_remainder = constant(
        evaluations
            .iter()
            .map(|node| (node.party, node.cash_remainder.value))
            .collect(),
    )?;
    let statements = dvp_statements(
        &instruction.amount_commitment,
        &instruction.price_commitment,
        &cash_commitment,
        &securities_remainder,
        &cash_remainder,
        &evaluations,
        SHAMIR_THRESHOLD,
    )?;
    let relation_evaluations = parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "dvp_bind",
                json!({
                    "job_id": hex::encode(job_id),
                    "evaluations": wire_array(&evaluation_wires),
                }),
            )?;
            let raw = public_wire(&value, "DvP relation")?;
            match decode_dvp(&raw).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::RelationEvaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("proof node returned another DvP relation".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relations = dvp_relation_statements(&statements, &relation_evaluations)?;

    let mut seals = Vec::with_capacity(SIGNING_QUORUM.len());
    let mut rounds = Vec::with_capacity(SIGNING_QUORUM.len());
    for party in SIGNING_QUORUM {
        let value =
            parties[party - 1].call("dvp_round1", json!({"job_id": hex::encode(job_id)}))?;
        let seal = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "proof node omitted DvP round-one seal".to_owned())?,
            "DvP round-one seal",
        )?;
        let round = public_wire(
            value
                .get("round")
                .ok_or_else(|| "proof node omitted DvP round one".to_owned())?,
            "DvP round one",
        )?;
        seals.push(
            match decode_dvp(&seal).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::Round1Seal(value),
                } if wire_job == job_id => value,
                _ => return Err("proof node returned another DvP seal".into()),
            },
        );
        rounds.push(
            match decode_dvp(&round).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::Round1(value),
                } if wire_job == job_id => value,
                _ => return Err("proof node returned another DvP round".into()),
            },
        );
    }
    let challenge = make_dvp_challenge(&statements, &rounds, &seals, &SIGNING_QUORUM)?;
    let challenge_wire = encode_dvp(&DvpEnvelope {
        job_id,
        message: DvpMessage::Challenge(challenge),
    })
    .map_err(|error| error.to_string())?;
    let responses = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let value = parties[*party - 1].call(
                "dvp_round2",
                json!({
                    "job_id": hex::encode(job_id),
                    "challenge": BASE64.encode(&challenge_wire),
                }),
            )?;
            let raw = public_wire(&value, "DvP round two")?;
            match decode_dvp(&raw).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::Round2(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("proof node returned another DvP response".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let proofs = assemble_dvp_proofs(
        key,
        &statements,
        &relations,
        &rounds,
        &seals,
        &responses,
        &SIGNING_QUORUM,
    )?;
    if !verify_product(
        key,
        &mut Transcript::new(DVP_PRODUCT_CONTEXT),
        &instruction.amount_commitment,
        &instruction.price_commitment,
        &cash_commitment,
        &proofs.product,
    ) || !verify_threshold_range(
        key,
        &securities_remainder,
        &proofs.securities_remainder,
        DVP_SECURITIES_REMAINDER_CONTEXT,
    ) || !verify_threshold_range(
        key,
        &cash_remainder,
        &proofs.cash_remainder,
        DVP_CASH_REMAINDER_CONTEXT,
    ) {
        return Err("public verifier rejected the MPC-derived DvP proof".into());
    }
    Ok((
        proofs,
        cash_commitment,
        securities_remainder,
        cash_remainder,
    ))
}

fn opening_share(value: &Value) -> Result<EncryptedOpeningShare, String> {
    let decode32 = |name: &str| -> Result<[u8; 32], String> {
        hex::decode(
            value
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("proof node omitted opening {name}"))?,
        )
        .map_err(|_| format!("proof node opening {name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("proof node opening {name} is not 32 bytes"))
    };
    Ok(EncryptedOpeningShare {
        party: value
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|party| usize::try_from(party).ok())
            .ok_or_else(|| "proof node opening party is invalid".to_owned())?,
        ephemeral: CompressedRistretto(decode32("ephemeral")?)
            .decompress()
            .ok_or_else(|| "proof node opening ephemeral is not canonical".to_owned())?,
        masked_value: Option::<Scalar>::from(Scalar::from_canonical_bytes(decode32(
            "masked_value",
        )?))
        .ok_or_else(|| "proof node opening value mask is not canonical".to_owned())?,
        masked_blinding: Option::<Scalar>::from(Scalar::from_canonical_bytes(decode32(
            "masked_blinding",
        )?))
        .ok_or_else(|| "proof node opening blinding mask is not canonical".to_owned())?,
    })
}

fn collect_opening<T: ProofPartyRpc>(
    parties: &mut [T],
    job_id: [u8; 32],
    leg: &str,
    recipient: RistrettoPoint,
) -> Result<OpeningEnvelope, String> {
    let context = opening_context(&job_id, leg)?;
    let recipient_wire = hex::encode(recipient.compress().to_bytes());
    let context_wire = hex::encode(context);
    let shares = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let value = parties[*party - 1].call(
                "claim_opening_share",
                json!({
                    "job_id": hex::encode(job_id),
                    "leg": leg,
                    "recipient_view": recipient_wire.clone(),
                }),
            )?;
            if value.get("context").and_then(Value::as_str) != Some(context_wire.as_str())
                || value.get("recipient_view").and_then(Value::as_str)
                    != Some(recipient_wire.as_str())
            {
                return Err("proof node changed an opening context or recipient".into());
            }
            opening_share(&value)
        })
        .collect::<Result<Vec<_>, String>>()?;
    OpeningEnvelope::new(context, SHAMIR_THRESHOLD + 1, recipient, shares)
}

fn call_wire<T: ProofPartyRpc>(
    party: &mut T,
    method: &str,
    job_id: [u8; 32],
    name: &str,
) -> Result<Vec<u8>, String> {
    let value = party.call(method, json!({"job_id": hex::encode(job_id)}))?;
    public_wire(&value, name)
}

fn public_wire(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    let raw = BASE64
        .decode(
            value
                .as_str()
                .ok_or_else(|| format!("proof node {name} is not a public wire"))?,
        )
        .map_err(|_| format!("proof node {name} is not valid base64"))?;
    if raw.is_empty() || raw.len() > MAX_PUBLIC_WIRE_BYTES {
        return Err(format!("proof node {name} exceeds its fixed bound"));
    }
    Ok(raw)
}

fn wire_array(wires: &[Vec<u8>]) -> Value {
    Value::Array(
        wires
            .iter()
            .map(|wire| Value::String(BASE64.encode(wire)))
            .collect(),
    )
}

fn point(value: Option<&Value>, name: &str) -> Result<RistrettoPoint, String> {
    let encoded: [u8; 32] = hex::decode(
        value
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{name} omitted its point"))?,
    )
    .map_err(|_| format!("{name} point is not hexadecimal"))?
    .try_into()
    .map_err(|_| format!("{name} point is not 32 bytes"))?;
    CompressedRistretto(encoded)
        .decompress()
        .ok_or_else(|| format!("{name} point is not canonical"))
}
