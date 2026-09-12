//! Real-cryptography verifier vectors. These do not stand in for execution of
//! seven MPC processes, corporate services, or Avalanche consensus.
use super::*;
use merlin::Transcript;
use rand_core::OsRng;
use std::collections::BTreeMap;
use zkfmi_zk::sigma::prove_product;
use zkpi::{
    asset_scalar, frost, Bounds, PartialInstruction, AMOUNT_RANGE_CONTEXT, PRICE_RANGE_CONTEXT,
};
use zkpi_committee::dvp_issuer::{
    DvpProofs, DVP_CASH_REMAINDER_CONTEXT, DVP_PRODUCT_CONTEXT, DVP_SECURITIES_REMAINDER_CONTEXT,
};
use zkpi_proofs::opening_envelope::{encrypt_opening_share, opening_context, OpeningEnvelope};
use zkpi_proofs::threshold_range::{
    deal_bits, joint_prove_range_from_contributions, ThresholdRangeProof,
};

const NOW: u64 = 1_000;

fn range(key: &Pedersen, value: u64, blind: Scalar, context: &[u8]) -> ThresholdRangeProof {
    let parties = [1, 2, 3, 4, 5, 6, 7];
    let dealt = deal_bits(key, value, &blind, 32, &parties, 2, &mut OsRng).unwrap();
    let contributions = SIGNING_QUORUM
        .iter()
        .map(|party| dealt.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    joint_prove_range_from_contributions(key, &contributions, &SIGNING_QUORUM, context, &mut OsRng)
        .unwrap()
        .0
}

fn sign(
    keys: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
    message: &[u8],
) -> frost::Signature {
    let mut nonces = BTreeMap::new();
    let commitments = SIGNING_QUORUM
        .iter()
        .map(|party| {
            let id = frost::Identifier::try_from(*party as u16).unwrap();
            let (nonce, commitment) = frost::round1::commit(keys[&id].signing_share(), &mut OsRng);
            nonces.insert(id, nonce);
            (id, commitment)
        })
        .collect();
    let package = frost::SigningPackage::new(commitments, message);
    let shares = nonces
        .iter()
        .map(|(id, nonce)| {
            (
                *id,
                frost::round2::sign(&package, nonce, &keys[id]).unwrap(),
            )
        })
        .collect();
    frost::aggregate(&package, &shares, public).unwrap()
}

struct Fixture {
    request: NativeFillAuthorizationRequest,
    execution: NativeFillExecution,
    trust: NativeReservationTrust,
    public: frost::keys::PublicKeyPackage,
    keys: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    payment_digest: [u8; 64],
    securities_reserve: [u8; 32],
    cash_reserve: [u8; 32],
    openings: BTreeMap<String, serde_json::Value>,
    maker_is_payer: bool,
}

impl Fixture {
    fn new() -> Self {
        Self::with_direction(false)
    }

    fn with_direction(maker_is_payer: bool) -> Self {
        let key = Pedersen::new(b"qomm:defmi:v1");
        let (shares, public) = zkpi::deal_quorum(7, 3, &mut OsRng).unwrap();
        let keys = shares
            .into_iter()
            .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
            .collect();
        let issuer = oclob_core::application_crypto::SigningKey::from_bytes(&[31; 64]);
        let trust = NativeReservationTrust {
            venue_id: [32; 32],
            defmi_id: [33; 32],
            issuer: issuer.hybrid_public_key(),
        };
        let pq_committee = zkfmi_crypto::test_support::committee(
            Sha256::digest(public.serialize().unwrap()).into(),
        );
        let scope = ApplicationReserveScope {
            application_binding: oclob_manifest_v1().digest().unwrap(),
            venue_id: trust.venue_id,
            defmi_id: trust.defmi_id,
            committee_key_digest: Sha256::digest(public.serialize().unwrap()).into(),
            pq_committee_digest: pq_committee.digest().unwrap(),
            committee_epoch: 1,
            amount_bits: 32,
        };
        let make_authority = |index: u8, quantity: u64, blind: u64, delta: u64| {
            let point = key.g * Scalar::from(11 + u64::from(index));
            let order_signer =
                oclob_core::application_crypto::SigningKey::from_bytes(&[90 + index; 64]);
            let permit = ReservationPermit {
                version: 3,
                role: ReservationRole::Application,
                application_binding: scope.application_binding,
                venue_id: trust.venue_id,
                defmi_id: trust.defmi_id,
                canonical_state_root: [34; 32],
                accepted_height: 4,
                order_commitment: [40 + index; 32],
                participant_handle: point.compress().to_bytes(),
                entity_commitment: [42 + index; 32],
                reservation_id: [44 + index; 32],
                facility_id: [46 + index; 32],
                asset_id: [48 + index; 32],
                amount_commitment: key
                    .commit_u64(quantity, &Scalar::from(blind))
                    .compress()
                    .to_bytes(),
                escrow_note_id: [50 + index; 32],
                delegation_digest: [52 + index; 32],
                side_commitment: key
                    .commit_u64(
                        u64::from((index == 0) ^ maker_is_payer),
                        &Scalar::from(35_u64 + u64::from(index)),
                    )
                    .compress()
                    .to_bytes(),
                authority_digest: [54 + index; 32],
                reserve_receipt_digest: [56 + index; 32],
                reservation_sequence: 1,
                valid_until: 2_000,
                signer_public: issuer.hybrid_public_key(),
                signature: vec![],
            }
            .sign(&issuer.raw_hybrid_signer())
            .unwrap();
            let delta = Scalar::from(delta);
            let admission = ReservationAdmission::from_permit(
                &permit,
                &delta,
                &issuer.raw_hybrid_signer(),
                &[91; 32],
            )
            .unwrap();
            let binding = ExecutedReservationBinding {
                order_commitment: [58 + index; 32],
                source_order_commitment: permit.order_commitment,
                admission_digest: admission.digest().unwrap(),
                participant_handle: permit.participant_handle,
                amount_commitment: admission.amount_commitment,
                side_commitment: admission.side_commitment,
                order_signer: order_signer.verifying_key().to_bytes(),
                valid_until: 2_000,
            };
            let head = ApplicationSpendHead {
                hold_id: permit.reservation_id,
                sequence: 0,
                previous_receipt: permit.reserve_receipt_digest,
                remaining_commitment: permit.amount_commitment,
                reserve_reblinding: delta.to_bytes(),
                close: index == 1,
            };
            (
                NativeReservationAuthority {
                    admission,
                    permit,
                    reserve_reblinding: delta.to_bytes(),
                    claim_authorization_endpoint: ClaimAuthorizationEndpoint {
                        host: "claim-authority.test".into(),
                        port: 9890 + u16::from(index),
                        server_name: "claim-authority.test".into(),
                        certificate_sha256: [99 + index; 32],
                    },
                    order_signer: order_signer.verifying_key().to_bytes(),
                },
                binding,
                head,
                order_signer,
            )
        };
        let (maker, maker_binding, maker_head, maker_order_signer) = if maker_is_payer {
            make_authority(0, 4_040, 17, 29)
        } else {
            make_authority(0, 60, 13, 23)
        };
        let (taker, taker_binding, taker_head, taker_order_signer) = if maker_is_payer {
            make_authority(1, 60, 13, 23)
        } else {
            make_authority(1, 4_040, 17, 29)
        };
        let (securities, cash, securities_asset, cash_asset, securities_reserve, cash_reserve) =
            if maker_is_payer {
                (
                    taker_head,
                    maker_head,
                    taker.permit.asset_id,
                    maker.permit.asset_id,
                    taker_binding.amount_commitment,
                    maker_binding.amount_commitment,
                )
            } else {
                (
                    maker_head,
                    taker_head,
                    maker.permit.asset_id,
                    taker.permit.asset_id,
                    maker_binding.amount_commitment,
                    taker_binding.amount_commitment,
                )
            };
        let round_id = [61; 32];
        let output = [62; 32];
        let job = collaborative_job_id(round_id, 0, output).unwrap();
        let amount_blind = Scalar::from(67_u64);
        let price_blind = Scalar::from(68_u64);
        let cash_blind = Scalar::from(69_u64);
        let asset_blind = Scalar::from(70_u64);
        let amount = key.commit_u64(40, &amount_blind);
        let asset = key.commit(&asset_scalar(&securities_asset), &asset_blind);
        let maker_handle = point(maker.permit.participant_handle).unwrap();
        let taker_handle = point(taker.permit.participant_handle).unwrap();
        let (payer, payee) = if maker_is_payer {
            (maker_handle, taker_handle)
        } else {
            (taker_handle, maker_handle)
        };
        let partial = PartialInstruction::from_threshold_ranges(
            &key,
            &Bounds {
                amount_bits: 32,
                price_bits: 32,
                max_horizon: 3_600,
            },
            amount,
            key.commit_u64(100, &price_blind),
            asset,
            range(&key, 40, amount_blind, AMOUNT_RANGE_CONTEXT),
            range(&key, 100, price_blind, PRICE_RANGE_CONTEXT),
            payer,
            payee,
            1_800,
            job,
            output,
        )
        .unwrap();
        let payment_digest = partial.digest();
        let instruction = partial.sealed_hybrid(
            sign(&keys, &public, &payment_digest),
            zkfmi_crypto::test_support::approve(&pq_committee, &payment_digest, 1_000),
        );
        let claim_issue =
            native_claim_authorization_issue_from_sequences(&instruction, &maker, &taker, 0, 0)
                .unwrap();
        let make_claim_authorizations =
            |reservation_id: [u8; 32], signer: &ApplicationSigningKey| {
                let expected = claim_issue.expected_for(reservation_id).unwrap();
                NativeParticipantClaimAuthorizations {
                    version: CLAIM_AUTHORIZATION_ISSUE_VERSION,
                    reservation_id,
                    sequence: 0,
                    claims: expected.map(|(leg, recipient_commitment)| {
                        NativeClaimAuthorizationCommitment {
                            leg,
                            recipient_commitment,
                            authorization:
                                defmi::claim_redemption::NoteClaimAuthorization::generate(
                                    recipient_commitment,
                                    NOW,
                                    2_000,
                                )
                                .unwrap()
                                .commitment()
                                .unwrap(),
                        }
                    }),
                    signature: Vec::new(),
                }
                .sign(&claim_issue, signer)
                .unwrap()
            };
        let (payer_order_signer, payee_order_signer) = if maker_is_payer {
            (&maker_order_signer, &taker_order_signer)
        } else {
            (&taker_order_signer, &maker_order_signer)
        };
        let claim_authorizations = NativeFillClaimAuthorizations {
            payer: make_claim_authorizations(claim_issue.payer.reservation_id, payer_order_signer),
            payee: make_claim_authorizations(claim_issue.payee.reservation_id, payee_order_signer),
        };
        let sec_refund_blind = Scalar::from(13_u64 + 23) - amount_blind;
        let cash_refund_blind = Scalar::from(17_u64 + 29) - cash_blind;
        let dvp = DvpProofs {
            product: prove_product(
                &key,
                &mut Transcript::new(DVP_PRODUCT_CONTEXT),
                &amount,
                &Scalar::from(40_u64),
                &amount_blind,
                &Scalar::from(100_u64),
                &price_blind,
                &cash_blind,
                &mut OsRng,
            ),
            securities_remainder: range(
                &key,
                20,
                sec_refund_blind,
                DVP_SECURITIES_REMAINDER_CONTEXT,
            ),
            cash_remainder: range(&key, 40, cash_refund_blind, DVP_CASH_REMAINDER_CONTEXT),
        };
        let mut openings = BTreeMap::new();
        let mut make_opening = |leg: &str, value: u64, blind: Scalar, recipient| {
            let context = opening_context(&job, leg).unwrap();
            let shares = SIGNING_QUORUM
                .iter()
                .map(|party| {
                    let x = Scalar::from(*party as u64);
                    encrypt_opening_share(
                        context,
                        *party,
                        Scalar::from(value) + Scalar::from(7_u64) * x + Scalar::from(9_u64) * x * x,
                        blind + Scalar::from(17_u64) * x + Scalar::from(19_u64) * x * x,
                        &recipient,
                        &zkfmi_crypto::test_support::opening_recipient_public(),
                        &mut OsRng,
                    )
                    .unwrap()
                })
                .collect();
            let envelope = ApplicationOpening::from_domain(
                &OpeningEnvelope::new(context, 3, recipient, shares).unwrap(),
                instruction.nullifier(),
                claim_authorizations
                    .authorization(match leg {
                        "securities_delivery" => NativeClaimLeg::SecuritiesDelivery,
                        "securities_refund" => NativeClaimLeg::SecuritiesRefund,
                        "cash_delivery" => NativeClaimLeg::CashDelivery,
                        "cash_refund" => NativeClaimLeg::CashRefund,
                        _ => unreachable!(),
                    })
                    .unwrap(),
            )
            .unwrap();
            let own = &envelope.shares[0];
            openings.insert(leg.to_owned(), json!({ "party": own.party, "context": hex::encode(context),
                "recipient_view": hex::encode(envelope.recipient_view), "recipient_public": own.recipient_public, "sealed": own.sealed }));
            envelope
        };
        let envelopes = [
            make_opening("securities_delivery", 40, amount_blind, payer),
            make_opening("securities_refund", 20, sec_refund_blind, payee),
            make_opening("cash_delivery", 4_000, cash_blind, payee),
            make_opening("cash_refund", 40, cash_refund_blind, payer),
        ];
        let asset_link =
            defmi::asset_link::prove(&key, securities_asset, &asset, &asset_blind, &mut OsRng)
                .unwrap();
        let fill = ApplicationNoteFill {
            version: 2,
            pq_committee,
            pq_authorization: None,
            scope,
            before_root: [63; 32],
            operation_id: native_fill_operation(job),
            mpc_result_digest: output,
            securities_asset,
            cash_asset,
            securities,
            cash,
            instruction: zkpi::wire::encode(&instruction),
            dvp_proofs: encode_dvp_proofs(&dvp).unwrap(),
            cash_commitment: key.commit_u64(4_000, &cash_blind).compress().to_bytes(),
            asset_link_announcement: asset_link.announcement.compress().to_bytes(),
            asset_link_response: asset_link.response.to_bytes(),
            openings: envelopes,
            committee_public: public.serialize().unwrap(),
            signature: vec![],
            batch: None,
            optimistic: None,
        };
        Self {
            request: NativeFillAuthorizationRequest {
                round_id,
                slot: 0,
                fill,
                maker,
                taker,
                claim_authorizations,
            },
            securities_reserve,
            cash_reserve,
            execution: NativeFillExecution {
                maker: maker_binding,
                taker: taker_binding,
                taker_may_close: true,
            },
            trust,
            public,
            keys,
            payment_digest,
            openings,
            maker_is_payer,
        }
    }

    fn verify(
        &self,
        request: &NativeFillAuthorizationRequest,
        execution: &NativeFillExecution,
    ) -> Result<ApplicationStatementAuthorization, String> {
        self.verify_with_slots(request, execution, &[0])
    }

    fn verify_with_slots(
        &self,
        request: &NativeFillAuthorizationRequest,
        execution: &NativeFillExecution,
        matched_slots: &[usize],
    ) -> Result<ApplicationStatementAuthorization, String> {
        NativeFillVerifier {
            request,
            execution,
            trust: &self.trust,
            matched_slots,
            now: NOW,
        }
        .verify(CompletedApplicationProof {
            job_id: collaborative_job_id(
                self.request.round_id,
                0,
                self.request.fill.mpc_result_digest,
            )
            .unwrap(),
            payment_digest: self.payment_digest,
            quote_digest: self.request.fill.mpc_result_digest,
            maker_handle: self.execution.maker.participant_handle,
            taker_handle: self.execution.taker.participant_handle,
            maker_is_payer: self.maker_is_payer,
            securities_reserve: self.securities_reserve,
            cash_reserve: self.cash_reserve,
            opening_shares: &self.openings,
            committee_public: &self.public,
        })
    }
}

#[test]
fn completed_proof_can_certify_exact_native_fill_without_participant_signature() {
    let f = Fixture::new();
    let authorization = f.verify(&f.request, &f.execution).unwrap();
    let mut fill = f.request.fill.clone();
    assert!(fill.verify(&fill.scope, NOW).is_err());
    fill.signature = sign(&f.keys, &f.public, &authorization.message)
        .serialize()
        .unwrap();
    fill.pq_authorization = Some(zkfmi_crypto::test_support::approve(
        &fill.pq_committee,
        &authorization.message,
        1_000,
    ));
    fill.verify(&fill.scope, NOW).unwrap();
    let mut new_parent = f.request.clone();
    new_parent.fill.before_root = [91; 32];
    let revised = f.verify(&new_parent, &f.execution).unwrap();
    assert_ne!(authorization.message, revised.message);
    assert_eq!(authorization.action_digest, revised.action_digest);
    let wire = serde_json::to_value(&f.request).unwrap();
    let mut extra = wire.clone();
    extra["raw_order"] = json!("forbidden");
    assert!(serde_json::from_value::<NativeFillAuthorizationRequest>(extra).is_err());
    let mut extra = wire;
    extra["maker"]["original_opening"] = json!("forbidden");
    assert!(serde_json::from_value::<NativeFillAuthorizationRequest>(extra).is_err());
}

#[test]
fn native_claim_authorizations_are_pinned_to_participants_openings_and_local_execution() {
    let f = Fixture::new();
    f.verify(&f.request, &f.execution).unwrap();

    let mut missing = serde_json::to_value(&f.request).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .remove("claim_authorizations");
    assert!(serde_json::from_value::<NativeFillAuthorizationRequest>(missing).is_err());

    let mut swapped = f.request.clone();
    std::mem::swap(
        &mut swapped.claim_authorizations.payer,
        &mut swapped.claim_authorizations.payee,
    );
    assert!(f.verify(&swapped, &f.execution).is_err());

    let mut reused = f.request.clone();
    reused.claim_authorizations.payee.claims[0].authorization =
        reused.claim_authorizations.payer.claims[0].authorization;
    assert!(f.verify(&reused, &f.execution).is_err());

    let mut tampered_signature = f.request.clone();
    tampered_signature.claim_authorizations.payer.signature[0] ^= 1;
    assert!(f.verify(&tampered_signature, &f.execution).is_err());

    let mut substituted_opening = f.request.clone();
    substituted_opening.fill.openings[0].claim_authorization =
        substituted_opening.fill.openings[1].claim_authorization;
    assert!(f.verify(&substituted_opening, &f.execution).is_err());

    let mut wrong_local_signer = f.execution.clone();
    wrong_local_signer.maker.order_signer[0] ^= 1;
    assert!(f.verify(&f.request, &wrong_local_signer).is_err());

    let mut legacy = serde_json::to_value(&f.request).unwrap();
    legacy["claim_authorizations"]["payer"]
        .as_object_mut()
        .unwrap()
        .remove("signature");
    assert!(serde_json::from_value::<NativeFillAuthorizationRequest>(legacy).is_err());
}

#[test]
fn claim_authorization_evidence_rejects_cross_fill_key_reuse() {
    let f = Fixture::new();
    let (responses, keys) = claim_authorization_evidence(std::slice::from_ref(&f.request)).unwrap();
    assert_eq!(responses, 2);
    assert_eq!(keys.len(), 4);
    let error = claim_authorization_evidence(&[f.request.clone(), f.request]).unwrap_err();
    assert!(error.contains("reused across fill requests"));
}

#[test]
fn arriving_sell_closes_only_its_securities_reserve() {
    let f = Fixture::with_direction(true);
    assert!(f.request.fill.securities.close);
    assert!(!f.request.fill.cash.close);
    let authorization = f.verify(&f.request, &f.execution).unwrap();
    let mut fill = f.request.fill.clone();
    fill.signature = sign(&f.keys, &f.public, &authorization.message)
        .serialize()
        .unwrap();
    fill.pq_authorization = Some(zkfmi_crypto::test_support::approve(
        &fill.pq_committee,
        &authorization.message,
        1_000,
    ));
    fill.verify(&fill.scope, NOW).unwrap();
    let mut wrong_closure = f.request.clone();
    wrong_closure.fill.cash.close = true;
    assert!(f.verify(&wrong_closure, &f.execution).is_err());
    let mut still_active = f.execution.clone();
    still_active.taker_may_close = false;
    assert!(f.verify(&f.request, &still_active).is_err());
}

#[test]
fn native_signing_rejects_changed_execution_authority_heads_openings_and_proofs() {
    let f = Fixture::new();
    f.verify(&f.request, &f.execution).unwrap();
    for mutation in 0..17 {
        let mut request = f.request.clone();
        let mut execution = f.execution.clone();
        match mutation {
            0 => request.slot = 1,
            1 => request.fill.operation_id[0] ^= 1,
            2 => request.fill.scope.defmi_id[0] ^= 1,
            3 => request.fill.mpc_result_digest[0] ^= 1,
            4 => execution.taker.participant_handle = execution.maker.participant_handle,
            5 => request.fill.securities.close = true,
            6 => execution.taker_may_close = false,
            7 => request.fill.securities.hold_id[0] ^= 1,
            8 => request.fill.securities.reserve_reblinding = Scalar::from(24_u64).to_bytes(),
            9 => {
                request.fill.cash.remaining_commitment =
                    request.fill.securities.remaining_commitment
            }
            10 => request.fill.cash.previous_receipt[0] ^= 1,
            11 => request.maker.permit.signature[0] ^= 1,
            12 => request.maker.admission.signature[0] ^= 1,
            13 => request.fill.openings[0].shares[0].sealed.tag[0] ^= 1,
            14 => {
                request.fill.openings[0].shares.remove(0);
            }
            15 => request.fill.dvp_proofs[80] ^= 1,
            16 => request.fill.asset_link_response = Scalar::ONE.to_bytes(),
            _ => unreachable!(),
        };
        assert!(
            f.verify(&request, &execution).is_err(),
            "accepted mutation {mutation}"
        );
    }
}

#[test]
fn local_full_execution_refuses_an_extracted_or_reordered_signing_request() {
    let f = Fixture::new();
    let slots = [0, 2, 7];
    let mut request = f.request.clone();
    request.fill.batch = native_batch_binding(
        &request.fill.scope,
        request.fill.before_root,
        request.round_id,
        request.fill.mpc_result_digest,
        &slots,
        0,
    )
    .unwrap();
    assert!(f.verify_with_slots(&request, &f.execution, &slots).is_ok());
    assert!(f
        .verify_with_slots(&f.request, &f.execution, &slots)
        .is_err());
    for subset in [&[0][..], &[0, 7]] {
        let mut extracted = request.clone();
        extracted.fill.batch = native_batch_binding(
            &request.fill.scope,
            request.fill.before_root,
            request.round_id,
            request.fill.mpc_result_digest,
            subset,
            0,
        )
        .unwrap();
        assert!(f
            .verify_with_slots(&extracted, &f.execution, &slots)
            .is_err());
    }
    let mut reordered = request.clone();
    reordered.fill.batch.as_mut().unwrap().index = 1;
    assert!(f
        .verify_with_slots(&reordered, &f.execution, &slots)
        .is_err());
    let mut stale = request;
    stale.fill.before_root[0] ^= 1;
    assert!(f.verify_with_slots(&stale, &f.execution, &slots).is_err());
}
