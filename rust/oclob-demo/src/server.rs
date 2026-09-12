//! Browser-facing OCLOB demonstration server.
//!
//! Every order uses the same DeKYX -> encrypted corporate queue -> OCLOB MPC
//! -> zkPI -> DeFMI coordinator path as the command-line acceptance runner.
//! The operator projection never contains a participant's private order or
//! portfolio. Maker and taker projections contain only that participant's own
//! data.

use oclob_core::application_crypto::SigningKey;
use oclob_core::{authorize_order, Digest32, SecretOrder, Side, TimeInForce};
use oclob_dekyx::{deterministic_demo_environment, DemoEligibilityIssuer, DemoEligibilityWallet};
use oclob_service::{DurableOclobQueue, OclobExecutionReceipt, OclobService, QueueWorkerResult};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

mod native;

const MARKET: &str = "JGB10Y-JPY";
const MAX_HTTP_BYTES: usize = 1 << 20;
const EVENT_LIMIT: usize = 80;

pub fn run_from_env() -> Result<(), String> {
    let mut host = "0.0.0.0".to_string();
    let mut port = 18_800_u16;
    let mut state_dir = PathBuf::from("/tmp/oclob-demo-state");
    let mut mp_spdz_root = std::env::var_os("MP_SPDZ_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/MP-SPDZ"));
    let passphrase = std::env::var("OCLOB_QUEUE_PASSPHRASE").map_err(|_| {
        "OCLOB_QUEUE_PASSPHRASE is required; inject a PoC-only secret without writing it to source or logs"
            .to_string()
    })?;
    if passphrase.len() < 16 {
        return Err("OCLOB_QUEUE_PASSPHRASE must contain at least 16 bytes".into());
    }
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let value = |args: &mut std::iter::Skip<std::env::Args>| {
            args.next()
                .ok_or_else(|| format!("{argument} requires a value"))
        };
        match argument.as_str() {
            "--host" => host = value(&mut args)?,
            "--port" => {
                port = value(&mut args)?
                    .parse()
                    .map_err(|_| "--port must be a valid TCP port".to_string())?
            }
            "--state-dir" => state_dir = PathBuf::from(value(&mut args)?),
            "--mp-spdz-root" => mp_spdz_root = PathBuf::from(value(&mut args)?),
            _ => return Err(format!("unknown argument {argument}")),
        }
    }
    let runtime = DemoRuntime::new(&mp_spdz_root, &state_dir, passphrase.as_bytes())?;
    serve(&host, port, runtime)
}

struct Participant {
    role: &'static str,
    display_name: &'static str,
    handle: Digest32,
    signing_key: SigningKey,
    wallet: DemoEligibilityWallet,
    queue: DurableOclobQueue,
    next_nonce: u64,
    own_orders: Vec<OwnOrder>,
}

#[derive(Clone, Serialize)]
struct OwnOrder {
    request_id: String,
    side: Side,
    price: u64,
    quantity: u64,
    time_in_force: TimeInForce,
    status: String,
    submitted_at: u64,
}

#[derive(Clone, Serialize)]
struct PublicEvent {
    sequence: u64,
    at: u64,
    kind: String,
    title: String,
    detail: String,
    tone: &'static str,
}

struct DemoRuntime {
    native: native::NativeSettlement,
    views: Arc<Mutex<BTreeMap<String, Value>>>,
    service: OclobService,
    participants: BTreeMap<String, Participant>,
    mpc_nodes: [bool; 7],
    validators: [bool; 5],
    phase: String,
    event_sequence: u64,
    events: VecDeque<PublicEvent>,
    last_execution: Option<OclobExecutionReceipt<Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaceOrderRequest {
    actor: String,
    side: Side,
    price: u64,
    quantity: u64,
    time_in_force: TimeInForce,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToggleNodeRequest {
    group: String,
    index: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PumpRequest {
    actor: String,
}

impl DemoRuntime {
    fn new(mp_spdz_root: &Path, state_dir: &Path, passphrase: &[u8]) -> Result<Self, String> {
        fs::create_dir_all(state_dir).map_err(|error| error.to_string())?;
        let (eligibility, issuer) =
            deterministic_demo_environment(MARKET).map_err(|error| error.to_string())?;
        let service = OclobService::new(MARKET, mp_spdz_root, eligibility)
            .map_err(|error| error.to_string())?;
        let (maker_handle, taker_handle) = service.demo_participant_handles();
        let maker = participant(
            "maker",
            "売り手企業",
            maker_handle,
            11,
            41,
            b"oclob-demo-maker",
            &issuer,
            state_dir,
            passphrase,
        )?;
        let taker = participant(
            "taker",
            "買い手企業",
            taker_handle,
            22,
            42,
            b"oclob-demo-taker",
            &issuer,
            state_dir,
            passphrase,
        )?;
        // Establish the private portfolio projections before serving requests.
        service
            .participant_portfolio(maker_handle)
            .map_err(|error| error.to_string())?;
        service
            .participant_portfolio(taker_handle)
            .map_err(|error| error.to_string())?;
        let native = native::NativeSettlement::new(state_dir, passphrase)?;
        let mut runtime = Self {
            native,
            views: Arc::new(Mutex::new(BTreeMap::new())),
            service,
            participants: BTreeMap::from([
                (maker.role.to_string(), maker),
                (taker.role.to_string(), taker),
            ]),
            mpc_nodes: [true; 7],
            validators: [true; 5],
            phase: "ready".into(),
            event_sequence: 0,
            events: VecDeque::new(),
            last_execution: None,
        };
        runtime.event(
            "ready",
            "市場を開始",
            "7プロセスMPCと5台のAvalanche検証ノードへ接続しました",
            "ok",
        );
        Ok(runtime)
    }

    fn place_order(&mut self, request: PlaceOrderRequest) -> Result<Value, String> {
        if self.native.progress.lock().map_err(|e| e.to_string())?["stage"] == "failed" {
            return Err("前のネイティブ決済が未確定です。台帳との照合が終わるまで新しい注文は送信できません".into());
        }
        let now = unix_now()?;
        if request.price == 0 || request.quantity == 0 {
            return Err("価格と数量は1以上で指定してください".into());
        }
        let participant = self
            .participants
            .get_mut(&request.actor)
            .ok_or_else(|| "注文者は maker または taker で指定してください".to_string())?;
        participant.next_nonce = participant
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| "注文番号をこれ以上発行できません".to_string())?;
        let nonce = private_digest(
            participant.role.as_bytes(),
            participant.next_nonce,
            b"nonce",
        );
        let salt = private_digest(participant.role.as_bytes(), participant.next_nonce, b"salt");
        let order = SecretOrder::new_with_dekyx_nullifier(
            MARKET,
            request.side,
            request.price,
            request.quantity,
            request.time_in_force,
            now.saturating_add(3_600),
            participant.handle,
            participant.wallet.subject_nullifier(),
            nonce,
            salt,
        )
        .map_err(|error| error.to_string())?;
        let authority =
            authorize_order(&order, now.saturating_add(3_700), &participant.signing_key)
                .map_err(|error| error.to_string())?;
        let evidence = participant
            .wallet
            .present(
                order.commitment().0,
                private_digest(
                    participant.role.as_bytes(),
                    participant.next_nonce,
                    b"challenge",
                ),
                order.expires_at(),
                &mut OsRng,
            )
            .map_err(|error| error.to_string())?;
        let queued = participant
            .queue
            .enqueue(&order, &authority, &evidence, now)
            .map_err(|error| error.to_string())?;
        participant.own_orders.push(OwnOrder {
            request_id: queued.request_id.clone(),
            side: request.side,
            price: request.price,
            quantity: request.quantity,
            time_in_force: request.time_in_force,
            status: "queued".into(),
            submitted_at: now,
        });
        self.phase = "queued".into();
        self.event(
            "order_queued",
            "秘密注文を受付",
            "内容を公開せず、暗号化キューへ保存しました",
            "active",
        );
        let role = request.actor;
        self.publish_views()?;
        let worker = self.pump_role(&role, now)?;
        Ok(json!({ "queued": queued, "worker": worker_projection(&worker) }))
    }

    fn pump_role(&mut self, role: &str, now: u64) -> Result<QueueWorkerResult<Value>, String> {
        if self.native.progress.lock().map_err(|e| e.to_string())?["stage"] == "failed" {
            return Err(
                "前のネイティブ決済が未確定です。台帳との照合が終わるまで再送できません".into(),
            );
        }
        let mpc_healthy = self.mpc_nodes.iter().all(|healthy| *healthy);
        let validators_healthy = self.validators.iter().filter(|healthy| **healthy).count() >= 3;
        if !validators_healthy {
            self.phase = "waiting_for_defmi".into();
            return Ok(QueueWorkerResult::RetryableFailure {
                request_id: "oldest".into(),
                reason: "DeFMI確認ノードの模擬状態が3台未満のため正本更新を開始しません".into(),
            });
        }
        let participant = self
            .participants
            .get(role)
            .ok_or_else(|| "unknown participant".to_string())?;
        let result = participant
            .queue
            .pump_with(now, mpc_healthy, |order, authority, eligibility, now| {
                self.native
                    .execute(role, &mut self.service, order, authority, eligibility, now)
            })
            .map_err(|error| error.to_string())?;
        match &result {
            QueueWorkerResult::WaitingForMpc => {
                self.phase = "waiting_for_mpc".into();
                self.event(
                    "mpc_wait",
                    "MPCの復旧待ち",
                    "注文は暗号化キューに残り、別経路では照合しません",
                    "warn",
                );
            }
            QueueWorkerResult::Executed {
                request_id,
                receipt,
            } => {
                self.mark_order(role, request_id, "finalized");
                self.phase = if receipt.book_transition.fills.is_empty() {
                    "book_updated".into()
                } else {
                    "settled".into()
                };
                let detail = if let Some(fill) = receipt.book_transition.fills.first() {
                    format!(
                        "受付番号{}: {}円 × {}口を追加署名なしでDvP決済しました",
                        receipt.certificate.sequence, fill.price, fill.quantity
                    )
                } else {
                    format!(
                        "受付番号{}: 未約定分を公開板の合計へ反映しました",
                        receipt.certificate.sequence
                    )
                };
                self.event("finalized", "正本更新を確認", &detail, "ok");
                self.last_execution = Some((**receipt).clone());
            }
            QueueWorkerResult::RetryableFailure { .. } => {
                self.phase = "retrying".into();
            }
            QueueWorkerResult::Rejected { request_id, .. }
            | QueueWorkerResult::Expired { request_id } => {
                let uncertain =
                    self.native.progress.lock().map_err(|e| e.to_string())?["stage"] == "failed";
                self.mark_order(
                    role,
                    request_id,
                    if uncertain {
                        "manual_review"
                    } else {
                        "rejected"
                    },
                );
                self.phase = if uncertain {
                    "manual_review"
                } else {
                    "rejected"
                }
                .into();
            }
            QueueWorkerResult::Idle | QueueWorkerResult::DummyCover { .. } => {}
        }
        Ok(result)
    }

    fn pump(&mut self, request: PumpRequest) -> Result<Value, String> {
        let result = self.pump_role(&request.actor, unix_now()?)?;
        Ok(worker_projection(&result))
    }

    fn toggle_node(&mut self, request: ToggleNodeRequest) -> Result<Value, String> {
        let state = match request.group.as_str() {
            "mpc" => self
                .mpc_nodes
                .get_mut(request.index)
                .ok_or_else(|| "MPCノード番号は0から6です".to_string())?,
            "defmi" => self
                .validators
                .get_mut(request.index)
                .ok_or_else(|| "DeFMI確認ノード番号は0から4です".to_string())?,
            _ => return Err("group は mpc または defmi です".into()),
        };
        *state = !*state;
        let online = *state;
        self.event(
            "node_status",
            if online {
                "ノードを再開"
            } else {
                "ノードを停止"
            },
            "停止中は安全条件を満たすまで注文をキューで待機させます",
            if online { "ok" } else { "warn" },
        );
        Ok(json!({ "online": online }))
    }

    fn state(&self, viewer: &str) -> Result<Value, String> {
        let book = self.service.public_book();
        let settlement = self.service.settlement_state();
        let own = if let Some(participant) = self.participants.get(viewer) {
            let portfolio = self
                .service
                .participant_portfolio(participant.handle)
                .map_err(|error| error.to_string())?;
            let queue = participant
                .queue
                .metrics(unix_now()?)
                .map_err(|error| error.to_string())?;
            Some(json!({
                "role": participant.role,
                "display_name": participant.display_name,
                "portfolio": portfolio,
                "orders": participant.own_orders,
                "queue": queue,
            }))
        } else {
            None
        };
        let last = self.last_execution.as_ref().map(|receipt| {
            json!({
                "sequence": receipt.certificate.sequence,
                "order_commitment": receipt.certificate.commitment.hex(),
                "ordering_signers": receipt.certificate.votes.len(),
                "mpc_parties": receipt.mpc.parties,
                "mpc_protocol": receipt.mpc.protocol,
                "mpc_execution_ms": receipt.mpc.execution_ms,
                "transition_attestations": receipt.transition_proof["attestations"].as_array().map(Vec::len).unwrap_or(0),
                "fills": receipt.book_transition.fills,
                "threshold_zkpi": receipt.settlement.as_ref().is_some_and(|value| value.amount_range_is_threshold && value.price_range_is_threshold),
                "settlement_authorization_quorum": receipt.settlement.as_ref().map(|value| value.settlement_authorization_quorum),
                "post_match_signatures": receipt.settlement.as_ref().map(|value| value.post_match_participant_signatures).unwrap_or(0),
                "canonical_receipt": receipt.settlement.as_ref().map(|value| hex::encode(value.canonical_receipt_digest)),
                "canonical_height": receipt.settlement.as_ref().map(|value| value.canonical_height).unwrap_or(receipt.reservation.canonical_height),
            })
        });
        Ok(json!({
            "market": MARKET,
            "assurance_mode":self.native.mode,
            "native_progress":self.native.progress.lock().map_err(|e|e.to_string())?.clone(),
            "phase": self.phase,
            "viewer": viewer,
            "privacy": {
                "operator_projection_contains_pending_order": false,
                "participant_projection_contains_only_own_orders": true,
                "coordinator_receives_plain_order_before_secret_sharing": true,
                "public_book_is_price_level_aggregate": true,
                "post_match_participant_signature_required": false,
                "deployment_mode": "single_process_research_mvp",
                "mpc_topology": "seven_processes_on_one_host",
                "defmi_topology": "five_native_avalanche_validators"
            },
            "book": book,
            "own": own,
            "mpc_nodes": self.mpc_nodes,
            "defmi_validators": self.validators,
            "defmi": {
                "height": settlement.height,
                "securities_root": hex::encode(settlement.securities_root),
                "cash_root": hex::encode(settlement.cash_root),
                "reservation_root": hex::encode(settlement.reservation_root)
            },
            "last_execution": last,
            "events": self.events,
        }))
    }

    fn publish_views(&self) -> Result<(), String> {
        let values = ["operator", "maker", "taker"]
            .into_iter()
            .map(|viewer| Ok((viewer.to_string(), self.state(viewer)?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        *self.views.lock().map_err(|e| e.to_string())? = values;
        Ok(())
    }

    fn mark_order(&mut self, role: &str, request_id: &str, status: &str) {
        if let Some(order) = self.participants.get_mut(role).and_then(|participant| {
            participant
                .own_orders
                .iter_mut()
                .find(|order| order.request_id == request_id)
        }) {
            order.status = status.into();
        }
    }

    fn event(&mut self, kind: &str, title: &str, detail: &str, tone: &'static str) {
        self.event_sequence = self.event_sequence.saturating_add(1);
        self.events.push_front(PublicEvent {
            sequence: self.event_sequence,
            at: unix_now().unwrap_or(0),
            kind: kind.into(),
            title: title.into(),
            detail: detail.into(),
            tone,
        });
        self.events.truncate(EVENT_LIMIT);
    }
}

/// Build the only HTTP-safe view of a queue result. In particular, the full
/// execution receipt contains the DeKYX subject nullifier and reservation
/// records and therefore must never be serialized by the demo HTTP layer.
fn worker_projection(result: &QueueWorkerResult<Value>) -> Value {
    match result {
        QueueWorkerResult::Idle => json!({ "status": "idle" }),
        QueueWorkerResult::WaitingForMpc => json!({ "status": "waiting_for_mpc" }),
        QueueWorkerResult::DummyCover { slot, due_at } => json!({
            "status": "dummy_cover",
            "slot": slot,
            "due_at": due_at,
        }),
        QueueWorkerResult::Expired { request_id } => json!({
            "status": "expired",
            "request_id": request_id,
        }),
        QueueWorkerResult::Executed {
            request_id,
            receipt,
        } => {
            let (canonical_receipt, canonical_height) =
                if let Some(settlement) = &receipt.settlement {
                    (
                        settlement.canonical_receipt_digest,
                        settlement.canonical_height,
                    )
                } else if let Some(release) = &receipt.reservation_release {
                    (release.canonical_receipt_digest, release.canonical_height)
                } else {
                    (
                        receipt.reservation.canonical_receipt_digest,
                        receipt.reservation.canonical_height,
                    )
                };
            json!({
                "status": "executed",
                "request_id": request_id,
                "sequence": receipt.certificate.sequence,
                "fills": receipt.book_transition.fills,
                "arriving_remaining": receipt.book_transition.arriving_remaining,
                "ordering_signers": receipt.certificate.votes.len(),
                "mpc_parties": receipt.mpc.parties,
                "threshold_zkpi": receipt.settlement.as_ref().is_some_and(|settlement| {
                    settlement.amount_range_is_threshold && settlement.price_range_is_threshold
                }),
                "post_match_signatures": receipt.settlement.as_ref().map(|settlement| {
                    settlement.post_match_participant_signatures
                }).unwrap_or(0),
                "canonical_receipt": hex::encode(canonical_receipt),
                "canonical_height": canonical_height,
            })
        }
        QueueWorkerResult::RetryableFailure { request_id, reason } => json!({
            "status": "retryable_failure",
            "request_id": request_id,
            "reason": reason,
        }),
        QueueWorkerResult::Rejected { request_id, reason } => json!({
            "status": "rejected",
            "request_id": request_id,
            "reason": reason,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn participant(
    role: &'static str,
    display_name: &'static str,
    handle: Digest32,
    subject_seed: u64,
    signing_seed: u8,
    credential_label: &[u8],
    issuer: &DemoEligibilityIssuer,
    state_dir: &Path,
    passphrase: &[u8],
) -> Result<Participant, String> {
    let wallet = issuer
        .issue_wallet(subject_seed, credential_label, &mut OsRng)
        .map_err(|error| error.to_string())?;
    let queue = DurableOclobQueue::open(
        state_dir.join(format!("{role}-outbox.bin")),
        passphrase,
        "defmi-avalanche-demo",
        1_024,
        2,
    )
    .map_err(|error| error.to_string())?;
    Ok(Participant {
        role,
        display_name,
        handle,
        signing_key: SigningKey::from_bytes(&[signing_seed; 64]),
        wallet,
        queue,
        next_nonce: 0,
        own_orders: Vec::new(),
    })
}

fn private_digest(role: &[u8], sequence: u64, purpose: &[u8]) -> Digest32 {
    Sha256::new()
        .chain_update(b"OCLOB:DEMO:PRIVATE-CONTROL:v1")
        .chain_update((role.len() as u64).to_be_bytes())
        .chain_update(role)
        .chain_update(sequence.to_be_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into()
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn serve(host: &str, port: u16, runtime: DemoRuntime) -> Result<(), String> {
    let listener = TcpListener::bind((host, port)).map_err(|error| error.to_string())?;
    runtime.publish_views()?;
    let views = runtime.views.clone();
    let progress = runtime.native.progress.clone();
    let private_progress = runtime.native.private_progress.clone();
    let clients = runtime.native.clients.clone();
    let runtime = Arc::new(Mutex::new(runtime));
    println!("OCLOB demo listening on http://{host}:{port}");
    for connection in listener.incoming() {
        let runtime = Arc::clone(&runtime);
        let (views, progress, clients, private_progress) = (
            views.clone(),
            progress.clone(),
            clients.clone(),
            private_progress.clone(),
        );
        match connection {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) = handle_connection(
                        stream,
                        &runtime,
                        &views,
                        &progress,
                        &clients,
                        &private_progress,
                    ) {
                        eprintln!("OCLOB HTTP request rejected: {error}");
                    }
                });
            }
            Err(error) => eprintln!("OCLOB HTTP accept error: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    runtime: &Arc<Mutex<DemoRuntime>>,
    views: &Arc<Mutex<BTreeMap<String, Value>>>,
    progress: &Arc<Mutex<Value>>,
    clients: &Arc<Vec<defmi::avalanche::AvalancheRpcClient>>,
    private_progress: &Arc<Mutex<BTreeMap<String, Value>>>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .map_err(|error| error.to_string())?;
    let request = read_http_request(&mut stream)?;
    let (path, query) = request
        .target
        .split_once('?')
        .map_or((request.target.as_str(), ""), |parts| parts);
    let response = match (request.method.as_str(), path) {
        ("GET", "/health") => json_response("200 OK", &json!({ "status": "ok" }))?,
        ("GET", "/api/state") => {
            let viewer = query_value(query, "viewer").unwrap_or("operator");
            let mut state = views
                .lock()
                .map_err(|e| e.to_string())?
                .get(viewer)
                .cloned()
                .ok_or("unknown viewer")?;
            state["native_progress"] = progress.lock().map_err(|e| e.to_string())?.clone();
            if state["native_progress"]["active"] == true {
                if let Some(value) = private_progress
                    .lock()
                    .map_err(|e| e.to_string())?
                    .get(viewer)
                    .cloned()
                {
                    state["provisional"] = value;
                }
            }
            json_response("200 OK", &state)?
        }
        ("POST", "/api/assurance") => {
            let value: Value = serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
            let result = (|| -> Result<Value, String> {
                let mut state = runtime
                    .try_lock()
                    .map_err(|_| "wait for the active settlement")?;
                for participant in state.participants.values() {
                    let metrics = participant
                        .queue
                        .metrics(unix_now()?)
                        .map_err(|e| e.to_string())?;
                    if metrics.queued
                        + metrics.dispatching
                        + metrics.mpc_admitted
                        + metrics.release_pending
                        + metrics.manual_review
                        > 0
                    {
                        return Err("finish queued orders before changing assurance".into());
                    }
                }
                state
                    .native
                    .set_mode(value["mode"].as_str().ok_or("mode required")?)?;
                state.publish_views()?;
                Ok(json!({"mode":state.native.mode}))
            })();
            result_response(result)?
        }
        ("POST", "/api/challenge") => {
            let value: Value = serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
            let result = (|| -> Result<Value, String> {
                use zkpi_committee::optimistic::Challenge;
                let id = value["claim_id"].as_str().ok_or("claim ID required")?;
                let current = progress.lock().map_err(|e| e.to_string())?.clone();
                if current["active"] != true || current["claim_id"] != id {
                    return Err("only the active claim can be challenged".into());
                }
                let claim = hex::decode(id)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "invalid claim ID")?;
                let client = zkpi_defmi_sdk::optimistic::OptimisticClient { rpc: &clients[0] };
                let key = zkpi_committee::application_crypto::SigningKey::from_bytes(&[91; 64]);
                let receipt = client.challenge(&Challenge::signed(claim, &key)?)?;
                Ok(
                    json!({"claim_id":id,"tx_id":receipt.tx_id,"height":receipt.height,"after_root":hex::encode(receipt.after_root)}),
                )
            })();
            result_response(result)?
        }
        ("POST", "/api/order") => {
            let request: PlaceOrderRequest = serde_json::from_slice(&request.body)
                .map_err(|_| "order request is malformed".to_string())?;
            let result = (|| -> Result<Value, String> {
                let mut runtime = runtime
                    .try_lock()
                    .map_err(|_| "a settlement is already running")?;
                let result = runtime.place_order(request);
                runtime.publish_views()?;
                result
            })();
            result_response(result)?
        }
        ("POST", "/api/nodes/toggle") => {
            let request: ToggleNodeRequest = serde_json::from_slice(&request.body)
                .map_err(|_| "node request is malformed".to_string())?;
            let result = (|| -> Result<Value, String> {
                let mut runtime = runtime
                    .try_lock()
                    .map_err(|_| "a settlement is already running")?;
                let result = runtime.toggle_node(request);
                runtime.publish_views()?;
                result
            })();
            result_response(result)?
        }
        ("POST", "/api/queue/pump") => {
            let request: PumpRequest = serde_json::from_slice(&request.body)
                .map_err(|_| "queue request is malformed".to_string())?;
            let result = (|| -> Result<Value, String> {
                let mut runtime = runtime
                    .try_lock()
                    .map_err(|_| "a settlement is already running")?;
                let result = runtime.pump(request);
                runtime.publish_views()?;
                result
            })();
            result_response(result)?
        }
        ("GET", "/" | "/index.html") => static_response(
            "200 OK",
            include_bytes!("../../../oclob_demo/static/index.html"),
            "text/html; charset=utf-8",
        ),
        ("GET", "/app.css") => static_response(
            "200 OK",
            include_bytes!("../../../oclob_demo/static/app.css"),
            "text/css; charset=utf-8",
        ),
        ("GET", "/app.js") => static_response(
            "200 OK",
            include_bytes!("../../../oclob_demo/static/app.js"),
            "application/javascript; charset=utf-8",
        ),
        ("GET", "/react-flow.css") => static_response(
            "200 OK",
            include_bytes!("../../../oclob_demo/static/react-flow.css"),
            "text/css; charset=utf-8",
        ),
        ("GET", "/react-flow.js") => static_response(
            "200 OK",
            include_bytes!("../../../oclob_demo/static/react-flow.js"),
            "application/javascript; charset=utf-8",
        ),
        _ => static_response("404 Not Found", b"not found", "text/plain; charset=utf-8"),
    };
    stream
        .write_all(&response)
        .map_err(|error| error.to_string())?;
    Ok(())
}

struct HttpRequest {
    method: String,
    target: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8_192];
    let header_end = loop {
        let read = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("HTTP request ended before its headers".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_HTTP_BYTES {
            return Err("HTTP request exceeds one MiB".into());
        }
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "HTTP headers are not UTF-8".to_string())?;
    let mut lines = headers.split("\r\n");
    let first = lines
        .next()
        .ok_or_else(|| "HTTP request line is absent".to_string())?;
    let mut parts = first.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "HTTP method is absent".to_string())?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| "HTTP target is absent".to_string())?
        .to_string();
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err("only strict HTTP/1.1 requests are accepted".into());
    }
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|_| "Content-Length is invalid".to_string())?
        .unwrap_or(0);
    if header_end.saturating_add(content_length) > MAX_HTTP_BYTES {
        return Err("HTTP request exceeds one MiB".into());
    }
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("HTTP body ended early".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(HttpRequest {
        method,
        target,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn query_value<'a>(query: &'a str, wanted: &str) -> Option<&'a str> {
    query.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == wanted).then_some(value)
    })
}

fn result_response(result: Result<Value, String>) -> Result<Vec<u8>, String> {
    match result {
        Ok(value) => json_response("200 OK", &json!({ "ok": true, "data": value })),
        Err(error) => json_response("400 Bad Request", &json!({ "ok": false, "error": error })),
    }
}

fn json_response(status: &str, value: &Value) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(static_response(
        status,
        &body,
        "application/json; charset=utf-8",
    ))
}

fn static_response(status: &str, body: &[u8], content_type: &str) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_projection_has_no_private_order_fields() {
        let source = include_str!("server.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source exists");
        let operator = production_source
            .split("fn state(&self, viewer: &str)")
            .nth(1)
            .expect("state projection exists");
        assert!(operator.contains("own = if let Some(participant)"));
        assert!(operator.contains("else {\n            None"));
        assert!(!production_source.contains("serde_json::to_value(result)"));
        assert!(
            production_source.contains("fn worker_projection(result: &QueueWorkerResult<Value>)")
        );
    }

    #[test]
    fn http_parser_rejects_oversized_lengths_without_allocating_them() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .write_all(
                    format!(
                        "POST /api/order HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                        MAX_HTTP_BYTES + 1
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        let error = match read_http_request(&mut stream) {
            Err(error) => error,
            Ok(_) => panic!("oversized HTTP request was accepted"),
        };
        sender.join().unwrap();
        assert_eq!(error, "HTTP request exceeds one MiB");
    }
}
