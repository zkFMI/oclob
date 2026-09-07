(() => {
  'use strict';

  const state = { viewer: 'operator', snapshot: null, busy: false, offline: false, failures: 0 };
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const number = (value) => new Intl.NumberFormat('ja-JP').format(value ?? 0);
  const yen = (value) => `${number(value)} 円`;
  const lots = (value) => `${number(value)} 口`;
  const clock = (seconds) => seconds ? new Date(seconds * 1000).toLocaleTimeString('ja-JP', { hour12: false }) : '';

  // Server phases, in the words a person at the desk would use. "Queued" is a
  // holding state: the order is stored, not admitted, matched or settled.
  const phases = {
    ready: { label: '注文を受け付けています', note: '新しい注文を出せます。', tone: 'ok' },
    queued: { label: '注文を暗号化して保管中', note: 'まだ成立していません。順番が来たら秘密計算へ進みます。', tone: 'active' },
    waiting_for_mpc: { label: '計算ノードの復旧待ち', note: '注文は暗号化したまま保管しています。成立はしていません。', tone: 'warn' },
    waiting_for_defmi: { label: 'DeFMI 台帳の復旧待ち', note: '注文は保管したままです。台帳が戻れば同じ順番で続けます。', tone: 'warn' },
    retrying: { label: '同じ受付順で再送しています', note: '順番は変わりません。', tone: 'active' },
    // No fill happened. Whether the rest stayed on the book or was cancelled
    // (IOC) is not in this state, so only the certain facts are stated.
    book_updated: { label: '公開板を更新しました', note: '約定はありませんでした。板の内容を更新しました。', tone: 'ok' },
    settled: { label: '約定し、決済が完了しました', note: '証券と資金を同時に引き渡しました。', tone: 'ok' },
    rejected: { label: '注文を受け付けませんでした', note: '資金や在庫が足りないなど、条件を満たしていません。', tone: 'bad' },
  };
  const phaseInfo = (phase) => phases[phase] || { label: phase, note: '', tone: 'active' };

  const orderStatuses = {
    queued: ['保管中（未成立）', 'pending'],
    dispatching: ['秘密計算へ送信中', 'pending'],
    mpc_admitted: ['秘密計算に受理', 'pending'],
    finalized: ['処理完了（板または決済に反映）', 'done'],
    settled: ['決済完了', 'done'],
    released: ['確保分を解放', 'done'],
    rejected: ['受け付けられませんでした', 'bad'],
    expired: ['期限切れで取り消し', 'bad'],
    manual_review: ['確認が必要', 'warn'],
  };
  const orderStatus = (status) => orderStatuses[status] || [status, 'pending'];

  // The server's queue counter "settled" means the queue item completed through
  // the ledger (a resting order counts too), so it is not called 決済 here.
  const queueLabels = {
    queued: '保管中', dispatching: '送信中', mpc_admitted: '計算に受理', settled: '処理完了',
    released: '確保分を解放', release_pending: '解放待ち', expired: '期限切れ',
    manual_review: '要確認', aborted_before_reserve: '確保前に中止',
  };

  const roleHints = {
    operator: '市場運営者の画面です。公開板と処理の進み方だけが見え、どの企業の注文かは見えません。',
    maker: '売り手企業（Maker）の画面です。板に気配を出して取引相手になる側の例で、このデモでは売り・買いどちらの注文も出せます。自社の資金・在庫・注文が見えます。',
    taker: '買い手企業（Taker）の画面です。板の気配に対して注文を出す側の例で、売り・買いどちらの注文も出せます。自社の資金・在庫・注文が見えます。',
  };

  // Timeline entries arrive from the server with implementation wording
  // ("正本", "暗号化キュー", "DvP"). Rewrite the known kinds into plain
  // Japanese here; the raw server text stays available under 技術的な詳細.
  function eventText(event) {
    const detail = event.detail || '';
    switch (event.kind) {
      case 'ready':
        return ['市場を開始しました', '研究用の構成（計算プロセス 7 つ・台帳の確認ノード 5 つ）を用意しました。'];
      case 'order_queued':
        return ['注文を受け付けて保管', '中身を公開せずに暗号化して保管しました。まだ成立していません。'];
      case 'mpc_wait':
        return ['計算ノードの復旧待ち', '注文は保管したままです。別の経路で照合することはありません。'];
      case 'finalized': {
        const fill = /受付番号(\d+): (\d+)円 × (\d+)口/.exec(detail);
        if (fill) return ['約定し、決済しました', `受付番号 ${fill[1]}：${number(Number(fill[2]))} 円 × ${number(Number(fill[3]))} 口。証券と資金を同時に引き渡しました。企業の追加署名はありません。`];
        const rest = /受付番号(\d+): 未約定分/.exec(detail);
        if (rest) return ['板を更新しました', `受付番号 ${rest[1]}：約定はなく、公開板の合計を更新しました。`];
        return ['台帳を更新しました', detail];
      }
      case 'node_status': {
        const resumed = (event.title || '').includes('再開');
        return resumed
          ? ['ノードの停止模擬を解除', '表示上の停止を解除しました。']
          : ['ノードの停止を模擬', '停止中は、安全な数がそろうまで注文を保管して待機します（表示だけの模擬）。'];
      }
      default:
        return [event.title, detail];
    }
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    });
    let payload;
    try { payload = await response.json(); } catch (error) { throw new Error('サーバーの応答を読み取れませんでした'); }
    if (!response.ok || payload.ok === false) throw new Error(payload.error || '処理に失敗しました');
    return payload.data ?? payload;
  }

  function toast(message, error = false) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.toggle('error', error);
    element.classList.add('show');
    window.clearTimeout(toast.timer);
    toast.timer = window.setTimeout(() => element.classList.remove('show'), 4200);
  }

  function setConnection(online, detail) {
    const banner = $('#connection-banner');
    state.offline = !online;
    banner.classList.toggle('hidden', online);
    document.body.classList.toggle('offline', !online);
    if (!online) {
      banner.textContent = `サーバーに接続できません（${detail}）。表示は最後に取得した内容です。数秒ごとに再接続します。`;
      $('#phase-label').textContent = '接続できません';
      $('#status-dot').className = 'status-dot bad';
    }
  }

  async function refresh() {
    try {
      state.snapshot = await api(`/api/state?viewer=${encodeURIComponent(state.viewer)}`);
      state.failures = 0;
      setConnection(true);
      render();
    } catch (error) {
      state.failures += 1;
      if (state.failures >= 2 || !state.snapshot) setConnection(false, error.message);
      if (!state.snapshot) renderEmpty();
    }
  }

  function renderEmpty() {
    $('#summary-phase').textContent = '接続できません';
    $('#summary-phase-note').textContent = 'サーバーが応答したら自動で表示します。';
    $('#empty-book').textContent = 'サーバーに接続できないため、板を表示できません。';
    $('#timeline').replaceChildren(item('li', 'loading', 'サーバーに接続できないため、履歴を表示できません。'));
  }

  function render() {
    const data = state.snapshot;
    if (!data) return;
    const info = phaseInfo(data.phase);
    $('#market-label').textContent = data.market;
    $('#phase-label').textContent = info.label;
    $('#status-dot').className = `status-dot ${info.tone}`;
    document.body.className = `viewer-${state.viewer}${state.offline ? ' offline' : ''}`;
    renderSummary(data, info);
    renderRole(data);
    renderPortfolio(data.own);
    renderOrders(data.own);
    renderNodes(data);
    renderBook(data);
    renderTimeline(data.events);
    renderDiagnostics(data);
    renderReceipt(data.last_execution);
    renderGraph(data);
  }

  function renderSummary(data, info) {
    $('#summary-phase').textContent = info.label;
    $('#summary-phase-note').textContent = info.note;
    $('#summary-book').textContent = `${number(data.book.sequence)} 回`;
    const levels = data.book.levels.length;
    $('#summary-book-note').textContent = levels ? `${levels} つの価格帯に注文が残っています。` : '板に残っている注文はありません。';
    const last = data.last_execution;
    const fills = last?.fills?.length ? last.fills.reduce((sum, fill) => sum + fill.quantity, 0) : 0;
    if (last && fills) {
      $('#summary-settlement').textContent = `${number(fills)} 口が約定`;
      $('#summary-settlement-note').textContent = `${last.fills.map((fill) => `${number(fill.price)} 円`).join('・')}。証券と資金を同時に引き渡し済み。`;
    } else if (last) {
      $('#summary-settlement').textContent = '約定なし';
      $('#summary-settlement-note').textContent = '最後の注文では約定がなく、板の内容を更新しました。';
    } else {
      $('#summary-settlement').textContent = '—';
      $('#summary-settlement-note').textContent = 'まだ決済はありません。';
    }
    const mpcUp = data.mpc_nodes.filter(Boolean).length;
    const valUp = data.defmi_validators.filter(Boolean).length;
    $('#summary-nodes').textContent = `計算 ${mpcUp}/${data.mpc_nodes.length}・台帳 ${valUp}/${data.defmi_validators.length}`;
    const degraded = mpcUp < data.mpc_nodes.length || valUp < data.defmi_validators.length;
    $('#summary-nodes-note').textContent = degraded
      ? '一部のノードを停止として模擬しています。安全な数を割ると処理は待機します。'
      : 'すべて利用できます（研究用の1台構成）。';
  }

  function renderRole(data) {
    const privateView = Boolean(data.own);
    $('#portfolio-panel').classList.toggle('hidden', !privateView);
    $('#order-panel').classList.toggle('hidden', !privateView);
    $('#orders-panel').classList.toggle('hidden', !privateView);
    $('#role-hint').textContent = roleHints[state.viewer] || '';
    $('#projection-badge').textContent = privateView ? '自社の表示' : '運営者の表示';
    $('#projection-badge').classList.toggle('own', privateView);
    const list = $('#visibility-list');
    list.replaceChildren();
    const rows = privateView ? [
      ['yes', '自社の資金・在庫と、自社が出した注文の状況'],
      ['yes', '確定した価格ごとの合計数量（公開板）'],
      ['no', '他社の注文の中身や残高'],
      ['no', '受付待ちの注文の中身は、運営者向けの表示には含まれません（出した企業の画面には表示されます）'],
    ] : [
      ['yes', '確定した価格ごとの合計数量（公開板）'],
      ['yes', '処理の進み方と決済の結果'],
      ['no', '受付待ちの注文の中身（価格・数量・売買）。出した企業の画面にだけ表示されます'],
      ['no', 'どの企業がいくら持っているか'],
    ];
    rows.forEach(([cls, text]) => list.append(item('li', cls, text)));
    if (privateView) {
      $('#order-eyebrow').textContent = `${data.own.display_name}として注文を出す`;
      const side = data.own.role === 'maker' ? 'sell' : 'buy';
      const radio = document.querySelector(`input[name="side"][value="${side}"]`);
      if (radio && !state.busy && !state.sideTouched) radio.checked = true;
      renderOrderPreview();
    }
  }

  function renderPortfolio(own) {
    const root = $('#portfolio-cards');
    root.replaceChildren();
    if (!own) return;
    const p = own.portfolio;
    const cards = [
      ['資金', '使える額', yen(p.available_cash), [['確保中', yen(p.reserved_cash)], ['合計', yen(p.cash)]]],
      ['在庫', '使える数量', lots(p.available_securities), [['確保中', lots(p.reserved_securities)], ['合計', lots(p.securities)]]],
    ];
    cards.forEach(([title, label, value, rows]) => {
      const card = item('div', 'portfolio-card');
      card.append(item('span', 'card-title', title), item('span', 'card-label', label), item('strong', '', value));
      const dl = item('dl', 'card-rows');
      rows.forEach(([k, v]) => { const row = item('div'); row.append(item('dt', '', k), item('dd', '', v)); dl.append(row); });
      card.append(dl);
      root.append(card);
    });
  }

  function renderOrders(own) {
    if (!own) return;
    const orders = [...(own.orders || [])].sort((a, b) => (b.submitted_at || 0) - (a.submitted_at || 0));
    $('#orders-count').textContent = `${orders.length} 件`;
    const root = $('#own-orders');
    root.replaceChildren();
    $('#own-orders-empty').classList.toggle('hidden', orders.length > 0);
    orders.slice(0, 8).forEach((order) => {
      const [label, tone] = orderStatus(order.status);
      const row = item('div', `own-order ${tone}`);
      const head = item('div', 'own-order-head');
      head.append(item('strong', '', `${order.side === 'sell' ? '売り' : '買い'} ${number(order.quantity)} 口 @ ${number(order.price)} 円`), item('span', `order-status ${tone}`, label));
      const meta = item('small', '', [
        clock(order.submitted_at),
        order.time_in_force === 'immediate_or_cancel' ? '残りは取り消し' : '板に残す',
      ].filter(Boolean).join(' ・ '));
      row.append(head, meta);
      root.append(row);
    });
    const q = own.queue || {};
    const summary = $('#queue-summary');
    summary.replaceChildren();
    const chips = Object.entries(queueLabels)
      .filter(([key]) => key === 'queued' || (q[key] || 0) > 0)
      .map(([key, label]) => item('span', `queue-chip ${key === 'queued' && q.queued ? 'pending' : ''}`, `${label} ${number(q[key] || 0)}`));
    if (q.oldest_unfinalized_age_seconds != null) chips.push(item('span', 'queue-chip warn', `未確定の最長待ち ${q.oldest_unfinalized_age_seconds} 秒`));
    chips.forEach((chip) => summary.append(chip));
    const waiting = (q.queued || 0) + (q.dispatching || 0);
    $('#retry-queue').classList.toggle('hidden', waiting === 0);
  }

  function renderNodes(data) {
    nodeButtons($('#mpc-controls'), 'mpc', data.mpc_nodes, '計算ノード');
    nodeButtons($('#defmi-controls'), 'defmi', data.defmi_validators, '台帳の確認ノード');
  }

  function nodeButtons(root, group, values, groupLabel) {
    root.replaceChildren();
    values.forEach((online, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = online ? '' : 'off';
      button.textContent = String(index + 1);
      button.title = `${groupLabel} ${index + 1}：${online ? '利用できます' : '停止を模擬中'}。押すと表示上の状態を切り替えます。`;
      button.setAttribute('aria-label', button.title);
      button.setAttribute('aria-pressed', String(!online));
      button.addEventListener('click', () => toggleNode(group, index));
      root.append(button);
    });
  }

  function renderBook(data) {
    const book = data.book;
    $('#book-sequence').textContent = `更新 ${number(book.sequence)} 回`;
    $('#book-market').textContent = data.market;
    const root = $('#book-levels'); root.replaceChildren();
    const maximum = Math.max(1, ...book.levels.map((level) => level.quantity));
    [...book.levels]
      .sort((a, b) => a.side === b.side ? (a.side === 'sell' ? b.price - a.price : b.price - a.price) : (a.side === 'sell' ? -1 : 1))
      .forEach((level) => {
        const row = item('div', `book-row ${level.side}`);
        row.style.setProperty('--depth', `${Math.max(8, level.quantity / maximum * 100)}%`);
        row.append(item('span', '', level.side === 'sell' ? '売り' : '買い'), item('span', '', number(level.price)), item('span', '', number(level.quantity)));
        root.append(row);
      });
    const empty = $('#empty-book');
    empty.classList.toggle('hidden', book.levels.length > 0);
    empty.textContent = '板に残っている注文はまだありません。';
  }

  function renderTimeline(events) {
    const root = $('#timeline'); root.replaceChildren();
    if (!events.length) { root.append(item('li', 'loading', 'まだ記録はありません。')); return; }
    events.slice(0, 12).forEach((event) => {
      const [title, detail] = eventText(event);
      const li = item('li', event.tone);
      li.title = `サーバーの原文：${event.title} — ${event.detail}`;
      const head = item('div', 'timeline-head');
      head.append(item('strong', '', title), item('time', '', clock(event.at)));
      li.append(head, item('p', '', detail));
      root.append(li);
    });
    const raw = $('#raw-timeline');
    if (raw) {
      raw.replaceChildren();
      events.slice(0, 12).forEach((event) => raw.append(item('li', '', `${clock(event.at)} [${event.kind}] ${event.title} — ${event.detail}`)));
    }
  }

  function renderDiagnostics(data) {
    $('#defmi-height').textContent = `更新 ${number(data.defmi.height)} 回`;
    const roots = $('#root-values'); roots.replaceChildren();
    [['証券残高の識別値', data.defmi.securities_root], ['資金残高の識別値', data.defmi.cash_root], ['確保枠の識別値', data.defmi.reservation_root]]
      .forEach(([label, value]) => roots.append(pair(label, value, true)));

    const exec = $('#execution-values'); exec.replaceChildren();
    const last = data.last_execution;
    if (!last) { exec.append(pair('状態', 'まだ処理はありません')); }
    else {
      [
        ['受付番号', `#${last.sequence}`],
        ['受付順の署名', `${last.ordering_signers} 台（模擬ノード）`],
        ['秘密計算', `${last.mpc_parties} プロセス・${Math.round(last.mpc_execution_ms)} ミリ秒（${last.mpc_protocol}）`],
        ['約定', last.fills?.length ? last.fills.map((fill) => `${number(fill.quantity)} 口 @ ${number(fill.price)} 円`).join('、') : 'なし'],
        ['決済の証明（zkPI）', last.threshold_zkpi ? `作成済み・承認 ${last.settlement_authorization_quorum} 台` : '作成なし（板の更新のみ）'],
        ['台帳への反映', `${last.transition_attestations} 台が確認・更新 ${number(last.canonical_height)} 回目`],
        ['約定後に企業が署名した回数', String(last.post_match_signatures ?? 0)],
        ['注文の識別値', last.order_commitment, true],
        ['台帳の受付記録', last.canonical_receipt, true],
      ].forEach(([label, value, mono]) => exec.append(pair(label, value, mono)));
    }

    const facts = $('#privacy-facts'); facts.replaceChildren();
    const p = data.privacy || {};
    const factRows = [
      ['この環境は研究用で、すべての処理が 1 台のサーバーの中で動いています。', p.deployment_mode === 'single_process_research_mvp'],
      ['秘密計算を担う 7 つのプロセスは同じサーバー上にあり、独立した 7 社の運用ではありません。', p.mpc_topology === 'seven_processes_on_one_host'],
      ['DeFMI 台帳は同じプロセス内の研究用の状態機械で、外部のブロックチェーンの合意ではありません。', p.defmi_topology === 'in_process_state_machine'],
      ['注文は現在、サーバーが受け取ってから暗号化して分割しています。企業側で分割する方式は本番化前の必須項目です。', p.coordinator_receives_plain_order_before_secret_sharing],
      ['運営者向けの表示には受付待ちの注文の中身を含めません。', p.operator_projection_contains_pending_order === false],
      ['企業向けの表示には、その企業自身の注文だけを含めます。', p.participant_projection_contains_only_own_orders],
      ['公開板は価格ごとの合計数量だけです。', p.public_book_is_price_level_aggregate],
      ['約定後に企業が追加で署名する必要はありません。', p.post_match_participant_signature_required === false],
    ];
    factRows.filter(([, show]) => show).forEach(([text]) => facts.append(item('li', '', text)));
  }

  function renderReceipt(receipt) {
    const root = $('#receipt-steps'); root.replaceChildren();
    const fills = receipt?.fills?.length || 0;
    const steps = receipt ? [
      ['受付', `受付番号 #${receipt.sequence}`, true],
      ['秘密計算で照合', `${receipt.mpc_parties} プロセスで ${Math.round(receipt.mpc_execution_ms)} ミリ秒`, true],
      ['決済の証明（zkPI）', receipt.threshold_zkpi ? '作成済み' : '不要（約定なし）', receipt.threshold_zkpi],
      ['DeFMI 台帳', fills ? `決済を反映（${number(receipt.canonical_height)} 回目の更新）` : `板を反映（${number(receipt.canonical_height)} 回目の更新）`, true],
    ] : [
      ['受付', 'まだ注文はありません', false], ['秘密計算で照合', '—', false], ['決済の証明（zkPI）', '—', false], ['DeFMI 台帳', '—', false],
    ];
    steps.forEach(([label, value, done]) => {
      const step = item('div', `receipt-step${done ? ' done' : ''}`);
      step.append(item('span', '', label), item('strong', '', value));
      root.append(step);
    });
  }

  function renderOrderPreview() {
    const form = $('#order-form');
    if (!form || !state.snapshot?.own) return;
    const data = new FormData(form);
    const side = data.get('side');
    const price = Number(data.get('price')) || 0;
    const quantity = Number(data.get('quantity')) || 0;
    const preview = $('#order-preview');
    if (!price || !quantity) { preview.textContent = ''; return; }
    // The amount is what the displayed limit × full quantity would come to. A
    // fill can be partial or at a better price, so it is not a promised receipt.
    preview.textContent = side === 'sell'
      ? `送信時に在庫 ${number(quantity)} 口を確保します。表示の指値 ${number(price)} 円 × ${number(quantity)} 口がすべて成立した場合の受取額は ${number(price * quantity)} 円です。一部だけ、または指値より有利な価格で成立することがあります。`
      : `送信時に資金 ${number(price * quantity)} 円（指値 ${number(price)} 円 × ${number(quantity)} 口）を確保します。すべて成立した場合に ${number(quantity)} 口を受け取ります。一部だけ、または指値より有利な価格で成立することがあります。`;
  }

  // ---- graph -------------------------------------------------------------

  function renderGraph(data) {
    if (!window.OclobNetworkGraph) return;
    const phase = data.phase;
    const inFlight = ['queued', 'waiting_for_mpc', 'waiting_for_defmi', 'retrying'].includes(phase);
    const hasResult = Boolean(data.last_execution);
    const settled = Boolean(data.last_execution?.fills?.length);
    const narrow = $('#network-graph').clientWidth < 560;
    const ctx = { data, phase, inFlight, hasResult, settled, viewer: state.viewer };
    const model = narrow ? narrowGraph(ctx) : wideGraph(ctx);
    const anyOff = data.mpc_nodes.some((on) => !on) || data.defmi_validators.some((on) => !on);
    const notes = [
      '線は注文がたどる経路です。通信の実況や生存監視ではありません。',
      '研究用の 1 台構成：計算プロセス 7 つと台帳の確認ノード 5 つは同じサーバー内で動いています。',
    ];
    if (anyOff) notes.push('赤い破線は、障害の模擬で停止扱いにしたノードです。');
    window.OclobNetworkGraph.render($('#network-graph'), model, {
      ariaLabel: 'OCLOBの参加企業、受付、秘密計算、決済の証明、DeFMI台帳を結ぶ処理の流れ',
      phase, phaseLabel: phaseInfo(phase).label, noRoundText: '',
      legend: [
        { type: 'maker', label: '参加企業' }, { type: 'matcher', label: '受付・秘密計算' },
        { type: 'zkpi', label: '決済の証明' }, { type: 'ledger', label: 'DeFMI 台帳' },
      ],
      legendNotes: notes,
      reducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    });
  }

  function participantNodes(ctx, makerPos, takerPos, w, h) {
    const { data, viewer } = ctx;
    const mine = (role) => data.own?.role === role;
    return [
      graphNode('maker', 'maker', makerPos[0], makerPos[1], w, h, '売り手企業', viewer === 'maker' ? '自社の注文と在庫を表示中' : '注文の中身は非公開', mine('maker') ? '表示中' : '', mine('maker') ? ['is-me'] : []),
      graphNode('taker', 'taker', takerPos[0], takerPos[1], w, h, '買い手企業', viewer === 'taker' ? '自社の注文と資金を表示中' : '注文の中身は非公開', mine('taker') ? '表示中' : '', mine('taker') ? ['is-me'] : []),
    ];
  }

  function coreNodes(ctx, pos) {
    const { data, phase, hasResult } = ctx;
    const active = (names) => names.includes(phase);
    const mpcUp = data.mpc_nodes.filter(Boolean).length;
    return [
      graphNode('ordering', 'matcher', ...pos.ordering, '受付順を決める', '5 台の署名で順番を固定（模擬ノード）', `次は #${data.book.sequence + 1}`, active(['queued']) ? ['is-active'] : []),
      graphNode('mpc', 'matcher', ...pos.mpc, '秘密計算で照合', '注文を開かずに 7 プロセスで照合', `${mpcUp}/7 利用可`, active(['waiting_for_mpc', 'retrying']) ? ['is-active'] : mpcUp < 5 ? ['is-stopped'] : []),
      graphNode('zkpi', 'zkpi', ...pos.zkpi, '決済の証明（zkPI）', '約定と確保枠が正しいことを証明', hasResult ? (data.last_execution.threshold_zkpi ? '作成済み' : '今回は不要') : '待機中', active(['settled']) ? ['is-active'] : []),
      graphNode('defmi', 'ledger', ...pos.defmi, 'DeFMI 台帳', '証券と資金を同時に引き渡し', `更新 ${data.defmi.height} 回`, active(['settled', 'waiting_for_defmi']) ? ['is-active'] : []),
    ];
  }

  function flowEdges(ctx, paths) {
    const { inFlight, hasResult, settled, phase } = ctx;
    const orderState = inFlight ? 'flow' : hasResult ? 'done' : 'idle';
    const mpcState = phase === 'queued' || phase === 'retrying' ? 'flow' : hasResult ? 'done' : 'idle';
    const settleState = settled ? 'done' : 'idle';
    return [
      edge('maker-order', 'maker', 'ordering', paths.makerOrder, orderState, 'teal'),
      edge('taker-order', 'taker', 'ordering', paths.takerOrder, orderState, 'teal'),
      edge('ordered-mpc', 'ordering', 'mpc', paths.orderedMpc, mpcState, 'amber'),
      edge('mpc-zkpi', 'mpc', 'zkpi', paths.mpcZkpi, settleState, 'amber'),
      edge('zkpi-defmi', 'zkpi', 'defmi', paths.zkpiDefmi, settleState, 'blue'),
    ];
  }

  function wideGraph(ctx) {
    const { data } = ctx;
    const nodes = [
      ...participantNodes(ctx, [100, 150], [100, 400], 156, 96),
      ...coreNodes(ctx, { ordering: [300, 275, 142, 104], mpc: [512, 275, 156, 110], zkpi: [720, 175, 150, 96], defmi: [720, 385, 150, 104] }),
    ];
    const mpcPositions = [[440, 68], [488, 68], [536, 68], [584, 68], [464, 482], [512, 482], [560, 482]];
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      nodes.push(graphNode(`mpc-${index}`, 'matcher', x, y, 42, 40, `M${index + 1}`, '', '', online ? ['is-mini'] : ['is-mini', 'is-stopped']));
    });
    data.defmi_validators.forEach((online, index) => nodes.push(graphNode(`val-${index}`, 'ledger', 648 + index * 36, 545, 32, 36, `D${index + 1}`, '', '', online ? ['is-mini'] : ['is-mini', 'is-stopped'])));
    const edges = flowEdges(ctx, {
      makerOrder: curve(178, 150, 229, 260),
      takerOrder: curve(178, 400, 229, 290),
      orderedMpc: curve(371, 275, 434, 275),
      mpcZkpi: curve(590, 265, 645, 175),
      zkpiDefmi: curveVertical(720, 223, 720, 333),
    });
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      edges.push(edge(`mpc-link-${index}`, `mpc-${index}`, 'mpc', curveVertical(x, y < 275 ? y + 20 : y - 20, 512 + (x - 512) * 0.3, y < 275 ? 220 : 330), online ? 'done' : 'cut', 'amber'));
    });
    data.defmi_validators.forEach((online, index) => edges.push(edge(`val-link-${index}`, 'defmi', `val-${index}`, curveVertical(720, 437, 648 + index * 36, 527), online ? 'done' : 'cut', 'blue')));
    return { nodes, edges, labels: [{ x: 790, y: 278, text: '企業の追加署名なし' }], W: 820, H: 600 };
  }

  function narrowGraph(ctx) {
    const { data } = ctx;
    const nodes = [
      ...participantNodes(ctx, [96, 80], [264, 80], 152, 96),
      ...coreNodes(ctx, { ordering: [180, 250, 240, 100], mpc: [180, 420, 240, 110], zkpi: [180, 740, 240, 96], defmi: [180, 905, 240, 104] }),
    ];
    const mpcPositions = [[66, 545], [142, 545], [218, 545], [294, 545], [104, 600], [180, 600], [256, 600]];
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      nodes.push(graphNode(`mpc-${index}`, 'matcher', x, y, 60, 40, `M${index + 1}`, '', '', online ? ['is-mini'] : ['is-mini', 'is-stopped']));
    });
    data.defmi_validators.forEach((online, index) => nodes.push(graphNode(`val-${index}`, 'ledger', 60 + index * 60, 1020, 48, 36, `D${index + 1}`, '', '', online ? ['is-mini'] : ['is-mini', 'is-stopped'])));
    const edges = flowEdges(ctx, {
      makerOrder: curveVertical(96, 128, 130, 200),
      takerOrder: curveVertical(264, 128, 230, 200),
      orderedMpc: curveVertical(180, 300, 180, 365),
      mpcZkpi: sideCurve(300, 420, 300, 740, 346),
      zkpiDefmi: curveVertical(180, 788, 180, 853),
    });
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      edges.push(edge(`mpc-link-${index}`, `mpc-${index}`, 'mpc', curveVertical(x, y - 20, 180 + (x - 180) * 0.4, 475), online ? 'done' : 'cut', 'amber'));
    });
    data.defmi_validators.forEach((online, index) => edges.push(edge(`val-link-${index}`, 'defmi', `val-${index}`, curveVertical(180, 957, 60 + index * 60, 1002), online ? 'done' : 'cut', 'blue')));
    return { nodes, edges, labels: [{ x: 270, y: 820, text: '企業の追加署名なし' }], W: 360, H: 1060 };
  }

  function graphNode(id, type, x, y, w, h, title, sub, badge, classes) {
    return { id, type, x, y, w, h, title, sub, badge, classes, metrics: [] };
  }
  function edge(id, source, target, d, edgeState, color) {
    return { id, source, target, d, state: edgeState, color, own: true, particle: edgeState === 'flow' };
  }
  function curve(x1, y1, x2, y2) {
    const midpoint = (x1 + x2) / 2;
    return `M ${x1} ${y1} C ${midpoint} ${y1}, ${midpoint} ${y2}, ${x2} ${y2}`;
  }
  function curveVertical(x1, y1, x2, y2) {
    const midpoint = (y1 + y2) / 2;
    return `M ${x1} ${y1} C ${x1} ${midpoint}, ${x2} ${midpoint}, ${x2} ${y2}`;
  }
  function sideCurve(x1, y1, x2, y2, sideX) {
    return `M ${x1} ${y1} C ${sideX} ${y1}, ${sideX} ${y2}, ${x2} ${y2}`;
  }

  // ---- helpers -----------------------------------------------------------

  function item(tag, className = '', text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }
  function pair(label, value, mono = false) {
    const row = item('div');
    const dd = item('dd', mono ? 'mono' : '', value ?? '—');
    if (mono && value) dd.title = value;
    row.append(item('dt', '', label), dd);
    return row;
  }

  // ---- actions -----------------------------------------------------------

  async function toggleNode(group, index) {
    if (state.busy) return;
    try {
      await api('/api/nodes/toggle', { method: 'POST', body: JSON.stringify({ group, index }) });
      await refresh();
    } catch (error) { toast(error.message, true); }
  }

  $$('.role-tab').forEach((button) => button.addEventListener('click', async () => {
    state.viewer = button.dataset.viewer;
    state.sideTouched = false;
    $$('.role-tab').forEach((tab) => {
      const active = tab === button; tab.classList.toggle('active', active); tab.setAttribute('aria-pressed', String(active));
    });
    document.body.className = `viewer-${state.viewer}${state.offline ? ' offline' : ''}`;
    $('#role-hint').textContent = roleHints[state.viewer] || '';
    await refresh();
  }));

  $('#order-form').addEventListener('input', (event) => {
    if (event.target.name === 'side') state.sideTouched = true;
    renderOrderPreview();
  });

  $('#order-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!['maker', 'taker'].includes(state.viewer) || state.busy) return;
    const form = new FormData(event.currentTarget);
    const button = $('#submit-order');
    state.busy = true; button.disabled = true; button.textContent = '受付・照合・決済を実行中…';
    try {
      const result = await api('/api/order', { method: 'POST', body: JSON.stringify({
        actor: state.viewer,
        side: form.get('side'),
        price: Number(form.get('price')),
        quantity: Number(form.get('quantity')),
        time_in_force: form.get('time_in_force'),
      }) });
      const status = result.worker?.status || 'executed';
      const messages = {
        waiting_for_mpc: '注文を暗号化して保管しました。計算ノードが戻るまで成立しません。',
        executed: '注文を処理し、結果を台帳に反映しました。',
        expired: '注文は期限切れで取り消されました。確保していた分は戻ります。',
        rejected: '注文は受け付けられませんでした。',
        retryable_failure: '一時的に処理できませんでした。保管したまま再送します。',
        dummy_cover: '注文を保管しました。順番が来たら処理します。',
        idle: '注文を保管しました。',
      };
      toast(messages[status] || '注文を受け付けました。');
      await refresh();
    } catch (error) { toast(error.message, true); }
    finally { state.busy = false; button.disabled = false; button.textContent = 'この内容で注文を出す'; }
  });

  $('#retry-queue').addEventListener('click', async () => {
    if (!['maker', 'taker'].includes(state.viewer) || state.busy) return;
    state.busy = true;
    try {
      await api('/api/queue/pump', { method: 'POST', body: JSON.stringify({ actor: state.viewer }) });
      await refresh(); toast('保管中の先頭の注文を、同じ受付順でもう一度送りました。');
    } catch (error) { toast(error.message, true); }
    finally { state.busy = false; }
  });

  refresh();
  window.setInterval(() => { if (!state.busy) refresh(); }, 2500);
  let resizeTimer = null;
  window.addEventListener('resize', () => {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => { if (state.snapshot) renderGraph(state.snapshot); }, 150);
  });
})();
