(() => {
  'use strict';

  // The page is the graph. Everything else (a company's balances and order
  // form, the public book, the history, the technical details) opens in one
  // panel over the graph: a side drawer on a desktop, a bottom sheet on a
  // phone. `panel` names what the drawer shows: a graph card id (maker,
  // taker, ordering, mpc, zkpi, defmi, book) or a dock view (history,
  // details). Nothing here changes what the server returns per viewer: the
  // company sections only exist for the viewer whose data the server sent.
  const state = {
    viewer: 'operator',
    snapshot: null,
    busy: false,
    offline: false,
    failures: 0,
    sideTouched: false,
    panel: null,
    focusNode: null,
    highlight: null,
    returnTo: null,
    hintDismissed: false,
    expanded: false,
    viewerRevision: 0,
  };
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const number = (value) => new Intl.NumberFormat('ja-JP').format(value ?? 0);
  const yen = (value) => `${number(value)} 円`;
  const lots = (value) => `${number(value)} 口`;
  const clock = (seconds) => seconds ? new Date(seconds * 1000).toLocaleTimeString('ja-JP', { hour12: false }) : '';
  const sheetLayout = () => window.matchMedia('(max-width: 700px)').matches;

  const NODE_PANELS = ['maker', 'taker', 'ordering', 'mpc', 'zkpi', 'defmi', 'book'];
  const VIEW_PANELS = ['history', 'details'];
  const PARTICIPANTS = { maker: '売り手企業', taker: '買い手企業' };

  // Server phases, in the words a person at the desk would use. "Queued" is a
  // holding state: the order is stored, not admitted, matched or settled.
  const phases = {
    ready: { label: '注文を受け付け中', note: '新しい注文を出せます。', tone: 'ok' },
    queued: { label: '注文を暗号化して保管中', note: 'まだ成立していません。順番が来たら秘密計算へ進みます。', tone: 'active' },
    waiting_for_mpc: { label: '計算ノードの復旧待ち', note: '注文は暗号化したまま保管しています。成立はしていません。', tone: 'warn' },
    waiting_for_defmi: { label: 'DeFMI 台帳の復旧待ち', note: '注文は保管したままです。台帳が戻れば同じ順番で続けます。', tone: 'warn' },
    retrying: { label: '同じ受付順で再送中', note: '順番は変わりません。', tone: 'active' },
    // No fill happened. Whether the rest stayed on the book or was cancelled
    // (IOC) is not in this state, so only the certain facts are stated.
    book_updated: { label: '公開板を更新しました', note: '約定はなく、板の合計を更新しました。', tone: 'ok' },
    settled: { label: '約定し、決済が完了しました', note: '証券と資金を同時に引き渡しました。', tone: 'ok' },
    manual_review: {label:'台帳との照合が必要です',note:'決済結果が不明なため新規注文と再送を停止しています。',tone:'bad'},
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

  // One line per viewpoint, shown until the first card is opened.
  const hints = {
    operator: ['市場運営者の視点', '公開板と処理の進み方が見えます。どの企業の注文かは見えません。図の箱を選ぶと、その内容と操作が開きます。'],
    maker: ['売り手企業の視点', '「売り手企業」の箱を選ぶと、自社の資金・在庫の確認と注文ができます。他の箱は処理の内容を示します。'],
    taker: ['買い手企業の視点', '「買い手企業」の箱を選ぶと、自社の資金・在庫の確認と注文ができます。他の箱は処理の内容を示します。'],
  };

  // Timeline entries arrive from the server with implementation wording
  // ("正本", "暗号化キュー", "DvP"). Rewrite the known kinds into plain
  // Japanese here; the raw server text stays available under 技術的な詳細.
  function eventText(event) {
    const detail = event.detail || '';
    switch (event.kind) {
      case 'ready':
        return ['市場を開始しました', '研究用の構成（計算プロセス 7 つ・台帳の確認ノード 5 台）を用意しました。'];
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
    const viewer = state.viewer;
    const revision = state.viewerRevision;
    try {
      const snapshot = await api(`/api/state?viewer=${encodeURIComponent(viewer)}`);
      if (revision !== state.viewerRevision) return;
      state.snapshot = snapshot;
      state.failures = 0;
      setConnection(true);
      render();
    } catch (error) {
      if (revision !== state.viewerRevision) return;
      state.failures += 1;
      if (state.failures >= 2 || !state.snapshot) setConnection(false, error.message);
      if (!state.snapshot) renderEmpty();
    }
  }

  function renderAssurance(data) {
    const progress = data.native_progress || {}, status = progress.status?.status;
    const select = $('#assurance-mode');
    select.value = data.assurance_mode || 'joint_proof';
    select.disabled = state.busy || !!progress.active;
    const box = $('#assurance-status'), button = $('#challenge-claim');
    box.hidden = !progress.active && !progress.claim_id && progress.stage !== 'failed';
    const remaining = Math.max(0, Math.ceil((progress.challenge_deadline || 0) - Date.now()/1000));
    const names = {pending:'暫定結果を受理・未決済', challenged:'challenge中・元の証拠を検証', proven:'証拠を確認・確定期限待ち', finalized:progress.settled ? '台帳への決済確定を確認' : '検証確定・DvP決済中', rejected:'暫定結果を棄却・決済不可'};
    $('#assurance-message').textContent = progress.stage === 'failed' ? '決済未完了・台帳状態の確認が必要' : (names[status] || '秘密計算と共同証明を実行中') + (status === 'pending' || status === 'proven' ? '（残り約'+remaining+'秒）' : '');
    if (data.provisional?.fills?.length) $('#assurance-message').textContent += ' · 暫定約定 ' + data.provisional.fills.map(fill=>yen(fill.price)+' × '+lots(fill.quantity)).join(' / ');
    button.hidden = status !== 'pending'  || !progress.active || remaining === 0;
  }
  $('#assurance-mode').addEventListener('change', async event => {
    if (state.busy) return;
    state.busy = true; event.target.disabled = true; $('#submit-order').disabled = true;
    try { await api('/api/assurance', {method:'POST',body:JSON.stringify({mode:event.target.value})}); await refresh(); }
    catch (error) {toast(error.message,true);}
    finally {state.busy = false; $('#submit-order').disabled = false; await refresh();}
  });
  $('#challenge-claim').addEventListener('click', async event => {
    event.target.disabled = true;
    try {
      await api('/api/challenge', {method:'POST',body:JSON.stringify({claim_id:state.snapshot?.native_progress?.claim_id})});
      toast('challengeを台帳で受理しました。元の証拠による応答を待っています。'); await refresh();
    } catch(error) {toast(error.message,true);}
    finally {event.target.disabled = false;}
  });

  function renderEmpty() {
    $('#empty-book').textContent = 'サーバーに接続できないため、板を表示できません。';
    $('#timeline').replaceChildren(item('li', 'loading', 'サーバーに接続できないため、履歴を表示できません。'));
    renderHint();
    renderDrawer();
  }

  function render() {
    const data = state.snapshot;
    if (!data) return;
    renderAssurance(data);
    const info = phaseInfo(data.phase);
    $('#market-label').textContent = data.market;
    $('#phase-label').textContent = info.label;
    $('#phase-label').title = info.note;
    $('#status-dot').className = `status-dot ${info.tone}`;
    document.body.className = `viewer-${state.viewer}${state.offline ? ' offline' : ''}`;
    renderPortfolio(data.own);
    renderOrders(data.own);
    renderOrderForm(data.own);
    renderNodes(data);
    renderProcess(data);
    renderBook(data);
    renderTimeline(data.events);
    renderDiagnostics(data);
    renderHint();
    renderDrawer();
    renderGraph(data);
  }

  // ---- panel (drawer / bottom sheet) -----------------------------------

  function panelMeta(panel, data) {
    const own = data?.own;
    switch (panel) {
      case 'maker':
      case 'taker': {
        const mine = own && own.role === state.viewer && own.role === panel;
        return {
          kicker: '参加企業',
          title: PARTICIPANTS[panel],
          lead: mine
            ? '自社だけに見える資金・在庫と、自社が出した注文です。'
            : `${PARTICIPANTS[panel]}の資金・在庫・注文は、${PARTICIPANTS[panel]}として表示したときだけ見えます。`,
        };
      }
      case 'ordering':
        return { kicker: '処理', title: '受付順の確定', lead: '5 台の署名で受付順を固定します。順番が決まってから秘密計算へ渡します。' };
      case 'mpc':
        return { kicker: '処理', title: '秘密計算で照合', lead: '注文の中身を開かずに、7 つの計算プロセスで板と照合します。' };
      case 'zkpi':
        return { kicker: '処理', title: '決済の証明（zkPI）', lead: '約定の数量と価格が確保した範囲に収まることを、中身を明かさずに証明します。' };
      case 'defmi':
        return { kicker: '台帳', title: 'DeFMI 台帳', lead: '証券と資金を同時に引き渡して確定します（DvP）。確定した内容だけが公開板に載ります。' };
      case 'book':
        return { kicker: '全員に公開', title: '公開板', lead: '確定した注文を価格ごとに合計した数量です。個々の注文は載りません。' };
      case 'history':
        return { kicker: '公開してよい記録だけ', title: '処理の履歴', lead: '' };
      case 'details':
        return { kicker: '技術的な詳細', title: '識別値・処理の内訳・この環境の制約', lead: '' };
      default:
        return { kicker: '', title: '', lead: '' };
    }
  }

  function renderDrawer() {
    const drawer = $('#drawer');
    const open = Boolean(state.panel);
    drawer.hidden = !open;
    $('#stage').classList.toggle('drawer-open', open);
    drawer.classList.toggle('expanded', state.expanded);
    $('#drawer-expand').setAttribute('aria-expanded', String(state.expanded));
    $$('.dock-button').forEach((button) => {
      const active = button.dataset.panel === state.panel;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    if (!open) return;
    const data = state.snapshot;
    const meta = panelMeta(state.panel, data);
    $('#drawer-kicker').textContent = meta.kicker;
    $('#drawer-title').textContent = meta.title;
    $('#drawer-lead').textContent = meta.lead;
    $('#drawer-lead').classList.toggle('hidden', !meta.lead);

    const participant = Boolean(PARTICIPANTS[state.panel]);
    const mine = participant && Boolean(data?.own) && data.own.role === state.viewer && data.own.role === state.panel;
    show('#participant-gate', participant && !mine);
    show('#portfolio-panel', mine);
    show('#order-panel', mine);
    show('#orders-panel', mine);
    show('#ordering-panel', state.panel === 'ordering');
    show('#mpc-panel', state.panel === 'mpc');
    show('#zkpi-panel', state.panel === 'zkpi');
    show('#defmi-panel', state.panel === 'defmi');
    show('#book-panel', state.panel === 'book');
    show('#history-panel', state.panel === 'history');
    show('#details-panel', state.panel === 'details');
    if (participant && !mine) renderGate(state.panel);
    $$('.node-row').forEach((row) => {
      const focus = Boolean(state.highlight) && row.dataset.group === state.highlight.group && Number(row.dataset.index) === state.highlight.index;
      row.classList.toggle('is-focus', focus);
    });
  }

  function show(selector, visible) {
    $(selector).classList.toggle('hidden', !visible);
  }

  function renderGate(panel) {
    const name = PARTICIPANTS[panel];
    const text = state.viewer === 'operator'
      ? `市場運営者には、${name}の資金・在庫・注文は見えません。公開板の合計と処理の進み方だけが見えます。`
      : `${PARTICIPANTS[state.viewer]}の画面からは、${name}の資金・在庫・注文は見えません。各社に見えるのは自社の情報だけです。`;
    $('#gate-text').textContent = text;
    $('#gate-switch').textContent = `${name}として表示する`;
  }

  function openPanel(panel, origin = {}) {
    state.panel = panel;
    state.focusNode = origin.node || (NODE_PANELS.includes(panel) ? panel : null);
    state.highlight = origin.highlight || null;
    state.returnTo = origin.node || null;
    state.hintDismissed = true;
    renderHint();
    renderDrawer();
    if (state.snapshot) renderGraph(state.snapshot);
    window.requestAnimationFrame(() => {
      const body = $('#drawer-body');
      const row = state.highlight ? body.querySelector('.node-row.is-focus button') : null;
      if (row) {
        row.focus({ preventScroll: true });
        row.scrollIntoView({ block: 'nearest' });
      } else {
        body.scrollTop = 0;
        $('#drawer-title').focus({ preventScroll: true });
      }
    });
  }

  function closeDrawer() {
    if (!state.panel) return;
    const returnTo = state.returnTo;
    state.panel = null;
    state.focusNode = null;
    state.highlight = null;
    state.returnTo = null;
    state.expanded = false;
    renderHint();
    renderDrawer();
    if (state.snapshot) renderGraph(state.snapshot);
    const card = returnTo ? document.querySelector(`#network-graph [data-node-id="${returnTo}"]`) : null;
    if (card) card.focus({ preventScroll: true });
  }

  // A card on the graph was chosen (click, Enter or Space).
  function activateNode(id) {
    let panel = id;
    let highlight = null;
    if (id.startsWith('mpc-')) { panel = 'mpc'; highlight = { group: 'mpc', index: Number(id.slice(4)) }; }
    if (id.startsWith('val-')) { panel = 'defmi'; highlight = { group: 'defmi', index: Number(id.slice(4)) }; }
    if (!NODE_PANELS.includes(panel)) return;
    if (state.panel === panel && state.returnTo === id) { closeDrawer(); return; }
    openPanel(panel, { node: id, highlight });
  }

  function togglePanel(panel) {
    if (state.panel === panel) closeDrawer();
    else openPanel(panel);
  }

  function renderHint() {
    const [title, body] = hints[state.viewer] || hints.operator;
    $('#hint-title').textContent = title;
    $('#hint-body').textContent = body;
    const action = $('#hint-action');
    action.classList.toggle('hidden', !PARTICIPANTS[state.viewer]);
    action.textContent = `${PARTICIPANTS[state.viewer] || ''}の資金・在庫と注文を開く`;
    $('#hint').classList.toggle('hidden', state.hintDismissed || Boolean(state.panel));
  }

  // ---- sections --------------------------------------------------------

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

  function renderOrderForm(own) {
    if (!own) return;
    // A seller starts on "sell", a buyer on "buy"; either can be changed.
    const side = own.role === 'maker' ? 'sell' : 'buy';
    const radio = document.querySelector(`input[name="side"][value="${side}"]`);
    if (radio && !state.busy && !state.sideTouched) radio.checked = true;
    renderOrderPreview();
  }

  function renderNodes(data) {
    const mpcUp = data.mpc_nodes.filter(Boolean).length;
    const valUp = data.defmi_validators.filter(Boolean).length;
    $('#mpc-count').textContent = `${mpcUp}/${data.mpc_nodes.length} 利用可`;
    $('#defmi-count').textContent = `${valUp}/${data.defmi_validators.length} 利用可`;
    nodeList($('#mpc-controls'), 'mpc', data.mpc_nodes, '計算ノード');
    nodeList($('#defmi-controls'), 'defmi', data.defmi_validators, '台帳の確認ノード');
  }

  function nodeList(root, group, values, groupLabel) {
    root.replaceChildren();
    values.forEach((online, index) => {
      const row = item('li', `node-row${online ? '' : ' off'}`);
      row.dataset.group = group;
      row.dataset.index = String(index);
      const focus = Boolean(state.highlight) && state.highlight.group === group && state.highlight.index === index;
      row.classList.toggle('is-focus', focus);
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = online ? '停止を模擬' : '停止を解除';
      button.setAttribute('aria-label', `${groupLabel} ${index + 1} の${online ? '停止を模擬する' : '停止模擬を解除する'}（表示だけ）`);
      button.addEventListener('click', () => toggleNode(group, index));
      row.append(
        item('span', 'node-name', `${groupLabel} ${index + 1}`),
        item('span', 'node-state', online ? '利用可' : '停止を模擬中'),
        button,
      );
      root.append(row);
    });
  }

  function renderProcess(data) {
    const last = data.last_execution;
    const fills = last?.fills?.length ? last.fills : [];
    const filled = fills.reduce((sum, fill) => sum + fill.quantity, 0);

    fillValues($('#ordering-values'), [
      ['次の受付番号', `#${data.book.sequence + 1}`],
      ['署名するノード', '5 台（研究用の模擬ノード）'],
      ['最後の受付', last ? `#${last.sequence}（署名 ${last.ordering_signers} 台）` : 'まだ注文はありません'],
      ['いまの段階', phaseInfo(data.phase).label],
    ]);

    fillValues($('#mpc-values'), last ? [
      ['受付番号', `#${last.sequence}`],
      ['計算プロセス', `${last.mpc_parties} プロセス`],
      ['プロトコル', last.mpc_protocol],
      ['実行時間', `${Math.round(last.mpc_execution_ms)} ミリ秒`],
      ['結果', fills.length ? `約定 ${number(filled)} 口` : '約定なし（板の合計を更新）'],
    ] : [['状態', 'まだ照合はありません']]);

    fillValues($('#zkpi-values'), last ? [
      ['受付番号', `#${last.sequence}`],
      ['証明', last.threshold_zkpi ? '作成済み' : '作成なし（約定がないため不要）', last.threshold_zkpi ? 'ok' : ''],
      ['決済の承認', last.threshold_zkpi ? `${last.settlement_authorization_quorum} 台` : '—'],
      ['約定', fills.length ? fills.map((fill) => `${number(fill.quantity)} 口 @ ${number(fill.price)} 円`).join('、') : 'なし'],
      ['約定後の企業の署名', `${last.post_match_signatures ?? 0} 回（不要）`],
    ] : [['状態', 'まだ処理はありません']]);

    $('#defmi-height').textContent = `更新 ${number(data.defmi.height)} 回`;
    fillValues($('#defmi-values'), last ? [
      ['最後の反映', fills.length ? `決済（受付番号 #${last.sequence}）` : `板の更新（受付番号 #${last.sequence}）`],
      ['市場遷移の証拠', last.transition_attestations ? `${last.transition_attestations} 台の署名` : '暫定方式の確定参照'],
      ['台帳の受付記録', last.canonical_receipt, 'mono'],
    ] : [['最後の反映', 'まだ処理はありません']]);
    const roots = $('#root-values');
    roots.replaceChildren();
    [['証券残高の識別値', data.defmi.securities_root], ['資金残高の識別値', data.defmi.cash_root], ['確保枠の識別値', data.defmi.reservation_root]]
      .forEach(([label, value]) => roots.append(pair(label, value, true)));

    fillValues($('#book-values'), [
      ['価格帯', data.book.levels.length ? `${data.book.levels.length} つ` : 'なし'],
      ['最後の決済', last && fills.length
        ? `${number(filled)} 口が約定（${fills.map((fill) => `${number(fill.price)} 円`).join('・')}）`
        : last ? '最後の処理では約定なし' : 'まだ決済はありません'],
    ]);
  }

  function fillValues(root, rows) {
    root.replaceChildren();
    rows.forEach(([label, value, tone]) => root.append(pair(label, value, tone === 'mono', tone && tone !== 'mono' ? tone : '')));
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
    events.slice(0, 20).forEach((event) => {
      const [title, detail] = eventText(event);
      const li = item('li', event.tone);
      li.title = `サーバーの原文：${event.title} — ${event.detail}`;
      const head = item('div', 'timeline-head');
      head.append(item('strong', '', title), item('time', '', clock(event.at)));
      li.append(head, item('p', '', detail));
      root.append(li);
    });
    const raw = $('#raw-timeline');
    raw.replaceChildren();
    events.slice(0, 20).forEach((event) => raw.append(item('li', '', `${clock(event.at)} [${event.kind}] ${event.title} — ${event.detail}`)));
  }

  function renderDiagnostics(data) {
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
        ['台帳への反映', `ネイティブ台帳の高さ ${number(last.canonical_height)} で確定`],
        ['約定後に企業が署名した回数', String(last.post_match_signatures ?? 0)],
        ['注文の識別値', last.order_commitment, true],
        ['台帳の受付記録', last.canonical_receipt, true],
      ].forEach(([label, value, mono]) => exec.append(pair(label, value, mono)));
    }

    const privateView = Boolean(data.own);
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
      ['画面ごとの表示の絞り込みはこの研究用サーバーが行っています。分散した秘匿の保証は実サービス側の設計です。', true],
    ];
    factRows.filter(([, display]) => display).forEach(([text]) => facts.append(item('li', '', text)));

    const notes = $('#graph-notes'); notes.replaceChildren();
    graphNotes(data).forEach((text) => notes.append(item('li', '', text)));
  }

  function graphNotes(data) {
    const anyOff = data.mpc_nodes.some((on) => !on) || data.defmi_validators.some((on) => !on);
    const notes = [
      '線は注文がたどる経路です。通信の実況や生存監視ではありません。線の色は、その経路の処理が最後にどこまで進んだかを示します。',
      '研究用の 1 台構成です。計算プロセス 7 つと台帳の確認ノード 5 台は同じサーバー内で動いています。',
      '箱を選ぶと内容と操作が開きます。個別の注文や残高は、その企業として表示したときだけ開きます。',
    ];
    if (anyOff) notes.push('赤い破線は、障害の模擬で停止扱いにしたノードです。');
    return notes;
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
      ? `必要な在庫は ${number(quantity)} 口です。指値 ${number(price)} 円 × ${number(quantity)} 口がすべて成立した場合の受取額は ${number(price * quantity)} 円です。一部だけ、または指値より有利な価格で成立することがあります。`
      : `必要な資金は ${number(price * quantity)} 円（指値 ${number(price)} 円 × ${number(quantity)} 口）です。すべて成立した場合に ${number(quantity)} 口を受け取ります。一部だけ、または指値より有利な価格で成立することがあります。`;
  }

  // ---- graph -------------------------------------------------------------

  function selectedGraphNode() {
    if (state.highlight) return `${state.highlight.group === 'mpc' ? 'mpc' : 'val'}-${state.highlight.index}`;
    return NODE_PANELS.includes(state.panel) ? state.panel : null;
  }

  function renderGraph(data) {
    if (!window.OclobNetworkGraph || !data) return;
    const container = $('#network-graph');
    const phase = data.phase;
    const inFlight = ['queued', 'waiting_for_mpc', 'waiting_for_defmi', 'retrying'].includes(phase);
    const hasResult = Boolean(data.last_execution);
    const settled = Boolean(data.last_execution?.fills?.length);
    const narrow = container.clientWidth < 560;
    const sheet = sheetLayout();
    const ctx = { data, phase, inFlight, hasResult, settled, viewer: state.viewer };
    const model = narrow ? narrowGraph(ctx) : wideGraph(ctx);
    // On a phone the graph already stops above the dock; only the open sheet
    // covers part of it.
    const obscuredBottom = sheet && state.panel ? $('#drawer').offsetHeight : 0;
    window.OclobNetworkGraph.render(container, model, {
      ariaLabel: '参加企業、受付順の確定、秘密計算、決済の証明、DeFMI 台帳、公開板を結ぶ処理の流れ。各箱はボタンで、選ぶと内容と操作が開きます',
      phase, phaseLabel: phaseInfo(phase).label, noRoundText: '',
      legend: [
        { type: 'maker', label: '参加企業' }, { type: 'matcher', label: '受付・秘密計算' },
        { type: 'zkpi', label: '決済の証明' }, { type: 'ledger', label: 'DeFMI 台帳' }, { type: 'book', label: '公開板' },
      ],
      legendNotes: graphNotes(data),
      reducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
      chrome: 'overlay',
      fill: true,
      interactive: true,
      selectedNodeId: selectedGraphNode(),
      focusNodeId: state.focusNode,
      obscuredBottom,
      controlsPosition: sheet ? 'top-right' : 'bottom-right',
      onNodeActivate: (id) => activateNode(id),
      onDismiss: () => closeDrawer(),
    });
  }

  function participantNodes(ctx, makerPos, takerPos, w, h) {
    const { data } = ctx;
    const mine = (role) => data.own?.role === role;
    const sub = (role, mineText) => mine(role) ? mineText : '注文の中身は本人以外に非公開';
    return [
      graphNode('maker', 'maker', makerPos[0], makerPos[1], w, h, '売り手企業', sub('maker', '資金・在庫・注文を確認できます'), mine('maker') ? '自社' : '', mine('maker') ? ['is-me'] : []),
      graphNode('taker', 'taker', takerPos[0], takerPos[1], w, h, '買い手企業', sub('taker', '資金・在庫・注文を確認できます'), mine('taker') ? '自社' : '', mine('taker') ? ['is-me'] : []),
    ];
  }

  function coreNodes(ctx, pos) {
    const { data, phase, hasResult } = ctx;
    const active = (names) => names.includes(phase);
    const mpcUp = data.mpc_nodes.filter(Boolean).length;
    const valUp = data.defmi_validators.filter(Boolean).length;
    const levels = data.book.levels.length;
    return [
      graphNode('ordering', 'matcher', ...pos.ordering, '受付順の確定', '5 台の署名で順番を固定', `次は #${data.book.sequence + 1}`, active(['queued']) ? ['is-active'] : []),
      graphNode('mpc', 'matcher', ...pos.mpc, '秘密計算で照合', '注文を開かずに 7 プロセスで照合', `${mpcUp}/${data.mpc_nodes.length} 利用可`, active(['waiting_for_mpc', 'retrying']) ? ['is-active'] : mpcUp < data.mpc_nodes.length ? ['is-stopped'] : []),
      graphNode('zkpi', 'zkpi', ...pos.zkpi, '決済の証明（zkPI）', '約定と確保枠の正しさを証明', hasResult ? (data.last_execution.threshold_zkpi ? '作成済み' : '今回は不要') : '待機中', active(['settled']) ? ['is-active'] : []),
      graphNode('defmi', 'ledger', ...pos.defmi, 'DeFMI 台帳', '証券と資金を同時に引き渡し', `更新 ${number(data.defmi.height)} 回`, active(['settled', 'waiting_for_defmi']) ? ['is-active'] : valUp < 3 ? ['is-stopped'] : []),
      graphNode('book', 'book', ...pos.book, '公開板', '価格ごとの合計だけを公開', levels ? `${levels} 価格帯` : '注文なし', active(['book_updated']) ? ['is-active'] : []),
    ];
  }

  function memberNode(id, type, x, y, w, h, title, groupLabel, index, online) {
    const node = graphNode(id, type, x, y, w, h, title, '', '', online ? ['is-mini'] : ['is-mini', 'is-stopped']);
    node.focusable = false;
    node.ariaLabel = `${groupLabel} ${index + 1}：${online ? '利用可' : '停止を模擬中'}。選ぶと停止の模擬を切り替える一覧を開きます`;
    return node;
  }

  function flowEdges(ctx, paths) {
    const { inFlight, hasResult, settled, phase } = ctx;
    const orderState = inFlight ? 'flow' : hasResult ? 'done' : 'idle';
    const mpcState = phase === 'queued' || phase === 'retrying' ? 'flow' : hasResult ? 'done' : 'idle';
    const settleState = settled ? 'done' : 'idle';
    const publishState = hasResult ? 'done' : 'idle';
    return [
      edge('maker-order', 'maker', 'ordering', paths.makerOrder, orderState, 'teal'),
      edge('taker-order', 'taker', 'ordering', paths.takerOrder, orderState, 'teal'),
      edge('ordered-mpc', 'ordering', 'mpc', paths.orderedMpc, mpcState, 'amber'),
      edge('mpc-zkpi', 'mpc', 'zkpi', paths.mpcZkpi, settleState, 'amber'),
      edge('zkpi-defmi', 'zkpi', 'defmi', paths.zkpiDefmi, settleState, 'blue'),
      edge('defmi-book', 'defmi', 'book', paths.defmiBook, publishState, 'blue'),
    ];
  }

  function wideGraph(ctx) {
    const { data } = ctx;
    const nodes = [
      ...participantNodes(ctx, [100, 150], [100, 400], 156, 96),
      ...coreNodes(ctx, {
        ordering: [300, 275, 142, 104], mpc: [512, 275, 156, 110],
        zkpi: [720, 175, 150, 96], defmi: [720, 385, 150, 104], book: [930, 385, 150, 104],
      }),
    ];
    const mpcPositions = [[440, 68], [488, 68], [536, 68], [584, 68], [464, 482], [512, 482], [560, 482]];
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      nodes.push(memberNode(`mpc-${index}`, 'matcher', x, y, 42, 40, `M${index + 1}`, '計算ノード', index, online));
    });
    data.defmi_validators.forEach((online, index) => nodes.push(memberNode(`val-${index}`, 'ledger', 648 + index * 36, 545, 32, 36, `D${index + 1}`, '台帳の確認ノード', index, online)));
    const edges = flowEdges(ctx, {
      makerOrder: curve(178, 150, 229, 260),
      takerOrder: curve(178, 400, 229, 290),
      orderedMpc: curve(371, 275, 434, 275),
      mpcZkpi: curve(590, 265, 645, 175),
      zkpiDefmi: curveVertical(720, 223, 720, 333),
      defmiBook: curve(795, 385, 855, 385),
    });
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      edges.push(edge(`mpc-link-${index}`, `mpc-${index}`, 'mpc', curveVertical(x, y < 275 ? y + 20 : y - 20, 512 + (x - 512) * 0.3, y < 275 ? 220 : 330), online ? 'done' : 'cut', 'amber'));
    });
    data.defmi_validators.forEach((online, index) => edges.push(edge(`val-link-${index}`, 'defmi', `val-${index}`, curveVertical(720, 437, 648 + index * 36, 527), online ? 'done' : 'cut', 'blue')));
    return { nodes, edges, labels: [{ x: 790, y: 278, text: '企業の追加署名なし' }], W: 1040, H: 600 };
  }

  // Phones: one column, top to bottom, fitted into the screen as a whole.
  function narrowGraph(ctx) {
    const { data } = ctx;
    const nodes = [
      ...participantNodes(ctx, [96, 70], [284, 70], 150, 84),
      ...coreNodes(ctx, {
        ordering: [190, 210, 230, 84], mpc: [190, 350, 230, 96],
        zkpi: [190, 580, 230, 84], defmi: [190, 715, 230, 90], book: [190, 920, 230, 84],
      }),
    ];
    const mpcPositions = Array.from({ length: 7 }, (_, index) => [34 + index * 48, 455]);
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      nodes.push(memberNode(`mpc-${index}`, 'matcher', x, y, 42, 34, `M${index + 1}`, '計算ノード', index, online));
    });
    data.defmi_validators.forEach((online, index) => nodes.push(memberNode(`val-${index}`, 'ledger', 70 + index * 60, 815, 52, 34, `D${index + 1}`, '台帳の確認ノード', index, online)));
    const edges = flowEdges(ctx, {
      makerOrder: curveVertical(96, 112, 140, 168),
      takerOrder: curveVertical(284, 112, 240, 168),
      orderedMpc: curveVertical(190, 252, 190, 302),
      mpcZkpi: sideCurve(305, 350, 305, 580, 362),
      zkpiDefmi: curveVertical(190, 622, 190, 670),
      defmiBook: sideCurve(305, 715, 305, 920, 362),
    });
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      edges.push(edge(`mpc-link-${index}`, `mpc-${index}`, 'mpc', curveVertical(x, y - 17, 190 + (x - 190) * 0.4, 398), online ? 'done' : 'cut', 'amber'));
    });
    data.defmi_validators.forEach((online, index) => edges.push(edge(`val-link-${index}`, 'defmi', `val-${index}`, curveVertical(190, 760, 70 + index * 60, 798), online ? 'done' : 'cut', 'blue')));
    return { nodes, edges, labels: [{ x: 190, y: 646, text: '企業の追加署名なし' }], W: 380, H: 1000 };
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
  function pair(label, value, mono = false, tone = '') {
    const row = item('div');
    const dd = item('dd', [mono ? 'mono' : '', tone].filter(Boolean).join(' '), value ?? '—');
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
      // The list is rebuilt on refresh; keep the keyboard on the same row.
      const button = document.querySelector(`.node-row[data-group="${group}"][data-index="${index}"] button`);
      if (button) button.focus({ preventScroll: true });
    } catch (error) { toast(error.message, true); }
  }

  async function switchViewer(viewer) {
    if (!['operator', 'maker', 'taker'].includes(viewer)) return;
    state.viewer = viewer;
    state.viewerRevision += 1;
    // Retain the last public graph while fetching the new viewpoint, but
    // remove the previous company's data immediately, including on errors.
    if (state.snapshot) state.snapshot = { ...state.snapshot, viewer, own: null };
    state.sideTouched = false;
    // Show the one-line guidance for the new viewpoint, unless a panel is
    // already open (then the user has found the cards).
    state.hintDismissed = Boolean(state.panel);
    $$('.role-tab').forEach((tab) => {
      const active = tab.dataset.viewer === viewer;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-pressed', String(active));
    });
    document.body.className = `viewer-${state.viewer}${state.offline ? ' offline' : ''}`;
    renderHint();
    if (state.snapshot) render();
    else renderDrawer();
    await refresh();
  }

  $$('.role-tab').forEach((button) => button.addEventListener('click', () => { void switchViewer(button.dataset.viewer); }));

  $$('.dock-button').forEach((button) => button.addEventListener('click', () => togglePanel(button.dataset.panel)));

  $('#drawer-close').addEventListener('click', () => closeDrawer());

  $('#drawer-expand').addEventListener('click', () => {
    state.expanded = !state.expanded;
    renderDrawer();
    if (state.snapshot) renderGraph(state.snapshot);
  });

  $('#hint-close').addEventListener('click', () => { state.hintDismissed = true; renderHint(); });

  $('#hint-action').addEventListener('click', () => {
    if (PARTICIPANTS[state.viewer]) openPanel(state.viewer, { node: state.viewer });
  });

  $('#gate-switch').addEventListener('click', () => {
    if (PARTICIPANTS[state.panel]) void switchViewer(state.panel);
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || !state.panel) return;
    // Escape inside a <select> is closing its own list, not the panel.
    if (event.target instanceof HTMLSelectElement) return;
    event.preventDefault();
    closeDrawer();
  });

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

  renderHint();
  refresh();
  window.setInterval(() => { refresh(); }, 1000);
  let resizeTimer = null;
  window.addEventListener('resize', () => {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => { if (state.snapshot) renderGraph(state.snapshot); }, 150);
  });
})();
