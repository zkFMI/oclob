(() => {
  'use strict';

  const state = { viewer: 'operator', snapshot: null, busy: false };
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const short = (value, length = 10) => value ? `${value.slice(0, length)}…` : '—';
  const number = (value) => new Intl.NumberFormat('ja-JP').format(value ?? 0);
  const phaseLabels = {
    ready: '注文受付中', queued: '暗号化して待機', waiting_for_mpc: 'MPC復旧待ち',
    waiting_for_defmi: 'DeFMI復旧待ち', retrying: '安全に再送中',
    book_updated: '公開板を更新', settled: 'DvP決済済み', rejected: '注文を拒否',
  };

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    });
    const payload = await response.json();
    if (!response.ok || payload.ok === false) throw new Error(payload.error || '処理に失敗しました');
    return payload.data ?? payload;
  }

  function toast(message, error = false) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.toggle('error', error);
    element.classList.add('show');
    window.setTimeout(() => element.classList.remove('show'), 3800);
  }

  async function refresh() {
    try {
      state.snapshot = await api(`/api/state?viewer=${encodeURIComponent(state.viewer)}`);
      render();
    } catch (error) {
      toast(error.message, true);
    }
  }

  function render() {
    const data = state.snapshot;
    if (!data) return;
    $('#market-label').textContent = data.market;
    $('#phase-label').textContent = phaseLabels[data.phase] || data.phase;
    renderRole(data);
    renderPortfolio(data.own);
    renderNodes(data);
    renderBook(data.book);
    renderTimeline(data.events);
    renderRoots(data.defmi);
    renderReceipt(data.last_execution);
    renderGraph(data);
  }

  function renderRole(data) {
    const privateView = Boolean(data.own);
    $('#portfolio-panel').classList.toggle('hidden', !privateView);
    $('#order-panel').classList.toggle('hidden', !privateView);
    $('#retry-queue').classList.toggle('hidden', !privateView);
    $('#projection-badge').textContent = privateView ? '法人投影' : '運営投影';
    $('#projection-badge').classList.toggle('own', privateView);
    $('#privacy-title').textContent = privateView
      ? `${data.own.display_name}の専用画面`
      : '運営画面に未処理注文を表示しません';
    $('#privacy-copy').textContent = privateView
      ? '選択した法人向け投影のサンプルです。このJSONには当該法人の資金、在庫、注文だけを含めます。役割タブはデモ用であり、認証ではありません。現在はサーバーが注文を受け取ってから秘密分散します。'
      : '運営画面向け投影のサンプルです。このJSONには未処理注文を含めず、確定後の価格帯別合計、証明、決済結果だけを返します。現在は同じサーバープロセスが注文を受け取り、MPC用の秘密分散を作ります。';
    if (privateView) {
      const side = data.own.role === 'maker' ? 'sell' : 'buy';
      const radio = document.querySelector(`input[name="side"][value="${side}"]`);
      if (radio && !state.busy) radio.checked = true;
    }
  }

  function renderPortfolio(own) {
    const root = $('#portfolio-cards');
    root.replaceChildren();
    if (!own) return;
    const values = [
      ['利用可能な資金', `${number(own.portfolio.available_cash)} 円`, `予約中 ${number(own.portfolio.reserved_cash)} 円`],
      ['利用可能な在庫', `${number(own.portfolio.available_securities)} 口`, `予約中 ${number(own.portfolio.reserved_securities)} 口`],
      ['送信済み注文', `${own.orders.length} 件`, `待機 ${own.queue.queued + own.queue.dispatching} 件`],
      ['確定待ち最長', own.queue.oldest_unfinalized_age_seconds == null ? 'なし' : `${own.queue.oldest_unfinalized_age_seconds} 秒`, '暗号化して保存'],
    ];
    values.forEach(([label, value, note]) => {
      const card = document.createElement('div');
      card.className = 'portfolio-card';
      const title = document.createElement('span'); title.textContent = label;
      const strong = document.createElement('strong'); strong.textContent = value;
      const small = document.createElement('small'); small.textContent = note;
      card.append(title, strong, small); root.append(card);
    });
  }

  function renderNodes(data) {
    nodeButtons($('#mpc-controls'), 'mpc', data.mpc_nodes);
    nodeButtons($('#defmi-controls'), 'defmi', data.defmi_validators);
  }

  function nodeButtons(root, group, values) {
    root.replaceChildren();
    values.forEach((online, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = online ? '' : 'off';
      button.textContent = String(index + 1);
      const groupLabel = group === 'mpc' ? 'MPC処理' : 'DeFMI確認処理';
      button.title = `${groupLabel} ${index + 1}: ${online ? '利用可能' : '停止を模擬中'}。押すと研究用の状態表示だけを切り替えます`;
      button.setAttribute('aria-label', button.title);
      button.addEventListener('click', () => toggleNode(group, index));
      root.append(button);
    });
  }

  function renderBook(book) {
    $('#book-sequence').textContent = `受付 ${book.sequence}`;
    const root = $('#book-levels'); root.replaceChildren();
    const maximum = Math.max(1, ...book.levels.map((level) => level.quantity));
    [...book.levels]
      .sort((a, b) => a.side === b.side ? (a.side === 'sell' ? a.price - b.price : b.price - a.price) : (a.side === 'sell' ? -1 : 1))
      .forEach((level) => {
        const row = document.createElement('div'); row.className = `book-row ${level.side}`;
        row.style.setProperty('--depth', `${Math.max(8, level.quantity / maximum * 100)}%`);
        const side = document.createElement('span'); side.textContent = level.side === 'sell' ? '売り' : '買い';
        const price = document.createElement('span'); price.textContent = number(level.price);
        const quantity = document.createElement('span'); quantity.textContent = number(level.quantity);
        row.append(side, price, quantity); root.append(row);
      });
    $('#empty-book').classList.toggle('hidden', book.levels.length > 0);
  }

  function renderTimeline(events) {
    const root = $('#timeline'); root.replaceChildren();
    events.slice(0, 12).forEach((event) => {
      const item = document.createElement('li'); item.className = event.tone;
      const title = document.createElement('strong'); title.textContent = event.title;
      const detail = document.createElement('p'); detail.textContent = event.detail;
      item.append(title, detail); root.append(item);
    });
  }

  function renderRoots(defmi) {
    $('#defmi-height').textContent = `高さ ${defmi.height}`;
    const root = $('#root-values'); root.replaceChildren();
    [['証券残高', defmi.securities_root], ['資金残高', defmi.cash_root], ['予約枠', defmi.reservation_root]].forEach(([label, value]) => {
      const row = document.createElement('div');
      const dt = document.createElement('dt'); dt.textContent = label;
      const dd = document.createElement('dd'); dd.textContent = value; dd.title = value;
      row.append(dt, dd); root.append(row);
    });
  }

  function renderReceipt(receipt) {
    const root = $('#receipt-steps'); root.replaceChildren();
    const steps = receipt ? [
      ['受付順', `5/7形式・#${receipt.sequence}`, true],
      ['秘密照合', `${receipt.mpc_parties}プロセス・${Math.round(receipt.mpc_execution_ms)}ms`, true],
      ['zkPI', receipt.threshold_zkpi ? '分散証明済み' : '板登録のみ', receipt.threshold_zkpi],
      ['DeFMI', `正本高さ ${receipt.canonical_height}`, true],
    ] : [
      ['受付順', '未実行', false], ['秘密照合', '未実行', false], ['zkPI', '未生成', false], ['DeFMI', '未更新', false],
    ];
    steps.forEach(([label, value, done]) => {
      const item = document.createElement('div'); item.className = `receipt-step${done ? ' done' : ''}`;
      const span = document.createElement('span'); span.textContent = label;
      const strong = document.createElement('strong'); strong.textContent = value;
      item.append(span, strong); root.append(item);
    });
  }

  function renderGraph(data) {
    if (!window.OclobNetworkGraph) return;
    const phase = data.phase;
    const active = (names) => names.includes(phase);
    const flowToOrder = active(['queued', 'waiting_for_mpc', 'retrying', 'book_updated', 'settled']);
    const flowToMpc = active(['queued', 'retrying', 'book_updated', 'settled']);
    const flowToSettlement = active(['settled']);
    const narrow = $('#network-graph').clientWidth < 560;
    const model = narrow
      ? narrowGraph(data, active, flowToOrder, flowToMpc, flowToSettlement)
      : wideGraph(data, active, flowToOrder, flowToMpc, flowToSettlement);
    window.OclobNetworkGraph.render($('#network-graph'), model, {
      ariaLabel: 'OCLOBの参加企業、受付順、MPC秘密照合、zkPI、DeFMI正本を結ぶ処理経路',
      phase, phaseLabel: phaseLabels[phase] || phase, noRoundText: '',
      legend: [
        { type: 'maker', label: '参加企業' }, { type: 'matcher', label: '秘密計算' },
        { type: 'zkpi', label: '決済証明' }, { type: 'ledger', label: '正本台帳' },
      ],
      legendNotes: [
        '運営画面には未処理注文を表示しません',
        '現MVPは同一プロセス受信後に秘密分散します。企業側での分散は本番化前の必須項目です',
        '赤は障害状態を模擬した表示です',
      ],
      reducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    });
  }

  function wideGraph(data, active, flowToOrder, flowToMpc, flowToSettlement) {
    const nodes = [
      graphNode('maker', 'maker', 92, 170, 164, 108, '売り手企業', state.viewer === 'maker' ? '自社の注文・在庫' : '運営画面には詳細なし', state.viewer === 'maker' ? '表示中' : '', data.own?.role === 'maker' ? ['is-me'] : []),
      graphNode('taker', 'taker', 92, 420, 164, 108, '買い手企業', state.viewer === 'taker' ? '自社の注文・資金' : '運営画面には詳細なし', state.viewer === 'taker' ? '表示中' : '', data.own?.role === 'taker' ? ['is-me'] : []),
      graphNode('ordering', 'matcher', 290, 295, 174, 124, '受付順を固定', '5/7署名形式（模擬ノード）', `次は #${data.book.sequence + 1}`, active(['queued']) ? ['is-active'] : []),
      graphNode('mpc', 'matcher', 525, 295, 194, 140, 'MPC秘密照合', 'MP-SPDZを7プロセスで実行', `${data.mpc_nodes.filter(Boolean).length}/7 利用可`, active(['waiting_for_mpc', 'retrying']) ? ['is-active'] : []),
      graphNode('zkpi', 'zkpi', 755, 215, 176, 124, 'zkPI', '約定条件と予約枠を証明', data.last_execution?.threshold_zkpi ? '生成済み' : '待機', active(['settled']) ? ['is-active'] : []),
      graphNode('defmi', 'ledger', 965, 295, 184, 140, 'DeFMI正本', '研究用正本を原子的に更新', `高さ ${data.defmi.height}`, active(['settled', 'waiting_for_defmi']) ? ['is-active'] : []),
    ];
    const mpcPositions = [[420, 92], [490, 92], [560, 92], [630, 92], [455, 505], [525, 505], [595, 505]];
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      nodes.push(graphNode(`mpc-${index}`, 'matcher', x, y, 64, 54, `M${index + 1}`, online ? '利用可' : '停止模擬', '', online ? [] : ['is-stopped']));
    });
    data.defmi_validators.forEach((online, index) => nodes.push(graphNode(`val-${index}`, 'ledger', 805 + index * 72, 510, 64, 54, `D${index + 1}`, online ? '確認可' : '停止模擬', '', online ? [] : ['is-stopped'])));
    const edges = [
      edge('maker-order', 'maker', 'ordering', curve(174, 170, 203, 295), flowToOrder ? 'flow' : 'idle', 'teal'),
      edge('taker-order', 'taker', 'ordering', curve(174, 420, 203, 295), flowToOrder ? 'flow' : 'idle', 'teal'),
      edge('ordered-mpc', 'ordering', 'mpc', curve(377, 295, 428, 295), flowToMpc ? 'flow' : 'idle', 'amber'),
      edge('mpc-zkpi', 'mpc', 'zkpi', curve(622, 295, 667, 215), flowToSettlement ? 'flow' : (data.last_execution ? 'done' : 'idle'), 'amber'),
      edge('zkpi-defmi', 'zkpi', 'defmi', curve(843, 215, 873, 295), flowToSettlement ? 'flow' : (data.last_execution ? 'done' : 'idle'), 'blue'),
    ];
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      edges.push(edge(`mpc-link-${index}`, `mpc-${index}`, 'mpc', curveVertical(x, y < 295 ? y + 27 : y - 27, 525, y < 295 ? 225 : 365), online ? 'done' : 'cut', 'amber'));
    });
    data.defmi_validators.forEach((online, index) => edges.push(edge(`val-link-${index}`, 'defmi', `val-${index}`, curveVertical(965, 365, 805 + index * 72, 483), online ? 'done' : 'cut', 'blue')));
    return {
      nodes,
      edges,
      labels: [
        { x: 188, y: 224, text: '署名済み注文' },
        { x: 404, y: 265, text: '順番証明', strong: true },
        { x: 646, y: 240, text: '約定結果' },
        { x: 861, y: 238, text: '追加署名なし' },
      ],
      W: 1080,
      H: 570,
    };
  }

  function narrowGraph(data, active, flowToOrder, flowToMpc, flowToSettlement) {
    const nodes = [
      graphNode('maker', 'maker', 92, 82, 154, 100, '売り手企業', state.viewer === 'maker' ? '自社情報を表示' : '詳細は非表示', state.viewer === 'maker' ? '表示中' : '', data.own?.role === 'maker' ? ['is-me'] : []),
      graphNode('taker', 'taker', 268, 82, 154, 100, '買い手企業', state.viewer === 'taker' ? '自社情報を表示' : '詳細は非表示', state.viewer === 'taker' ? '表示中' : '', data.own?.role === 'taker' ? ['is-me'] : []),
      graphNode('ordering', 'matcher', 180, 245, 284, 112, '受付順を固定', '5/7署名形式（模擬ノード）', `次は #${data.book.sequence + 1}`, active(['queued']) ? ['is-active'] : []),
      graphNode('mpc', 'matcher', 180, 430, 284, 120, 'MPC秘密照合', 'MP-SPDZを7プロセスで実行', `${data.mpc_nodes.filter(Boolean).length}/7 利用可`, active(['waiting_for_mpc', 'retrying']) ? ['is-active'] : []),
      graphNode('zkpi', 'zkpi', 180, 805, 284, 112, 'zkPI', '約定条件と予約枠を証明', data.last_execution?.threshold_zkpi ? '生成済み' : '待機', active(['settled']) ? ['is-active'] : []),
      graphNode('defmi', 'ledger', 180, 1005, 284, 120, 'DeFMI正本', '研究用正本を原子的に更新', `高さ ${data.defmi.height}`, active(['settled', 'waiting_for_defmi']) ? ['is-active'] : []),
    ];
    const mpcPositions = [[48, 580], [136, 580], [224, 580], [312, 580], [92, 652], [180, 652], [268, 652]];
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      nodes.push(graphNode(`mpc-${index}`, 'matcher', x, y, 72, 54, `M${index + 1}`, online ? '利用可' : '停止模擬', '', online ? [] : ['is-stopped']));
    });
    data.defmi_validators.forEach((online, index) => nodes.push(graphNode(`val-${index}`, 'ledger', 44 + index * 68, 1170, 60, 54, `D${index + 1}`, online ? '確認可' : '停止模擬', '', online ? [] : ['is-stopped'])));
    const edges = [
      edge('maker-order', 'maker', 'ordering', curveVertical(92, 132, 140, 189), flowToOrder ? 'flow' : 'idle', 'teal'),
      edge('taker-order', 'taker', 'ordering', curveVertical(268, 132, 220, 189), flowToOrder ? 'flow' : 'idle', 'teal'),
      edge('ordered-mpc', 'ordering', 'mpc', curveVertical(180, 301, 180, 370), flowToMpc ? 'flow' : 'idle', 'amber'),
      edge('mpc-zkpi', 'mpc', 'zkpi', sideCurve(180, 490, 180, 749, 338), flowToSettlement ? 'flow' : (data.last_execution ? 'done' : 'idle'), 'amber'),
      edge('zkpi-defmi', 'zkpi', 'defmi', curveVertical(180, 861, 180, 945), flowToSettlement ? 'flow' : (data.last_execution ? 'done' : 'idle'), 'blue'),
    ];
    data.mpc_nodes.forEach((online, index) => {
      const [x, y] = mpcPositions[index];
      edges.push(edge(`mpc-link-${index}`, `mpc-${index}`, 'mpc', curveVertical(x, y - 27, 180, 490), online ? 'done' : 'cut', 'amber'));
    });
    data.defmi_validators.forEach((online, index) => edges.push(edge(`val-link-${index}`, 'defmi', `val-${index}`, curveVertical(180, 1065, 44 + index * 68, 1143), online ? 'done' : 'cut', 'blue')));
    return {
      nodes,
      edges,
      labels: [
        { x: 180, y: 164, text: '署名済み注文' },
        { x: 180, y: 335, text: '順番証明', strong: true },
        { x: 275, y: 710, text: '約定結果' },
        { x: 180, y: 904, text: '追加署名なし' },
      ],
      W: 360,
      H: 1240,
    };
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

  async function toggleNode(group, index) {
    if (state.busy) return;
    try {
      await api('/api/nodes/toggle', { method: 'POST', body: JSON.stringify({ group, index }) });
      await refresh();
    } catch (error) { toast(error.message, true); }
  }

  $$('.role-tab').forEach((button) => button.addEventListener('click', async () => {
    state.viewer = button.dataset.viewer;
    $$('.role-tab').forEach((item) => {
      const active = item === button; item.classList.toggle('active', active); item.setAttribute('aria-pressed', String(active));
    });
    await refresh();
  }));

  $('#order-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!['maker', 'taker'].includes(state.viewer) || state.busy) return;
    const form = new FormData(event.currentTarget);
    const button = $('#submit-order');
    state.busy = true; button.disabled = true; button.textContent = 'デモ署名・秘密照合・決済を実行中…';
    try {
      const result = await api('/api/order', { method: 'POST', body: JSON.stringify({
        actor: state.viewer,
        side: form.get('side'),
        price: Number(form.get('price')),
        quantity: Number(form.get('quantity')),
        time_in_force: form.get('time_in_force'),
      }) });
      const status = result.worker?.status || 'executed';
      toast(status === 'waiting_for_mpc' ? '注文を暗号化キューへ保存しました' : '注文処理を正本まで確認しました');
      await refresh();
    } catch (error) { toast(error.message, true); }
    finally { state.busy = false; button.disabled = false; button.textContent = '選択した法人として注文を送る'; }
  });

  $('#retry-queue').addEventListener('click', async () => {
    if (!['maker', 'taker'].includes(state.viewer) || state.busy) return;
    state.busy = true;
    try {
      await api('/api/queue/pump', { method: 'POST', body: JSON.stringify({ actor: state.viewer }) });
      await refresh(); toast('キューの先頭を同じ受付順で確認しました');
    } catch (error) { toast(error.message, true); }
    finally { state.busy = false; }
  });

  refresh();
  window.setInterval(() => { if (!state.busy) refresh(); }, 2500);
  window.addEventListener('resize', () => { if (state.snapshot) renderGraph(state.snapshot); });
})();
