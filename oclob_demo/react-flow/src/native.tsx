import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType } from 'react';
import { createRoot } from 'react-dom/client';
import { ReactFlowProvider } from '@xyflow/react';
import type { OclobGraphModel, OclobGraphOptions } from './main';
import { isFresh, parsePublicBook, type PublicBook } from './native-book.js';
import { BookPanel, EvidencePanel } from './native-panels.js';
import './native.css';

type GraphComponent = ComponentType<{ model: OclobGraphModel; options: OclobGraphOptions }>;

function diagram(book: PublicBook | null, narrow: boolean): OclobGraphModel {
  const w = narrow ? 160 : 225;
  const nodes: OclobGraphModel['nodes'] = Array.from({ length: 7 }, (_, party) => ({
    id: `mpc-${party}`, type: 'matcher', x: narrow ? 95 + (party % 2) * 190 : 145 + (party % 2) * 265,
    y: 55 + Math.floor(party / 2) * 105, w, h: 76, title: `MPC ${party + 1}`,
    sub: book ? 'この板に署名済み' : '署名を確認できません',
    classes: book ? [] : ['is-silent'],
  }));
  nodes.push({ id: 'feed', type: 'ledger', x: narrow ? 190 : 720, y: narrow ? 510 : 170,
    w: narrow ? 320 : 280, h: 100, title: '公開板の配信', sub: book ? `検証した更新番号 ${book.sequence}` : '有効な公開板を待っています' });
  nodes.push({ id: 'defmi', type: 'zkpi', x: narrow ? 190 : 720, y: narrow ? 680 : 380,
    w: narrow ? 320 : 280, h: 100, title: 'DeFMI 決済記録',
    sub: !book ? '確認できません' : book.finality.length ? `台帳の高さ ${book.finality[0].height} を7ノードが確認` : 'この板の更新には決済がありません' });
  const feed = nodes[7], defmi = nodes[8];
  const edges: OclobGraphModel['edges'] = nodes.slice(0, 7).map((node, index) => ({
    id: `${node.id}-feed`, source: node.id, target: 'feed',
    // Route around (never through) neighbouring cards: each node signs
    // independently; a visually chained pair would imply a false dependency.
    d: narrow ? (index % 2 === 0
      ? `M ${node.x - w / 2} ${node.y} L 5 ${node.y} L 5 445 L ${feed.x} 445 L ${feed.x} ${feed.y - 50}`
      : `M ${node.x + w / 2} ${node.y} L 375 ${node.y} L 375 445 L ${feed.x} 445 L ${feed.x} ${feed.y - 50}`)
      : (index % 2 === 0
        ? `M ${node.x} ${node.y + 38} L ${node.x} ${node.y + 53} L 555 ${node.y + 53} L 555 ${feed.y} L ${feed.x - 140} ${feed.y}`
        : `M ${node.x + w / 2} ${node.y} L 555 ${node.y} L 555 ${feed.y} L ${feed.x - 140} ${feed.y}`),
    state: book ? 'done' : 'idle', color: 'amber', own: Boolean(book),
  }));
  edges.push({ id: 'finality', source: 'defmi', target: 'feed',
    d: `M ${defmi.x} ${defmi.y - 50} L ${feed.x} ${feed.y + 50}`,
    state: book?.finality.length ? 'done' : 'idle', color: 'blue', own: Boolean(book?.finality.length) });
  return { nodes, edges, labels: [], W: narrow ? 380 : 880, H: narrow ? 745 : 455 };
}

function NativeApp({ Graph }: { Graph: GraphComponent }) {
  const [book, setBook] = useState<PublicBook | null>(null);
  const [status, setStatus] = useState<'loading' | 'ready' | 'unavailable'>('loading');
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  const [narrow, setNarrow] = useState(window.innerWidth < 650);
  const floor = useRef('0');
  const market = useRef<string | null>(null);
  const current = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  const refresh = useCallback(async () => {
    if (current.current) return;
    const controller = new AbortController();
    current.current = controller;
    setBusy(true);
    const timeout = window.setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(`/v1/book/view?minimum_sequence=${floor.current}`, {
        cache: 'no-store', credentials: 'omit', signal: controller.signal,
      });
      if (!response.ok) throw Error('unavailable');
      const value = parsePublicBook(await response.json(), floor.current);
      if (market.current && market.current !== value.market) throw Error('market_changed');
      if (!mounted.current || controller.signal.aborted) return;
      market.current = value.market;
      floor.current = value.sequence;
      setBook(value); setNow(Date.now()); setStatus('ready');
    } catch {
      if (mounted.current) { setBook(null); setStatus('unavailable'); }
    } finally {
      clearTimeout(timeout);
      current.current = null;
      if (mounted.current) setBusy(false);
    }
  }, []);
  useEffect(() => {
    mounted.current = true;
    void refresh();
    const poll = window.setInterval(() => void refresh(), 5000);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    const resize = () => setNarrow(window.innerWidth < 650);
    window.addEventListener('resize', resize);
    return () => { mounted.current = false; current.current?.abort(); clearInterval(poll); clearInterval(clock); window.removeEventListener('resize', resize); };
  }, [refresh]);
  const visible = book && status === 'ready' && isFresh(book, now) ? book : null;
  const model = useMemo(() => diagram(visible, narrow), [visible, narrow]);
  const options: OclobGraphOptions = {
    ariaLabel: '7台のMPCノードの署名とDeFMI決済記録から公開板を確認する構成',
    phase: visible ? visible.sequence : status, phaseLabel: '証跡のつながり（通信の実況ではありません）',
    noRoundText: '', legend: [{ type: 'matcher', label: '計算ノードの署名' }, { type: 'ledger', label: '決済後の記録' }],
    legendNotes: ['線は公開板を確認するための証跡の関係です。', 'ノードの稼働監視や送金中のアニメーションではありません。'], reducedMotion: true,
  };
  return <div className="native-app">
    <header className="native-header"><div><a className="native-brand" href="/">OCLOB</a><span className="native-mode">実サービス接続 · 読み取り専用</span></div>
      <button type="button" disabled={busy} onClick={() => void refresh()}>{busy ? '確認中…' : '今すぐ確認'}</button></header>
    <main>
      <div className="native-heading"><div><h1>公開板と決済の確認</h1><p>{visible?.market ?? market.current ?? '市場を確認しています'}</p></div>
        <span className={`native-status ${visible ? 'native-ok' : ''}`} role="status">{visible ? '有効な公開板を取得' : status === 'loading' ? '公開板を取得中' : book ? '公開板の有効期限切れ' : '公開板を確認できません'}</span></div>
      {!visible && <div className="native-notice" role={status === 'loading' ? 'status' : 'alert'}>
        {status === 'loading' ? 'MPCノードの署名と決済後の記録を確認しています。' : 'まだ公開板がない、有効期限が切れた、または配信元に接続できない状態です。古い価格は表示しません。5秒ごとに再確認します。'}
      </div>}
      <div className="native-layout">
        <aside><BookPanel book={visible}/>{visible && <EvidencePanel book={visible}/>}</aside>
        <section className="native-panel native-network" aria-labelledby="network-title"><h2 id="network-title">どこで確認された公開板か</h2>
          <p className="native-muted">7台の計算ノードが署名した同じ板を、決済後の記録と照合して配信します。</p>
          <div id="network-graph" style={{ height: narrow ? 870 : 650 }}><ReactFlowProvider><Graph key={narrow ? 'narrow' : 'wide'} model={model} options={options}/></ReactFlowProvider></div>
          <details className="native-limits"><summary>この画面で確認できること・できないこと</summary>
            <p>確認できるのは、公開価格・残数量・更新順序・計算ノードの署名・約定を伴う更新の決済後の記録です。</p>
            <p>注文前の内容、注文者、法人の在庫・資金は公開しません。法人としての注文操作や残高確認は、別の認証付き画面の実装が必要です。</p>
            <p>7ノードは計算参加者を表します。独立した7事業者による運用や、DeFMIの合意をブラウザーが直接検証したことを意味しません。</p>
          </details>
        </section>
      </div>
    </main><footer className="native-footer">OCLOB · 公開情報のみ · 自動確認 5秒間隔 · <a href="/v1/book" target="_blank" rel="noreferrer">署名付き原本 JSON</a></footer>
  </div>;
}

export function startNativeApp(Graph: GraphComponent) {
  const container = document.getElementById('native-root');
  if (container) createRoot(container).render(<NativeApp Graph={Graph}/>);
}
