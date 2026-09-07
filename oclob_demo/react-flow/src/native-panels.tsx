import { displayTime, formatInteger, sortedLevels, type PublicBook } from './native-book.js';

export function BookPanel({ book }: { book: PublicBook | null }) {
  return <section className="native-panel native-book" aria-labelledby="book-title">
    <h2 id="book-title">公開板</h2>
    <p className="native-muted">価格ごとに合計した残数量です。注文者は公開しません。</p>
    {!book ? <p className="native-empty">現在の板を確認できるまで、価格と数量を表示しません。</p> :
      (['sell', 'buy'] as const).map(side => {
        const rows = sortedLevels(book, side);
        return <div className={`native-side native-${side}`} key={side}>
          <h3>{side === 'sell' ? '売り注文' : '買い注文'} <span>{rows.length} 価格帯</span></h3>
          {!rows.length ? <p className="native-empty">公開されている{side === 'sell' ? '売り' : '買い'}注文はありません。</p> :
            <table><thead><tr><th scope="col">価格</th><th scope="col">残数量</th></tr></thead>
              <tbody>{rows.map(row => <tr key={row.price}><td>{formatInteger(row.price)}</td><td>{formatInteger(row.quantity)}</td></tr>)}</tbody>
            </table>}
        </div>;
      })}
    <p className="native-muted native-small">単位は市場設定の整数単位です。通貨換算・保有残高ではありません。</p>
  </section>;
}

export function EvidencePanel({ book }: { book: PublicBook }) {
  return <section className="native-panel" aria-labelledby="evidence-title">
    <h2 id="evidence-title">この公開板の確認情報</h2>
    <dl className="native-evidence">
      <div><dt>板の更新番号</dt><dd>{formatInteger(book.sequence)}</dd></div>
      <div><dt>署名した計算ノード</dt><dd>{book.nodes.length} / 7</dd></div>
      <div><dt>この表示の有効期限</dt><dd>{displayTime(book.nodes[0].valid_until)}</dd></div>
      <div><dt>この更新の決済</dt><dd>{book.finality.length ? '決済後の記録を 7 ノードが確認' : '決済を伴わない板の更新'}</dd></div>
      {book.finality.length > 0 && <div><dt>DeFMI 台帳の更新回数</dt><dd>{formatInteger(book.finality[0].height)}</dd></div>}
    </dl>
    <details><summary>技術的な詳細（識別値と各ノードの署名鍵）</summary>
      <p>処理の識別値</p><code>{book.round}</code>
      {book.finality.length > 0 && <><p>決済記録の識別値</p><code>{book.finality[0].receipt}</code></>}
      <ul className="native-keys">{book.nodes.map(node => <li key={node.party}>計算ノード {node.party + 1}<code>{node.signer}</code></li>)}</ul>
    </details>
    <p className="native-muted native-small">署名・決済記録・有効期限は API サーバーが登録済みの鍵で検査しています。ブラウザー自身による暗号検証や、各ノードの現在の生存確認ではありません。</p>
  </section>;
}
