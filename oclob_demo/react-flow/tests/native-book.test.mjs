// Synthetic shape/rendering UNIT tests only. Native financial/UI acceptance
// uses the actual remote MPC/DeFMI network, never these fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { parsePublicBook, isFresh, formatInteger, sortedLevels } from '../.test-build/native-book.js';
import { BookPanel, EvidencePanel } from '../.test-build/native-panels.js';
const now = 1000000;
function fixture(settled = false) {
  return { version: 1, market: 'unit-only', sequence: '18446744073709551615', round: 'ab'.repeat(32),
    levels: [{ side: 'sell', price: '101', quantity: '30' }, { side: 'sell', price: '100', quantity: '15' }],
    nodes: Array.from({ length: 7 }, (_, party) => ({ party, signer: 'cd'.repeat(32), issued_at: '999', valid_until: '1100', settlement_required: settled })),
    finality: settled ? Array.from({ length: 7 }, (_, party) => ({ party, height: '18446744073709551615', receipt: 'ef'.repeat(32) })) : [] };
}
test('decimal u64 quantities and sequence are exact; no Number conversion', () => {
  const book = parsePublicBook(fixture(), '18446744073709551615', now);
  assert.equal(formatInteger(book.sequence), '18,446,744,073,709,551,615');
  assert.deepEqual(sortedLevels(book, 'sell').map(l => l.price), ['100', '101']);
  assert.equal(isFresh(book, now), true);
  assert.equal(isFresh(book, 1100000), false);
});
test('reject malformed, expired, incomplete and regressing evidence', () => {
  const mutations = [
    b => { b.sequence = 1; }, b => { b.sequence = '18446744073709551616'; },
    b => { b.sequence = '01'; }, b => { b.nodes.pop(); }, b => { b.nodes[6].party = 0; },
    b => { b.nodes[0].valid_until = '1000'; }, b => { b.nodes[0].issued_at = '1001'; },
    b => { b.levels[0].quantity = '-1'; }, b => { b.levels[1] = b.levels[0]; },
    b => { b.nodes[0].settlement_required = true; }, b => { b.round = 'x'; },
  ];
  for (const mutate of mutations) { const b = fixture(); mutate(b); assert.throws(() => parsePublicBook(b, '0', now)); }
  assert.throws(() => parsePublicBook({ ...fixture(), sequence: '3' }, '4', now));
  const b = fixture(true); b.finality[0].height = '1';
  assert.throws(() => parsePublicBook(b, '0', now));
});
test('unavailable view does not render stale price rows or a zero-balance substitute', () => {
  const html = renderToStaticMarkup(createElement(BookPanel, { book: null }));
  assert.ok(html.includes('価格と数量を表示しません'));
  assert.ok(!html.includes('<table'));
});
test('circuit capacity includes eight resting slots plus the arriving slot', () => {
  const b = fixture();
  b.levels = Array.from({ length: 9 }, (_, i) => ({ side: 'sell', price: String(100 + i), quantity: '1' }));
  assert.equal(parsePublicBook(b, '0', now).levels.length, 9);
  b.levels.push({ side: 'sell', price: '109', quantity: '1' });
  assert.throws(() => parsePublicBook(b, '0', now));
});
test('actual shape renders levels, exact height and verification boundary without health claims', () => {
  const book = parsePublicBook(fixture(true), '0', now);
  const html = renderToStaticMarkup(createElement(BookPanel, { book }));
  assert.ok(html.indexOf('>100<') < html.indexOf('>101<'));
  assert.ok(html.includes('買い注文はありません'));
  const evidence = renderToStaticMarkup(createElement(EvidencePanel, { book }));
  assert.ok(evidence.includes('18,446,744,073,709,551,615'));
  assert.ok(evidence.includes('現在の生存確認ではありません'));
  assert.ok(!evidence.includes('稼働中'));
});
