export type Level = { side: 'buy' | 'sell'; price: string; quantity: string };
export type AttestingNode = { party: number; signer: string; issued_at: string; valid_until: string; settlement_required: boolean };
export type Finality = { party: number; height: string; receipt: string };
export type PublicBook = { version: 1; market: string; sequence: string; round: string; levels: Level[]; nodes: AttestingNode[]; finality: Finality[] };

const u64Max = 18446744073709551615n;
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('invalid_book');
  return value as Record<string, unknown>;
}
function integer(value: unknown, nonzero = false): string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)
      || BigInt(value) > u64Max || (nonzero && value === '0')) throw Error('invalid_integer');
  return value;
}
function digest(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw Error('invalid_digest');
  return value;
}
function party(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 6) throw Error('invalid_party');
  return value;
}
function list(value: unknown, max: number): unknown[] {
  if (!Array.isArray(value) || value.length > max) throw Error('invalid_list');
  return value;
}
function allParties(values: { party: number }[]): boolean {
  return values.length === 7 && new Set(values.map(v => v.party)).size === 7;
}

// UI shape/freshness checks are NOT browser-side cryptographic verification.
// The isolated HTTP gateway verifies the pinned TLS feed and every signature.
export function parsePublicBook(value: unknown, minimum = '0', now = Date.now()): PublicBook {
  const v = record(value);
  if (v.version !== 1 || typeof v.market !== 'string' || !v.market || v.market.length > 64) throw Error('invalid_book');
  const sequence = integer(v.sequence, true);
  if (BigInt(sequence) < BigInt(integer(minimum))) throw Error('regression');
  // The circuit accepts MAX_MATCH_SLOTS (8) resting slots plus one arrival.
  const levels = list(v.levels, 9).map(item => {
    const row = record(item);
    if (row.side !== 'buy' && row.side !== 'sell') throw Error('invalid_side');
    return { side: row.side, price: integer(row.price, true), quantity: integer(row.quantity, true) } as Level;
  });
  if (new Set(levels.map(l => `${l.side}:${l.price}`)).size !== levels.length) throw Error('duplicate_level');
  const nodes = list(v.nodes, 7).map(item => {
    const row = record(item);
    if (typeof row.settlement_required !== 'boolean') throw Error('invalid_finality_flag');
    return { party: party(row.party), signer: digest(row.signer), issued_at: integer(row.issued_at),
      valid_until: integer(row.valid_until), settlement_required: row.settlement_required };
  });
  if (!allParties(nodes)) throw Error('missing_attestations');
  const time = BigInt(Math.floor(now / 1000));
  const first = nodes[0];
  if (nodes.some(n => n.issued_at !== first.issued_at || n.valid_until !== first.valid_until
    || n.settlement_required !== first.settlement_required
    || BigInt(n.issued_at) > time || BigInt(n.valid_until) <= time
    || BigInt(n.valid_until) - BigInt(n.issued_at) > 300n)) throw Error('expired_or_inconsistent');
  const finality = list(v.finality, 7).map(item => {
    const row = record(item);
    return { party: party(row.party), height: integer(row.height, true), receipt: digest(row.receipt) };
  });
  if (first.settlement_required ? !allParties(finality) : finality.length !== 0) throw Error('missing_finality');
  if (finality.some(f => f.height !== finality[0].height || f.receipt !== finality[0].receipt)) throw Error('inconsistent_finality');
  return { version: 1, market: v.market, sequence, round: digest(v.round), levels, nodes, finality };
}

export function isFresh(book: PublicBook, now: number): boolean {
  const seconds = BigInt(Math.floor(now / 1000));
  return book.nodes.every(n => BigInt(n.issued_at) <= seconds && seconds < BigInt(n.valid_until));
}
export function formatInteger(value: string): string { return BigInt(value).toLocaleString('ja-JP'); }
export function displayTime(value: string): string {
  const seconds = BigInt(value);
  if (seconds > 8640000000000n) return `${value}（Unix秒）`;
  return new Date(Number(seconds) * 1000).toLocaleTimeString('ja-JP', { hour12: false });
}
export function sortedLevels(book: PublicBook, side: Level['side']): Level[] {
  return book.levels.filter(l => l.side === side).sort((a, b) => {
    const order = BigInt(a.price) < BigInt(b.price) ? -1 : BigInt(a.price) === BigInt(b.price) ? 0 : 1;
    return side === 'sell' ? order : -order;
  });
}
