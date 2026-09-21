// Measure the x402 buyer market from the only source that cannot lie: Base USDC transfers.
// A $0.001-$0.10 transfer to a wallet that many distinct senders pay is an x402 settlement;
// one wallet making many such payments to MANY distinct receivers is a funded buying agent.
// Read-only. No keys, no funds, no writes.
const RPC = process.env.BASE_RPC || "https://mainnet.base.org";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CHUNK = Number(process.env.CHUNK || 100);
const CHUNKS = Number(process.env.CHUNKS || 12);

let lastError = "unknown";
const rpc = async (method, params) => {
  for (let attempt = 0; attempt < 4; attempt++) {
    const r = await fetch(RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(30_000),
    }).catch(() => null);
    if (!r) { await new Promise((x) => setTimeout(x, 800 * (attempt + 1))); continue; }
    const j = await r.json().catch(() => null);
    if (j?.result !== undefined) return j.result;
    const msg = String(j?.error?.message || `http ${r.status}`);
    lastError = msg;
    if (/limit|too (many|large)|429|rate|range/i.test(msg)) break;
    await new Promise((x) => setTimeout(x, 1500 * (attempt + 1)));
  }
  throw new Error(lastError);
};

const addr = (t) => "0x" + t.slice(-40).toLowerCase();
const latest = BigInt(await rpc("eth_blockNumber", []));
const logs = [];
for (let c = 0; c < CHUNKS; c++) {
  const to = latest - BigInt(c * CHUNK);
  const from = to - BigInt(CHUNK - 1);
  if (from <= 0n) break;
  const part = await rpc("eth_getLogs", [{
    address: USDC, topics: [TRANSFER],
    fromBlock: "0x" + from.toString(16), toBlock: "0x" + to.toString(16),
  }]).catch((e) => { console.log(`chunk ${c} skipped: ${e.message}`); return []; });
  logs.push(...part);
  console.log(`blocks ${from}-${to}: ${part.length} transfers (cumulative ${logs.length})`);
}

const MIN = 1_000n;          // $0.001
const MAX = 100_000n;        // $0.10
const tiny = [];
for (const l of logs) {
  const v = BigInt(l.data || "0x0");
  if (v >= MIN && v <= MAX) tiny.push({ v, from: addr(l.topics[1]), to: addr(l.topics[2]), block: Number(parseInt(l.blockNumber, 16)) });
}
const distinct = (k) => new Set(tiny.map((t) => t[k])).size;
const group = (k) => {
  const m = new Map();
  for (const t of tiny) {
    const e = m.get(t[k]) || { n: 0, peers: new Set(), usd: 0n };
    e.n += 1; e.peers.add(k === "from" ? t.to : t.from); e.usd += t.v;
    m.set(t[k], e);
  }
  return m;
};
const receivers = group("to");
const senders = group("from");
const fmt = (a) => (Number(a) / 1e6).toFixed(4);

console.log(`\nwindow: ${CHUNK * CHUNKS} blocks (~${Math.round(CHUNK * CHUNKS * 2 / 60)} min, base block ~2s), ${logs.length} USDC transfers total`);
console.log(`micro-payments 0.001-0.10 USDC: ${tiny.length} (${distinct("from")} senders -> ${distinct("to")} receivers), total $${fmt(tiny.reduce((s, t) => s + t.v, 0n))}`);
console.log(`\nTop receivers of micro-payments (candidate x402 sellers):`);
for (const [w, e] of [...receivers].sort((a, b) => b[1].n - a[1].n).slice(0, 12)) {
  console.log(`  ${w}  payments=${e.n} distinctPayers=${e.peers.size} usd=$${fmt(e.usd)}`);
}
console.log(`\nTop senders of micro-payments (candidate funded buying agents):`);
for (const [w, e] of [...senders].sort((a, b) => b[1].peers.size - a[1].peers.size).slice(0, 12)) {
  console.log(`  ${w}  payments=${e.n} distinctReceivers=${e.peers.size} usdSpent=$${fmt(e.usd)}`);
}
console.log(`\nAmount histogram of micro-payments (atomic -> count, distinct senders):`);
{
  const by = new Map();
  for (const t of tiny) {
    const e = by.get(t.v) || { n: 0, senders: new Set() };
    e.n += 1; e.senders.add(t.from);
    by.set(t.v, e);
  }
  for (const [v, e] of [...by].sort((a, b) => b[1].n - a[1].n).slice(0, 14)) {
    console.log(`  $${fmt(v).padEnd(8)} payments=${String(e.n).padStart(5)} senders=${e.senders.size}`);
  }
}
console.log(`\nRecurring-buyer test (senders that paid >=5 DIFFERENT receivers):`);
{
  const pro = [...senders].filter(([, e]) => e.peers.size >= 5);
  console.log(`  ${pro.length} wallets, ${pro.reduce((s, [, e]) => s + e.n, 0)} payments, $${fmt(pro.reduce((s, [, e]) => s + e.usd, 0n))} spent`);
}
console.log(`\nx402 FINGERPRINT — receivers paid by >=5 DISTINCT senders at ONE round amount.`);
// A single fixed price collected from many independent payers is what a per-call API looks like.
// Exchange withdrawals and airdrops fan out the other way (one sender, many receivers).
{
  const byPair = new Map();
  for (const t of tiny) {
    const k = `${t.to}|${t.v}`;
    const e = byPair.get(k) || new Set();
    e.add(t.from);
    byPair.set(k, e);
  }
  const hits = [...byPair].filter(([, s]) => s.size >= 5).sort((a, b) => b[1].size - a[1].size);
  console.log(`  ${hits.length} (receiver, price) pairs qualify:`);
  for (const [k, s] of hits.slice(0, 15)) {
    const [w, v] = k.split("|");
    console.log(`  ${w}  price=$${fmt(BigInt(v))}  distinctPayers=${s.size}`);
  }
}
console.log(`\nAre we in this market as a receiver? ${receivers.has("0x7c8a3c26bd579c5176a29a5a8ae80536319fa94b") ? "YES" : "no (wallet still $0 from this window)"}`);
