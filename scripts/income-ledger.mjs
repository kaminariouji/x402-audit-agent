// Outcome ledger — the single place a claim of income is either backed by a read or not written down.
//
// Why this file exists: this project has produced a lot of confident prose and very few settled calls.
// Every hour of work has to be answerable with "what did you measure, and did it change the wallet".
// This script appends one row per run: wallet balance (positive control included), settlement evidence,
// gate health, and the reach/visibility reads that are the actual blocker. It does not earn anything, and
// it must never be used to imply that it did.
//
// READ-ONLY: no signing, no payment, no writes outside .agents/income-ledger.json.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LEDGER = path.join(HERE, "..", "src", "agents", "income-ledger.json");
const ORIGIN = process.env.ORIGIN || "https://labored-safari-islamic.ngrok-free.dev";
const HOST = new URL(ORIGIN).host;
const PAY_TO = process.env.PAY_TO || "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b";
const CROO_ESCROW = "0x33ecdcc8dd32330ec5a62ab1986f25ed5b5d170d"; // positive control, never ours to spend
const USDC = "0x833589fcD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_RPC = process.env.BASE_RPC || "https://base-rpc.publicnode.com";
const SOL_RPC = process.env.SOL_RPC || "https://api.mainnet-beta.solana.com";
const SOL_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // from server.mjs:81, do not retype

const json = async (url, body) => {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  return (await r.json()).result ?? null;
};
const hexNum = (h) => (h == null ? null : Number(BigInt(h)));
const usdc = (raw) => (raw == null ? null : Number(BigInt(raw)) / 1e6);

// A zero is only a zero if the same read path returns non-zero for an address we KNOW has money.
async function usdcBase(addr) {
  const data = "0x70a08231" + addr.replace(/^0x/, "").padStart(64, "0");
  return usdc(hexNum(await json(BASE_RPC, { jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: USDC, data }, "latest"] })));
}

const dockerLogs = () => {
  try { return execFileSync("docker", ["logs", "--since", "24h", "x402-audit"], { encoding: "utf8", maxBuffer: 1 << 28, stdio: ["ignore", "pipe", "pipe"] }); }
  catch (e) { return `__ERR__${String(e.message).slice(0, 120)}`; }
};

const out = { asof: new Date().toISOString(), origin: ORIGIN };

// 1. does the same RPC read path work at all?
const control = await usdcBase(CROO_ESCROW);
out.control_croo_escrow_usdc = control;
out.read_path = control != null ? "OK" : "READ_FAILED — every zero below is UNKNOWN, not a zero";

// 2. our own payout address, both rails
out.payto_base_usdc = await usdcBase(PAY_TO);
let solRaw = null;
try {
  const r = await fetch(SOL_RPC, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getTokenAccountsByOwner", params: [PAY_TO, { mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyQ7Dw" }, { encoding: "jsonParsed" }] }),
    signal: AbortSignal.timeout(15000) });
  const j = (await r.json()).result;
  solRaw = (j?.value || []).reduce((a, v) => a + Number(v?.account?.data?.parsed?.info?.tokenAmount?.uiAmount ?? 0), 0);
  out.payto_solana_usdc = Number.isFinite(solRaw) ? solRaw : null;
  out.payto_solana_accounts = (j?.value || []).length;
} catch (e) { out.payto_solana_usdc = null; out.solana_read = `READ_FAILED ${String(e.message).slice(0, 60)}`; }

// 3. settlements: a paid call is one whose log line carries a pay= identity, and any response header proof.
const logs = dockerLogs();
if (logs.startsWith("__ERR__")) out.log_read = `UNREADABLE ${logs.slice(7)}`;
else {
  const paid = logs.split("\n").filter((l) => /\bpay=[a-zA-Z0-9]{6,}/.test(l));
  out.settlements_24h = paid.length;
  out.settlement_lines = paid.slice(0, 5);
  out.server_errors_24h = (logs.match(/\] 5\d\d /g) || []).length;
  out.requests_24h = (logs.match(/^\[20\d\d-\d\d-\d\dT/gm) || []).length;
  // Who is actually knocking? 2,800 hits with 0 settlements can mean "buyers looked and refused" or
  // "only scanners ever arrived", and those two need opposite fixes. The app logs ua= and pay= per line,
  // so this is a read, not an inference.
  const parsed = [];
  for (const l of logs.split("\n")) {
    const m = /^\[[^\]]+\]\s+(\d{3})\s+(GET|POST|HEAD|OPTIONS|PUT|DELETE)\s+(\S+)\s+ua=(\S+)\s+pay=(\S+)/.exec(l);
    if (m) parsed.push({ status: m[1], method: m[2], path: m[3], ua: m[4], pay: m[5] });
  }
  const top = (arr, n = 8) => [...arr.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  const tally = (f) => { const m = new Map(); for (const p of parsed) { const k = f(p); m.set(k, (m.get(k) || 0) + 1); } return m; };
  out.parsed_lines = parsed.length;
  out.by_status = Object.fromEntries(top(tally((p) => p.status), 8));
  out.top_paths = Object.fromEntries(top(tally((p) => `${p.method} ${p.path.split("?")[0]}`), 12));
  out.top_ua = Object.fromEntries(top(tally((p) => p.ua), 10));
  out.with_payment_header = parsed.filter((p) => p.pay !== "-" && p.pay !== "none").length;
}

// 4. the gate is still a gate. Retried because the free edge resets a request burst — a transport reset
//    is not a gate failure, and reporting one as one would put a false outage in the ledger.
const gateProbe = async () => {
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(`${ORIGIN}/gas`, { headers: { accept: "application/json", "ngrok-skip-browser-warning": "1" }, signal: AbortSignal.timeout(20000) });
      await r.body.cancel().catch(() => {});
      return r.status;
    } catch (e) { if (i === 2) return `FETCH_FAILED ${String(e.message).slice(0, 50)}`; await new Promise((r) => setTimeout(r, 1500)); }
  }
};
out.gate_gas = await gateProbe();

// 5. reach: the two external grades that decide whether a buyer can find us at all.
try {
  const c = await fetch(`https://agentprobe.org/api/search?q=${encodeURIComponent(HOST)}`, { headers: { accept: "application/json", "user-agent": "x402-ledger/1.0" }, signal: AbortSignal.timeout(20000) });
  const hits = (await c.json()).hits ?? [];
  out.census_rows = hits.length;
  out.census_scores = [...new Set(hits.map((h) => String(h.score)))].join("/");
} catch (e) { out.census = `READ_FAILED ${String(e.message).slice(0, 50)}`; }
try {
  const b = await fetch(`https://agent-tools.cloud/api/v1/services/${HOST.replace(/\./g, "-")}-scan`, { headers: { accept: "application/json", "user-agent": "x402-ledger/1.0" }, signal: AbortSignal.timeout(20000) });
  const o = await b.json();
  out.broker = { health: o.health, http_status: o.http_status ?? null, conformance: o.conformance ?? null, resource_count: o.resource_count ?? null, price_max: o.price_max ?? null, tx_30d: o.tx_30d ?? null, health_checked: o.health_checked ?? null };
} catch (e) { out.broker = `READ_FAILED ${String(e.message).slice(0, 50)}`; }

// 6. persist + print
const hist = existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, "utf8")) : [];
mkdirSync(path.dirname(LEDGER), { recursive: true });
hist.push(out);
writeFileSync(LEDGER, JSON.stringify(hist, null, 1));
const income = (out.payto_base_usdc ?? 0) + (out.payto_solana_usdc ?? 0);
console.log(JSON.stringify(out, null, 1));
console.log(`\nWALLET TOTAL (both rails) = ${income.toFixed(6)} USDC | read_path=${out.read_path} | settlements(24h)=${out.settlements_24h ?? "?"}`);
console.log(`rows in ledger: ${hist.length}, first=${hist[0]?.asof}, latest=${out.asof}`);
