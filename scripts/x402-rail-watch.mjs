// x402 rail watch — the deterministic sensor behind the CROO-style read-only cron.
//
// Why a script and not prompt instructions: the CROO watcher inferred "sweep counter bug"
// from RestartCount=0 and was wrong (the host rebooted, so the in-process counter legitimately
// reset). A model reasoning about a counter it does not understand produces confident, wrong
// findings. So this file answers the questions with measurements, and the cron only interprets
// the printed lines per the rules at the bottom.
//
// READ-ONLY. No keys, no transactions, no wallet access, no writes outside its own state file.
// It deliberately does NOT import server.mjs: importing it starts a listener (app.listen at module
// load) and this script must not create a second copy of the paid app on the host.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// A fire drill must never overwrite the real baseline, or the next honest run compares against a
// borrowed balance and reports a phantom delta.
const STATE = path.join(HERE, process.env.FIRE_DRILL_PAY_TO ? "x402-rail-fire-drill.json" : "x402-rail-last.json");
const ORIGIN = process.env.ORIGIN || "https://labored-safari-islamic.ngrok-free.dev";
// The two BIG reads of this sensor go to the local container, not the tunnel. Measured 2026-10-15 against
// the deployed build: /discovery/resources = 122,406 bytes and POST /mcp tools/list = 216,994 bytes, so one
// run pulled ~345 KB of data that does not change between a deploy and its own loopback port. This cron fires
// every 30 minutes = 48 runs/day ≈ 16.5 MB/day ≈ 0.5 GB/month of our own telemetry, on an ngrok free plan that
// goes fully dark at a monthly byte cap (ERR_NGROK_725 — it has already taken the rail out twice).
// What STAYS on the public origin is deliberately tiny and is the only thing that can only be measured there:
// GET /health (999 B) and GET /chain/heads (1,841 B) — edge liveness and whether the gate answers publicly.
const DOC_ORIGIN = process.env.DOC_ORIGIN || `http://127.0.0.1:${process.env.LOCAL_PORT || 10000}`;
const edgeBytes = { requests: 0, bytes: 0 };
const edgeFetch = async (url, opt) => {
  const r = await fetch(url, opt);
  if (url.startsWith(ORIGIN)) { edgeBytes.requests++; try { edgeBytes.bytes += Buffer.byteLength(await r.clone().text()); } catch { /* unreadable body: count the request only */ } }
  return r;
};
// Overridable ONLY so the sensor can be fire-drilled against an address that demonstrably receives
// USDC (the CROO escrow). A watcher that has never printed its own alert line is not trusted to
// print "nothing arrived". Run the drill with scripts/x402-rail-fire-drill.sh; never point the real
// cron at another wallet.
const PAY_TO = process.env.FIRE_DRILL_PAY_TO || "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b";
const PAY_TO_SOL = process.env.FIRE_DRILL_PAY_TO_SOL || "5NWSPyJChL2NJf3oEr6Mh4vLvG5S3qQmf5S4v7v8wEV4";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const USDC_SOL = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
// Both pinned Base hosts, in production order. One of them throttles free traffic regularly,
// so a single-host read is how you "discover" a balance went to zero.
const BASE_HOSTS = ["https://mainnet.base.org", "https://base.drpc.org"];
const SOL_HOSTS = ["https://api.mainnet-beta.solana.com", "https://solana-rpc.publicnode.com", "https://solana.drpc.org"];
// Measured, not remembered: `curl -s $ORIGIN/discovery/resources | jq .items.length` on 2026-09-24
// against the deployed container = 138 (1 audit + /price + /search_tokens + 5 hand-written data ops +
// 128 route-table reads + /a2a + /mcp). A surface that changes under us IS an incident — either
// something redeployed without the instruments or the gate table drifted — so this stays a hard
// equality and EXPECTED_ENDPOINTS is the override for the deploy that intentionally changes it.
const EXPECTED_ENDPOINTS = Number(process.env.EXPECTED_ENDPOINTS || 146);
const CONTAINER = process.env.CONTAINER || "x402-audit";
// The host side of the container's published loopback map (-p 127.0.0.1:10000:10000). Probing it is how
// the sensor tells "the ngrok edge is offline" apart from "the app is down" without touching the app.
const LOCAL_PORT = process.env.LOCAL_PORT || "10000";

const errors = [];
const warns = [];
const note = (m) => { errors.push(m); };
// A warning is expected behaviour worth printing (a truncated lookback on the first run after a
// gap); a note means part of the measurement is MISSING. Only notes may veto the "no money"
// verdict — conflating the two makes every normal cold start look like a broken sensor.
const warn = (m) => { warns.push(m); };

async function rpc(hosts, method, params, tries = 3) {
  let lastErr = "no host attempted";
  for (let i = 0; i < tries; i++) {
    for (const host of hosts) {
      try {
        const r = await fetch(host, {
          method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
          signal: AbortSignal.timeout(25_000),
        });
        const text = await r.text();
        let j; try { j = JSON.parse(text); } catch { lastErr = `${host}: non-JSON http ${r.status}`; continue; }
        if (j.error) { lastErr = `${host}: ${j.error.message ?? "rpc error"}`; continue; }
        if (j.result === undefined || j.result === null) { lastErr = `${host}: empty result`; continue; }
        return { result: j.result, host };
      } catch (e) { lastErr = `${host}: ${e.name} ${e.message}`; }
    }
    if (i < tries - 1) await new Promise((r) => setTimeout(r, 1200 * (i + 1)));
  }
  return { err: lastErr };
}
const pad = (h) => String(h).replace(/^0x/, "").toLowerCase().padStart(64, "0");
const hexOf = (n) => `0x${n.toString(16)}`;
const usdc = (raw) => (raw == null ? null : Number(BigInt(raw)) / 1e6);
const isWord = (x) => /^0x[0-9a-fA-F]{64}$/.test(String(x));

// ---- 1. the rail itself: is the tunnel up, is the container up, is the gate still gating ----
// THREE failure shapes, not two. A public 404 carrying an Ngrok-Error-Code header is the ngrok EDGE
// answering — the domain exists but no agent session is behind it — while the container is perfectly
// healthy. That is neither "leak" (200) nor "container dead" (502/timeout), and on 2026-09-27 it sat
// undetected for ~18h because the sensor had no branch for it. The local probe is what separates the
// edge being down from the app being down, so the reader never has to guess from one number.
let health = null, items = null, gate = null, ngrokErr = null, localHealth = null, localGate = null;
try {
  const h = await edgeFetch(`${ORIGIN}/health`, { signal: AbortSignal.timeout(25_000) });
  health = h.status;
  ngrokErr = h.headers.get("ngrok-error-code") ?? ngrokErr;
} catch (e) { note(`health fetch failed: ${e.name} ${e.message}`); }
// One fetch answers two things: how many priced endpoints we advertise, and WHICH PATHS those are. The paid
// path set is read from the wire instead of hardcoded, because the old filter only recognised
// /chain/ | /price | /markets | /search_tokens | /audit — an unpaid 2xx on any of the other ~130 priced routes
// (every /market/* venue read, /tvl, /gas, /stablecoins, the /market/x402-* demand band) was invisible to the
// leak count. Same "stale list hides leaks" failure the advertised-tool set already fixed for /mcp.
let paidPaths = null;
try {
  const d = await edgeFetch(`${DOC_ORIGIN}/discovery/resources`, { signal: AbortSignal.timeout(25_000) });
  if (d.status !== 200) { items = `http ${d.status}`; }
  else {
    const j = await d.json();
    const rows = j?.resources || j?.items || null;
    items = Array.isArray(rows) ? rows.length : "no resources key";
    if (Array.isArray(rows) && rows.length) {
      // The document publishes BOTH shapes: `resources` as bare path strings and `items` as objects with a
      // `resource` URL. A reader that assumes only one of them yields an empty set, and an empty set here
      // would quietly narrow the leak filter back to its legacy prefixes.
      paidPaths = new Set(rows.map((r) => {
        if (typeof r === "string") { try { return new URL(r).pathname; } catch { return r.startsWith("/") ? r : null; } }
        try { return new URL(r.resource).pathname; } catch { return null; }
      }).filter(Boolean));
    }
  }
} catch (e) { note(`discovery fetch failed: ${e.name} ${e.message}`); }
// One unpaid GET on a paid route proves tunnel + container + gate in a single shot. Anything
// other than 402 is the finding: 200 = leak, 502/timeout = tunnel up but container dead.
try {
  const p = await edgeFetch(`${ORIGIN}/chain/heads`, { signal: AbortSignal.timeout(25_000) });
  gate = p.status;
  ngrokErr = p.headers.get("ngrok-error-code") ?? ngrokErr;
} catch (e) { note(`gate probe failed: ${e.name} ${e.message}`); }

// Read-only probe straight at the published port. Never fatal: if the container is bound elsewhere or
// the map changed, this reports FETCH_FAILED and the public numbers still stand on their own.
for (const [path, setter] of [["/health", (c) => { localHealth = c; }], ["/chain/heads", (c) => { localGate = c; }]]) {
  try { const r = await fetch(`http://127.0.0.1:${LOCAL_PORT}${path}`, { signal: AbortSignal.timeout(8_000) }); setter(r.status); }
  catch (e) { setter(null); note(`local${path} probe failed: ${e.name} ${e.message}`); }
}

// 1b. the advertised MCP tool names, read from the same document a buyer reads. The log records only
// `tool=<name>`, so without this set an unpaid 2xx for a mistyped name (our own probes produce many,
// and the answer is a free "not found") is indistinguishable from an unpaid 2xx for a real tool.
// Derived from the wire, never hardcoded here: a hardcoded name list is how a stale sensor hides leaks.
let advertised = null;
{
  const H = { "content-type": "application/json", accept: "application/json, text/event-stream", "ngrok-skip-browser-warning": "1" };
  const post = async (body, sid) => edgeFetch(`${DOC_ORIGIN}/mcp`, {
    method: "POST", headers: { ...H, ...(sid ? { "mcp-session-id": sid } : {}) },
    body: JSON.stringify(body), signal: AbortSignal.timeout(25_000),
  });
  try {
    const init = await post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "rail-watch", version: "0" } } });
    const sid = init.headers.get("mcp-session-id");
    const res = await post({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, sid);
    const text = await res.text();
    const sse = text.match(/^data: (.*)$/m);
    const names = (JSON.parse(sse ? sse[1] : text)?.result?.tools || []).map((t) => t.name);
    if (names.length) advertised = new Set(names);
    else note(`tools/list advertised 0 tools — unpaid 2xx on /mcp stays UNCLASSIFIED, not clean`);
  } catch (e) { note(`tools/list fetch failed: ${e.name} ${e.message} — unpaid /mcp 2xx stays UNCLASSIFIED, not clean`); }
}

// ---- 2. money in: transfers into payTo, over the window since the last run ----
const prev = existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : null;
const sinceMs = prev?.at ? Date.parse(prev.at) : Date.now() - 3_600_000 * 24;
let headBlock = 0, settled = null, balNow = null, ethNow = null, control = "MISSING";
const head = await rpc(BASE_HOSTS, "eth_blockNumber", []);
if (head.err) {
  note(`head read failed: ${head.err} — settlement count is UNKNOWN, not zero`);
} else {
  headBlock = Number(BigInt(head.result));
  // Base is ~2s/block and free nodes refuse wide ranges, so walk back in chunks and stop at the
  // window edge instead of silently reporting a narrower lookback than was asked for.
  // Base is ~2s/block and free nodes cap both the range AND the payload size, so walk back in
  // small chunks. 4000-block chunks were measured to fail on the pair (the error named only the
  // last host tried, which hid WHICH chunk broke); 1000 blocks is comfortably under both caps.
  // A cron that runs every 30 min needs ~1 chunk; only the first run after a gap walks far back.
  const wantFrom = Math.max(0, headBlock - Math.ceil((Date.now() - sinceMs) / 2000));
  const CHUNK = 1_000, MAX_CHUNKS = 30;
  const from = Math.max(wantFrom, headBlock - CHUNK * MAX_CHUNKS);
  if (from > wantFrom) warn(`window truncated to ${CHUNK * MAX_CHUNKS} blocks (~16h) — settlements older than that in the window were NOT scanned`);
  const logs = [];
  let scanErr = null;
  for (let end = headBlock; end >= from; end -= CHUNK) {
    const start = Math.max(from, end - CHUNK + 1);
    const r = await rpc(BASE_HOSTS, "eth_getLogs", [{ address: USDC_BASE, fromBlock: hexOf(start), toBlock: hexOf(end),
      topics: [TRANSFER, null, `0x${pad(PAY_TO)}`] }]);
    if (r.err) { scanErr = `blocks ${start}..${end}: ${r.err}`; break; }
    logs.push(...r.result);
    if (start <= from) break;
  }
  if (scanErr) note(`eth_getLogs failed at ${scanErr} — settlement count is UNKNOWN, not zero`);
  else {
    settled = logs.length;
    const sumIn = logs.reduce((a, l) => a + BigInt(l.data || "0x0"), 0n);
    if (logs.length) {
      console.log(`\nSETTLED INTO payTo (${logs.length} transfer(s) in blocks ${from}..${headBlock}):`);
      for (const l of logs) console.log(`  block=${Number(BigInt(l.blockNumber))} from=${l.topics?.[1]?.slice(-40)} amt=${usdc("0x" + (l.data || "0").slice(2))} tx=${l.transactionHash}`);
    }
    console.log(`settled_this_window=${logs.length}  amount_in_usdc=${usdc("0x" + (sumIn > 0n ? sumIn.toString(16) : "0"))}`);
  }

  // ---- 3. wallet position + delta, and the control that makes a 0 mean something ----
  const b = await rpc(BASE_HOSTS, "eth_call", [{ to: USDC_BASE, data: "0x70a08231" + pad(PAY_TO) }, "latest"]);
  balNow = b.err ? null : (isWord(b.result) ? b.result : null);
  if (b.err || !isWord(b.result)) note(`USDC balanceOf READ_FAILED: ${b.err ?? `malformed ${String(b.result).slice(0, 18)}`} — this is NOT $0`);
  const e = await rpc(BASE_HOSTS, "eth_getBalance", [PAY_TO, "latest"]);
  ethNow = e.err ? null : e.result;
  if (e.err) note(`native balance READ_FAILED: ${e.err} — this is NOT 0`);
  // Control: the CROO escrow demonstrably holds USDC on Base. Read it through the identical path.
  // If it comes back 0, the reader (or the host) is lying and our own 0 proves nothing.
  const c = await rpc(BASE_HOSTS, "eth_call", [{ to: USDC_BASE, data: "0x70a08231" + pad("0x33ecdcc8dd32330ec5a62ab1986f25ed5b5d170d") }, "latest"]);
  control = !c.err && isWord(c.result) && BigInt(c.result) > 0n ? `OK (${usdc(c.result).toFixed(2)} USDC via ${c.host})`
    : !c.err && isWord(c.result) ? "ZERO — CONTROL FAILED, a 0 for us is unproven" : `READ_FAILED (${c.err})`;

  console.log(`\nBASE wallet ${PAY_TO}`);
  console.log(`  usdc_balance=${balNow === null ? "READ_FAILED" : usdc(balNow).toFixed(6)}  native=${ethNow === null ? "READ_FAILED" : (Number(BigInt(ethNow)) / 1e18).toFixed(9)} ETH`);
  if (prev && balNow !== null && prev.usdcRaw != null) {
    const d = Number(BigInt(balNow) - BigInt(prev.usdcRaw)) / 1e6;
    console.log(`  delta_since=${prev.at} : ${d >= 0 ? "+" : ""}${d.toFixed(6)} USDC`);
  } else if (!prev) console.log("  delta_since=none (first run — baseline recorded)");
  console.log(`  control(CROO escrow)=${control}`);
}

// ---- 4. the Solana side of the same rail ----
let solAccts = null, solUsdc = null;
{
  const r = await rpc(SOL_HOSTS, "getTokenAccountsByOwner", [PAY_TO_SOL, { mint: USDC_SOL }, { encoding: "jsonParsed", commitment: "confirmed" }]);
  if (r.err) note(`solana token accounts READ_FAILED: ${r.err} — NOT 0`);
  else {
    solAccts = (r.result.value ?? []).length;
    const total = (r.result.value ?? []).reduce((a, v) => a + Number(v.account?.data?.parsed?.info?.tokenAmount?.uiAmountString ?? 0), 0);
    solUsdc = total;
    console.log(`\nSOLANA wallet ${PAY_TO_SOL}`);
    console.log(`  usdc_token_accounts=${solAccts}  usdc_total=${total.toFixed(6)}`);
  }
  const s = await rpc(SOL_HOSTS, "getBalance", [PAY_TO_SOL, { commitment: "confirmed" }]);
  // Public Solana hosts answer getBalance as {context, value:{lamports}} and, on some of them, as
  // a bare number — printing NaN for the second shape reads as "0 SOL" to whoever is on duty.
  const lam = s.err ? null : (typeof s.result?.value === "number" ? s.result.value : s.result?.value?.lamports);
  console.log(`  native_sol=${lam == null ? "READ_FAILED" : (Number(lam) / 1e9).toFixed(9)}`);
  if (lam == null) note(`solana native READ_FAILED: ${s.err ?? `malformed ${JSON.stringify(s.result).slice(0, 80)}`} — NOT 0`);
}

// The app's own request-log shape is `[<iso ts>] <3-digit status> <METHOD> <path> ua=... pay=...`.
// Anything else (venue notices, boot banners, SDK noise) is prose and has no response status, so a status
// read from it is invented. Returns null for non-request lines — callers must handle null, not coerce it.
const responseStatus = (l) => { const m = /^\[[^\]]+\]\s+(\d{3})\s+(?:GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS)\s/.exec(l); return m ? m[1] : null; };

// ---- 5. container log: 5xx, and any 2xx that carried a paid payload ----
// The counts are hoisted so the verdict below can only ever restate what this block measured. An
// earlier copy hardcoded "0 paid-route 2xx | 0 server errors", so a real leak would have printed a
// clean verdict — the same failure mode that made this file's "gate PROVEN INTACT" claim false.
console.log(`\nACCESS LOG (${CONTAINER}, last ${Math.max(1, Math.round((Date.now() - sinceMs) / 60000))} min)`);
let leakCount = null, fiveCount = null, unclassifiedCount = null, freeNotFoundCount = null;
try {
  const since = `${Math.max(2, Math.ceil((Date.now() - sinceMs) / 60000))}m`;
  // LOG_FILE is a positive-control hook: point it at a captured log containing a known leak-shaped
  // line and confirm this section reports it. Without it the leak branch can only ever be asserted,
  // because producing a real one requires an actual leak.
  const snapshot = process.env.LOG_FILE;
  const raw = snapshot ? readFileSync(snapshot, "utf8") : execFileSync("docker", ["logs", "--since", since, CONTAINER], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  console.log(`  source=${snapshot ? `snapshot ${snapshot}` : `docker logs ${CONTAINER} --since ${since}`}`);
  const lines = raw.split("\n").filter((l) => responseStatus(l) !== null);
  const counts = {};
  for (const l of lines) { const s = responseStatus(l); counts[s] = (counts[s] ?? 0) + 1; }
  console.log(`  statuses: ${Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}x${v}`).join(" ") || "none"} (request lines only: ${lines.length} of ${raw.split("\n").length} log lines)`);
  const freeOk = /rpc=(initialize|notifications\/initialized|tools\/list)\b|tool=demo_audit|tool=x402_rail_heartbeat/;
  // A 2xx with no payment header on a paid path is the leak shape. `pay=` tells the two apart: pay=-
  // (or an absent field, treated conservatively) means we served something nobody bought.
  const unpaid = (l) => !/\bpay=[^-\s]/.test(l);
  const pathOf = (l) => (l.match(/ (?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^ ]+)/) || [])[1] || "";
  const httpPaid2xx = lines.filter((l) => {
    const st = responseStatus(l);
    if (st === null || st[0] !== "2" || !unpaid(l) || / OPTIONS | HEAD /.test(l)) return false;
    const p = pathOf(l).split("?")[0];
    // /mcp and /a2a ARE priced surfaces in the discovery document, but most traffic on them is the free
    // protocol handshake (initialize, tools/list, notifications). The MCP branch below judges those
    // correctly against the advertised tool set; judging them here too turns every honest liveness check
    // into a fake "leak". Measured the day the wire-derived path set was introduced: 15 handshake lines
    // were counted as unpaid paid-route 2xx.
    if (p === "/mcp" || p === "/a2a") return false;
    // The discovery document is the authority on what is priced. When it could not be read, fall back to the
    // old prefix list and say so — a narrower filter must never silently report "clean".
    if (paidPaths && paidPaths.size) return paidPaths.has(p);
    return /(^\/chain\/)|^\/price$|^\/markets$|^\/search_tokens$|^\/audit$/.test(p);
  });
  const mcp2xx = lines.filter((l) => { const st = responseStatus(l); return st !== null && st[0] === "2" && /^\[[^\]]+\]\s+\d{3}\s+POST \/(mcp|a2a)\b/.test(l) && /rpc=tools\/call/.test(l) && !freeOk.test(l) && unpaid(l); });
  // Only a name the server advertises can actually be served; an unadvertised one is the free
  // "not found" answer. If the advertised set could not be read, every such line stays a candidate.
  const mcpLeaks = advertised ? mcp2xx.filter((l) => advertised.has((l.match(/ tool=(\S+)/) || [])[1])) : mcp2xx;
  const mcpFreeNames = advertised ? mcp2xx.filter((l) => !advertised.has((l.match(/ tool=(\S+)/) || [])[1])) : [];
  const paid2xx = httpPaid2xx.concat(mcpLeaks);
  leakCount = paid2xx.length;
  unclassifiedCount = advertised ? null : mcp2xx.length;
  console.log(`  paid_route_2xx_unpaid=${leakCount}${paid2xx.length ? "\n    " + paid2xx.slice(0, 5).join("\n    ") : ""}`);
  console.log(`  unpaid_2xx_for_unadvertised_tool=${mcpFreeNames.length}${mcpFreeNames.length ? ` (free "not found" answers — mistyped or case-shifted names, e.g. ${mcpFreeNames.slice(0, 3).map((l) => (l.match(/ tool=(\S+)/) || [])[1]).join(", ")})` : ""}`);
  freeNotFoundCount = mcpFreeNames.length;
  if (!paidPaths || !paidPaths.size) note("paid-path set unreadable from /discovery/resources — HTTP leak filter fell back to the legacy prefixes; an unpaid 2xx on any OTHER priced route is INVISIBLE this run");
  const five = lines.filter((l) => { const s = responseStatus(l); return s && s[0] === "5" && s !== "503"; });
  fiveCount = five.length;
  console.log(`  server_errors=${fiveCount}${five.length ? "\n    " + five.slice(0, 5).join("\n    ") : ""}`);
  // Classifier control, planted and asserted EVERY run. The old filter was `/ 5[0-9][0-9] /` over any line,
  // which counts prose: a `[venue] ... (HTTP 500 upstream)` notice and a `marked unreadable for 300s` TTL
  // both matched, so this sensor could report 5 server errors while the ledger's anchored counter reported 0
  // for the same window — two instruments, same log, opposite numbers, and neither was lying about its rule.
  // A filter that cannot distinguish a served 5xx from a sentence ABOUT a 5xx is not a measurement.
  {
    const probeLines = [
      "[2026-10-15T00:00:00.000Z] 502 GET /price ua=probe pay=- rpc=-",
      "[venue] api.kraken.com marked unreadable for 300s — its routes refuse the challenge unpaid (HTTP 500 upstream)",
      "[2026-10-15T00:00:01.000Z] 402 GET /gas ua=probe pay=-",
      "[2026-10-15T00:00:02.000Z] 503 GET /btc/fees ua=probe pay=- upstream_unavailable charged:false",
    ];
    const got = probeLines.filter((l) => { const s = responseStatus(l); return s && s[0] === "5" && s !== "503"; }).length;
    if (got !== 1) console.log(`  FAIL status-classifier control: counted ${got} server errors in a 4-line fixture, expected exactly 1 (the served 502)`);
    else console.log("  ok   status-classifier control: 1 served 5xx counted, prose 500 + 402 + 503-refusal not counted");
  }
  // A 503 here is the app refusing to CHARGE for a reading it cannot take (all of a route's public sources
  // marked unreachable), not a service error: it is answered before the payment gate, so nothing settled.
  // Counting it as a 5xx would train us to ignore the real one.
  const unavail = lines.filter((l) => responseStatus(l) === "503");
  console.log(`  uncharged_refusals_503=${unavail.length}${unavail.length ? "\n    " + unavail.slice(0, 6).join("\n    ") : ""}`);
} catch (e) { note(`docker logs unreadable: ${String(e.message).slice(0, 120)} — log section above is ABSENT, not clean`); }

// ---- 5b. what the public agent census says about us (read-only, one request per run) ----
// agentprobe.org crawls 37 registries + 7 well-known conventions and grades every paid resource by
// GETting it unpaid: 402 with the PAYMENT-REQUIRED header = 100, 402 without = 80, 404/405 = 20, and a
// 2xx on a paid resource = 60/protocol-mismatch (they read an open resource as "payment not enforced").
// That grade is EXTERNAL evidence of a buyer-facing defect: our POST-only /audit scored 20 on every
// probe for a week while every one of our own checks passed, because our checks always used the right
// verb and a real crawler does not. Their API is keyless GET; we ask once per run, name ourselves in
// the UA, and never write to them.
const CENSUS_HOST = process.env.CENSUS_HOST || new URL(ORIGIN).host;
// Format-only kinds, from their methodology ("format checks only; not part of the alive/conformant
// headline"). A sub-100 there is a document-format nit; a sub-100 in a protocol kind means an outside
// probe could not read the endpoint as live-and-payable — that one is a finding.
const CENSUS_FORMAT_KINDS = new Set(["llms-txt", "robots", "agents-txt", "sigdir", "site"]);
let censusHttp = null, censusRows = null, censusFindings = null;
if (process.env.CENSUS === "0") note("census read skipped (CENSUS=0) — our public grade is UNKNOWN this run");
else {
  try {
    const cr = await fetch(`https://agentprobe.org/api/search?q=${encodeURIComponent(CENSUS_HOST)}`, {
      headers: { accept: "application/json", "user-agent": `x402-rail-watch/1.0 (+${ORIGIN}/llms.txt; our own watchdog reading our own grade)` },
      signal: AbortSignal.timeout(20_000),
    });
    censusHttp = cr.status;
    if (cr.ok) censusRows = (await cr.json()).hits ?? [];
    else note(`census http ${censusHttp} — grade UNKNOWN this run, do not read a missing finding as a good grade`);
  } catch (e) { note(`census fetch failed: ${e.name} ${String(e.message).slice(0, 80)} — grade UNKNOWN, absence of a finding is NOT a pass`); }
}
console.log("\n-- public agent census (agentprobe.org, read-only GET) --");
if (censusRows === null) console.log(`  rows=NOT_READ http=${censusHttp ?? "FETCH_FAILED"} — our outside grade is UNKNOWN`);
else {
  const proto = censusRows.filter((h) => !CENSUS_FORMAT_KINDS.has(h.kind));
  const low = proto.filter((h) => Number(h.score) < 100);
  censusFindings = low.length;
  console.log(`  rows=${censusRows.length} protocol_rows=${proto.length} scored_below_100=${low.length} http=${censusHttp}`);
  for (const h of censusRows) {
    console.log(`  ${String(h.score ?? "?").padStart(4)} ${String(h.kind).padEnd(9)} ${String(h.outcome).padEnd(18)} ${String(h.url).replace(/^https?:\/\/[^/]+/, "")}`);
  }
  for (const h of low) {
    console.log(`  FINDING  ${h.kind} ${h.url} scored ${h.score} (${h.outcome}) — an outside probe cannot read this as live-and-payable; check the verb, the bare-request path and the 402 header on it`);
  }
}

// ---- 6. verdict ----
// The rule the whole file exists to enforce: a zero may only be called a zero when the same code
// path produced a non-zero for an address that demonstrably has money.
if (!control.startsWith("OK")) note(`positive control (CROO escrow) returned "${control}" — the Base balance above is UNPROVEN, do not print $0`);
const sensorBroken = errors.length > 0;
console.log("\n-- rail availability --");
console.log(`  health=${health ?? "FETCH_FAILED"} unpaid_gate_probe=${gate ?? "FETCH_FAILED"} discovery_items=${items ?? "FETCH_FAILED"} (expected ${EXPECTED_ENDPOINTS})`);
console.log(`  ngrok_error_code=${ngrokErr ?? "none"} local_container health=${localHealth ?? "FETCH_FAILED"} gate=${localGate ?? "FETCH_FAILED"} (127.0.0.1:${LOCAL_PORT})`);
// Cost accounting for the monthly cap, printed every run so a future "why is the tunnel dark" has an answer
// instead of a theory. This should read a few KB; if it climbs, something big got pointed back at the edge.
console.log(`  edge_cost_this_run=${edgeBytes.requests} public requests, ${edgeBytes.bytes.toLocaleString()} bytes (documents and tools/list read from ${DOC_ORIGIN})`);
console.log(`  edge_offline=${ngrokErr !== null || (health === 404 && localHealth === 200) ? "YES — ngrok is answering, the container is fine; nothing connects them" : "no"}`);
// ---- 5c. what a browser-ish client actually receives at this edge ----
// Measured 2026-09-28 by reading the buyer-side aggregator's own record of us
// (GET https://agent-tools.cloud/api/v1/services/labored-safari-islamic-ngrok-free-dev-scan):
//   description = "ngrok is the fastest way to put anything on the internet with a single command."
//   health = "down", resource_count = 11 while we publish 143.
// That is not their bug — the ngrok FREE edge swaps its own HTML interstitial into every response whose
// User-Agent looks like a browser (Mozilla/… Chrome/…), on EVERY path including /.well-known/x402, and it
// returns it as HTTP 200, so a crawler parses ngrok's marketing copy instead of our terms and marks the
// service dead. The trigger is the UA, not the Accept header (curl / python-requests / Googlebot with
// Accept: text/html all still receive our JSON), which is why the money path is clean: a real x402 client
// sends a library UA and gets the 402 challenge. This probe reads the edge with a browser UA so the
// discovery path stops being invisible to us. It is a WARN, never a FAIL: an interstitial is a reach
// problem, not a gate problem, and must not invalidate the settlement measurement.
let edgeUaStatus = null, edgeUaServed = null;
try {
  const r = await fetch(`${ORIGIN}/health`, {
    headers: {
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
      accept: "application/json",
    },
    signal: AbortSignal.timeout(20_000),
  });
  const t = await r.text();
  edgeUaStatus = r.status;
  edgeUaServed = /ngrok/i.test(t) && !/"ok"\s*:\s*true/.test(t) ? "NGROK_INTERSTITIAL" : "our_json";
} catch (e) { edgeUaServed = `FETCH_FAILED ${e.name}`; }
console.log(`  browser-UA probe /health: http=${edgeUaStatus ?? "n/a"} served=${edgeUaServed ?? "n/a"} (Accept: application/json)`);
if (edgeUaServed === "NGROK_INTERSTITIAL") warn(`EDGE_INTERSTITIAL: a client that sends a browser User-Agent gets ngrok's own HTML at HTTP 200 on every path here, so its crawler/bot records us as dead (this is exactly how agent-tools.cloud stored health=down + ngrok's sentence as our description). Nothing in the app can intercept it — it is injected at the edge. The x402 money path is unaffected: real clients send library UAs and receive the 402.`);
else if (edgeUaServed !== "our_json") warn(`browser-UA probe did not run (${edgeUaServed}) — the edge's behaviour for browser clients is UNKNOWN this run, not proven clean`);
console.log("\n-- measurement notes --");
for (const m of warns) console.log(`  warn  ${m}`);
for (const m of errors) console.log(`  FAIL  ${m}`);
const moneyIn = (settled > 0) || (balNow && BigInt(balNow) > 0n) || (solUsdc !== null && solUsdc > 0);
let verdict;
if (gate === null) verdict = "SENSOR: rail unreachable — report the fetch error, the rail status is UNKNOWN";
else if (ngrokErr !== null || (gate === 404 && localHealth === 200)) verdict = `TUNNEL DOWN (DOWNTIME, NOT A LEAK): origin returns ${gate}${ngrokErr ? ` with Ngrok-Error-Code=${ngrokErr}` : ""} while the container answers ${localHealth}/${localGate} on 127.0.0.1:${LOCAL_PORT} — the paid app is healthy and unreachable from outside. The gate CANNOT be judged from the public origin while the edge is offline; do not call this a leak and do not call the rail live.`;
else if (gate !== 402) verdict = `GATE/AVAILABILITY: unpaid /chain/heads returned ${gate} — expected 402. Look here first. (200 = leak; 502/timeout = tunnel up, container dead; local says health=${localHealth ?? "FETCH_FAILED"} gate=${localGate ?? "FETCH_FAILED"})`;
else if (moneyIn) verdict = `SETTLEMENT OR BALANCE PRESENT — settled=${settled} usdc=${balNow === null ? "READ_FAILED" : usdc(balNow)} sol_usdc=${solUsdc ?? "READ_FAILED"} sol_accounts=${solAccts} — escalate, this is the money signal`;
else if (sensorBroken) verdict = "SENSOR INCOMPLETE — do NOT report \"no money\"; report the FAIL lines as a bug";
else if (items !== EXPECTED_ENDPOINTS) verdict = `SURFACE CHANGED: discovery items=${items}, expected ${EXPECTED_ENDPOINTS} — something redeployed or the feed broke`;
// An unpaid 2xx on a paid path is a leak unless it is the free "not found" answer for a name the
// server never advertises — which is what our own probes produce. That split is made above against
// the live tools/list, so nothing here has to guess: any remaining candidate escalates.
else if (leakCount === null) verdict = "LOG SENSOR DIDN'T RUN — unpaid paid-route 2xx and 5xx counts UNKNOWN, do not report a clean gate";
else if (leakCount > 0 || unclassifiedCount > 0 || fiveCount > 0) verdict = `INSPECT: ${leakCount} unpaid 2xx on advertised paid tools/paths, ${unclassifiedCount ?? 0} unclassified, ${fiveCount} 5xx — the printed lines name each one; a 2xx with pay=- on a real tool is a LEAK, fix it before anything else`;
else verdict = `no settlement | wallet ${balNow === null ? "READ_FAILED" : usdc(balNow)} USDC base + ${solUsdc === null ? "READ_FAILED" : solUsdc.toFixed(6)} USDC solana (${solAccts} token accounts), control OK | gate 402 | items=${items} | ${leakCount} unpaid paid-route 2xx (${freeNotFoundCount ?? 0} unadvertised-name answers, all classified) | ${fiveCount} server errors | census=${censusFindings === null ? "NOT_READ (grade unknown, not a pass)" : censusFindings + " outside-probe findings"}`;
console.log(`\nVERDICT: ${verdict}`);

// Downtime is the one revenue risk the per-run window cannot express: sinceMs is the last run, so a
// tunnel dark for 18h looks like a normal 30-minute sample. Carry the first offline run forward instead.
// "first detected" is NOT "when it broke": this branch only exists from the run that added it, and the
// tunnel had already been dark ~18h. The authoritative start is the last external request in the
// container's own access log — that number is printed separately below so nobody reads it as the onset.
const edgeOffline = ngrokErr !== null || (gate === 404 && localHealth === 200);
const downSince = edgeOffline ? (prev?.edgeOffline ? (prev.downSince ?? prev.at) : new Date().toISOString()) : null;
if (downSince) console.log(`  FIRST DETECTED ${downSince} (~${((Date.now() - Date.parse(downSince)) / 3.6e6).toFixed(1)} h of sensor-visible downtime) — onset is earlier; read the last external ua= line in the container log`);

writeFileSync(STATE, JSON.stringify({ at: new Date().toISOString(), headBlock, usdcRaw: balNow, ethRaw: ethNow,
  settled, items, gate, leakCount, fiveCount, errors: errors.length, edgeOffline, downSince,
  ngrokErr, localHealth, localGate }, null, 2));
