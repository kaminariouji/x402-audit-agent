// Gate-bypass probe for EVERY priced data route against a target origin.
// The payment gate is keyed by the exact string "GET /chain/x", but Express routing is by default
// NOT case-sensitive and NOT strict about a trailing slash. If a handler answers while the gate
// fails to recognise the path, the paid payload goes out free — that is the whole point of this file.
// The class was measured live on 2026-09-24, so the instrument reads the server's own route table:
// a new band (MARKET_ROUTES) or a new route is covered by the next run without editing this file.
// Read-only: never sends money, never touches the wallet.
// DEFAULT TARGET IS LOCAL. This is 136 routes x 19 variants ~= 2,600 requests; over the ngrok edge that is
// the single biggest consumer of the monthly byte cap that has twice taken the rail dark, and the gate being
// tested is the same deployed build answering on 127.0.0.1:10000 (verified: identical 402, 1,841 bytes,
// advertising the PUBLIC origin and the real payTo). Run with ORIGIN=<public> after a deploy to prove the
// edge forwards it too — that is one deliberate run, not the default.
import { PROBE_ORIGIN, target, meter } from "../scripts/probe-target.mjs";
const O = PROBE_ORIGIN;
const M = meter();
console.log(`target: ${target(O)}`);
process.env.PORT ??= "10993";
const m = await import("../services/x402-mcp/server.mjs");
const routes = m.DATA_ROUTES;

const out = [];
let bad = 0;
// A 503 that states upstream_unavailable + charged:false is the app REFUSING to sell a reading it cannot
// take (every public source for that route is currently unreachable). No payment was possible and no data
// was served, so it satisfies the invariant this probe exists for — it must not be reported as a defect,
// and it must not be silently skipped either: the refusal is named in the pass line.
const refusedUnpaid = (status, text = "") => status === 503 && /"error"s*:s*"upstream_unavailable"/.test(text) && /"charged"s*:s*false/.test(text);
const say = (ok, name, detail) => {
  if (!ok) bad++;
  out.push(`${ok ? "ok  " : "FAIL"} ${name}${detail ? " :: " + String(detail).slice(0, 220) : ""}`);
};
// ~420 short HTTPS calls in a row trip resets at the ngrok free edge. Every request here is an
// idempotent GET/HEAD/OPTIONS with no side effect, so a bounded retry is safe and keeps the probe
// from reporting the transport as a gate failure.
const fetchT = async (url, opt, tries = 4) => {
  let last;
  for (let i = 0; i < tries; i++) {
    try { return await M.fetch(url, opt); } catch (e) { last = e; await new Promise((r) => setTimeout(r, 400 * (i + 1))); }
  }
  throw last;
};

// Variants: [label, path builder, HTTP method]. All must NOT return the paid payload.
const variants = (p) => [
  ["exact", () => p, "GET"],
  ["trailing slash", () => p + "/", "GET"],
  ["double trailing slash", () => p + "//", "GET"],
  ["leading double slash", () => "/" + p, "GET"],
  ["internal double slash", () => p.replace("/", "//"), "GET"],
  ["Title-Case", () => p.split("/").map((s) => s && s[0].toUpperCase() + s.slice(1)).join("/"), "GET"],
  ["UPPERCASE", () => p.toUpperCase(), "GET"],
  ["mixed Case", () => p.replace(/^\/(chain|market)/i, (seg) => seg.split("").map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join("")), "GET"],
  ["encoded slash", () => p.replace("/", "%2F"), "GET"],
  ["encoded next-char", () => p.slice(0, 6) + "%62" + p.slice(7), "GET"],
  ["trailing dot", () => p + ".", "GET"],
  ["json suffix", () => p + ".json", "GET"],
  ["trailing space", () => p + "%20", "GET"],
  ["matrix param", () => p + ";a=b", "GET"],
  ["trailing hash", () => p + "#frag", "GET"],
  ["backslash before last seg", () => p.replace(/\/([^/]*)$/, "/\\$1"), "GET"],
  ["HEAD exact", () => p, "HEAD"],
  ["HEAD trailing slash", () => p + "/", "HEAD"],
  ["OPTIONS exact", () => p, "OPTIONS"],
];

for (const r of routes) {
  const qs = new URLSearchParams(r.args.map((a) => [a.name, String(a.example ?? "")])).toString();
  const paidKeys = (r.out || []).map((e) => e[0]).filter(Boolean);
  const hits = [];
  for (const [label, build, method] of variants(r.path)) {
    let url;
    try { url = new URL(O + build() + (method === "GET" || method === "HEAD" ? "?" + qs : "")); }
    catch { continue; }
    let res, text = "";
    try {
      res = await fetchT(url, { method, headers: { accept: "application/json" }, redirect: "manual" });
      await new Promise((r) => setTimeout(r, 60));
      text = await res.text();
    } catch (e) {
      say(false, `${r.path} ${label}`, "request error " + e.message);
      continue;
    }
    // A payload leak = a 2xx/3xx carrying one of the route's own result keys or its example data.
    let leaks = false;
    if (res.status < 400) {
      let body = null;
      try { body = JSON.parse(text); } catch { /* non-json: only the raw-text scan below can catch it */ }
      if (body && typeof body === "object") {
        const flat = JSON.stringify(body);
        leaks = paidKeys.some((k) => k in (body || {})) || /"(chainId|blockNumber|balanceWei|gasWei|tokenId|owner|nativeWei)"/.test(flat);
      } else {
        leaks = paidKeys.some((k) => text.includes(String(k))) || text.length > 400;
      }
    }
    if (leaks) hits.push(`${label} -> ${res.status}`);
    if (method === "GET" && label === "exact") {
      say(res.status === 402 || refusedUnpaid(res.status, text), `${r.path} exact unpaid -> 402`, refusedUnpaid(res.status, text) ? `${res.status} REFUSED-UNPAID (vendor unreachable, no challenge possible)` : res.status);
    }
  }
  say(hits.length === 0, `${r.path} no variant serves the payload`, hits.join(" | ") || "all variants refused");
}

// Method-override headers only matter if a handler is mounted for GET and something rewrites the method.
for (const hdr of [{ "x-http-method-override": "GET" }, { "x-method-override": "GET" }, { "method-override": "GET" }]) {
  const r = await fetchT(`${O}/chain/balance?${new URLSearchParams({ chain: "base", address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" })}`,
    { method: "POST", headers: { ...hdr, "content-type": "application/json" }, body: "{}" }).catch(() => null);
  say(!r || r.status >= 400, `POST /chain/balance with ${Object.keys(hdr)[0]}`, r?.status);
}

// ---- the 10 routes that shipped before /chain/* ----
// The same rewrite class was measured green-to-red on these first: /Price, /PRICE and /price/ all
// served a live quote unpaid on 2026-09-24. Keep them in the instrument, not just the new surface.
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const legacy = [
  ["GET", "/price", `?address=${USDC}`, /"found":true|"price"|"liquidity"/],
  ["GET", "/search_tokens", "?q=pepe&limit=2", /"results":\[\{"|"query":"pepe"/],
  ["GET", "/markets", "?vs=usd&limit=2", /"rows":\[\{"rank"/],
  ["GET", "/tvl", "?limit=2", /"rows":\[\{"chain"/],
  ["GET", "/stablecoins", "?limit=2", /"rows":\[\{|"circulating"/],
  ["GET", "/trending", "?limit=2", /"tokens":\[\{|"dex"/],
  ["GET", "/gas", "?chains=base", /"gasPriceGwei"/],
  ["POST", "/audit", "", /"signalCount"|"findings":\[\{"/],
  ["POST", "/mcp", "", /"result":\{"content"/],
  ["POST", "/a2a", "", /"kind":"task"/],
];
const bodyFor = (p) => p === "/mcp"
  ? JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "top_markets", arguments: { vs: "usd", limit: 2 } } })
  : JSON.stringify({ jsonrpc: "2.0", id: 1, method: "message/send", params: { message: { role: "user", parts: [{ kind: "data", data: { code: "state.earnings.total_usd += 999;" } }] } } });
for (const [method, p, qs, payloadRe] of legacy) {
  const vs = [
    ["exact", p], ["trailing slash", p + "/"], ["double slash", "//" + p.slice(1)],
    ["Title", "/" + p.slice(1, 2).toUpperCase() + p.slice(2)], ["UPPER", p.toUpperCase()],
    ["mid-Case", p.slice(0, 3) + p.slice(3, 4).toUpperCase() + p.slice(4)],
  ];
  const hits = [];
  for (const [label, vpath] of vs) {
    const opt = method === "GET" ? { headers: { accept: "application/json" } }
      : { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: p === "/audit" ? JSON.stringify({ code: "state.earnings.total_usd += 999; // LEAKMARK-7q9z", filename: "a.js" }) : bodyFor(p) };
    const r = await fetchT(O + vpath + qs, opt).catch(() => null);
    await new Promise((r) => setTimeout(r, 60));
    if (!r) { hits.push(`${label}: request error`); continue; }
    const text = await r.text().catch(() => "");
    if (r.status < 400 && payloadRe.test(text)) hits.push(`${label} -> ${r.status}`);
    if (label === "exact") say(r.status === 402 || refusedUnpaid(r.status, text), `${method} ${p} unpaid -> 402`, refusedUnpaid(r.status, text) ? `${r.status} REFUSED-UNPAID (vendor unreachable)` : `${r.status} ${text.slice(0, 70)}`);
  }
  say(hits.length === 0, `${method} ${p} no variant serves the payload`, hits.join(" | ") || "all variants refused");
}


console.log(out.filter((l) => l.startsWith("FAIL")).join("\n") || out.join("\n"));
console.log(bad
  ? `\nBYPASS PROBE FAIL (${bad}) — see FAIL lines above`
  : `\nBYPASS PROBE OK — ${routes.length} routes x 19 path/method variants: nothing served without payment`);
M.report("variant battery");
process.exit(bad ? 1 : 0);
