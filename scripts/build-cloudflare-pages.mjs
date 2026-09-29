// Builds the static site for Cloudflare Pages (project name of your choice -> <proj>.pages.dev).
//
// WHY this exists as separate files: every crawler that reads us through the tunnel either gets ngrok's
// own HTML interstitial (browser-shaped User-Agent, HTTP 200, on EVERY path) or, once a month, a flat
// HTTP 403 `ERR_NGROK_725 — account bandwidth limit reached`. Neither is our answer, and we cannot patch
// either from inside the app: the edge injects them before the request reaches us. A static Pages origin is
// the free, permanent, capless, interstitial-free place to publish exactly the facts a buyer's agent needs,
// pointing AT the tunnel where the paid compute actually runs.
//
// WHAT this is not: it is not a mirror of the data. No prices are typed here, no route list is pasted. Every
// number is read from the running service at build time, and the build aborts if a document cannot be read,
// because the failure mode we already lived through once is a discovery document that quietly keeps
// advertising last month's terms.
//
// Usage:  node scripts/build-cloudflare-pages.mjs [--origin https://<tunnel>] [--out cloudflare-pages]
import fs from "node:fs";
import path from "node:path";

const arg = (n, d) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.split("=").slice(1).join("=") : d; };
const ORIGIN = arg("origin", "http://127.0.0.1:10000");
const OUT = arg("out", "cloudflare-pages");

async function get(u) {
  const r = await fetch(u, { headers: { accept: "application/json", "ngrok-skip-browser-warning": "1" }, signal: AbortSignal.timeout(25_000) });
  const t = await r.text();
  if (!r.ok) throw new Error(`${u} -> HTTP ${r.status}: ${t.slice(0, 120)}`);
  if (/<ngrok|bandwidth limit/i.test(t)) throw new Error(`${u} -> the edge answered, not our app. Start the container (or wait out the tunnel quota) before rebuilding.`);
  try { return JSON.parse(t); } catch { throw new Error(`${u} -> body is not JSON: ${t.slice(0, 80)}`); }
}

const terms = await get(`${ORIGIN}/.well-known/x402`);
const disc = await get(`${ORIGIN}/discovery/resources`);
const card = await get(`${ORIGIN}/.well-known/mcp/server-card.json`);

const items = disc.items || [];
if (items.length < 100) throw new Error(`live service advertised only ${items.length} resources — refusing to publish a page built from a partial read`);
const urlOf = (it) => { try { return new URL(it.resource); } catch { return null; } };
const priceOf = (it) => {
  const a = (it.accepts || [])[0];
  if (!a || a.amount == null) return null;
  return Number(a.amount) / 10 ** Number(a.decimals ?? 6);
};
const prices = items.map(priceOf).filter((v) => v != null && v > 0);
if (prices.length !== items.length) throw new Error(`only ${prices.length}/${items.length} resources carry a readable amount — refusing to guess the rest`);
const min = Math.min(...prices), max = Math.max(...prices);
const nets = disc.networks || [];
const band = new Map();
for (const it of items) {
  const u = urlOf(it); const p = u ? u.pathname : "?";
  const k = p.startsWith("/market/x402") ? "Rail demand map" : p.startsWith("/market/") ? "Exchange / venue reads" : p.startsWith("/chain/") ? "Chain state reads" : "Legacy + audit";
  band.set(k, (band.get(k) || 0) + 1);
}
const free = card.free_tools || [];
const rows = items.map((it) => {
  const u = urlOf(it);
  return { method: it.method || "GET", path: u ? u.pathname : String(it.resource), title: it.title || it.name || "", price_usd: priceOf(it),
    networks: (it.accepts || []).map((a) => a.network), sample: u ? `${u.origin}${u.pathname}${(it.args || it.parameters || []).length ? "?" : ""}` : "" };
});

const built = new Date().toISOString();
const site = {
  service: terms.name, version: terms.version, built_at: built, built_from: ORIGIN,
  protocol: "x402 (HTTP 402 + PAYMENT-REQUIRED header; v1 and v2 both accepted)",
  currency: "USDC", price_usd: { min, max }, networks: nets,
  pay_to: disc.payTo, assets: Object.fromEntries(items.flatMap((i) => i.accepts || []).map((a) => [a.network, a.asset]).filter(([k, v]) => k && v)),
  priced_resources: items.length, mcp_tools: (card.tools || []).length || items.length, free_tools_before_paying: free,
  resource_bands: Object.fromEntries(band),
  how_to_pay: "Send GET/POST to the resource URL with no payment; the 402 body carries accepts[] with scheme, network, token contract, amount in atomic units and the payTo address. Sign it (EIP-3009 for USDC on Base, SPL Token Transfer for Solana), retry with the PAYMENT-SIGNATURE header, and the answer is the data. There is no account, no API key and no rate limit tied to identity.",
  endpoints: { origin: ORIGIN, mcp: `${ORIGIN}/mcp`, a2a: `${ORIGIN}/a2a`, terms: `${ORIGIN}/.well-known/x402`, resources: `${ORIGIN}/discovery/resources`, openapi: `${ORIGIN}/openapi.json`, briefing: `${ORIGIN}/llms.txt`, server_card: `${ORIGIN}/.well-known/mcp/server-card.json`, agent_card: `${ORIGIN}/.well-known/agent-card.json` },
  resources: rows,
  provenance: "Generated by scripts/build-cloudflare-pages.mjs from the running service. Nothing on this page is typed by hand; if it disagrees with the origin, the origin is right and this file is stale.",
};

fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, "x402-info.json"), JSON.stringify(site, null, 1));
fs.writeFileSync(path.join(OUT, "discovery.json"), JSON.stringify({ built_at: built, origin: ORIGIN, count: rows.length, resources: rows }, null, 1));

const li = (a, b) => `    <tr><td>${a}</td><td><code>${b}</code></td></tr>`;
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
fs.writeFileSync(path.join(OUT, "index.html"), `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(terms.name)} — x402 pay-per-call agent (${rows.length} priced resources)</title>
<meta name="description" content="${esc(`${rows.length} x402-priced crypto reads at $${min}-$${max} per call in USDC on Base and Solana, plus a crypto-bot honesty audit. MCP + HTTP, no account, no API key.`)}">
<link rel="alternate" type="application/json" title="x402 terms" href="${esc(site.endpoints.terms)}">
<link rel="alternate" type="application/json" title="resource list" href="${esc(site.endpoints.resources)}">
<link rel="canonical" href="https://x402-audit.pages.dev/">
<style>
 body{font:16px/1.65 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:48rem;margin:3rem auto;padding:0 1.2rem;color:#111;background:#fff}
 h1{font-size:1.45rem;margin:0 0 .2rem} h2{font-size:1.05rem;margin-top:2rem} p.lede{color:#444;margin-top:0}
 code{background:#f4f4f5;padding:.1rem .35rem;border-radius:5px;font-size:.9em}
 table{border-collapse:collapse;width:100%;font-size:.93rem} td,th{border-bottom:1px solid #e5e7eb;padding:.4rem .3rem;text-align:left;vertical-align:top}
 ul{padding-left:1.1rem} a{color:#1d4ed8} .foot{color:#666;font-size:.82rem;margin-top:2.5rem;border-top:1px solid #eee;padding-top:1rem}
 .now{background:#fef9c3;border:1px solid #fde68a;border-radius:8px;padding:.6rem .8rem;font-size:.9rem}
</style></head><body>
<h1>${esc(terms.name)}</h1>
<p class="lede">${rows.length} crypto reads you pay for one at a time, over x402. No account, no API key, no free tier beyond the two tools named below. This page is static on purpose: the live service sits behind a tunnel that either shows browser-shaped User-Agents an interstitial or, once a month, runs out of bandwidth — and a crawler should never have to depend on that.</p>
<div class="now"><strong>Where the compute actually is.</strong> Paid calls run at <code>${esc(ORIGIN.replace(/^http:\/\//, "https://"))}</code>. If that answers 403 with <code>ERR_NGROK_725</code>, the tunnel is out of monthly bandwidth and the service is alive but unreachable; nothing in this table changes because of it.</div>
<h2>What it costs</h2>
<table>
${li("Protocol", site.protocol)}
${li("Assets", "USDC (ERC-20 on Base, SPL on Solana)")}
${li("Price", `$${min}–$${max} per call, metered per resource`)}
${li("Priced resources", `${rows.length} (also ${site.mcp_tools} MCP tools)`)}
${li("Free before paying", free.map((f) => `<code>${esc(f)}</code>`).join(", ") || "none")}
${li("Payout (Base)", disc.payTo?.["eip155:8453"] || "?")}
${li("Payout (Solana)", disc.payTo?.["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"] || "?")}
</table>
<h2>What's in the ${rows.length}</h2>
<table><tr><th>Band</th><th>Count</th></tr>
${[...band.entries()].map(([k, v]) => `    <tr><td>${esc(k)}</td><td>${v}</td></tr>`).join("\n")}
</table>
<h2>How a call is paid</h2>
<p>Request the resource with no payment. The <code>402</code> body carries <code>accepts[]</code> — scheme, network, USDC contract, amount in atomic units, <code>payTo</code>, <code>maxTimeoutSeconds</code>. Sign it (EIP-3009 <code>TransferWithAuthorization</code> on Base, SPL token transfer on Solana) and retry with the payment header. v1 (<code>X-PAYMENT</code>) and v2 (<code>PAYMENT-SIGNATURE</code>) are both accepted, so a client that only speaks one still gets served.</p>
<h2>Machine-readable</h2>
<ul>
  <li>full terms: <a href="${esc(site.endpoints.terms)}"><code>${esc(site.endpoints.terms)}</code></a></li>
  <li>resource list: <a href="${esc(site.endpoints.resources)}"><code>${esc(site.endpoints.resources)}</code></a> — and a static snapshot here: <a href="/discovery.json"><code>/discovery.json</code></a>, <a href="/x402-info.json"><code>/x402-info.json</code></a></li>
  <li>MCP server card: <a href="${esc(site.endpoints.server_card)}"><code>${esc(site.endpoints.server_card)}</code></a> · agent card (A2A): <a href="${esc(site.endpoints.agent_card)}"><code>${esc(site.endpoints.agent_card)}</code></a></li>
  <li>OpenAPI: <a href="${esc(site.endpoints.openapi)}"><code>${esc(site.endpoints.openapi)}</code></a> · agent briefing: <a href="${esc(site.endpoints.briefing)}"><code>${esc(site.endpoints.briefing)}</code></a></li>
</ul>
<p class="foot">Built ${esc(built)} by <code>scripts/build-cloudflare-pages.mjs</code> from the running service at <code>${esc(ORIGIN)}</code>. Every number above was read from <code>/.well-known/x402</code>, <code>/discovery/resources</code> and the MCP server card at build time; none of it is typed. If this page and the origin disagree, the origin is right and this page is stale.</p>
</body></html>
`);
console.log(`wrote ${OUT}/ index.html + x402-info.json + discovery.json`);
console.log(`  measured from ${ORIGIN}: ${rows.length} priced resources, $${min}-$${max}, networks=${nets.length}, free=${free.join(",") || "none"}`);
console.log(`  bands: ${[...band.entries()].map(([k, v]) => `${k}=${v}`).join(" · ")}`);
console.log("  deploy: npx wrangler pages deploy " + OUT + "   (log in with `npx wrangler login` yourself — the token stays in your own keyring)");
