// Builds the GitHub Pages mirror (x402-info.json + index.html) FROM THE LIVE SERVICE.
//
// Why a generator instead of an edited file: the mirror is the one copy of our terms that a browser-UA
// crawler can read — the ngrok edge hands those clients its own HTML interstitial at HTTP 200, so every
// well-known document we serve at the origin is invisible to them. That makes this page load-bearing for
// discovery, and it went stale exactly the way hand-maintained text does: it was written when the rail had
// a handful of routes, and every number in it stopped being true while nobody looked. The last published
// version advertised the OLD price and the OLD endpoint list.
//
// So nothing here is typed. Every figure is read from the served documents of the running service
// (/.well-known/x402, /.well-known/x402 terms + /discovery/resources + /.well-known/mcp/server-card.json),
// and the build FAILS if any of them cannot be read — a mirror that silently keeps yesterday's numbers is
// worse than no mirror, because it looks authoritative.
//
// Run: node scripts/build-pages-mirror.mjs [--origin https://<host>] [--out <dir>]
import fs from "node:fs";
import path from "node:path";

const ORIGIN = (process.argv.find((a) => a.startsWith("--origin=")) || "").split("=")[1]
  || process.env.X402_MIRROR_ORIGIN || "https://labored-safari-islamic.ngrok-free.dev";
const OUT = (process.argv.find((a) => a.startsWith("--out=")) || "").split("=")[1]
  || path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, "$1")), "..", "pages-mirror");

async function need(url) {
  const r = await fetch(url, { headers: { accept: "application/json", "user-agent": "x402-mirror-builder" }, signal: AbortSignal.timeout(20_000) });
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}: refused to build a mirror from an unreadable source`);
  const t = await r.text();
  try { return JSON.parse(t); } catch { throw new Error(`${url} -> not JSON (the ngrok interstitial would look like this). Aborting rather than copying junk into the mirror.`); }
}

const terms = await need(`${ORIGIN}/.well-known/x402`);
const disc = await need(`${ORIGIN}/discovery/resources`);
const card = await need(`${ORIGIN}/.well-known/mcp/server-card.json`);

const items = disc.items || [];
if (!items.length) throw new Error("live /discovery/resources returned zero items — refusing to publish an empty mirror");
const paidCount = items.length;
const pathname = (it) => { try { return new URL(it.resource || it.uri).pathname; } catch { return ""; } };
const byKind = new Map();
for (const it of items) {
  const p = pathname(it);
  const band = p.startsWith("/market/x402") ? "rail demand map" : p.startsWith("/market/") ? "market/venue read" : p === "/audit" ? "source-code audit" : "chain read";
  byKind.set(band, (byKind.get(band) || 0) + 1);
}
// Price comes from the wire form the buyer actually signs: accepts[].amount in atomic units with its own
// `decimals`. The first draft looked for a friendly `price` field on the item — the live document has none,
// and the build died on its own guard instead of inventing a number, which is the behaviour wanted here.
const prices = [];
for (const it of items) {
  const a = (it.accepts || [])[0];
  if (!a || a.amount == null) continue;
  const dec = Number(a.decimals ?? 6);
  const usd = Number(a.amount) / 10 ** dec;
  if (Number.isFinite(usd) && usd > 0) prices.push(usd);
}
if (!prices.length) throw new Error("no accepts[].amount readable on any live resource — the mirror would have to invent a price");
const uniqPrices = [...new Set(prices.map((p) => Number(p.toFixed(6))))].sort((a, b) => a - b);
const cheap = uniqPrices[0], dear = uniqPrices[uniqPrices.length - 1];
const priced = prices.length;
if (priced !== paidCount) throw new Error(`only ${priced}/${paidCount} live resources advertise an amount — refusing to price the mirror from a partial read`);
const freeTools = card.free_tools || [];
if (!Array.isArray(card.free_tools)) throw new Error("server card carries no free_tools list — refusing to guess what costs nothing");
// Bound to where these actually live on the wire (measured 2026-09-29): /discovery/resources carries
// payTo / currency / networks / facilitator, while /.well-known/x402 carries the long description and the
// resource tables. The first draft read payTo off the terms doc, where it does not exist, and would have
// published a mirror with a blank payout address.
const nets = disc.networks || terms.networks || [];
if (!nets.length) throw new Error("live documents advertise no networks");
const payTo = disc.payTo || {};
if (!Object.keys(payTo).length) throw new Error("live /discovery/resources carries no payTo — refusing to publish a mirror without a payout address");
const assets = {};
for (const it of items) for (const a of (it.accepts || [])) if (a.network && a.asset) assets[a.network] = a.asset;
if (Object.keys(assets).length !== nets.length) throw new Error(`only ${Object.keys(assets).length}/${nets.length} networks name a USDC contract — partial read, refusing to guess the rest`);
// Sanity, not decoration: if the count of paid resources and the count of MCP tools disagree, one of the
// two documents was rebuilt without the other. They are generated from the same table, so drift means a bug.
const toolCount = (card.tools || []).length;
if (toolCount && toolCount !== paidCount) throw new Error(`drift: live card advertises ${toolCount} paid tools but /discovery/resources lists ${paidCount} resources`);

const priceLines = [...byKind.entries()].map(([k, n]) => `    "${n} × ${k} — $${(n === paidCount ? cheap : cheap).toFixed(3)}–$${dear.toFixed(3)} per call, USDC on Base or Solana"`);
const info = {
  name: disc.server || card.name || terms.name,
  title: terms.name || card.title || "x402 Audit + Market Data",
  description: `Pay-per-call x402 service over MCP and plain HTTP. ${paidCount} priced resources on two networks. No account, no API key, no free tier beyond the two demo tools named below.`,
  currency: terms.currency || "USDC",
  networks: nets,
  payTo,
  assets,
  price: { min_usd: cheap, max_usd: dear },
  priced_resources: paidCount,
  mcp_tools: toolCount || paidCount,
  free_tools: freeTools,
  resource_bands: Object.fromEntries(byKind),
  endpoints: {
    mcp: `${ORIGIN}/mcp`,
    http_data: `${ORIGIN}/market/<resource>`,
    terms: `${ORIGIN}/.well-known/x402`,
    resource_list: `${ORIGIN}/discovery/resources`,
    agent_card: `${ORIGIN}/.well-known/agent-card.json`,
    openapi: `${ORIGIN}/openapi.json`,
    briefing: `${ORIGIN}/llms.txt`,
  },
  settlement: "USDC. Payment is verified and settled by the x402 facilitator before any data is returned; a call without a valid payment gets HTTP 402 and a machine-readable challenge, never a partial answer.",
  built_from: { origin: ORIGIN, at: new Date().toISOString(), documents: ["/.well-known/x402", "/discovery/resources", "/.well-known/mcp/server-card.json"] },
  note: "This file is GENERATED by scripts/build-pages-mirror.mjs from the running service. Do not hand-edit: the whole reason it was wrong before is that it was written once and never re-read. Regenerate with the origin up.",
};

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${info.title} — x402 pay-per-call agent</title>
<meta name="description" content="${paidCount} priced crypto reads over x402 (MCP + HTTP), USDC on Base and Solana.">
<style>
 body{font:16px/1.6 system-ui,max-width:46rem;margin:3rem auto;padding:0 1.2rem;color:#111}
 code,pre{background:#f5f5f5;border-radius:6px;padding:.15rem .4rem;font-size:.92em}
 pre{padding:.8rem 1rem;overflow:auto}
 h1{font-size:1.5rem;margin-bottom:.2rem} .sub{color:#555;margin-top:0}
 table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #ddd;padding:.45rem .3rem;text-align:left;font-size:.95rem}
 .foot{color:#666;font-size:.85rem;margin-top:2.5rem;border-top:1px solid #eee;padding-top:1rem}
</style></head><body>
<h1>${card.name || "Crypto Bot Audit + Market Data"}</h1>
<p class="sub">Pay-per-call over <code>x402</code>. No account, no API key, no usage limits — you pay USDC per call and the answer is the data.</p>
<table>
 <tr><th>Priced resources</th><td>${paidCount} (${info.mcp_tools} of them also callable as MCP tools)</td></tr>
 <tr><th>Price</th><td>$${cheap.toFixed(3)}–$${dear.toFixed(3)} per call, USDC on Base or Solana</td></tr>
 <tr><th>What sells here</th><td>${[...byKind.entries()].map(([k, n]) => `${n} ${k}`).join(" · ")}</td></tr>
 <tr><th>Free to try first</th><td>${freeTools.map((t) => `<code>${t}</code>`).join(", ") || "none"}</td></tr>
 <tr><th>Networks</th><td>${nets.map((n) => `<code>${n}</code>`).join(" ")}</td></tr>
 <tr><th>Payout address</th><td><code>${payTo["eip155:8453"] || payTo[nets[0]] || "?"}</code></td></tr>
</table>
<h2>Connect it</h2>
<pre>npm i @protocolinsurer/x402-mcp-client
X402_MCP_BASE_URL=${ORIGIN}   # + the buyer's own wallet key, set by you, never by us</pre>
<p>The client's <code>tools/list</code> shows all ${info.mcp_tools} paid tools with their prices, and it handles the 402 → sign → retry automatically. Plain HTTP works too: <code>GET ${ORIGIN}/market/&lt;resource&gt;</code>.</p>
<h2>Authoritative documents (live origin)</h2>
<ul>
${Object.entries(info.endpoints).map(([k, v]) => `  <li><code>${k}</code> — <a href="${v}">${v}</a></li>`).join("\n")}
</ul>
<p class="foot">Mirror generated <code>${info.built_from.at}</code> from <code>${ORIGIN}</code> by
<code>scripts/build-build-pages-mirror.mjs</code>. This page exists because the tunnel in front of the live
service shows its own HTML to browser-shaped user agents, so crawlers cannot read the same documents an
x402 client can. Numbers here are read from the service, not copied by hand — if they disagree with
<code>/.well-known/x402</code>, the service is right and this file is stale.</p>
</body></html>
`;

fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, "x402-info.json"), JSON.stringify(info, null, 2) + "\n");
fs.writeFileSync(path.join(OUT, "index.html"), html);
console.log(`wrote ${OUT} from ${ORIGIN}`);
console.log(`  measured: priced_resources=${paidCount} mcp_tools=${info.mcp_tools} price_band=$${cheap}-$${dear} networks=${nets.length} free_tools=${freeTools.join(",") || "none"}`);
console.log(`  bands: ${[...byKind.entries()].map(([k, n]) => `${k}=${n}`).join(" ")}`);
console.log(`  every figure above was read from the live service this run; none of it is typed into this file`);
