// Regenerate services/x402-mcp/server.json — the MCP Registry entry — FROM THE WIRE.
//
// Why this exists: the published entry is what an MCP client reads before it installs us, and it had been
// hand-written three times. Read it live today:
//   1.0.0  "…0.05 USDC on Base; demo free."        ← a price we stopped charging weeks ago
//   1.1.0  "…9 MCP tools, USDC on Base."           ← we serve 143, on two networks
//   1.2.0  "…8 market-data tools 0.001…"           ← 133 data routes, not 8
// and the stale 1.0.0 line is almost certainly where the buyer-side broker got `price_max: 0.05` — its own
// row cites `sources:[x402scan]`, and an aggregator that advertises a $0.05 ceiling excludes us from any
// buyer filtering under it. A hand-typed description cannot fail loudly when the rail grows, so it never
// does: every number below is read from the running service.
//
// Publishing itself is a GitHub-authenticated action (registry CLI / OIDC) and stays the user's call;
// this script only makes the artifact correct and reviewable.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ORIGIN = process.env.ORIGIN || "https://labored-safari-islamic.ngrok-free.dev";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "..", "services", "x402-mcp", "server.json");
const H = { accept: "application/json", "ngrok-skip-browser-warning": "1" };

// Every read must succeed or we do not write: a generator that emits defaults is how a stale entry gets
// republished looking fresh.
async function need(url, opts) {
  const r = await fetch(url, { ...opts, headers: { ...H, ...(opts?.headers || {}) }, signal: AbortSignal.timeout(25_000) });
  if (!r.ok) throw new Error(`${url} -> http ${r.status}`);
  return r.json();
}
const manifest = await need(`${ORIGIN}/.well-known/x402`);
const disc = await need(`${ORIGIN}/discovery/resources`);
if (!Array.isArray(manifest.resources_detail) || !manifest.resources_detail.length) throw new Error("manifest.resources_detail missing — the wire does not expose the priced resource list, refusing to generate");
if (!Array.isArray(disc.items) || !disc.items.length) throw new Error("/discovery/resources items missing, refusing to generate");

// The MCP tool set is read from tools/list over a free handshake (never from a hardcoded count).
const init = await fetch(`${ORIGIN}/mcp`, {
  method: "POST", signal: AbortSignal.timeout(25_000),
  headers: { ...H, "content-type": "application/json", accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", clientInfo: { name: "server-json-builder", version: "1" }, capabilities: {} } }),
});
if (!init.ok) throw new Error(`initialize -> http ${init.status}`);
const list = await fetch(`${ORIGIN}/mcp`, {
  method: "POST", signal: AbortSignal.timeout(25_000),
  headers: { ...H, "content-type": "application/json", accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
});
if (!list.ok) throw new Error(`tools/list -> http ${list.status}`);
const line = (await list.text()).split("\n").map((l) => l.replace(/^data: /, "")).find((l) => l.trim().startsWith("{"));
const tools = JSON.parse(line || "{}")?.result?.tools;
if (!Array.isArray(tools) || tools.length < 20) throw new Error(`tools/list gave ${tools?.length} tools — too few to be the real set, refusing to generate`);

const audit = manifest.resources_detail.find((r) => /\/audit$/.test(r.resource));
const prices = [...new Set(manifest.resources_detail.map((r) => r.price_usd))].sort((a, b) => a - b);
const cheap = Math.min(...prices), dear = Math.max(...prices);
const nGet = manifest.resources_detail.filter((r) => r.method === "GET").length;
const nPaidHttp = manifest.resources_detail.length;
const nets = (manifest.networks || []).map((n) => n.network);
// Free tools come from the card's own field, never from pattern-matching a description: the first version
// of this script regexed "free|no payment|demo" over tool descriptions and produced `Free before you pay:
// demo_audit, x402_rail_heartbeat, chain_logs` — chain_logs is a PAID $0.001 tool, and the sentence had
// already been written into the file we publish. A claim about money is only allowed from a field that
// states it.
const card = await need(`${ORIGIN}/.well-known/mcp/server-card.json`);
if (!Array.isArray(card.free_tools) || !card.free_tools.length) throw new Error("server card carries no free_tools list — refusing to guess which tools cost nothing");
const freeTools = card.free_tools;

// The registry's own limit on this field is 100 characters, MEASURED rather than assumed: the publish run
// of 2026-09-29T16:15Z was rejected with `422 {"message":"expected length <= 100","location":"body.description"}`
// against the ~470-char sentence the previous version assembled. The old guard here said "registry limit is
// ~500" — a guessed ceiling that could never fire, which is how a 470-char string reached a 100-char field.
// The rich sentence belongs in OUR documents (llms.txt, /openapi.json, the server card), where nothing caps
// it; this one line is a shopfront, so it is rebuilt from measured counts and hard-limited.
const NET_LABEL = { "eip155:8453": "Base", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "Solana" };
const netNames = nets.map((n) => NET_LABEL[n] || n.replace(/:.*/, ""));
const description = `x402 pay-per-call: ${tools.length} MCP tools, no account or key. USDC on ${netNames.join(" + ")}, \$${cheap}-\$${dear}/call.`;
if (description.length > 100) throw new Error(`generated description is ${description.length} chars — the registry rejects >100 (measured 422 on body.description). Shorten the assembly, do not truncate mid-meaning.`);

const prev = fs.existsSync(OUT) ? JSON.parse(fs.readFileSync(OUT, "utf8")) : null;
// The registry keys on `version`: republishing identical facts under the same version is a no-op, and
// publishing CHANGED facts under an unchanged version would leave the old text serving the entry. So a
// content change forces a minor bump, and a no-change run leaves the file byte-identical.
const bumpMinor = (v) => { const p = String(v).split(".").map((n) => parseInt(n, 10) || 0); return `${p[0]}.${(p[1] ?? 0) + 1}.0`; };
const changed = !!prev && prev.description !== description;
const version = prev ? (changed ? bumpMinor(prev.version) : prev.version) : "1.0.0";
const out = {
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  name: prev?.name || "io.github.kaminariouji/x402-audit-agent",
  title: prev?.title || "Crypto Bot Audit + Market Data (x402 paid)",
  description,
  version,
  remotes: prev?.remotes || [{ type: "streamable-http", url: `${ORIGIN}/mcp` }],
};
fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${path.relative(process.cwd(), OUT)} (version ${out.version}, ${description.length} chars)`);
console.log(`  measured: tools=${tools.length} http_resources=${nPaidHttp} prices=${prices.join("/")} networks=${nets.length} free_tools=${freeTools.join(",") || "none"}`);
console.log(`  description: ${description}`);
if (prev && prev.description !== description) console.log(`  CHANGED from: ${prev.description}`);
