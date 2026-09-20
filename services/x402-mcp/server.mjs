// x402-gated paid agent — lean, self-contained deployable (MCP + HTTP audit).
// Free handshake + free demo + free discovery; paid tools/call and POST /audit via x402 USDC.
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { x402ResourceServer, x402HTTPResourceServer, HTTPFacilitatorClient } from "@x402/core/server";
import { paymentMiddlewareFromHTTPServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { z } from "zod";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const { scanText } = require(path.join(__dirname, "audit-bot-honesty.cjs"));

// Receiving wallet (public address only; safe to embed). Override with X402_PAY_TO.
const PAY_TO = process.env.X402_PAY_TO || "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b";
const FACILITATOR_URL = process.env.X402_FACILITATOR_URL || "https://facilitator.payai.network";
const NETWORK = process.env.X402_NETWORK || "eip155:8453";
const PRICE = process.env.X402_PRICE || "$0.05";
const PRICE_DATA = process.env.X402_PRICE_DATA || "$0.01"; // per-call price for the market-data route
const PORT = Number(process.env.PORT || 10000); // Render injects PORT
// Public origin used in discovery metadata (OpenAPI servers, x402 resource fan-out).
const PUBLIC_URL = (process.env.X402_PUBLIC_URL || "https://labored-safari-islamic.ngrok-free.dev").replace(/\/+$/, "");

const FREE_METHODS = new Set(["initialize", "notifications/initialized", "ping", "tools/list", "resources/list", "prompts/list"]);
const FREE_TOOLS = new Set(["demo_audit"]);

// ---- MCP server ----
// Accept an EVM address (0x + 40 hex) OR a Solana base58 mint (32-44 chars). This keeps
// the route a token-address lookup a caller cannot steer — the upstream host stays pinned.
const EVM_ADDR = /^0x[a-fA-F0-9]{40}$/;
const SOL_MINT = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
function isTokenAddress(a) { return EVM_ADDR.test(a) || SOL_MINT.test(a); }
async function fetchPrice(address) {
  const r = await fetch(`https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(address)}`, { headers: { accept: "application/json" } });
  const j = await r.json().catch(() => ({}));
  // Price the requested token ITSELF: keep only pairs where it is the baseToken (a stablecoin
  // like USDC usually appears only as the quote, so its "price" would otherwise be the pool's
  // other side, e.g. AERO). Take the deepest-liquidity such pair across any chain.
  const lc = address.toLowerCase();
  const pairs = (j.pairs || [])
    .filter(p => { const bt = p.baseToken?.address; return bt && (bt === address || bt.toLowerCase() === lc); })
    .sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
  const p = pairs[0];
  if (!p) return { address, found: false, note: "no DEX pair where this address is the base token", source: "dexscreener", ts: new Date().toISOString() };
  return { address, found: true, name: p.baseToken?.name, symbol: p.baseToken?.symbol,
    priceUsd: p.priceUsd, liquidityUsd: p.liquidity?.usd, fdv: p.fdv, marketCap: p.marketCap, volume24h: p.volume?.h24,
    chainId: p.chainId, dex: p.dexId, pairUrl: p.url, source: "dexscreener", ts: new Date().toISOString() };
}
// Pinned, keyless upstream (Dexscreener). The URL host is a constant and the query is
// encoded — no user-controlled host, so this route cannot be turned into an SSRF probe.
const DEXSCREENER_SEARCH = "https://api.dexscreener.com/latest/dex/search?q=";
const LEAN = 12;
function leanPair(p) {
  return {
    chainId: p.chainId, dex: p.dexId,
    symbol: p.baseToken?.symbol, name: p.baseToken?.name, address: p.baseToken?.address,
    priceUsd: p.priceUsd, liquidityUsd: p.liquidity?.usd, fdv: p.fdv, marketCap: p.marketCap,
    volume24h: p.volume?.h24, change24h: p.priceChange?.h24, pairUrl: p.url,
  };
}
async function searchTokens(rawQuery, limit) {
  const r = await fetch(DEXSCREENER_SEARCH + encodeURIComponent(rawQuery), { headers: { accept: "application/json" } });
  const j = await r.json().catch(() => ({}));
  const all = (j.pairs || []).map(leanPair);
  // Dedupe by chain+token address, keep the deepest-liquidity pair per token, then rank.
  const byToken = new Map();
  for (const p of all) {
    const k = `${p.chainId}:${(p.address || "").toLowerCase()}`;
    const cur = byToken.get(k);
    if (!cur || (p.liquidityUsd || 0) > (cur.liquidityUsd || 0)) byToken.set(k, p);
  }
  const results = [...byToken.values()]
    .sort((a, b) => (b.liquidityUsd || 0) - (a.liquidityUsd || 0))
    .slice(0, limit);
  return { query: rawQuery, count: results.length, results, source: "dexscreener", ts: new Date().toISOString() };
}
const mcp = new McpServer({ name: "crypto-bot-honesty-audit", version: "1.0.0" }, {
  instructions: "Scans a JS/TS crypto-bot source file for the bug patterns that make it report income it never earned.",
});
mcp.registerTool("audit_bot_code", {
  title: "Audit crypto-bot source for fake-earnings bugs",
  description:
    "Input one JS/TS source file (string). Returns findings for: testnet-as-USD, silent-zero balance, cooldown key mismatch, fake faucet endpoint, speculative earnings text.",
  inputSchema: { code: z.string().describe("one JS/TS file"), filename: z.string().optional() },
}, async ({ code, filename }) => {
  console.log(`[audit] tools/call audit_bot_code ${filename || "submitted.js"} bytes=${code?.length || 0}`);
  const findings = scanText(code, filename || "submitted.js");
  return { content: [{ type: "text", text: JSON.stringify({ signalCount: findings.length, findings }, null, 2) }] };
});
mcp.registerTool("demo_audit", {
  title: "Free demo of the audit (fixed sample, no payment)",
  description: "Runs the scanner on a small built-in bad-bot sample and returns the findings. Free; no x402 payment.",
  inputSchema: {},
}, async () => {
  // Deliberately-broken sample that trips 5 rules (proven by scanner --selftest).
  const sample = [
    'const provider = new ethers.JsonRpcProvider("https://eth-sepolia.example");',
    'export function record(a) { state.earnings.total_usd += a; }',
    'export async function claim(wallet) {',
    '  let balance;',
    '  try { balance = BigInt(await provider.send("eth_getBalance", [wallet.address]) || "0"); }',
    '  catch (e) { balance = 0; }',
    '  const id = wallet.id;',
    '  const last = state.faucet.lastClaim[id];',
    '  if (!last) { state.faucet.lastClaim[`micro_${id}`] = new Date().toISOString(); state.stats.totalFaucetClaims++; }',
    '  return balance;',
    '}',
  ].join("\n");
  const findings = scanText(sample, "sample-bot.js");
  return { content: [{ type: "text", text: JSON.stringify({ demo: true, signalCount: findings.length, findings }, null, 2) }] };
});
mcp.registerTool("get_token_price", {
  title: "Token spot price + liquidity (paid, Base or Solana)",
  description: "Live DEX spot price, liquidity, FDV, market cap and 24h volume for any token by contract address — EVM (Base/etc.) or Solana mint. Highest-liquidity pair. Cheap per-call market quote (0.01 USDC via x402).",
  inputSchema: { address: z.string().describe("Token contract address: EVM (0x…, 42 hex) or Solana base58 mint (32-44 chars)") },
}, async ({ address }) => {
  const a = typeof address === "string" ? address.trim() : "";
  if (!isTokenAddress(a))
    return { content: [{ type: "text", text: JSON.stringify({ error: "address must be an EVM contract (0x + 42 hex) or a Solana base58 mint" }) }], isError: true };
  const price = await fetchPrice(a);
  return { content: [{ type: "text", text: JSON.stringify(price, null, 2) }] };
});
mcp.registerTool("search_tokens", {
  title: "Search tokens by name/symbol across DEXs (paid)",
  description: "Search crypto tokens by name or symbol; returns the highest-liquidity matched pairs with price, liquidity, FDV and 24h volume across chains. Cheap per-call market lookup (0.01 USDC via x402).",
  inputSchema: { query: z.string().describe("token name or symbol, e.g. \"pepe\" or \"coinbase\""), limit: z.number().int().min(1).max(25).optional() },
}, async ({ query, limit }) => {
  const q = typeof query === "string" ? query.trim() : "";
  if (q.length < 1 || q.length > 64)
    return { content: [{ type: "text", text: JSON.stringify({ error: "query must be 1-64 chars" }) }], isError: true };
  const results = await searchTokens(q, Math.min(Math.max(Number(limit) || LEAN, 1), 25));
  return { content: [{ type: "text", text: JSON.stringify(results, null, 2) }] };
});

// ---- x402 resource server ----
// Default facilitator (payai) is keyless and serves real Base-USDC payments today.
// To get indexed into the Coinbase x402 Bazaar (23k+ resources, where buyer agents
// search), settlement must route through the CDP Facilitator: set
// X402_FACILITATOR_URL=https://api.cdp.coinbase.com/platform/v2/x402 and
// X402_FACILITATOR_HEADERS to a JSON header map (CDP API-key auth) from a free
// Coinbase CDP key. No key -> unchanged keyless behavior. Secrets stay in env, never in code.
const FACILITATOR_HEADERS = (() => {
  try { return process.env.X402_FACILITATOR_HEADERS ? JSON.parse(process.env.X402_FACILITATOR_HEADERS) : null; }
  catch { console.error("[x402] X402_FACILITATOR_HEADERS is not valid JSON; ignoring"); return null; }
})();
const facilitatorClient = FACILITATOR_HEADERS
  ? new HTTPFacilitatorClient({
      url: FACILITATOR_URL,
      // Facilitator client keys auth by request path; apply the same headers to each.
      createAuthHeaders: async () => ({
        verify: FACILITATOR_HEADERS, settle: FACILITATOR_HEADERS, supported: FACILITATOR_HEADERS,
      }),
    })
  : new HTTPFacilitatorClient({ url: FACILITATOR_URL });
const resourceServer = new x402ResourceServer(facilitatorClient).register(NETWORK, new ExactEvmScheme());
const httpServer = new x402HTTPResourceServer(resourceServer, {
  "POST /mcp": {
    accepts: { scheme: "exact", price: PRICE, network: NETWORK, payTo: PAY_TO },
    description: "Per-call x402 payment to run audit_bot_code on one source file.",
    mimeType: "application/json",
    extensions: {
      ...declareDiscoveryExtension({
        method: "POST", bodyType: "json",
        input: { code: "state.earnings.total_usd += amount;", filename: "bot.js" },
        inputSchema: { type: "object", properties: { code: { type: "string" }, filename: { type: "string" } }, required: ["code"] },
        output: { example: { signalCount: 1, findings: [{ rule: "TESTNET_AS_USD", severity: "high", line: 1 }] } },
      }),
    },
  },
  "POST /audit": {
    accepts: { scheme: "exact", price: PRICE, network: NETWORK, payTo: PAY_TO },
    description: "Per-call x402 payment to audit one JS/TS crypto-bot source file over plain HTTP.",
    mimeType: "application/json",
    extensions: {
      ...declareDiscoveryExtension({
        method: "POST", bodyType: "json",
        input: { code: "state.earnings.total_usd += amount;", filename: "bot.js" },
        inputSchema: { type: "object", properties: { code: { type: "string" }, filename: { type: "string" } }, required: ["code"] },
        output: { example: { signalCount: 1, findings: [{ rule: "TESTNET_AS_USD", severity: "high", line: 1 }] } },
      }),
    },
  },
  "GET /price": {
    accepts: { scheme: "exact", price: PRICE_DATA, network: NETWORK, payTo: PAY_TO },
    description: "Live DEX spot price + liquidity + FDV + 24h volume for any token by contract address (query ?address=0x.. or a Solana mint); returns the highest-liquidity pair. Cheap per-call market quote. — $0.01 USDC",
    mimeType: "application/json",
    tags: ["price", "defi", "market-data", "base", "solana", "token", "liquidity", "quote"],
    extensions: {
      ...declareDiscoveryExtension({
        method: "GET",
        input: { address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" },
        inputSchema: { type: "object", properties: { address: { type: "string", description: "Token contract address: EVM (0x…, 42 hex) or Solana base58 mint (32-44 chars)" } }, required: ["address"] },
        output: { example: { found: true, symbol: "BONK", priceUsd: "0.000003010", liquidityUsd: 290132, fdv: 0, marketCap: 0, chainId: "solana", source: "dexscreener", ts: "2026-09-20T00:00:00.000Z" } },
      }),
    },
  },
  "GET /search_tokens": {
    accepts: { scheme: "exact", price: PRICE_DATA, network: NETWORK, payTo: PAY_TO },
    description: "Search crypto tokens by name/symbol (query ?q=pepe&limit=12); returns highest-liquidity matched pairs with price, liquidity, FDV and 24h volume. Cheap per-call market lookup. — $0.01 USDC",
    mimeType: "application/json",
    tags: ["search", "tokens", "defi", "market-data", "price", "liquidity"],
    extensions: {
      ...declareDiscoveryExtension({
        method: "GET",
        input: { q: "pepe" },
        inputSchema: { type: "object", properties: { q: { type: "string", description: "token name or symbol to search" }, limit: { type: "number", description: "max results 1-25 (optional)" } }, required: ["q"] },
        output: { example: { query: "pepe", count: 2, results: [{ chainId: "base", symbol: "PEPE", address: "0x..", priceUsd: "0.00001", liquidityUsd: 42000, fdv: 120000, volume24h: 9000, source: "dexscreener" }], source: "dexscreener", ts: "2026-09-20T00:00:00.000Z" } },
      }),
    },
  },
});
// Gate the JSON-RPC method level on /mcp; /audit is gated by matching its route config.
httpServer.requiresPayment = function (context) {
  const method = context.method || context.adapter?.getMethod?.();
  const path = context.path;
  if (method === "POST" && path === "/audit") return true;
  if (method === "GET" && path === "/price") return true;
  if (method === "GET" && path === "/search_tokens") return true;
  if (method === "POST" && path === "/mcp") {
    const body = context.adapter?.getBody?.() || {};
    if (FREE_METHODS.has(body.method)) return false;
    if (body.method === "tools/call") return !FREE_TOOLS.has(body?.params?.name);
    return true;
  }
  return false; // every other path is free metadata
};

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));

// ---- free metadata (registered BEFORE the payment gate) ----
app.get("/health", (_req, res) => res.json({ ok: true, kind: "mcp+http", payTo: PAY_TO, network: NETWORK, price: PRICE }));
app.get("/", (_req, res) => res.json({
  name: "crypto-bot-honesty-audit",
  endpoints: { paid: ["POST /audit", "GET /price?address=0x.. (token spot price)", "GET /search_tokens?q=.. (token search)", "POST /mcp (tools/call audit_bot_code)"], free: ["GET /", "/health", "/llms.txt", "/openapi.json", "/.well-known/x402-info", "MCP demo_audit"] },
  price: PRICE, network: NETWORK, currency: "USDC", payTo: PAY_TO, protocol: "x402 (HTTP 402)",
}));
app.get("/audit", (_req, res) => res.status(405).json({
  error: "method_not_allowed", paid_endpoint: "POST /audit", price: PRICE, network: NETWORK, currency: "USDC", payTo: PAY_TO,
  probe: "this service is LIVE; send POST with an x402 payment to use it",
}));
// x402scan / Bazaar fan-out compat: list payable resources at their absolute URLs.
app.get(["/.well-known/x402", "/.well-known/x402.json"], (_req, res) => {
  res.json({
    version: 1,
    resources: [`${PUBLIC_URL}/audit`, `${PUBLIC_URL}/price`, `${PUBLIC_URL}/search_tokens`],
    ownershipProofs: [PAY_TO],
    instructions: "Pay-per-call x402 USDC on Base. POST /audit with an x402 payment; GET /price?address=0x.. for a token quote; GET /search_tokens?q=.. for a token search; MCP tool audit_bot_code on POST /mcp.",
  });
});
app.get("/.well-known/x402-info", (_req, res) => res.json({
  name: "crypto-bot-honesty-audit",
  description: "Paid x402 agent (HTTP + MCP): scans a JS/TS crypto-bot source file for the bug patterns that make it report income it never earned (testnet-as-USD, fake faucet endpoints, hardcoded earnings, auto-settled claim stubs).",
  documentationUrl: "https://github.com/kaminariouji/x402-audit-agent",
  contactUrl: "https://github.com/kaminariouji",
  protocol: "x402 (HTTP 402)",
  pricing: { currency: "USDC", network: NETWORK, endpoints: [
    { path: "/audit", method: "POST", price: PRICE },
    { path: "/price", method: "GET", price: PRICE_DATA, note: "token spot price by ?address= (EVM 0x or Solana mint)" },
    { path: "/search_tokens", method: "GET", price: PRICE_DATA, note: "token search by ?q=name-or-symbol" },
    { path: "/mcp", method: "POST", price: PRICE, note: "per tools/call audit_bot_code" },
  ], freeEndpoints: ["/", "/health", "/llms.txt", "/openapi.json", "/.well-known/x402-info", "MCP demo_audit"] },
  capabilities: ["analyze", "audit", "classify", "market-data", "price", "search"],
  payTo: PAY_TO,
}));
app.get("/openapi.json", (_req, res) => res.json({
  openapi: "3.0.0",
  info: {
    title: "crypto-bot-honesty-audit", version: "1.0.0",
    description: "Pay-per-call x402 agent: scans one JS/TS crypto-bot source file for the bug patterns that make it report income it never earned.",
    contact: { url: "https://github.com/kaminariouji/x402-audit-agent" },
    "x-guidance": "Paid routes. (1) POST /audit body { code, filename } -> 0.05 USDC. (2) GET /price?address=0x.. (Base token spot price + liquidity) -> 0.01 USDC. (3) GET /search_tokens?q=name (token search, highest-liquidity pairs) -> 0.01 USDC. Unpaid -> HTTP 402 with x402 terms; pay USDC on Base (eip155:8453) via an x402 client and retry. MCP tool audit_bot_code on POST /mcp is metered the same way; demo_audit is free.",
  },
  servers: [{ url: PUBLIC_URL }],
  security: [{ x402: [] }],
  components: { securitySchemes: { x402: { type: "apiKey", in: "header", name: "X-PAYMENT", description: `x402 USDC payment on ${NETWORK}; settle then resend with the X-PAYMENT header.` } } },
  paths: { "/audit": { post: {
    summary: "Audit a crypto-bot source file (paid via x402)",
    "x-payment-info": { protocols: ["x402"], price: { mode: "fixed", currency: "USD", amount: "0.05" } },
    security: [{ x402: [] }],
    requestBody: { required: true, content: { "application/json": { schema: { type: "object",
      properties: { code: { type: "string", description: "one JS/TS file" }, filename: { type: "string" } }, required: ["code"] } } } },
    responses: { 200: { description: "findings[] after settlement" }, 402: { description: "Payment required (x402 challenge)" } },
  } }, "/price": { get: {
    summary: "Live token spot price + liquidity by contract address, EVM or Solana (paid via x402)",
    "x-payment-info": { protocols: ["x402"], price: { mode: "fixed", currency: "USD", amount: "0.01" } },
    security: [{ x402: [] }],
    parameters: [{ name: "address", in: "query", required: true, description: "Token contract address: EVM (0x…, 42 hex) or Solana base58 mint (32-44 chars)", schema: { type: "string" } }],
    responses: { 200: { description: "priceUsd/liquidity/fdv after settlement" }, 402: { description: "Payment required (x402 challenge)" } },
  } }, "/search_tokens": { get: {
    summary: "Search crypto tokens by name/symbol; returns highest-liquidity matched pairs (paid via x402)",
    "x-payment-info": { protocols: ["x402"], price: { mode: "fixed", currency: "USD", amount: "0.01" } },
    security: [{ x402: [] }],
    parameters: [
      { name: "q", in: "query", required: true, description: "token name or symbol to search (1-64 chars)", schema: { type: "string" } },
      { name: "limit", in: "query", required: false, description: "max results 1-25", schema: { type: "number" } },
    ],
    responses: { 200: { description: "results[] after settlement" }, 402: { description: "Payment required (x402 challenge)" } },
  } } },
}));
app.get("/llms.txt", (_req, res) => res.type("text/plain").send([
  "# crypto-bot-honesty-audit", "",
  "> Pay-per-call x402 agent that scans one JS/TS crypto-bot source file for the bug patterns that make it report income it never earned.", "",
  `Price: ${PRICE} USDC on ${NETWORK} (Base) via x402 HTTP-402. No signup, no API key. Recipient: ${PAY_TO}`,
  "Facilitator: " + FACILITATOR_URL, "",
  "## Endpoints",
  "- `POST /audit` (paid): body `{ \"code\": \"<file>\", \"filename\": \"bot.js\" }` -> `{ signalCount, findings[] }`. Unpaid -> HTTP 402.",
  `- \`GET /price?address=0x..\` (paid, ${PRICE_DATA}): live DEX spot price + liquidity + FDV + market cap + 24h volume for any token by address — EVM (Base/etc.) or Solana mint; highest-liquidity pair.`,
  `- \`GET /search_tokens?q=name&limit=12\` (paid, ${PRICE_DATA}): search tokens by name/symbol -> highest-liquidity matched pairs (price/liquidity/FDV/volume across chains).`,
  "- `POST /mcp` (paid per tools/call `audit_bot_code`); MCP `demo_audit` + handshake are free.",
  "- `GET /`, `/health`, `/.well-known/x402-info` (free metadata)", "",
  "## Buyer quickstart (no signup — your x402 client auto-pays the 402 and retries)",
  "Any funded EVM wallet on Base can call this; you keep your own keys, we never hold funds. A standard x402 client catches our HTTP 402, reads the header, pays " + PRICE + " USDC on " + NETWORK + ", and retries transparently.", "",
  "```js",
  "import { x402Fetch } from \"x402-fetch\";        // or x402-axios / x402-requests",
  "import { privateKeyToAccount } from \"viem/accounts\";",
  "const wallet = privateKeyToAccount(process.env.PRIVATE_KEY); // buyer's own funded key",
  "const res = await x402Fetch(fetch, \"" + PUBLIC_URL + "/audit\", {",
  "  method: \"POST\", headers: { \"content-type\": \"application/json\" },",
  "  body: JSON.stringify({ code: SOURCE, filename: \"bot.js\" }),",
  "}, { wallet });",
  "const { signalCount, findings } = await res.json(); // returned only after settlement",
  "```",
  "Facilitator verify/settle is free for the seller (buyer pays gas). Docs: https://docs.x402.org/getting-started/quickstart-for-buyers", "",
  "MCP: point any MCP client at " + PUBLIC_URL + "/mcp (Streamable HTTP). initialize, tools/list and demo_audit are free; paid tools are audit_bot_code, get_token_price, search_tokens.", "",
  "Source: https://github.com/kaminariouji/x402-audit-agent",
].join("\n")));

// ---- payment gate ----
app.use(paymentMiddlewareFromHTTPServer(httpServer, undefined, undefined, true));

// ---- paid endpoints (only reached after settlement) ----
app.post("/audit", (req, res) => {
  const { code, filename } = req.body || {};
  if (typeof code !== "string" || code.length === 0) return res.status(400).json({ error: 'body must be { "code": "<source string>" }' });
  const findings = scanText(code, filename || "submitted.js");
  res.json({ scannedBytes: code.length, signalCount: findings.length, findings,
    disclaimer: "Static-analysis signals; each must be confirmed by reading the cited line. Not a guarantee of correctness or profitability." });
});
// Paid market-data route: live DEX spot price for a Base token (only reached after settlement).
app.get("/price", async (req, res) => {
  const address = String(req.query.address || "").trim();
  if (!isTokenAddress(address)) return res.status(400).json({ error: "query ?address= must be an EVM contract (0x + 42 hex) or a Solana base58 mint" });
  try {
    res.json(await fetchPrice(address));
  } catch (e) {
    res.status(502).json({ address, error: "upstream_price_lookup_failed", detail: String(e?.message || e) });
  }
});
// Paid token-search route: name/symbol -> highest-liquidity matched pairs (only after settlement).
app.get("/search_tokens", async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (q.length < 1 || q.length > 64) return res.status(400).json({ error: "query ?q= must be 1-64 chars" });
  const limit = Math.min(Math.max(Number(req.query.limit) || LEAN, 1), 25);
  try {
    res.json(await searchTokens(q, limit));
  } catch (e) {
    res.status(502).json({ query: q, error: "upstream_search_lookup_failed", detail: String(e?.message || e) });
  }
});
app.post("/mcp", async (req, res) => {
  try {
    const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await mcp.connect(t);
    res.on("close", () => t.close().catch(() => {}));
    await t.handleRequest(req, res, req.body);
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: String(e?.message || e) }, id: null });
  }
});

app.listen(PORT, () => {
  console.log(`=== x402 audit agent :${PORT} | USDC on ${NETWORK} -> ${PAY_TO} | ${PRICE}/call ===`);
});
