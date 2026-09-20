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
const PORT = Number(process.env.PORT || 10000); // Render injects PORT
// Public origin used in discovery metadata (OpenAPI servers, x402 resource fan-out).
const PUBLIC_URL = (process.env.X402_PUBLIC_URL || "https://labored-safari-islamic.ngrok-free.dev").replace(/\/+$/, "");

const FREE_METHODS = new Set(["initialize", "notifications/initialized", "ping", "tools/list", "resources/list", "prompts/list"]);
const FREE_TOOLS = new Set(["demo_audit"]);

// ---- MCP server ----
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

// ---- x402 resource server ----
const facilitatorClient = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
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
});
// Gate the JSON-RPC method level on /mcp; /audit is gated by matching its route config.
httpServer.requiresPayment = function (context) {
  const method = context.method || context.adapter?.getMethod?.();
  const path = context.path;
  if (method === "POST" && path === "/audit") return true;
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
  endpoints: { paid: ["POST /audit", "POST /mcp (tools/call audit_bot_code)"], free: ["GET /", "/health", "/llms.txt", "/openapi.json", "/.well-known/x402-info", "MCP demo_audit"] },
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
    resources: [`${PUBLIC_URL}/audit`],
    ownershipProofs: [PAY_TO],
    instructions: "Pay-per-call x402 USDC on Base. POST /audit with an x402 payment; MCP tool audit_bot_code on POST /mcp.",
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
    { path: "/mcp", method: "POST", price: PRICE, note: "per tools/call audit_bot_code" },
  ], freeEndpoints: ["/", "/health", "/llms.txt", "/openapi.json", "/.well-known/x402-info", "MCP demo_audit"] },
  capabilities: ["analyze", "audit", "classify"],
  payTo: PAY_TO,
}));
app.get("/openapi.json", (_req, res) => res.json({
  openapi: "3.0.0",
  info: {
    title: "crypto-bot-honesty-audit", version: "1.0.0",
    description: "Pay-per-call x402 agent: scans one JS/TS crypto-bot source file for the bug patterns that make it report income it never earned.",
    contact: { url: "https://github.com/kaminariouji/x402-audit-agent" },
    "x-guidance": "Send POST /audit with body { code, filename }. Unpaid -> HTTP 402 with x402 terms; pay 0.05 USDC on Base (eip155:8453) and retry with the X-PAYMENT header. MCP tool audit_bot_code on POST /mcp is metered the same way; demo_audit is free.",
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
  } } },
}));
app.get("/llms.txt", (_req, res) => res.type("text/plain").send([
  "# crypto-bot-honesty-audit", "",
  "> Pay-per-call x402 agent that scans one JS/TS crypto-bot source file for the bug patterns that make it report income it never earned.", "",
  `Price: ${PRICE} USDC on ${NETWORK} (Base) via x402 HTTP-402. No signup, no API key. Recipient: ${PAY_TO}`,
  "Facilitator: " + FACILITATOR_URL, "",
  "## Endpoints",
  "- `POST /audit` (paid): body `{ \"code\": \"<file>\", \"filename\": \"bot.js\" }` -> `{ signalCount, findings[] }`. Unpaid -> HTTP 402.",
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
  "MCP: point any MCP client at " + PUBLIC_URL + "/mcp (Streamable HTTP). initialize, tools/list and demo_audit are free; audit_bot_code is the paid tool.", "",
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
