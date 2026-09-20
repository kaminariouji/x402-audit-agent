// x402-gated MCP server: hosted "crypto-bot honesty audit" tool.
// Free MCP handshake (initialize / tools/list); paid per tools/call via x402 USDC.
import express from "express";
import fs from "node:fs";
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
const { scanText } = require(path.join(__dirname, "..", "..", "scripts", "audit-bot-honesty.cjs"));

const evm = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "..", "wallet", "wallet-address.json"), "utf8")
);
const PAY_TO = process.env.X402_PAY_TO || evm.evmAddress;
const FACILITATOR_URL = process.env.X402_FACILITATOR_URL || "https://facilitator.payai.network";
const NETWORK = process.env.X402_NETWORK || "eip155:8453";
const PRICE = process.env.X402_PRICE || "$0.05";
const PORT = Number(process.env.X402_MCP_PORT || 4022);

const FREE_METHODS = new Set(["initialize", "notifications/initialized", "ping", "tools/list", "resources/list", "prompts/list"]);

// ---- MCP server with one paid tool ----
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

// Free demo (no payment) so buyer agents can try the tool before paying —
// same pattern several vendors in awesome-x402-mcp-services use (demo=true free).
mcp.registerTool("demo_audit", {
  title: "Free demo of the audit (fixed sample, no payment)",
  description: "Runs the scanner on a small built-in bad-bot sample and returns the findings. Free; no x402 payment.",
  inputSchema: {},
}, async () => {
  const sample = "state.earnings.total_usd += amount; // testnet claim\nawait fetch('https://faucet.example/api/claim');";
  const findings = scanText(sample, "sample-bot.js");
  return { content: [{ type: "text", text: JSON.stringify({ demo: true, signalCount: findings.length, findings }, null, 2) }] };
});

// demo_audit stays free; audit_bot_code is metered.
const FREE_TOOLS = new Set(["demo_audit"]);

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
        method: "POST",
        bodyType: "json",
        input: { code: "state.earnings.total_usd += amount;", filename: "bot.js" },
        inputSchema: { type: "object", properties: { code: { type: "string" }, filename: { type: "string" } }, required: ["code"] },
        output: { example: { signalCount: 1, findings: [{ rule: "TESTNET_AS_USD", severity: "high", line: 1 }] } },
      }),
    },
  },
});
// Gate ONLY paid JSON-RPC methods; leave the MCP handshake free.
httpServer.requiresPayment = function (context) {
  const body = context.adapter?.getBody?.() || {};
  if (FREE_METHODS.has(body.method)) return false;
  if (body.method === "tools/call") {
    return !FREE_TOOLS.has(body?.params?.name);  // paid tools metered; demo_audit free
  }
  return true;                                   // anything else on /mcp -> require payment
};

const app = express();
app.use(express.json({ limit: "2mb" }));
app.get("/health", (_req, res) => res.json({ ok: true, kind: "mcp", payTo: PAY_TO, network: NETWORK, price: PRICE }));
app.use(paymentMiddlewareFromHTTPServer(httpServer, undefined, undefined, true));

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
  console.log(`=== x402 MCP server :${PORT} (USDC on ${NETWORK} -> ${PAY_TO}, ${PRICE}/tools/call) ===`);
});
