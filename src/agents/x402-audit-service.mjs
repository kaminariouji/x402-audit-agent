/**
 * x402 paid agent — "crypto-bot honesty audit as a service"
 *
 * Exposes a machine-payable HTTP endpoint. Any client (human or AI agent) that
 * POSTs a JS/TS source snippet gets the honesty scanner's findings back. Payment
 * is USDC on Base mainnet via the x402 protocol (HTTP 402 flow), settled by a
 * public facilitator and deposited straight into our wallet.
 *
 * Money flow — this is the important part:
 *   client  --(402 challenge)-->  us
 *   client  --(PAYMENT-SIGNATURE + USDC)-->  facilitator settles on-chain
 *   USDC    -->  PAY_TO wallet          (receiving costs us $0; buyer pays fees)
 *
 * Nothing here runs "for free": an unpaid POST never reaches the scanner, it just
 * gets a 402 with payment requirements. That is the whole point — the service is
 * the price gate.
 */
import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Reuse the exact same rules the CLI scanner uses (exported as CJS).
const { scanText } = require(path.join(__dirname, "..", "..", "scripts", "audit-bot-honesty.cjs"));

// --- Config (env overridable; wallet-address.json is the default payTo) ---
function readPayTo() {
  if (process.env.X402_PAY_TO) return process.env.X402_PAY_TO;
  try {
    const w = JSON.parse(
      fs.readFileSync(path.join(__dirname, "..", "..", "wallet", "wallet-address.json"), "utf8")
    );
    return w.evmAddress;
  } catch {
    return null;
  }
}

const PAY_TO = readPayTo();
const FACILITATOR_URL = process.env.X402_FACILITATOR || "https://facilitator.payai.network";
const NETWORK = process.env.X402_NETWORK || "eip155:8453"; // Base mainnet = real USDC
const PRICE = process.env.X402_PRICE || "$0.05";
const PORT = process.env.X402_PORT || 4021;

if (!PAY_TO) {
  console.error("No payTo wallet: set X402_PAY_TO or create wallet/wallet-address.json");
  process.exit(1);
}

// --- App ---
const app = express();
app.use(express.json({ limit: "256kb" }));

const facilitatorClient = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
const server = new x402ResourceServer(facilitatorClient).register(NETWORK, new ExactEvmScheme());

app.use(
  paymentMiddleware(
    {
      "POST /audit": {
        accepts: {
          scheme: "exact",
          price: PRICE,
          network: NETWORK,
          payTo: PAY_TO,
        },
        description: "Scan a JS/TS crypto-bot source file for the bug patterns that make it report income it never earned.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            method: "POST",
            bodyType: "json",
            input: { code: "state.earnings.total_usd += amount;", filename: "bot.js" },
            inputSchema: {
              type: "object",
              properties: {
                code: { type: "string", description: "One JS/TS source file to scan" },
                filename: { type: "string" },
              },
              required: ["code"],
            },
            output: {
              example: {
                scannedBytes: 42,
                signalCount: 1,
                findings: [{ rule: "TESTNET_AS_USD", severity: "high", line: 1, text: "…" }],
              },
            },
          }),
        },
      },
    },
    server,
    undefined,
    undefined,
    true
  )
);

// Free: service discovery / how-to-pay. Lets a human or crawler learn the price.
app.get("/", (_req, res) => {
  res.json({
    name: "crypto-bot-honesty-audit",
    endpoint: "POST /audit",
    price: PRICE,
    network: NETWORK,
    currency: "USDC",
    payTo: PAY_TO,
    protocol: "x402 (HTTP 402)",
    request: { code: "<string: one JS/TS file>", filename: "optional.js" },
    returns: "findings[] with { rule, severity, line, text, note }; summary notes that signals require human review",
  });
});

// Free liveness probe.
app.get("/health", (_req, res) => res.json({ ok: true, payTo: PAY_TO, network: NETWORK }));

// Standard discovery metadata pulled by x402 registries/crawlers (Bazaar, overlay).
app.get("/.well-known/x402-info", (_req, res) => {
  res.json({
    name: "crypto-bot-honesty-audit",
    description:
      "Paid x402 agent: scans a JS/TS crypto-bot source file for the bug patterns that make it report income it never earned (testnet-as-USD, silent-zero balances, cooldown key mismatch, fake faucet endpoints, attempts-counted-as-results).",
    documentationUrl: "https://github.com/kaminariouji/x402-audit-agent",
    contactUrl: "https://github.com/kaminariouji",
    protocol: "x402 (HTTP 402)",
    pricing: {
      currency: "USDC",
      network: NETWORK,
      endpoints: [{ path: "/audit", method: "POST", price: PRICE }],
      freeEndpoints: ["/", "/health", "/.well-known/x402-info"],
    },
    capabilities: ["analyze", "audit", "classify"],
    payTo: PAY_TO,
  });
});

// Paid: only reached after the facilitator confirms settlement.
app.post("/audit", (req, res) => {
  const { code, filename } = req.body || {};
  if (typeof code !== "string" || code.length === 0) {
    return res.status(400).json({ error: 'body must be { "code": "<source string>" }' });
  }
  const findings = scanText(code, filename || "submitted.js");
  res.json({
    scannedBytes: code.length,
    signalCount: findings.length,
    findings,
    disclaimer:
      "These are static-analysis signals. Each must be confirmed by reading the cited line. Not a guarantee of correctness or profitability.",
  });
});

const http = app.listen(PORT, () => {
  console.log(`\n=== x402 audit agent listening on http://localhost:${PORT} ===`);
  console.log(`  receiving USDC on ${NETWORK} -> ${PAY_TO}`);
  console.log(`  price per /audit call: ${PRICE}`);
  console.log(`  facilitator: ${FACILITATOR_URL}`);
  console.log(`\n  unpaid POST /audit -> HTTP 402 + PAYMENT-REQUIRED (this proves the price gate works)`);
});

// The facilitator verifies against a live Base node; if it's unreachable at boot,
// say so loudly rather than pretending payments will settle.
setTimeout(() => {
  if (http.listening) return;
  console.error("server failed to bind");
}, 2000);
