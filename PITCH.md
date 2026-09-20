# x402 Crypto-Bot Honesty Audit — Pitch

## The problem
Autonomous "crypto farming" bots routinely report income they never earned: they
count testnet drops as USD, swallow failed balance reads as a silent `0`, key
cooldowns so they double-claim, hit fake faucet endpoints, and print speculative
"profits" from text that was never a real fill. Users (and their agents) trust
these numbers. The failure mode is invisible because the bug is in the bot's own
reporting code.

## What we built
A **pay-per-call AI agent**, exposed both as an HTTP API and a live **MCP server**,
that scans one JS/TS crypto-bot source file for the exact bug patterns that make it
report fake earnings (testnet-as-USD, silent-zero balances, cooldown key-mismatch,
fake faucet endpoints, speculative-earnings text) and returns line-cited findings.

The twist that makes this a real product, not a demo: **it dogfoods the machine
economy it inspects.** The agent is *itself* paid exclusively in **x402 USDC
micropayments** — a buyer (human or another AI agent) gets an HTTP 402, pays a few
cents of USDC on Base via an x402 client, and the service settles straight to the
builder's wallet. No accounts, no API keys, no invoices.

## Architecture (live today)
- **Transport:** Express, Docker-hardened (non-root `node` user, `--read-only`,
  `--cap-drop ALL`, `--security-opt no-new-privileges`), published over a durable
  HTTPS tunnel.
- **Payments:** `@x402/express` + `ExactEvmScheme` on Base (`eip155:8453`),
  free keyless facilitator. Unpaid → 402 with x402 terms + Bazaar extension.
- **Two surfaces, one brain:** the same scanner (`scanText`) powers `POST /audit`,
  the free `demo_audit` MCP tool, and the paid `audit_bot_code` MCP tool.
- **Market-data routes** (the category that actually moves volume on x402):
  `GET /price?address=` (EVM *or* Solana mint spot price + liquidity + FDV) and
  `GET /search_tokens?q=` (token search) at **$0.01/call**, served from a pinned
  keyless upstream (no SSRF surface).
- **MCP gating:** `initialize` / `tools/list` / `demo_audit` are free so any MCP
  client can shake hands; only `tools/call` on paid tools is metered.

## Discovery & distribution (all public, all verified)
- Registered as a payable merchant on **x402scan** (free SIWX wallet signature).
- Published to the **official MCP Registry** via headless **GitHub Actions OIDC**
  (`io.github.kaminariouji/x402-audit-agent`) — no browser login.
- Full machine-readable discovery: `/.well-known/x402`, `/.well-known/x402-info`,
  `/openapi.json` (per-route `x-payment-info`), `/llms.txt`.
- Coinbase's keyless **CDP validator** returns `valid: true / accepted` for every
  paid route — i.e. the platform confirms we're eligible for x402 Bazaar indexing.

## Business model
Micro-priced, metered API + MCP calls in USDC on Base. Low unit cost ($0.01–0.05)
matches observed x402 buyer behavior (median ~$0.028/call); the market-data routes
target the single highest-volume x402 category. Revenue is fully automated and
non-custodial — the buyer signs an off-chain `transferWithAuthorization`, the
facilitator settles, USDC lands in the builder wallet.

## Roadmap
- Flip settlement to the CDP facilitator to index into the 23k-resource Bazaar
  where buyer agents search.
- Add a durable cloud host + a self-serve onboarding page for the MCP tool.
- Broaden audit rules to more bot frameworks (Python/Rust) and add an
  "honesty score" summary endpoint.

## Honest status
The mechanism works and moves real money end-to-end (verified: 402 challenge,
decoded payTo/amount/asset, scanner never runs unpaid). It has **not yet received
an organic third-party payment** — demand, not code, is the remaining gate. We are
publishing the true state rather than inflating a number — which is, literally,
the product.

Repo: https://github.com/kaminariouji/x402-audit-agent
