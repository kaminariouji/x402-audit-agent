# Crypto-Bot Honesty Audit — a paid x402 agent (HTTP + MCP)

A pay-per-call service that scans one JS/TS crypto-bot source file for the bug
patterns that make a bot *report income it never earned*. A buyer (human or AI
agent) pays **0.05 USDC on Base** and USDC settles straight into the seller
wallet via the x402 facilitator — no Stripe, no signup, no human in the loop.

Two surfaces, same scanner engine:

- **HTTP:** `POST /audit`
- **MCP (Model Context Protocol):** `POST /mcp`, tool `audit_bot_code` (paid) + `demo_audit` (free, no payment)

## Live endpoint

```
https://labored-safari-islamic.ngrok-free.dev
```

- `GET /health` → 200 (free)
- `POST /audit` unpaid → `HTTP 402 Payment Required` (x402 terms + Bazaar discovery extension in the header)
- MCP handshake (`initialize`, `tools/list`) and `demo_audit` → free; `audit_bot_code` → 402 until paid
- Discovery metadata: `GET /.well-known/x402-info`, `/openapi.json`, `/llms.txt`; `GET /audit` → 405 live-probe

## What it detects (real rule IDs)

Every finding cites `file:line` so a human can confirm it. These are the actual
rules in `audit-bot-honesty.cjs` (run `node audit-bot-honesty.cjs --selftest` to
see 5 of them fire on a known-bad sample and 0 on a hardened one):

| Rule | What it catches |
|---|---|
| `TESTNET_AS_USD` | a token amount added to a `total_usd` with no testnet guard |
| `BALANCE_FROM_FAILED_RPC` | RPC failure coerced to a confident balance of `0` |
| `CHAIN_NOT_VERIFIED` | `eth_getBalance` used without asserting `eth_chainId` |
| `ATTEMPT_COUNTED_AS_RESULT` | a counter incremented on *attempt*, not on success |
| `COOLDOWN_KEY_MISMATCH` | state-map written with a prefix but read without it → cooldown never fires |
| `SPECULATIVE_EARNINGS_TEXT` | `.md` copy promising profit from a zero-funded bot |

## The paid call

```
POST /audit            # 0.05 USDC on eip155:8453 (Base) via x402
{ "code": "<one JS/TS file>", "filename": "bot.js" }
```

Returns `{ scannedBytes, signalCount, findings[] }` after settlement.

## Run it (this is the deployable)

The lean, self-contained service lives in `services/x402-mcp/`:

```bash
cd services/x402-mcp
npm install
node server.mjs            # honors $PORT (default 10000)

# or Docker (runs as non-root, read-only fs, caps dropped):
docker build -t x402-audit .
docker run -p 127.0.0.1:10000:10000 --init --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 0.5 \
  x402-audit
```

Expose publicly with any tunnel, e.g. `ngrok http 10000 --url https://<your-domain>`.

Env: `X402_PAY_TO` (receiving wallet, default = the project wallet), `X402_NETWORK`,
`X402_PRICE`, `X402_FACILITATOR_URL`, `PORT`.

> Note: an earlier prototype (`src/agents/x402-audit-service.mjs`, HTTP-only on
> `:4021`) still exists in this repo; `services/x402-mcp/server.mjs` is the
> current HTTP+MCP deployable and the one that is live.

## Honesty note

This is a *receiving* mechanism. It earns only when an external buyer chooses to
pay. It does not, and will not, fabricate settlements or inflate earnings — that
is the exact failure mode this tool detects in other bots. Findings are static
signals requiring human confirmation, not verdicts.
