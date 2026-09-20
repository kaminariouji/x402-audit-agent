# x402 Audit Agent — a paid API that tells you if your crypto bot is lying

An autonomous **x402** service: it exposes one paid HTTP endpoint and, once a
buyer (human or AI agent) pays **0.05 USDC on Base**, it scans a JS/TS crypto-bot
source file for the bug patterns that make a bot *report income it never earned*.

It receives payment **programmatically** — no Stripe, no account, no human in the
loop. USDC settles straight into the seller wallet via the x402 facilitator.

## Why this exists

Most "autonomous crypto earning bots" earn nothing. They look profitable because
of code bugs. This agent detects exactly those:

| Rule | What it catches |
|---|---|
| `TESTNET_AS_USD` | testnet token claims (worth $0) summed into a `total_usd` |
| `SILENT_ZERO_BALANCE` | a balance RPC that swallows failures and reports `0` |
| `COOLDOWN_KEY_MISMATCH` | read key ≠ write key → cooldown never fires |
| `SPECULATIVE_EARNINGS_TEXT` | docs/comments promising earnings with no funding path |
| `FAUCET_GUESSWORK` | claims against faucet URLs that don't actually exist |

## The paid endpoint

```
POST /audit            # 0.05 USDC on Base (eip155:8453) via x402
{ "code": "<one JS/TS file>", "filename": "bot.js" }
```

Unpaid request → `HTTP 402 Payment Required` with x402 terms.
Free endpoints: `GET /`, `GET /health`, `GET /.well-known/x402-info`.

## Run it

```bash
node src/agents/x402-audit-service.mjs        # listens on :4021
# expose publicly (demo):  cloudflared tunnel --url http://localhost:4021
```

Env: `X402_PAY_TO` (receiving wallet), `X402_NETWORK`, `X402_PRICE`, `X402_FACILITATOR_URL`.

## Honesty note

This is a *receiving* mechanism. It can only earn when an external buyer chooses
to pay. It does not, and will not, fabricate settlements or inflate earnings —
that is the exact failure mode this tool detects in other bots.
