# Paid x402 agent — crypto-bot honesty audit + keyless market data (HTTP + MCP)

Two pay-per-call products on one server, no Stripe, no signup, no API key, no
human in the loop. A buyer (human or AI agent) gets an `HTTP 402` challenge and
settles it with **USDC on Base or Solana** — the funds land directly in the
seller wallet through the x402 facilitator.

1. **Crypto-bot honesty audit** — scans one JS/TS source file for the bug
   patterns that make a bot *report income it never earned*. `0.01` USDC/call.
2. **Keyless crypto market data** — price, search, market caps, chain TVL,
   stablecoin supply, trending DEX tokens, live gas, from public upstreams.
   `0.01` USDC/call.

Both networks are offered in the same challenge (509 of the ~1000 resources
indexed by the facilitator settle on Solana vs 456 on Base, so Base-only pricing
excluded the majority of paying agents). On Solana the facilitator is the
`feePayer`, so receiving costs the seller nothing.

Surfaces:

- **HTTP:** `POST /audit` + the seven `GET` data routes below
- **MCP (Model Context Protocol):** `POST /mcp`, 9 tools — `audit_bot_code`, `get_token_price`, `search_tokens`, `top_markets`, `chain_tvl`, `stablecoin_supply`, `trending_tokens`, `gas_prices` (paid) + `demo_audit` (free, no payment)
- Listed in the official MCP Registry as `io.github.kaminariouji/x402-audit-agent`

## Live endpoint

```
https://labored-safari-islamic.ngrok-free.dev
```

- `GET /health` → 200 (free, reports both settlement networks)
- `POST /audit` unpaid → `HTTP 402 Payment Required` (x402 terms + Bazaar discovery extension in the `payment-required` header)
- MCP handshake (`initialize`, `tools/list`) and `demo_audit` → free; `audit_bot_code` → 402 until paid
- `GET /mcp` → `405 Allow: POST` (Streamable-HTTP servers that don't offer SSE must answer 405, not 404, or indexers mark a live server dead)
- Discovery metadata: `GET /.well-known/x402-info`, `/.well-known/x402`, `/openapi.json`, `/llms.txt`; `GET /audit` → 405 live-probe

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
POST /audit            # 0.01 USDC — accepts eip155:8453 (Base) or solana:5eykt… (Solana)
{ "code": "<one JS/TS file>", "filename": "bot.js" }
```

Returns `{ scannedBytes, signalCount, findings[] }` after settlement.

### Keyless market data — 0.01 USDC per call

No API key and no account on either side; each route reads a pinned public
upstream (CoinGecko/CoinPaprika, DefiLlama, DexScreener, public RPC) with a 30s
cache. Upstream hosts are hardcoded and inputs are validated — the server never
fetches a caller-supplied URL.

| Route | Returns |
|---|---|
| `GET /price?address=0x…\|<solana mint>` | DEX spot price, liquidity, FDV, mcap, 24h volume (highest-liquidity pair) |
| `GET /search_tokens?q=pepe&limit=10` | best-matched pairs across chains |
| `GET /markets?vs=usd&limit=25` | top coins by market cap with 1h/24h/7d change |
| `GET /tvl?limit=25` | DeFi value locked ranked per chain, in USD |
| `GET /stablecoins?limit=20` | USD-pegged supply by asset with peg mechanism |
| `GET /trending?limit=10&chain=base` | currently promoted DEX tokens with live quotes |
| `GET /gas?chains=base,arbitrum` | live gas price + base fee in gwei |

Every response carries `caveat: "public aggregator snapshot, not an oracle"`.
`node data-selftest.mjs` hits the real upstreams and asserts both the data shape
and that an unpaid call is answered `402` with **two** network accepts (it must
be run with `PORT` set, e.g. `PORT=10999`).

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

Env: `X402_PAY_TO` (Base receiving wallet) and `X402_PAY_TO_SOLANA` (Solana
receiving wallet) — both default to the project wallet; `X402_NETWORK`,
`X402_SOLANA_NETWORK`, `X402_PRICE`, `X402_PRICE_DATA`, `X402_FACILITATOR_URL`,
`X402_PUBLIC_URL`, `PORT`. Private keys never enter the image: the server only
holds *receiving* addresses.

> Note: an earlier prototype (`src/agents/x402-audit-service.mjs`, HTTP-only on
> `:4021`) still exists in this repo; `services/x402-mcp/server.mjs` is the
> current HTTP+MCP deployable and the one that is live.

## Honesty note

This is a *receiving* mechanism. It earns only when an external buyer chooses to
pay. It does not, and will not, fabricate settlements or inflate earnings — that
is the exact failure mode this tool detects in other bots. Findings are static
signals requiring human confirmation, not verdicts.
