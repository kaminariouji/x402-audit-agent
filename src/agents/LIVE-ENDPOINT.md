# x402 paid service — LIVE public endpoint

Every number below was read from the running service on 2026-09-28T14:43Z, not typed from memory. Re-verify with
the commands at the bottom; if they disagree with this file, the file is wrong — trust the responses.

> Every count below is a SNAPSHOT of the running route table, not a fact to trust from memory: the
> table grows when a band ships, and a stale number in a discovery document is the exact defect we keep
> finding in other people's listings. Re-read it: `curl -s <origin>/discovery/resources` (items) and the
> MCP `tools/list`. Last full re-measure: 2026-10-05T11:00Z, build `b609f42dfe142f561cf58534a92f65bf`,
> 146 payable resources / 146 MCP tools, of which /market/npm-package-risk, /market/npm-tree-risk and
> /market/github-repo-health are the newest band.
## Current public origin
`https://labored-safari-islamic.ngrok-free.dev`

| check | command | expected |
|---|---|---|
| app alive | `curl -i https://<origin>/health` | `200` |
| payment gate holds | `curl -i https://<origin>/chain/heads` | **`402`** with `PAYMENT-REQUIRED` terms |
| what we sell | `curl https://<origin>/discovery/resources` | snapshot: **146** at last measure; always re-read `items.length` live, both networks |
| human/agent-readable index | `curl https://<origin>/llms.txt` | route-by-route list with prices |
| MCP endpoint | `POST https://<origin>/mcp` (`initialize`) | `200`; count = `result.tools.length` from `tools/list` (146 at last measure) |

## Prices as published
- every data read (136 routes at last measure): **$0.001** per call
- `POST /audit` (crypto-bot honesty scan): **$0.01** per call
- settled in USDC on **Base** (`eip155:8453`) **or Solana** (`solana:5eykt…Kvdp`), `scheme: exact`
- payout address advertised in every 402 challenge: EVM `0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b`,
  Solana `5NWSPyJChL2NJf3oEr6Mh4vLvG5S3qQmf5S4v7v8wEV4`
- no account, no API key, no signup: the 402 challenge carries the terms, the buyer signs and resends

## What the service actually is
1. `POST /audit` — static scan of one JS/TS source file for the bug patterns that make a trading bot report
   income it never earned (testnet amounts summed as USD, self-assigned payout prices, unsigned quote → revenue,
   `balanceOf` read failures treated as zero, etc.). Findings come back with `file:line` and rule IDs.
2. 136 read routes at last measure (the number moves with the table — read `/discovery/resources`) — chain state (blocks, balances, allowances, approvals, bytecode capability scans, EIP-1967
   proxy checks) and public venue data (Kraken, Coinbase Exchange, OKX, Bitfinex, Gate, KuCoin, Deribit,
   Hyperliquid, DeFiLlama, mempool.space, blockchain.info, alternative.me, Polymarket, DexScreener, Jupiter,
   Blockscout), each mirrored as an MCP tool with an `outputSchema` + identical `structuredContent`.
3. `/market/x402-*` and `/market/token-verdict` — the differentiated band: a measured 30-day demand map of this
   x402 rail itself (calls and unique payers per listed host, taken from the public discovery index) and an
   assembled per-token risk verdict (deepest pool + buy/sell counts + bytecode capability selectors + proxy
   check, with an explicit list of what it did not verify).

## Availability rule — we refuse money we cannot honor
The x402 gate settles a valid payment *before* the handler runs, so an unreachable public vendor would leave
a buyer charged and answered with a 502. Since 2026-09-28 a paid data route whose **every** venue is
currently unreachable is refused *before* the challenge:

```
$ curl -i https://<origin>/market/btc-fee-estimates        # while mempool.space is down
HTTP/1.1 503 Service Unavailable
{"error":"upstream_unavailable","route":"GET /market/btc-fee-estimates","venues":["mempool.space"],
 "charged":false,"note":"…no payment challenge is issued for a reading we could not deliver…"}
```
No `accepts[]`, no data, nothing payable; the mirrored MCP tool answers the same refusal without settling.
A venue is marked unreadable only by a thrown fetch (DNS/connect/timeout) on a path taken from the route's own
code, or by a real read failure (`mj` 5xx/429/timeout), and any successful read clears it immediately — a base
ping once timed out for `api.gateio.ws` while its real `order_book` endpoint answered 200, which would have
refused five sellable routes. Refusing money on a false signal is worse than the 502 it prevents.

Four refinements, each added after a measurement and each covered by `.tmp-check/venue-blacklist-instrument.mjs`
(stubbed fetch, real `mj` + real route handlers, 10 rules, and a per-phase assert that the stub was actually
reached — the first version reused one identifier, the memo served a cached 200, and two phases "passed"
while fetching nothing):

1. a route stays sellable while **any** of its venues is reachable, which is why the Bitcoin band answers 402
   (not 503) with `mempool.space` marked down;
2. a `tolerate` route (lookup-shaped: Bitfinex 500 / GitHub 403 for a bad identifier is an answer *about the
   asset*) blacklists only on the **second** tolerated 403/429/5xx within a minute — one typo must not turn
   every route on that host into a 503. A tolerated 404 never blacklists;
3. **HTTP 200 whose body is an HTML/XML page is not a reading.** The old code `JSON.parse`-failed, kept the
   page as a bare value, memoized it, and served that page to every later buyer for the whole TTL — that is
   how `/market/btc-chain-tip` threw "returned no height". A page is now refused, never cached, and triggers
   the same fallback chain as an unreachable host;
4. per-host read budget: 4s for the three fast Bitcoin readers (healthy answers measured 0.27–0.95s, every
   11-second sample was `mempool.space` hanging with no answer), 12s elsewhere. Six of the nine `/market/btc-*`
   routes dropped below the instrument's 8s warning line; `/market/btc-chain-tip` is still ~12s because it
   makes two serial reads;
5. when the reach sweep has **already** marked `mempool.space` down, a read goes straight to the fallback
   chain instead of waiting out the primary's 4s budget. That closed the last slow route: `slow (>8s): (none)`
   across all 73 `/market/*` handlers, and `/market/btc-chain-tip` passes instead of failing. This is a
   separate call to `mempoolFallbackRead()`, deliberately *not* a URL rewrite — a fallback reached through
   the primary path would inherit "429/5xx marks you down", which is the false blacklist rule 1 exists to
   prevent. Guarded by the reverse case too: if every fallback fails, the marked-down primary still gets its
   honest attempt, so a vendor that recovered between sweeps is never locked out of serving;
6. **a cached or stale answer carries the venue that produced it.** `mk(host, …)` builds `source` from what
   `mj` returns, and neither the memo hit nor the `lastGood` stale path returned a host — so every second
   call inside the TTL answered with **no `source` key at all**. The live battery could not see this because
   it reads each route exactly once, i.e. always cold; the stubbed instrument caught it by making a second
   read on the same key. Both paths now carry the storing host, and the instrument asserts a cache hit and a
   stale serve each name a source. Skipping a known-down primary outright would be faster, and was not done: a 429
   from the community mirror must not blacklist it, and the ordered fallback chain is what makes
   `/market/btc-chain-tip` answer at all — `mempool.space` aborted, `mempool.emzy.de` answered
   `429 rate_limited` on both tip paths, `blockstream.info` (Electrs, path-gated to `/blocks/tip/*` because
   `/v1/fees/recommended` is a 404 there) served height 969029 and the tip hash.
Residual, known gap: a vendor that fails *between* checks still settles first (tracked in the project tasks).

## Published discovery surface (all free, all generated from the same route table)
| document | path | notes |
|---|---|---|
| x402 terms manifest | `/.well-known/x402` (+`.json`) | `resources` = 146 **strings** (the contract both measured paying sellers publish), `resource_calls` = `"POST /audit"` form, `resources_detail` = semantic objects with atomic `amount`+`asset`, plus `name`/`description`/`tags` at the head |
| client discovery | `/discovery/resources` | 146 items, identical set (drift check `.tmp-check/manifest-drift.mjs` = 0) |
| OpenAPI / briefing | `/openapi.json`, `/llms.txt` | parameters, 402 shape, prices |
| MCP server card | `/.well-known/mcp.json`, `/.well-known/mcp/server-card.json` | tool list generated from the registrations: names + descriptions byte-identical to `tools/list`, `authentication: none`, `free_tools`, per-class prices |
| ARD catalog | `/.well-known/ai-catalog.json`, `/.well-known/ard.json` | 5 entries, every URL verified to resolve (`scripts/…discovery-cards.mjs` = 23/23) |
| A2A card | `/.well-known/agent-card.json` (+`agent.json`) | both wire families on `/a2a` |
| Registry artifact | `services/x402-mcp/server.json` | local artifact v1.5.0, generated by `scripts/build-mcp-server-json.mjs` from the live wire. **Published row verified 2026-10-05T11:10Z** via `GET https://registry.modelcontextprotocol.io/v0/servers?search=kaminariouji` (note the nesting: rows are under `servers[].server`, and the list endpoint is `/v0/servers`, not `/v1/`): `1.5.0`, `isLatest=true`, `status=active`, `updatedAt=2026-09-29T16:19:11Z`. An earlier revision of this file claimed the published text was still v1.3.0-era and "republishing has not been done" — that claim was stale and contradicted the API; corrected here. **What is still true and still costs us:** `1.0.0`, `1.1.0`, `1.2.0` all remain `status=active` beside it, and v1.0.0's own description reads `0.05 USDC on Base` while v1.1.0 reads `9 MCP tools`. A client that walks versions without honouring `isLatest` still sees a $0.05 ceiling and a 9-tool surface for us — the most likely origin of the `price_max: 0.05` / `resource_count: 11` the buyer-side broker still holds. Nothing inside the app can retire another version's row; every document WE serve states $0.001–$0.01 and 146.

## How we look from outside (instruments we do not control)
- `agentprobe.org` (census of ~167k endpoints; grades an x402 route by GETting it unpaid: `402`+header=100,
  `404/405`=20, `2xx`=60 protocol-mismatch). Rows measured 2026-10-05T10:49Z: **8 rows — `/mcp` kind=mcp at
  `score:20 outcome:"protocol-mismatch"`, and 7 rows (`ard`, `llms-txt`, `agents-txt`, `robots`, `sigdir` on
  `/`, plus `x402` on `/audit` and `/gas`) at `score:null outcome:"http-error"`.** Those are outage reads,
  not new defects: during the 2026-09-30 bandwidth outage every path answered `ERR_NGROK_8010`, and this
  census row was 100 on 2026-09-28T18:21Z. Do NOT write "all rows 100" as a current fact — the last clean
  reading is history. Re-read: `GET https://agentprobe.org/api/search?q=labored-safari-islamic.ngrok-free.dev`,
  rows carry only `id,url,kind,outcome,score,name` (no timestamp), so age comes from the id and from history.
  The `/mcp` 20 is the one row that is plausibly structural: the census GETs it, and `/mcp` is POST-only by
  design (Streamable HTTP requires `initialize` first), so a 405/20 there is our transport, not our gate.
- `agent-tools.cloud` (aggregator/broker with keyless GET, feeds the census above; `GET /api/v1/ask` is what a
  paying agent is shown). Row re-read 2026-10-05T11:00Z: `health:"degraded"`, `http_status:400`,
  `conformance:"fail"`, `resource_count:11` (8 distinct paths held: `/audit /gas /markets /price
  /search_tokens /stablecoins /trending /tvl`), `price_min 0.001 / price_max 0.05`, `quality_score 41.7`,
  `tx_30d:1`, `payto_payers_30d:1`, `owner_verified:0` despite `owner_edited:["description","mcp_url","name"]`
  (our PATCH landed; the verify flag did NOT stick), `sources:[x402scan@2026-10-04T16:45Z]`,
  `health_checked:2026-10-04T21:53Z` — i.e. recorded while the tunnel was down. `/api/v1/ask` on 10 queries
  returns us in **0 of 10** answers (`scripts/broker-reach-check.mjs`), and the sellers it does steer agents
  to earn `tx_30d` 116–1,082 in exactly the categories we ship (gas, token safety, stablecoins, Polymarket,
  BTC fees, perp funding) at $0.001–$0.05.
- **Why the broker holds a $0.05 ceiling for us:** its `x402scan` harvest overlaps the MCP Registry, where our
  own `1.0.0` row is still `status=active` with `0.05 USDC on Base` in the description while `1.5.0`
  (`isLatest=true`) says $0.001–$0.01. A consumer that walks versions without honouring `isLatest` reads the
  old price. Verified 2026-10-05 via `GET https://registry.modelcontextprotocol.io/v0/servers?search=kaminariouji`.

- **Why a crawler can lose us at the edge (measured narrower than we first wrote it):** ngrok's free tier
  injects its own interstitial at HTTP 200 / `Ngrok-Error-Code: ERR_NGROK_6024` — but only for a **genuine
  browser User-Agent**. Re-measured 2026-10-05 across `/gas`, `/llms.txt`, `/.well-known/x402` × 7 UAs:
  `node`, `curl/8.4.0`, `python-httpx/0.28.1`, `Googlebot/2.1`, our own tool UAs and even an **empty** UA all
  receive the real `402`/`200` JSON; only `Mozilla/5.0 … Chrome/140 …` gets the 249-byte ngrok page. Per
  ngrok's own error reference there is **no free-plan toggle or config field** to disable it — the only exits
  are a non-browser UA, the `ngrok-skip-browser-warning` header, or a paid plan (not proposed: capital).
  `scripts/x402-rail-watch.mjs` §5c probes this each run and prints `EDGE_INTERSTITIAL` as a warning;
  `.tmp-check/health-probe-replay.mjs` replays 12 UA×Accept shapes per path on demand.
- **Who actually reaches us (access log, 24 h, read 2026-10-05T11:03Z):** 2,800 request lines, of which
  **2,714 carry `ua=node`** — that is our own instrument battery, not demand. Status split `402×1,579 /
  404×681 / 405×279` is likewise mostly self-inflicted (the variant drill's wrong names and verb matrix).
  Real external callers in 72 h: `mcpbeat/0.1` and `InvokeRankBot/0.1` completed `POST /mcp` handshakes
  (200/202), `Googlebot/2.1` read `/llms.txt` and `/.well-known/x402`, `python-httpx` probed `/mcp`.
  **`with_payment_header = 0`.** So MCP directories *can* index us even over ngrok; nobody has ever tried to
  pay. Never cite request volume as evidence of demand without the UA attribution — `node scripts/income-ledger.mjs`
  prints both.

Deployed bytes when this section was written: `services/x402-mcp/server.mjs` md5
`b609f42dfe142f561cf58534a92f65bf`, identical inside the `x402-audit` container at `/app/server.mjs`
(read with `MSYS_NO_PATHCONV=1 docker exec x402-audit md5sum /app/server.mjs` — Git Bash rewrites the
container path otherwise, and the failure looks like a missing file rather than a mangled one).

## Honest status of this project
**It has earned $0.** Settlements into the payout wallet: zero. Traffic is real but it is crawlers and liveness
monitors, not buyers, and no request has ever carried a payment header. Being reachable, payable and verified is
not the same as being bought — the constraint this project has never cleared is a payer, not the code.

Ledger as of 2026-10-05T11:03Z (`node scripts/income-ledger.mjs`, appended to `src/agents/income-ledger.json`):
`payto_base_usdc=0`, `payto_solana_usdc=0` across `0` token accounts, `settlements_24h=0`,
`with_payment_header=0`, `server_errors_24h=0` — and this zero is a **measured** zero because the same read path
returned `control_croo_escrow_usdc=1409.961` in the same run. The pre-registered verdict date for this goal is
**2026-10-06**; if the wallet still reads 0 then, the conclusion is that the demand exists (the broker steers
agents to sellers in our exact categories earning $0.001–$0.05 per call at 116–1,083 transactions per 30 days)
but not for a wallet with no audience, and the honest output is that measurement, not another listing.

## History of this file (why to trust the table above over prose)
Up to 2026-09-28 this page advertised `https://even-species-chicken-foreign.trycloudflare.com` — a session-long
Cloudflare quick tunnel that died days later — and an audit price of `$0.05`. Both were stale, which is exactly
the kind of claim that costs a cold seller a buyer. It also pointed readers at
`https://github.com/kaminariouji/x402-audit-agent`, a repository that does not exist; the service's published
`documentationUrl` and OpenAPI `contact.url` now resolve to `<origin>/llms.txt` instead, and the only remaining
mentions of that repo name are the MCP Registry identifiers, which must keep their published form.
