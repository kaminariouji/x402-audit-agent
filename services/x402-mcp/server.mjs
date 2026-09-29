// x402-gated paid agent — lean, self-contained deployable (MCP + HTTP audit).
// Free handshake + free demo + free discovery; paid tools/call and POST /audit via x402 USDC.
import express from "express";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
// The card below states which protocol revisions this server negotiates, so it reads them from the
// installed SDK instead of typing a list that could claim a version the transport does not accept.
import { SUPPORTED_PROTOCOL_VERSIONS, LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";
import { x402ResourceServer, x402HTTPResourceServer, HTTPFacilitatorClient } from "@x402/core/server";
import { paymentMiddlewareFromHTTPServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { z } from "zod";
import { handleA2ARequest, handleA2AX402Request, a2aX402ExtensionRequested, X402_A2A_EXT_URI } from "./a2a.mjs";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const { scanText, RULES } = require(path.join(__dirname, "audit-bot-honesty.cjs"));
const SEVERITY_BY_RULE = new Map(RULES.map((r) => [r.id, r.severity]));

// Receiving wallet (public address only; safe to embed). Override with X402_PAY_TO.
const PAY_TO = process.env.X402_PAY_TO || "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b";
const FACILITATOR_URL = process.env.X402_FACILITATOR_URL || "https://facilitator.payai.network";
const NETWORK = process.env.X402_NETWORK || "eip155:8453";
const PRICE = process.env.X402_PRICE || "$0.01";
// Pricing comes from the measured market, not guesswork: across all 6,605 resources cataloged by
// our facilitator the median call is $0.005, p75 is $0.02 and 52% of the market sits at or below
// $0.005 — a $0.05 audit was in the most expensive 17% of the ecosystem, so commodity quotes are
// priced at $0.001 and the differentiated audit at $0.01 (both env-overridable).
const PRICE_DATA = process.env.X402_PRICE_DATA || "$0.001"; // per-call price for the market-data route
const PORT = Number(process.env.PORT || 10000); // Render injects PORT
// Public origin used in discovery metadata (OpenAPI servers, x402 resource fan-out).
const PUBLIC_URL = (process.env.X402_PUBLIC_URL || "https://labored-safari-islamic.ngrok-free.dev").replace(/\/+$/, "");
// 509 of the ~1000 resources indexed by our facilitator settle on Solana vs 456 on Base, so
// Base-only pricing excluded the majority of paying agents. One challenge, both networks; the
// Solana entry carries the facilitator's feePayer, so receiving USDC still costs the wallet $0.
const SOLANA_NETWORK = process.env.X402_SOLANA_NETWORK || "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const PAY_TO_SOLANA = process.env.X402_PAY_TO_SOLANA || "5NWSPyJChL2NJf3oEr6Mh4vLvG5S3qQmf5S4v7v8wEV4";
// Order is a money-path decision, not cosmetic: x402HTTPClient's default selector takes accepts[0],
// so whichever entry is first is where an unconfigured buyer's payment attempt goes.
//   Base   -> VERIFIES. Measured against this very acceptance (evm-key-ab.mjs), payai /verify accepts a
//             correctly-signed EIP-712 TransferWithAuthorization and fails only at the signer's balance
//             (invalid_exact_evm_insufficient_balance) for 3/3 fresh zero-balance keys. An earlier
//             "payai refuses all EVM" reading was a confound: every probe had reused the well-known
//             anvil test key 0x70997970…, which payai rejects as invalid_exact_evm_signature.
//   Solana -> RECEIVING COSTS US $0, BUT ONLY SOME BUYERS CAN PAY US. Measured two live Solana x402
//             settlements (.tmp-check/sol-ata-creation-tx.mjs): the PAYER's transaction carried
//             spl-associated-token-account `create` + transferChecked in one tx, with `source` = the
//             payer, so the seller's ATA rent (getMinimumBalanceForRentExemption(165) = 1488440
//             lamports, not the 2039280 we had quoted) was paid by the buyer and our wallet paid
//             nothing. So "fund the ATA first" was never a zero-capital blocker and is retracted.
//             What IS true: the reference client derives both ATAs and appends only
//             [transferChecked, memo] (@x402/svm/dist/cjs/index.js:541-593 — no create instruction),
//             so a buyer on that client fails against an account that
//             does not exist yet. Our payTo has 0 token accounts, so until a create-capable buyer
//             pays us, only create-capable clients can settle here.
// So Base leads: it is the rail every buyer can settle on today, keyless.
const acceptsFor = (price) => ([
  { scheme: "exact", price, network: NETWORK, payTo: PAY_TO },
  { scheme: "exact", price, network: SOLANA_NETWORK, payTo: PAY_TO_SOLANA },
]);
// Bazaar catalog search only reads what the 402 challenge carries: serviceName (<=32 chars),
// the FIRST 5 tags, description and iconUrl (see @x402/extensions sanitize* rules). Facilitators
// soft-drop anything over those limits, so the arrays below are capped at 5, strongest first.
const SERVICE_NAME = "x402 Audit + Market Data";
// Every document we publish must resolve. `github.com/kaminariouji/x402-audit-agent` is a 404 — the service has no
// public repo — so the canonical "who is behind this endpoint / what does it really do" pointer is our own
// live machine-readable page, which no buyer has to trust and no redeploy can stale out.
const DOCS_URL = `${PUBLIC_URL}/llms.txt`;
const ICON_URL = process.env.X402_ICON_URL || "https://github.com/kaminariouji.png";
// Shared pricing block for every human/crawler-facing discovery route.
const PAYMENT_INFO = {
  protocol: "x402 (HTTP 402)", currency: "USDC",
  // Mirrors acceptsFor: Base first, because that is the network a default client should try.
  networks: [
    { network: NETWORK, label: "Base mainnet", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: PAY_TO, prices: { audit: PRICE, data: PRICE_DATA } },
    { network: SOLANA_NETWORK, label: "Solana mainnet", asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", payTo: PAY_TO_SOLANA, prices: { audit: PRICE, data: PRICE_DATA }, note: "the facilitator is feePayer and the payer creates + rents the destination token account inside its own tx (measured, .tmp-check/sol-ata-creation-tx.mjs), so receiving costs this wallet $0; use a client that appends createAssociatedTokenAccountIdempotent, because the reference @x402/svm client does not and our payTo has no USDC account yet" },
  ],
};

const FREE_METHODS = new Set(["initialize", "notifications/initialized", "ping", "tools/list", "resources/list", "prompts/list"]);
const FREE_TOOLS = new Set(["demo_audit", "x402_rail_heartbeat"]);
// Every GET route below the gate costs PRICE_DATA per call. The chain-state and venue reads are
// appended from DATA_ROUTES further down, so a new route cannot be added to the surface without
// being paid — the same table also feeds the challenge, the discovery documents and the MCP tools.
const PAID_DATA_PATHS = new Set(["/price", "/search_tokens", "/markets", "/tvl", "/stablecoins", "/trending", "/gas"]);
// Table used to emit the OpenAPI paths for the data routes.
const DATA_ROUTE_SPEC = {
  "/markets": { summary: "Top coins by market cap: price, market cap, volume, 1h/24h/7d change (paid via x402)", params: [["vs", false, "quote currency: usd, eur, gbp, jpy, btc, eth", "string", "usd"], ["limit", false, "rows 1-100 (default 25)", "number", 25]] },
  "/tvl": { summary: "DeFi value-locked ranking per chain in USD (paid via x402)", params: [["limit", false, "rows 1-100 (default 25)", "number", 25]] },
  "/stablecoins": { summary: "USD-pegged stablecoin supply by asset, peg mechanism and chain count (paid via x402)", params: [["limit", false, "rows 1-100 (default 20)", "number", 20]] },
  "/trending": { summary: "Currently promoted DEX tokens enriched with live price, liquidity and 24h volume (paid via x402)", params: [["limit", false, "rows 1-50 (default 10)", "number", 10], ["chain", false, "optional chainId filter, e.g. base or solana", "string", "base"]] },
  "/gas": { summary: "Live gas and base fee in gwei for Base and Arbitrum from public RPC (paid via x402)", params: [["chains", false, "comma list from: base, arbitrum", "string", "base,arbitrum"]] },
};

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
  if (!p) return { address, found: false, note: "no DEX pair where this address is the base token", source: "dexscreener", ts: new Date(nowMs()).toISOString() };
  return { address, found: true, name: p.baseToken?.name, symbol: p.baseToken?.symbol,
    priceUsd: p.priceUsd, liquidityUsd: p.liquidity?.usd, fdv: p.fdv, marketCap: p.marketCap, volume24h: p.volume?.h24,
    chainId: p.chainId, dex: p.dexId, pairUrl: p.url, source: "dexscreener", ts: new Date(nowMs()).toISOString() };
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
  return { query: rawQuery, count: results.length, results, source: "dexscreener", ts: new Date(nowMs()).toISOString() };
}

// ---- market-data helpers for the paid routes ----
// Every upstream host below is a compile-time constant and the variable part is validated or
// percent-encoded, so a caller cannot steer a request off these hosts.
const CACHE_MS = 30_000;
const memo = new Map();
async function cachedJson(key, url, init) {
  const hit = memo.get(key);
  if (hit && hit.exp > nowMs()) return hit.val;
  const t0 = Date.now();
  const r = await fetch(url, init);
  clockSample(t0, r);
  if (!r.ok) throw new Error(`upstream ${new URL(url).host} returned HTTP ${r.status}`);
  const val = await r.json();
  if (val && typeof val === "object" && !Array.isArray(val) && val.error) {
    throw new Error(`upstream ${new URL(url).host} returned ${String(val.error).slice(0, 80)}`);
  }
  memo.set(key, { exp: nowMs() + CACHE_MS, val });
  return val;
}
const UP = {
  coingeckoMarkets: "https://api.coingecko.com/api/v3/coins/markets",
  paprikaTickers: "https://api.coinpaprika.com/v1/tickers",
  llamaChains: "https://api.llama.fi/v2/chains",
  llamaStables: "https://stablecoins.llama.fi/stablecoins",
  dexscreenerBoosts: "https://api.dexscreener.com/token-boosts/latest/v1",
};
// ---- chain-state primitives: the measured $0.001 band ----
// Why this exists: verified on-chain against the winners' own payTo wallets (.tmp-check/competitor-take.mjs),
// the routes that actually settle per-call money are cheap chain reads at $0.001 (api.onesource.io
// $6.76/day, a paywalled public RPC $7.92/day), while the audit category we already sell tops out at
// $0.69/day at 200x our price. The other lever is surface, not price: median unique payers per 30d rise
// from 14 at 6-15 published endpoints to 40 at 16-40, while the median ask is $0.01 in every bucket.
// So: more atomic chain-read routes, each its own priced resource, at the price the money is at.
// A caller picks a chain out of this map and never supplies a URL, so no route here can be steered off
// these hosts; every variable part is validated against a strict shape before it reaches fetch.
// Each chain carries TWO measured public hosts. One host is not enough on a paid route: a free public
// node 429s under a fan-out (a single /chain/token-meta call fires five reads), and my first run of
// .tmp-check/chain-selftest.mjs proved that shows up as nulls in a payload the buyer already paid for.
// Every host below passed .tmp-check/probe-rpc-burst.mjs — 24 state reads at concurrency 3, all
// non-empty, checked against Multicall3 (0xcA11bde0…6CA11), which is deployed at that same address on
// all seven chains, so "0x" from a host is a wrong answer rather than an absent contract.
const CHAINS = {
  base: { rpcs: ["https://mainnet.base.org", "https://base.drpc.org"], chainId: 8453, label: "Base", native: "ETH" },
  ethereum: { rpcs: ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"], chainId: 1, label: "Ethereum", native: "ETH" },
  arbitrum: { rpcs: ["https://arb1.arbitrum.io/rpc", "https://arbitrum.drpc.org"], chainId: 42161, label: "Arbitrum One", native: "ETH" },
  // bsc-dataseed.binance.org is listed all over the internet and is dead: every method fails at the
  // transport layer (measured twice in .tmp-check/rpc-host-matrix.out, 2026-09-24). Keeping it first
  // meant a BSC buyer paid the timeout of a nonexistent host before reaching a live one. The two
  // bnbchain.org seeds answer every method this file uses, including eth_getBlockReceipts.
  bsc: { rpcs: ["https://bsc-dataseed1.bnbchain.org", "https://bsc-dataseed2.bnbchain.org", "https://bsc.drpc.org"], chainId: 56, label: "BNB Smart Chain", native: "BNB" },
  polygon: { rpcs: ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org"], chainId: 137, label: "Polygon PoS", native: "POL" },
  optimism: { rpcs: ["https://mainnet.optimism.io", "https://optimism.drpc.org"], chainId: 10, label: "OP Mainnet", native: "ETH" },
  avalanche: { rpcs: ["https://api.avax.network/ext/bc/C/rpc", "https://avalanche.drpc.org"], chainId: 43114, label: "Avalanche C-Chain", native: "AVAX" },
};
const CHAIN_KEYS = Object.keys(CHAINS);
// The two chains /gas already quotes, derived so the two tables cannot drift apart.
const RPC = { base: CHAINS.base.rpcs[0], arbitrum: CHAINS.arbitrum.rpcs[0] };
const CURRENCIES = new Set(["usd", "eur", "gbp", "jpy", "btc", "eth"]);
const TX_COST_CURRENCY = process.env.X402_TX_COST_CURRENCY || "usd";

class HttpError extends Error {
  constructor(status, message) { super(message); this.name = "HttpError"; this.status = status; }
}
const bad = (m) => { throw new HttpError(400, m); };

// ---- the clock this service publishes -------------------------------------------------------
// Measured 2026-09-24 on the machine that runs production: `Date.now()` sat exactly 7h00m behind
// true UTC (host and container share one clock; Coinbase /time, KuCoin /timestamp and Deribit's Date
// header agreed with each other to the second — .tmp-check/clock-offset2.txt). Every wall clock in
// the answers is then wrong by seven hours: `ts` contradicts the venue timestamps sitting in the
// same payload, `/chain/heads` ageSeconds clamps to a flattering 0 for every chain, and any query
// with a time window silently asks the venue for data that stopped seven hours ago.
// So the service keeps its own clock. Every HTTP response we already receive carries a `Date`
// header in UTC; the median of the last samples is the correction. Upstream hosts are compile-time
// constants, so nothing a caller controls can steer what we trust, and the magnitude cap plus the
// one-minute adoption rate bound how far a lying or broken CDN could drag us.
const CLOCK_SAMPLES = 24, CLOCK_ADOPT_MS = 60_000, CLOCK_SPAN_MS = 86_400_000, CLOCK_DEADBAND_MS = 1_000;
const clockOffsets = [];
let clockOffsetMs = 0, clockAdoptedAt = 0, clockHostSkewMs = null;
function clockSample(t0, res) {
  let remote;
  try { remote = Date.parse(res?.headers?.get?.("date") ?? ""); } catch { return; }
  // Reject anything implausible rather than letting a garbage header move a published timestamp.
  if (!Number.isFinite(remote) || remote < 1_600_000_000_000 || remote > 4_102_444_800_000) return;
  clockHostSkewMs = Math.round(remote - (t0 + Date.now()) / 2);
  clockOffsets.push(clockHostSkewMs);
  if (clockOffsets.length > CLOCK_SAMPLES) clockOffsets.shift();
  const now = Date.now();
  if (now - clockAdoptedAt < CLOCK_ADOPT_MS || clockOffsets.length < 3) return;
  const sorted = [...clockOffsets].sort((a, b) => a - b);
  const med = sorted[Math.floor(sorted.length / 2)];
  const next = Math.abs(med) < CLOCK_DEADBAND_MS ? 0 : med;
  // A host clock that drifts more than a day is a machine problem, not something to paper over.
  if (Math.abs(next) > CLOCK_SPAN_MS) return;
  if (next === clockOffsetMs) return;
  clockAdoptedAt = now;
  clockOffsetMs = next;
  console.log(`[clock] host wall clock is off by ${(next / 60000).toFixed(1)} min; published times corrected`);
}
// Absolute, publishable time. Relative arithmetic (durations, TTL comparisons) is unaffected by the
// offset either way, so both sides of a comparison use this and stay mutually consistent.
const nowMs = () => Date.now() + clockOffsetMs;
const nowSec = () => Math.floor(nowMs() / 1000);

const HEXQ = /^0x[0-9a-fA-F]+$/;
const ADDR_RE = /^0x[a-fA-F0-9]{40}$/;
const WORD_RE = /^0x[0-9a-fA-F]{64}$/;
const BLOCK_TAGS = new Set(["latest", "earliest", "pending", "safe", "finalized"]);
// "0x" and "" are NOT zero here: an empty result is "the node gave us nothing", and reporting it as a
// balance of 0 would be a fabricated read.
const toBig = (v) => (typeof v === "string" && HEXQ.test(v) ? BigInt(v) : null);
const gweiOf = (v) => { const b = toBig(v); return b === null ? null : Number(b) / 1e9; };
const fmtDec = (wei, dp) => { const s = String(wei).padStart(dp + 1, "0"); return `${s.slice(0, s.length - dp) || "0"}.${s.slice(s.length - dp)}`; };
const hexOf = (n) => `0x${BigInt(n).toString(16)}`;
const firstOf = (v) => (Array.isArray(v) ? v[0] : v);

// Canonical ERC-20/721 selectors and interface ids — all verified live against Base USDC by
// .tmp-check/chain-selftest.mjs rather than trusted from memory. The three ERC-721 approval/URI
// selectors were added only after .tmp-check/probe-erc721-approvals.mjs passed both controls: the
// mutated selector had to revert, and the same calldata had to be REFUSED by ERC-20 USDC (which
// really does not implement them). A selector that answers either way proves nothing.
const SEL = {
  balanceOf: "0x70a08231", allowance: "0xdd62ed3e", totalSupply: "0x18160ddd",
  decimals: "0x313ce567", name: "0x06fdde03", symbol: "0x95d89b41",
  ownerOf: "0x6352211e", supportsInterface: "0x01ffc9a7",
  tokenURI: "0xc87b56dd", getApproved: "0x081812fc", isApprovedForAll: "0xe985e9c5",
};
// event topic0 = keccak256 of the signature. Both of these are confirmed by eth_getLogs returning
// rows whose topic count matches the signature (3 for Approval/Transfer with indexed from/to).
const TOPIC = {
  Transfer: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
  Approval: "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
};
const ZERO_ADDR = "0x0000000000000000000000000000000000000000";
// Second band of contract views, added with the 46→100 endpoint expansion. Nothing here is recalled:
// .tmp-check/derive-selectors-100.mjs computes each value from its ABI string with
// toFunctionSelector()/keccak256(toBytes()) and aborts if it disagrees with SEL above, and
// chain-selftest re-derives them at runtime. (The first band taught this the hard way: a hand-typed
// getApproved selector made a live route answer `readable:null` for data the chain had.)
const SEL2 = {
  owner: "0x8da5cb5b",            // owner()
  implementation: "0x5c60da1b",   // implementation()
  paused: "0x5c975abb",           // paused()
  nonces: "0x7ecebe00",           // nonces(address)
  domainSeparator: "0x3644e515",  // DOMAIN_SEPARATOR()
  bal1155: "0x00fdd58e",          // balanceOf(address,uint256)
  supply1155: "0x346e6c0e",       // totalSupply(address,uint256)
  uri1155: "0x0e89341c",          // uri(uint256)
  balanceOfBatch: "0x4e1273f4",   // balanceOfBatch(address[],uint256[])
  contractURI: "0xe8a3d485",      // contractURI()
  permit: "0xd505accf",           // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
  revertString: "0x08c379a0",     // Error(string) — the ABI encoding of require("reason")
  revertPanic: "0x4e487b71",      // Panic(uint256) — the encoding of assert()/solidity>=0.8 panics
};
// EIP-1967 proxy slots = keccak256(label) - 1. Proven, not assumed: on Base the Gas Price Oracle
// predeploy answers implementation() and the slot read with the SAME address (measured
// .tmp-check/probe-100-surface.mjs, both 0x4f1db3c6…88f1) — that pair is the selftest's control.
const SLOT1967 = {
  implementation: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  admin: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
  beacon: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
};
// Selector -> ABI signature, for the two routes that answer "what can this bytecode do?" without
// executing anything. Derived by toFunctionSelector() in .tmp-check/derive-selectors-100.mjs; the
// selftest re-derives every key here and fails the build on drift. A 4-byte prefix that is not in
// this table is reported as unknown, never guessed at.
const KNOWN_SELECTOR = {
  "0xa9059cbb": "transfer(address,uint256)", "0x23b872dd": "transferFrom(address,address,uint256)",
  "0x095ea7b3": "approve(address,uint256)", "0xdd62ed3e": "allowance(address,address)",
  "0x70a08231": "balanceOf(address)", "0x18160ddd": "totalSupply()", "0x313ce567": "decimals()",
  "0x06fdde03": "name()", "0x95d89b41": "symbol()", "0x39509351": "increaseAllowance(address,uint256)",
  "0xa457c2d7": "decreaseAllowance(address,uint256)",
  "0x6352211e": "ownerOf(uint256)", "0xc87b56dd": "tokenURI(uint256)", "0x081812fc": "getApproved(uint256)",
  "0xe985e9c5": "isApprovedForAll(address,address)", "0xa22cb465": "setApprovalForAll(address,bool)",
  "0x42842e0e": "safeTransferFrom(address,address,uint256)", "0xb88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
  "0x00fdd58e": "balanceOf(address,uint256)", "0x346e6c0e": "totalSupply(address,uint256)",
  "0x4e1273f4": "balanceOfBatch(address[],uint256[])", "0x2eb2c2d6": "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
  "0x0e89341c": "uri(uint256)", "0xe8a3d485": "contractURI()",
  "0x01ffc9a7": "supportsInterface(bytes4)", "0xd505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
  "0x7ecebe00": "nonces(address)", "0x3644e515": "DOMAIN_SEPARATOR()",
  "0x8da5cb5b": "owner()", "0xf2fde38b": "transferOwnership(address)", "0x79ba5097": "acceptOwnership()",
  "0x715018a6": "renounceOwnership()", "0x5c975abb": "paused()", "0x8456cb59": "pause()", "0x3f4ba83a": "unpause()",
  "0x5c60da1b": "implementation()", "0x3659cfe6": "upgradeTo(address)", "0x4f1ef286": "upgradeToAndCall(address,bytes)",
  "0x8f283970": "changeAdmin(address)",
  "0x40c10f19": "mint(address,uint256)", "0xa0712d68": "mint(uint256)", "0x42966c68": "burn(uint256)",
  "0x79cc6790": "burnFrom(address,uint256)", "0xd0e30db0": "deposit()", "0x2e1a7d4d": "withdraw(uint256)",
  "0xac9650d8": "multicall(bytes[])", "0x38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
  "0xe8e33700": "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
  "0xa0e67e2b": "getOwners()", "0xe75235b8": "getThreshold()", "0x2f54bf6e": "isOwner(address)",
  "0x51945447": "execute(address,uint256,bytes,uint8)", "0x173825d9": "removeOwner(address)",
  "0xffa1ad74": "VERSION()", "0xdd5f5591": "domainSeparators()", "0xa82a8b96": "signMessages()",
};
const IFACE = { ERC165: "0x01ffc9a7", ERC20: "0x36372b07", ERC721: "0x80ac58cd", ERC721Metadata: "0x5b5e139f", ERC1155: "0xd9b67a26" };
// address and uint256 are left-padded; bytes4 is right-padded — getting this backwards silently
// returns a wrong answer instead of an error, so the two helpers stay separate.
const padLeft = (h) => String(h).replace(/^0x/, "").padStart(64, "0");
const padRight = (h) => String(h).replace(/^0x/, "").padEnd(64, "0");
const wordAddr = (a) => padLeft(a);
const wordUint = (v) => padLeft(BigInt(v).toString(16));
const wordBytes4 = (id) => padRight(id);
const calldata = (selector, ...words) => selector + words.join("");
const decodeAddress = (hex) => (WORD_RE.test(hex || "") ? `0x${hex.slice(-40)}` : null);
// An EMPTY storage slot is answered as 32 zero bytes, so decodeAddress turns "nothing stored here" into
// the zero address — and the zero address is truthy in JS. A plain wallet therefore read back as
// `isProxy: true, implementationFromSlot: 0x0000…`, which is a lie a buyer pays for. Slots and view
// calls that report a pointer need this; getApproved deliberately keeps the bare decode, because there
// the zero address IS the answer ("no operator approved") rather than an unset slot.
const slotAddr = (a) => (a && !/^0x0{40}$/.test(a) ? a : null);
function decodeString(hex) {
  if (!HEXQ.test(hex || "") || hex.length <= 2) return null;
  const buf = Buffer.from(hex.slice(2), "hex");
  try {
    if (buf.length >= 96 && buf.readUInt32BE(28) === 32) {
      const len = buf.readUInt32BE(60);
      if (len >= 0 && len <= 4096) return buf.subarray(64, 64 + len).toString("utf8").replace(/\0+$/, "") || null;
    }
    if (buf.length >= 64) return buf.subarray(32).toString("utf8").replace(/\0+$/, "") || null;
  } catch { /* not the ABI shape we expect */ }
  return null;
}

// Public nodes rate-limit by source IP, and one buyer hammering us would ban the whole origin.
// Three in-flight calls per host is the ceiling that keeps a paid burst from burning the endpoint.
// Two hosts per chain plus this cap means a five-read route spreads instead of queueing on one node.
const RPC_TIMEOUT_MS = Number(process.env.X402_RPC_TIMEOUT_MS || 8_000);
const HOST_INFLIGHT = Number(process.env.X402_RPC_INFLIGHT || 3);
const hostQueues = new Map();
async function acquireHost(url) {
  let q = hostQueues.get(url);
  if (!q) { q = { active: 0, waiters: [] }; hostQueues.set(url, q); }
  if (q.active < HOST_INFLIGHT) { q.active++; return; }
  await new Promise((resolve) => q.waiters.push(resolve));
}
function releaseHost(url) {
  const q = hostQueues.get(url);
  const next = q.waiters.shift();
  if (next) next(); else q.active--;
}
// Rotating the starting host keeps a single route's fan-out from piling all its reads onto one node,
// which is exactly the pattern that produced 429s inside a paid response on the first run.
let rpcCursor = 0;
// `rpcCallHost` is the primitive and answers the question a buyer cannot otherwise ask: WHICH node
// replied. A shared free node can serve a stale or wrong-chain answer while still returning 200, so
// /chain/client-version and /chain/network-id name the host that answered. `rpcCall` keeps the old
// result-only contract because every other route depends on it.
async function rpcCallHost(chainKey, method, params = []) {
  const ch = CHAINS[chainKey];
  if (!ch) bad(`unknown chain; allowed: ${CHAIN_KEYS.join(", ")}`);
  // Rotate the STARTING host once per call. It used to be `rpcCursor++ + i` inside the attempt loop,
  // which with two hosts evaluated to index c and then c+2 = c again: the "fallback" re-sent the exact
  // same request to the same node, so a slow publicnode produced a null field or a 502 on a route the
  // buyer had already paid for, and the second measured host never ran.
  const start = rpcCursor++;
  let lastErr = null;
  for (let i = 0; i < ch.rpcs.length; i++) {
    const url = ch.rpcs[(start + i) % ch.rpcs.length];
    await acquireHost(url);
    try {
      const t0 = Date.now();
      const r = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
      });
      clockSample(t0, r);
      if (!r.ok) throw new HttpError(502, `${ch.label} node ${new URL(url).host}: HTTP ${r.status}${r.status === 429 ? " (rate-limited, retry shortly)" : ""}`);
      const body = await r.json();
      // A JSON-RPC error is a real answer for a view call ("reverted"), so callers that expect reverts
      // catch it; on a route that cannot be a revert it must surface as our own fault, not null.
      if (body?.error) throw new HttpError(502, `${ch.label} ${method}: ${String(body.error.message ?? body.error).slice(0, 140)}`);
      return { result: body.result, host: new URL(url).host };
    } catch (e) {
      lastErr = e;
    } finally {
      releaseHost(url);
    }
  }
  throw lastErr instanceof HttpError ? lastErr
    : new HttpError(502, `${ch.label} ${method}: ${String(lastErr?.message || lastErr).slice(0, 140)}`);
}
const rpcCall = async (chainKey, method, params = []) => (await rpcCallHost(chainKey, method, params)).result;
const headOf = async (chain) => Number(toBig(await rpcCall(chain, "eth_blockNumber")) ?? 0);
// eth_getBlockReceipts is NOT universal on free nodes. Measured across every host this file ships
// (.tmp-check/rpc-host-matrix.out, 2026-09-24): mainnet.base.org answers -32601 "rpc method is
// unsupported" while base.drpc.org returns the whole list — so on Base a single throttled host turned a
// paid route into a 502 after the buyer had already settled. When no host supports the method, rebuild
// the same answer from per-transaction receipts for the first few transactions and mark it partial.
const RECEIPT_FALLBACK_CAP = 40;
async function blockReceipts(chainKey, block) {
  try {
    const raw = await rpcCall(chainKey, "eth_getBlockReceipts", [block]);
    if (Array.isArray(raw)) return { receipts: raw, partial: false };
  } catch {
    // Every host refused the method (or was down) — that is not the caller's failure, so do not bill it
    // as one: the per-transaction path below is the same data.
  }
  const blk = await rpcCall(chainKey, "eth_getBlockByNumber", [block, false]).catch(() => null);
  const hashes = Array.isArray(blk?.transactions) ? blk.transactions.filter((t) => typeof t === "string") : null;
  if (!hashes) return { receipts: null, partial: false };
  const got = await Promise.all(hashes.slice(0, RECEIPT_FALLBACK_CAP).map(
    (h) => rpcCall(chainKey, "eth_getTransactionReceipt", [h]).catch(() => null)));
  return { receipts: got.filter(Boolean), partial: true, total: hashes.length };
}
// ---- bounded log scan ----
// A free node refuses eth_getLogs on RESPONSE SIZE, not on span. Measured 2026-09-24 against the hosts
// this file pins (.tmp-check/probe-100-round5.mjs): on Base a 200-block USDC Transfer scan is answered
// `-32020 backend response too large` while 100 blocks returns 9,696 logs, base.drpc.org separately
// hard-caps spans at 2000/10000 blocks, and on Ethereum 500/1000 blocks abort at the socket. So one
// call for a 1000-block window — which is what /chain/logs advertises — would 502 a buyer who already
// settled. The window is therefore walked in 100-block chunks and any chunk a node refuses is halved
// down to one block, under a hard node-call budget so no paid read can spend the node.
const LOG_CHUNK = 100;
const LOG_BUDGET = 24;
async function scanLogs(chain, base, from, to, cap = 500) {
  const plan = [];
  for (let s = from; s <= to; s += LOG_CHUNK) plan.push([s, Math.min(to, s + LOG_CHUNK - 1)]);
  let spans = plan, calls = 0, overflow = false;
  const logs = [], uncovered = [];
  for (let pass = 0; pass < 8 && spans.length; pass++) {
    const batch = spans.splice(0, 8);
    const results = await Promise.all(batch.map(async ([a, b]) => {
      calls++;
      try {
        const r = await rpcCall(chain, "eth_getLogs", [{ ...base, fromBlock: hexOf(a), toBlock: hexOf(b) }]);
        return { ok: true, a, b, rows: r || [] };
      } catch (e) {
        return { ok: false, a, b, err: String(e?.message || e).slice(0, 140) };
      }
    }));
    const retry = [];
    for (const r of results) {
      if (r.ok) { logs.push(...r.rows); if (logs.length > cap * 2) overflow = true; continue; }
      if (r.a === r.b) { uncovered.push({ blocks: String(r.a), why: r.err }); continue; }
      const m = Math.floor((r.a + r.b) / 2);
      retry.push([r.a, m], [m + 1, r.b]);
    }
    spans = retry.concat(spans);
    if (overflow) break;
    if (calls >= LOG_BUDGET) {
      for (const [a, b] of spans) uncovered.push({ blocks: `${a}-${b}`, why: "not read: this scan spent its node-call budget" });
      spans = [];
      break;
    }
  }
  // Whatever is still queued here was deliberately not read: the pass limit was reached or enough logs
  // were already in hand. Reported, never silently dropped.
  for (const [a, b] of spans) uncovered.push({ blocks: a === b ? String(a) : `${a}-${b}`, why: "not read: the scan stopped before this range" });
  const key = (l) => Number(toBig(l.blockNumber) ?? 0n) * 1e6 + Number(toBig(l.logIndex) ?? 0n);
  logs.sort((x, y) => key(x) - key(y));
  return { logs, calls, uncovered, overflow, count: logs.length };
}
// An empty eth_call return is ambiguous: the contract may genuinely have no such function, or this free
// node may simply have dropped the call (measured 2026-09-24: BAYC supportsInterface(ERC-721) came back
// "0x" from publicnode while supportsInterface(ERC-721Metadata) answered true in the SAME request). A
// buyer must not be billed for an "unknown" that a second node disproves, so a blank answer gets one
// second opinion — rpcCall's rotating cursor puts that retry on the other host.
async function callContract(chain, to, data, block = "latest") {
  const params = [{ to, data }, block];
  const first = await rpcCall(chain, "eth_call", params);
  if (first === "0x" || first === "" || first == null) {
    const again = await rpcCall(chain, "eth_call", params).catch(() => null);
    if (again && again !== "0x") return again;
  }
  return first;
}
async function hasInterface(chain, to, id) {
  try {
    const v = toBig(await callContract(chain, to, calldata(SEL.supportsInterface, wordBytes4(id))));
    return v === null ? null : v > 0n;
  } catch { return null; }
}
async function tokenDecimals(chain, token) {
  try {
    const v = toBig(await callContract(chain, token, calldata(SEL.decimals)));
    if (v === null || v > 18n) return null;
    return Number(v);
  } catch { return null; }
}
// One JSON-RPC error from a token view must not fail the whole answer: a token without `name()` is a
// real token, not a broken response.
async function tryCall(chain, to, data, decode) {
  try { return decode(await callContract(chain, to, data)); } catch { return null; }
}
// A reverting view call is an answer ("this contract has no such method"), not a server fault — and it
// must never become a 502 on a route the buyer already paid for. The block argument is forwarded so a
// historical route cannot silently read the head while advertising a past block.
const callOrNull = (chain, to, data, block = "latest") => callContract(chain, to, data, block).catch(() => null);

// A reverted transaction's reason is not carried on most receipts, and eth_getLogs-by-txHash is refused
// on four of our seven chains (measured, .tmp-check/probe-100-surface.mjs). The honest recovery is to
// replay the exact call against the block BEFORE it landed and decode the standard Error(string) /
// Panic(uint256) abstractions. A free node without archive state answers "missing trie node" — that is
// reported as no-reason, never as a server fault, because the buyer already has the status they paid
// for. The two selectors are the derived pair in SEL2, not hand-typed.
function decodeRevert(raw) {
  const h = String(raw || "").toLowerCase();
  if (!/^0x([0-9a-f]{2}){4,}$/.test(h)) return null;
  const sel = h.slice(0, 10), body = h.slice(10);
  if (sel === SEL2.revertString) {
    const len = toBig(`0x${body.slice(64, 128)}`);
    if (len === null || len > 4096n) return null;
    return Buffer.from(body.slice(128, 128 + Number(len) * 2), "hex").toString("utf8");
  }
  if (sel === SEL2.revertPanic) {
    const code = toBig(`0x${body.slice(0, 64)}`);
    return code === null ? null : `Panic(0x${code.toString(16)})`;
  }
  return `custom error ${sel}`;
}
async function revertReasonOf(chain, tx, receipt) {
  if (typeof receipt?.revertReason === "string") {
    const direct = decodeRevert(receipt.revertReason) ?? String(receipt.revertReason).slice(0, 160);
    if (direct) return { reason: direct, source: "receipt" };
  }
  if (!tx?.input || tx.input === "0x" || !tx.blockNumber) return { reason: null, source: null };
  const call = { from: tx.from, data: tx.input, gas: tx.gas, value: tx.value };
  if (!tx.to) return { reason: null, source: null }; // a creation has no replay target
  call.to = tx.to;
  const bn = toBig(tx.blockNumber);
  if (bn === null) return { reason: null, source: null };
  const prev = hexOf(bn > 0n ? bn - 1n : 0n);
  try {
    const raw = await rpcCall(chain, "eth_call", [call, prev]);
    return { reason: decodeRevert(raw), source: raw && raw !== "0x" ? "replayed eth_call" : null };
  } catch (e) {
    const msg = String(e?.message || e);
    return { reason: decodeRevert(msg.match(/0x[0-9a-fA-F]{8,}/)?.[0] || ""), source: "reverted replay" };
  }
}

const COERCE = {
  chain: (v) => { const c = String(firstOf(v) ?? "").trim().toLowerCase(); if (!CHAINS[c]) bad(`chain must be one of: ${CHAIN_KEYS.join(", ")}`); return c; },
  chainList: (v, s) => {
    const list = [...new Set(String(firstOf(v) ?? "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean))];
    if (!list.length) bad(`${s.name} needs at least one chain: ${CHAIN_KEYS.join(", ")}`);
    if (list.length > s.max) bad(`${s.name} accepts at most ${s.max} chains per call`);
    for (const c of list) if (!CHAINS[c]) bad(`unknown chain "${c.slice(0, 24)}"; allowed: ${CHAIN_KEYS.join(", ")}`);
    return list;
  },
  address: (v, s) => { const a = String(firstOf(v) ?? "").trim(); if (!ADDR_RE.test(a)) bad(`${s.name} must be an EVM address (0x + 40 hex)`); return a; },
  addressList: (v, s) => {
    // Deduping is right for a LIST OF INDEPENDENT LOOKUPS (balances, tokens, owners) and wrong for a
    // POSITIONAL column: balanceOfBatch pairs accounts[i] with tokenIds[i], so collapsing a repeated
    // holder silently answered 1 pair where 2 were paid for. `positional` opts out.
    const parts = String(firstOf(v) ?? "").split(",").map((x) => x.trim()).filter(Boolean);
    const list = s.positional ? parts : [...new Set(parts)];
    if (!list.length) bad(`${s.name} needs at least one address`);
    if (list.length > s.max) bad(`${s.name} accepts at most ${s.max} addresses per call`);
    for (const a of list) if (!ADDR_RE.test(a)) bad(`${s.name} contains a malformed address`);
    return list;
  },
  txHash: (v, s) => { const h = String(firstOf(v) ?? "").trim(); if (!WORD_RE.test(h)) bad(`${s.name} must be a 32-byte hex hash (0x + 64 hex)`); return h.toLowerCase(); },
  // `calls=0xTo:0xData,0xTo:0xData` — validated field by field so a malformed pair is a pre-gate 400,
  // never a settled payment followed by an error. Hex-only data cannot contain a comma, so the split
  // is unambiguous, and both halves are re-checked rather than trusted to the caller's framing.
  callList: (v, s) => {
    const parts = String(firstOf(v) ?? "").split(",").map((x) => x.trim()).filter(Boolean);
    if (!parts.length) bad(`${s.name} needs at least one to:data pair`);
    if (parts.length > s.max) bad(`${s.name} accepts at most ${s.max} calls per request`);
    return parts.map((p, i) => {
      const ci = p.indexOf(":");
      if (ci === -1) bad(`${s.name}[${i}] must be formatted address:calldata`);
      const to = p.slice(0, ci).trim(), data = p.slice(ci + 1).trim();
      if (!ADDR_RE.test(to)) bad(`${s.name}[${i}] target is not an EVM address`);
      if (!/^0x([0-9a-fA-F]{2})*$/.test(data)) bad(`${s.name}[${i}] calldata must be hex with an even number of digits`);
      if ((data.length - 2) / 2 > s.maxData) bad(`${s.name}[${i}] calldata is over ${s.maxData} bytes`);
      return { to, data: data.toLowerCase() };
    });
  },
  uintList: (v, s) => {
    const parts = String(firstOf(v) ?? "").split(",").map((x) => x.trim()).filter(Boolean);
    if (!parts.length) bad(`${s.name} needs at least one decimal id`);
    if (parts.length > s.max) bad(`${s.name} accepts at most ${s.max} ids per call`);
    return parts.map((p, i) => {
      if (!/^\d+$/.test(p)) bad(`${s.name}[${i}] must be a non-negative integer`);
      const n = BigInt(p);
      if (n > BigInt(s.maxId ?? 1_000_000_000_000_000_000n)) bad(`${s.name}[${i}] is too large`);
      return n;
    });
  },
  word: (v, s) => { const h = String(firstOf(v) ?? "").trim(); if (!WORD_RE.test(h)) bad(`${s.name} must be a 32-byte hex word (0x + 64 hex)`); return h.toLowerCase(); },
  slot: (v) => { const h = String(firstOf(v) ?? "").trim(); if (!/^0x[0-9a-fA-F]{1,64}$/.test(h)) bad("slot must be a hex storage slot"); return `0x${h.slice(2).padStart(64, "0")}`.toLowerCase(); },
  block: (v, s) => {
    const raw = String(firstOf(v) ?? "").trim().toLowerCase();
    if (BLOCK_TAGS.has(raw)) return raw;
    if (/^\d+$/.test(raw) || HEXQ.test(raw)) {
      const n = BigInt(raw);
      if (n > BigInt(s.max ?? 9_007_199_254_740_991)) bad(`${s.name} is beyond the supported block range`);
      return hexOf(n);
    }
    bad(`${s.name} must be latest|safe|finalized|earliest|pending or a block number`);
  },
  data: (v, s) => {
    const d = String(firstOf(v) ?? "").trim();
    if (!/^0x([0-9a-fA-F]{2})*$/.test(d)) bad(`${s.name} must be hex with an even number of digits`);
    if ((d.length - 2) / 2 > s.max) bad(`${s.name} is over ${s.max} bytes`);
    return d.toLowerCase();
  },
  uint: (v, s) => {
    const raw = String(firstOf(v) ?? "").trim();
    if (!/^\d+$/.test(raw)) bad(`${s.name} must be a non-negative integer`);
    const n = BigInt(raw);
    if (n > BigInt(s.max ?? 1_000)) bad(`${s.name} must be at most ${s.max ?? 1000}`);
    return n;
  },
  // Every market route's variable path segment goes through `text` or `list`: an anchored regex plus a
  // hard length bound, so no caller can carry a slash, a dot-dot or a second host into a URL whose host
  // is a compile-time constant. Both percent-encode again at the call site anyway.
  text: (v, s) => {
    const t = String(firstOf(v) ?? "").trim();
    if (!t.length) bad(`${s.name} must not be empty`);
    // The default has to be at least as wide as the anchored regex the same spec carries — a cap
    // narrower than the pattern rejects inputs the route explicitly documents as valid (a 42-character
    // EVM address was measured doing exactly that). The pattern stays the real bound.
    const maxLen = s.maxLen ?? 48;
    if (t.length > maxLen) bad(`${s.name} must be at most ${maxLen} characters`);
    if (!s.pattern.test(t)) bad(`${s.name} ${s.hint || "has an unexpected shape"}`);
    return s.keepCase ? t : t.toLowerCase();
  },
  list: (v, s) => {
    const parts = [...new Set(String(firstOf(v) ?? "").split(",").map((x) => x.trim()).filter(Boolean))];
    if (!parts.length) bad(`${s.name} needs at least one value`);
    if (parts.length > s.max) bad(`${s.name} accepts at most ${s.max} values per call`);
    for (const p of parts) if (!s.pattern.test(p)) bad(`${s.name} contains a malformed value: ${p.slice(0, 40)}`);
    return s.keepCase ? parts : parts.map((p) => p.toLowerCase());
  },
  oneOf: (v, s) => {
    const t = String(firstOf(v) ?? "").trim();
    // Return the table's own spelling, not the caller's: several venues are case-sensitive in the URL
    // (Llama wants "Base", Kraken wants "XBTUSD"), and a lowercased match would silently 404 upstream
    // after the buyer already paid.
    const hit = s.values.find((x) => String(x).toLowerCase() === t.toLowerCase());
    if (!hit) bad(`${s.name} must be one of: ${s.values.join(", ")}`);
    return hit;
  },
};

const A = {
  chain: (o = {}) => ({ name: "chain", kind: "chain", required: true, type: "string", desc: `chain key: ${CHAIN_KEYS.join(", ")}`, example: "base", ...o }),
  chains: (o = {}) => ({ name: "chains", kind: "chainList", required: false, type: "string", max: 4, default: ["base"], desc: `comma list, up to 4: ${CHAIN_KEYS.join(", ")}`, example: "base,ethereum", ...o }),
  address: (o = {}) => ({ name: "address", kind: "address", required: true, type: "string", desc: "target address, 0x + 40 hex", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ...o }),
  addresses: (o = {}) => ({ name: "addresses", kind: "addressList", required: true, type: "string", max: 25, desc: "comma list of up to 25 addresses", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913,0x4200000000000000000000000000000000000006", ...o }),
  token: (o = {}) => ({ name: "token", kind: "address", required: true, type: "string", desc: "token / NFT contract address", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ...o }),
  owner: (o = {}) => ({ name: "owner", kind: "address", required: true, type: "string", desc: "holder address", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ...o }),
  spender: (o = {}) => ({ name: "spender", kind: "address", required: true, type: "string", desc: "allowance spender address", example: "0x0000000000000000000000000000000000000000", ...o }),
  to: (o = {}) => ({ name: "to", kind: "address", required: true, type: "string", desc: "contract address to call", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ...o }),
  from: (o = {}) => ({ name: "from", kind: "address", required: false, type: "string", desc: "simulation caller address", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ...o }),
  hash: (o = {}) => ({ name: "hash", kind: "txHash", required: true, type: "string", desc: "transaction hash, 0x + 64 hex", example: "0x55bd09129b86846556030b6036d48c75865b1f8e73ee6f7df60a22a56f3cd0d4", ...o }),
  block: (o = {}) => ({ name: "block", kind: "block", required: false, type: "string", default: "latest", max: 5e15, desc: "block number or latest|safe|finalized|earliest|pending", example: "latest", ...o }),
  slot: (o = {}) => ({ name: "slot", kind: "slot", required: true, type: "string", desc: "storage slot (hex, up to 32 bytes)", example: "0x0", ...o }),
  data: (o = {}) => ({ name: "data", kind: "data", required: true, type: "string", max: 4096, desc: "hex calldata, even digits, max 4096 bytes", example: "0x95d89b41", ...o }),
  tokenId: (o = {}) => ({ name: "tokenId", kind: "uint", required: true, type: "string", max: 10n ** 30n, desc: "token id (decimal)", example: 1, ...o }),
  fromBlock: (o = {}) => ({ name: "fromBlock", kind: "uint", required: true, type: "string", max: 5e15, desc: "first block number to scan (inclusive)", example: 5_000, ...o }),
  toBlock: (o = {}) => ({ name: "toBlock", kind: "uint", required: false, type: "string", max: 5e15, desc: "last block number (default: current head); range capped at 1000 blocks", example: 5_999, ...o }),
  topic0: (o = {}) => ({ name: "topic0", kind: "word", required: false, type: "string", desc: "first event topic, 0x + 64 hex", example: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", ...o }),
  value: (o = {}) => ({ name: "value", kind: "uint", required: false, type: "string", max: 10n ** 30n, default: 0n, desc: "native value in wei (decimal)", example: 0, ...o }),
  count: (o = {}) => ({ name: "count", kind: "uint", required: false, type: "string", max: 16, default: 8n, desc: "how many items to read (bounded)", example: 8, ...o }),
  blocks: (o = {}) => ({ name: "blocks", kind: "uint", required: false, type: "string", max: 100, default: 20n, desc: "window size in blocks (bounded)", example: 20, ...o }),
  fromSlot: (o = {}) => ({ name: "fromSlot", kind: "slot", required: false, type: "string", default: "0x0", desc: "first storage slot (hex, up to 32 bytes)", example: "0x0", ...o }),
  operator: (o = {}) => ({ name: "operator", kind: "address", required: true, type: "string", desc: "delegate/operator address being tested", example: "0x0000000000000000000000000000000000000000", ...o }),
  owners: (o = {}) => ({ name: "owners", kind: "addressList", required: true, type: "string", max: 20, desc: "comma list of up to 20 holder addresses", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913,0xa0b86991C6218A36cDD3b2C3d5E0F5b8D2f0A11C", ...o }),
  calls: (o = {}) => ({ name: "calls", kind: "callList", required: true, type: "string", max: 10, maxData: 1024, desc: "up to 10 pairs, formatted 0xTo:0xCalldata,comma separated", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913:0x95d89b41,0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913:0x18160ddd", ...o }),
  // Added with the 100-endpoint band. Every one of these is validated before the gate, so a caller
  // that gets the shape wrong pays nothing.
  blockHash: (o = {}) => ({ name: "blockHash", kind: "word", required: true, type: "string", desc: "block hash, 0x + 64 hex", example: "0x1c2e3a…", ...o }),
  tokenIds: (o = {}) => ({ name: "tokenIds", kind: "uintList", required: true, type: "string", max: 10, desc: "comma list of up to 10 token ids (decimal)", example: "1,2", ...o }),
  accounts: (o = {}) => ({ name: "accounts", kind: "addressList", required: true, type: "string", max: 10, positional: true, desc: "comma list of up to 10 holder addresses, positionally matched to tokenIds", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ...o }),
  tokens: (o = {}) => ({ name: "tokens", kind: "addressList", required: true, type: "string", max: 10, desc: "comma list of up to 10 ERC-20/ERC-721 contract addresses", example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913,0x4200000000000000000000000000000000000006", ...o }),
  timestamp: (o = {}) => ({ name: "timestamp", kind: "uint", required: true, type: "string", max: 5_000_000_000, desc: "unix seconds to locate a block at", example: 1758000000, ...o }),
  index: (o = {}) => ({ name: "index", kind: "uint", required: true, type: "string", max: 5000, desc: "transaction index inside the block (decimal)", example: 0, ...o }),
  // ---- market-band arg factories ----
  // One anchored regex each. The upstream host is always a constant; these bound the only variable part.
  slug: (name, o = {}) => ({ name, kind: "text", required: true, type: "string", maxLen: 48,
    pattern: /^[a-z0-9][a-z0-9._-]{0,47}$/i, hint: "must be a slug: letters, digits, dot, dash or underscore",
    example: "bitcoin", desc: "identifier slug", ...o }),
  pair: (o = {}) => ({ name: "pair", kind: "text", required: true, type: "string", maxLen: 24, keepCase: true,
    pattern: /^[A-Za-z0-9]{2,12}([,\/][A-Za-z0-9]{2,12})?$/, hint: "must be an exchange pair like XBTUSD or BTC/USD",
    example: "XBTUSD", desc: "exchange pair as the venue spells it", ...o }),
  product: (o = {}) => ({ name: "product", kind: "text", required: true, type: "string", maxLen: 26, keepCase: true,
    pattern: /^[A-Za-z0-9]{2,13}-[A-Za-z0-9]{2,13}$/, hint: "must be a Coinbase product id like BTC-USD",
    example: "BTC-USD", desc: "Coinbase Exchange product id (BASE-QUOTE)", ...o }),
  coinRef: (o = {}) => ({ name: "ref", kind: "text", required: true, type: "string", maxLen: 96,
    pattern: /^[a-z][a-z0-9-]{1,19}:[A-Za-z0-9._-]{3,80}$/, hint: "must be chain:address or coingecko:id, e.g. base:0x8335…2913",
    example: "coingecko:bitcoin", desc: "asset reference as network:identifier", ...o }),
  refList: (o = {}) => ({ name: "refs", kind: "list", required: true, type: "string", max: 10,
    pattern: /^[a-z][a-z0-9-]{1,19}:[A-Za-z0-9._-]{3,80}$/, desc: "comma list of up to 10 network:identifier refs",
    example: "coingecko:bitcoin,base:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ...o }),
  addrList: (o = {}) => ({ name: "addresses", kind: "list", required: true, type: "string", max: 20, keepCase: true,
    pattern: /^0x[0-9a-fA-F]{40}$/, desc: "comma list of contract addresses (checksum case preserved)",
    example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ...o }),
  oneOf: (name, values, o = {}) => ({ name, kind: "oneOf", required: false, type: "string", values,
    default: values[0], example: values[0], desc: `one of: ${values.join(", ")}`, ...o }),
  num: (name, o = {}) => ({ name, kind: "uint", required: false, type: "string", max: 100, default: 20n,
    example: 20, desc: "a bounded count", ...o }),
  // The market band's identifier argument: one anchored regex per route, written next to the URL it
  // feeds, so the shape the venue accepts and the shape we enforce are impossible to tell apart.
  text: (name, pattern, o = {}) => ({ name, kind: "text", required: true, type: "string", keepCase: true,
    pattern, desc: `the exact identifier ${name} the venue recognises`, ...o }),
  mints: (o = {}) => ({ name: "mints", kind: "list", required: true, type: "string", max: 20, keepCase: true,
    pattern: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/, desc: "comma list of up to 20 Solana token mints",
    example: "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", ...o }),
};

// `preCheck` runs inside parseChainArgs, i.e. BEFORE the payment gate. A rule that can be evaluated
// from the query alone must not live in the handler, or a buyer settles $0.001 and then gets a 400.
const cr = (path, title, desc, tags, args, out, exampleOut, run, preCheck, probe) =>
  ({ path, title, summary: `${title} (paid via x402)`, desc, tags, args, out, exampleOut, run, preCheck, probe, chainRoute: true });

const blockSummary = (b) => ({
  number: Number(toBig(b?.number) ?? 0), hash: b?.hash ?? null, parentHash: b?.parentHash ?? null,
  timestamp: Number(toBig(b?.timestamp) ?? 0), isoTime: b?.timestamp ? new Date(Number(toBig(b.timestamp)) * 1000).toISOString() : null,
  author: b?.author ?? b?.miner ?? null, transactionsCount: (b?.transactions || []).length,
  size: Number(toBig(b?.size) ?? 0), gasUsed: String(toBig(b?.gasUsed) ?? 0n), gasLimit: String(toBig(b?.gasLimit) ?? 0n),
  baseFeeGwei: gweiOf(b?.baseFeePerGas),
});

const CHAIN_ROUTES = [
  cr("/chain/block-number", "Current block height", "Latest block number for one chain straight from a public node — the cheapest possible 'is the chain alive and where is it' check.",
    ["chain", "block-number", "height", "rpc", "base"], [A.chain()],
    [["blockNumber", "integer", "latest block height"]],
    {blockNumber: 51745405},
    async ({ chain }) => ({ blockNumber: await headOf(chain) })),
  cr("/chain/balance", "Native balance for one address", "Native coin balance (wei plus a decimal string) at the latest block, with the chain's symbol so the number cannot be misread as USD.",
    ["balance", "chain", "wallet", "native", "rpc"], [A.chain(), A.address()],
    [["address", "string"], ["nativeSymbol", "string"], ["wei", "string", "balance in wei"], ["balance", "string", "decimal-formatted native amount"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", nativeSymbol: "ETH", wei: "9800646158085843", balance: "0.009800646158085843"},
    async ({ chain, address }) => {
      const wei = toBig(await rpcCall(chain, "eth_getBalance", [address, "latest"])) ?? 0n;
      return { address, nativeSymbol: CHAINS[chain].native, wei: String(wei), balance: fmtDec(wei, 18) };
    }),
  cr("/chain/balances", "Batch native balances", "Up to 25 addresses in one paid call — the shape a portfolio or risk bot actually needs, cheaper than 25 single lookups.",
    ["balance", "batch", "chain", "wallet", "rpc"], [A.chain(), A.addresses()],
    [["nativeSymbol", "string"], ["requested", "integer"], ["rows", "array"]],
    {nativeSymbol: "ETH", requested: 2, rows: [{address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", wei: "9800646158085843", balance: "0.009800646158085843"}]},
    async ({ chain, addresses }) => {
      const rows = await Promise.all(addresses.map(async (a) => {
        const wei = toBig(await rpcCall(chain, "eth_getBalance", [a, "latest"])) ?? 0n;
        return { address: a, wei: String(wei), balance: fmtDec(wei, 18) };
      }));
      return { nativeSymbol: CHAINS[chain].native, requested: rows.length, rows };
    }),
  cr("/chain/nonce", "Transaction count (nonce)", "eth_getTransactionCount at any block tag — what an agent needs before it builds a transaction, and how a bot detects a stuck or reused nonce.",
    ["nonce", "chain", "wallet", "rpc", "transaction"], [A.chain(), A.address(), A.block({ name: "blockTag" })],
    [["address", "string"], ["blockTag", "string"], ["nonce", "integer"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", blockTag: "latest", nonce: 1},
    async ({ chain, address, blockTag }) => ({ address, blockTag, nonce: Number(toBig(await rpcCall(chain, "eth_getTransactionCount", [address, blockTag])) ?? 0n) })),
  cr("/chain/code", "Is this address a contract?", "eth_getCode size check: bytecode length plus whether the address is a contract at all — the two-second answer to 'did I just send funds to an EOA'.",
    ["contract", "bytecode", "chain", "address", "rpc"], [A.chain(), A.address()],
    [["address", "string"], ["isContract", "boolean"], ["bytecodeSize", "integer", "bytes of deployed code"], ["codePrefix", "string"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", isContract: true, bytecodeSize: 1852, codePrefix: "0x60806040526004361061005a57600035"},
    async ({ chain, address }) => {
      const code = (await rpcCall(chain, "eth_getCode", [address, "latest"])) || "0x";
      const size = (code.length - 2) / 2;
      return { address, isContract: size > 0, bytecodeSize: size, codePrefix: size > 0 ? code.slice(0, 34) : null };
    }),
  cr("/chain/block", "Block by number or tag", "One block header decoded: height, time, author, gas used vs limit, base fee in gwei and transaction count. Readable numbers, not raw hex.",
    ["block", "chain", "header", "rpc", "gas"], [A.chain(), A.block()],
    [["block", "object", "decoded header"]],
    {block: {number: 51745406, hash: "0x23adbaf19a8a6de61a109061c854e9a75371ac5cf9de581d1e5f2aaa33a3532b", parentHash: "0xf6dc8094ae0ffc755cc4bf2eebff904838daf668f3e4ecf1efbf7d60328d2b5c", timestamp: 1790280159, isoTime: "2026-09-24T20:02:39.000Z", author: "0x4200000000000000000000000000000000000011"}},
    async ({ chain, block }) => ({ block: blockSummary(await rpcCall(chain, "eth_getBlockByNumber", [block, false])) })),
  cr("/chain/block-txids", "Transaction hashes in a block", "Every transaction hash in one block plus the count — the step between 'which block' and 'which transfers happened', without pulling full receipts.",
    ["block", "transactions", "chain", "rpc", "indexing"], [A.chain(), A.block()],
    [["blockNumber", "integer"], ["count", "integer"], ["truncated", "boolean"], ["transactionHashes", "array"]],
    {blockNumber: 51745378, count: 182, truncated: false, transactionHashes: ["0xba422b30934ce9aab82c98f9d3dc08f2792a425168fa90229b3216d56d288349"]},
    async ({ chain, block }) => {
      const b = await rpcCall(chain, "eth_getBlockByNumber", [block, false]);
      const hashes = (b?.transactions || []).map((t) => (typeof t === "string" ? t : t?.hash)).filter(Boolean);
      return { blockNumber: Number(toBig(b?.number) ?? 0n), count: hashes.length, truncated: false, transactionHashes: hashes.slice(0, 1000), ...(hashes.length > 1000 ? { truncated: true } : {}) };
    }),
  cr("/chain/tx", "Transaction by hash", "eth_getTransactionByHash decoded to the fields a caller branches on: from, to, value, nonce, gas, calldata length and inclusion block. Reports found:false rather than inventing a zero.",
    ["transaction", "chain", "hash", "rpc", "status"], [A.chain(), A.hash()],
    [["found", "boolean"], ["transaction", "object"], ["pending", "boolean"]],
    {found: true, transaction: {hash: "0xc7fb4c81e619eac18ad474c63157ef2edd6e81a425170d007692c45123457bef", from: "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001", to: "0x4200000000000000000000000000000000000015", nonce: 51745382, valueWei: "0", value: "0.000000000000000000"}, pending: false},
    async ({ chain, hash }) => {
      const t = await rpcCall(chain, "eth_getTransactionByHash", [hash]);
      if (!t) return { found: false, note: "no transaction with this hash on this chain yet" };
      return { found: true, transaction: {
        hash: t.hash, from: t.from, to: t.to, nonce: Number(toBig(t.nonce) ?? 0n),
        valueWei: String(toBig(t.value) ?? 0n), value: fmtDec(toBig(t.value) ?? 0n, 18),
        gas: String(toBig(t.gas) ?? 0n), gasPriceGwei: gweiOf(t.gasPrice), maxFeePerGasGwei: gweiOf(t.maxFeePerGas),
        inputSize: (t.input || "").length > 2 ? (t.input.length - 2) / 2 : 0, selector: (t.input || "").slice(0, 10) || null,
        blockNumber: t.blockNumber ? Number(toBig(t.blockNumber)) : null, transactionIndex: t.transactionIndex ? Number(toBig(t.transactionIndex)) : null, type: t.type ?? null,
      }, pending: !t.blockNumber };
    }),
  cr("/chain/receipt", "Receipt, gas used and confirmations", "Status, gasUsed, effective gas price, contract created, log count and live confirmations for one hash — whether a transaction actually landed and what it cost.",
    ["receipt", "gas", "confirmation", "chain", "rpc"], [A.chain(), A.hash()],
    // contractAddress: an address when the tx deploys, null otherwise — a null sample carries no type,
    // so this one key is named from the code (`r.contractAddress ?? null`) rather than measured.
    [["found", "boolean"], ["status", "integer", "1 = success"], ["transactionHash", "string"], ["from", "string"], ["to", "string"], ["contractAddress", "string|null"], ["blockNumber", "integer"], ["confirmations", "integer"], ["gasUsed", "string"], ["cumulativeGasUsed", "string"], ["effectiveGasPriceGwei", "integer"], ["costWei", "string"], ["logCount", "integer"], ["logsBloomPresent", "boolean"]],
    {found: true, status: 1, transactionHash: "0xc7fb4c81e619eac18ad474c63157ef2edd6e81a425170d007692c45123457bef", from: "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001", to: "0x4200000000000000000000000000000000000015", contractAddress: null, blockNumber: 51745379, confirmations: 28, gasUsed: "46230", cumulativeGasUsed: "46230", effectiveGasPriceGwei: 0, costWei: "0", logCount: 0, logsBloomPresent: true},
    async ({ chain, hash }) => {
      const r = await rpcCall(chain, "eth_getTransactionReceipt", [hash]);
      if (!r) return { found: false, note: "no receipt on this chain for this hash" };
      const head = await headOf(chain);
      const bn = Number(toBig(r.blockNumber) ?? 0n);
      return { found: true, status: Number(toBig(r.status) ?? 0n), transactionHash: r.transactionHash, from: r.from, to: r.to,
        contractAddress: r.contractAddress ?? null, blockNumber: bn, confirmations: Math.max(0, head - bn),
        gasUsed: String(toBig(r.gasUsed) ?? 0n), cumulativeGasUsed: String(toBig(r.cumulativeGasUsed) ?? 0n),
        effectiveGasPriceGwei: gweiOf(r.effectiveGasPrice), costWei: String((toBig(r.gasUsed) ?? 0n) * (toBig(r.effectiveGasPrice) ?? 0n)),
        logCount: (r.logs || []).length, logsBloomPresent: (r.logsBloom || "").length > 6 };
    }),
  cr("/chain/logs", "Event logs for an address or topic", "eth_getLogs over a bounded window (max 1000 blocks) with an address and/or first topic — transfers and events without running an indexer. Refuses an unfiltered scan. Walks the window in chunks because a free node refuses a big one on response size, and reports any range no node would serve instead of failing a settled call.",
    ["logs", "events", "transfers", "chain", "rpc"],
    [A.chain(), A.address({ name: "address", required: false, desc: "contract that emitted the events" }), A.topic0(), A.fromBlock(), A.toBlock()],
    [["range", "object"], ["count", "integer"], ["truncated", "boolean"], ["nodeCalls", "integer"], ["chunks", "object"], ["rows", "array"]],
    {range: {fromBlock: 51745179, toBlock: 51745279, head: 51745407, requestedToBlock: 51745279}, count: 9719, truncated: true, nodeCalls: 2, chunks: {size: 100, budget: 24}, rows: [{blockNumber: 51745179, transactionHash: "0x80ddfdfbb49ef5c756b0ee13a934864087437692f6a83bd6374abfe046f60d2e", logIndex: 19, address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", topics: ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"], data: "0x000000000000000000000000000000000000000000000000000000000009d2c8"}]},
    async ({ chain, address, topic0, fromBlock, toBlock }) => {
      const head = await headOf(chain);
      const from = Number(fromBlock);
      const to = toBlock === undefined ? head : Number(toBlock);
      const start = Math.min(from, to), end = Math.max(from, to);
      // A window that has not happened yet is an honest empty answer, not a 400: by the time this runs
      // the buyer has already settled, and "there are no logs here" is what they paid for.
      if (start > head) {
        return { range: { fromBlock: start, toBlock: end, head }, count: 0, truncated: false, nodeCalls: 0, rows: [],
          note: `fromBlock ${start} is ahead of the current head (${head}), so nothing has been emitted in it yet` };
      }
      const clipped = Math.min(end, head);
      const filter = {};
      if (address) filter.address = address;
      if (topic0) filter.topics = [topic0];
      const cap = 500;
      const { logs, calls, uncovered } = await scanLogs(chain, filter, start, clipped, cap);
      return { range: { fromBlock: start, toBlock: clipped, head, requestedToBlock: end },
        count: logs.length, truncated: logs.length > cap || uncovered.length > 0,
        nodeCalls: calls, chunks: { size: LOG_CHUNK, budget: LOG_BUDGET },
        ...(uncovered.length ? { uncovered, note: "one or more ranges were not answered by either pinned node within this scan's budget — the rows below are complete for every other range" } : {}),
        rows: logs.slice(0, cap).map((l) => ({ blockNumber: Number(toBig(l.blockNumber) ?? 0n), transactionHash: l.transactionHash,
          logIndex: l.logIndex ? Number(toBig(l.logIndex)) : null, address: l.address, topics: l.topics || [],
          data: typeof l.data === "string" ? l.data.slice(0, 2066) : null })) };
    },
    (a) => {
      if (!a.address && !a.topic0) bad("logs need ?address= and/or ?topic0= — an unfiltered scan is not sold");
      if (a.toBlock !== undefined && a.toBlock !== null) {
        const span = a.toBlock > a.fromBlock ? a.toBlock - a.fromBlock + 1n : a.fromBlock - a.toBlock + 1n;
        if (span > 1000n) bad(`block range is ${span} blocks; this route caps a scan at 1000`);
      }
    }),
  cr("/chain/call", "Read-only contract call", "eth_call with your own calldata against one pinned public node: raw return data plus its decoded uint/address forms. The escape hatch for any view function we did not wrap.",
    ["eth-call", "contract", "read", "chain", "rpc"], [A.chain(), A.to(), A.data(), A.block({ name: "blockTag" })],
    [["to", "string"], ["blockTag", "string"], ["returnData", "string"], ["returnSize", "integer"], ["returnedNoData", "boolean"], ["reverted", "boolean"], ["asUint", "string"], ["asAddress", "string|null"], ["asString", "string"]],
    {to: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", blockTag: "latest", returnData: "0x000000000000000000000000000000000000000000…", returnSize: 96, returnedNoData: false, reverted: false, asUint: "42904985375816310718636879994258707607933970…", asAddress: null, asString: "USDC"},
    async ({ chain, to, data, blockTag }) => {
      // A revert is the contract's answer, not our failure, so it is reported as data: a buyer who paid
      // $0.001 to learn "this call reverts" must not be handed a 502.
      let r = "0x", revertReason = null;
      try {
        r = await callContract(chain, to, data, blockTag);
      } catch (e) {
        if (e instanceof HttpError && e.status === 400) throw e;
        r = "0x";
        revertReason = String(e?.message || e).slice(0, 160);
      }
      const empty = !r || r === "0x";
      const u = toBig(r);
      return { to, blockTag, returnData: r || "0x", returnSize: empty ? 0 : (r.length - 2) / 2,
        returnedNoData: empty, reverted: empty, ...(revertReason ? { revertReason } : {}),
        ...(empty ? { note: "the node returned no data — a revert or an empty return; this is not a value of zero" } : { asUint: u === null ? null : String(u), asAddress: decodeAddress(r), asString: decodeString(r) }) };
    }),
  cr("/chain/storage", "Raw storage slot", "eth_getStorageAt for one slot of one account — verify a contract's own bookkeeping (owner slot, mapping entry) instead of trusting a view function.",
    ["storage", "slot", "chain", "rpc", "contract"], [A.chain(), A.address(), A.slot(), A.block({ name: "blockTag" })],
    [["address", "string"], ["slot", "string"], ["blockTag", "string"], ["value", "string", "32-byte word"], ["asUint", "string"], ["asAddress", "string"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", slot: "0x0000000000000000000000000000000000000000000000000000000000000002", blockTag: "latest", value: "0x0000000000000000000000001f2e3a640175d20ac31ed523b6733b977173e277", asUint: "178009634717433154990808687687379929950661632631", asAddress: "0x1f2e3a640175d20ac31ed523b6733b977173e277"},
    async ({ chain, address, slot, blockTag }) => {
      const v = await rpcCall(chain, "eth_getStorageAt", [address, slot, blockTag]);
      const u = toBig(v);
      return { address, slot, blockTag, value: v ?? null, asUint: u === null ? null : String(u), asAddress: decodeAddress(v) };
    }),
  cr("/chain/fee-data", "Full EIP-1559 fee quote", "gasPrice, base fee, priority fee and the all-in cost of a 21000-gwei native transfer in wei and native units — what sending costs right now, on one chain.",
    ["gas", "fees", "eip1559", "chain", "rpc"], [A.chain()],
    [["nativeSymbol", "string"], ["gasPriceGwei", "number"], ["baseFeeGwei", "number"], ["maxPriorityFeeGwei", "number"], ["blockNumber", "integer"], ["nativeTransferCost", "object"]],
    {nativeSymbol: "ETH", gasPriceGwei: 0.006, baseFeeGwei: 0.005, maxPriorityFeeGwei: 0.001, blockNumber: 51745408, nativeTransferCost: {gas: 21000, wei: "136500000000", native: "0.000000136500000000"}},
    async ({ chain }) => {
      const [gp, blk, pf] = await Promise.all([
        rpcCall(chain, "eth_gasPrice", []),
        rpcCall(chain, "eth_getBlockByNumber", ["latest", false]),
        rpcCall(chain, "eth_maxPriorityFeePerGas", []).catch(() => null),
      ]);
      const gpBig = toBig(gp) ?? 0n, base = toBig(blk?.baseFeePerGas) ?? null, prio = toBig(pf);
      const transfer = 21000n * (gpBig + (prio ?? 0n) / 2n);
      return { chainLabel: CHAINS[chain].label, nativeSymbol: CHAINS[chain].native,
        gasPriceGwei: gweiOf(gp), baseFeeGwei: base === null ? null : Number(base / 1000000n) / 1e3,
        maxPriorityFeeGwei: prio === null ? null : Number(prio / 1000000n) / 1e3,
        blockNumber: Number(toBig(blk?.number) ?? 0n),
        nativeTransferCost: { gas: 21000, wei: String(transfer), native: fmtDec(transfer, 18) } };
    }),
  cr("/chain/gas-estimate", "Estimate gas for a call", "eth_estimateGas for a transfer or contract call you describe — the exact simulation a wallet runs before signing, without needing a wallet.",
    ["gas", "estimate", "simulation", "chain", "rpc"],
    [A.chain(), A.to(), A.from({ required: false }), A.data({ name: "data", required: false, default: "0x", desc: "hex calldata" }), A.value()],
    [["estimable", "boolean"], ["to", "string"], ["gasEstimate", "string"], ["gasPriceGwei", "number"], ["atSenderGas", "object"]],
    {estimable: true, to: "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b", gasEstimate: "21000", gasPriceGwei: 0.006, atSenderGas: {wei: "126000000000", native: "0.000000126000000000", nativeSymbol: "ETH"}},
    async ({ chain, to, from, data, value }) => {
      const tx = { to, data };
      if (from) tx.from = from;
      if (value > 0n) tx.value = hexOf(value);
      try {
        const g = toBig(await rpcCall(chain, "eth_estimateGas", [tx]));
        const [gp] = await Promise.all([rpcCall(chain, "eth_gasPrice", [])]);
        const cost = (g ?? 0n) * (toBig(gp) ?? 0n);
        return { estimable: true, to, gasEstimate: String(g ?? 0n), gasPriceGwei: gweiOf(gp),
          atSenderGas: { wei: String(cost), native: fmtDec(cost, 18), nativeSymbol: CHAINS[chain].native } };
      } catch (e) {
        if (e instanceof HttpError && e.status === 400) throw e;
        return { estimable: false, to, note: "the node refused to estimate this call", reason: String(e?.message || e).slice(0, 160) };
      }
    }),
  cr("/chain/token-balance", "ERC-20 balance with decimals", "balanceOf plus the token's own decimals, formatted — a human-readable USDC/token balance, not a raw 18-digit integer that needs a calculator.",
    ["erc20", "balance", "token", "chain", "rpc"], [A.chain(), A.token(), A.owner()],
    [["token", "string"], ["owner", "string"], ["symbol", "string"], ["decimals", "integer"], ["raw", "string"], ["formatted", "string"], ["decimalsAssumed", "boolean"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", owner: "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b", symbol: "USDC", decimals: 6, raw: "0", formatted: "0.000000", decimalsAssumed: false},
    async ({ chain, token, owner }) => {
      const [raw, dp, sym] = await Promise.all([
        // A revert is "this contract has no balanceOf", not a server fault: answer readable:false, and
        // never a 502 on a route a buyer has already paid.
        callContract(chain, token, calldata(SEL.balanceOf, wordAddr(owner))).then(toBig).catch(() => null),
        tokenDecimals(chain, token),
        tryCall(chain, token, calldata(SEL.symbol), decodeString),
      ]);
      if (raw === null) return { token, owner, readable: false, note: "balanceOf returned no data — this contract is not an ERC-20 (or reverted)" };
      const d = dp ?? 18;
      return { token, owner, symbol: sym, decimals: dp, raw: String(raw), formatted: fmtDec(raw, d), decimalsAssumed: dp === null };
    }),
  cr("/chain/token-meta", "Token name, symbol, decimals, supply", "The four ERC-20 view calls a listing needs, in one paid call, each tolerant of a token that does not implement it.",
    ["erc20", "metadata", "token", "supply", "chain"], [A.chain(), A.token()],
    [["token", "string"], ["name", "string"], ["symbol", "string"], ["decimals", "integer"], ["totalSupply", "string"], ["totalSupplyFormatted", "string"], ["isContract", "boolean"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", name: "USD Coin", symbol: "USDC", decimals: 6, totalSupply: "4271790631862566", totalSupplyFormatted: "4271790631.862566", isContract: true},
    async ({ chain, token }) => {
      const [name, symbol, decimals, supply] = await Promise.all([
        tryCall(chain, token, calldata(SEL.name), decodeString),
        tryCall(chain, token, calldata(SEL.symbol), decodeString),
        tokenDecimals(chain, token),
        callContract(chain, token, calldata(SEL.totalSupply)).catch(() => null),
      ]);
      const sup = toBig(supply);
      return { token, name, symbol, decimals, totalSupply: sup === null ? null : String(sup),
        totalSupplyFormatted: sup === null ? null : fmtDec(sup, decimals ?? 18),
        isContract: ((await rpcCall(chain, "eth_getCode", [token, "latest"])) || "0x").length > 4,
        note: sup === null ? "totalSupply was not readable on this contract" : undefined };
    }),
  cr("/chain/allowance", "ERC-20 allowance", "allowance(owner, spender) in raw and decimal form — how much a approval still lets a third party move, which is the number behind most drain headlines.",
    ["erc20", "allowance", "approval", "security", "chain"], [A.chain(), A.token(), A.owner(), A.spender()],
    [["token", "string"], ["owner", "string"], ["spender", "string"], ["decimals", "integer"], ["raw", "string"], ["formatted", "string"], ["unlimitedApproval", "boolean"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", owner: "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b", spender: "0x0000000000000000000000000000000000000000", decimals: 6, raw: "0", formatted: "0.000000", unlimitedApproval: false},
    async ({ chain, token, owner, spender }) => {
      const [raw, dp] = await Promise.all([
        callContract(chain, token, calldata(SEL.allowance, wordAddr(owner), wordAddr(spender))).then(toBig).catch(() => null),
        tokenDecimals(chain, token),
      ]);
      if (raw === null) return { token, owner, spender, readable: false, note: "allowance() returned no data — not an ERC-20 with an allowance mapping" };
      const d = dp ?? 18;
      return { token, owner, spender, decimals: dp, raw: String(raw), formatted: fmtDec(raw, d),
        unlimitedApproval: raw >= 2n ** 255n };
    }),
  cr("/chain/nft-owner", "ERC-721 owner of a token id", "ownerOf(tokenId) resolved for one NFT — proof of who holds a specific id right now, from the contract itself.",
    ["nft", "erc721", "ownership", "chain", "rpc"], [A.chain(), A.token({ desc: "NFT contract address" }), A.tokenId()],
    [["token", "string"], ["tokenId", "string"], ["owner", "string"], ["found", "boolean"]],
    {token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", tokenId: "2448", owner: "0x58867fa928b92ca3dc1c709d058ea1bfa1fc28d5", found: true},
    async ({ chain, token, tokenId }) => {
      const r = await callOrNull(chain, token, calldata(SEL.ownerOf, wordUint(tokenId)));
      const owner = decodeAddress(r);
      return { token, tokenId: String(tokenId), owner, found: !!owner, ...(owner ? {} : { note: "no 32-byte address came back; the id may not be minted or the contract is not ERC-721" }) };
    }),
  cr("/chain/nft-balance", "ERC-721 tokens held by an address", "balanceOf(owner) on an NFT contract — how many ids one wallet holds, without indexing every transfer.",
    ["nft", "erc721", "balance", "chain", "rpc"], [A.chain(), A.token({ desc: "NFT contract address" }), A.owner()],
    [["token", "string"], ["owner", "string"], ["balance", "integer"], ["raw", "string"], ["overflow", "boolean"]],
    {token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", owner: "0x58867fa928b92ca3dc1c709d058ea1bfa1fc28d5", balance: 7, raw: "7", overflow: false},
    async ({ chain, token, owner }) => {
      const v = toBig(await callOrNull(chain, token, calldata(SEL.balanceOf, wordAddr(owner))));
      if (v === null) return { token, owner, readable: false, note: "balanceOf returned no data — this contract is not ERC-721" };
      return { token, owner, balance: Number(v), raw: String(v), overflow: v > BigInt(Number.MAX_SAFE_INTEGER) };
    }),
  cr("/chain/nft-meta", "NFT collection name and standards", "name/symbol plus which token standards the contract actually claims (ERC-165, ERC-721, ERC-721Metadata, ERC-1155) via supportsInterface.",
    ["nft", "erc721", "metadata", "standards", "chain"], [A.chain(), A.token({ desc: "NFT contract address" })],
    [["token", "string"], ["name", "string"], ["symbol", "string"], ["supports", "object"]],
    {token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", name: "BoredApeYachtClub", symbol: "BAYC", supports: {ERC165: true, ERC20: false, ERC721: true, ERC721Metadata: true, ERC1155: false}},
    async ({ chain, token }) => {
      const [name, symbol] = await Promise.all([
        tryCall(chain, token, calldata(SEL.name), decodeString),
        tryCall(chain, token, calldata(SEL.symbol), decodeString),
      ]);
      const supports = {};
      const erc165 = await hasInterface(chain, token, IFACE.ERC165);
      supports.ERC165 = erc165;
      for (const k of ["ERC20", "ERC721", "ERC721Metadata", "ERC1155"]) {
        supports[k] = erc165 === false ? false : await hasInterface(chain, token, IFACE[k]);
      }
      return { token, name, symbol, supports };
    }),
  cr("/chain/contract-check", "Contract fingerprint before you interact", "Bytecode size plus every supported-interface answer in one call — the pre-flight that tells an agent whether a 'token' address is a contract at all and which standards it claims.",
    ["security", "contract", "erc165", "audit", "chain"], [A.chain(), A.address({ name: "address", desc: "contract to fingerprint" })],
    [["address", "string"], ["isContract", "boolean"], ["bytecodeSize", "integer"], ["supports", "object"], ["codePrefix", "string"]],
    {address: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", isContract: true, bytecodeSize: 16790, supports: {ERC165: true, ERC20: false, ERC721: true, ERC721Metadata: true, ERC1155: false}, codePrefix: "0x60806040526004361061021a57600035"},
    async ({ chain, address }) => {
      const code = (await rpcCall(chain, "eth_getCode", [address, "latest"])) || "0x";
      const size = (code.length - 2) / 2;
      const supports = { ERC165: null, ERC20: null, ERC721: null, ERC721Metadata: null, ERC1155: null };
      if (size > 0) {
        const e165 = await hasInterface(chain, address, IFACE.ERC165);
        supports.ERC165 = e165;
        for (const k of ["ERC20", "ERC721", "ERC721Metadata", "ERC1155"]) {
          supports[k] = e165 === false ? false : await hasInterface(chain, address, IFACE[k]);
        }
      }
      return { address, isContract: size > 0, bytecodeSize: size, supports,
        codePrefix: size > 0 ? code.slice(0, 34) : null,
        note: "supportsInterface is a contract's own claim, not an audit — a malicious token can answer truthy" };
    }),
  cr("/chain/wallet-state", "Wallet snapshot across chains", "Balance, nonce and contract/EOA flag for one address on up to 4 chains in a single paid call — the one-shot 'what does this wallet actually hold' check.",
    ["wallet", "balance", "portfolio", "multi-chain", "chain"], [A.chains(), A.address()],
    [["address", "string"], ["chains", "array"], ["rows", "array"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chains: ["base"], rows: [{chain: "base", chainId: 8453, label: "Base", nativeSymbol: "ETH", wei: "9800646158085843", balance: "0.009800646158085843"}]},
    async ({ chains, address }) => {
      const rows = await Promise.all(chains.map(async (c) => {
        const [wei, nonce, code] = await Promise.all([
          rpcCall(c, "eth_getBalance", [address, "latest"]).then(toBig),
          rpcCall(c, "eth_getTransactionCount", [address, "latest"]).then(toBig),
          rpcCall(c, "eth_getCode", [address, "latest"]),
        ]);
        const w = wei ?? 0n;
        return { chain: c, chainId: CHAINS[c].chainId, label: CHAINS[c].label, nativeSymbol: CHAINS[c].native,
          wei: String(w), balance: fmtDec(w, 18), nonce: Number(nonce ?? 0n), isContract: ((code || "0x").length - 2) / 2 > 0 };
      }));
      return { address, chains, rows };
    }),

  // ---- second surface band (added 2026-09-24) -------------------------------------------------
  // Every method and selector below was probed against the EXACT hosts production pins before it was
  // wired (.tmp-check/probe-new-selectors.mjs, probe-erc721-approvals.mjs, probe-host-caps.mjs):
  // eth_getBlockReceipts answers with a receipt count that equals the block's own transaction count,
  // eth_feeHistory needs a block NUMBER (mainnet.base.org rejects "latest" for that method), and the
  // three ERC-721 selectors pass a mutated-selector revert plus a negative control on ERC-20 USDC.
  // debug_traceTransaction and txpool_status are NOT here because both pinned hosts refuse them.
  cr("/chain/heads", "Live head across chains", "Latest block, its age in seconds, base fee and block fullness for up to 4 chains in one paid call — the fastest answer to 'which of these chains is actually caught up right now'.",
    ["chain", "liveness", "head", "monitoring", "rpc"], [A.chains()],
    [["chains", "array"], ["observedAt", "string"], ["rows", "array", "one entry per chain"]],
    {chains: ["base"], observedAt: "2026-09-24T20:03:00.000Z", rows: [{chain: "base", chainId: 8453, label: "Base", nativeSymbol: "ETH", blockNumber: 51745416, blockHash: "0x39549759d86a61a8d1990d1a84d6e92ab25317419bb209031aedbcdf3ad42107"}]},
    async ({ chains }) => {
      const now = nowSec();
      const rows = await Promise.all(chains.map(async (c) => {
        const b = await rpcCall(c, "eth_getBlockByNumber", ["latest", false]);
        const used = toBig(b?.gasUsed) ?? 0n, limit = toBig(b?.gasLimit) ?? 0n;
        const ts = Number(toBig(b?.timestamp) ?? 0n);
        return { chain: c, chainId: CHAINS[c].chainId, label: CHAINS[c].label, nativeSymbol: CHAINS[c].native,
          blockNumber: Number(toBig(b?.number) ?? 0n), blockHash: b?.hash ?? null, timestamp: ts,
          ageSeconds: ts ? Math.max(0, now - ts) : null, baseFeeGwei: gweiOf(b?.baseFeePerGas),
          gasUsed: String(used), gasLimit: String(limit),
          gasUtilizationPct: limit > 0n ? Number((used * 10000n) / limit) / 100 : null,
          transactionsCount: (b?.transactions || []).length };
      }));
      return { chains, observedAt: new Date(now * 1000).toISOString(), rows };
    }),
  cr("/chain/block-stats", "Measured block cadence", "Seconds per block and blocks per hour, taken from the timestamps of two real headers at the edges of a window — one stalled block shows as a wider span instead of being smoothed away.",
    ["chain", "block-time", "throughput", "congestion", "rpc"], [A.chain(), A.blocks()],
    [["chainId", "integer"], ["label", "string"], ["head", "integer"], ["windowBlocks", "integer"], ["fromBlock", "integer"], ["toBlock", "integer"], ["spanSeconds", "integer"], ["secondsPerBlock", "number"], ["blocksPerHour", "number"], ["edges", "object"]],
    {chainId: 8453, label: "Base", head: 51745416, windowBlocks: 20, fromBlock: 51745395, toBlock: 51745415, spanSeconds: 40, secondsPerBlock: 2, blocksPerHour: 1800, edges: {newest: {number: 51745415, timestamp: 1790280177, transactionsCount: 180, gasUsed: "26123267", gasLimit: "400000000", baseFeeGwei: 0.005}, oldest: {number: 51745395, timestamp: 1790280137, transactionsCount: 202, gasUsed: "34672923", gasLimit: "400000000", baseFeeGwei: 0.005}}},
    async ({ chain, blocks }) => {
      const n = Number(blocks);
      const head = await headOf(chain);
      const newest = Math.max(0, head - 1);
      const older = Math.max(0, newest - n);
      const [a, b] = await Promise.all([
        rpcCall(chain, "eth_getBlockByNumber", [hexOf(newest), false]),
        rpcCall(chain, "eth_getBlockByNumber", [hexOf(older), false]),
      ]);
      const hi = Number(toBig(a?.number) ?? 0n), lo = Number(toBig(b?.number) ?? 0n);
      const span = Number(toBig(a?.timestamp) ?? 0n) - Number(toBig(b?.timestamp) ?? 0n);
      const window = hi - lo;
      if (window <= 0 || span < 0) return { head, windowBlocks: window, usable: false, note: "the two headers did not differ — widen ?blocks=" };
      const per = span / window;
      const edge = (x) => ({ number: Number(toBig(x?.number) ?? 0n), timestamp: Number(toBig(x?.timestamp) ?? 0n),
        transactionsCount: (x?.transactions || []).length, gasUsed: String(toBig(x?.gasUsed) ?? 0n),
        gasLimit: String(toBig(x?.gasLimit) ?? 0n), baseFeeGwei: gweiOf(x?.baseFeePerGas) });
      return { chain, chainId: CHAINS[chain].chainId, label: CHAINS[chain].label, head,
        windowBlocks: window, fromBlock: lo, toBlock: hi, spanSeconds: span,
        secondsPerBlock: Math.round(per * 1000) / 1000, blocksPerHour: Math.round((3600 / per) * 100) / 100,
        edges: { newest: edge(a), oldest: edge(b) },
        note: "throughput is derived from the two window-edge headers, not averaged over every block in between" };
    }),
  cr("/chain/block-receipts", "Every receipt in one block", "eth_getBlockReceipts in a single paid call: per-transaction gas, status and log count, plus where the block's total fees went — instead of one receipt read per transaction.",
    ["block", "receipts", "gas", "fees", "chain"], [A.chain(), A.block()],
    [["blockNumber", "integer"], ["count", "integer"], ["cap", "integer"], ["aggregatedOver", "integer"], ["truncated", "boolean"], ["successCount", "integer"], ["failedCount", "integer"], ["totalGasUsed", "string"], ["feesPaidWei", "string"], ["feesPaidNative", "string"], ["uniqueSenders", "integer"], ["rows", "array"]],
    {blockNumber: 51745376, count: 258, cap: 300, aggregatedOver: 258, truncated: false, successCount: 234, failedCount: 24, totalGasUsed: "37748459", feesPaidWei: "389711211824511", feesPaidNative: "0.000389711211824511", uniqueSenders: 214, rows: [{transactionHash: "0x1ec65356cb66d02ce119a48bef3089d91c1a6908fb0280d6d74fa4e3c3e72095", from: "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001", to: "0x4200000000000000000000000000000000000015", status: 1, contractAddress: null, gasUsed: "46230"}]},
    async ({ chain, block }) => {
      const { receipts: raw, partial, total } = await blockReceipts(chain, block);
      if (!Array.isArray(raw)) return { found: false, note: "no node would answer for that block: it is not a block this chain has, or every host refused both eth_getBlockReceipts and the block itself" };
      const cap = 300;
      let totalGas = 0n, spent = 0n;
      for (const r of raw) {
        const g = toBig(r?.gasUsed) ?? 0n;
        totalGas += g; spent += g * (toBig(r?.effectiveGasPrice) ?? 0n);
      }
      const count = partial ? total : raw.length;
      return { chain, blockNumber: raw[0]?.blockNumber ? Number(toBig(raw[0].blockNumber)) : null,
        // `count` is the block's transaction count and `aggregatedOver` how many receipts the totals
        // actually cover. They differ on a >300-transaction block (cap) and on the fallback path (40).
        count, cap, aggregatedOver: raw.length, truncated: raw.length < count,
        successCount: raw.filter((r) => toBig(r?.status) === 1n).length,
        failedCount: raw.filter((r) => r?.status !== undefined && toBig(r.status) !== 1n).length,
        totalGasUsed: String(totalGas), feesPaidWei: String(spent), feesPaidNative: fmtDec(spent, 18),
        uniqueSenders: new Set(raw.map((r) => String(r?.from || "").toLowerCase()).filter(Boolean)).size,
        rows: raw.slice(0, cap).map((r) => ({ transactionHash: r.transactionHash, from: r.from ?? null, to: r.to ?? null,
          status: Number(toBig(r?.status) ?? 0n), contractAddress: r.contractAddress ?? null,
          gasUsed: String(toBig(r?.gasUsed) ?? 0n), effectiveGasPriceGwei: gweiOf(r?.effectiveGasPrice),
          cumulativeGasUsed: String(toBig(r?.cumulativeGasUsed) ?? 0n), logCount: (r?.logs || []).length })),
        // Two different truncations, and a buyer must not have to guess which one happened: `truncated`
        // says the TOTALS miss transactions, while the row list has its own cap. On a 475-transaction
        // block both can be true at once, so the row cap is spelled out instead of left to `cap`.
        ...(raw.length > cap ? { caveat: `rows are capped at ${cap}: the per-transaction list covers the first ${cap} of ${raw.length}, while totalGasUsed/feesPaidWei/successCount aggregate all ${raw.length}` } : {}),
        ...(partial ? { note: `no host supported eth_getBlockReceipts, so the first ${raw.length} of ${count} transactions were read individually — the per-row data is complete for those rows and the block totals cover only them` } : {}) };
    }),
  cr("/chain/fee-history", "Base-fee and priority-fee trend", "eth_feeHistory over a bounded window: base fee at every block plus the 25/50/75 priority-fee percentiles. Whether gas is RISING is not answerable from one instantaneous quote, which is what /chain/fee-data gives.",
    ["gas", "fees", "eip1559", "trend", "chain"], [A.chain(), A.blocks()],
    [["label", "string"], ["head", "integer"], ["oldestBlock", "integer"], ["blocksCovered", "integer"], ["baseFeeGwei", "object"], ["trendPct", "integer"], ["priorityFeeGwei", "object"], ["gasUsedRatio", "array"], ["perBlockBaseFeeGwei", "array"]],
    {label: "Base", head: 51745417, oldestBlock: 51745398, blocksCovered: 21, baseFeeGwei: {first: 0.005, last: 0.005, min: 0.005, max: 0.005}, trendPct: 0, priorityFeeGwei: {p25: 0.001, p50: 0.001, p75: 0.00125}, gasUsedRatio: [9.7], perBlockBaseFeeGwei: [0.005]},
    async ({ chain, blocks }) => {
      const n = Number(blocks);
      const head = await headOf(chain);
      // mainnet.base.org rejects eth_feeHistory with the "latest" block reference (measured
      // 2026-09-24), so the window's NEWEST block is resolved to a number first: a paid route must
      // not fail because one node speaks a narrower dialect than the spec. The second argument is
      // newestBlock, not startBlock — head-n would sell a stale window and skip the blocks asked for.
      const h = await rpcCall(chain, "eth_feeHistory", [hexOf(n), hexOf(head), [25, 50, 75]]);
      const series = (h?.baseFeePerGas ?? []).map(gweiOf);
      const nums = series.filter((x) => x !== null);
      const cols = [[], [], []];
      for (const r of h?.reward ?? []) for (let i = 0; i < 3; i++) { const g = gweiOf(r?.[i]); if (g !== null) cols[i].push(g); }
      const median = (arr) => { if (!arr.length) return null; const s = [...arr].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };
      return { chain, label: CHAINS[chain].label, head, oldestBlock: h?.oldestBlock ? Number(toBig(h.oldestBlock)) : null,
        blocksCovered: nums.length,
        baseFeeGwei: nums.length ? { first: nums[0], last: nums[nums.length - 1], min: Math.min(...nums), max: Math.max(...nums) } : null,
        trendPct: nums.length > 1 && nums[0] > 0 ? Math.round(((nums[nums.length - 1] - nums[0]) / nums[0]) * 1000) / 10 : null,
        priorityFeeGwei: { p25: median(cols[0]), p50: median(cols[1]), p75: median(cols[2]) },
        gasUsedRatio: (h?.gasUsedRatio ?? []).map((x) => Math.round(Number(x) * 1000) / 10),
        perBlockBaseFeeGwei: nums.slice(-20) };
    }),
  cr("/chain/storage-range", "A run of storage slots", "Up to 16 consecutive 32-byte words from any starting slot — walk a struct or the array behind a mapping instead of trusting one view function to explain itself.",
    ["storage", "slots", "contract", "inspect", "chain"],
    [A.chain(), A.address({ name: "address", desc: "contract whose storage is read" }), A.fromSlot(), A.count(), A.block({ name: "blockTag" })],
    [["address", "string"], ["blockTag", "string"], ["fromSlot", "string"], ["count", "integer"], ["populated", "integer"], ["rows", "array"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", blockTag: "0x315925d", fromSlot: "0x2", count: 4, populated: 3, rows: [{slot: "0x2", value: "0x0000000000000000000000001f2e3a640175d20ac31ed523b6733b977173e277", isZero: false, asUint: "178009634717433154990808687687379929950661632631", asAddress: "0x1f2e3a640175d20ac31ed523b6733b977173e277"}]},
    async ({ chain, address, fromSlot, count, blockTag }) => {
      const base = BigInt(fromSlot);
      const n = Number(count);
      if (base + BigInt(n) > 2n ** 64n) bad(`fromSlot + count would wrap the addressable slot space`);
      const rows = await Promise.all(Array.from({ length: n }, async (_, i) => {
        const slot = hexOf(base + BigInt(i));
        const v = await rpcCall(chain, "eth_getStorageAt", [address, slot, blockTag]).catch(() => null);
        const u = toBig(v);
        return { slot: `0x${(base + BigInt(i)).toString(16)}`, value: v ?? null,
          isZero: u !== null && u === 0n, asUint: u === null ? null : String(u), asAddress: decodeAddress(v) };
      }));
      return { address, blockTag, fromSlot: `0x${base.toString(16)}`, count: rows.length,
        populated: rows.filter((r) => r.value !== null && !r.isZero).length, rows };
    },
    (a) => { if (BigInt(a.count) > 16n) bad("this route reads at most 16 slots per call"); }),
  cr("/chain/multicall", "Up to 10 contract reads, one payment", "Batched eth_call: ten (target, calldata) pairs settled once, each answered independently so one reverting view cannot fail the rest. A tenth of the per-call cost of doing them one at a time.",
    ["batch", "eth-call", "read", "contract", "chain"], [A.chain(), A.calls(), A.block({ name: "blockTag" })],
    [["blockTag", "string"], ["requested", "integer"], ["answered", "integer"], ["rows", "array"]],
    {blockTag: "latest", requested: 2, answered: 2, rows: [{to: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", selector: "0x95d89b41", calldataSize: 4, ok: true, returnData: "0x000000000000000000000000000000000000000000…", returnSize: 96}]},
    async ({ chain, calls, blockTag }) => {
      const rows = await Promise.all(calls.map(async (c) => {
        let r = null, err = null;
        try { r = await callContract(chain, c.to, c.data, blockTag); } catch (e) { err = String(e?.message || e).slice(0, 120); }
        const empty = !r || r === "0x";
        const u = toBig(r);
        return { to: c.to, selector: c.data.slice(0, 10) || null, calldataSize: (c.data.length - 2) / 2,
          ok: !err && !empty, ...(err ? { error: err } : {}),
          returnData: empty ? null : r.slice(0, 2066), returnSize: empty ? 0 : (r.length - 2) / 2,
          asUint: u === null ? null : String(u), asAddress: decodeAddress(r), asString: decodeString(r) };
      }));
      return { chain, blockTag, requested: rows.length, answered: rows.filter((x) => x.ok).length, rows,
        note: "ok:false means the call reverted or the node returned nothing — that is the contract's answer, not a failed read" };
    }),
  cr("/chain/token-balances", "One token, many holders", "balanceOf for up to 20 wallets on the same ERC-20, with decimals and symbol resolved once — the holder snapshot a distribution or listing check needs, in one settlement.",
    ["erc20", "balance", "holders", "batch", "chain"], [A.chain(), A.token(), A.owners()],
    [["token", "string"], ["symbol", "string"], ["decimals", "integer"], ["decimalsAssumed", "boolean"], ["requested", "integer"], ["readableCount", "integer"], ["sumRaw", "string"], ["sumFormatted", "string"], ["rows", "array"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", decimals: 6, decimalsAssumed: false, requested: 2, readableCount: 2, sumRaw: "10518879265", sumFormatted: "10518.879265", rows: [{owner: "0x8343c68279587498526114e6385f0a87f248e0d9", readable: true, raw: "10518879265", formatted: "10518.879265"}]},
    async ({ chain, token, owners }) => {
      const [dp, sym] = await Promise.all([tokenDecimals(chain, token), tryCall(chain, token, calldata(SEL.symbol), decodeString)]);
      const d = dp ?? 18;
      const rows = await Promise.all(owners.map(async (o) => {
        const raw = await callContract(chain, token, calldata(SEL.balanceOf, wordAddr(o))).then(toBig).catch(() => null);
        return { owner: o, readable: raw !== null, raw: raw === null ? null : String(raw), formatted: raw === null ? null : fmtDec(raw, d) };
      }));
      let total = 0n;
      for (const r of rows) if (r.readable) total += BigInt(r.raw);
      return { chain, token, symbol: sym, decimals: dp, decimalsAssumed: dp === null, requested: rows.length,
        readableCount: rows.filter((r) => r.readable).length, sumRaw: String(total), sumFormatted: fmtDec(total, d), rows };
    }),
  cr("/chain/nft-token-uri", "ERC-721 tokenURI for one id", "The metadata pointer a wallet will follow for a specific id, plus whether it is on-chain JSON or an off-host scheme. The string is returned as text — this endpoint never resolves it.",
    ["nft", "erc721", "metadata", "tokenuri", "chain"], [A.chain(), A.token({ desc: "NFT contract address" }), A.tokenId()],
    [["token", "string"], ["tokenId", "string"], ["found", "boolean"], ["tokenUri", "string"], ["length", "integer"], ["isOnChainJson", "boolean"], ["scheme", "string"], ["host", "string|null"], ["fetchedByUs", "boolean"]],
    {token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", tokenId: "2448", found: true, tokenUri: "ipfs://QmeSjSinHpPnmXmspMjwiXyN6zS4E9zccariGR3jxcaWtq/2448", length: 58, isOnChainJson: false, scheme: "ipfs", host: null, fetchedByUs: false},
    async ({ chain, token, tokenId }) => {
      const uri = await tryCall(chain, token, calldata(SEL.tokenURI, wordUint(tokenId)), decodeString);
      if (!uri) return { token, tokenId: String(tokenId), found: false, fetchedByUs: false,
        note: "tokenURI reverted or returned nothing — this contract may not implement it, or the id is not minted" };
      let scheme = null, host = null;
      // Only http/https is parsed as a URL; ipfs:// and data: have opaque-ish authorities, and
      // new URL("data:ipfs://x") reports scheme "data:" with an empty host, which would mislabel
      // an off-chain pointer as on-chain. The prefix before the first colon is the real answer.
      const colon = uri.indexOf(":");
      const head = colon > 0 ? uri.slice(0, colon).toLowerCase() : "";
      if (/^[a-z][a-z0-9+.-]*$/.test(head)) scheme = head; else scheme = "relative";
      if (scheme === "http" || scheme === "https") {
        try { host = new URL(uri).host || null; } catch { host = null; }
      }
      return { token, tokenId: String(tokenId), found: true, tokenUri: uri.slice(0, 2048), length: uri.length,
        isOnChainJson: scheme === "data", scheme, host, fetchedByUs: false,
        note: "returned as text only; this route never fetches ipfs:// or http:// targets" };
    }),
  cr("/chain/nft-approved", "Who may move this one NFT", "getApproved(tokenId) — the single-operator approval on one id. Non-zero means someone other than the owner can transfer that exact token without owning it.",
    ["nft", "erc721", "approval", "security", "chain"], [A.chain(), A.token({ desc: "NFT contract address" }), A.tokenId()],
    [["token", "string"], ["tokenId", "string"], ["readable", "boolean"], ["approved", "string"], ["hasApproval", "boolean"]],
    {token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", tokenId: "2448", readable: true, approved: "0x0000000000000000000000000000000000000000", hasApproval: false},
    async ({ chain, token, tokenId }) => {
      const r = await callOrNull(chain, token, calldata(SEL.getApproved, wordUint(tokenId)));
      const approved = decodeAddress(r);
      if (!approved) return { token, tokenId: String(tokenId), readable: false,
        note: "getApproved returned no 32-byte word — the id is probably not minted or the contract is not ERC-721" };
      return { token, tokenId: String(tokenId), readable: true, approved, hasApproval: approved.toLowerCase() !== ZERO_ADDR,
        note: "the zero address means no single-token approval; a non-zero address can transfer THIS id without owning it. " +
          "Blanket setApprovalForAll permissions are a different mechanism — /chain/nft-approved-for-all answers those." };
    }),
  cr("/chain/nft-approved-for-all", "Can this operator move a whole wallet?", "isApprovedForAll(owner, operator) — the setApprovalForAll permission behind most NFT drain headlines, answered per pair in one paid call.",
    ["nft", "erc721", "approval", "security", "chain"], [A.chain(), A.token({ desc: "NFT contract address" }), A.owner(), A.operator()],
    [["token", "string"], ["owner", "string"], ["operator", "string"], ["readable", "boolean"], ["approved", "boolean"]],
    {token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", owner: "0x3255ae35b5f2df602d8764aca82697ea28c6de46", operator: "0x1e0049783f008a0085193e00003d00cd54003c71", readable: true, approved: true},
    async ({ chain, token, owner, operator }) => {
      const r = await callOrNull(chain, token, calldata(SEL.isApprovedForAll, wordAddr(owner), wordAddr(operator)));
      const u = toBig(r);
      if (u === null) return { token, owner, operator, readable: false,
        note: "isApprovedForAll returned no data — this contract does not implement the ERC-721 approval extension" };
      return { token, owner, operator, readable: true, approved: u > 0n,
        note: u > 0n ? "true means this operator can transfer EVERY token the owner holds in this collection" : "no blanket approval for this operator" };
    }),
  cr("/chain/code-at", "Was this a contract at that block?", "eth_getCode at a historical block, compared against today: bytecode present then, size at both points, and whether the code changed since. The check for 'what did this address look like when I traded'.",
    ["bytecode", "contract", "history", "audit", "chain"], [A.chain(), A.address(), A.block()],
    [["address", "string"], ["block", "string"], ["blockNumber", "integer"], ["bytecodeSize", "integer"], ["latestBytecodeSize", "integer"], ["existedAtBlock", "boolean"], ["isContractNow", "boolean"], ["changedSince", "boolean"], ["codePrefix", "string"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", block: "0x3158e7b", blockNumber: 51744379, bytecodeSize: 1852, latestBytecodeSize: 1852, existedAtBlock: true, isContractNow: true, changedSince: false, codePrefix: "0x60806040526004361061005a57600035"},
    async ({ chain, address, block }) => {
      const [then, now] = await Promise.all([
        rpcCall(chain, "eth_getCode", [address, block]),
        rpcCall(chain, "eth_getCode", [address, "latest"]),
      ]);
      const t = String(then || "0x"), nv = String(now || "0x");
      const size = (h) => (h.length - 2) / 2;
      return { chain, address, block, blockNumber: /^0x[0-9a-f]+$/.test(block) ? Number(BigInt(block)) : block,
        bytecodeSize: size(t), latestBytecodeSize: size(nv),
        existedAtBlock: size(t) > 0, isContractNow: size(nv) > 0,
        changedSince: t.toLowerCase() !== nv.toLowerCase(),
        codePrefix: size(t) > 0 ? t.slice(0, 34) : null,
        note: size(t) === 0 ? "no bytecode at that block — either an EOA, or the contract was deployed later" : undefined };
    }),
  cr("/chain/supply-at", "Token supply at a past block", "totalSupply read at any block and diffed against now, formatted with the token's own decimals — how much of a supply was minted since a date, without an indexer.",
    ["erc20", "supply", "history", "inflation", "chain"], [A.chain(), A.token(), A.block()],
    [["token", "string"], ["symbol", "string"], ["decimals", "integer"], ["decimalsAssumed", "boolean"], ["block", "string"], ["blockNumber", "integer"], ["atBlockRaw", "string"], ["atBlockFormatted", "string"], ["latestRaw", "string"], ["latestFormatted", "string"], ["deltaRaw", "string"], ["deltaFormatted", "string"], ["direction", "string"], ["changePct", "number"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", decimals: 6, decimalsAssumed: false, block: "0x315906f", blockNumber: 51744879, atBlockRaw: "4267902489091715", atBlockFormatted: "4267902489.091715", latestRaw: "4271790631862566", latestFormatted: "4271790631.862566", deltaRaw: "3888142770851", deltaFormatted: "3888142.770851", direction: "increased", changePct: 0.0911019588},
    async ({ chain, token, block }) => {
      const [then, now, dp, sym] = await Promise.all([
        callContract(chain, token, calldata(SEL.totalSupply), block).catch(() => null),
        callContract(chain, token, calldata(SEL.totalSupply), "latest").catch(() => null),
        tokenDecimals(chain, token),
        tryCall(chain, token, calldata(SEL.symbol), decodeString),
      ]);
      const a = toBig(then), b = toBig(now);
      if (a === null || b === null) return { token, block, readable: false,
        note: "totalSupply was not readable at one of the two points — this contract may not expose it" };
      const d = dp ?? 18;
      const delta = b - a;
      return { chain, token, symbol: sym, decimals: dp, decimalsAssumed: dp === null,
        block, blockNumber: /^0x[0-9a-f]+$/.test(block) ? Number(BigInt(block)) : block,
        atBlockRaw: String(a), atBlockFormatted: fmtDec(a, d), latestRaw: String(b), latestFormatted: fmtDec(b, d),
        deltaRaw: String(delta), deltaFormatted: fmtDec(delta < 0n ? -delta : delta, d), direction: delta > 0n ? "increased" : delta < 0n ? "decreased" : "unchanged",
        // BigInt division truncates toward zero, so the old `* 10000n / a / 100` shape reported
        // changePct 0 for every move under 0.01% — a bounded supply change read as "no change".
        changePct: a > 0n ? Number((delta * 100n * 10n ** 10n) / a) / 1e10 : null };
    }),
  cr("/chain/approvals-scan", "Recent ERC-20 approvals", "Approval events for one token over a short, bounded window, decoded to owner/spender/amount — the ledger of who just gave someone leave to move their USDC.",
    ["erc20", "approval", "events", "security", "chain"], [A.chain(), A.token(), A.blocks({ max: 25n, default: 10n })],
    [["token", "string"], ["range", "object"], ["count", "integer"], ["truncated", "boolean"], ["decimals", "integer"], ["rows", "array"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", range: {fromBlock: 51745398, toBlock: 51745422, head: 51745422}, count: 158, truncated: false, decimals: 6, rows: [{blockNumber: 51745398, transactionHash: "0x792ea70268beaa44dd0deafa3118f8367530bc36d1c5e62300131f28a3cc53ff", logIndex: 400, address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", owner: "0x0017cfd832401e54c490ec2eecda31e27b2d4d8e", spender: "0x6131b5fae19ea4f9d964eac0408e4408b66337b5"}]},
    async ({ chain, token, blocks }) => {
      const head = await headOf(chain);
      const from = Math.max(0, head - Number(blocks) + 1);
      const raw = (await rpcCall(chain, "eth_getLogs", [{ address: token, fromBlock: hexOf(from), toBlock: hexOf(head), topics: [TOPIC.Approval] }])) || [];
      const cap = 500;
      const dp = await tokenDecimals(chain, token);
      return { chain, token, range: { fromBlock: from, toBlock: head, head }, count: raw.length,
        truncated: raw.length > cap, decimals: dp,
        rows: raw.slice(0, cap).map((l) => ({ blockNumber: Number(toBig(l.blockNumber) ?? 0n), transactionHash: l.transactionHash,
          logIndex: l.logIndex ? Number(toBig(l.logIndex)) : null, address: l.address,
          owner: decodeAddress(l.topics?.[1]), spender: decodeAddress(l.topics?.[2]),
          amountRaw: String(toBig(l.data) ?? 0n), amountFormatted: fmtDec(toBig(l.data) ?? 0n, dp ?? 18) })) };
    }),
  cr("/chain/transfers-scan", "Recent ERC-20 transfers", "Transfer events for one token over a short window, decoded from/to/amount with the token's decimals applied — the outflow check a monitoring bot wants first, without running an indexer.",
    ["erc20", "transfer", "events", "outflow", "chain"], [A.chain(), A.token(), A.blocks({ max: 25n, default: 10n })],
    [["token", "string"], ["decimals", "integer"], ["decimalsAssumed", "boolean"], ["range", "object"], ["count", "integer"], ["truncated", "boolean"], ["sumRaw", "string"], ["sumFormatted", "string"], ["rows", "array"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", decimals: 6, decimalsAssumed: false, range: {fromBlock: 51745399, toBlock: 51745423, head: 51745423}, count: 2264, truncated: true, sumRaw: "709825974999", sumFormatted: "709825.974999", rows: [{blockNumber: 51745399, transactionHash: "0xf4003e094bc7879c851d4961442a4f834b1adc967970eef6242b521d97a1c9ef", logIndex: 14, address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", from: "0x9ab7730b09ebd9ff2df70f06339bd289a1680a46", to: "0x4f6f91599858bf0d19fabcf2c5d591fe13f7c059"}]},
    async ({ chain, token, blocks }) => {
      const head = await headOf(chain);
      const from = Math.max(0, head - Number(blocks) + 1);
      const raw = (await rpcCall(chain, "eth_getLogs", [{ address: token, fromBlock: hexOf(from), toBlock: hexOf(head), topics: [TOPIC.Transfer] }])) || [];
      const cap = 500;
      const dp = await tokenDecimals(chain, token);
      let sum = 0n;
      const rows = raw.slice(0, cap).map((l) => { const v = toBig(l.data) ?? 0n; sum += v;
        return { blockNumber: Number(toBig(l.blockNumber) ?? 0n), transactionHash: l.transactionHash,
          logIndex: l.logIndex ? Number(toBig(l.logIndex)) : null, address: l.address,
          from: decodeAddress(l.topics?.[1]), to: decodeAddress(l.topics?.[2]),
          amountRaw: String(v), amountFormatted: fmtDec(v, dp ?? 18) }; });
      return { chain, token, decimals: dp, decimalsAssumed: dp === null,
        range: { fromBlock: from, toBlock: head, head }, count: raw.length, truncated: raw.length > cap,
        sumRaw: String(sum), sumFormatted: fmtDec(sum, dp ?? 18), rows };
    }),

  // ---- band three (2026-09-24): routes measured in .tmp-check/probe-100-{surface,round2,round3,round5}.mjs ----
  // Nothing below ships on a method that was not answered by a pinned host first. That rule killed
  // three candidates: eth_getProof (answered on only 4 of 7 chains), eth_getLogs?transactionHash=
  // (refused on 4 of 7 — the receipt carries the same logs, so /chain/tx-events uses the receipt),
  // and Uniswap V3 slot0() (my factory addresses returned "0x", i.e. wrong address, not missing
  // method). A route that only answers sometimes bills a buyer for a null, which is bug #2's class.
  cr("/chain/client-version", "Which client answers this chain", "web3_clientVersion for the node that served the call — the build string is how you tell reth from erigon from a proxy that is silently serving a different chain.",
    ["rpc", "client", "node", "chain", "version"], [A.chain()],
    [["clientVersion", "string"], ["answeredBy", "string", "host that replied"]],
    {clientVersion: "Geth/v10.0.0/drpc", answeredBy: "base.drpc.org"},
    async ({ chain }) => { const { result, host } = await rpcCallHost(chain, "web3_clientVersion", []); return { clientVersion: result, answeredBy: host }; }),
  cr("/chain/network-id", "Chain ID and network ID agree?", "eth_chainId versus net_version for one chain. A mismatch is how a wallet ends up signing Base transactions for Mainnet, so this is a two-call safety check, not trivia.",
    ["chain", "chainid", "network", "config", "rpc"], [A.chain()],
    [["chainId", "integer"], ["expectedChainId", "integer"], ["netVersion", "string"], ["agree", "boolean"], ["matchesOurConfig", "boolean"]],
    {chainId: 8453, expectedChainId: 8453, netVersion: "8453", agree: true, matchesOurConfig: true},
    async ({ chain }) => {
      const [cid, net] = await Promise.all([rpcCall(chain, "eth_chainId", []), rpcCall(chain, "net_version", []).catch(() => null)]);
      const n = Number(toBig(cid) ?? 0n);
      return { chainId: n, expectedChainId: CHAINS[chain].chainId, netVersion: net ?? null, agree: net === null ? null : String(n) === String(net), matchesOurConfig: n === CHAINS[chain].chainId };
    }),
  cr("/chain/sync-status", "Is this node caught up?", "eth_syncing plus the head: a public node that is quietly 300 blocks behind answers every other question with stale data, and nothing else in a response tells you that.",
    ["sync", "node", "health", "chain", "rpc"], [A.chain()],
    // safeBlock/finalizedBlock: null on a node that reports no finality markers, and a null sample
    // carries no type, so these two are named from the code (`Number(toBig(...))`) not measured.
    [["syncing", "boolean"], ["head", "integer"], ["currentBlock", "integer"], ["highestBlock", "integer"], ["lagBlocks", "integer"], ["safeBlock", "integer|null"], ["finalizedBlock", "integer|null"]],
    {syncing: false, head: 51745424, currentBlock: 51745424, highestBlock: 51745424, lagBlocks: 0, safeBlock: null, finalizedBlock: null},
    async ({ chain }) => {
      const [s, head, blk] = await Promise.all([
        rpcCall(chain, "eth_syncing", []).catch(() => false),
        headOf(chain),
        rpcCall(chain, "eth_getBlockByNumber", ["latest", false]).catch(() => null),
      ]);
      const obj = s && typeof s === "object" ? s : null;
      const highest = obj ? Number(toBig(obj.highestBlock) ?? 0) : head;
      const current = obj ? Number(toBig(obj.currentBlock) ?? 0) : head;
      return { syncing: !!obj, head, currentBlock: current, highestBlock: highest,
        lagBlocks: Math.max(0, highest - current), safeBlock: blk?.safeBlockNumber ? Number(toBig(blk.safeBlockNumber)) : null,
        finalizedBlock: blk?.finalizedBlockNumber ? Number(toBig(blk.finalizedBlockNumber)) : null };
    }),
  cr("/chain/tx-count", "How many transactions in a block", "eth_getBlockTransactionCountByNumber for one block tag or height — the cheapest load/throughput reading of a chain that never has to move a full block header over the wire.",
    ["block", "transactions", "count", "chain", "throughput"], [A.chain(), A.block()],
    [["blockTag", "string"], ["count", "integer"]],
    {blockTag: "0x315809d", count: 276},
    async ({ chain, block }) => {
      const n = await rpcCall(chain, "eth_getBlockTransactionCountByNumber", [block]);
      return { blockTag: block, count: Number(toBig(n) ?? 0n) };
    }),
  cr("/chain/block-by-hash", "Block header by hash", "The same decoded header /chain/block gives, addressed by hash instead of height — which is what a receipt, a log or a reorg report actually hands you.",
    ["block", "hash", "header", "chain", "rpc"], [A.chain(), A.blockHash()],
    [["requestedHash", "string"], ["found", "boolean"], ["block", "object"]],
    {requestedHash: "0x8d1dea39782231728ea7221c0f27e780425526afa36039ff51adf942e44320be", found: true, block: {number: 51740829, hash: "0x8d1dea39782231728ea7221c0f27e780425526afa36039ff51adf942e44320be", parentHash: "0x7d042696f873398cb75d265424a320ce4cbce30018a4e0e0c399652bd9e9ed7e", timestamp: 1790271005, isoTime: "2026-09-24T17:30:05.000Z", author: "0x4200000000000000000000000000000000000011"}},
    async ({ chain, blockHash }) => {
      const b = await rpcCall(chain, "eth_getBlockByHash", [blockHash, false]);
      if (!b) return { requestedHash: blockHash, found: false, note: "this node has no block with that hash (it may not be on this chain, or may not be synced to it)" };
      return { requestedHash: blockHash, found: true, block: blockSummary(b) };
    }),
  cr("/chain/tx-at-index", "One transaction by block and index", "eth_getTransactionByBlockNumberAndIndex — pick the Nth transaction of a block without transferring the whole block, which is how you sample a block instead of downloading it.",
    ["transaction", "block", "index", "chain", "rpc"], [A.chain(), A.block(), A.index()],
    [["found", "boolean"], ["index", "integer"], ["transaction", "object"]],
    {found: true, index: 0, transaction: {hash: "0x4cf43fb9412b60a73cb79eedda0147229c7171cacfafa0e7460b412f7d860150", from: "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001", to: "0x4200000000000000000000000000000000000015", valueWei: "0", nonce: 51740832, gas: "1000000"}},
    async ({ chain, block, index }) => {
      const t = await rpcCall(chain, "eth_getTransactionByBlockNumberAndIndex", [block, hexOf(index)]);
      if (!t) return { found: false, note: "no transaction at that index in that block" };
      return { found: true, index: Number(index), transaction: {
        hash: t.hash, from: t.from, to: t.to, valueWei: String(toBig(t.value) ?? 0n),
        nonce: Number(toBig(t.nonce) ?? 0n), gas: String(toBig(t.gas) ?? 0n), gasPriceGwei: gweiOf(t.gasPrice),
        selector: (t.input || "").slice(0, 10) || null, inputSize: (t.input || "").length > 2 ? (t.input.length - 2) / 2 : 0,
        blockNumber: t.blockNumber ? Number(toBig(t.blockNumber)) : null, blockHash: t.blockHash ?? null } };
    }),
  cr("/chain/block-series", "A short run of block headers", "Height, timestamp, transaction count, gas used and base fee for up to 25 consecutive blocks — the series itself, so a caller can plot throughput or fee pressure instead of taking our word for the average.",
    ["block", "series", "throughput", "gas", "chain"], [A.chain(), A.blocks({ max: 25n, default: 10n, desc: "how many blocks, newest first (max 25)" })],
    [["count", "integer"], ["window", "object"], ["secondsPerBlock", "integer"], ["rows", "array"]],
    {count: 6, window: {from: 51745421, to: 51745426}, secondsPerBlock: 2, rows: [{number: 51745426, timestamp: 1790280199, isoTime: "2026-09-24T20:03:19.000Z", transactionsCount: 192, gasUsed: "28608897", gasLimit: "400000000"}]},
    async ({ chain, blocks }) => {
      const head = await headOf(chain);
      const from = Math.max(0, head - Number(blocks) + 1);
      const rows = [];
      for (let n = head; n >= from; n--) {
        const b = await rpcCall(chain, "eth_getBlockByNumber", [hexOf(n), false]).catch(() => null);
        if (!b) continue;
        rows.push({ number: Number(toBig(b.number) ?? n), timestamp: Number(toBig(b.timestamp) ?? 0n),
          isoTime: new Date(Number(toBig(b.timestamp) ?? 0n) * 1000).toISOString(), transactionsCount: (b.transactions || []).length,
          gasUsed: String(toBig(b.gasUsed) ?? 0n), gasLimit: String(toBig(b.gasLimit) ?? 0n), baseFeeGwei: gweiOf(b.baseFeePerGas),
          size: Number(toBig(b.size) ?? 0n), author: b.author ?? b.miner ?? null });
      }
      const span = rows.length > 1 ? (rows[0].timestamp - rows[rows.length - 1].timestamp) : 0;
      return { count: rows.length, window: { from, to: head }, secondsPerBlock: rows.length > 1 ? +(span / (rows.length - 1)).toFixed(3) : null, rows };
    }),
  cr("/chain/block-by-timestamp", "Which block was mined at a time", "Binary-searches the header timestamps for the first block at or after a unix time — every 'what was the supply / who held what on that date' question starts here, and no public node offers the lookup.",
    ["block", "timestamp", "date", "search", "chain"], [A.chain(), A.timestamp()],
    [["found", "boolean"], ["requestedTimestamp", "integer"], ["blockNumber", "integer"], ["blockTimestamp", "integer"], ["isoTime", "string"], ["hash", "string"], ["probes", "integer"], ["head", "integer"]],
    {found: true, requestedTimestamp: 1790271005, blockNumber: 51740829, blockTimestamp: 1790271005, isoTime: "2026-09-24T17:30:05.000Z", hash: "0x8d1dea39782231728ea7221c0f27e780425526afa36039ff51adf942e44320be", probes: 26, head: 51745428},
    async ({ chain, timestamp }) => {
      const target = Number(timestamp);
      const head = await headOf(chain);
      const at = async (n) => toBig((await rpcCall(chain, "eth_getBlockByNumber", [hexOf(n), false]).catch(() => null))?.timestamp);
      const earliest = await at(0).catch(() => null);
      const headTs = await at(head);
      if (headTs === null) throw new HttpError(502, "no header timestamps from this node");
      if (earliest !== null && target < Number(earliest)) return { found: false, note: `before this chain's genesis block data (${new Date(Number(earliest) * 1000).toISOString()})`, head };
      if (target > Number(headTs)) return { found: false, note: `in the future: head ${head} is ${new Date(Number(headTs) * 1000).toISOString()}`, head };
      let lo = 0, hi = head, probes = 0;
      while (lo < hi && probes < 26) {
        probes++;
        const mid = lo + Math.floor((hi - lo) / 2);
        const ts = await at(mid);
        if (ts === null) { hi = mid; continue; }
        if (Number(ts) < target) lo = mid + 1; else hi = mid;
      }
      const b = await rpcCall(chain, "eth_getBlockByNumber", [hexOf(lo), false]);
      return { found: true, requestedTimestamp: target, blockNumber: lo, blockTimestamp: Number(toBig(b?.timestamp) ?? 0n),
        isoTime: b?.timestamp ? new Date(Number(toBig(b.timestamp)) * 1000).toISOString() : null,
        hash: b?.hash ?? null, probes, head, note: "the first block whose timestamp is at or after the requested time" };
    }),
  cr("/chain/contract-owner", "Who controls this contract", "owner() decoded, plus whether the same address answers owner() as a storage read — the single field that decides who can pause, mint or upgrade the thing you are about to interact with.",
    ["owner", "control", "contract", "security", "admin"], [A.chain(), A.address()],
    [["address", "string"], ["hasCode", "boolean"], ["bytecodeSize", "integer"], ["readable", "boolean"], ["owner", "string"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", hasCode: true, bytecodeSize: 1852, readable: true, owner: "0x3abd6f64a422225e61e435bae41db12096106df7"},
    async ({ chain, address }) => {
      const code = (await rpcCall(chain, "eth_getCode", [address, "latest"])) || "0x";
      const size = (code.length - 2) / 2;
      const raw = await callOrNull(chain, address, calldata(SEL2.owner));
      const owner = decodeAddress(raw);
      return { address, hasCode: size > 0, bytecodeSize: size, readable: !!owner,
        owner, ...(owner ? {} : { note: "no owner() answer — the contract does not expose one, or is an EOA, or the node returned nothing. This is not 'no owner'." }) };
    }),
  cr("/chain/proxy-check", "Is it a proxy, and what is behind it", "The three EIP-1967 slots (implementation, admin, beacon) read next to implementation(): a proxy hides the real code, so bytecode-size checks alone understate what an upgrade can change.",
    ["proxy", "eip1967", "upgrade", "contract", "security"], [A.chain(), A.address()],
    // beacon: null unless this is a beacon proxy, and a null sample carries no type — so this one key
    // is named from the code (slotAddr of the EIP-1967 beacon slot) instead of measured.
    [["address", "string"], ["hasCode", "boolean"], ["bytecodeSize", "integer"], ["isProxy", "boolean"], ["implementationFromSlot", "string"], ["implementationFromCall", "string"], ["slotMatchesCall", "boolean"], ["proxyAdmin", "string"], ["beacon", "string|null"], ["eip1967Slots", "object"]],
    {address: "0x4200000000000000000000000000000000000002", hasCode: true, bytecodeSize: 2055, isProxy: true, implementationFromSlot: "0xc0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d30002", implementationFromCall: "0xc0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d30002", slotMatchesCall: true, proxyAdmin: "0x4200000000000000000000000000000000000018", beacon: null, eip1967Slots: {implementation: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", admin: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", beacon: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"}},
    async ({ chain, address }) => {
      const read = (slot) => rpcCall(chain, "eth_getStorageAt", [address, slot, "latest"]).catch(() => null);
      const [implSlot, adminSlot, beaconSlot, called, code] = await Promise.all([
        read(SLOT1967.implementation), read(SLOT1967.admin), read(SLOT1967.beacon),
        callOrNull(chain, address, calldata(SEL2.implementation)),
        rpcCall(chain, "eth_getCode", [address, "latest"]).catch(() => "0x"),
      ]);
      const a = slotAddr(decodeAddress(implSlot)), b = slotAddr(decodeAddress(called));
      const admin = slotAddr(decodeAddress(adminSlot)), beacon = slotAddr(decodeAddress(beaconSlot));
      const codeSize = ((code || "0x").length - 2) / 2;
      return {
        address, hasCode: codeSize > 0, bytecodeSize: codeSize,
        isProxy: !!(a || b || admin || beacon),
        implementationFromSlot: a, implementationFromCall: b,
        ...(a && b ? { slotMatchesCall: a === b } : {}),
        proxyAdmin: admin, beacon: beacon,
        eip1967Slots: SLOT1967,
        note: admin ? "a proxy admin exists: that address can upgrade the implementation, which means the code you audited is not permanent"
          : (a || b) ? "implementation is set with no readable admin — check who can call upgradeTo()"
          : "no EIP-1967 slots set: either not a proxy, or a non-EIP-1967 proxy pattern",
      };
    }),
  cr("/chain/paused-check", "Is this contract paused right now", "paused() with the revert and no-data cases kept apart from a false — 'this token has no pause switch' and 'this token is not paused' are different facts to trade on.",
    ["paused", "state", "contract", "risk", "erc20"], [A.chain(), A.address()],
    [["address", "string"], ["readable", "boolean"], ["paused", "boolean"], ["raw", "string"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", readable: true, paused: false, raw: "0x0000000000000000000000000000000000000000000000000000000000000000"},
    async ({ chain, address }) => {
      const raw = await callOrNull(chain, address, calldata(SEL2.paused));
      const v = toBig(raw);
      return { address, readable: v !== null, paused: v === null ? null : v > 0n,
        raw: raw ?? null, ...(v === null ? { note: "paused() gave no answer — the contract has no Pausable switch, which is not the same as not paused" } : {}) };
    }),
  cr("/chain/permit-ready", "Does this token support gasless permit()", "DOMAIN_SEPARATOR() plus the owner's current nonce and whether permit() is in the code — the three inputs a signed-approval relayer needs before it can move funds without the holder paying gas.",
    ["permit", "eip2612", "signature", "allowance", "erc20"], [A.chain(), A.token(), A.owner({ desc: "address whose permit nonce to read" })],
    // implementation: null unless the token is a proxy, and a null sample carries no type — named from
    // the code (the address behind the EIP-1967 slot or implementation()).
    [["token", "string"], ["owner", "string"], ["domainSeparator", "string"], ["nonce", "string"], ["hasPermitSelector", "boolean"], ["permitSelectorIn", "string"], ["implementation", "string"], ["permitReady", "boolean"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", owner: "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b", domainSeparator: "0x02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f", nonce: "0", hasPermitSelector: true, permitSelectorIn: "implementation", implementation: "0x2ce6311ddae708829bc0784c967b7d77d19fd779", permitReady: true},
    async ({ chain, token, owner }) => {
      // A proxy token's own bytecode is the forwarding shim — the permit() selector lives in the
      // implementation. Scanning only eth_getCode(token) told Base USDC, whose DOMAIN_SEPARATOR() and
      // nonces() BOTH answer, that it has no permit(): a relayer paying for this read would skip the
      // chain's biggest stablecoin on a false negative. The implementation is therefore resolved the
      // same two ways /chain/proxy-check resolves it, because proxies disagree on where it is kept:
      // measured on 2026-09-24, USDC's EIP-1967 slot is EMPTY and only implementation() answers.
      const [ds, nonce, code, implSlot, implCall] = await Promise.all([
        callOrNull(chain, token, calldata(SEL2.domainSeparator)),
        callOrNull(chain, token, calldata(SEL2.nonces, wordAddr(owner))),
        rpcCall(chain, "eth_getCode", [token, "latest"]).catch(() => "0x"),
        rpcCall(chain, "eth_getStorageAt", [token, SLOT1967.implementation, "latest"]).catch(() => null),
        callOrNull(chain, token, calldata(SEL2.implementation)).catch(() => null),
      ]);
      const impl = slotAddr(decodeAddress(implSlot)) || slotAddr(decodeAddress(implCall));
      const implCode = impl ? await rpcCall(chain, "eth_getCode", [impl, "latest"]).catch(() => "0x") : null;
      // The bytecode is one continuous hex string, so the selector is searched WITHOUT its 0x.
      const inToken = String(code || "0x").toLowerCase().includes(SEL2.permit.slice(2));
      const inImpl = implCode ? String(implCode).toLowerCase().includes(SEL2.permit.slice(2)) : false;
      const hasPermit = inToken || inImpl;
      const n = toBig(nonce);
      const sep = typeof ds === "string" && ds.length === 66 ? ds.toLowerCase() : null;
      return { token, owner, domainSeparator: sep, nonce: n === null ? null : String(n), hasPermitSelector: hasPermit,
        // Where the selector was found, because "not in the token's own code" used to be a lie about
        // every proxied token on every chain this route serves.
        permitSelectorIn: inToken ? "token" : inImpl ? "implementation" : null,
        implementation: impl,
        permitReady: !!(sep && n !== null && hasPermit),
        note: (sep && n !== null && hasPermit) ? "signature-based approvals are live on this token for this owner" : "at least one of DOMAIN_SEPARATOR()/nonces()/permit() is missing, so EIP-2612-style permit is not usable here" };
    }),
  cr("/chain/1155-balance", "ERC-1155 balance of one id", "balanceOf(account, id) for a multi-token contract, formatted with whatever supply unit the contract uses — the read a Zora/Sudoswap-style position tracker needs, which an ERC-20 or ERC-721 lookup cannot answer.",
    ["erc1155", "balance", "multitoken", "chain", "nft"], [A.chain(), A.token(), A.owner({ name: "account", desc: "holder address" }), A.tokenId()],
    [["token", "string"], ["account", "string"], ["tokenId", "string"], ["balanceRaw", "string"], ["readable", "boolean"], ["supported", "boolean"]],
    {token: "0x204B70042E2FD080ab88bdCAcB9a557EE3da4bBc", account: "0xC785D6AD03275d09CB9Df5d8eC1816f305399D67", tokenId: "2", balanceRaw: "4758", readable: true, supported: true},
    async ({ chain, token, account, tokenId }) => {
      const [raw, supported] = await Promise.all([
        callOrNull(chain, token, calldata(SEL2.bal1155, wordAddr(account), wordUint(tokenId))),
        hasInterface(chain, token, IFACE.ERC1155),
      ]);
      const v = toBig(raw);
      return { token, account, tokenId: String(tokenId), balanceRaw: v === null ? null : String(v), readable: v !== null, supported };
    }),
  cr("/chain/1155-uri", "ERC-1155 metadata pointer for an id", "uri(id) decoded from the ABI string, with the {id} substitution left visible instead of followed — the metadata URL a wallet will fetch, returned as text and never requested by us.",
    ["erc1155", "metadata", "uri", "nft", "chain"], [A.chain(), A.token(), A.tokenId()],
    [["token", "string"], ["tokenId", "string"], ["readable", "boolean"], ["uri", "string"], ["raw", "string"], ["template", "boolean"]],
    {token: "0x204B70042E2FD080ab88bdCAcB9a557EE3da4bBc", tokenId: "2", readable: true, uri: "ipfs://QmNfvPePcwt8CsifgiV61FDBfHkarmQcHFfq6M4Ms4LDMK/2", raw: "0x000000000000000000000000000000000000000000…", template: false},
    async ({ chain, token, tokenId }) => {
      const raw = await callOrNull(chain, token, calldata(SEL2.uri1155, wordUint(tokenId)));
      const s = decodeString(raw);
      return { token, tokenId: String(tokenId), readable: !!s, uri: s ?? null, raw: raw ?? null,
        template: !!s && s.includes("{id}"),
        ...(s ? { note: "returned as text only — this route never fetches the URI it reads" } : { note: "uri(id) gave no answer: not an ERC-1155, no metadata for this id, or the call reverted" }) };
    }),
  cr("/chain/1155-batch", "Many ERC-1155 positions, one payment", "balanceOfBatch over up to 10 (account, id) pairs in a single settled call — the position snapshot of a portfolio, which is otherwise one paid read per line.",
    ["erc1155", "batch", "portfolio", "balance", "chain"],
    [A.chain(), A.token(), A.accounts({ desc: "up to 10 holder addresses, positionally matched to tokenIds" }), A.tokenIds({ desc: "up to 10 ids (decimal), same order as accounts" })],
    [["token", "string"], ["requested", "integer"], ["readable", "boolean"], ["answered", "integer"], ["rows", "array"]],
    {token: "0x204B70042E2FD080ab88bdCAcB9a557EE3da4bBc", requested: 2, readable: true, answered: 2, rows: [{account: "0xC785D6AD03275d09CB9Df5d8eC1816f305399D67", tokenId: "2", balanceRaw: "4758"}]},
    async ({ chain, token, accounts, tokenIds }) => {
      // balanceOfBatch(address[],uint256[]) is two DYNAMIC arrays, so the calldata is a two-word head
      // of byte-offsets followed by (length, items) for each array. Every word is 32 bytes: building it
      // with an unpadded hex string is the bug that makes a contract read back its own length as a
      // balance, so all of it goes through padLeft.
      const n = Math.min(accounts.length, tokenIds.length);
      const w = (v) => padLeft(BigInt(v).toString(16));
      const calld = SEL2.balanceOfBatch + w(0x40) + w(0x40 + 32 + n * 32)
        + w(n) + accounts.slice(0, n).map((a) => padLeft(a)).join("")
        + w(n) + tokenIds.slice(0, n).map((t) => w(t)).join("");
      const raw = await callOrNull(chain, token, calld);
      const words = typeof raw === "string" && raw.length > 2 ? (raw.slice(2).match(/.{1,64}/g) || []) : [];
      // Return head is the same two offsets; word 2 is the balances array's length, so the values start
      // at word 3. Anything shorter means the contract did not answer in the shape we sent for.
      const off = words.length > 0 ? Number(toBig(`0x${words[0]}`) ?? 64n) / 32 : 2;
      const len = words.length > off ? Number(toBig(`0x${words[off]}`) ?? 0n) : 0;
      const bal = words.slice(off + 1, off + 1 + Math.min(len, n));
      return { token, requested: n, readable: bal.length > 0, answered: len,
        rows: Array.from({ length: n }, (_, i) => ({ account: accounts[i], tokenId: String(tokenIds[i]),
          balanceRaw: bal[i] ? String(BigInt(`0x${bal[i]}`)) : null })),
        ...(bal.length ? {} : { note: "balanceOfBatch returned nothing — the contract may not implement ERC-1155, or rejected the batch lengths" }) };
    }),
  cr("/chain/1155-check", "Is this really an ERC-1155", "supportsInterface for the multi-token ids plus contractURI and a probe of one id — the pre-flight before a client assumes a contract is a 721 and sends the wrong call.",
    ["erc1155", "supportsinterface", "nft", "contract", "standards"], [A.chain(), A.token(), A.tokenId({ required: false, default: 0n, desc: "id to probe uri() with (default 0)" })],
    [["token", "string"], ["probedTokenId", "string"], ["standards", "object"], ["supported", "boolean"], ["contractURI", "string"]],
    {token: "0x204B70042E2FD080ab88bdCAcB9a557EE3da4bBc", probedTokenId: "2", standards: {ERC165: true, ERC721: false, ERC1155: true}, supported: true, contractURI: "ipfs://QmfYmpDKX2qtTnoyeJWyri7e7KW5V5tH1Z91VrEXtBUvDU/0"},
    async ({ chain, token, tokenId }) => {
      const [e165, e721, e1155, contractUri] = await Promise.all([
        hasInterface(chain, token, IFACE.ERC165), hasInterface(chain, token, IFACE.ERC721),
        hasInterface(chain, token, IFACE.ERC1155),
        callOrNull(chain, token, calldata(SEL2.contractURI)),
      ]);
      return { token, probedTokenId: String(tokenId ?? 0n), standards: { ERC165: e165, ERC721: e721, ERC1155: e1155 },
        supported: e1155 === true, contractURI: decodeString(contractUri),
        note: "interface ids are the ones proven against live contracts in this file's IFACE table; per-id metadata is answered by GET /chain/1155-uri" };
    }),
  cr("/chain/storage-diff", "Did one storage slot change?", "The same slot read at two blocks: previous, current, and whether they differ — the primitive behind 'what did this contract's state actually move between those two dates'.",
    ["storage", "slot", "diff", "history", "chain"], [A.chain(), A.address(), A.slot(), A.block({ name: "blockA", default: "safe", desc: "older block (number or latest|safe|finalized|earliest)" }), A.block({ name: "blockB", desc: "newer block (number or tag)", default: "latest" })],
    [["address", "string"], ["slot", "string"], ["blocks", "object"], ["valueA", "string"], ["valueB", "string"], ["asUintA", "string"], ["asUintB", "string"], ["changed", "boolean"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", slot: "0x0000000000000000000000000000000000000000000000000000000000000002", blocks: {a: "0x315923b", b: "latest", head: 51745437}, valueA: "0x0000000000000000000000001f2e3a640175d20ac31ed523b6733b977173e277", valueB: "0x0000000000000000000000001f2e3a640175d20ac31ed523b6733b977173e277", asUintA: "178009634717433154990808687687379929950661632631", asUintB: "178009634717433154990808687687379929950661632631", changed: false},
    async ({ chain, address, slot, blockA, blockB }) => {
      const [a, b] = await Promise.all([
        rpcCall(chain, "eth_getStorageAt", [address, slot, blockA]),
        rpcCall(chain, "eth_getStorageAt", [address, slot, blockB]),
      ]);
      const ua = toBig(a), ub = toBig(b);
      const head = await headOf(chain);
      return { address, slot, blocks: { a: blockA, b: blockB, head }, valueA: a ?? null, valueB: b ?? null,
        asUintA: ua === null ? null : String(ua), asUintB: ub === null ? null : String(ub),
        changed: String(a ?? "").toLowerCase() !== String(b ?? "").toLowerCase() };
    }),
  cr("/chain/token-meta-at", "Token name, symbol, supply at a block", "The ERC-20 listing fields read at a past block tag or height, formatted with the decimals the contract itself reported — how a supply looked on a date, not how it looks now.",
    ["erc20", "history", "supply", "token", "chain"], [A.chain(), A.token(), A.block({ required: true, default: undefined, desc: "block number or tag to read the listing fields at" })],
    [["token", "string"], ["blockTag", "string"], ["name", "string|null"], ["symbol", "string|null"], ["decimals", "integer|null"], ["totalSupplyRaw", "string|null"], ["totalSupply", "string|null"]],
    {token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", blockTag: "0x3158089", name: "USD Coin", symbol: "USDC", decimals: 6, totalSupplyRaw: "4274312172737682", totalSupply: "4274312172.737682"},
    async ({ chain, token, block }) => {
      const [name, symbol, dec, supply] = await Promise.all([
        callOrNull(chain, token, calldata(SEL.name), block), callOrNull(chain, token, calldata(SEL.symbol), block),
        callOrNull(chain, token, calldata(SEL.decimals), block), callOrNull(chain, token, calldata(SEL.totalSupply), block),
      ]);
      // An `eth_call` against an address that has no code at that block does not revert — free nodes answer
      // `0x`, i.e. RETURNED NOTHING. Reading that as a number gives `decimals: 0` and `totalSupply: 0`,
      // which is a fabricated history: measured on Base, USDC at `earliest` returned 0x for all four calls
      // and the route printed decimals 0 / supply null while name and symbol were correctly null. So an
      // empty return is now "unreadable", and only a real 32-byte word (even an all-zero one) is a value.
      const word = (h) => (typeof h === "string" && /^0x[0-9a-fA-F]{64}$/.test(h) ? h : null);
      const dp = word(dec) === null ? null : Number(toBig(dec));
      const scaleKnown = dp !== null && Number.isFinite(dp) && dp <= 18;
      const s = word(supply) === null ? null : toBig(supply);
      // name/symbol are ABI strings, not single words, so they go through the decoder untouched (it
      // already answers null for `0x` and for garbage).
      return { token, blockTag: block, name: decodeString(name), symbol: decodeString(symbol),
        decimals: scaleKnown ? dp : null,
        totalSupplyRaw: s === null ? null : String(s), totalSupply: s === null || !scaleKnown ? null : fmtDec(s, dp) };
    }),
  cr("/chain/nft-owner-at", "Who owned an NFT at a block", "ownerOf(id) read at a chosen block and again at the head: previous holder, current holder, and whether it moved — the ownership history a sale-attribution or stolen-collection check needs.",
    ["nft", "owner", "history", "erc721", "chain"], [A.chain(), A.token(), A.tokenId(), A.block({ required: true, default: undefined, desc: "older block number or tag to compare the current owner against" })],
    [["token", "string"], ["tokenId", "string"], ["blockThen", "string"], ["ownerThen", "string"], ["ownerNow", "string"], ["readable", "boolean"], ["moved", "boolean"]],
    {token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", tokenId: "7761", blockThen: "0x18d7672", ownerThen: "0x62b69dffa3840c7cac6cf5dc5380521ded75e8c9", ownerNow: "0x62b69dffa3840c7cac6cf5dc5380521ded75e8c9", readable: true, moved: false},
    async ({ chain, token, tokenId, block }) => {
      const data = calldata(SEL.ownerOf, wordUint(tokenId));
      const [then, now] = await Promise.all([
        rpcCall(chain, "eth_call", [{ to: token, data }, block]).catch(() => null),
        rpcCall(chain, "eth_call", [{ to: token, data }, "latest"]).catch(() => null),
      ]);
      const a = decodeAddress(then), b = decodeAddress(now);
      return { token, tokenId: String(tokenId), blockThen: block, ownerThen: a, ownerNow: b,
        readable: !!(a || b), moved: a && b ? a !== b : null,
        ...(a || b ? {} : { note: "ownerOf answered nothing at either block — wrong chain for this collection, an id that was never minted, or a revert" }) };
    }),
  cr("/chain/bytecode-fingerprint", "Fingerprint a contract's code", "SHA-256 of the deployed bytecode plus its size and edges — two addresses with the same fingerprint are the same compiled contract, which is how a clone of a known scam shows up before you interact with it.",
    ["bytecode", "fingerprint", "clone", "contract", "security"], [A.chain(), A.address()],
    [["address", "string"], ["hasCode", "boolean"], ["bytecodeSize", "integer"], ["sha256", "string"], ["prefix", "string"], ["suffix", "string"]],
    {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", hasCode: true, bytecodeSize: 1852, sha256: "0x98d785fcb1bf847f287adc2310759fd94cc13e754b974bc72131382e8266f607", prefix: "0x60806040526004361061", suffix: "0x736f6c634300060c0033"},
    async ({ chain, address }) => {
      const code = (await rpcCall(chain, "eth_getCode", [address, "latest"]).catch(() => "0x")) || "0x";
      const size = (code.length - 2) / 2;
      return { address, hasCode: size > 0, bytecodeSize: size,
        sha256: size === 0 ? null : "0x" + createHash("sha256").update(Buffer.from(code.slice(2), "hex")).digest("hex"),
        prefix: size === 0 ? null : code.slice(0, 22), suffix: size === 0 ? null : "0x" + code.slice(-20),
        note: "SHA-256 of the runtime bytecode as returned by eth_getCode — a fingerprint, not an EVM address hash" };
    }),
  cr("/chain/bytecode-capabilities", "Which functions this code carries", "Scans deployed bytecode for 4-byte selectors we can name from a derived table: what this contract can be asked to do, read off the code rather than trusted from a README.",
    ["bytecode", "selector", "abi", "contract", "analysis"], [A.chain(), A.address(), A.count({ max: 60n, default: 40n, desc: "how many named selectors to list (max 60)" })],
    [["address", "string"], ["hasCode", "boolean"], ["bytecodeSize", "integer"], ["push4Candidates", "integer"], ["namedCount", "integer"], ["named", "array"], ["unnamedSelectorCount", "integer"]],
    {address: "0xc5102fE9359FD9a28f877a67E36B0F050d81a3CC", hasCode: true, bytecodeSize: 16498, push4Candidates: 42, namedCount: 18, named: [{selector: "0x715018a6", signature: "renounceOwnership()"}], unnamedSelectorCount: 24},
    async ({ chain, address, count }) => {
      const code = String((await rpcCall(chain, "eth_getCode", [address, "latest"]).catch(() => "0x")) || "0x").toLowerCase();
      const size = (code.length - 2) / 2;
      if (size === 0) return { address, hasCode: false, push4Candidates: 0, namedCount: 0, named: [], unnamedSelectorCount: 0, note: "no bytecode at this address on this chain" };
      // PUSH4 (opcode 0x63) is how a selector reaches a function dispatch table. This scan is an
      // inventory, not a decode: it finds the 4-byte values the code carries and names only those that
      // appear in KNOWN_SELECTOR. An unnamed value is counted, never guessed at, and a 0x63 that is
      // really part of a literal or an immutables blob can still read as a candidate.
      const found = new Set();
      const body = code.slice(2);
      for (let i = 0; i + 10 <= body.length; i += 2) {
        if (body[i] === "6" && body[i + 1] === "3") found.add("0x" + body.slice(i + 2, i + 10));
      }
      const all = [...found];
      const known = all.filter((s) => KNOWN_SELECTOR[s]);
      const named = known.slice(0, Number(count)).map((s) => ({ selector: s, signature: KNOWN_SELECTOR[s] }));
      return { address, hasCode: true, bytecodeSize: size, push4Candidates: all.length,
        namedCount: named.length, named,
        unnamedSelectorCount: all.length - known.length,
        ...(Number(count) < known.length ? { moreNamed: known.length - Number(count) } : {}),
        note: "bytecode scan, not a decode: PUSH4 finds selectors a function dispatches on but cannot prove reachability, and unnamed 4-byte values are counted, not guessed at" };
    }),
  cr("/chain/contract-diff", "Same contract, two addresses?", "Bytecode fingerprints of two addresses compared: size, SHA-256 and prefix/suffix equality — the question behind 'is this new token a redeploy of the one that ruggened last week'.",
    ["clone", "bytecode", "diff", "contract", "security"], [A.chain(), A.address(), A.address({ name: "other", desc: "second address to compare against" })],
    [["a", "object"], ["b", "object"], ["bothHaveCode", "boolean"], ["identicalBytecode", "boolean"], ["sameSize", "boolean"]],
    {a: {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", hasCode: true, bytecodeSize: 1852, sha256: "0x98d785fcb1bf847f287adc2310759fd94cc13e754b974bc72131382e8266f607"}, b: {address: "0xc5102fE9359FD9a28f877a67E36B0F050d81a3CC", hasCode: true, bytecodeSize: 16498, sha256: "0x45f45bc84fa33d73d707ce9b46883ce75307c632981e5a5b16e6d6706e96341c"}, bothHaveCode: true, identicalBytecode: false, sameSize: false},
    async ({ chain, address, other }) => {
      const fp = async (a) => {
        const code = String((await rpcCall(chain, "eth_getCode", [a, "latest"]).catch(() => "0x")) || "0x");
        const size = (code.length - 2) / 2;
        return { address: a, hasCode: size > 0, bytecodeSize: size,
          sha256: size === 0 ? null : "0x" + createHash("sha256").update(Buffer.from(code.slice(2), "hex")).digest("hex") };
      };
      const [a, b] = await Promise.all([fp(address), fp(other)]);
      return { chain, a, b, bothHaveCode: a.hasCode && b.hasCode,
        identicalBytecode: !!(a.sha256 && b.sha256 && a.sha256 === b.sha256),
        sameSize: a.bytecodeSize === b.bytecodeSize,
        note: "identical runtime bytecode means the same compiled code, not the same owner, storage or intent" };
    }),
  cr("/chain/wallet-tokens", "One wallet, many ERC-20s", "balanceOf for one address across up to 10 tokens on one chain, each formatted with its own decimals and symbol — the holding snapshot a portfolio bot wants in a single settlement instead of ten.",
    ["erc20", "portfolio", "balance", "wallet", "token"], [A.chain(), A.address({ name: "owner", desc: "holder address" }), A.tokens()],
    [["owner", "string"], ["requested", "integer"], ["tokensReadable", "integer"], ["totalRowsWithBalance", "integer"], ["rows", "array"]],
    {owner: "0x8343c68279587498526114e6385f0a87f248e0d9", requested: 1, tokensReadable: 1, totalRowsWithBalance: 1, rows: [{token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", decimals: 6, symbol: "USDC", balanceRaw: "10518879265", balance: "10518.879265", readable: true}]},
    async ({ chain, owner, tokens }) => {
      const rows = await Promise.all(tokens.map(async (token) => {
        const [raw, dec, sym] = await Promise.all([
          callOrNull(chain, token, calldata(SEL.balanceOf, wordAddr(owner))),
          callOrNull(chain, token, calldata(SEL.decimals)),
          callOrNull(chain, token, calldata(SEL.symbol)),
        ]);
        const d = toBig(dec); const v = toBig(raw);
        const use = d !== null && d <= 18n ? Number(d) : null;
        return { token, decimals: use, symbol: decodeString(sym), balanceRaw: v === null ? null : String(v),
          balance: v === null || use === null ? null : fmtDec(v, use), readable: v !== null };
      }));
      return { chain, owner, requested: rows.length, tokensReadable: rows.filter((r) => r.readable).length,
        totalRowsWithBalance: rows.filter((r) => (r.balanceRaw ?? "0") !== "0").length, rows };
    }),
  cr("/chain/wallet-nfts", "One wallet, many collections", "ERC-721 balanceOf for one address across up to 10 collections with each collection's name and symbol resolved once — the 'what NFTs does this wallet actually hold' check without an indexer.",
    ["erc721", "nft", "portfolio", "wallet", "holdings"], [A.chain(), A.address({ name: "owner", desc: "holder address" }), A.tokens({ desc: "up to 10 ERC-721 contract addresses" })],
    [["owner", "string"], ["requested", "integer"], ["totalHeld", "string"], ["collectionsWithHoldings", "integer"], ["rows", "array"]],
    {owner: "0x58867fa928b92ca3dc1c709d058ea1bfa1fc28d5", requested: 1, totalHeld: "7", collectionsWithHoldings: 1, rows: [{token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", name: "BoredApeYachtClub", symbol: "BAYC", supportsERC721: true, balance: "7", readable: true}]},
    async ({ chain, owner, tokens }) => {
      const rows = await Promise.all(tokens.map(async (token) => {
        const [raw, name, sym, is721] = await Promise.all([
          callOrNull(chain, token, calldata(SEL.balanceOf, wordAddr(owner))),
          callOrNull(chain, token, calldata(SEL.name)), callOrNull(chain, token, calldata(SEL.symbol)),
          hasInterface(chain, token, IFACE.ERC721),
        ]);
        const v = toBig(raw);
        return { token, name: decodeString(name), symbol: decodeString(sym), supportsERC721: is721,
          balance: v === null ? null : String(v), readable: v !== null };
      }));
      // A contract that reports a 2^255 balance must not turn our summary field into a float, so the
      // total is summed in BigInt and published as a decimal string.
      const total = rows.reduce((s, r) => s + (r.balance === null ? 0n : BigInt(r.balance)), 0n);
      return { chain, owner, requested: rows.length, totalHeld: String(total),
        collectionsWithHoldings: rows.filter((r) => r.balance && r.balance !== "0").length, rows };
    }),
  cr("/chain/wallet-approvals", "What one spender can still move", "allowance(owner, spender) across up to 10 tokens for one wallet — the standing-approval audit that answers 'if this address gets phished tonight, what leaves'.",
    ["allowance", "approval", "risk", "wallet", "erc20"], [A.chain(), A.owner(), A.spender(), A.tokens()],
    [["owner", "string"], ["spender", "string"], ["requested", "integer"], ["openApprovals", "integer"], ["unrestrictedApprovals", "integer"], ["rows", "array"]],
    {owner: "0xbaa8c0dd620f6411c9cc380140d5d312bcaf2a38", spender: "0x01d40099fcd87c018969b0e8d4ab1633fb34763c", requested: 1, openApprovals: 1, unrestrictedApprovals: 1, rows: [{token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", decimals: 6, allowanceRaw: "11579208923731619542357098500868790785326998…", allowance: "11579208923731619542357098500868790785326998…", readable: true}]},
    async ({ chain, owner, spender, tokens }) => {
      const rows = await Promise.all(tokens.map(async (token) => {
        const [raw, dec, sym] = await Promise.all([
          callOrNull(chain, token, calldata(SEL.allowance, wordAddr(owner), wordAddr(spender))),
          callOrNull(chain, token, calldata(SEL.decimals)), callOrNull(chain, token, calldata(SEL.symbol)),
        ]);
        const d = toBig(dec); const v = toBig(raw);
        const use = d !== null && d <= 18n ? Number(d) : null;
        const unlimited = v !== null && v >= (2n ** 255n);
        return { token, symbol: decodeString(sym), decimals: use, allowanceRaw: v === null ? null : String(v),
          allowance: v === null || use === null ? null : fmtDec(v, use), readable: v !== null, unrestricted: unlimited };
      }));
      return { chain, owner, spender, requested: rows.length,
        openApprovals: rows.filter((r) => r.allowanceRaw && r.allowanceRaw !== "0").length,
        unrestrictedApprovals: rows.filter((r) => r.unrestricted).length, rows };
    }),
  cr("/chain/tx-status", "Did this transaction land", "One call for the pair every bot needs after sending: the transaction plus its receipt, with confirmations, block, status, gas used and revert reason together — instead of two paid reads and a race.",
    ["transaction", "receipt", "status", "confirmation", "chain"], [A.chain(), A.hash()],
    [["found", "boolean"], ["hash", "string"], ["pending", "boolean"], ["failed", "boolean"], ["blockNumber", "integer"], ["confirmations", "integer"], ["status", "integer"], ["from", "string"], ["to", "string"], ["valueWei", "string"], ["gasUsed", "string"], ["effectiveGasPriceGwei", "integer"], ["contractAddress", "string|null"], ["logCount", "integer"], ["revertReason", "string|null"]],
    {found: true, hash: "0xc7fb4c81e619eac18ad474c63157ef2edd6e81a425170d007692c45123457bef", pending: false, failed: false, blockNumber: 51745379, confirmations: 61, status: 1, from: "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001", to: "0x4200000000000000000000000000000000000015", valueWei: "0", gasUsed: "46230", effectiveGasPriceGwei: 0, contractAddress: null, logCount: 0, revertReason: null},
    async ({ chain, hash }) => {
      const [t, r, head] = await Promise.all([
        rpcCall(chain, "eth_getTransactionByHash", [hash]).catch(() => null),
        rpcCall(chain, "eth_getTransactionReceipt", [hash]).catch(() => null),
        headOf(chain),
      ]);
      if (!t && !r) return { found: false, hash, head, note: "no transaction and no receipt on this chain for this hash — it may be on a different chain, or still not broadcast" };
      const bn = r?.blockNumber ? Number(toBig(r.blockNumber)) : (t?.blockNumber ? Number(toBig(t.blockNumber)) : null);
      const failed = !!r && toBig(r.status) === 0n;
      // Only a settled failure costs the extra replay; a successful transaction is answered in one round.
      const revert = failed ? await revertReasonOf(chain, t, r) : { reason: null, source: null };
      return { found: true, hash, pending: !bn, failed,
        blockNumber: bn, confirmations: bn === null ? null : Math.max(0, head - bn),
        status: r ? Number(toBig(r.status) ?? 0n) : null, from: t?.from ?? r?.from ?? null, to: t?.to ?? r?.to ?? null,
        valueWei: t ? String(toBig(t.value) ?? 0n) : null, gasUsed: r ? String(toBig(r.gasUsed) ?? 0n) : null,
        effectiveGasPriceGwei: gweiOf(r?.effectiveGasPrice), contractAddress: r?.contractAddress ?? null,
        logCount: (r?.logs || []).length,
        revertReason: revert.reason, ...(revert.source ? { revertReasonSource: revert.source } : {}),
        ...(failed && !revert.reason ? { revertNote: "the transaction failed but no node we use would give a reason — most receipts do not carry one, and replaying the call needs archive state this public node may not keep" } : {}) };
    }),
  cr("/chain/tx-events", "Every event one transaction emitted", "The receipt's logs decoded to address, topic0, indexed values and data size — what a transaction actually did, straight from the node, which is the only honest answer when eth_getLogs by transaction hash is refused.",
    ["transaction", "logs", "events", "decode", "chain"], [A.chain(), A.hash()],
    [["found", "boolean"], ["hash", "string"], ["blockNumber", "integer"], ["status", "integer"], ["count", "integer"], ["truncated", "boolean"], ["rows", "array"]],
    {found: true, hash: "0xc7fb4c81e619eac18ad474c63157ef2edd6e81a425170d007692c45123457bef", blockNumber: 51745379, status: 1, count: 0, truncated: false, rows: []},
    async ({ chain, hash }) => {
      const r = await rpcCall(chain, "eth_getTransactionReceipt", [hash]).catch(() => null);
      if (!r) return { found: false, hash, note: "no receipt for this hash on this chain" };
      const logs = r.logs || [];
      return { found: true, hash, blockNumber: Number(toBig(r.blockNumber) ?? 0n), status: Number(toBig(r.status) ?? 0n),
        count: logs.length, truncated: logs.length > 200,
        rows: logs.slice(0, 200).map((l) => ({ logIndex: l.logIndex ? Number(toBig(l.logIndex)) : null, address: l.address,
          topic0: l.topics?.[0] ?? null, topics: l.topics || [],
          transferLike: l.topics?.[0] === TOPIC.Transfer && l.topics.length === 3
            ? { from: decodeAddress(l.topics[1]), to: decodeAddress(l.topics[2]), amountRaw: String(toBig(l.data) ?? 0n) } : null,
          approvalLike: l.topics?.[0] === TOPIC.Approval && l.topics.length === 3
            ? { owner: decodeAddress(l.topics[1]), spender: decodeAddress(l.topics[2]), amountRaw: String(toBig(l.data) ?? 0n) } : null,
          dataSize: typeof l.data === "string" ? (l.data.length - 2) / 2 : 0 })) };
    }),
];
// CHAIN_PATHS / CHAIN_BY_PATH and the PAID_DATA_PATHS fill-in live in the DATA_ROUTES block below,
// so a route cannot exist in one enumeration and be missing from another.

function parseChainArgs(route, query) {
  const out = {};
  for (const spec of route.args) {
    const raw = query?.[spec.name];
    if (raw === undefined || raw === "" || (typeof raw === "object" && !Array.isArray(raw))) {
      if (spec.required) bad(`query ?${spec.name}= is required (${String(spec.desc).slice(0, 90)})`);
      out[spec.name] = spec.default;
      continue;
    }
    out[spec.name] = COERCE[spec.kind](raw, spec);
  }
  route.preCheck?.(out);
  return out;
}

async function topMarkets(vs, limit) {
  const gecko = `${UP.coingeckoMarkets}?vs_currency=${vs}&order=market_cap_desc&per_page=${limit}&page=1&sparkline=false&price_change_percentage=1h%2C24h%2C7d`;
  try {
    const j = await cachedJson(`cg:${vs}:${limit}`, gecko, { headers: { accept: "application/json" } });
    return { source: "coingecko", rows: j.map((c) => ({
      rank: c.market_cap_rank, id: c.id, symbol: c.symbol, name: c.name,
      price: c.current_price, marketCap: c.market_cap, volume: c.total_volume,
      circulating: c.circulating_supply, change1h: c.price_change_percentage_1h_in_currency,
      change24h: c.price_change_percentage_24h_in_currency, change7d: c.price_change_percentage_7d_in_currency,
    })) };
  } catch (e) {
    // CoinGecko rate-limits datacenter IPs; fall back so a paid call never fails on it.
    const j = await cachedJson(`pap:${vs}:${limit}`, `${UP.paprikaTickers}?quotes=${vs}&limit=${Math.min(limit * 3, 200)}`, { headers: { accept: "application/json" } });
    // Paprika keys its quote block UPPERCASE (`{"quotes":{"USD":{"price":83122.5…}}}`, measured) while our
    // `vs` parameter arrives lowercase — `quotes.usd` from this fallback. That mismatch made EVERY row of
    // this branch null: rank, id, symbol and name came back filled, and price / marketCap / volume were
    // silently null, so a buyer paying for "top coins by market cap" got a hollow table sorted by a number
    // that wasn't there. The selftest caught it (`markets btc price > 0 :: null`). Look the quote up by
    // any case, and if the host still hands back nothing priced, refuse rather than sell the emptiness.
    const quote = (c) => (c?.quotes && (c.quotes[vs] || c.quotes[String(vs).toUpperCase()] || Object.values(c.quotes)[0])) || null;
    const rows = j.filter((c) => Number(c.rank) > 0).sort((a, b) => a.rank - b.rank).slice(0, limit).map((c) => {
      const q = quote(c) || {};
      return {
        rank: c.rank, id: c.id, symbol: c.symbol, name: c.name, price: q.price ?? null,
        marketCap: q.market_cap ?? null, volume: q.volume_24h ?? null,
        circulating: c.circulating_supply ?? c.total_supply ?? null, change1h: null,
        change24h: q.percent_change_24h ?? null, change7d: q.percent_change_7d ?? null,
      };
    });
    if (!rows.some((r) => Number(r.price) > 0)) throw new HttpError(502, `coinpaprika returned ${rows.length} rows with no price for ${vs} — refused rather than served empty`);
    return { source: "coingecko-fallback-coinpaprika", note: String(e?.message || e), rows };
  }
}

async function chainTvl(limit) {
  const j = await cachedJson("llama:chains", UP.llamaChains, { headers: { accept: "application/json" } });
  const rows = j.filter((c) => Number(c.tvl) > 0).sort((a, b) => b.tvl - a.tvl).slice(0, limit)
    .map((c) => ({ chain: c.name, chainId: c.chainId ?? null, tvl: Math.round(c.tvl), gasToken: c.tokenSymbol ?? null }));
  return { source: "defillama", total: j.length, rows };
}

async function stablecoinSnapshot(limit) {
  const j = await cachedJson("llama:stables", `${UP.llamaStables}?includePrices=false`, { headers: { accept: "application/json" } });
  const rows = (j?.peggedAssets || []).map((a) => ({
    name: a.name, symbol: a.symbol, pegType: a.peggedType || a.pegType || null,
    pegMechanism: a.pegMechanism || null, circulating: a.circulating?.peggedUSD ?? null,
    onChain: Object.keys(a.circulating?.byChainLatestTime || {}).length,
  })).filter((r) => Number(r.circulating) > 0).sort((a, b) => b.circulating - a.circulating).slice(0, limit);
  return { source: "defillama", note: "circulating is USD-pegged supply, not a redemption guarantee", rows };
}

// "What is heating up right now" — DexScreener paid boosts, enriched with one batched quote call
// so the response carries price and liquidity instead of just boost counts.
async function trendingBoosted(chain, limit) {
  const all = await cachedJson("boost:latest", UP.dexscreenerBoosts, { headers: { accept: "application/json" } });
  const scoped = chain ? all.filter((r) => r.chainId === chain) : all;
  const top = scoped.slice(0, limit);
  const byChain = new Map();
  for (const r of top) {
    if (!byChain.has(r.chainId)) byChain.set(r.chainId, []);
    byChain.get(r.chainId).push(r.tokenAddress);
  }
  const quotes = new Map();
  await Promise.all([...byChain].map(async ([cid, addrs]) => {
    try {
      const url = `https://api.dexscreener.com/tokens/v1/${encodeURIComponent(cid)}/${addrs.map((a) => encodeURIComponent(a)).join(",")}`;
      const pairs = await cachedJson(`boostq:${cid}:${addrs.join(",")}`, url, { headers: { accept: "application/json" } });
      for (const p of (Array.isArray(pairs) ? pairs : [])) {
        const k = `${p.chainId}:${(p.baseToken?.address || "").toLowerCase()}`;
        const cur = quotes.get(k);
        if (!cur || (p.liquidity?.usd || 0) > (cur.liquidityUsd || 0)) {
          quotes.set(k, { priceUsd: p.priceUsd, liquidityUsd: p.liquidity?.usd ?? null, volume24h: p.volume?.h24 ?? null, change24h: p.priceChange?.h24 ?? null, dex: p.dexId, pairUrl: p.url });
        }
      }
    } catch { /* boosts still reported without a quote */ }
  }));
  return { source: "dexscreener", note: "boosts are paid promotions by token projects, not an endorsement or a ranking of quality",
    count: top.length, rows: top.map((r) => ({
      chainId: r.chainId, tokenAddress: r.tokenAddress, totalAmount: r.totalAmount,
      latestTime: r.latestTime, description: typeof r.description === "string" ? r.description.slice(0, 140) : null,
      url: r.url, ...((quotes.get(`${r.chainId}:${(r.tokenAddress || "").toLowerCase()}`) || {})),
    })) };
}

async function gasPrices(chains) {
  const rows = [];
  for (const name of chains) {
    const url = RPC[name];
    const rpc = async (method, params) => {
      const j = await cachedJson(`rpc:${name}:${method}`, url, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      if (j?.error) throw new Error(`${name}: ${String(j.error.message || j.error).slice(0, 80)}`);
      return j.result;
    };
    const [gp, blk] = await Promise.all([rpc("eth_gasPrice", []), rpc("eth_getBlockByNumber", ["latest", false])]);
    const gwei = (hex) => Number(BigInt(hex || "0x0")) / 1e9;
    rows.push({
      chain: name, gasPriceGwei: +gwei(gp).toFixed(4), baseFeeGwei: +gwei(blk?.baseFeePerGas).toFixed(4),
      blockNumber: Number(BigInt(blk?.number || "0x0")),
      maxFeeGwei: blk?.nextBaseFee ? +gwei(blk.nextBaseFee).toFixed(4) : null,
    });
  }
  return { source: "public RPC", currency: TX_COST_CURRENCY, note: "gwei estimates from a public node; a simple transfer costs ~21000 gas", rows };
}

// ============================================================================================
// THE MARKET BAND — 64 venue endpoints, each its own priced resource.
//
// Why venues and not one more aggregator: GeckoTerminal and CoinGecko were both cut mid-build after
// measurement (.tmp-check/probe-market-round3-out.txt) — they return 429 to a shared residential IP
// after roughly 3-6 calls a minute, and a route that hands a buyer who already paid a 429 is a bug,
// not a limitation. Every host shipped below answered 200 through an 8-sequential + 8-parallel burst
// (.tmp-check/probe-market-round4-out.txt), which is what two concurrent agents on one $0.001 route
// actually looks like. Every enum value a route exposes (candle interval, chain name, timespan,
// pair spelling) was probed individually in rounds 6-7; the ones that came back empty or 400 —
// Kraken's interval=360, blockchain.info's timespan=1month, Bitfinex's /book, Deribit's option
// listing, Jupiter's retired /price/v2 — are not in this file.
//
// Three rules every route below obeys:
//  1. The host is a compile-time constant; the variable part is a path or query segment that goes
//     through an anchored regex in `A.*` before the payment gate. No caller can steer a request
//     off these hosts, so no route here is an SSRF primitive.
//  2. Venues that answer HTTP 200 with an error body (Kraken `error:[…]`, OKX `code!=="0"`, KuCoin
//     `code!=="200000"`, Gate/Polymarket 4xx, Hyperliquid 500 on an unknown coin) map to
//     `found:false` plus the venue's own reason — never to a fabricated number.
//  3. `mj()` remembers the last good payload per cache key, so a venue hiccup answers with data
//     marked `"stale": true` instead of billing $0.001 for an error page.
// ============================================================================================
const MK = {
  kraken: "https://api.kraken.com/0/public/",
  cbex: "https://api.exchange.coinbase.com",
  okx: "https://www.okx.com/api/v5",
  bitfinex: "https://api-pub.bitfinex.com/v2",
  gate: "https://api.gateio.ws/api/v4/spot",
  kucoin: "https://api.kucoin.com/api/v1",
  deribit: "https://www.deribit.com/api/v2/public",
  hyper: "https://api.hyperliquid.xyz/info",
  llama: "https://api.llama.fi",
  coins: "https://coins.llama.fi",
  mempool: "https://mempool.space/api",
  // Same software, different operator. Verified live from inside the production container on
  // 2026-09-28 while mempool.space timed out: `https://mempool.emzy.de/api/v1/fees/recommended` answered
  // 200 with the identical field set, so a fee/height/difficulty reading from it means the same thing.
  // It is a community instance, so it is used only as a fallback and the payload always names whichever
  // host actually answered (`source`), never a fixed "mempool.space".
  mempoolMirror: "https://mempool.emzy.de/api",
  // A third Bitcoin reader, and deliberately NOT a general mirror: it is Electrs, not mempool.space, so it
  // serves the two `/blocks/tip/*` paths and nothing else — measured from the production container
  // 2026-09-28: `/blocks/tip/height` 200 "969029" in 943ms and `/blocks/tip/hash` 200 with a real 64-hex
  // value under `accept: application/json`, while `/v1/fees/recommended` answered 404 "endpoint does not
  // exist". That is exactly the path the tip route needed, because at the same moment mempool.space timed
  // out (7s, aborted) and emzy answered 429 rate_limited on both tip paths, which is why
  // /market/btc-chain-tip was the one route still failing the handler battery. Path-gated below so no
  // route can silently claim a fee or hashrate reading came from here.
  blockstream: "https://blockstream.info/api",
  bci: "https://api.blockchain.info",
  fng: "https://api.alternative.me/fng/",
  poly: "https://gamma-api.polymarket.com",
  dex: "https://api.dexscreener.com",
  jup: "https://lite-api.jup.ag",
  scout: { base: "https://base.blockscout.com", ethereum: "https://eth.blockscout.com" },
};
// A `mr` route is identical to a `cr` route in every respect — same validator (`parseChainArgs`),
// same challenge, same gate, same MCP mirror — except it reads a venue instead of a chain node.
// `probe` carries the arguments the shipped instrument exercises this handler with.
const mr = (path, title, desc, tags, args, out, exampleOut, probe, run) =>
  ({ path, title, summary: `${title} (paid via x402)`, desc, tags, args, out, exampleOut, probe, run, marketRoute: true });

const lastGood = new Map();
// Venue liveness, kept because the x402 gate settles BEFORE a handler runs: a buyer who pays $0.001 for a
// reading whose vendor is down gets money taken and a 502 (measured 2026-09-28 — mempool.space stopped
// answering from this host and 7 /market/btc-* routes could only fail after settlement). A refusal that
// happens BEFORE the challenge is the only way to make that unchargeable, so failures are recorded here
// and the pre-gate middleware below consults them. Host → unix ms until which we believe it is dead.
// Two rules, both learned by measurement today (2026-09-28), keep this honest:
//  1. NEVER ping a venue base. `api.gateio.ws/api/v4/spot` times out while the path the route actually
//     reads (`/api/v4/spot/order_book?currency_pair=BTC_USDT`) answers 200 — a base ping would have marked
//     a healthy vendor dead and refused five sellable routes unpaid. Turning away money on a false signal
//     is worse than the paid-502 it prevents. Reachability probes therefore use a real path taken from the
//     route's own source (see venueReachUrls), and a host is marked down ONLY when the fetch THROWS
//     (DNS/connect/timeout). Any HTTP status, even 500, is a live server answering; vendor error semantics
//     are not our evidence for an outage.
//  2. The TTL must EXCEED the sweep period, or the guard blinks off between pings. The first draft had a
//     90s TTL against a 180s sweep and it showed up as "503 refusals: 0" on an instrument that had just
//     seen the 503 by hand. 5 minutes against a 2.5-minute sweep keeps coverage continuous, and any
//     successful read clears the marker immediately, so a recovered vendor is sellable within one sweep.
const VENUE_DOWN_TTL_MS = 300_000;
const venueDown = new Map();
const venueHostOf = (url) => { try { return new URL(url).host; } catch { return null; } };
const markVenueDown = (url) => {
  const h = venueHostOf(url);
  if (!h || venueDown.has(h)) return;
  venueDown.set(h, nowMs() + VENUE_DOWN_TTL_MS);
  console.log(`[venue] ${h} marked unreadable for ${VENUE_DOWN_TTL_MS / 1000}s — its routes refuse the challenge unpaid until a read succeeds`);
};
const markVenueUp = (url) => { const h = venueHostOf(url); if (h) { venueDown.delete(h); venueTolerated.delete(h); } };
const isVenueDown = (host) => {
  const until = venueDown.get(host);
  if (until === undefined) return false;
  if (until <= nowMs()) { venueDown.delete(host); return false; }
  return true;
};
// A tolerated read answers 4xx/5xx as DATA about the identifier the buyer asked for, so a single such
// answer is not proof of an outage: measured 2026-09-28, Bitfinex answers 500 for a pair that does not
// exist and Gate answers 400 for a malformed one. Blacklisting on the FIRST tolerated error would let one
// buyer's typo turn every route on that host into a 503 — the same false signal rule 1 above refuses to
// act on. So a tolerated failure only counts, and the host goes unreadable when it REPEATS inside a
// minute, which is what a rate limit or a broken vendor actually looks like (a correct-but-empty answer
// about a second bogus identifier cannot push the count up because 404/400 never count).
const VENUE_TOLERATED_WINDOW_MS = 60_000;
const venueTolerated = new Map();
const markVenueToleratedFail = (url, status) => {
  const h = venueHostOf(url);
  if (!h) return;
  const prev = venueTolerated.get(h);
  const n = (prev && prev.exp > nowMs() ? prev.n : 0) + 1;
  venueTolerated.set(h, { n, exp: nowMs() + VENUE_TOLERATED_WINDOW_MS });
  if (n >= 2) markVenueDown(url);
};
// A public JSON API that answers HTTP 200 with an HTML/XML page is not answering the question. This is
// not hypothetical: measured 2026-09-28, `/market/btc-chain-tip` threw "mempool.space returned no height"
// at 10.9s while the tip key held a page body — because the old code treated any 200 whose text failed
// `JSON.parse` as a bare value, memoized it, and served that page to every later buyer for the whole TTL
// (so one challenge page poisoned a paid route's cache instead of failing once). `jsonOrBare` keeps the
// bare-number behaviour mempool's tip endpoint genuinely needs; `isPageNotJson` is the new guard.
const jsonOrBare = (text) => { let v; try { v = JSON.parse(text); } catch { v = text.trim(); } return v; };
const isPageNotJson = (v) => typeof v === "string" && /^\s*(?:<\?xml|<!doctype\s+html|<html[\s>])|^\s*<head[\s>]/i.test(v);
// Per-host read budget. 12s was a blanket guess, and with three Bitcoin sources in series it became a
// 25s paid call (measured 2026-09-28 in the handler battery: 12s aborted primary + 9s aborted fallback +
// the third read). These three hosts answer in well under a second when healthy — 0.27s emzy fees, 0.94s
// blockstream tip, sub-second for every /market/btc-* row recorded this week — and every one of the
// 11-second samples was mempool.space hanging toward the timeout with no answer at all. 4s is ~4x the
// healthy ceiling; past it the value of waiting is lower than the value of the next source or of failing
// fast, and a buyer who is going to be served stale gets it seconds sooner.
const FAST_VENUES = new Set(["mempool.space", "mempool.emzy.de", "blockstream.info"]);
const readBudgetMs = (url) => (FAST_VENUES.has(venueHostOf(url)) ? 4_000 : 12_000);
// The Bitcoin source chain, in the order we are willing to believe it. Only the two `/blocks/tip/*` paths
// have a third source: blockstream is Electrs, and `/v1/fees/recommended` is a 404 there (measured), so no
// fee or hashrate reading can ever be attributed to it by mistake.
const BTC_TIP_PATH = /^\/blocks\/tip\/(height|hash)$/;
const mempoolFallbackUrls = (rel) => [MK.mempoolMirror + rel, ...(BTC_TIP_PATH.test(rel) ? [MK.blockstream + rel] : [])];
// Try the fallbacks and return a reading, or null when none of them produced one. Two rules here are the
// scar tissue of 2026-09-28 and must not be "simplified" away: a STATUS answer from a fallback host never
// blacklists that host (the mirror 429-rate-limited the tip paths while serving six other routes fine, and
// blacklisting it turned sellable routes into unpaid 503s), and a 200 whose body is a page is never cached.
async function mempoolFallbackRead(key, rel) {
  for (const mirrorUrl of mempoolFallbackUrls(rel)) {
    const mHost = venueHostOf(mirrorUrl);
    try {
      const mr = await fetch(mirrorUrl, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(readBudgetMs(mirrorUrl)) });
      const mt = await mr.text();
      if (mr.ok) {
        const mv = jsonOrBare(mt);
        if (isPageNotJson(mv)) {
          console.log(`[market] fallback ${mHost} answered 200 with a page, not JSON for ${key}; not used`);
          continue;
        }
        memo.set(key, { exp: nowMs() + MARKET_TTL, val: mv, host: mHost });
        lastGood.set(key, { val: mv, host: mHost });
        markVenueUp(mirrorUrl);
        console.log(`[market] mempool.space unreadable — served ${mHost} for ${key}`);
        return { d: mv, stale: false, host: mHost, viaMirror: true };
      }
      console.log(`[market] fallback ${mHost} answered ${mr.status} for ${key}; host not blacklisted on a status answer`);
    } catch (me) { markVenueDown(mirrorUrl); void me; }
  }
  return null;
}
async function mj(key, url, init, opt) {
  const hit = memo.get(key);
  // `host` travels with the cached value. Every `mr` route builds its payload through `mk(host, …)`, so a
  // hit that returned only the value answered with NO `source` key — and a cache hit is the common case
  // inside the TTL, so the second buyer of the same reading got an envelope missing the one field that
  // says who measured it. Found by the stub instrument, not by the live battery (which reads each route
  // exactly once, i.e. always cold).
  if (hit && hit.exp > nowMs()) return { d: hit.val, stale: false, host: hit.host };
  // Going straight to the fallbacks when the primary is ALREADY marked down is what turns the worst case
  // from 12s into ~2.5s: `/market/btc-chain-tip` makes two serial reads, and each one used to burn a full
  // 4s abort on a host that the reach sweep has been reporting dead all day. This deliberately does NOT
  // rewrite `url` and fall into the primary path — a fallback host reached that way would inherit the
  // primary's "429/5xx marks you down" rule, which is exactly the false blacklist the loop below forbids.
  const isMpPrimary = venueHostOf(url) === "mempool.space" && String(url).startsWith(MK.mempool);
  const mpRel = isMpPrimary ? String(url).slice(MK.mempool.length) : null;
  if (isMpPrimary && isVenueDown("mempool.space")) {
    const early = await mempoolFallbackRead(key, mpRel);
    if (early) return early;
    // Nothing available: fall through and give the primary its one honest attempt.
  }
  const t0 = Date.now();
  try {
    const r = await fetch(url, {
      ...(init || {}),
      headers: { accept: "application/json", ...(init?.headers || {}) },
      signal: AbortSignal.timeout(readBudgetMs(url)),
    });
    clockSample(t0, r);
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      const host = new URL(url).host;
      // `tolerate` is for venues that answer 4xx/5xx when the identifier is well-formed but simply is
      // not listed there (Bitfinex 500, Gate 400, Hyperliquid 500). Those are answers about the asset,
      // not failures of our route, so they must not become a 502 to a buyer who already paid.
      if (opt?.tolerate) {
        // A tolerated 4xx/5xx is still an answer about the identifier, so it is returned as data — but a
        // repeated 403/429/5xx from a REAL endpoint read means this vendor is not serving us right now, and
        // the pre-gate refusal should spare the NEXT buyer from paying into it. Counted, not acted on at
        // once (see markVenueToleratedFail). A 404 never blacklists: "no such package/repo" is a correct
        // answer, not an outage. (Synthetic base-URL pings never blacklist either; see the reach-sweep rules
        // above — this is a genuine read that failed.)
        if (r.status === 403 || r.status === 429 || r.status >= 500) markVenueToleratedFail(url, r.status);
        return { d: null, stale: false, missing: `${host} HTTP ${r.status}${body ? `: ${body.replace(/\s+/g, " ").slice(0, 150)}` : ""}` };
      }
      // A 5xx or 429 from the venue is the venue failing, not the question being unanswerable.
      if (r.status >= 500 || r.status === 429) markVenueDown(url);
      throw new HttpError(r.status === 404 ? 404 : r.status === 429 ? 429 : 502, `${host} HTTP ${r.status}`);
    }
    const text = await r.text();
    const val = jsonOrBare(text); // mempool's tip endpoint answers a bare number, so a non-JSON body is legal
    // …until it is a page. Two delivery paths, matching the `!r.ok` rules above rather than inventing a
    // third: a lookup route (tolerate) gets it as a `missing` answer it renders as found:false, because
    // turning "GitHub handed us a challenge page" into a 502 would charge a buyer for an HTTP redirect;
    // a reading route throws a plain Error, which lands in the same branch as an unreachable vendor —
    // host marked down, mirror tried, and a buyer refused BEFORE the challenge rather than charged.
    if (isPageNotJson(val)) {
      const h = venueHostOf(url) || "upstream";
      if (opt?.tolerate) {
        markVenueToleratedFail(url, r.status);
        return { d: null, stale: false, missing: `${h} HTTP ${r.status}: an HTML/XML page instead of JSON` };
      }
      throw new Error(`${h} answered HTTP ${r.status} with an HTML/XML page instead of JSON`);
    }
    memo.set(key, { exp: nowMs() + MARKET_TTL, val, host: venueHostOf(url) });
    lastGood.set(key, { val, host: venueHostOf(url) });
    markVenueUp(url);
    return { d: val, stale: false, host: venueHostOf(url) };
  } catch (e) {
    const s = lastGood.get(key);
    if (s !== undefined) {
      console.log(`[market] stale-answer ${new URL(url).host} for ${key}: ${String(e?.message || e).slice(0, 70)}`);
      // The host that supplied the stored reading, not the one that just failed — a buyer reading a stale
      // fee figure has to be able to see it came from mempool.space while blockstream was down.
      return { d: s.val, stale: true, host: s.host };
    }
    // No cached copy to serve, and the HTTP gate settles BEFORE the handler runs — so whatever escapes here
    // is what a buyer who has already paid receives. A raw `TypeError: fetch failed` (measured 2026-09-28,
    // when mempool.space stopped answering from this host and all 7 /market/btc-* routes threw it on a cold
    // cache after the container restart) is an unhandled 500 with a stack. Every other failure path in this
    // function answers with a shaped HttpError, so an unreachable venue must do the same: name the host and
    // the failure class, and say plainly that the reading is unavailable rather than served.
    if (!(e instanceof HttpError)) {
      let host = "upstream";
      try { host = new URL(url).host; } catch { /* keep the generic name */ }
      markVenueDown(url);
      // Same-API-family fallback: only for mempool.space, only when the primary did not give us a reading
      // (a thrown fetch, or a 200 whose body is a page rather than JSON), and only to an instance that
      // serves the identical path. If the mirror answers, the reading is real and `host` says who supplied it.
      if (isMpPrimary) {
        const fb = await mempoolFallbackRead(key, mpRel);
        if (fb) return fb;
      }
      // Three causes, each named honestly in the message the buyer (and the log) gets. The first draft of
      // the page-rejection above fell through to "connect/DNS failure", which would have blamed the network
      // for a vendor that was answering with a challenge page.
      const msg = String(e?.message || "");
      const kind = /HTML\/XML page/.test(msg) ? "answered a page instead of JSON"
        : (e?.name === "AbortError" || /timeout|aborted/i.test(msg) ? "timed out" : "connect/DNS failure");
      throw new HttpError(502, `${host} ${kind} and no cached copy of this reading exists — reported unavailable rather than answered`);
    }
    throw e;
  }
}
// A 404 from a lookup venue means "that instrument does not exist here". With no cached payload to
// fall back on, that is an answer, not a failure, so it must not become a 502 after settlement.
async function mjLookup(key, url, init, opt) {
  try { return await mj(key, url, init, opt); }
  catch (e) {
    if (e instanceof HttpError && e.status === 404) return { d: null, stale: false, missing: true };
    throw e;
  }
}
const MARKET_TTL = Number(process.env.X402_MARKET_TTL_MS || CACHE_MS);
const kv = (o) => (o && typeof o === "object" && !Array.isArray(o) ? o[Object.keys(o)[0]] : o);
const mk = (source, out, stale, note) => ({
  source, ...out,
  ...(note !== undefined && out.note === undefined ? { note } : {}),
  ...(stale ? { stale: true } : {}),
});
const nf = (x) => (x === undefined || x === null || x === "" ? null : Number(x));
// Polymarket's gamma API encodes its list fields as JSON *strings* (`"[\"Yes\", \"No\"]"`, measured on
// /markets/4464920). Handing a buyer a string where the schema says array is a broken document, so
// decode here — and answer null rather than throwing when the venue sends something unparseable.
const jsonArr = (x) => {
  if (Array.isArray(x)) return x;
  if (typeof x !== "string" || !x.trim().startsWith("[")) return null;
  try { const v = JSON.parse(x); return Array.isArray(v) ? v : null; } catch { return null; }
};
// Venues do not agree on OHLCV column order. Each mapping here is read off the measured row in
// .tmp-check/probe-market-round{4,6,7}-out.txt, and every series is re-emitted oldest-first with at
// most `limit` rows, so one contract holds across fifteen upstreams. Prices stay strings: a venue
// that reports 84320.60 must not arrive back as 84320.6.
const candle = (row, order, divisor = 1000) => {
  // Guarded because a venue that hands back a wrapped or short row must not turn a paid call into a
  // 502: `new Date(NaN).toISOString()` throws RangeError, which surfaced as our own server error.
  const raw = Number(Array.isArray(row) ? row[0] : NaN);
  const sec = Number.isFinite(raw) && raw > 0 ? Math.round(raw / divisor) : null;
  return { timeSec: sec, iso: sec === null ? null : new Date(sec * 1000).toISOString(),
    ...Object.fromEntries(order.map((k, i) => [k, row[i + 1] === undefined ? null : String(row[i + 1])])) };
};
// Drop rows without a usable timestamp before sorting: `timeSec: null` sorts as 0 and would pin a
// junk row onto the oldest end of every answer.
const chron = (rows, limit) => rows.filter((r) => Number.isFinite(r?.timeSec)).sort((a, b) => a.timeSec - b.timeSec).slice(-Math.max(1, limit));
// Bitfinex answers `/candles/.../last` with ONE flat row and ignores limit+sort (measured), while
// `hist?sort=1&limit=N` answers the OLDEST N candles from 2013. Only the rows-of-arrays form is a
// series, so anything else has to be wrapped or discarded rather than mapped over.
const candleRows = (d) => (Array.isArray(d) ? (d.length && !Array.isArray(d[0]) && typeof d[0] === "number" ? [d] : d.filter((r) => Array.isArray(r))) : []);
const narg = (v, dflt) => { const x = Number(v); return Number.isFinite(x) && x > 0 ? x : dflt; };
// How many ms of history a candle route may ask for, per interval — the bound exists because
// Hyperliquid answers 1m candles for two days with 2881 rows and 390 KB (measured, round 7).
const WINDOW_MS = { "1m": 3 * 3600e3, "5m": 12 * 3600e3, "15m": 3 * 86400e3, "30m": 5 * 86400e3, "1h": 10 * 86400e3, "1H": 10 * 86400e3, "2h": 20 * 86400e3, "4h": 45 * 86400e3, "4H": 45 * 86400e3, "12h": 90 * 86400e3, "1d": 365 * 86400e3, "1D": 365 * 86400e3, "1w": 3 * 86400e5, "1W": 3 * 86400e5, "1week": 3 * 86400e5, "1day": 365 * 86400e3, "1hour": 10 * 86400e3, "1min": 6 * 3600e3, "15min": 3 * 86400e3, "5min": 12 * 3600e3, "30min": 5 * 86400e3, "4hour": 45 * 86400e3, "3600": 30 * 86400e3, "86400": 3 * 86400e5 };
const EVM_MINT_NOTE = "quote is what the venue's own tape says, not a cross-venue consensus price";

// ---- Kraken (US/EU spot, fiat-quoted) ------------------------------------------------------
const KR_PAIR = A.text("pair", /^[A-Za-z0-9]{3,14}$/, { example: "XBTUSD", desc: "Kraken pair as the venue spells it: XBTUSD, ETHUSD, SOLUSD" });
const MK_KRAKEN = [
  mr("/market/kraken-ticker", "Kraken spot ticker", "Last trade, best bid and ask with size, 24h volume, VWAP and 24h high/low for one Kraken spot pair, straight from the venue's own tape.",
    ["market", "spot", "ticker", "kraken", "price"],
    [KR_PAIR],
    [["found", "boolean"], ["pair", "string"], ["last", "string"], ["bid", "string"], ["ask", "string"], ["bidSize", "string"], ["askSize", "string"], ["volume24h", "string"], ["vwap24h", "string"], ["high24h", "string"], ["low24h", "string"], ["trades24h", "integer"]],
    {found: true, pair: "XXBTZUSD", last: "84104.10000", bid: "84104.20000", ask: "84104.30000", bidSize: "1", askSize: "1", volume24h: "3293.04250283", vwap24h: "84097.64908", high24h: "84914.80000", low24h: "82832.30000", trades24h: 135678},
    { pair: "XBTUSD" },
    async ({ pair }) => {
      const { d, stale } = await mj(`kr:tk:${pair}`, `${MK.kraken}Ticker?pair=${encodeURIComponent(pair)}`);
      if (d?.error?.length) return mk("kraken", { found: false, reason: d.error.join(",") }, stale);
      const key = Object.keys(d.result || {})[0], t = d.result[key] || {};
      return mk("kraken", { found: true, pair: key, last: t.c?.[0] ?? null, bid: t.b?.[0] ?? null, ask: t.a?.[0] ?? null,
        bidSize: t.b?.[1] ?? null, askSize: t.a?.[1] ?? null, volume24h: t.v?.[1] ?? null, vwap24h: t.p?.[1] ?? null,
        high24h: t.h?.[1] ?? null, low24h: t.l?.[1] ?? null, trades24h: nf(t.t?.[1]) }, stale, EVM_MINT_NOTE);
    }),
  mr("/market/kraken-ohlc", "Kraken OHLC candles", "OHLCV candles for one Kraken pair: open, high, low, close, volume and trade count per bucket, oldest first. Only the intervals the venue actually serves are offered.",
    ["market", "candles", "ohlc", "kraken", "chart"],
    [KR_PAIR, A.oneOf("interval", ["15", "60", "240", "1440"], { desc: "candle width in minutes (360 is rejected by Kraken; 30 and 720 are unmeasured and therefore not offered)" }),
     A.num("limit", { max: 720, default: 48n, desc: "how many candles (max 720)" })],
    [["found", "boolean"], ["pair", "string"], ["interval", "integer"], ["count", "integer"], ["rows", "array"]],
    {found: true, pair: "XXBTZUSD", interval: 60, count: 721, rows: [{timeSec: 1790308800, iso: "2026-09-25T04:00:00.000Z", open: "84211.2", high: "84278.7", low: "84042.1", close: "84192.7"}]},
    { pair: "XBTUSD", interval: "60", limit: "3" },
    async ({ pair, interval, limit }) => {
      const { d, stale } = await mj(`kr:ohlc:${pair}:${interval}`, `${MK.kraken}OHLC?pair=${encodeURIComponent(pair)}&interval=${interval}`);
      if (d?.error?.length) return mk("kraken", { found: false, reason: d.error.join(",") }, stale);
      const raw = kv(d.result) || [];
      return mk("kraken", { found: raw.length > 0, pair: Object.keys(d.result || {})[0], interval: nf(interval),
        count: raw.length, rows: chron(raw.map((r) => candle(r, ["open", "high", "low", "close", "vwap", "volume", "trades"], 1)), narg(limit, 48)) }, stale);
    }),
  mr("/market/kraken-depth", "Kraken order book", "Top of the Kraken book for one pair: resting bid and ask levels with size and price-count, plus the derived spread and mid.",
    ["market", "orderbook", "depth", "kraken", "liquidity"],
    [KR_PAIR, A.num("count", { max: 50, default: 10n, desc: "levels per side (max 50)" })],
    [["found", "boolean"], ["pair", "string"], ["bids", "array"], ["asks", "array"], ["bestBid", "string"], ["bestAsk", "string"], ["spreadPct", "number"]],
    {found: true, pair: "XXBTZUSD", bids: [["84104.20000"]], asks: [["84104.30000"]], bestBid: "84104.20000", bestAsk: "84104.30000", spreadPct: 0.00000119},
    { pair: "XBTUSD", count: "5" },
    async ({ pair, count }) => {
      const { d, stale } = await mj(`kr:dp:${pair}:${count}`, `${MK.kraken}Depth?pair=${encodeURIComponent(pair)}&count=${narg(count, 10)}`);
      if (d?.error?.length) return mk("kraken", { found: false, reason: d.error.join(",") }, stale);
      const key = Object.keys(d.result || {})[0], b = d.result[key] || {};
      const level = (a) => (a || []).map((r) => [r[0], r[1], nf(r[2])]);
      const bb = b.bids?.[0]?.[0], ba = b.asks?.[0]?.[0];
      return mk("kraken", { found: true, pair: key, bids: level(b.bids), asks: level(b.asks), bestBid: bb ?? null, bestAsk: ba ?? null,
        spreadPct: bb && ba ? +((Number(ba) - Number(bb)) / Number(bb)).toFixed(8) : null }, stale);
    }),
  mr("/market/kraken-trades", "Kraken recent trades", "The last trades printed on a Kraken pair, each with price, size, side and exchange timestamp — tape activity, not a summary.",
    ["market", "trades", "tape", "kraken", "flow"],
    [KR_PAIR, A.num("limit", { max: 200, default: 25n, desc: "trades to return (max 200)" })],
    [["found", "boolean"], ["pair", "string"], ["count", "integer"], ["trades", "array"]],
    {found: true, pair: "XXBTZUSD", count: 5, trades: [{price: "84104.10000", size: "0.00193641", side: "sell", timeSec: 1790317126.3303254, iso: "2026-09-25T06:18:46.330Z", tradeId: 109034930}]},
    { pair: "XBTUSD", limit: "5" },
    async ({ pair, limit }) => {
      const { d, stale } = await mj(`kr:tr:${pair}`, `${MK.kraken}Trades?pair=${encodeURIComponent(pair)}`);
      if (d?.error?.length) return mk("kraken", { found: false, reason: d.error.join(",") }, stale);
      const key = Object.keys(d.result || {})[0];
      const rows = ((d.result[key] || []).slice(-(narg(limit, 25)))).map((t) => ({
        price: t[0], size: t[1], side: t[3] === "b" ? "buy" : "sell", timeSec: nf(t[2]), iso: new Date(Math.round(Number(t[2]) * 1000)).toISOString(), tradeId: t[6] }));
      return mk("kraken", { found: rows.length > 0, pair: key, count: rows.length, trades: rows.reverse() }, stale);
    }),
  mr("/market/kraken-spread", "Kraken bid/ask spread history", "Quoted spread samples for a Kraken pair with the mean spread in basis points — how expensive it is to cross that venue right now.",
    ["market", "spread", "cost", "kraken", "liquidity"],
    [KR_PAIR, A.num("limit", { max: 500, default: 60n, desc: "spread samples (max 500)" })],
    [["found", "boolean"], ["pair", "string"], ["samples", "array"], ["meanSpreadBps", "number"]],
    {found: true, pair: "XXBTZUSD", samples: [{timeSec: 1790317119, bid: "84104.40000", ask: "84104.50000", spreadBps: 0.012}], meanSpreadBps: 0.25},
    { pair: "XBTUSD", limit: "5" },
    async ({ pair, limit }) => {
      const { d, stale } = await mj(`kr:sp:${pair}`, `${MK.kraken}Spread?pair=${encodeURIComponent(pair)}`);
      if (d?.error?.length) return mk("kraken", { found: false, reason: d.error.join(",") }, stale);
      const key = Object.keys(d.result || {})[0];
      const all = (d.result[key] || []).map((s) => {
        const bid = Number(s[1]), ask = Number(s[2]);
        return { timeSec: nf(s[0]), bid: s[1], ask: s[2], spreadBps: bid > 0 ? +(((ask - bid) / bid) * 1e4).toFixed(3) : null };
      });
      const mid = all.filter((r) => Number.isFinite(r.spreadBps)).reduce((a, r) => a + r.spreadBps, 0) / (all.length || 1);
      return mk("kraken", { found: all.length > 0, pair: key, samples: all.slice(-(narg(limit, 60))), meanSpreadBps: +mid.toFixed(3) }, stale);
    }),
  mr("/market/kraken-pair-spec", "Kraken pair specification", "How Kraken itself defines a pair: base and quote, decimal precision, order size limits, the public leverage ladder and the first two fee tiers.",
    ["market", "metadata", "fees", "kraken", "pair"],
    [A.text("pair", /^[A-Za-z0-9]{3,16}$/, { example: "XXBTZUSD", desc: "Kraken pair key as stored by the venue (XXBTZUSD)" })],
    [["found", "boolean"], ["pair", "string"], ["altname", "string"], ["wsname", "string"], ["base", "string"], ["quote", "string"], ["baseClass", "string"], ["quoteClass", "string"], ["lot", "string"], ["status", "string"], ["pairDecimals", "integer"], ["lotDecimals", "integer"], ["lotMultiplier", "integer"], ["costDecimals", "integer"], ["tickSize", "string"], ["orderMin", "string"], ["costMin", "string"], ["leverageBuy", "array"], ["leverageSell", "array"], ["longPositionLimit", "integer"], ["shortPositionLimit", "integer"], ["marginCall", "integer"], ["marginStop", "integer"]],
    {found: true, pair: "XXBTZUSD", altname: "XBTUSD", wsname: "XBT/USD", base: "XXBT", quote: "ZUSD", baseClass: "currency", quoteClass: "currency", lot: "unit", status: "online", pairDecimals: 1, lotDecimals: 8, lotMultiplier: 1, costDecimals: 5, tickSize: "0.1", orderMin: "0.00005", costMin: "0.5", leverageBuy: [2], leverageSell: [2], longPositionLimit: 350, shortPositionLimit: 250, marginCall: 80, marginStop: 40},
    { pair: "XXBTZUSD" },
    async ({ pair }) => {
      const { d, stale } = await mj(`kr:ap:${pair}`, `${MK.kraken}AssetPairs?pair=${encodeURIComponent(pair)}`);
      if (d?.error?.length) return mk("kraken", { found: false, reason: d.error.join(",") }, stale);
      const key = Object.keys(d.result || {})[0], p = d.result[key];
      if (!p) return mk("kraken", { found: false, reason: "pair not listed" }, stale);
      // Every key below is read off .tmp-check/kraken-pair-raw.txt. The fee tiers and `margin_enabled`
      // this route used to publish are gone on measurement, not by taste: the unauthenticated endpoint
      // answers `fees: []`, `fees_maker: []` and omits margin_enabled for every pair tried
      // (XXBTZUSD, ETHUSD, DOTUSD), so no caller could ever receive them.
      return mk("kraken", { found: true, pair: key, altname: p.altname, wsname: p.wsname, base: p.base, quote: p.quote,
        baseClass: p.aclass_base, quoteClass: p.aclass_quote, lot: p.lot ?? null, status: p.status ?? null,
        pairDecimals: nf(p.pair_decimals), lotDecimals: nf(p.lot_decimals), lotMultiplier: nf(p.lot_multiplier),
        costDecimals: nf(p.cost_decimals), tickSize: p.tick_size ?? null,
        orderMin: p.ordermin ?? null, costMin: p.costmin ?? null,
        leverageBuy: Array.isArray(p.leverage_buy) ? p.leverage_buy : [],
        leverageSell: Array.isArray(p.leverage_sell) ? p.leverage_sell : [],
        longPositionLimit: nf(p.long_position_limit), shortPositionLimit: nf(p.short_position_limit),
        marginCall: nf(p.margin_call), marginStop: nf(p.margin_stop) }, stale);
    }),
];

// ---- Coinbase Exchange (USD-licensed venue) -------------------------------------------------
const CB_PRODUCT = A.text("product", /^[A-Za-z0-9]{2,13}-[A-Za-z0-9]{2,13}$/, { example: "BTC-USD", desc: "Coinbase Exchange product id, BASE-QUOTE (BTC-USD, ETH-USD, SOL-USD)" });
const MK_CBEX = [
  mr("/market/cbex-ticker", "Coinbase Exchange ticker", "Last trade, top of book, 24h volume and the exchange's own clock for one Coinbase product.",
    ["market", "spot", "ticker", "coinbase", "price"],
    [CB_PRODUCT],
    [["found", "boolean"], ["product", "string"], ["price", "string"], ["bid", "string"], ["ask", "string"], ["size", "string"], ["volume", "string"], ["tradeId", "integer"], ["time", "string"]],
    {found: true, product: "BTC-USD", price: "84104.23", bid: "84104.23", ask: "84104.24", size: "0.00000009", volume: "7063.24816945", tradeId: 1098215708, time: "2026-09-25T06:18:50.288358365Z"},
    { product: "BTC-USD" },
    async ({ product }) => {
      const { d, stale } = await mjLookup(`cb:tk:${product}`, `${MK.cbex}/products/${encodeURIComponent(product)}/ticker`);
      if (d === null) return mk("coinbase-exchange", { found: false, product, reason: "no such product on this venue" }, stale);
      return mk("coinbase-exchange", { found: true, product, price: d.price ?? null, bid: d.bid ?? null, ask: d.ask ?? null,
        size: d.size ?? null, volume: d.volume ?? null, tradeId: nf(d.trade_id), time: d.time ?? null }, stale, EVM_MINT_NOTE);
    }),
  mr("/market/cbex-stats", "Coinbase 24h and 30d stats", "Open, high, low, last and both the 24h and 30-day traded volume for a Coinbase product — what a session actually cost and moved.",
    ["market", "volume", "stats", "coinbase", "range"],
    [CB_PRODUCT],
    [["found", "boolean"], ["product", "string"], ["open", "string"], ["high", "string"], ["low", "string"], ["last", "string"], ["volume24h", "string"], ["volume30d", "string"], ["change24hPct", "number"]],
    {found: true, product: "BTC-USD", open: "84095.61", high: "84929.78", low: "82708.96", last: "84086.85", volume24h: "7063.24816945", volume30d: "189170.86980943", change24hPct: -0.0104},
    { product: "BTC-USD" },
    async ({ product }) => {
      const { d, stale } = await mjLookup(`cb:st:${product}`, `${MK.cbex}/products/${encodeURIComponent(product)}/stats`);
      if (d === null) return mk("coinbase-exchange", { found: false, product, reason: "no such product on this venue" }, stale);
      const chg = Number(d.open) > 0 && d.last !== undefined ? +(((Number(d.last) - Number(d.open)) / Number(d.open)) * 100).toFixed(4) : null;
      return mk("coinbase-exchange", { found: true, product, open: d.open ?? null, high: d.high ?? null, low: d.low ?? null,
        last: d.last ?? null, volume24h: d.volume ?? null, volume30d: d.volume_30day ?? null, change24hPct: chg }, stale);
    }),
  mr("/market/cbex-trades", "Coinbase recent trades", "Public fill feed for a Coinbase product: price, size, side, timestamp and trade id, newest first.",
    ["market", "trades", "tape", "coinbase", "flow"],
    [CB_PRODUCT, A.num("limit", { max: 200, default: 25n, desc: "trades to return (max 200)" })],
    [["found", "boolean"], ["product", "string"], ["count", "integer"], ["trades", "array"]],
    {found: true, product: "BTC-USD", count: 3, trades: [{tradeId: 1098215708, side: "buy", price: "84104.23000000", size: "0.00000009", time: "2026-09-25T06:18:50.288358Z"}]},
    { product: "BTC-USD", limit: "3" },
    async ({ product, limit }) => {
      const { d, stale } = await mjLookup(`cb:tr:${product}:${limit}`, `${MK.cbex}/products/${encodeURIComponent(product)}/trades?limit=${narg(limit, 25)}`);
      if (d === null) return mk("coinbase-exchange", { found: false, product, reason: "no such product on this venue" }, stale);
      const rows = (Array.isArray(d) ? d : []).map((t) => ({ tradeId: nf(t.trade_id), side: t.side, price: t.price, size: t.size, time: t.time }));
      return mk("coinbase-exchange", { found: rows.length > 0, product, count: rows.length, trades: rows }, stale);
    }),
  mr("/market/cbex-candles", "Coinbase OHLC candles", "Candles from Coinbase Exchange for the granularities its API serves (1m to 1d), oldest first, with volume per bucket.",
    ["market", "candles", "ohlc", "coinbase", "chart"],
    [CB_PRODUCT, A.oneOf("granularity", ["60", "300", "900", "3600", "21600", "86400"], { desc: "candle width in seconds" }),
     A.num("limit", { max: 350, default: 48n, desc: "candles to return (max 350, the venue's own page size)" })],
    [["found", "boolean"], ["product", "string"], ["granularity", "integer"], ["count", "integer"], ["rows", "array"]],
    {found: true, product: "ETH-USD", granularity: 86400, count: 2, rows: [{timeSec: 1790208000, iso: "2026-09-24T00:00:00.000Z", low: "2626.94", high: "2706.26", open: "2683.87", close: "2687.28"}]},
    { product: "ETH-USD", granularity: "86400", limit: "2" },
    async ({ product, granularity, limit }) => {
      const { d, stale } = await mjLookup(`cb:cd:${product}:${granularity}`, `${MK.cbex}/products/${encodeURIComponent(product)}/candles?granularity=${granularity}`);
      if (d === null) return mk("coinbase-exchange", { found: false, product, reason: "no such product on this venue" }, stale);
      const rows = chron((Array.isArray(d) ? d : []).map((r) => candle(r, ["low", "high", "open", "close", "volume"], 1)), narg(limit, 48));
      return mk("coinbase-exchange", { found: rows.length > 0, product, granularity: nf(granularity), count: rows.length, rows }, stale);
    }),
  mr("/market/cbex-best-quote", "Coinbase best bid and ask", "Level-1 book for a Coinbase product: the single best bid, the single best ask, their sizes and the book sequence number.",
    ["market", "orderbook", "spread", "coinbase", "liquidity"],
    [CB_PRODUCT],
    [["found", "boolean"], ["product", "string"], ["bestBid", "string"], ["bidSize", "string"], ["bestAsk", "string"], ["askSize", "string"], ["spread", "number"], ["sequence", "integer"], ["auctionMode", "boolean"], ["time", "string"]],
    {found: true, product: "BTC-USD", bestBid: "84104.23", bidSize: "0.11284358", bestAsk: "84104.24", askSize: "0.07180698", spread: 0.01, sequence: 136743492611, auctionMode: false, time: "2026-09-25T06:18:49.386842377Z"},
    { product: "BTC-USD" },
    async ({ product }) => {
      const { d, stale } = await mjLookup(`cb:b1:${product}`, `${MK.cbex}/products/${encodeURIComponent(product)}/book?level=1`);
      if (d === null) return mk("coinbase-exchange", { found: false, product, reason: "no such product on this venue" }, stale);
      const bid = d.bids?.[0], ask = d.asks?.[0];
      return mk("coinbase-exchange", { found: true, product, bestBid: bid?.[0] ?? null, bidSize: bid?.[1] ?? null,
        bestAsk: ask?.[0] ?? null, askSize: ask?.[1] ?? null, spread: bid && ask ? +(Number(ask[0]) - Number(bid[0])).toFixed(8) : null,
        sequence: nf(d.sequence), auctionMode: d.auction_mode ?? null, time: d.time ?? null }, stale);
    }),
  mr("/market/cbex-product-spec", "Coinbase product specification", "The venue's own rules for one product: tick and lot size, minimum order, whether it is margin/post-only/limit-only, and whether trading is enabled.",
    ["market", "metadata", "fees", "coinbase", "pair"],
    [CB_PRODUCT],
    [["found", "boolean"], ["id", "string"], ["base", "string"], ["quote", "string"], ["display", "string"], ["quoteIncrement", "string"], ["baseIncrement", "string"], ["minMarketFunds", "string"], ["maxSlippagePct", "string"], ["highBidLimitPct", "string"], ["status", "string"], ["statusMessage", "string"], ["tradingDisabled", "boolean"], ["cancelOnly", "boolean"], ["limitOnly", "boolean"], ["postOnly", "boolean"], ["auctionMode", "boolean"], ["marginEnabled", "boolean"], ["fxStablecoin", "boolean"]],
    {found: true, id: "BTC-USD", base: "BTC", quote: "USD", display: "BTC-USD", quoteIncrement: "0.01", baseIncrement: "0.00000001", minMarketFunds: "1", maxSlippagePct: "0.02000000", highBidLimitPct: "", status: "online", statusMessage: "", tradingDisabled: false, cancelOnly: false, limitOnly: false, postOnly: false, auctionMode: false, marginEnabled: false, fxStablecoin: false},
    { product: "BTC-USD" },
    async ({ product }) => {
      const { d, stale } = await mjLookup(`cb:pr:${product}`, `${MK.cbex}/products/${encodeURIComponent(product)}`);
      if (d === null) return mk("coinbase-exchange", { found: false, product, reason: "no such product on this venue" }, stale);
      // Coinbase's product record has 18 keys and `max_market_funds` is not one of them (measured on
      // BTC-USD, ETH-USD, SOL-USD, BTC-USDC — see .tmp-check/raw-key-dump.txt). The route used to
      // publish that field anyway and always answer null; these are the limits the venue really sends.
      return mk("coinbase-exchange", { found: true, id: d.id, base: d.base_currency, quote: d.quote_currency, display: d.display_name,
        quoteIncrement: d.quote_increment, baseIncrement: d.base_increment, minMarketFunds: d.min_market_funds,
        maxSlippagePct: d.max_slippage_percentage ?? null, highBidLimitPct: d.high_bid_limit_percentage ?? null,
        status: d.status, statusMessage: d.status_message ?? null, tradingDisabled: d.trading_disabled ?? null,
        cancelOnly: d.cancel_only ?? null, limitOnly: d.limit_only ?? null, postOnly: d.post_only ?? null,
        auctionMode: d.auction_mode ?? null,
        marginEnabled: d.margin_enabled ?? null, fxStablecoin: d.fx_stablecoin ?? null }, stale);
    }),
  mr("/market/cbex-clock", "Coinbase exchange clock", "The venue's own server time plus the offset against this server — the check that stops a signed order being rejected for clock drift.",
    ["market", "time", "clock", "coinbase", "latency"],
    [],
    [["iso", "string"], ["epoch", "number"], ["skewMs", "integer"], ["roundTripMs", "integer"]],
    {iso: "2026-09-25T06:18:52.355Z", epoch: 1790317132.355, skewMs: -97, roundTripMs: 287},
    {},
    async () => {
      const t0 = Date.now();
      const { d, stale } = await mj("cb:time", `${MK.cbex}/time`);
      const rtt = Date.now() - t0;
      const remote = Number(d?.epoch) * 1000;
      return mk("coinbase-exchange", { iso: d?.iso ?? null, epoch: nf(d?.epoch), skewMs: Number.isFinite(remote) ? Math.round(remote - (nowMs() + rtt / 2)) : null, roundTripMs: rtt }, stale,
        "skewMs is venue time minus the clock this service publishes its answers with (host clock plus the measured correction); anything over a second here is a real clock problem on this server");
    }),
];

// ---- OKX (global spot + swaps) ---------------------------------------------------------------
const OK_INST = A.text("instId", /^[A-Za-z0-9]{2,10}(-[A-Za-z0-9]{2,9}){1,2}$/, { example: "BTC-USDT", desc: "OKX instrument id, BASE-QUOTE (BTC-USDT, ETH-USDT-SWAP)" });
const okxBad = (d) => (d && String(d.code) !== "0" ? `okx code ${d.code}: ${String(d.msg || "").slice(0, 90)}` : null);
const MK_OKX = [
  mr("/market/okx-ticker", "OKX spot ticker", "Last, bid, ask, 24h open/high/low and both base and quote volume for one OKX instrument.",
    ["market", "spot", "ticker", "okx", "price"],
    [OK_INST],
    [["found", "boolean"], ["instId", "string"], ["instType", "string"], ["last", "string"], ["lastSz", "string"], ["bidPx", "string"], ["bidSz", "string"], ["askPx", "string"], ["askSz", "string"], ["open24h", "string"], ["high24h", "string"], ["low24h", "string"], ["volume24h", "string"], ["quoteVolume24h", "string"], ["sodUtc0", "string"], ["sodUtc8", "string"], ["venueTsMs", "integer"]],
    {found: true, instId: "BTC-USDT", instType: "SPOT", last: "84122.6", lastSz: "0.00958117", bidPx: "84122.5", bidSz: "0.31968375", askPx: "84122.6", askSz: "0.43477071", open24h: "84197.2", high24h: "84944.4", low24h: "82874.5", volume24h: "6600.53096902", quoteVolume24h: "554837295.019642333", sodUtc0: "84409.9", sodUtc8: "84419.6", venueTsMs: 1790317132070},
    { instId: "BTC-USDT" },
    async ({ instId }) => {
      const { d, stale } = await mj(`ok:tk:${instId}`, `${MK.okx}/market/ticker?instId=${encodeURIComponent(instId)}`);
      const bad = okxBad(d);
      if (bad) return mk("okx", { found: false, reason: bad }, stale);
      const t = d?.data?.[0] || {};
      // An explicit pick-list rather than `...t`: OKX adds fields to its ticker as it ships features,
      // and a payload that grows keys the published schema never promised is a lie to the buyer who
      // already paid. `venueTsMs` is named apart because the envelope stamps its own ISO `ts`.
      return mk("okx", { found: true, instId: t.instId ?? null, instType: t.instType ?? null,
        last: t.last ?? null, lastSz: t.lastSz ?? null, bidPx: t.bidPx ?? null, bidSz: t.bidSz ?? null,
        askPx: t.askPx ?? null, askSz: t.askSz ?? null, open24h: t.open24h ?? null, high24h: t.high24h ?? null,
        low24h: t.low24h ?? null, volume24h: t.vol24h ?? null, quoteVolume24h: t.volCcy24h ?? null,
        sodUtc0: t.sodUtc0 ?? null, sodUtc8: t.sodUtc8 ?? null, venueTsMs: nf(t.ts) }, stale, EVM_MINT_NOTE);
    }),
  mr("/market/okx-candles", "OKX OHLC candles", "Mark, base and quote volume per bucket for an OKX instrument, oldest first, across the bar widths the venue serves.",
    ["market", "candles", "ohlc", "okx", "chart"],
    [OK_INST, A.oneOf("bar", ["1m", "15m", "1H", "4H", "1D", "1W"], { desc: "OKX bar width" }), A.num("limit", { max: 300, default: 48n, desc: "candles (max 300)" })],
    [["found", "boolean"], ["instId", "string"], ["bar", "string"], ["count", "integer"], ["rows", "array"]],
    {found: true, instId: "BTC-USDT", bar: "1D", count: 2, rows: [{timeSec: 1790179200, iso: "2026-09-23T16:00:00.000Z", open: "84000.1", high: "84944.4", low: "82874.5", close: "84419.6"}]},
    { instId: "BTC-USDT", bar: "1D", limit: "2" },
    async ({ instId, bar, limit }) => {
      const { d, stale } = await mj(`ok:cd:${instId}:${bar}:${limit}`, `${MK.okx}/market/candles?instId=${encodeURIComponent(instId)}&bar=${encodeURIComponent(bar)}&limit=${narg(limit, 48)}`);
      const bad = okxBad(d);
      if (bad) return mk("okx", { found: false, reason: bad }, stale);
      const rows = chron((d?.data || []).map((r) => candle(r, ["open", "high", "low", "close", "volume", "quoteVolume"])), narg(limit, 48));
      return mk("okx", { found: rows.length > 0, instId, bar, count: rows.length, rows }, stale);
    }),
  mr("/market/okx-depth", "OKX order book", "Price-level ladder from OKX for one instrument with per-level contract count, plus the derived top-of-book spread.",
    ["market", "orderbook", "depth", "okx", "liquidity"],
    [OK_INST, A.num("levels", { max: 25, default: 10n, desc: "levels per side (max 25)" })],
    [["found", "boolean"], ["instId", "string"], ["bids", "array"], ["asks", "array"], ["bestBid", "string"], ["bestAsk", "string"]],
    {found: true, instId: "BTC-USDT", bids: [["84122.5"]], asks: [["84122.6"]], bestBid: "84122.5", bestAsk: "84122.6"},
    { instId: "BTC-USDT", levels: "5" },
    async ({ instId, levels }) => {
      const { d, stale } = await mj(`ok:bk:${instId}:${levels}`, `${MK.okx}/market/books?instId=${encodeURIComponent(instId)}&sz=${narg(levels, 10)}`);
      const bad = okxBad(d);
      if (bad) return mk("okx", { found: false, reason: bad }, stale);
      const b = d?.data?.[0] || {};
      const lvl = (a) => (a || []).map((r) => [r[0], r[1], nf(r[2]), nf(r[3])]);
      return mk("okx", { found: true, instId, bids: lvl(b.bids), asks: lvl(b.asks), bestBid: b.bids?.[0]?.[0] ?? null,
        bestAsk: b.asks?.[0]?.[0] ?? null, ts: nf(b.ts) }, stale);
    }),
  mr("/market/okx-trades", "OKX recent trades", "Fill-by-fill tape from OKX with aggressor side, price, size and venue timestamp.",
    ["market", "trades", "tape", "okx", "flow"],
    [OK_INST, A.num("limit", { max: 100, default: 25n, desc: "trades (max 100)" })],
    [["found", "boolean"], ["instId", "string"], ["count", "integer"], ["trades", "array"]],
    {found: true, instId: "BTC-USDT", count: 3, trades: [{tradeId: "1062664287", side: "buy", price: "84122.6", size: "0.00958117", timeSec: 1790317127, iso: "2026-09-25T06:18:47.000Z"}]},
    { instId: "BTC-USDT", limit: "3" },
    async ({ instId, limit }) => {
      const { d, stale } = await mj(`ok:tr:${instId}:${limit}`, `${MK.okx}/market/trades?instId=${encodeURIComponent(instId)}&limit=${narg(limit, 25)}`);
      const bad = okxBad(d);
      if (bad) return mk("okx", { found: false, reason: bad }, stale);
      const rows = (d?.data || []).map((t) => ({ tradeId: t.tradeId, side: t.side, price: t.px, size: t.sz,
        timeSec: Math.round(Number(t.ts) / 1000), iso: new Date(Math.round(Number(t.ts) / 1000) * 1000).toISOString() }));
      return mk("okx", { found: rows.length > 0, instId, count: rows.length, trades: rows }, stale);
    }),
  mr("/market/okx-instrument-spec", "OKX instrument specification", "Contract rules as OKX defines them: tick and lot size, minimum size, price limits, whether it is a swap or option, and settlement date.",
    ["market", "metadata", "fees", "okx", "contract"],
    [OK_INST, A.oneOf("instType", ["SPOT", "MARGIN", "SWAP", "FUTURES", "OPTION"], { desc: "which OKX instrument family to look in" })],
    [["found", "boolean"], ["instId", "string"], ["instType", "string"], ["instFamily", "string"], ["category", "string"], ["baseCcy", "string"], ["quoteCcy", "string"], ["settleCcy", "string"], ["ctType", "string"], ["ctVal", "number|null"], ["ctMult", "integer|null"], ["ctValCcy", "string"], ["lever", "string"], ["tickSz", "string"], ["lotSz", "string"], ["minSz", "string"], ["maxLmtSz", "string"], ["maxMktSz", "string"], ["maxLmtAmt", "string"], ["state", "string"], ["openType", "string"], ["ruleType", "string"], ["uly", "string"], ["optType", "string"], ["listTimeMs", "integer"], ["expTimeMs", "integer|null"], ["positionLimit", "string"], ["positionLimitPct", "integer|null"], ["tradeQuoteCcyList", "array"]],
    {found: true, instId: "BTC-USD-261225", instType: "FUTURES", instFamily: "BTC-USD", category: "1", baseCcy: "", quoteCcy: "", settleCcy: "BTC", ctType: "inverse", ctVal: 100, ctMult: 1, ctValCcy: "USD", lever: "20", tickSz: "0.1", lotSz: "0.1", minSz: "0.1", maxLmtSz: "1000000", maxMktSz: "10000", maxLmtAmt: "20000000", state: "live", openType: "", ruleType: "normal", uly: "BTC-USD", optType: "", listTimeMs: 1775808600859, expTimeMs: 1798185600000, positionLimit: "200000000", positionLimitPct: 25, tradeQuoteCcyList: []},
    { instId: "BTC-USDT-SWAP", instType: "SWAP" },
    async ({ instId, instType }) => {
      const { d, stale } = await mj(`ok:in:${instType}:${instId}`, `${MK.okx}/public/instruments?instType=${encodeURIComponent(instType)}&instId=${encodeURIComponent(instId)}`);
      const bad = okxBad(d);
      if (bad) return mk("okx", { found: false, reason: bad }, stale);
      const p = d?.data?.[0];
      if (!p) return mk("okx", { found: false, reason: "instrument not in that family" }, stale);
      // OKX's instrument record carries 55 fields and grows more per venue release; `...p` made the
      // live payload disagree with the published schema on every one of them. This picks the contract
      // rules a caller actually sizes an order from, and `?? null` keeps each key present so the
      // declaration below is the whole contract rather than whatever this one instrument filled in.
      // `stepSz`, `quoteLotSz`, `tradeMode`, `marginMode` and `nextFundingTime` are deliberately NOT
      // here: the /public/instruments answer measured 55 keys and does not contain them
      // (.tmp-check/okx-instrument-keys.txt) — the route used to publish four fields no caller could
      // ever receive.
      return mk("okx", { found: true, instId: p.instId ?? null, instType: p.instType ?? null,
        instFamily: p.instFamily ?? null, category: p.category ?? null, baseCcy: p.baseCcy ?? null,
        quoteCcy: p.quoteCcy ?? null, settleCcy: p.settleCcy ?? null, ctType: p.ctType ?? null,
        ctVal: nf(p.ctVal), ctMult: nf(p.ctMult), ctValCcy: p.ctValCcy ?? null, lever: p.lever ?? null,
        tickSz: p.tickSz ?? null, lotSz: p.lotSz ?? null, minSz: p.minSz ?? null, maxLmtSz: p.maxLmtSz ?? null,
        maxMktSz: p.maxMktSz ?? null, maxLmtAmt: p.maxLmtAmt ?? null, state: p.state ?? null,
        openType: p.openType ?? null, ruleType: p.ruleType ?? null, uly: p.uly ?? null,
        optType: p.optType ?? null, listTimeMs: nf(p.listTime), expTimeMs: nf(p.expTime),
        positionLimit: p.posLmtAmt ?? null, positionLimitPct: nf(p.posLmtPct),
        tradeQuoteCcyList: Array.isArray(p.tradeQuoteCcyList) ? p.tradeQuoteCcyList : [] }, stale);
    }),
  mr("/market/okx-funding-rate", "OKX perpetual funding", "Current and next funding rate for an OKX perpetual, with the settlement timestamps and the funding band the venue caps it at.",
    ["market", "funding", "perp", "okx", "carry"],
    [A.text("instId", /^[A-Za-z0-9]{2,10}-[A-Za-z0-9]{2,9}-SWAP$/, { example: "BTC-USDT-SWAP", desc: "OKX perpetual swap id" })],
    [["found", "boolean"], ["instId", "string"], ["instType", "string"], ["fundingRate", "string"], ["fundingTime", "integer"], ["nextFundingTime", "integer"], ["prevFundingTime", "integer"], ["settFundingRate", "string"], ["settState", "string"], ["interestRate", "string"], ["premium", "string"], ["impactValue", "string"], ["method", "string"], ["formulaType", "string"], ["maxFundingRate", "string"], ["minFundingRate", "string"], ["fundingRate8hPct", "number"]],
    {found: true, instId: "BTC-USDT-SWAP", instType: "SWAP", fundingRate: "0.0000763422020260", fundingTime: 1790323200000, nextFundingTime: 1790352000000, prevFundingTime: 1790294400000, settFundingRate: "-0.0000037995722708", settState: "settled", interestRate: "0.0001000000000000", premium: "-0.0004089284292036", impactValue: "20000.0000000000000000", method: "current_period", formulaType: "withRate", maxFundingRate: "0.00375", minFundingRate: "-0.00375", fundingRate8hPct: 0.00763422},
    { instId: "BTC-USDT-SWAP" },
    async ({ instId }) => {
      const { d, stale } = await mj(`ok:fr:${instId}`, `${MK.okx}/public/funding-rate?instId=${encodeURIComponent(instId)}`);
      const bad = okxBad(d);
      if (bad) return mk("okx", { found: false, reason: bad }, stale);
      const f = d?.data?.[0];
      if (!f) return mk("okx", { found: false, reason: "no funding for that instrument" }, stale);
      return mk("okx", { found: true, instId: f.instId ?? null, instType: f.instType ?? null,
        fundingRate: f.fundingRate ?? null, fundingTime: nf(f.fundingTime), nextFundingTime: nf(f.nextFundingTime),
        prevFundingTime: nf(f.prevFundingTime), settFundingRate: f.settFundingRate ?? null,
        settState: f.settState ?? null, interestRate: f.interestRate ?? null, premium: f.premium ?? null,
        impactValue: f.impactValue ?? null, method: f.method ?? null, formulaType: f.formulaType ?? null,
        maxFundingRate: f.maxFundingRate ?? null, minFundingRate: f.minFundingRate ?? null,
        fundingRate8hPct: nf(f.fundingRate) === null ? null : +(Number(f.fundingRate) * 100).toFixed(8) }, stale,
        "fundingRate is per 8h settlement window as OKX publishes it; annualised it is that rate times 3");
    }),
];

// ---- Bitfinex (audited USD venue) -----------------------------------------------------------
const BF_PAIR = A.text("pair", /^[A-Za-z0-9]{3,12}$/, { example: "BTCUSD", desc: "Bitfinex currency pair without the venue's leading t: BTCUSD, ETHUSD, ADAUSD" });
const bfId = (p) => `t${String(p).toUpperCase()}`;
const MK_BITFINEX = [
  mr("/market/bfex-ticker", "Bitfinex spot ticker", "Top of book, last, 24h change in price and percent, and 24h volume/high/low for one Bitfinex spot pair.",
    ["market", "spot", "ticker", "bitfinex", "price"],
    [BF_PAIR],
    [["found", "boolean"], ["pair", "string"], ["bid", "integer"], ["bidSize", "number"], ["ask", "integer"], ["askSize", "number"], ["change24h", "integer"], ["changePct24h", "number"], ["last", "integer"], ["volume24h", "number"], ["high24h", "integer"], ["low24h", "integer"]],
    {found: true, pair: "tBTCUSD", bid: 84078, bidSize: 1.77650578, ask: 84092, askSize: 2.26997615, change24h: -126, changePct24h: -0.00149644, last: 84074, volume24h: 1273.75195306, high24h: 84890, low24h: 82865},
    { pair: "BTCUSD" },
    async ({ pair }) => {
      const { d, stale, missing } = await mj(`bf:tk:${pair}`, `${MK.bitfinex}/ticker/${bfId(pair)}`, null, { tolerate: true });
      if (missing || !Array.isArray(d) || d.length < 10) return mk("bitfinex", { found: false, reason: missing || "no ticker row for that pair" }, stale);
      return mk("bitfinex", { found: true, pair: bfId(pair), bid: d[0], bidSize: d[1], ask: d[2], askSize: d[3],
        change24h: d[4], changePct24h: d[5], last: d[6], volume24h: d[7], high24h: d[8], low24h: d[9] }, stale, EVM_MINT_NOTE);
    }),
  mr("/market/bfex-candles", "Bitfinex OHLC candles", "Candles for a Bitfinex spot pair at the timeframes its v2 API serves, oldest first, with base volume per bucket.",
    ["market", "candles", "ohlc", "bitfinex", "chart"],
    [BF_PAIR, A.oneOf("timeframe", ["1m", "15m", "1h", "4h", "1D", "1W"], { desc: "Bitfinex candle timeframe" }),
     A.num("limit", { max: 300, default: 48n, desc: "candles (max 300)" })],
    [["found", "boolean"], ["pair", "string"], ["timeframe", "string"], ["count", "integer"], ["rows", "array"]],
    {found: true, pair: "tBTCUSD", timeframe: "1h", count: 3, rows: [{timeSec: 1790308800, iso: "2026-09-25T04:00:00.000Z", open: "84190", close: "84161", high: "84256", low: "84004"}]},
    { pair: "BTCUSD", timeframe: "1h", limit: "3" },
    async ({ pair, timeframe, limit }) => {
      // `/last` measured broken (returns one flat row and ignores limit+sort) and `hist?sort=1` measured
      // worse: it answers the OLDEST N buckets, from 2013. `sort=-1` is the only form that yields a
      // recent series, and `chron` re-orders it oldest-first for the caller.
      const { d, stale, missing } = await mj(`bf:cd:${pair}:${timeframe}`, `${MK.bitfinex}/candles/trade:${timeframe}:${bfId(pair)}/hist?limit=${narg(limit, 48)}&sort=-1`, null, { tolerate: true });
      if (missing) return mk("bitfinex", { found: false, reason: missing }, stale);
      const rows = chron(candleRows(d).map((r) => candle(r, ["open", "close", "high", "low", "volume"])), narg(limit, 48));
      return mk("bitfinex", { found: rows.length > 0, pair: bfId(pair), timeframe, count: rows.length, rows }, stale);
    }),
  mr("/market/bfex-pairs", "Bitfinex listed pairs", "The pair ids Bitfinex itself publishes for its spot exchange, optionally filtered by a substring — the lookup that stops a bot guessing a market that does not exist.",
    ["market", "metadata", "pairs", "bitfinex", "list"],
    [A.text("contains", /^[A-Za-z0-9:]{1,12}$/, { required: false, default: null, maxLen: 12, example: "USD", desc: "case-insensitive substring filter on the pair id" }),
     A.num("limit", { max: 300, default: 100n, desc: "ids to return (max 300)" })],
    [["total", "integer"], ["matched", "integer"], ["pairs", "array"]],
    {total: 194, matched: 27, pairs: ["ADABTC"]},
    { contains: "BTC" },
    async ({ contains, limit }) => {
      const { d, stale } = await mj(`bf:pairs`, `${MK.bitfinex}/conf/pub:list:pair:exchange`);
      const all = (Array.isArray(d?.[0]) ? d[0] : []).map(String);
      const need = contains ? String(contains).toUpperCase() : null;
      const hits = need ? all.filter((p) => p.toUpperCase().includes(need)) : all;
      return mk("bitfinex", { total: all.length, matched: hits.length,
        pairs: hits.slice(0, narg(limit, 100)).map((p) => p.replace(/^t(?=[A-Z]{2,12}$)/, "")) }, stale);
    }),
];

// ---- Gate.io (deep alt liquidity) -----------------------------------------------------------
const GT_PAIR = A.text("pair", /^[A-Za-z0-9]{2,10}_[A-Za-z0-9]{2,10}$/, { example: "BTC_USDT", desc: "Gate currency_pair, BASE_QUOTE" });
const MK_GATE = [
  mr("/market/gate-ticker", "Gate spot ticker", "Last, best bid and ask with size, 24h percent change and both base and quote volume for one Gate currency pair.",
    ["market", "spot", "ticker", "gate", "price"],
    [GT_PAIR],
    [["found", "boolean"], ["currency_pair", "string"], ["last", "string"], ["lowest_ask", "string"], ["lowest_size", "string"], ["highest_bid", "string"], ["highest_size", "string"], ["change_percentage", "string"], ["base_volume", "string"], ["quote_volume", "string"], ["high_24h", "string"], ["low_24h", "string"]],
    {found: true, currency_pair: "BTC_USDT", last: "84116.1", lowest_ask: "84121.9", lowest_size: "0.056662", highest_bid: "84121.8", highest_size: "0.407599", change_percentage: "-0.07", base_volume: "6592.54040509", quote_volume: "554301333.659904013", high_24h: "84938.1", low_24h: "82888"},
    { pair: "BTC_USDT" },
    async ({ pair }) => {
      const { d, stale, missing } = await mj(`gt:tk:${pair}`, `${MK.gate}/tickers?currency_pair=${encodeURIComponent(pair)}`, null, { tolerate: true });
      if (missing) return mk("gate", { found: false, reason: missing }, stale);
      const t = Array.isArray(d) ? d[0] : null;
      if (!t) return mk("gate", { found: false, reason: "pair not listed" }, stale);
      return mk("gate", { found: true, ...t }, stale, EVM_MINT_NOTE);
    }),
  mr("/market/gate-candles", "Gate OHLC candles", "OHLCV per bucket from Gate with the quote volume and the window-closed flag, oldest first.",
    ["market", "candles", "ohlc", "gate", "chart"],
    [GT_PAIR, A.oneOf("interval", ["5m", "1h", "4h", "1d", "1w"], { desc: "Gate candle interval (only the values its API accepted when measured)" }),
     A.num("limit", { max: 1000, default: 48n, desc: "candles (max 1000)" })],
    [["found", "boolean"], ["currency_pair", "string"], ["interval", "string"], ["count", "integer"], ["rows", "array"]],
    {found: true, currency_pair: "BTC_USDT", interval: "1h", count: 3, rows: [{timeSec: 1790308800, iso: "2026-09-25T04:00:00.000Z", quoteVolume: "6278780.34685180", close: "84212.2", high: "84299.3", low: "84060"}]},
    { pair: "BTC_USDT", interval: "1h", limit: "3" },
    async ({ pair, interval, limit }) => {
      const { d, stale, missing } = await mj(`gt:cd:${pair}:${interval}:${limit}`, `${MK.gate}/candlesticks?currency_pair=${encodeURIComponent(pair)}&interval=${encodeURIComponent(interval)}&limit=${narg(limit, 48)}`, null, { tolerate: true });
      if (missing) return mk("gate", { found: false, reason: missing }, stale);
      const rows = chron((Array.isArray(d) ? d : []).map((r) => ({
        // Gate stamps its candles in SECONDS (measured: r[0] = 1790258400 for a 14:00 UTC bucket), so
        // the default millisecond divisor would publish 1970-01-21 as the bucket time.
        ...candle(r, ["quoteVolume", "close", "high", "low", "open", "volume"], 1), closed: r[7] === "true",
      })), narg(limit, 48));
      return mk("gate", { found: rows.length > 0, currency_pair: pair, interval, count: rows.length, rows }, stale);
    }),
  mr("/market/gate-depth", "Gate order book", "Resting bids and asks from Gate for one pair, with the venue's own sequence fields and the derived top-of-book spread.",
    ["market", "orderbook", "depth", "gate", "liquidity"],
    [GT_PAIR, A.num("levels", { max: 50, default: 10n, desc: "levels per side (max 50)" })],
    [["found", "boolean"], ["currency_pair", "string"], ["bids", "array"], ["asks", "array"], ["bestBid", "string"], ["bestAsk", "string"], ["updateMs", "integer"], ["spreadPct", "number"]],
    {found: true, currency_pair: "BTC_USDT", bids: [["84116.1"]], asks: [["84116.2"]], bestBid: "84116.1", bestAsk: "84116.2", updateMs: 1790317134917, spreadPct: 0.00000119},
    { pair: "BTC_USDT", levels: "5" },
    async ({ pair, levels }) => {
      const { d, stale, missing } = await mj(`gt:bk:${pair}:${levels}`, `${MK.gate}/order_book?currency_pair=${encodeURIComponent(pair)}&limit=${narg(levels, 10)}`, null, { tolerate: true });
      if (missing) return mk("gate", { found: false, reason: missing }, stale);
      const bb = d?.bids?.[0]?.[0], ba = d?.asks?.[0]?.[0];
      return mk("gate", { found: true, currency_pair: pair, bids: d?.bids || [], asks: d?.asks || [],
        bestBid: bb ?? null, bestAsk: ba ?? null, updateMs: nf(d?.update),
        spreadPct: bb && ba ? +((Number(ba) - Number(bb)) / Number(bb)).toFixed(8) : null }, stale);
    }),
  mr("/market/gate-trades", "Gate recent trades", "Gate's public fill feed for one pair: side, price, base amount, millisecond timestamp and trade id.",
    ["market", "trades", "tape", "gate", "flow"],
    [GT_PAIR, A.num("limit", { max: 100, default: 25n, desc: "trades (max 100)" })],
    [["found", "boolean"], ["currency_pair", "string"], ["count", "integer"], ["trades", "array"]],
    {found: true, currency_pair: "BTC_USDT", count: 3, trades: [{tradeId: "220552474", side: "sell", price: "84116.1", amount: "0.000118", total: null, timeSec: 1790317121}]},
    { pair: "BTC_USDT", limit: "3" },
    async ({ pair, limit }) => {
      const { d, stale, missing } = await mj(`gt:tr:${pair}:${limit}`, `${MK.gate}/trades?currency_pair=${encodeURIComponent(pair)}&limit=${narg(limit, 25)}`, null, { tolerate: true });
      if (missing) return mk("gate", { found: false, reason: missing }, stale);
      const rows = (Array.isArray(d) ? d : []).map((t) => ({ tradeId: t.id, side: t.side, price: t.price, amount: t.amount,
        total: t.total, timeSec: nf(t.create_time), iso: t.create_time ? new Date(Number(t.create_time) * 1000).toISOString() : null }));
      return mk("gate", { found: rows.length > 0, currency_pair: pair, count: rows.length, trades: rows }, stale);
    }),
  mr("/market/gate-pair-spec", "Gate pair specification", "How Gate defines a currency pair: base and quote, the flat fee percent, order-size floors and caps, precision and whether it is tradable.",
    ["market", "metadata", "fees", "gate", "pair"],
    [GT_PAIR],
    [["found", "boolean"], ["id", "string"], ["base", "string"], ["base_name", "string"], ["quote", "string"], ["quote_name", "string"], ["type", "string"], ["fee", "string"], ["trade_status", "string"], ["amount_precision", "integer"], ["price_precision", "integer"], ["min_base_amount", "string"], ["max_base_amount", "string|null"], ["min_quote_amount", "string"], ["max_quote_amount", "string"], ["market_order_max_stock", "string"], ["market_order_max_money", "string"], ["slippage", "string"], ["up_rate", "number"], ["down_rate", "number"], ["st_tag", "boolean"], ["trade_quotes", "array"]],
    {found: true, id: "BTC_USDT", base: "BTC", base_name: "Bitcoin", quote: "USDT", quote_name: "Tether", type: "normal", fee: "0.2", trade_status: "tradable", amount_precision: 6, price_precision: 1, min_base_amount: "0.000001", max_base_amount: "100", min_quote_amount: "3", max_quote_amount: "5000000", market_order_max_stock: "65", market_order_max_money: "5000000", slippage: "0.03", up_rate: 0.08, down_rate: 0.08, st_tag: false, trade_quotes: []},
    { pair: "BTC_USDT" },
    async ({ pair }) => {
      const { d, stale, missing } = await mj(`gt:cp:${pair}`, `${MK.gate}/currency_pairs/${encodeURIComponent(pair)}`, null, { tolerate: true });
      if (missing) return mk("gate", { found: false, reason: missing }, stale);
      if (!d?.id) return mk("gate", { found: false, reason: "pair not listed" }, stale);
      // Field names read off .tmp-check/raw-key-dump.txt. Two corrections against the previous
      // version: the venue's price step is `precision`, not `price_precision` (so this route used to
      // answer null for its own headline field), and `disable_deposit` is not in the record at all.
      return mk("gate", { found: true, id: d.id, base: d.base, base_name: d.base_name, quote: d.quote, quote_name: d.quote_name,
        type: d.type ?? null, fee: d.fee ?? null, trade_status: d.trade_status ?? null,
        amount_precision: nf(d.amount_precision), price_precision: nf(d.precision),
        min_base_amount: d.min_base_amount ?? null, max_base_amount: d.max_base_amount ?? null,
        min_quote_amount: d.min_quote_amount ?? null, max_quote_amount: d.max_quote_amount ?? null,
        market_order_max_stock: d.market_order_max_stock ?? null, market_order_max_money: d.market_order_max_money ?? null,
        slippage: d.slippage ?? null, up_rate: nf(d.up_rate), down_rate: nf(d.down_rate),
        st_tag: d.st_tag ?? null, trade_quotes: Array.isArray(d.trade_quotes) ? d.trade_quotes : [] }, stale);
    }),
];

// ---- KuCoin (alt-heavy, tight tick data) ----------------------------------------------------
const KC_SYM = A.text("symbol", /^[A-Z0-9]{2,10}-[A-Z0-9]{2,10}$/, { example: "BTC-USDT", desc: "KuCoin symbol, BASE-QUOTE in upper case (BTC-USDT, SOL-USDT)" });
const kcBad = (d) => (d && String(d.code) !== "200000" ? `kucoin code ${d.code}: ${String(d.msg || "").slice(0, 90)}` : null);
const MK_KUCOIN = [
  mr("/market/kucoin-ticker", "KuCoin 24h stats", "KuCoin's own 24h statistics for a symbol: last, best bid/ask with size, 24h high/low, change, base and quote volume, average price and the taker/maker fee rates it applies.",
    ["market", "spot", "ticker", "kucoin", "price", "fees"],
    [KC_SYM],
    [["found", "boolean"], ["time", "integer"], ["symbol", "string"], ["buy", "string"], ["sell", "string"], ["changeRate", "string"], ["changePrice", "string"], ["high", "string"], ["low", "string"], ["vol", "string"], ["volValue", "string"], ["last", "string"], ["averagePrice", "string"], ["takerFeeRate", "string"], ["makerFeeRate", "string"], ["takerCoefficient", "string"], ["makerCoefficient", "string"]],
    {found: true, time: 1790317136258, symbol: "BTC-USDT", buy: "84119.2", sell: "84119.3", changeRate: "-0.0003", changePrice: "-28", high: "84923", low: "82868", vol: "3070.5086626005860382", volValue: "258402671.272824005110718", last: "84119.3", averagePrice: "84035.87357353", takerFeeRate: "0.001", makerFeeRate: "0.001", takerCoefficient: "1", makerCoefficient: "1"},
    { symbol: "BTC-USDT" },
    async ({ symbol }) => {
      const { d, stale } = await mj(`kc:st:${symbol}`, `${MK.kucoin}/market/stats?symbol=${encodeURIComponent(symbol)}`);
      const bad = kcBad(d);
      if (bad) return mk("kucoin", { found: false, reason: bad }, stale);
      const t = d?.data;
      if (!t || t.last === undefined || t.last === null) return mk("kucoin", { found: false, reason: "symbol has no 24h stats (not listed, or no trades)" }, stale);
      return mk("kucoin", { found: true, ...t, ts: nf(t.time) }, stale, EVM_MINT_NOTE);
    }),
  mr("/market/kucoin-best-quote", "KuCoin best bid and ask", "KuCoin's level-1 book for a symbol in one call: inside price, both sides with size, the book sequence and the venue timestamp.",
    ["market", "orderbook", "quote", "kucoin", "liquidity"],
    [KC_SYM],
    [["found", "boolean"], ["symbol", "string"], ["time", "integer"], ["sequence", "string"], ["price", "string"], ["size", "string"], ["bestBid", "string"], ["bestBidSize", "string"], ["bestAsk", "string"], ["bestAskSize", "string"]],
    {found: true, symbol: "BTC-USDT", time: 1790317133343, sequence: "37713808977", price: "84119.3", size: "0.0115497", bestBid: "84119.2", bestBidSize: "1.71702611", bestAsk: "84119.3", bestAskSize: "0.0032094"},
    { symbol: "BTC-USDT" },
    async ({ symbol }) => {
      const { d, stale } = await mj(`kc:l1:${symbol}`, `${MK.kucoin}/market/orderbook/level1?symbol=${encodeURIComponent(symbol)}`);
      const bad = kcBad(d);
      if (bad) return mk("kucoin", { found: false, reason: bad }, stale);
      const t = d?.data;
      if (!t || !t.price) return mk("kucoin", { found: false, reason: "no book for that symbol" }, stale);
      return mk("kucoin", { found: true, symbol, ...t, ts: nf(t.time) }, stale);
    }),
  mr("/market/kucoin-candles", "KuCoin OHLC candles", "KuCoin candles with base and quote (transaction-value) volume per bucket, oldest first, across every type value the venue answered.",
    ["market", "candles", "ohlc", "kucoin", "chart"],
    [KC_SYM, A.oneOf("type", ["1min", "15min", "1hour", "4hour", "1day", "1week"], { desc: "KuCoin candle type" }),
     A.num("limit", { max: 1500, default: 48n, desc: "candles (max 1500; KuCoin answers at most 1500 per call)" })],
    [["found", "boolean"], ["symbol", "string"], ["type", "string"], ["count", "integer"], ["rows", "array"]],
    {found: true, symbol: "BTC-USDT", type: "1hour", count: 3, rows: [{timeSec: 1790308800, iso: "2026-09-25T04:00:00.000Z", open: "84234.1", close: "84206", high: "84288.1", low: "84063.1"}]},
    { symbol: "BTC-USDT", type: "1hour", limit: "3" },
    async ({ symbol, type, limit }) => {
      const { d, stale } = await mj(`kc:cd:${symbol}:${type}`, `${MK.kucoin}/market/candles?type=${encodeURIComponent(type)}&symbol=${encodeURIComponent(symbol)}`);
      const bad = kcBad(d);
      if (bad) return mk("kucoin", { found: false, reason: bad }, stale);
      const rows = chron((d?.data || []).map((r) => candle(r, ["open", "close", "high", "low", "volume", "quoteVolume"], 1)), narg(limit, 48));
      return mk("kucoin", { found: rows.length > 0, symbol, type, count: rows.length, rows }, stale);
    }),
];

// ---- Deribit (the only keyless options/IV surface here) -------------------------------------
const DR_INST = A.text("instrument", /^[A-Z]{2,6}-[A-Z0-9]{2,12}$/, { example: "BTC-PERPETUAL", desc: "Deribit instrument name, CURRENCY-SUFFIX (BTC-PERPETUAL, ETH-25SEP26)" });
const drErr = (d) => (d?.error ? `deribit ${d.error.code}: ${String(d.error.message || "").slice(0, 90)}` : null);
const MK_DERIBIT = [
  mr("/market/deribit-index", "Deribit index price", "Deribit's own index price for an underlying plus the estimated delivery price it settles against — the reference a funding or settlement check needs.",
    ["market", "index", "price", "deribit", "reference"],
    [A.oneOf("indexName", ["btc_usd", "eth_usd", "sol_usd"], { desc: "Deribit index name (only the ones measured)" })],
    [["found", "boolean"], ["indexName", "string"], ["indexPrice", "number"], ["estimatedDeliveryPrice", "number"]],
    {found: true, indexName: "btc_usd", indexPrice: 84108.17, estimatedDeliveryPrice: 84108.17},
    { indexName: "btc_usd" },
    async ({ indexName }) => {
      const { d, stale, missing } = await mj(`dr:ix:${indexName}`, `${MK.deribit}/get_index_price?index_name=${encodeURIComponent(indexName)}`, null, { tolerate: true });
      if (missing) return mk("deribit", { found: false, reason: missing }, stale);
      const bad = drErr(d);
      if (bad) return mk("deribit", { found: false, reason: bad }, stale);
      return mk("deribit", { found: true, indexName, indexPrice: nf(d.result?.index_price),
        estimatedDeliveryPrice: nf(d.result?.estimated_delivery_price) }, stale);
    }),
  mr("/market/deribit-funding-window", "Deribit funding over a window", "The funding Deribit's own get_funding_rate_value reports as having accrued on one instrument between two timestamps — a window total, not a snapshot rate.",
    ["market", "funding", "perp", "deribit", "carry"],
    [DR_INST, A.num("hours", { max: 720, default: 24n, desc: "look-back window in whole hours (max 720)" })],
    [["found", "boolean"], ["instrument", "string"], ["hours", "integer"], ["startMs", "integer"], ["endMs", "integer"], ["fundingOverWindow", "number"], ["annualizedPct", "number"]],
    {found: true, instrument: "BTC-PERPETUAL", hours: 24, startMs: 1790230736928, endMs: 1790317136928, fundingOverWindow: 0.000061014988441864154, annualizedPct: 2.227},
    { instrument: "BTC-PERPETUAL", hours: "24" },
    async ({ instrument, hours }) => {
      const h = narg(hours, 24);
      // The corrected clock, not Date.now(): with the host seven hours out this window asked Deribit
      // for funding that stopped seven hours ago and reported the gap as the current 24h carry.
      const endMs = nowMs(), startMs = endMs - h * 3600e3;
      const { d, stale, missing } = await mj(`dr:fr:${instrument}:${h}`,
        `${MK.deribit}/get_funding_rate_value?instrument_name=${encodeURIComponent(instrument)}&start_timestamp=${startMs}&end_timestamp=${endMs}`, null, { tolerate: true });
      if (missing) return mk("deribit", { found: false, reason: missing }, stale);
      const bad = drErr(d);
      if (bad) return mk("deribit", { found: false, reason: bad }, stale);
      const v = nf(d.result);
      return mk("deribit", { found: v !== null, instrument, hours: h, startMs, endMs, fundingOverWindow: v,
        annualizedPct: v === null ? null : +((v * (8760 / h)) * 100).toFixed(4) }, stale,
        "fundingOverWindow is the venue's accumulated rate for the window; annualisedPct assumes that window repeats for a year");
    }),
  mr("/market/deribit-volatility-index", "Deribit daily volatility index", "Historical daily candles of Deribit's DVOL-style volatility index for an underlying — the implied-vol level options are priced off, as OHLC per day.",
    ["market", "volatility", "options", "deribit", "iv"],
    [A.oneOf("currency", ["BTC", "ETH"], { desc: "underlying whose volatility index Deribit publishes" }),
     A.num("days", { max: 365, default: 30n, desc: "days of history (max 365)" })],
    [["found", "boolean"], ["currency", "string"], ["days", "integer"], ["count", "integer"], ["rows", "array"]],
    {found: true, currency: "BTC", days: 10, count: 11, rows: [{timeSec: 1789430400, iso: "2026-09-15T00:00:00.000Z", open: "39.13", high: "41.17", low: "38.89", close: "39.01"}]},
    { currency: "BTC", days: "10" },
    async ({ currency, days }) => {
      const n = narg(days, 30), endMs = nowMs(), startMs = endMs - n * 86400e3;
      const { d, stale, missing } = await mj(`dr:vol:${currency}:${n}:${Math.floor(endMs / 86400e3)}`,
        `${MK.deribit}/get_volatility_index_data?currency=${encodeURIComponent(currency)}&start_timestamp=${startMs}&end_timestamp=${endMs}&resolution=86400`, null, { tolerate: true });
      if (missing) return mk("deribit", { found: false, reason: missing }, stale);
      const bad = drErr(d);
      if (bad) return mk("deribit", { found: false, reason: bad }, stale);
      const rows = chron((d?.result?.data || []).map((r) => candle(r, ["open", "high", "low", "close"])), 500);
      return mk("deribit", { found: rows.length > 0, currency, days: n, count: rows.length, rows }, stale,
        "values are index points (percent annualised volatility), not a price");
    }),
  mr("/market/deribit-instruments", "Deribit instrument list", "The contract rules Deribit publishes per instrument: tick size, contract size, min trade amount, max leverage, fee rates, state and expiry — perpetuals only or the whole listed futures set.",
    ["market", "metadata", "fees", "deribit", "contract"],
    [A.oneOf("currency", ["BTC", "ETH"], { desc: "currency to list instruments for" }),
     A.oneOf("family", ["perpetual", "all"], { desc: "just -PERPETUAL, or every listed future including dated ones" }),
     A.num("limit", { max: 50, default: 12n, desc: "instruments to return (max 50)" })],
    [["found", "boolean"], ["currency", "string"], ["family", "string"], ["listed", "integer"], ["count", "integer"], ["rows", "array"]],
    {found: true, currency: "BTC", family: "perpetual", listed: 14, count: 1, rows: [{instrumentName: "BTC-PERPETUAL", kind: "future", instrumentType: "reversed", quoteCurrency: "USD", priceIndex: "btc_usd", tickSize: 0.5}]},
    { currency: "BTC", family: "perpetual", limit: "3" },
    async ({ currency, family, limit }) => {
      const { d, stale, missing } = await mj(`dr:in:${currency}`, `${MK.deribit}/get_instruments?currency=${encodeURIComponent(currency)}&kind=future`, null, { tolerate: true });
      if (missing) return mk("deribit", { found: false, reason: missing }, stale);
      const bad = drErr(d);
      if (bad) return mk("deribit", { found: false, reason: bad }, stale);
      const all = (d?.result || []).map((r) => ({ instrumentName: r.instrument_name, kind: r.kind,
        instrumentType: r.instrument_type, quoteCurrency: r.quote_currency, priceIndex: r.price_index,
        tickSize: nf(r.tick_size), contractSize: nf(r.contract_size), minTradeAmount: nf(r.min_trade_amount),
        maxLeverage: nf(r.max_leverage), state: r.state, takerCommission: nf(r.taker_commission),
        makerCommission: nf(r.maker_commission), isCritical: r.is_critical ?? null,
        underlyingType: r.underlying_type ?? null, productGroup: r.product_group ?? null,
        expirationMs: nf(r.expiration_timestamp), settlementCurrency: r.settlement_currency ?? null }));
      const rows = family === "perpetual" ? all.filter((r) => /-PERPETUAL$/.test(r.instrumentName)) : all;
      return mk("deribit", { found: rows.length > 0, currency, family, listed: all.length, count: Math.min(rows.length, narg(limit, 12)),
        rows: rows.slice(0, narg(limit, 12)) }, stale);
    }),
];

// ---- Hyperliquid (the perp DEX whose info API needs no key) --------------------------------
// Every call here is POST /info with a fixed-shape body; `coin` is the only variable the caller owns
// and it is regex-bound, so the request cannot be steered at another host or another `type`.
const HL_COIN = A.text("coin", /^[A-Za-z][A-Za-z0-9]{0,11}$/, { example: "BTC", desc: "Hyperliquid coin symbol as its meta lists it (BTC, ETH, HYPE, kPEPE)" });
const hl = (type, extra, key) => mj(`hl:${key || type}`, MK.hyper,
  { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type, ...(extra || {}) }) },
  { tolerate: true });
const MK_HL = [
  mr("/market/hl-mid-price", "Hyperliquid mid price", "The venue's own mid for one or more Hyperliquid perp coins, straight from allMids — the reference price a funding or liquidation check starts from.",
    ["market", "perp", "mid", "hyperliquid", "price"],
    [{ name: "coins", kind: "list", required: false, type: "string", max: 12, keepCase: true, default: ["BTC", "ETH", "HYPE"],
       example: "BTC,ETH", pattern: /^[A-Za-z][A-Za-z0-9]{0,11}$/, desc: "comma list of up to 12 Hyperliquid coin symbols (default BTC,ETH,HYPE)" }],
    [["requested", "integer"], ["matched", "integer"], ["mids", "object"]],
    {requested: 2, matched: 2, mids: {BTC: 84111.5, ETH: 2676.05}},
    { coins: "BTC,ETH" },
    async ({ coins }) => {
      const { d, stale, missing } = await hl("allMids", null, "allMids");
      if (missing) return mk("hyperliquid", { found: 0, requested: (coins || []).length, mids: {}, reason: missing }, stale);
      const mids = {}, absent = [];
      for (const c of coins || []) {
        const v = nf(d?.[c]);
        if (v === null) absent.push(c); else mids[c] = v;
      }
      return mk("hyperliquid", { requested: (coins || []).length, matched: Object.keys(mids).length, mids,
        ...(absent.length ? { notListed: absent } : {}) }, stale,
        "allMids keys also include binary-market ids; only the symbols you asked for are returned");
    }),
  mr("/market/hl-perp-specs", "Hyperliquid perp specifications", "Per-coin contract rules from Hyperliquid's own meta: size decimals, maximum leverage and the margin table id, for the whole listed universe or filtered by substring.",
    ["market", "metadata", "perp", "hyperliquid", "leverage"],
    [A.text("contains", /^[A-Za-z0-9]{1,12}$/, { required: false, default: null, example: "PEPE", desc: "case-insensitive substring filter on the coin name" }),
     A.num("limit", { max: 100, default: 25n, desc: "coins to return (max 100)" })],
    [["universe", "integer"], ["count", "integer"], ["rows", "array"]],
    {universe: 234, count: 1, rows: [{name: "BTC", szDecimals: 5, maxLeverage: 40, marginTableId: 56, onlyIsolated: null, isInternalPoS: null}]},
    { contains: "BTC", limit: "3" },
    async ({ contains, limit }) => {
      const { d, stale, missing } = await hl("meta", null, "meta");
      if (missing) return mk("hyperliquid", { universe: 0, count: 0, rows: [], reason: missing }, stale);
      const all = (d?.universe || []).map((u) => ({ name: u.name, szDecimals: nf(u.szDecimals),
        maxLeverage: nf(u.maxLeverage), marginTableId: nf(u.marginTableId), onlyIsolated: u.only_isolated ?? null,
        isInternalPoS: u.is_internal_pos_asset ?? null }));
      const need = contains ? String(contains).toLowerCase() : null;
      const rows = need ? all.filter((r) => String(r.name).toLowerCase().includes(need)) : all;
      return mk("hyperliquid", { universe: all.length, count: Math.min(rows.length, narg(limit, 25)),
        rows: rows.slice(0, narg(limit, 25)) }, stale);
    }),
  mr("/market/hl-order-book", "Hyperliquid L2 book", "Hyperliquid's l2Book for one perp: the resting bid and ask levels with price, size and opaque-order count, plus the book time.",
    ["market", "orderbook", "depth", "hyperliquid", "liquidity"],
    [HL_COIN],
    [["found", "boolean"], ["coin", "string"], ["bids", "array"], ["asks", "array"], ["bestBid", "string"], ["bestAsk", "string"]],
    {found: true, coin: "BTC", bids: [{px: "84111.0", sz: "4.41511", n: 18}], asks: [{px: "84112.0", sz: "3.75", n: 16}], bestBid: "84111.0", bestAsk: "84112.0"},
    { coin: "BTC" },
    async ({ coin }) => {
      const { d, stale, missing } = await hl("l2Book", { coin }, `l2:${coin}`);
      if (missing) return mk("hyperliquid", { found: false, coin, reason: missing }, stale);
      // Measured on the raw record (.tmp-check/hl-l2book-keys.txt): levels[0] is the bid ladder and
      // levels[1] the ask ladder, each ordered BEST first (bids 84420→84401 descending, asks
      // 84426→84449 ascending). Reading them the other way round and taking the last row labelled the
      // asks as bids and published the worst price on each side as "best" — a crossed book a buyer
      // pays for and cannot tell from a real one.
      const [bids = [], asks = []] = Array.isArray(d?.levels) ? d.levels : [];
      if (!Array.isArray(d?.levels)) return mk("hyperliquid", { found: false, coin, reason: "no book published for that coin" }, stale);
      const top = (a) => (a.length ? a[0] : null);
      return mk("hyperliquid", { found: true, coin, bids, asks, bestBid: top(bids)?.px ?? null,
        bestAsk: top(asks)?.px ?? null, ts: nf(d?.time) }, stale);
    }),
  mr("/market/hl-candles", "Hyperliquid OHLC candles", "candleSnapshot for one Hyperliquid perp: open, high, low, close, volume and order count per bucket, oldest first, bounded to the window each interval can carry.",
    ["market", "candles", "ohlc", "hyperliquid", "chart"],
    [HL_COIN, A.oneOf("interval", ["1m", "15m", "1h", "4h", "12h", "1d", "1w"], { desc: "candle interval" }),
     A.num("limit", { max: 500, default: 48n, desc: "candles (max 500)" })],
    [["found", "boolean"], ["coin", "string"], ["interval", "string"], ["count", "integer"], ["rows", "array"]],
    {found: true, coin: "BTC", interval: "1h", count: 3, rows: [{timeSec: 1790308800, iso: "2026-09-25T04:00:00.000Z", open: "84221.0", high: "84285.0", low: "84050.0", close: "84198.0"}]},
    { coin: "BTC", interval: "1h", limit: "3" },
    async ({ coin, interval, limit }) => {
      const start = nowMs() - (WINDOW_MS[interval] || 3 * 86400e3);
      const { d, stale, missing } = await hl("candleSnapshot",
        { req: { coin, interval, startTime: start, endTime: nowMs() } }, `cd:${coin}:${interval}:${Math.floor(start / 86400e3)}`);
      if (missing) return mk("hyperliquid", { found: false, coin, reason: missing }, stale);
      const rows = chron((Array.isArray(d) ? d : []).map((r) => ({ timeSec: Math.round(Number(r.t) / 1000),
        iso: new Date(Math.round(Number(r.t) / 1000) * 1000).toISOString(), open: r.o, high: r.h, low: r.l, close: r.c,
        volume: r.v, trades: nf(r.n) })), narg(limit, 48));
      return mk("hyperliquid", { found: rows.length > 0, coin, interval, count: rows.length, rows }, stale);
    }),
  mr("/market/hl-funding-history", "Hyperliquid funding history", "Every funding print Hyperliquid has for a perp coin since a look-back point: rate, premium component and the settlement timestamp.",
    ["market", "funding", "perp", "hyperliquid", "carry"],
    [HL_COIN, A.num("hours", { max: 720, default: 72n, desc: "look-back in whole hours (max 720)" })],
    [["found", "boolean"], ["coin", "string"], ["hours", "integer"], ["count", "integer"], ["latestRate", "string"]],
    {found: true, coin: "ETH", hours: 48, count: 48, latestRate: "0.0000125"},
    { coin: "ETH", hours: "48" },
    async ({ coin, hours }) => {
      const h = narg(hours, 72);
      const { d, stale, missing } = await hl("fundingHistory", { coin, startTime: nowMs() - h * 3600e3 }, `fh:${coin}:${Math.floor(h / 6)}`);
      if (missing) return mk("hyperliquid", { found: false, coin, count: 0, rows: [], reason: missing }, stale);
      const rows = (Array.isArray(d) ? d : []).map((r) => ({ timeMs: nf(r.time),
        iso: r.time ? new Date(Number(r.time)).toISOString() : null, fundingRate: r.fundingRate, premium: r.premium }));
      return mk("hyperliquid", { found: rows.length > 0, coin, hours: h, count: rows.length,
        latestRate: rows.at(-1)?.fundingRate ?? null }, stale,
        "fundingRate is per hour on Hyperliquid; the printed premium is the venue's own index-premium term");
    }),
  mr("/market/hl-asset-context", "Hyperliquid per-asset context", "The live risk frame Hyperliquid publishes per perp: funding, open interest, mark and oracle price, premium and 24h notional volume.",
    ["market", "perp", "funding", "open-interest", "hyperliquid"],
    [HL_COIN],
    [["found", "boolean"], ["coin", "string"], ["funding", "string"], ["openInterest", "string"], ["markPx", "string"], ["oraclePx", "string"], ["midPx", "string"], ["premium", "string"], ["dayNtlVlm", "string"], ["dayBaseVlm", "string"], ["prevDayPx", "string"], ["impactPxs", "array"]],
    {found: true, coin: "BTC", funding: "0.0000125", openInterest: "39516.21646", markPx: "84112.0", oraclePx: "84121.0", midPx: "84111.5", premium: "-0.0001069887", dayNtlVlm: "3881787704.2451591492", dayBaseVlm: "46188.45348", prevDayPx: "84084.0", impactPxs: ["84111.0"]},
    { coin: "BTC" },
    async ({ coin }) => {
      const { d, stale, missing } = await hl("metaAndAssetCtxs", null, "metaCtx");
      if (missing) return mk("hyperliquid", { found: false, coin, reason: missing }, stale);
      const idx = (d?.[0]?.universe || []).findIndex((u) => u?.name === coin);
      const c = idx >= 0 ? d?.[1]?.[idx] : null;
      if (!c) return mk("hyperliquid", { found: false, coin, reason: "coin is not in the perp universe" }, stale);
      // impactPxs arrives as [] for a thinly-quoted book and [""] on some coins. Both are absent
      // answers, not data, and they must not be advertised as an array of prices in the OpenAPI.
      const impact = Array.isArray(c.impactPxs) ? c.impactPxs.filter((x) => x !== "" && x !== null && x !== undefined) : null;
      return mk("hyperliquid", { found: true, coin, funding: c.funding ?? null, openInterest: c.openInterest ?? null,
        markPx: c.markPx ?? null, oraclePx: c.oraclePx ?? null, midPx: c.midPx ?? null, premium: c.premium ?? null,
        dayNtlVlm: c.dayNtlVlm ?? null, dayBaseVlm: c.dayBaseVlm ?? null, prevDayPx: c.prevDayPx ?? null,
        impactPxs: impact && impact.length ? impact : null }, stale);
    }),
];

// ---- DefiLlama (TVL + priced history, keyless) ----------------------------------------------
const MK_LLAMA = [
  mr("/market/llama-chain-tvl-history", "Chain TVL history", "Daily total-value-locked history for one chain from DefiLlama's own series, downsampled to the window you ask for — the trend line, not a snapshot.",
    ["defi", "tvl", "history", "llama", "chain"],
    [A.oneOf("chain", ["Ethereum", "BSC", "Solana", "Arbitrum", "Base", "Polygon", "Optimism", "Avalanche"], { desc: "chain as DefiLlama names it (only measured names)" }),
     A.num("days", { max: 3650, default: 365n, desc: "daily points to return (max 3650)" })],
    [["found", "boolean"], ["chain", "string"], ["days", "integer"], ["count", "integer"], ["latestTvlUsd", "integer"], ["rows", "array"]],
    {found: true, chain: "Base", days: 3, count: 3, latestTvlUsd: 6183767664, rows: [{dateSec: 1790121600, iso: "2026-09-23T00:00:00.000Z", tvlUsd: 6262134022}]},
    { chain: "Base", days: "3" },
    async ({ chain, days }) => {
      const { d, stale } = await mj(`ll:tvlh:${chain}`, `${MK.llama}/v2/historicalChainTvl/${encodeURIComponent(chain)}`);
      const rows = (Array.isArray(d) ? d : []).slice(-narg(days, 365)).map((r) => ({ dateSec: nf(r.date),
        iso: r.date ? new Date(Number(r.date) * 1000).toISOString() : null, tvlUsd: Math.round(Number(r.tvl) || 0) }));
      return mk("defillama", { found: rows.length > 0, chain, days: narg(days, 365), count: rows.length,
        latestTvlUsd: rows.at(-1)?.tvlUsd ?? null, rows }, stale);
    }),
  mr("/market/llama-asset-price-history", "Token price history", "Hourly or daily USD price points for one token reference (network:address) from DefiLlama's coin API, with the symbol and confidence it attaches to the series.",
    ["price", "history", "token", "llama", "chart"],
    [A.coinRef(), A.oneOf("period", ["1h", "1d"], { desc: "point spacing" }),
     A.num("span", { max: 720, default: 48n, desc: "how many points (max 720)" })],
    [["found", "boolean"], ["ref", "string"], ["symbol", "string"], ["decimals", "integer"], ["confidence", "number"], ["period", "string"], ["count", "integer"], ["prices", "array"]],
    {found: true, ref: "base:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", symbol: "USDC", decimals: 6, confidence: 0.99, period: "1h", count: 3, prices: [{timestamp: 1790309440, iso: "2026-09-25T04:10:40.000Z", price: 0.9998113993380022}]},
    { ref: "base:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", period: "1h", span: "3" },
    async ({ ref, period, span }) => {
      const n = narg(span, 48);
      const { d, stale } = await mj(`ll:ch:${ref}:${period}:${Math.ceil(n / 24)}`, `${MK.coins}/chart/${encodeURIComponent(ref)}?span=${n}&period=${encodeURIComponent(period)}`);
      const key = Object.keys(d?.coins || {})[0], c = d?.coins?.[key];
      if (!c) return mk("defillama", { found: false, ref, reason: "DefiLlama has no series for that reference" }, stale);
      const prices = (c.prices || []).slice(-n).map((p) => ({ timestamp: nf(p.timestamp),
        iso: p.timestamp ? new Date(Number(p.timestamp) * 1000).toISOString() : null, price: nf(p.price) }));
      return mk("defillama", { found: prices.length > 0, ref: key, symbol: c.symbol ?? null, decimals: nf(c.decimals),
        confidence: nf(c.confidence), period, count: prices.length, prices }, stale);
    }),
  mr("/market/llama-price-snapshot", "Batch token prices", "Current USD price, symbol, decimals and confidence for up to 10 network:address references in one paid call — the cheapest way to mark a portfolio.",
    ["price", "batch", "token", "llama", "quote"],
    [A.refList()],
    [["found", "boolean"], ["requested", "integer"], ["priced", "integer"], ["prices", "object"], ["notPriced", "array"]],
    {found: true, requested: 2, priced: 2, prices: {"base:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": {symbol: "USDC", price: 0.999871682133581, decimals: 6, confidence: 0.99, timestamp: 1790317000}, "ethereum:0xdac17f958d2ee523a2206206994597c13d831ec7": {symbol: "USDT", price: 0.999847318398821, decimals: 6, confidence: 0.99, timestamp: 1790317000}}, notPriced: []},
    { refs: "base:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913,ethereum:0xdAC17F958D2ee523a2206206994597C13D831ec7" },
    async ({ refs }) => {
      const { d, stale } = await mj(`ll:pc:${refs.join("|").slice(0, 80)}`, `${MK.coins}/prices/current/${refs.map(encodeURIComponent).join(",")}`);
      const coins = d?.coins || {};
      const prices = {}, notPriced = [];
      for (const r of refs) {
        const c = coins[r];
        if (!c) { notPriced.push(r); continue; }
        prices[r] = { symbol: c.symbol ?? null, price: nf(c.price), decimals: nf(c.decimals),
          confidence: nf(c.confidence), timestamp: nf(c.timestamp) };
      }
      return mk("defillama", { found: Object.keys(prices).length > 0, requested: refs.length,
        priced: Object.keys(prices).length, prices, notPriced }, stale);
    }),
];

// ---- Bitcoin blockspace + long-run price ----------------------------------------------------
const MK_BTC = [
  mr("/market/btc-chain-tip", "Bitcoin chain tip", "The current Bitcoin block height as mempool.space sees it, plus the best tip hash — the two-second liveness check for anything Bitcoin-facing.",
    ["bitcoin", "block-height", "chain-tip", "mempool", "liveness"],
    [],
    [["height", "integer"], ["tipHash", "string"]],
    {height: 968514, tipHash: "0000000000000000000212506cfdddf8f0d74827d0286d751a6c4eebc4c2f6eb"},
    {},
    async () => {
      const { d, stale, host: mp } = await mj("mp:tip", `${MK.mempool}/blocks/tip/height`);
      const height = nf(d);
      if (height === null) throw new HttpError(502, "mempool.space returned no height");
      const h = await mj("mp:tiphash", `${MK.mempool}/blocks/tip/hash`).then((r) => String(r.d).trim()).catch(() => null);
      return mk(mp, { height, tipHash: h && /^[0-9a-f]{64}$/.test(h) ? h : null }, stale);
    }),
  mr("/market/btc-fee-estimates", "Bitcoin fee estimates", "The recommended sat-per-vbyte fee targets for the next blocks: fastest, half-hour, one-hour, economy and minimum.",
    ["bitcoin", "fees", "sat-per-vbyte", "mempool", "estimate"],
    [],
    [["fastestFee", "integer"], ["halfHourFee", "integer"], ["hourFee", "integer"], ["economyFee", "integer"], ["minimumFee", "integer"]],
    {fastestFee: 1, halfHourFee: 1, hourFee: 1, economyFee: 1, minimumFee: 1},
    {},
    async () => {
      const { d, stale, host: mp } = await mj("mp:fees", `${MK.mempool}/v1/fees/recommended`);
      return mk(mp, { fastestFee: nf(d?.fastestFee), halfHourFee: nf(d?.halfHourFee),
        hourFee: nf(d?.hourFee), economyFee: nf(d?.economyFee), minimumFee: nf(d?.minimumFee) }, stale,
        "sat/vByte, not sats per virtual kilobyte and not a USD figure");
    }),
  mr("/market/btc-block-projections", "Bitcoin next-block fee projections", "Per-block projection for the mempool's next ~8 blocks: size, transaction count, total fees, median fee and the fee-rate range that would make it.",
    ["bitcoin", "mempool", "fees", "projection", "blocks"],
    [A.num("limit", { max: 8, default: 8n, desc: "projected blocks to return (the venue publishes about 8)" })],
    [["found", "boolean"], ["count", "integer"], ["blocks", "array"]],
    {found: true, count: 2, blocks: [{position: 0, blockSize: 1751146, blockVSize: 997966, txCount: 6319, totalFees: 1004908, medianFee: 0.3526121205648873}]},
    { limit: "2" },
    async ({ limit }) => {
      const { d, stale, host: mp } = await mj("mp:mblocks", `${MK.mempool}/v1/fees/mempool-blocks`);
      const rows = (Array.isArray(d) ? d : []).slice(0, narg(limit, 8)).map((b, i) => ({ position: i,
        blockSize: nf(b.blockSize), blockVSize: nf(b.blockVSize), txCount: nf(b.nTx),
        totalFees: nf(b.totalFees), medianFee: nf(b.medianFee), feeRange: b.feeRange || [] }));
      return mk(mp, { found: rows.length > 0, count: rows.length, blocks: rows }, stale);
    }),
  mr("/market/btc-spot-prices", "Bitcoin spot price in fiat", "The reference BTC price in USD plus six other fiat currencies with the quote timestamp — as a Bitcoin-native explorer publishes it, not as a venue tape.",
    ["bitcoin", "price", "usd", "fiat", "mempool"],
    [],
    [["usd", "integer"], ["eur", "integer"], ["gbp", "integer"], ["cad", "integer"], ["chf", "integer"], ["aud", "integer"], ["jpy", "integer"], ["timeSec", "integer"]],
    {usd: 84093, eur: 73901, gbp: 63514, cad: 118852, chf: 69625, aud: 119733, jpy: 13310256, timeSec: 1790316905},
    {},
    async () => {
      const { d, stale, host: mp } = await mj("mp:prices", `${MK.mempool}/v1/prices`);
      return mk(mp, { usd: nf(d?.USD), eur: nf(d?.EUR), gbp: nf(d?.GBP), cad: nf(d?.CAD),
        chf: nf(d?.CHF), aud: nf(d?.AUD), jpy: nf(d?.JPY), timeSec: nf(d?.time) }, stale);
    }),
  mr("/market/btc-difficulty-adjustment", "Bitcoin difficulty retarget", "Where the next difficulty adjustment stands: percent progress, projected change, remaining blocks and time, the next retarget height and the average block time behind it.",
    ["bitcoin", "difficulty", "retarget", "mining", "mempool"],
    [],
    [["progressPercent", "number"], ["difficultyChange", "number"], ["remainingBlocks", "integer"], ["remainingTimeMs", "integer"], ["estimatedRetargetMs", "integer"], ["previousRetarget", "number"], ["previousTimeMs", "integer"], ["nextRetargetHeight", "integer"], ["timeAvgSec", "integer"], ["adjustedTimeAvgSec", "integer"], ["expectedBlocks", "number"]],
    {progressPercent: 41.36904761904761, difficultyChange: -2.7926262095139043, remainingBlocks: 1182, remainingTimeMs: 730448814, estimatedRetargetMs: 1791047586814, previousRetarget: 4.163398081310405, previousTimeMs: 1789801745, nextRetargetHeight: 969696, timeAvgSec: 617977, adjustedTimeAvgSec: 617977, expectedBlocks: 858.9883333333333},
    {},
    async () => {
      const { d, stale, host: mp } = await mj("mp:diff", `${MK.mempool}/v1/difficulty-adjustment`);
      return mk(mp, { progressPercent: nf(d?.progressPercent), difficultyChange: nf(d?.difficultyChange),
        remainingBlocks: nf(d?.remainingBlocks), remainingTimeMs: nf(d?.remainingTime),
        estimatedRetargetMs: nf(d?.estimatedRetargetDate), previousRetarget: nf(d?.previousRetarget),
        previousTimeMs: nf(d?.previousTime), nextRetargetHeight: nf(d?.nextRetargetHeight),
        timeAvgSec: nf(d?.timeAvg), adjustedTimeAvgSec: nf(d?.adjustedTimeAvg), expectedBlocks: nf(d?.expectedBlocks) }, stale);
    }),
  mr("/market/btc-recent-blocks", "Latest Bitcoin blocks", "The blocks a Bitcoin explorer has just indexed: height, hash, time, difficulty, transaction count, size and weight, with the mined fees and pool name when the explorer attaches them.",
    ["bitcoin", "blocks", "mining", "mempool", "chain"],
    [A.num("limit", { max: 15, default: 10n, desc: "blocks to return (the endpoint publishes about 15)" })],
    [["found", "boolean"], ["count", "integer"], ["tipHeight", "integer"], ["blocks", "array"]],
    {found: true, count: 2, tipHeight: 968514, blocks: [{height: 968514, id: "0000000000000000000212506cfdddf8f0d74827d0286d751a6c4eebc4c2f6eb", timeSec: 1790316941, iso: "2026-09-25T06:15:41.000Z", difficulty: 132757073449487.5, txCount: 5057}]},
    { limit: "2" },
    async ({ limit }) => {
      const { d, stale, host: mp } = await mj("mp:blocks", `${MK.mempool}/v1/blocks`);
      const all = (Array.isArray(d) ? d : []).map((b) => ({ height: nf(b.height), id: b.id, timeSec: nf(b.timestamp),
        iso: b.timestamp ? new Date(Number(b.timestamp) * 1000).toISOString() : null, difficulty: nf(b.difficulty),
        txCount: nf(b.tx_count), size: nf(b.size), weight: nf(b.weight), stale: b.stale ?? null,
        previousblockhash: b.previousblockhash ?? null, totalFees: nf(b.extras?.totalFees),
        medianFee: nf(b.extras?.medianFee), reward: nf(b.extras?.reward), avgFee: nf(b.extras?.avgFee),
        pool: b.extras?.pool?.name ?? null, coinbaseAddress: b.extras?.coinbaseAddress ?? null }));
      return mk(mp, { found: all.length > 0, count: Math.min(all.length, narg(limit, 10)),
        tipHeight: all[0]?.height ?? null, blocks: all.slice(0, narg(limit, 10)) }, stale);
    }),
  mr("/market/btc-mining-hashrate", "Bitcoin hashrate and difficulty series", "Network hashrate points and the difficulty-adjustment series over a bounded window, with the current hashrate and difficulty the explorer reports.",
    ["bitcoin", "hashrate", "difficulty", "mining", "mempool"],
    [A.oneOf("window", ["1m", "3m", "6m", "1y"], { desc: "history window (only the values measured)" }),
     A.num("limit", { max: 400, default: 60n, desc: "points per series to return (max 400)" })],
    [["found", "boolean"], ["window", "string"], ["currentHashrateHs", "string"], ["currentDifficulty", "number"], ["hashratePoints", "integer"], ["difficultyPoints", "integer"], ["hashrates", "array"], ["difficulty", "array"]],
    {found: true, window: "1m", currentHashrateHs: "937159489867462900000", currentDifficulty: 132757073449487.5, hashratePoints: 3, difficultyPoints: 2, hashrates: [{timeSec: 1790121600, avgHashrateHs: "934361833300531000000"}], difficulty: [{timeSec: 1788640367, height: 965664, difficulty: 127450789715843.1, adjustmentPct: 1.013064980506897}]},
    { window: "1m", limit: "3" },
    async ({ window, limit }) => {
      const { d, stale, host: mp } = await mj(`mp:hr:${window}`, `${MK.mempool}/v1/mining/hashrate/${encodeURIComponent(window)}`);
      const n = narg(limit, 60);
      const hashrates = (d?.hashrates || []).slice(-n).map((r) => ({ timeSec: nf(r.timestamp), avgHashrateHs: r.avgHashrate === undefined ? null : String(r.avgHashrate) }));
      const difficulty = (d?.difficulty || []).slice(-n).map((r) => ({ timeSec: nf(r.time), height: nf(r.height),
        difficulty: nf(r.difficulty), adjustmentPct: nf(r.adjustment) }));
      return mk(mp, { found: hashrates.length > 0 || difficulty.length > 0, window,
        currentHashrateHs: d?.currentHashrate === undefined ? null : String(d.currentHashrate),
        currentDifficulty: nf(d?.currentDifficulty), hashratePoints: hashrates.length, difficultyPoints: difficulty.length,
        hashrates, difficulty }, stale, "avgHashrateHs is hashes/second as a decimal string; exahash is that divided by 1e18");
    }),
  mr("/market/btc-network-stats", "Bitcoin network statistics", "One shot at the network's aggregate state: price, hash rate, difficulty, next retarget height, blocks and transactions in the last day, coins mined, fees collected and total supply.",
    ["bitcoin", "statistics", "network", "blockchain.info", "mining"],
    [],
    [["timestampMs", "integer"], ["marketPriceUsd", "number"], ["hashRateGh", "number"], ["difficulty", "integer"], ["nextRetargetHeight", "integer"], ["nTx", "integer"], ["nBlocksMined", "integer"], ["blocksSize", "integer"], ["minutesBetweenBlocks", "number"], ["totalBtcSats", "integer"], ["nBlocksTotal", "integer"], ["btcMinedSats", "integer"], ["totalFeesSats", "integer"], ["estimatedBtcSent", "integer"], ["totalBtcSent", "integer"], ["estimatedTxVolumeUsd", "number"], ["tradeVolumeBtc", "number"], ["tradeVolumeUsd", "number"]],
    {timestampMs: 1790317040000, marketPriceUsd: 84252, hashRateGh: 983309097545.7668, difficulty: 132757073449487, nextRetargetHeight: 969695, nTx: 706090, nBlocksMined: 149, blocksSize: 229821704, minutesBetweenBlocks: 9.1351, totalBtcSats: 2008910625000000, nBlocksTotal: 968514, btcMinedSats: 46562500000, totalFeesSats: -46562500000, estimatedBtcSent: 12709164113651, totalBtcSent: 117907759707462, estimatedTxVolumeUsd: 10707724949.033247, tradeVolumeBtc: 5093.53, tradeVolumeUsd: 429140089.56},
    {},
    async () => {
      const { d, stale } = await mj("bci:stats", `${MK.bci}/stats?format=json`);
      return mk("blockchain.info", { timestampMs: nf(d?.timestamp), marketPriceUsd: nf(d?.market_price_usd),
        hashRateGh: nf(d?.hash_rate), difficulty: nf(d?.difficulty), nextRetargetHeight: nf(d?.nextretarget),
        nTx: nf(d?.n_tx), nBlocksMined: nf(d?.n_blocks_mined), blocksSize: nf(d?.blocks_size),
        minutesBetweenBlocks: nf(d?.minutes_between_blocks), totalBtcSats: nf(d?.totalbc),
        nBlocksTotal: nf(d?.n_blocks_total), btcMinedSats: nf(d?.n_btc_mined), totalFeesSats: nf(d?.total_fees_btc),
        estimatedBtcSent: nf(d?.estimated_btc_sent), totalBtcSent: nf(d?.total_btc_sent),
        estimatedTxVolumeUsd: nf(d?.estimated_transaction_volume_usd), tradeVolumeBtc: nf(d?.trade_volume_btc),
        tradeVolumeUsd: nf(d?.trade_volume_usd) }, stale,
        "satoshi-denominated fields end in Sats; total_fees_btc is published negative by this endpoint and is reproduced as-is");
    }),
  mr("/market/btc-usd-price-history", "Bitcoin USD price history", "Daily BTC/USD closes back to the earliest point the explorer keeps, downsampled to a bounded number of points — a long-run price series without a key.",
    ["bitcoin", "price", "history", "usd", "blockchain.info"],
    [A.oneOf("timespan", ["6months", "1year", "5years", "all"], { desc: "history window (1month is rejected upstream and is therefore not offered)" }),
     A.num("limit", { max: 500, default: 120n, desc: "points to return (newest first slice, max 500)" })],
    [["found", "boolean"], ["name", "string"], ["unit", "string"], ["timespan", "string"], ["total", "integer"], ["count", "integer"], ["values", "array"]],
    {found: true, name: "Market Price (USD)", unit: "USD", timespan: "6months", total: 181, count: 3, values: [{timeSec: 1790121600, iso: "2026-09-23T00:00:00.000Z", usd: 86184.81}]},
    { timespan: "6months", limit: "3" },
    async ({ timespan, limit }) => {
      const { d, stale } = await mj(`bci:px:${timespan}`, `${MK.bci}/charts/market-price?timespan=${encodeURIComponent(timespan)}&format=json`);
      const n = narg(limit, 120);
      const all = (d?.values || []).map((v) => ({ timeSec: nf(v.x), iso: v.x ? new Date(Number(v.x) * 1000).toISOString() : null, usd: nf(v.y) }));
      return mk("blockchain.info", { found: all.length > 0, name: d?.name ?? null, unit: d?.unit ?? null, timespan,
        total: all.length, count: Math.min(all.length, n), values: all.slice(-n) }, stale);
    }),
];

// ---- Sentiment + prediction markets --------------------------------------------------------
const MK_SENTIMENT = [
  mr("/market/fear-greed-index", "Crypto fear and greed index", "The alternative.me fear-and-greed reading: index value, its label and the seconds until the next update, for today or a whole history back to 365 days.",
    ["sentiment", "fear-greed", "crypto", "index", "macro"],
    [A.num("limit", { max: 365, default: 1n, desc: "daily readings to return, newest first (max 365)" })],
    [["found", "boolean"], ["name", "string"], ["count", "integer"], ["latestValue", "integer"], ["latestClassification", "string"], ["timeUntilUpdateSec", "integer"], ["rows", "array"]],
    {found: true, name: "Fear and Greed Index", count: 3, latestValue: 71, latestClassification: "Greed", timeUntilUpdateSec: 63658, rows: [{value: 71, classification: "Greed", dateSec: 1790294400, iso: "2026-09-25T00:00:00.000Z", timeUntilUpdateSec: 63658}]},
    { limit: "3" },
    async ({ limit }) => {
      const { d, stale } = await mj(`fng:${narg(limit, 1)}`, `${MK.fng}?limit=${narg(limit, 1)}`);
      const rows = (d?.data || []).map((r) => ({ value: nf(r.value), classification: r.value_classification ?? null,
        dateSec: nf(r.timestamp), iso: r.timestamp ? new Date(Number(r.timestamp) * 1000).toISOString() : null,
        timeUntilUpdateSec: nf(r.time_until_update) }));
      return mk("alternative.me", { found: rows.length > 0, name: d?.name ?? null, count: rows.length,
        latestValue: rows[0]?.value ?? null, latestClassification: rows[0]?.classification ?? null,
        timeUntilUpdateSec: rows[0]?.timeUntilUpdateSec ?? null, rows,
        ...(d?.metadata?.error ? { upstreamError: d.metadata.error } : {}) }, stale,
        "0 is extreme fear and 100 extreme greed; only the newest reading carries time_until_update");
    }),
];

const MK_POLY = [
  mr("/market/poly-markets", "Polymarket active markets", "Open prediction markets ranked by the venue's own 24h volume or liquidity: question, outcomes with prices, volume, liquidity, spread, best bid/ask and the end date.",
    ["prediction-market", "polymarket", "odds", "volume", "events"],
    [A.oneOf("order", ["volume24hr", "liquidity"], { desc: "which venue field to rank by" }),
     A.num("limit", { max: 20, default: 10n, desc: "markets to return (max 20)" })],
    [["found", "boolean"], ["order", "string"], ["count", "integer"], ["rows", "array"]],
    {found: true, order: "volume24hr", count: 3, rows: [{id: "559704", question: "Will Mitch Landrieu win the 2028 Democratic presidential nomination?", slug: "will-mitch-landrieu-win-the-2028-democratic-presidential-nomination", conditionId: "0xd0e58ada317f9778a221592cfed03405b235b137c8dd916817a39b72bf6dc19a", outcomes: ["Yes"], outcomePrices: ["0.0015"]}]},
    { order: "volume24hr", limit: "3" },
    async ({ order, limit }) => {
      const n = narg(limit, 10);
      const { d, stale, missing } = await mj(`pm:mk:${order}:${n}`, `${MK.poly}/markets?closed=false&limit=${n}&order=${encodeURIComponent(order)}&ascending=false`, null, { tolerate: true });
      if (missing) return mk("polymarket", { count: 0, rows: [], reason: missing }, stale);
      const rows = (Array.isArray(d) ? d : []).map((m) => ({ id: m.id, question: m.question, slug: m.slug,
        conditionId: m.conditionId, outcomes: jsonArr(m.outcomes), outcomePrices: jsonArr(m.outcomePrices),
        volume24hr: nf(m.volume24hr), volumeNum: nf(m.volumeNum), liquidity: nf(m.liquidity),
        liquidityNum: nf(m.liquidityNum), spread: nf(m.spread), bestBid: nf(m.bestBid), bestAsk: nf(m.bestAsk),
        lastTradePrice: nf(m.lastTradePrice), oneDayPriceChange: nf(m.oneDayPriceChange),
        endDate: m.endDate ?? null, active: m.active ?? null, closed: m.closed ?? null,
        acceptingOrders: m.acceptingOrders ?? null, enableOrderBook: m.enableOrderBook ?? null,
        competitive: nf(m.competitive), umaResolutionStatuses: jsonArr(m.umaResolutionStatuses) }));
      return mk("polymarket", { found: rows.length > 0, order, count: rows.length, rows }, stale,
        "outcomes and outcomePrices are JSON-encoded strings at the venue and are decoded into arrays here");
    }),
  mr("/market/poly-market-detail", "Polymarket market detail", "Everything Polymarket's API records for one market id: the question and description, resolution source and resolver, outcomes and prices, the whole volume and liquidity series it reports, fees and the CLOB token ids.",
    ["prediction-market", "polymarket", "detail", "resolution", "odds"],
    [A.text("id", /^\d{1,12}$/, { example: "559681", desc: "Polymarket numeric market id" })],
    [["found", "boolean"], ["id", "string"], ["question", "string"], ["slug", "string"], ["conditionId", "string"], ["description", "string"], ["resolutionSource", "string"], ["outcomes", "array"], ["outcomePrices", "array"], ["volumeNum", "number"], ["volume24hr", "number|null"], ["liquidityNum", "number|null"], ["spread", "number"], ["bestBid", "number|null"], ["bestAsk", "number"], ["lastTradePrice", "number"], ["oneDayPriceChange", "number|null"], ["endDate", "string"], ["startDate", "string"], ["active", "boolean"], ["closed", "boolean"], ["acceptingOrders", "boolean"], ["enableOrderBook", "boolean"], ["orderMinSize", "integer"], ["resolutionStatuses", "array"], ["resolvedBy", "string"], ["feeType", "string"], ["makerBaseFee", "integer"], ["takerBaseFee", "integer"], ["umaBond", "integer"], ["umaReward", "integer"], ["clobTokenIds", "array"]],
    {found: true, id: "4464920", question: "Will Norway win on 2026-09-24?", slug: "unl-nor-den-2026-09-24-nor", conditionId: "0x80c7ab790a5ab37e11c79a5a658d729ac29e6e17aa2d3fc859e4a78c0d896369", description: "In the upcoming game, scheduled for Septembe…", resolutionSource: "https://www.uefa.com/uefanationsleague/", outcomes: ["Yes"], outcomePrices: ["1"], volumeNum: 13521950.763898998, volume24hr: 13277999.705529915, liquidityNum: null, spread: 0.001, bestBid: 0.999, bestAsk: 1, lastTradePrice: 0.999, oneDayPriceChange: 0.4445, endDate: "2026-09-24T18:45:00Z", startDate: "2026-09-11T10:00:17Z", active: true, closed: true, acceptingOrders: false, enableOrderBook: true, orderMinSize: 5, resolutionStatuses: ["proposed"], resolvedBy: "0x69c47De9D4D3Dad79590d61b9e05918E03775f24", feeType: "sports_fees_v3", makerBaseFee: 1000, takerBaseFee: 1000, umaBond: 250, umaReward: 0.8, clobTokenIds: ["23305969272951306317157739183583008201155714…"]},
    { id: "559681" },
    async ({ id }) => {
      const { d, stale, missing } = await mjLookup(`pm:md:${id}`, `${MK.poly}/markets/${encodeURIComponent(id)}`, null, { tolerate: true });
      if (missing) return mk("polymarket", { found: false, id, reason: "Polymarket has no market with that id" }, stale);
      if (!d?.id) return mk("polymarket", { found: false, id, reason: missing || "empty market object" }, stale);
      // Key set and types read off .tmp-check/poly-fields.txt (market 4464920). Two corrections against
      // the previous version: `outcomes`, `outcomePrices` and `clobTokenIds` arrive as JSON-encoded
      // STRINGS, so passing them through handed buyers a string under a schema that said array; and
      // `events` is not a field of /markets/{id} at all, so that key could never be filled.
      return mk("polymarket", { found: true, id: d.id, question: d.question ?? null, slug: d.slug ?? null,
        conditionId: d.conditionId ?? null, description: typeof d.description === "string" ? d.description.slice(0, 600) : null,
        resolutionSource: d.resolutionSource ?? null,
        outcomes: jsonArr(d.outcomes), outcomePrices: jsonArr(d.outcomePrices), volumeNum: nf(d.volumeNum),
        volume24hr: nf(d.volume24hr), liquidityNum: nf(d.liquidityNum), spread: nf(d.spread),
        bestBid: nf(d.bestBid), bestAsk: nf(d.bestAsk), lastTradePrice: nf(d.lastTradePrice),
        oneDayPriceChange: nf(d.oneDayPriceChange), endDate: d.endDate ?? null, startDate: d.startDate ?? null,
        active: d.active ?? null, closed: d.closed ?? null, acceptingOrders: d.acceptingOrders ?? null,
        enableOrderBook: d.enableOrderBook ?? null, orderMinSize: nf(d.orderMinSize),
        resolutionStatuses: jsonArr(d.umaResolutionStatuses), resolvedBy: d.resolvedBy ?? null,
        feeType: d.feeType ?? null, makerBaseFee: nf(d.makerBaseFee), takerBaseFee: nf(d.takerBaseFee),
        umaBond: nf(d.umaBond), umaReward: nf(d.umaReward), clobTokenIds: jsonArr(d.clobTokenIds) }, stale);
    }),
  mr("/market/poly-tags", "Polymarket tag list", "The topic tags Polymarket itself puts on markets, with each tag's id and slug — the vocabulary to filter or classify a prediction-market feed with.",
    ["prediction-market", "polymarket", "tags", "taxonomy", "metadata"],
    [A.num("limit", { max: 50, default: 20n, desc: "tags to return (max 50)" })],
    [["found", "boolean"], ["count", "integer"], ["rows", "array"]],
    {found: true, count: 3, rows: [{id: "101867", label: "product marekt fit", slug: "product-marekt-fit", createdAt: "2025-02-18T16:58:25.464578Z", updatedAt: "2026-04-17T17:23:11.67487Z"}]},
    { limit: "3" },
    async ({ limit }) => {
      const { d, stale, missing } = await mj(`pm:tg:${narg(limit, 20)}`, `${MK.poly}/tags?limit=${narg(limit, 20)}`, null, { tolerate: true });
      if (missing) return mk("polymarket", { count: 0, rows: [], reason: missing }, stale);
      const rows = (Array.isArray(d) ? d : []).map((t) => ({ id: t.id, label: t.label ?? null, slug: t.slug ?? null,
        createdAt: t.createdAt ?? null, updatedAt: t.updatedAt ?? null }));
      return mk("polymarket", { found: rows.length > 0, count: rows.length, rows }, stale,
        "labels are reproduced exactly as Polymarket stores them, including its own typos");
    }),
];

const MK_DEX = [
  mr("/market/dex-token-pairs", "Every pool holding a token", "All DEX pools DexScreener knows for one token address across chains, each with price, liquidity, 24h volume, trade counts, price change, FDV and market cap.",
    ["dex", "pairs", "liquidity", "dexscreener", "token"],
    [A.text("address", /^(0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/, { example: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", desc: "token address, EVM 0x.. or Solana base58 mint" }),
     A.num("limit", { max: 30, default: 10n, desc: "pools to return, most liquid first (max 30)" })],
    [["found", "boolean"], ["address", "string"], ["count", "integer"], ["pools", "integer"], ["rows", "array"]],
    {found: true, address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", count: 3, pools: 30, rows: [{chainId: "base", dexId: "aerodrome", pairAddress: "0x6cDcb1C4A4D1C3C6d054b27AC5B77e89eAFb971d", labels: null, baseToken: {address: "0x940181a94A35A4569E4529A3CDfB74e38FD98631", name: "Aerodrome", symbol: "AERO"}, quoteToken: {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", name: "USD Coin", symbol: "USDC"}}]},
    { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", limit: "3" },
    async ({ address, limit }) => {
      const { d, stale } = await mj(`dx:tk:${address.slice(0, 24)}`, `${MK.dex}/latest/dex/tokens/${encodeURIComponent(address)}`);
      const rows = (d?.pairs || []).map((p) => ({ chainId: p.chainId, dexId: p.dexId, pairAddress: p.pairAddress,
        labels: p.labels ?? null, baseToken: { address: p.baseToken?.address, name: p.baseToken?.name, symbol: p.baseToken?.symbol },
        quoteToken: { address: p.quoteToken?.address, name: p.quoteToken?.name, symbol: p.quoteToken?.symbol },
        priceUsd: p.priceUsd ?? null, priceNative: p.priceNative ?? null, liquidityUsd: nf(p.liquidity?.usd),
        liquidityBase: nf(p.liquidity?.base), volume24h: nf(p.volume?.h24), volume1h: nf(p.volume?.h1),
        txns24h: p.txns?.h24 ?? null, priceChange24h: nf(p.priceChange?.h24), priceChange1h: nf(p.priceChange?.h1),
        fdv: nf(p.fdv), marketCap: nf(p.marketCap), pairCreatedAtMs: nf(p.pairCreatedAt), url: p.url ?? null }));
      rows.sort((a, b) => (b.liquidityUsd ?? 0) - (a.liquidityUsd ?? 0));
      return mk("dexscreener", { found: rows.length > 0, address, count: Math.min(rows.length, narg(limit, 10)),
        pools: rows.length, rows: rows.slice(0, narg(limit, 10)) }, stale);
    }),
  mr("/market/dex-pair-detail", "One DEX pool in full", "Everything DexScreener publishes for a single pool: the pair's chain, dex and label, price in USD and native, liquidity split, volume and buy/sell counts per window, and 5m/1h/6h/24h price change.",
    ["dex", "pair", "liquidity", "dexscreener", "pool"],
    [A.text("chain", /^[a-z][a-z0-9-]{1,19}$/, { example: "base", desc: "DexScreener chain id (base, ethereum, solana, …)" }),
     A.text("pair", /^(0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/, { example: "0x5D0bC342178C8Fe2c2f9A9fcC9D52555C99936db", desc: "pool / pair address on that chain" })],
    [["found", "boolean"], ["chain", "string"], ["pair", "string"], ["chainId", "string"], ["dexId", "string"], ["pairAddress", "string"], ["labels", "array"], ["baseToken", "object"], ["quoteToken", "object"], ["priceUsd", "string"], ["priceNative", "string"], ["liquidityUsd", "number"], ["liquidityBase", "number"], ["liquidityQuote", "integer"], ["volume", "object"], ["txns", "object"], ["priceChange", "object"], ["fdv", "integer"], ["marketCap", "integer"], ["pairCreatedAtMs", "integer|null"], ["url", "string"]],
    {found: true, chain: "base", pair: "0x5D0bC342178C8Fe2c2f9A9fcC9D52555C99936db", chainId: "base", dexId: "quickswap", pairAddress: "0x5D0bC342178C8Fe2c2f9A9fcC9D52555C99936db", labels: ["v4"], baseToken: {address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", name: "USD Coin", symbol: "USDC"}, quoteToken: {address: "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA", name: "USD Base Coin", symbol: "USDbC"}, priceUsd: "0.9999", priceNative: "0.9999", liquidityUsd: 109432.96, liquidityBase: 65090, liquidityQuote: 44348, volume: {h24: 83826.14, h6: 2667.67, h1: 184.04, m5: 0.52}, txns: {m5: {buys: 0, sells: 1}, h1: {buys: 0, sells: 9}, h6: {buys: 7, sells: 16}, h24: {buys: 271, sells: 182}}, priceChange: {}, fdv: 3697073861, marketCap: 60895772293, pairCreatedAtMs: 1752584457000, url: "https://dexscreener.com/base/0x5d0bc342178c8fe2c2f9a9fcc9d52555c99936db"},
    { chain: "ethereum", pair: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc" },
    async ({ chain, pair }) => {
      const { d, stale } = await mjLookup(`dx:pr:${chain}:${pair.slice(0, 24)}`, `${MK.dex}/latest/dex/pairs/${encodeURIComponent(chain)}/${encodeURIComponent(pair)}`);
      const p = d?.pair || (Array.isArray(d?.pairs) ? d.pairs[0] : null);
      if (!p) return mk("dexscreener", { found: false, chain, pair, reason: "no pool at that address on that chain" }, stale);
      return mk("dexscreener", { found: true, chain, pair, chainId: p.chainId ?? null, dexId: p.dexId ?? null,
        pairAddress: p.pairAddress ?? null, labels: p.labels ?? null,
        baseToken: { address: p.baseToken?.address, name: p.baseToken?.name, symbol: p.baseToken?.symbol },
        quoteToken: { address: p.quoteToken?.address, name: p.quoteToken?.name, symbol: p.quoteToken?.symbol },
        priceUsd: p.priceUsd ?? null, priceNative: p.priceNative ?? null,
        liquidityUsd: nf(p.liquidity?.usd), liquidityBase: nf(p.liquidity?.base), liquidityQuote: nf(p.liquidity?.quote),
        volume: p.volume ?? null, txns: p.txns ?? null, priceChange: p.priceChange ?? null,
        fdv: nf(p.fdv), marketCap: nf(p.marketCap), pairCreatedAtMs: nf(p.pairCreatedAt), url: p.url ?? null }, stale);
    }),
  mr("/market/dex-boosted-tokens", "Boosted DEX tokens", "The tokens currently promoted on DexScreener, with the chain, token address, the description and links the submitter provided and the boost amount and timing — what is being pushed, not what has liquidity.",
    ["dex", "trending", "boost", "dexscreener", "promoted"],
    [A.num("limit", { max: 30, default: 15n, desc: "entries to return (max 30)" })],
    [["found", "boolean"], ["count", "integer"], ["rows", "array"]],
    {found: true, count: 3, rows: [{chainId: "solana", tokenAddress: "BwGU1xFkXuKTXeuAFP8CF5v15cHKiJiGCCQUH8cXpump", dexId: null, pairAddress: null, url: "https://dexscreener.com/solana/bwgu1xfkxuktx…", totalAmount: 30}]},
    { limit: "3" },
    async ({ limit }) => {
      const { d, stale } = await mj("dx:bo", `${MK.dex}/token-boosts/latest/v1`);
      const rows = (Array.isArray(d) ? d : []).slice(0, narg(limit, 15)).map((b) => ({ chainId: b.chainId ?? null,
        tokenAddress: b.tokenAddress ?? null, dexId: b.dexId ?? null, pairAddress: b.pairAddress ?? null,
        url: b.url ?? null, totalAmount: nf(b.totalAmount), amount: nf(b.amount),
        boostedAtMs: nf(b.boostedAt), links: b.links ?? null }));
      return mk("dexscreener", { found: rows.length > 0, count: rows.length, rows }, stale,
        "description, icon and header fields are omitted on purpose: they are submitter-supplied marketing copy, not market data");
    }),
];

const MK_JUP = [
  mr("/market/jup-token-prices", "Jupiter USD prices by mint", "Current USD price, 24h change, liquidity, decimals and the block the quote came from for up to 20 Solana mints, in one call — with an explicit list of which mints returned nothing.",
    ["solana", "price", "jupiter", "token", "quote"],
    [A.mints()],
    [["found", "boolean"], ["requested", "integer"], ["priced", "integer"], ["prices", "object"], ["notPriced", "array"]],
    {found: true, requested: 2, priced: 2, prices: {So11111111111111111111111111111111111111112: {usdPrice: 116.41532663368359, nativePrice: null, decimals: 9, priceChange24h: 1.1113183792705386, liquidity: 948322474.2373089, blockId: 450269615}, EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: {usdPrice: 0.999871682133581, nativePrice: null, decimals: 6, priceChange24h: 0.0005035641152582438, liquidity: 466167203.14396363, blockId: 450269615}}, notPriced: []},
    { mints: "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" },
    async ({ mints }) => {
      const { d, stale } = await mj(`jp:px:${mints.length}:${mints[0].slice(0, 12)}`, `${MK.jup}/price/v3?ids=${mints.join(",")}`);
      const prices = {}, notPriced = [];
      for (const m of mints) {
        const q = d?.[m];
        if (!q) { notPriced.push(m); continue; }
        prices[m] = { usdPrice: nf(q.usdPrice), nativePrice: q.nativePrice === undefined ? null : { value: nf(q.nativePrice?.value), mintSymbol: q.nativePrice?.mintSymbol ?? null },
          decimals: nf(q.decimals), priceChange24h: nf(q.priceChange24h), liquidity: nf(q.liquidity),
          blockId: nf(q.blockId), createdAt: q.createdAt ?? null };
      }
      return mk("jupiter", { found: Object.keys(prices).length > 0, requested: mints.length,
        priced: Object.keys(prices).length, prices, notPriced }, stale,
        "a mint missing from the response is not priced by Jupiter; it is reported in notPriced rather than as zero");
    }),
  mr("/market/jup-token-search", "Jupiter token search", "Solana tokens matching a name or symbol query, with market cap, FDV, liquidity, holder count, price-change and volume statistics and Jupiter's own audit flags.",
    ["solana", "search", "jupiter", "token", "discovery"],
    [A.text("query", /^[A-Za-z0-9][A-Za-z0-9 ._\/-]{0,31}$/, { example: "bonk", maxLen: 32, desc: "token name, symbol or mint prefix to search for" }),
     A.num("limit", { max: 20, default: 8n, desc: "tokens to return (max 20)" })],
    [["found", "boolean"], ["query", "string"], ["count", "integer"], ["rows", "array"]],
    {found: true, query: "bonk", count: 2, rows: [{mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", name: "Bonk", symbol: "Bonk", decimals: 5, dev: "9AhKqLR67hwapvG8SA2JFXaCshXc9nALJjpKaHZrsbkw", usdPrice: 0.000003625398908103317}]},
    { query: "bonk", limit: "2" },
    async ({ query, limit }) => {
      const { d, stale, missing } = await mj(`jp:se:${query}`, `${MK.jup}/tokens/v2/search?query=${encodeURIComponent(query)}`, null, { tolerate: true });
      if (missing) return mk("jupiter", { count: 0, rows: [], query, reason: missing }, stale);
      const rows = (Array.isArray(d) ? d : []).slice(0, narg(limit, 8)).map((t) => jupToken(t));
      return mk("jupiter", { found: rows.length > 0, query, count: rows.length, rows }, stale);
    }),
  mr("/market/jup-new-tokens", "Newest Solana tokens", "The most recently listed tokens on Jupiter's token API: mint, name, supply, market cap, liquidity, launch pool and the audit flags Jupiter attaches — a launch feed, not a recommendation.",
    ["solana", "new-tokens", "jupiter", "launch", "listing"],
    [A.num("limit", { max: 30, default: 15n, desc: "tokens to return (max 30)" })],
    [["found", "boolean"], ["count", "integer"], ["rows", "array"]],
    {found: true, count: 3, rows: [{mint: "GvmeNhDKFFnLvMFVzU9rDV5XGRMMLpgLwSxYutmqpump", name: "CARD DECLINED", symbol: "$DECLINED", decimals: 6, dev: "CxBqfdBo1zrNARTeJAKXUznxDADxs3KYrtTGyVkMWKng", usdPrice: 0.000003952958880078313}]},
    { limit: "3" },
    async ({ limit }) => {
      const { d, stale, missing } = await mj("jp:rc", `${MK.jup}/tokens/v2/recent`, null, { tolerate: true });
      if (missing) return mk("jupiter", { count: 0, rows: [], reason: missing }, stale);
      const rows = (Array.isArray(d) ? d : []).slice(0, narg(limit, 15)).map((t) => jupToken(t));
      return mk("jupiter", { found: rows.length > 0, count: rows.length, rows }, stale,
        "recently listed is the venue's own ordering; nothing here implies any check beyond the audit flags it publishes");
    }),
];
const jupToken = (t) => ({ mint: t.id ?? null, name: t.name ?? null, symbol: t.symbol ?? null,
  decimals: nf(t.decimals), dev: t.dev ?? null, usdPrice: nf(t.usdPrice), marketCap: nf(t.mcap), fdv: nf(t.fdv),
  liquidity: nf(t.liquidity), circSupply: nf(t.circSupply), totalSupply: nf(t.totalSupply),
  holderCount: nf(t.holderCount), tokenProgram: t.tokenProgram ?? null, isVerified: t.isVerified ?? null,
  organicScore: nf(t.organicScore), organicScoreLabel: t.organicScoreLabel ?? null, tags: t.tags ?? null,
  stats24h: t.stats24h ? { priceChange: nf(t.stats24h.priceChange), buyVolume: nf(t.stats24h.buyVolume),
    sellVolume: nf(t.stats24h.sellVolume), numBuys: nf(t.stats24h.numBuys), numSells: nf(t.stats24h.numSells),
    numTraders: nf(t.stats24h.numTraders) } : null,
  audit: t.audit ? { mintAuthorityDisabled: t.audit.mintAuthorityDisabled ?? null,
    freezeAuthorityDisabled: t.audit.freezeAuthorityDisabled ?? null,
    topHoldersPercentage: nf(t.audit.topHoldersPercentage), devMints: nf(t.audit.devMints) } : null,
  firstPool: t.firstPool ? { id: t.firstPool.id ?? null, createdAt: t.firstPool.createdAt ?? null } : null,
  launchpad: t.launchpad ?? null, createdAt: t.createdAt ?? null, updatedAt: t.updatedAt ?? null });

// ---- Blockscout explorers (verified-contract metadata, keyless) ------------------------------
const SCOUT_CHAIN = A.oneOf("chain", ["base", "ethereum"], { desc: "which Blockscout explorer to ask" });
const scoutHost = (c) => MK.scout[c] || MK.scout.base;
const SCOUT_ADDR = A.address({ name: "address" });
const MK_SCOUT = [
  mr("/market/scout-address-profile", "Explorer address profile", "What a Blockscout explorer knows about an address: native balance and USD rate, whether it is a verified contract, its name, proxy implementation, ENS name, holder/token flags and the token record when the address itself is a token.",
    ["explorer", "address", "contract", "verification", "blockscout"],
    [SCOUT_CHAIN, SCOUT_ADDR],
    [["found", "boolean"], ["chain", "string"], ["address", "string"], ["isContract", "boolean"], ["isVerified", "boolean"], ["isScam", "boolean"], ["reputation", "string"], ["name", "string|null"], ["proxyType", "string"], ["balanceWei", "string"], ["exchangeRateUsd", "number"], ["balanceUpdatedAtBlock", "integer"], ["ensDomainName", "string|null"], ["creatorAddress", "string|null"], ["creationTransactionHash", "string|null"], ["creationStatus", "string"], ["implementations", "array"], ["token", "object|null"], ["hasTokens", "boolean"], ["hasTokenTransfers", "boolean"], ["hasLogs", "boolean"], ["publicTags", "array"]],
    {found: true, chain: "base", address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", isContract: true, isVerified: true, isScam: false, reputation: "ok", name: "USD Coin", proxyType: "eip1967_oz", balanceWei: "9800646158085843", exchangeRateUsd: 2678.29, balanceUpdatedAtBlock: 51763733, ensDomainName: null, creatorAddress: "0x6aAFF8af0ae8017725312C388bA3745dfE91185B", creationTransactionHash: "0x8aa214f98bcf2984add809d10232135cccc4d6ab97d8477e66475d8bf68def34", creationStatus: "success", implementations: [{address: "0x2Ce6311ddAE708829bc0784C967b7d77D19FD779", name: "FiatTokenV2_2"}], token: {name: "USDC", symbol: "USDC", type: "ERC-20", decimals: 6, holders: 12866329, totalSupply: "4294801494454962"}, hasTokens: true, hasTokenTransfers: true, hasLogs: true, publicTags: []},
    { chain: "base", address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
    async ({ chain, address }) => {
      const { d, stale, missing } = await mjLookup(`bsk:a:${chain}:${address.slice(0, 14)}`, `${scoutHost(chain)}/api/v2/addresses/${encodeURIComponent(address)}`);
      if (missing || !d) return mk("blockscout", { found: false, chain, address, reason: "the explorer has no record for that address" }, stale);
      const tk = d.token;
      return mk("blockscout", { found: true, chain, address: d.hash ?? address, isContract: d.is_contract ?? null,
        isVerified: d.is_verified ?? null, isScam: d.is_scam ?? null, reputation: d.reputation ?? null,
        name: d.name ?? null, proxyType: d.proxy_type ?? null, balanceWei: d.coin_balance ?? null,
        exchangeRateUsd: nf(d.exchange_rate), balanceUpdatedAtBlock: nf(d.block_number_balance_updated_at),
        ensDomainName: d.ens_domain_name ?? null, creatorAddress: d.creator_address_hash ?? null,
        creationTransactionHash: d.creation_transaction_hash ?? null, creationStatus: d.creation_status ?? null,
        implementations: (d.implementations || []).map((i) => ({ address: i.address_hash ?? null, name: i.name ?? null })),
        token: tk ? { name: tk.name ?? null, symbol: tk.symbol ?? null, type: tk.type ?? null,
          decimals: nf(tk.decimals), holders: nf(tk.holders_count), totalSupply: tk.total_supply ?? null,
          circulatingMarketCap: nf(tk.circulating_market_cap), volume24h: nf(tk.volume_24h),
          exchangeRateUsd: nf(tk.exchange_rate) } : null,
        hasTokens: d.has_tokens ?? null, hasTokenTransfers: d.has_token_transfers ?? null,
        hasLogs: d.has_logs ?? null, publicTags: (d.public_tags || []).map((t) => t?.display_name ?? t).filter(Boolean) }, stale);
    }),
  mr("/market/scout-token-profile", "Explorer token profile", "The explorer's own record for one ERC-20/721 token: name, symbol, type, decimals, holder count, total supply, circulating market cap, 24h volume and the USD exchange rate it quotes.",
    ["explorer", "token", "metadata", "supply", "blockscout"],
    [SCOUT_CHAIN, SCOUT_ADDR],
    [["found", "boolean"], ["chain", "string"], ["address", "string"], ["name", "string"], ["symbol", "string"], ["type", "string"], ["decimals", "integer"], ["holders", "integer"], ["totalSupply", "string"], ["circulatingMarketCap", "number"], ["volume24h", "number"], ["exchangeRateUsd", "number"], ["reputation", "string"], ["iconUrl", "string"]],
    {found: true, chain: "ethereum", address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", name: "Tether", symbol: "USDT", type: "ERC-20", decimals: 6, holders: 17070882, totalSupply: "88304342264551152", circulatingMarketCap: 183738833507.56424, volume24h: 67893763218.071495, exchangeRateUsd: 0.999787, reputation: "ok", iconUrl: "https://assets.coingecko.com/coins/images/32…"},
    { chain: "ethereum", address: "0xdAC17F958D2ee523a2206206994597C13D831ec7" },
    async ({ chain, address }) => {
      const { d, stale, missing } = await mjLookup(`bsk:t:${chain}:${address.slice(0, 14)}`, `${scoutHost(chain)}/api/v2/tokens/${encodeURIComponent(address)}`);
      if (missing || !d) return mk("blockscout", { found: false, chain, address, reason: "no token record at that address on that explorer" }, stale);
      return mk("blockscout", { found: true, chain, address: d.address_hash ?? address, name: d.name ?? null,
        symbol: d.symbol ?? null, type: d.type ?? null, decimals: nf(d.decimals), holders: nf(d.holders_count),
        // `circulating_supply` answered null for every token probed (USDT and PEPE on Ethereum, USDC on
        // Base — .tmp-check/venue-field-types.txt), so the route stopped publishing a supply figure it
        // can only ever leave blank; `totalSupply` and the venue's own market cap carry the weight.
        totalSupply: d.total_supply ?? null,
        circulatingMarketCap: nf(d.circulating_market_cap), volume24h: nf(d.volume_24h),
        exchangeRateUsd: nf(d.exchange_rate), reputation: d.reputation ?? null, iconUrl: d.icon_url ?? null }, stale);
    }),
  mr("/market/scout-chain-stats", "Explorer chain statistics", "One explorer's view of its chain right now: addresses, blocks and transactions all-time and today, gas price tiers in gwei, average block time, market cap, coin price and network utilisation.",
    ["explorer", "chain", "statistics", "gas", "blockscout"],
    [SCOUT_CHAIN],
    [["found", "boolean"], ["chain", "string"], ["totalAddresses", "integer"], ["totalBlocks", "integer"], ["totalTransactions", "integer"], ["transactionsToday", "integer"], ["gasUsedToday", "string"], ["gasPricesGwei", "object"], ["averageBlockTimeMs", "integer"], ["coinPriceUsd", "number"], ["coinPriceChangePct", "number|null"], ["marketCapUsd", "number"], ["networkUtilizationPct", "number"], ["gasPricesUpdatedAt", "string"]],
    {found: true, chain: "ethereum", totalAddresses: 731137486, totalBlocks: 26052366, totalTransactions: 3766395065, transactionsToday: 1831147, gasUsedToday: "216292917098", gasPricesGwei: {slow: 0.21, average: 0.51, fast: 1.88}, averageBlockTimeMs: 12000, coinPriceUsd: 2673.98, coinPriceChangePct: -0.5, marketCapUsd: 326436551336.15936, networkUtilizationPct: 53.246930652823906, gasPricesUpdatedAt: "2026-09-25T06:19:05.366245Z"},
    { chain: "base" },
    async ({ chain }) => {
      const { d, stale, missing } = await mjLookup(`bsk:s:${chain}`, `${scoutHost(chain)}/api/v2/stats`);
      if (missing || !d) return mk("blockscout", { found: false, chain, reason: "that explorer returned no statistics" }, stale);
      return mk("blockscout", { found: true, chain, totalAddresses: nf(d.total_addresses), totalBlocks: nf(d.total_blocks),
        totalTransactions: nf(d.total_transactions), transactionsToday: nf(d.transactions_today),
        gasUsedToday: d.gas_used_today ?? null, gasPricesGwei: { slow: nf(d.gas_prices?.slow),
          average: nf(d.gas_prices?.average), fast: nf(d.gas_prices?.fast) },
        averageBlockTimeMs: nf(d.average_block_time), coinPriceUsd: nf(d.coin_price),
        coinPriceChangePct: nf(d.coin_price_change_percentage), marketCapUsd: nf(d.market_cap),
        networkUtilizationPct: nf(d.network_utilization_percentage),
        // `tvl` answered null from both explorers this route serves (base and ethereum — probed against
        // six Blockscout hosts, only gnosis carries it) and `gasPricesUpdatedAt` is the venue's own
        // staleness stamp, so the route stopped publishing a TVL figure it can never fill.
        gasPricesUpdatedAt: nf(d.gas_prices_updated_timestamp),
        gasPricesUpdatedAt: d.gas_price_updated_at ?? null }, stale,
        "gas_prices are published in gwei by Blockscout and are reproduced without conversion");
    }),
];

// --------------------------------------------------------------------------------
// RAIL INTELLIGENCE — the only thing on this origin that is not a re-read of public data.
//
// Everything above answers a question about crypto markets, and every other seller on x402 answers the same
// family of questions, which is exactly why measured demand for those routes is thin. This band answers a
// question an agent that SPENDS on x402 has and cannot get for free: before paying a stranger per call, is
// that stranger actually being called? The numbers below are our own keyless sweep of the public discovery
// index's per-host quality fields (30-day calls, unique payers, resource count, highest advertised price),
// frozen in rail-demand.json at build time.
//
// Honest by construction: every answer carries asOf + ageDays and snapshot:true, the file is read once at
// boot, and if it is missing every route in this band FAILS instead of answering. A settled call can never
// receive invented demand numbers from us.
// --------------------------------------------------------------------------------
const RAIL = (() => {
  try {
    const j = require(path.join(__dirname, "rail-demand.json"));
    if (!j || !Array.isArray(j.hosts) || !j.hosts.length) throw new Error("no hosts in snapshot");
    return j;
  } catch (e) {
    console.error(`[x402] rail-demand.json unavailable (${e.message}) — the /market/x402-* routes will refuse to answer rather than guess`);
    return null;
  }
})();
const RAIL_PRICE = process.env.X402_PRICE_INTEL || "$0.005";
const PCT = (x) => Math.round(x * 10) / 10;
const railAge = () => ({ asOf: RAIL?.asOf ?? null, ageDays: RAIL?.asOf ? PCT((nowMs() - Date.parse(RAIL.asOf)) / 86_400_000) : null });
// Computed once. The hosts array is already sorted by calls, descending.
const RAIL_STATS = RAIL ? (() => {
  const c = RAIL.hosts.map((r) => r.c);
  const at = (f) => c[Math.min(c.length - 1, Math.max(0, Math.floor(f * (c.length - 1))))] ?? 0;
  const traffic = RAIL.hosts.filter((r) => r.c > 0).length;
  const top6 = c.slice(0, 6).reduce((a, b) => a + b, 0);
  const bands = [["1 payer", 1, 1], ["2-5 payers", 2, 5], ["6-20 payers", 6, 20], ["21-100 payers", 21, 100], ["101+ payers", 101, Infinity]];
  return {
    hostsWithTraffic: traffic,
    medianCalls: at(0.5), p90Calls: at(0.9), p99Calls: at(0.99),
    top6Share: RAIL.totals.calls ? PCT((top6 / RAIL.totals.calls) * 100) : 0,
    bandRows: bands.map(([label, lo, hi]) => {
      const inBand = RAIL.hosts.filter((r) => r.p >= lo && r.p <= hi);
      return { band: label, hosts: inBand.length, calls: inBand.reduce((t, r) => t + r.c, 0), payers: inBand.reduce((t, r) => t + r.p, 0) };
    }),
  };
})() : null;
const railReady = () => { if (!RAIL || !RAIL_STATS) throw new Error("rail snapshot not shipped in this build (rail-demand.json missing) — nothing to report"); };

const MK_RAIL = [
  mr("/market/x402-overview", "x402 rail demand overview",
    "Thirty-day demand on the x402 pay-per-call rail, measured from its own public discovery index: hosts listed, resources, total calls, summed unique payers, and the median/p90/p99 calls per host. The number that answers 'is anyone buying anything here' without trusting a marketing page.",
    ["x402", "marketplace", "demand", "agents", "api"],
    [],
    [["found", "boolean"], ["snapshot", "boolean"], ["asOf", "string"], ["ageDays", "number"], ["windowDays", "integer"], ["hosts", "integer"], ["resources", "integer"], ["calls30d", "integer"], ["payerSlots30d", "integer"], ["hostsWithTraffic", "integer"], ["medianCallsPerHost", "integer"], ["p90CallsPerHost", "integer"], ["p99CallsPerHost", "integer"], ["top6HostSharePct", "number"], ["measuredFrom", "string"]],
    { found: true, snapshot: true, asOf: "2026-09-23T10:40:52.660Z", ageDays: 5.1, windowDays: 30, hosts: 2031, resources: 16678, calls30d: 718228, payerSlots30d: 12624, hostsWithTraffic: 2026, medianCallsPerHost: 11, p90CallsPerHost: 226, p99CallsPerHost: 2639, top6HostSharePct: 62.1, measuredFrom: "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources (keyless)" },
    {},
    async () => {
      railReady();
      const a = railAge();
      return mk("public x402 discovery index (keyless sweep, frozen)", {
        found: true, snapshot: true, asOf: a.asOf, ageDays: a.ageDays, windowDays: RAIL.windowDays,
        hosts: RAIL.totals.hosts, resources: RAIL.totals.resources, calls30d: RAIL.totals.calls,
        payerSlots30d: RAIL.totals.payerSlots, hostsWithTraffic: RAIL_STATS.hostsWithTraffic,
        medianCallsPerHost: RAIL_STATS.medianCalls, p90CallsPerHost: RAIL_STATS.p90Calls,
        p99CallsPerHost: RAIL_STATS.p99Calls, top6HostSharePct: RAIL_STATS.top6Share,
        measuredFrom: RAIL.measuredFrom,
      });
    }),

  mr("/market/x402-top-sellers", "Busiest sellers on the x402 rail",
    "The hosts actually receiving calls on this rail, ranked by thirty-day call count, each with its unique-payer count, number of listed resources and the highest price it advertises. Use it to see who is earning and at what price point, instead of guessing from a directory.",
    ["x402", "marketplace", "demand", "ranking", "agents"],
    [A.num("limit", { max: 50, default: 10n, desc: "hosts to return, busiest first (max 50)" })],
    [["found", "boolean"], ["snapshot", "boolean"], ["asOf", "string"], ["ageDays", "number"], ["count", "integer"], ["rows", "array"]],
    { found: true, snapshot: true, asOf: "2026-09-23T10:40:52.660Z", ageDays: 5.1, count: 2, rows: [{ rank: 1, host: "www.ax1.vc", calls30d: 173072, payers30d: 2562, resources: 12, maxPriceUsd: 0.05, lastCalledAt: "2026-09-23T06:54:34.771Z" }] },
    { limit: "3" },
    async ({ limit }) => {
      railReady();
      const a = railAge();
      const n = Math.max(1, Math.min(50, Number(narg(limit, 10))));
      const rows = RAIL.hosts.slice(0, n).map((r, i) => ({
        rank: i + 1, host: r.h, calls30d: r.c, payers30d: r.p, resources: r.r,
        maxPriceUsd: PCT((r.m / 1e6) * 100) / 100, lastCalledAt: r.l,
      }));
      return mk("public x402 discovery index (keyless sweep, frozen)", { found: rows.length > 0, snapshot: true, asOf: a.asOf, ageDays: a.ageDays, count: rows.length, rows });
    }),

  mr("/market/x402-host-demand", "Is one x402 seller actually being called?",
    "Demand history for a single host on this rail: thirty-day calls, unique payers, listed resources, last call timestamp, highest advertised price, and its rank among all listed hosts. The pre-purchase check an agent should run before paying an unknown endpoint.",
    ["x402", "marketplace", "demand", "reputation", "agents"],
    [A.text("host", /^[A-Za-z0-9.-]{4,120}$/, { example: "api.nansen.ai", desc: "hostname of the seller to check, without scheme (api.nansen.ai)" })],
    [["found", "boolean"], ["snapshot", "boolean"], ["asOf", "string"], ["ageDays", "number"], ["host", "string"], ["listed", "boolean"], ["calls30d", "integer"], ["payers30d", "integer"], ["resources", "integer"], ["lastCalledAt", "string"], ["maxPriceUsd", "number"], ["rankByCalls", "integer"], ["totalHosts", "integer"], ["percentile", "number"]],
    { found: true, snapshot: true, asOf: "2026-09-23T10:40:52.660Z", ageDays: 5.1, host: "api.nansen.ai", listed: true, calls30d: 4665, payers30d: 73, resources: 45, lastCalledAt: "2026-09-23T05:10:00.000Z", maxPriceUsd: 0.02, rankByCalls: 18, totalHosts: 2031, percentile: 99.1 },
    { host: "api.nansen.ai" },
    async ({ host }) => {
      railReady();
      const a = railAge();
      const h = String(host).toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").split(":")[0];
      const idx = RAIL.hosts.findIndex((r) => r.h === h);
      if (idx < 0) return mk("public x402 discovery index (keyless sweep, frozen)", { found: false, snapshot: true, asOf: a.asOf, ageDays: a.ageDays, host: h, listed: false, calls30d: 0, payers30d: 0, resources: 0, lastCalledAt: null, maxPriceUsd: 0, rankByCalls: null, totalHosts: RAIL.totals.hosts, percentile: null });
      const r = RAIL.hosts[idx];
      return mk("public x402 discovery index (keyless sweep, frozen)", {
        found: true, snapshot: true, asOf: a.asOf, ageDays: a.ageDays, host: r.h, listed: true,
        calls30d: r.c, payers30d: r.p, resources: r.r, lastCalledAt: r.l,
        maxPriceUsd: PCT((r.m / 1e6) * 100) / 100, rankByCalls: idx + 1, totalHosts: RAIL.totals.hosts,
        percentile: PCT((1 - (idx + 1) / RAIL.totals.hosts) * 100),
      });
    }),

  mr("/market/x402-payer-bands", "How many buyers does a cold x402 seller get?",
    "Hosts grouped by count of unique paying wallets over thirty days, with the calls each group receives. Reads as the real distribution of the rail: how many sellers get one payer, how many get 2-60, and how much of all traffic the top group holds.",
    ["x402", "marketplace", "demand", "distribution", "agents"],
    [],
    [["found", "boolean"], ["snapshot", "boolean"], ["asOf", "string"], ["ageDays", "number"], ["totalHosts", "integer"], ["bands", "array"], ["top6HostSharePct", "number"]],
    { found: true, snapshot: true, asOf: "2026-09-23T10:40:52.660Z", ageDays: 5.1, totalHosts: 2031, bands: [{ band: "2-5 payers", hosts: 970, calls: 18320, payers: 3010 }], top6HostSharePct: 62.1 },
    {},
    async () => {
      railReady();
      const a = railAge();
      return mk("public x402 discovery index (keyless sweep, frozen)", {
        found: true, snapshot: true, asOf: a.asOf, ageDays: a.ageDays, totalHosts: RAIL.totals.hosts,
        bands: RAIL_STATS.bandRows, top6HostSharePct: RAIL_STATS.top6Share,
      });
    }),
];

// --------------------------------------------------------------------------------
// TOKEN VERDICT — the one measured category on this rail that demonstrably gets paid.
//
// The demand snapshot above is not just a product, it is market research: the host with the most unique paying
// wallets on Base (www.ax1.vc, 4,112 payers / 260,080 calls in 30 days) does not sell raw chain data — it sells
// a plain-language VERDICT on a token. Cheap data reads are the two weakest categories we measured; judgement
// assembled from several reads at once is where the payers actually are. So this route composes reads we
// already serve into one answer an agent can act on, from public sources, at zero cost to run.
//
// What makes it worth paying for, and what keeps us honest about it:
//  - it reads the pool's actual BUY/SELL counts, because a token with liquidity but zero settled sells is the
//    classic non-selling trap, and that is invisible in a price-only quote;
//  - it reads what the deployed BYTECODE can be asked to do (mint, pause, blacklist, fee, renounceOwnership),
//    off the code, not off a README;
//  - every key is always present (null when a source failed), and the answer names what it CANNOT see. No
//    sell-path is simulated, no contract is certified safe. A verdict that overstates itself is the exact bug
//    class our own /audit scanner exists to catch, so this route is written to not commit it.
// --------------------------------------------------------------------------------
const RISK_WORDS = {
  mint: /(^|\b)(mint|mintToken|mintBatch|issueTokens?|_mintToken)\b/i,
  pause: /(^|\b)(pause|setPaused|tradePause|stopTrading|toggleIsOpenTrading|setTradeActive)\b/i,
  blacklist: /(^|\b)(blacklist|whitelist|setBlacklist|addBlacklist|_blacklistAddress|excludeFromAffiliate|setIsExcluded)\b/i,
  fee: /(^|\b)(setFee|updateFee|setTax|setTaxes|setMarketingFee|_setFees|setFeeOnTransfer|setExchangeFee)\b/i,
  maxWallet: /(^|\b)(updateMaxWallet|setMaxWallet|setMaxTxAmount|setWallStealMax|updateMaxTx)\b/i,
  renounce: /(^|\b)renounceOwnership\b/i,
};
const VERDICT_LADDER = (f) => (f <= 15 ? "low" : f <= 35 ? "moderate" : f <= 60 ? "elevated" : "high");

const MK_VERDICT = [
  mr("/market/token-verdict", "Plain-language risk verdict on one Base token",
    "One call, several reads assembled into a verdict: the deepest DEX pool (liquidity, 24h volume, buy AND sell counts, FDV, pool age), what the deployed bytecode can actually be asked to do (mint, pause, blacklist, fee changes, max-wallet caps, whether ownership was renounced), and whether the token is an upgradeable proxy. Returns reasons, a risk score, and an explicit list of what it did NOT check. Static on-chain and venue evidence only — never a simulated sell and never a certification of safety.",
    ["verdict", "risk", "token", "security", "base", "agents", "honeypot"],
    [A.chain({ default: "base", example: "base", desc: "chain key (the bytecode read needs an EVM chain; base is the default)" }),
     A.text("token", /^0x[0-9a-fA-F]{40}$/, { example: "0xc5102fE9359FD9a28f877a67E36B0F050d81a3CC", desc: "token contract address to judge" })],
    [["found", "boolean"], ["chain", "string"], ["token", "string"], ["verdict", "string"], ["riskScore", "integer"], ["riskLevel", "string"], ["reasons", "array"], ["signals", "object"], ["pool", "object"], ["code", "object"], ["proxy", "boolean"], ["liquidityUsd", "number"], ["pairAddress", "string|null"], ["poolAgeDays", "number|null"], ["buys24h", "integer|null"], ["sells24h", "integer|null"], ["volume24hUsd", "number"], ["priceUsd", "string|null"], ["fdvUsd", "number"], ["marketCapUsd", "number"], ["supply", "string|null"], ["name", "string|null"], ["symbol", "string|null"], ["cannotSee", "array"], ["sources", "array"], ["failedSources", "array"], ["disclaimer", "string"]],
    { found: true, chain: "base", token: "0xc5102fE9359FD9a28f877a67E36B0F050d81a3CC", verdict: "elevated: mintable by an active owner with 23k of liquidity and 0 recorded sells in 24h", riskScore: 62, riskLevel: "high", reasons: ["bytecode exposes mint(uint256) and the owner has not renounced", "pool reports buys but zero sells in the last 24h"], signals: { mintable: true, pausable: false, blacklistable: false, feeChangeable: true, maxWalletChangeable: false, ownershipRenounced: false }, pool: {}, code: {}, proxy: false, liquidityUsd: 23145.5, pairAddress: "0x0000000000000000000000000000000000000000", poolAgeDays: 41.2, buys24h: 88, sells24h: 0, volume24hUsd: 51200.4, priceUsd: "0.0004", fdvUsd: 400000, marketCapUsd: 380000, supply: "1000000000000000000000000", name: "Example Token", symbol: "EXM", cannotSee: ["no sell transaction was simulated, so a transfer-tax or rebate trap can be missed"], sources: ["dexscreener", "base-rpc"], failedSources: [], disclaimer: "Static evidence read from public sources; not advice and not a safety certification." },
    { chain: "base", token: "0xc5102fE9359FD9a28f877a67E36B0F050d81a3CC" },
    async ({ chain, token }) => {
      const addr = String(token);
      const failed = [];
      const soft = async (name, fn) => { try { return await fn(); } catch (e) { failed.push(`${name}: ${String(e?.message || e).slice(0, 60)}`); return null; } };
      // 1. find the deepest pool, then read that pool's own numbers.
      const pairs = await soft("dex-token-pairs", () => DATA_BY_PATH.get("/market/dex-token-pairs").run({ address: addr }));
      const best = (pairs?.rows || [])[0] || null;
      const pairAddress = best?.pairAddress ?? best?.address ?? null;
      let detail = null;
      if (pairAddress) detail = await soft("dex-pair-detail", () => DATA_BY_PATH.get("/market/dex-pair-detail").run({ chain: chain || "base", pair: pairAddress }));
      // 2. read the deployed bytecode's capability set.
      const caps = await soft("bytecode-capabilities", () => DATA_BY_PATH.get("/chain/bytecode-capabilities").run({ chain: chain || "base", address: addr, count: 60n }));
      // 3. is it behind an upgradable proxy?
      const prox = await soft("proxy-check", () => DATA_BY_PATH.get("/chain/proxy-check").run({ chain: chain || "base", address: addr }));
      // 4. token metadata for the human-readable line.
      const meta = await soft("token-meta", () => DATA_BY_PATH.get("/chain/token-meta").run({ chain: chain || "base", token: addr }));

      const named = (caps?.named || []).map((n) => String(n.signature || "").split("(")[0]);
      const has = (re) => named.some((s) => re.test(s));
      const signals = {
        mintable: has(RISK_WORDS.mint),
        pausable: has(RISK_WORDS.pause),
        blacklistable: has(RISK_WORDS.blacklist),
        feeChangeable: has(RISK_WORDS.fee),
        maxWalletChangeable: has(RISK_WORDS.maxWallet),
        ownershipRenounced: has(RISK_WORDS.renounce),
        codeReadable: !!caps?.hasCode,
      };
      const isProxy = !!(prox?.isProxy ?? prox?.proxy ?? false);
      const liq = Number(detail?.liquidityUsd ?? best?.liquidityUsd ?? 0) || 0;
      // Trade counts live in different shapes on the two venues' documents: the pool detail nests them per
      // window (txns.h24.{buys,sells}), the token-pairs row flattens them to txns24h.{buys,sells}. Reading the
      // wrong path silently yielded 0/0, which is worse than unknown — a buyer would read "0 sells" as the
      // honeypot signal when all we know is that we did not parse the field. So: read both real shapes, keep
      // null when neither answers, and only raise the zero-sell reason when the counts were measured.
      const t24 = detail?.txns?.h24 ?? detail?.txns ?? best?.txns24h ?? null;
      const sells = t24 && Number.isFinite(Number(t24.sells)) ? Number(t24.sells) : null;
      const buys = t24 && Number.isFinite(Number(t24.buys)) ? Number(t24.buys) : null;
      const created = Number(detail?.pairCreatedAtMs ?? best?.pairCreatedAtMs ?? 0) || 0;
      const ageDays = created ? Math.round(((nowMs() - created) / 86_400_000) * 10) / 10 : null;

      const reasons = [];
      let score = 0;
      if (!caps?.hasCode) { score += 25; reasons.push("no bytecode found at this address on this chain — it may be a wrong chain, a wallet, or a very new deploy"); }
      if (signals.mintable && !signals.ownershipRenounced) { score += 30; reasons.push("the code can mint more tokens and the owner has not renounced"); }
      else if (signals.mintable) { score += 10; reasons.push("the code can mint more tokens"); }
      if (signals.blacklistable) { score += 20; reasons.push("the code can block addresses from transferring (blacklist/whitelist selectors present)"); }
      if (signals.pausable) { score += 12; reasons.push("the code can pause trading"); }
      if (signals.feeChangeable) { score += 12; reasons.push("the code can change its own fee/tax after you buy"); }
      if (signals.maxWalletChangeable) { score += 6; reasons.push("the code can change max-wallet/max-tx limits"); }
      if (isProxy) { score += 10; reasons.push("the address is an upgradable proxy — the logic behind it can be swapped later"); }
      if (liq === 0) { score += 18; reasons.push("no DEX pool found for this token on the venue we queried"); }
      else if (liq < 1000) { score += 12; reasons.push(`liquidity is only $${liq.toFixed(0)} — a modest sell moves the price hard`); }
      if (sells === 0 && buys !== null && buys > 0) { score += 22; reasons.push(`pool recorded ${buys} buys and ZERO sells in the last 24h — the classic non-selling shape`); }
      else if (sells === null && buys === null) reasons.push("trade counts were not returned by the venue read, so the buy/sell balance is UNKNOWN here, not zero");
      if (ageDays !== null && ageDays < 3) { score += 8; reasons.push(`the pool is ${ageDays} days old — no history to learn from`); }
      if (!failed.length && score === 0) reasons.push("no risk flags found in the reads we could complete: no mint/pause/blacklist/fee selectors under a live owner, and the pool shows ordinary trading");
      score = Math.min(100, score);

      const cannotSee = [
        "no buy or sell was simulated, so a transfer-tax, rebate or honeypot implemented in _transfer without a named selector can be missed",
        "holder distribution and top-wallet concentration are not read here",
        "external liquidity locks, vesting and team identity are outside this evidence",
        "DEX venue data is as current as the venue's own indexer",
      ];
      const verdictLine = `${VERDICT_LADDER(score)} risk (${score}/100) for ${meta?.symbol || meta?.name || addr.slice(0, 10)}: ${reasons[0] || "nothing flagged in the completed reads"}`;
      return mk("dexscreener + chain RPC + bytecode selector scan", {
        found: !!(caps || detail || meta), chain: chain || "base", token: addr,
        verdict: verdictLine, riskScore: score, riskLevel: VERDICT_LADDER(score),
        reasons, signals,
        pool: { pairAddress, dex: detail?.dexId ?? best?.dexId ?? null, labels: detail?.labels ?? best?.labels ?? [], priceChange: detail?.priceChange ?? (best ? { h24: best.priceChange24h ?? null, h1: best.priceChange1h ?? null } : null) },
        code: caps ? { hasCode: !!caps.hasCode, bytecodeSize: caps.bytecodeSize ?? null, namedCount: caps.namedCount ?? null, named: (caps.named || []).map((n) => n.signature) } : {},
        proxy: isProxy,
        liquidityUsd: liq, pairAddress, poolAgeDays: ageDays,
        buys24h: buys, sells24h: sells,
        volume24hUsd: Number(detail?.volume?.h24 ?? best?.volume24h ?? 0) || 0,
        priceUsd: detail?.priceUsd ?? best?.priceUsd ?? null,
        fdvUsd: Number(detail?.fdv ?? best?.fdv ?? 0) || 0,
        marketCapUsd: Number(detail?.marketCap ?? best?.marketCap ?? 0) || 0,
        supply: meta?.totalSupply ?? null,
        name: meta?.name ?? null, symbol: meta?.symbol ?? null,
        cannotSee, sources: ["dexscreener", `${chain || "base"} public RPC`], failedSources: failed,
        disclaimer: "Static evidence read from public sources; not advice and not a safety certification.",
      });
    }),
];

// ---- software supply-chain risk --------------------------------------------------------------
// Why this band exists, measured rather than guessed: the x402 facilitator we point at publishes its own
// index (7,532 resources, keyless GET /discovery/resources), and 1,468 of them were updated inside the last
// 7 days. One of the freshest sellers in it (relay402.georgespring.workers.dev, 30 resources, $0.001-$0.10)
// sells exactly this kind of read — npm/GitHub package and repo risk — while our own audit product was one
// POST endpoint nobody could buy per-topic. This turns that into two ordinary $0.001 reads.
// Both are keyless public APIs over a FIXED host, with the only variable part bounded by an anchored regex
// (so no caller ever steers what we fetch), and an unknown package answers found:false as data instead of
// throwing a 404 after settlement.
const PKG_RISK = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const ageDays = (iso) => {
  const t = Date.parse(iso || "");
  return Number.isFinite(t) ? Math.round(((nowMs() - t) / 86400000) * 10) / 10 : null;
};
const riskLabel = (flags) => (flags.some((f) => /install-script|deprecated|archived|no-license|force-push-window/i.test(f))
  ? "elevated" : flags.length ? "watch" : "no-flags");
const PKG_READ_CACHE_NOTE = "registry metadata only; nothing is downloaded or executed";
async function readPkg(name) {
  const { d, missing, stale } = await mjLookup(`npm:${String(name).slice(0, 120)}`, `https://registry.npmjs.org/${encodeURIComponent(name)}`);
  if (missing || !d || typeof d !== "object") return null;
  const latest = String(d["dist-tags"]?.latest || "");
  const v = d.versions?.[latest] || {};
  const scripts = v.scripts || {};
  const installScripts = ["preinstall", "install", "postinstall"].filter((k) => typeof scripts[k] === "string" && scripts[k].trim());
  const time = d.time?.[latest] || d.time?.modified || null;
  const maintainers = Array.isArray(d.maintainers) ? d.maintainers.length : null;
  const deprecated = typeof v.deprecated === "string" && v.deprecated.trim() ? v.deprecated.slice(0, 200) : null;
  const age = ageDays(time);
  const flags = [
    ...installScripts.length ? ["install-script"] : [],
    ...deprecated ? ["deprecated"] : [],
    ...v.dist?.attestations || v.dist?.provenance ? [] : ["no-provenance"],
    ...maintainers === 1 ? ["single-maintainer"] : [],
    ...(age !== null && age > 730 ? ["stale-unpublished"] : []),
  ];
  return { name, latest, v, installScripts, time, age, deprecated, maintainers, flags, stale: !!stale,
    versionCount: d.versions ? Object.keys(d.versions).length : null,
    license: v.license ?? d.license ?? null,
    unpackedSize: v.dist?.unpackedSize === undefined ? null : String(v.dist.unpackedSize),
    provenance: !!(v.dist?.attestations || v.dist?.provenance), depsTotal: v.dependencies ? Object.keys(v.dependencies).length : 0 };
}
const MK_SUPPLYCHAIN = [
  mr("/market/npm-tree-risk", "Direct-dependency risk roll-up for one npm package",
    "One paid call that reads the package AND each of its direct dependencies (bounded, in published order) from the public npm registry, then rolls up what actually gets executed on install: which dependencies carry pre/postinstall scripts, which are deprecated, which ship without signed provenance, which are single-maintainer or unpublished-for-two-years. Returns the per-dependency rows, the counts, a verdict line, and an explicit list of what this cannot see. Static registry metadata only — it does not resolve a lockfile, walk the transitive tree beyond direct dependencies, download or execute any package, or compare against the name you meant to type.",
    ["security", "npm", "supply-chain", "dependencies", "audit"],
    [A.slug("name", { maxLen: 214, pattern: PKG_RISK, hint: "must be an npm package name, optionally @scope/name", example: "left-pad", desc: "npm package name (optionally scoped)" })],
    [["found", "boolean"], ["name", "string"], ["scope", "string|null"], ["latest", "string|null"],
     ["rootHasInstallScript", "boolean|null"], ["rootDeprecated", "string|null"], ["rootFlags", "array"],
     ["dependencyCount", "integer|null"], ["directChecked", "integer"], ["deps", "array"], ["rollup", "object"],
     ["risk", "string|null"], ["verdict", "string"], ["cannotSee", "array"], ["sources", "array"],
     ["failedSources", "array"], ["note", "string|null"]],
    { found: true, name: "left-pad", scope: null, latest: "1.3.0", rootHasInstallScript: false, rootDeprecated: null,
      rootFlags: ["no-provenance", "single-maintainer", "stale-unpublished"], dependencyCount: 0, directChecked: 0,
      deps: [], rollup: { installScripts: 0, deprecated: 0, noProvenance: 0, singleMaintainer: 0, stale: 0, flagged: [] },
      risk: "elevated", verdict: "no direct dependencies; the root itself is unpublished since 2018, single-maintainer and unsigned",
      cannotSee: ["the transitive tree below direct dependencies", "what any package's code actually does", "whether you meant a different, similarly-spelled package"],
      sources: ["registry.npmjs.org"], failedSources: [], note: "at most 10 direct dependencies are read per call, in the order the registry publishes them" },
    { name: "left-pad" },
    async ({ name }) => {
      const failed = [];
      const soft = async (label, fn) => { try { return await fn(); } catch (e) { failed.push(`${label}: ${String(e?.message || e).slice(0, 70)}`); return null; } };
      const root = await soft(name, () => readPkg(name));
      if (!root) {
        return mk("registry.npmjs.org", { found: false, name, scope: name.startsWith("@") ? name.split("/")[0] : null,
          latest: null, rootHasInstallScript: null, rootDeprecated: null, rootFlags: [], dependencyCount: null,
          directChecked: 0, deps: [], rollup: { installScripts: 0, deprecated: 0, noProvenance: 0, singleMaintainer: 0, stale: 0, flagged: [] },
          risk: null, verdict: "unavailable: the registry did not answer for this package", cannotSee: [], sources: ["registry.npmjs.org"],
          failedSources: failed, note: null }, false, "an unreadable answer is returned as data, and the roll-up is left empty rather than guessed");
      }
      const deps = Object.entries(root.v?.dependencies || {}).map(([d]) => d).slice(0, 10);
      const rows = [];
      let anyStale = false;
      for (const d of deps) {
        const info = await soft(d, () => readPkg(d));
        if (!info) { rows.push({ name: d, unreadable: true }); continue; }
        if (info.stale) anyStale = true;   // a cached reading must never be presented as a fresh one
        rows.push({ name: d, latest: info.latest || null, hasInstallScript: info.installScripts.length > 0,
          installScripts: info.installScripts, deprecated: info.deprecated, provenance: info.provenance,
          lastPublishAgeDays: info.age, maintainerCount: info.maintainers, flags: info.flags });
      }
      const all = [root, ...rows.filter((r) => !r.unreadable)];
      const count = (key, row) => (row.flags || []).includes(key);
      const rollup = {
        installScripts: rows.filter((r) => r.hasInstallScript).length + (root.installScripts.length ? 1 : 0),
        deprecated: all.filter((r) => count("deprecated", r)).length,
        noProvenance: all.filter((r) => count("no-provenance", r)).length,
        singleMaintainer: all.filter((r) => count("single-maintainer", r)).length,
        stale: all.filter((r) => count("stale-unpublished", r)).length,
        flagged: rows.filter((r) => (r.flags || []).length || r.unreadable).map((r) => r.name),
      };
      const riskFlags = [...root.flags, ...rows.flatMap((r) => r.unreadable ? ["unreadable"] : (r.flags || []))];
      const risk = riskFlags.some((f) => ["install-script", "deprecated"].includes(f)) ? "elevated"
        : riskFlags.length ? "watch" : "no-flags";
      const verdict = rollup.installScripts
        ? `${rollup.installScripts} package(s) in this direct set run a script at install time — that is the npm path to executing code on your machine`
        : root.deprecated ? `${name} itself is deprecated: ${String(root.deprecated).slice(0, 120)}`
        : deps.length ? `${deps.length} direct dependencies read; none run install-time scripts; ${rollup.noProvenance} without signed provenance, ${rollup.singleMaintainer} single-maintainer`
        : `no direct dependencies; only the package itself is read here`;
      return mk("registry.npmjs.org", { found: true, name, scope: name.startsWith("@") ? name.split("/")[0] : null,
        latest: root.latest || null, rootHasInstallScript: root.installScripts.length > 0,
        rootDeprecated: root.deprecated, rootFlags: root.flags,
        dependencyCount: root.depsTotal === undefined ? null : root.depsTotal, directChecked: rows.length,
        deps: rows, rollup, risk, verdict,
        cannotSee: ["the transitive tree below direct dependencies", "what any package's code actually does",
          "whether you meant a different, similarly-spelled package", "lockfiles, tarball contents and install behaviour (nothing is downloaded or run here)"],
        sources: ["registry.npmjs.org"], failedSources: failed,
        note: "at most 10 direct dependencies are read per call, in the order the registry publishes them" }, anyStale || !!root.stale);
    }),

  mr("/market/npm-package-risk", "npm package supply-chain risk",
    "One keyless read of the public npm registry for a package: does it ship an install-time script (the way malicious packages run code at install), is the released version deprecated, how old is the last publish, how many maintainers and dependencies, is there signed provenance, and what flags come out of those facts. Static metadata only: it does NOT execute the package, scan its source, or claim it is safe.",
    ["security", "npm", "supply-chain", "audit", "packages"],
    [A.slug("name", { maxLen: 214, pattern: PKG_RISK, hint: "must be an npm package name, optionally @scope/name", example: "left-pad", desc: "npm package name (optionally scoped)" })],
    [["found", "boolean"], ["name", "string"], ["scope", "string|null"], ["latest", "string|null"], ["publishedAt", "string|null"],
     ["lastPublishAgeDays", "number|null"], ["versionCount", "integer|null"], ["maintainerCount", "integer|null"],
     ["depsCount", "integer|null"], ["hasInstallScript", "boolean|null"], ["installScripts", "array"],
     ["provenance", "boolean|null"], ["deprecated", "string|null"], ["license", "string|null"],
     ["unpackedSize", "string|null"], ["flags", "array"], ["risk", "string|null"]],
    { found: true, name: "left-pad", scope: null, latest: "1.3.0", publishedAt: "2018-03-22T18:11:01.528Z",
      lastPublishAgeDays: 3112.4, versionCount: 20, maintainerCount: 1, depsCount: 0, hasInstallScript: false,
      installScripts: [], provenance: false, deprecated: null, license: "WTFPL", unpackedSize: "7288",
      flags: ["stale-unpublished", "no-provenance", "single-maintainer"], risk: "elevated" },
    { name: "left-pad" },
    async ({ name }) => {
      // ONE reader for the whole npm band: this route and /market/npm-tree-risk used to compute the same
      // flags in two places, which is the "two tables describing one thing, disagreeing" defect we keep
      // hitting — today identical, silently wrong the day one of them is edited. readPkg is now the only
      // place a package's facts are derived.
      const info = await readPkg(name);
      const scope = name.startsWith("@") ? name.split("/")[0] : null;
      if (!info) {
        return mk("registry.npmjs.org", { found: false, name, scope,
          latest: null, publishedAt: null, lastPublishAgeDays: null, versionCount: null, maintainerCount: null,
          depsCount: null, hasInstallScript: null, installScripts: [], provenance: null, deprecated: null,
          license: null, unpackedSize: null, flags: [], risk: null },
          false, "the npm registry has no package by that name (scoped names must be given in full, e.g. @org/pkg)");
      }
      return mk("registry.npmjs.org", { found: true, name, scope,
        latest: info.latest || null, publishedAt: info.time || null, lastPublishAgeDays: info.age,
        versionCount: info.versionCount, maintainerCount: info.maintainers, depsCount: info.depsTotal,
        hasInstallScript: info.installScripts.length > 0, installScripts: info.installScripts,
        provenance: info.provenance, deprecated: info.deprecated, license: info.license,
        unpackedSize: info.unpackedSize, flags: info.flags, risk: riskLabel(info.flags) }, info.stale);
    }),
  mr("/market/github-repo-health", "GitHub repository health",
    "Keyless read of the public GitHub API for one repository: archived, forked, how long since the last push, open issue count, stars, license, topics — plus the flags an integrator actually acts on (archived, no license, unmaintained window). Does not read the source, the dependency tree, or anything private, and does not clone or build.",
    ["security", "github", "supply-chain", "repository", "maintenance"],
    [A.slug("owner", { maxLen: 100, pattern: /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/, hint: "GitHub owner: letters, digits, dot, dash, underscore", example: "modelcontextprotocol", desc: "repository owner or org" }),
     A.slug("repo", { maxLen: 100, pattern: /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/, hint: "GitHub repository name", example: "registry", desc: "repository name" })],
    [["found", "boolean"], ["fullName", "string"], ["archived", "boolean|null"], ["fork", "boolean|null"],
     ["defaultBranch", "string|null"], ["licenseSpdx", "string|null"], ["stargazers", "integer|null"],
     ["openIssues", "integer|null"], ["pushedAt", "string|null"], ["lastPushAgeDays", "number|null"],
     ["createdAt", "string|null"], ["sizeKb", "integer|null"], ["topics", "array"], ["flags", "array"],
     ["risk", "string|null"], ["note", "string|null"]],
    { found: true, fullName: "modelcontextprotocol/registry", archived: false, fork: false, defaultBranch: "main",
      licenseSpdx: "Apache-2.0", stargazers: 2486, openIssues: 91, pushedAt: "2026-09-24T09:54:46Z",
      lastPushAgeDays: 4.3, createdAt: "2025-01-14T18:53:04Z", sizeKb: 203, topics: ["mcp"],
      flags: [], risk: "no-flags", note: "unauthenticated GitHub read: 60 requests/hour per source IP" },
    { owner: "modelcontextprotocol", repo: "registry" },
    async ({ owner, repo }) => {
      // tolerate: an unauthenticated GitHub read answers 403 from time to time (its abuse detection fires on
      // datacenter IPs — measured twice today: 200 with real data minutes apart from 403). Because the x402
      // gate settles BEFORE the handler, a 403 must be delivered as an honest data answer, not thrown at a
      // buyer who already paid. The status text is carried into the reason instead of being flattened into
      // "repository not found".
      const { d, stale, missing } = await mjLookup(`gh:${owner}/${repo}`.slice(0, 140), `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
        { headers: { "user-agent": "x402-audit-agent (public repository metadata read; keyless GitHub API)" } }, { tolerate: true });
      if (missing || d === null || typeof d !== "object" || !d.full_name) {
        return mk("api.github.com", { found: false, fullName: `${owner}/${repo}`, archived: null, fork: null,
          defaultBranch: null, licenseSpdx: null, stargazers: null, openIssues: null, pushedAt: null,
          lastPushAgeDays: null, createdAt: null, sizeKb: null, topics: [], flags: [], risk: null },
          stale, `GitHub did not return this repository${missing ? ` — it answered ${String(missing).slice(0, 90)}` : ""}. Anonymous reads are rate-limited to 60/hour per source IP, so a retry is legitimate and the answer is delivered as data, not charged twice for the same fact.`);
      }
      const flags = [
        ...d.archived ? ["archived"] : [],
        ...(!d.license || !d.license.spdx_id || d.license.spdx_id === "NOASSERTION") ? ["no-license"] : [],
        ...(() => { const a = ageDays(d.pushed_at); return a !== null && a > 365 ? ["unmaintained-window"] : []; })(),
      ];
      return mk("api.github.com", { found: true, fullName: d.full_name, archived: !!d.archived, fork: !!d.fork,
        defaultBranch: d.default_branch ?? null, licenseSpdx: d.license?.spdx_id ?? null,
        stargazers: nf(d.stargazers_count), openIssues: nf(d.open_issues_count), pushedAt: d.pushed_at ?? null,
        lastPushAgeDays: ageDays(d.pushed_at), createdAt: d.created_at ?? null, sizeKb: nf(d.size),
        topics: Array.isArray(d.topics) ? d.topics.slice(0, 12) : [], flags, risk: riskLabel(flags),
        note: "unauthenticated GitHub read: 60 requests/hour per source IP" }, stale);
    }),
];

const MARKET_ROUTES = [
  ...MK_KRAKEN, ...MK_CBEX, ...MK_OKX, ...MK_BITFINEX, ...MK_GATE, ...MK_KUCOIN, ...MK_DERIBIT,
  ...MK_HL, ...MK_LLAMA, ...MK_BTC, ...MK_SENTIMENT, ...MK_POLY, ...MK_DEX, ...MK_JUP, ...MK_SCOUT,
  ...MK_RAIL, ...MK_VERDICT, ...MK_SUPPLYCHAIN,
];

// --------------------------------------------------------------------------------
// ONE surface, five consumers.
//
// Everything the service publishes — the payment gate, the 402 challenge table, the
// pre-validation middleware, the fan-out documents, OpenAPI, llms.txt and the MCP tool
// list — is derived from this single `DATA_ROUTES` array. A route that exists in the table
// is therefore charged, described and callable through every protocol at once, and there is
// no hand-typed list left for a new endpoint to be missing from. The boot assertion below is
// what makes that statement checkable rather than aspirational.
// --------------------------------------------------------------------------------
const DATA_ROUTES = [...CHAIN_ROUTES, ...MARKET_ROUTES];
const DATA_BY_PATH = new Map(DATA_ROUTES.map((r) => [r.path, r]));
for (const r of DATA_ROUTES) PAID_DATA_PATHS.add(r.path);
const argHint = (r) => r.args.map((a) => `${a.name}=${a.example === undefined ? "" : a.example}`).join("&");
// One envelope and one error shape, shared by the HTTP route and its MCP mirror: a buyer on either
// protocol must not be able to get a different body for the same settled call.
const dataEnvelope = (r, args, out) =>
  r.chainRoute ? chainResult(args, out) : { ...out, ts: new Date(nowMs()).toISOString() };
const dataError = (r, e) => {
  const status = e instanceof HttpError ? e.status : 502;
  return { status, body: {
    error: status === 400 ? "invalid_request" : r.chainRoute ? "upstream_rpc_failed" : "upstream_venue_failed",
    detail: String(e?.message || e).slice(0, 200), route: `GET ${r.path}`,
  } };
};
// An MCP tool name is the route path with separators flattened; a collision would silently
// shadow a tool, so it fails the boot instead of shipping a surface that answers to two names.
// `probe` is required on the venue routes only: .tmp-check/chain-selftest.mjs carries its own
// per-route QUERIES/ASSERT tables, whose fixtures are read from the chain by raw fetch, which is
// a stronger control than a self-declared example could ever be.
const mcpToolName = (p) => p.slice(1).replace(/[^A-Za-z0-9]+/g, "_").toLowerCase();
// The reverse of the mirror, used by the availability rule: an MCP tool call has to know which HTTP route
// it is a copy of, and that mapping is generated from the same function that makes the forward one — so it
// cannot disagree with the advertised tool names.
const TOOL_TO_PATH = new Map(DATA_ROUTES.map((r) => [mcpToolName(r.path), r.path]));
const ROUTE_NAME_RE = /^\/(chain|market)\/[a-z0-9-]+$/;
{
  const seen = new Map();
  for (const r of DATA_ROUTES) {
    const problems = [];
    if (!ROUTE_NAME_RE.test(r.path)) problems.push(`path ${r.path} is not /chain/* or /market/*`);
    if (typeof r.run !== "function") problems.push(`${r.path} has no handler`);
    if (!Array.isArray(r.out) || !r.out.length) problems.push(`${r.path} declares no output keys`);
    if (!Array.isArray(r.args)) problems.push(`${r.path} declares no arg table`);
    if (!Array.isArray(r.tags) || !r.tags.length) problems.push(`${r.path} declares no tags`);
    if (typeof r.desc !== "string" || r.desc.length < 40) problems.push(`${r.path} has no buyer-facing description`);
    if (r.marketRoute && (!r.probe || typeof r.probe !== "object")) problems.push(`${r.path} ships no probe args for the instrument`);
    const key = mcpToolName(r.path);
    if (seen.has(key)) problems.push(`MCP tool name ${key} collides with ${seen.get(key)}`);
    else seen.set(key, r.path);
    if (problems.length) throw new Error(`route table invalid: ${problems.join("; ")}`);
  }
  for (const free of FREE_TOOLS) if (seen.has(free)) throw new Error(`free tool ${free} collides with a paid route name`);
}


const mcp = new McpServer({ name: "crypto-bot-honesty-audit", version: "1.0.0" }, {
    instructions: `Pay-per-call x402 agent, no account and no API key. ${DATA_ROUTES.length} atomic read routes at ${PRICE_DATA} USDC each — ${CHAIN_ROUTES.length} chain-state primitives over public RPC (${CHAIN_KEYS.join(", ")}), ${MARKET_ROUTES.length - 4} venue reads (Kraken, Coinbase Exchange, OKX, Bitfinex, Gate, KuCoin, Deribit, Hyperliquid, DeFiLlama, mempool.space and blockchain.info for Bitcoin, alternative.me sentiment, Polymarket, DexScreener, Jupiter and the Blockscout explorers) and 4 /market/x402-* rail-intelligence reads carrying our own measured 30-day demand map of this rail (calls and unique payers per listed host, from the keyless public discovery index) — plus POST /audit for a crypto-bot honesty scan at ${PRICE}. Every route is reachable over MCP under its own tool name and over plain HTTP GET; both answer byte-identically. Each mirrored tool advertises an outputSchema and returns the same object as structuredContent, so a client can decode the reply without parsing a text blob.`,
});
// Every tool is a read-only query or a static analysis. Declaring that is what lets an autonomous
// client skip its destructive-action confirmation step before it pays us.
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const REGISTERED_TOOLS = new Set();
// The exact title+description each tool advertises on the wire, kept so the MCP server card
// (/.well-known/mcp/server-card.json) is generated from the registration itself rather than from a
// second hand-written list that could drift — the failure class we already hit twice with the OpenAPI
// field tables and the tool-count prose.
const TOOL_META = new Map();
const regTool = (name, cfg, handler) => {
  if (REGISTERED_TOOLS.has(name)) throw new Error(`MCP tool ${name} is registered twice`);
  REGISTERED_TOOLS.add(name);
  TOOL_META.set(name, { title: cfg.title ?? name, description: String(cfg.description ?? "") });
  return mcp.registerTool(name, { ...cfg, annotations: cfg.annotations ?? READ_ONLY }, handler);
};
regTool("audit_bot_code", {
  title: "Audit crypto-bot source for fake-earnings bugs",
  description:
    `Input one JS/TS source file (string). Returns findings for: testnet-as-USD, silent-zero balance, cooldown key mismatch, fake faucet endpoint, speculative earnings text. Costs ${PRICE} USDC per call via x402.`,
  inputSchema: { code: z.string().describe("one JS/TS file"), filename: z.string().optional() },
}, async ({ code, filename }) => {
  console.log(`[audit] tools/call audit_bot_code ${filename || "submitted.js"} bytes=${code?.length || 0}`);
  const findings = scanText(code, filename || "submitted.js");
  return { content: [{ type: "text", text: JSON.stringify({ signalCount: findings.length, findings }, null, 2) }] };
});
regTool("demo_audit", {
  title: "Free demo of the audit (fixed sample, no payment)",
  description: "Runs the scanner on a small built-in bad-bot sample and returns the findings. Free; no x402 payment.",
  inputSchema: {},
  // The one tool whose result this file can prove end-to-end without money, so it carries the same
  // output contract the paid mirrors advertise.
  outputSchema: z.object({
    demo: z.boolean(),
    signalCount: z.number().int(),
    findings: z.array(z.record(z.string(), z.unknown())),
  }),
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
  const result = { demo: true, signalCount: findings.length, findings };
  return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], structuredContent: result };
});
// A buyer's router tests an endpoint before it pays, and until now the only thing it could test was the
// scanner demo. This gives the two differentiated products a free, provably-live sample — deliberately
// aggregate-only: totals and a median, never the per-host rows that are the paid content. Handing out the
// paid payload to look free would be the same self-harm as faking earnings, so the boundary is: counts here,
// names and rankings for money.
regTool("x402_rail_heartbeat", {
  title: "Free liveness sample of the x402 demand map (aggregates only)",
  description: "Free, no payment: proves this origin's x402 rail-intelligence routes are live by returning only the headline totals of our measured 30-day demand map (hosts, resources, calls, summed payers, median calls per host). WHICH hosts are earning, per-host calls/payers/rank and the per-token risk verdict stay paid — GET /market/x402-overview, /market/x402-top-sellers, /market/x402-host-demand, /market/x402-payer-bands, /market/token-verdict.",
  inputSchema: {},
  outputSchema: z.object({
    demo: z.boolean(), snapshot: z.boolean(), asOf: z.string().nullable(), ageDays: z.number().nullable(),
    hosts: z.number().int(), resources: z.number().int(), calls30d: z.number().int(),
    payerSlots30d: z.number().int(), medianCallsPerHost: z.number().int(), top6HostSharePct: z.number(),
    paid: z.record(z.string(), z.unknown()),
  }),
}, async () => {
  if (!RAIL || !RAIL_STATS) {
    const t = { demo: true, snapshot: false, asOf: null, ageDays: null, hosts: 0, resources: 0, calls30d: 0, payerSlots30d: 0, medianCallsPerHost: 0, top6HostSharePct: 0,
      paid: { error: "rail snapshot is not shipped in this build, so even the aggregate sample cannot be answered honestly" } };
    return { content: [{ type: "text", text: JSON.stringify(t, null, 2) }], structuredContent: t };
  }
  const t = {
    demo: true, snapshot: true, asOf: RAIL.asOf ?? null,
    ageDays: RAIL.asOf ? Math.round(((nowMs() - Date.parse(RAIL.asOf)) / 86_400_000) * 10) / 10 : null,
    hosts: RAIL.totals.hosts, resources: RAIL.totals.resources, calls30d: RAIL.totals.calls,
    payerSlots30d: RAIL.totals.payerSlots, medianCallsPerHost: RAIL_STATS.medianCalls,
    top6HostSharePct: RAIL_STATS.top6Share,
    paid: {
      "which hosts": "GET /market/x402-top-sellers", "one host": "GET /market/x402-host-demand?host=",
      "payer distribution": "GET /market/x402-payer-bands", "per-token risk": "GET /market/token-verdict?chain=base&token=0x…",
      "price": PRICE_DATA, "unit": "USDC per call, Base or Solana",
    },
  };
  return { content: [{ type: "text", text: JSON.stringify(t, null, 2) }], structuredContent: t };
});
regTool("get_token_price", {
  title: "Token spot price + liquidity (paid, Base or Solana)",
  description: `Live DEX spot price, liquidity, FDV, market cap and 24h volume for any token by contract address — EVM (Base/etc.) or Solana mint. Highest-liquidity pair. Costs ${PRICE_DATA} USDC per call via x402.`,
  inputSchema: { address: z.string().describe("Token contract address: EVM (0x…, 42 hex) or Solana base58 mint (32-44 chars)") },
}, async ({ address }) => {
  const a = typeof address === "string" ? address.trim() : "";
  if (!isTokenAddress(a))
    return { content: [{ type: "text", text: JSON.stringify({ error: "address must be an EVM contract (0x + 42 hex) or a Solana base58 mint" }) }], isError: true };
  const price = await fetchPrice(a);
  return { content: [{ type: "text", text: JSON.stringify(price, null, 2) }] };
});
regTool("search_tokens", {
  title: "Search tokens by name/symbol across DEXs (paid)",
  description: `Search crypto tokens by name or symbol; returns the highest-liquidity matched pairs with price, liquidity, FDV and 24h volume across chains. Costs ${PRICE_DATA} USDC per call via x402.`,
  inputSchema: { query: z.string().describe("token name or symbol, e.g. \"pepe\" or \"coinbase\""), limit: z.number().int().min(1).max(25).optional() },
}, async ({ query, limit }) => {
  const q = typeof query === "string" ? query.trim() : "";
  if (q.length < 1 || q.length > 64)
    return { content: [{ type: "text", text: JSON.stringify({ error: "query must be 1-64 chars" }) }], isError: true };
  const results = await searchTokens(q, Math.min(Math.max(Number(limit) || LEAN, 1), 25));
  return { content: [{ type: "text", text: JSON.stringify(results, null, 2) }] };
});
regTool("top_markets", {
  title: "Top coins by market cap (paid)",
  description: `Market-cap table with price, market cap, 24h volume and 1h/24h/7d change. Public aggregator snapshot, not an oracle. Costs ${PRICE_DATA} USDC per call via x402.`,
  inputSchema: { vs: z.enum(["usd", "eur", "gbp", "jpy", "btc", "eth"]).optional().describe("quote currency"), limit: z.number().int().min(1).max(100).optional() },
}, async ({ vs = "usd", limit = 25 }) => {
  const out = await topMarkets(vs, limit);
  return { content: [{ type: "text", text: JSON.stringify({ currency: vs, count: out.rows.length, rows: out.rows, source: out.source, caveat: "public aggregator snapshot, not an oracle", ts: new Date(nowMs()).toISOString() }, null, 2) }] };
});
regTool("chain_tvl", {
  title: "DeFi TVL ranked per chain (paid)",
  description: `Value locked in USD per chain, ranked. TVL is a protocol-reported metric, not a risk measure. Costs ${PRICE_DATA} USDC per call via x402.`,
  inputSchema: { limit: z.number().int().min(1).max(100).optional() },
}, async ({ limit = 25 }) => ({ content: [{ type: "text", text: JSON.stringify(await chainTvl(limit), null, 2) }] }));
regTool("stablecoin_supply", {
  title: "USD-pegged stablecoin supply by asset (paid)",
  description: `Circulating USD-pegged supply with peg mechanism and chain count. Costs ${PRICE_DATA} USDC per call via x402.`,
  inputSchema: { limit: z.number().int().min(1).max(100).optional() },
}, async ({ limit = 20 }) => ({ content: [{ type: "text", text: JSON.stringify(await stablecoinSnapshot(limit), null, 2) }] }));
regTool("trending_tokens", {
  title: "Promoted DEX tokens with live quotes (paid)",
  description: `Tokens currently bought into by projects for DEX exposure, enriched with price, liquidity and 24h volume. Boosts are paid promotions, not an endorsement. Costs ${PRICE_DATA} USDC per call via x402.`,
  inputSchema: { limit: z.number().int().min(1).max(50).optional(), chain: z.string().max(32).optional().describe("chainId filter, e.g. base or solana") },
}, async ({ limit = 10, chain }) => ({ content: [{ type: "text", text: JSON.stringify(await trendingBoosted(typeof chain === "string" ? chain.trim().slice(0, 32) : null, limit), null, 2) }] }));
regTool("gas_prices", {
  title: "Live gas and base fee in gwei (paid)",
  description: `Gas price, base fee and block height for Base and Arbitrum from public RPC — what a transaction costs before you send it. Costs ${PRICE_DATA} USDC per call via x402.`,
  inputSchema: { chains: z.array(z.enum(["base", "arbitrum"])).max(2).optional() },
}, async ({ chains = ["base", "arbitrum"] }) => ({ content: [{ type: "text", text: JSON.stringify(await gasPrices(chains), null, 2) }] }));

// ---- the published shape of a route's answer, as a schema ----
// A field table entry may declare `base|null`. That suffix is never a guess: `.tmp-check/gen-decls.mjs`
// writes it only for a field that came back `null` in a live, measured answer. It has to reach both
// documents, because the alternative is worse in opposite directions — JSON Schema cannot express
// "string|null" as a `type` string, and a zod field that receives null makes the SDK throw
// `Output validation error` AFTER the buyer's payment has already settled (validateToolOutput in
// @modelcontextprotocol/sdk server/mcp.js). Money taken, protocol error returned: the one failure mode
// this surface must not have.
const splitType = (t) => (String(t).endsWith("|null") ? [String(t).slice(0, -5), true] : [String(t), false]);
const jsonOf = (t) => {
  const [base, nul] = splitType(t);
  const j = base === "integer" ? "integer" : base === "number" ? "number" : base === "boolean" ? "boolean"
    : base === "array" ? "array" : base === "object" ? "object" : "string";
  return nul ? { type: [j, "null"] } : { type: j };
};
const zodOf = (t) => {
  const [base, nul] = splitType(t);
  let s = base === "integer" ? z.number().int() : base === "number" ? z.number() : base === "boolean" ? z.boolean()
    // Rows and nested objects keep their shape loose on purpose: this file can only prove the types of
    // the fields it measured, and an over-promised inner field would break a paid call.
    : base === "array" ? z.array(z.unknown()) : base === "object" ? z.record(z.string(), z.unknown()) : z.string();
  return nul ? s.nullable() : s;
};
// What the response envelope itself adds around a handler's object. Declared here so a client reading
// tools/list sees the same top-level keys it will receive.
const envelopeSchema = (r) => ({
  ts: z.string(), source: z.string(),
  ...(r.chainRoute ? { chain: z.string().nullable(), chainId: z.number().int().nullable(), chainLabel: z.string().nullable() } : {}),
  stale: z.boolean().nullable(), note: z.string().nullable(), reason: z.string().nullable(), caveat: z.string().nullable(),
});
// A route that SELLS one of the envelope's own keys (an `eth_chainId` read answers `chainId`) keeps its
// published type: the envelope entry is a fallback for the routes that do not declare it, never an
// overwrite of a measured one.
const envelopeExtras = (r, declared) => Object.fromEntries(Object.entries(envelopeSchema(r))
  .filter(([k]) => !declared.has(k)));
const envelopeJsonExtras = (r, declared) => Object.fromEntries(Object.entries({
  ts: { type: "string", format: "date-time" }, source: { type: "string", description: r.chainRoute ? "which public node answered" : "which venue answered" },
  ...(r.chainRoute ? { chain: { type: ["string", "null"] }, chainId: { type: ["integer", "null"] }, chainLabel: { type: ["string", "null"] } } : {}),
  stale: { type: ["boolean", "null"] }, note: { type: ["string", "null"] }, reason: { type: ["string", "null"] }, caveat: { type: ["string", "null"] },
}).filter(([k]) => !declared.has(k)));
// Every field is `.optional()`: one measured answer proves what a field CAN be, never that it always
// arrives, and a missing key against a `required` schema is the throw described above. Types are still
// enforced, which is the part a machine client actually needs to decode the payload.
const outputSchemaFor = (r) => {
  const declared = new Set((r.out || []).map((e) => e[0]));
  return z.object({
    ...Object.fromEntries((r.out || []).map(([k, t, d]) => {
      const s = zodOf(t);
      // The table's own description travels into the schema, so a client reads one field doc, not two.
      return [k, (d ? s.describe(String(d).slice(0, 200)) : s).optional()];
    })),
    ...Object.fromEntries(Object.entries(envelopeExtras(r, declared)).map(([k, s]) => [k, s.optional()])),
  });
};
const outputJsonSchemaFor = (r) => {
  const declared = new Set((r.out || []).map((e) => e[0]));
  return {
    type: "object",
    properties: {
      ...Object.fromEntries((r.out || []).map(([k, t, d]) => [k, { ...jsonOf(t), ...(d ? { description: String(d).slice(0, 200) } : {}) }])),
      ...envelopeJsonExtras(r, declared),
    },
  // `false` is the accurate claim, and it is not a choice: the SDK derives what tools/list advertises
  // from the zod object above and emits additionalProperties:false for a plain object (measured by
  // .tmp-check/mcp-wire-schema.mjs), so this document would otherwise state the opposite of the wire.
  // Nothing forbids it from being TRUE here — our own validation stays non-strict, so a field we forgot
  // to advertise cannot make a settled call throw. What keeps the claim honest is measurement:
  // schema-audit.mjs re-runs every live answer and fails on any key the table does not publish.
    additionalProperties: false,
  };
};

// ---- every data route is also an MCP tool ----
// The HTTP surface advertised 46 priced endpoints while `tools/list` advertised 8 paid tools, so an
// MCP client — the dominant kind of buyer on this rail — could not see, let alone call, 38 of them.
// Mirroring the table instead of hand-writing tools means the two protocols cannot disagree about a
// parameter, a price or which routes exist, and a route added to the table is reachable over MCP in
// the same commit. Values arrive as strings because the HTTP validators are string-in/typed-out: the
// exact same `parseChainArgs` runs here, so a bad shape is rejected identically on both paths.
for (const r of DATA_ROUTES) {
  const shape = {};
  for (const a of r.args) {
    const dflt = a.default === undefined ? "" : ` (default ${typeof a.default === "bigint" ? String(a.default) : JSON.stringify(a.default)})`;
    const d = `${String(a.desc).slice(0, 260)}${a.required ? " [required]" : dflt}`;
    shape[a.name] = a.required ? z.string().describe(d) : z.string().optional().describe(d);
  }
  const name = mcpToolName(r.path);
  regTool(name, {
    title: r.title,
    description: `${r.desc} Costs ${PRICE_DATA} USDC per call.${r.chainRoute ? ` Chains: ${CHAIN_KEYS.join(", ")}.` : ""} Byte-identical to GET ${r.path}?${argHint(r)}.`,
    inputSchema: shape,
    // The shape a buyer decodes, derived from the same measured table the HTTP documents render — see
    // outputSchemaFor for why every field is optional and `|null` fields accept null.
    outputSchema: outputSchemaFor(r),
  }, async (raw) => {
    // Availability rule, mirrored from the HTTP path: when every public source this read depends on is
    // failing from this host, refuse BEFORE running the handler. The gate already stood down for this call
    // (see requiresPayment), so nothing is settled, and returning here without calling run() means nothing
    // is served either. A buyer cannot be charged for a 502 and cannot get the data for free.
    if (allVenuesDown(r.path)) {
      console.log(`[unavailable] tools/call ${name} refused before the gate: all ${ROUTE_VENUES.get(r.path).length} venue(s) dead`);
      return mcpUnavailable(r.path);
    }
    const query = {};
    for (const [k, v] of Object.entries(raw || {})) if (typeof v === "string" && v.trim() !== "") query[k] = v;
    try {
      const args = parseChainArgs(r, query);
      const env = dataEnvelope(r, args, await r.run(args));
      return { content: [{ type: "text", text: JSON.stringify(env) }], structuredContent: env };
    } catch (e) {
      return { content: [{ type: "text", text: JSON.stringify(dataError(r, e).body) }], isError: true };
    }
  });
}
// Read from the registry itself, never typed: the count in the discovery documents is the count a
// client gets from tools/list.
const PAID_MCP_TOOL_COUNT = [...REGISTERED_TOOLS].filter((n) => !FREE_TOOLS.has(n)).length;
const FREE_MCP_TOOL_COUNT = REGISTERED_TOOLS.size - PAID_MCP_TOOL_COUNT;


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
const resourceServer = new x402ResourceServer(facilitatorClient)
  .register(NETWORK, new ExactEvmScheme())
  .register(SOLANA_NETWORK, new ExactSvmScheme());
// Bazaar's indexer only sees what the 402 challenge carries, so the input shape each route accepts is
// declared from the same arg table the validators use — one source of truth, no drift between what we
// advertise and what we actually enforce.
function bazaarInputOf(route) {
  const input = {}, properties = {}, required = [];
  for (const a of route.args) {
    // Query-parameter values in a Bazaar input MUST be strings: the SDK validates the extension it is
    // about to publish and, on a number like fromBlock 5000, silently drops the whole extension — so the
    // route loses the indexing that gets a buyer to find us. Measured, printed at boot:
    // `Route "GET /chain/logs" has an invalid bazaar extension: /input/queryParams/fromBlock: must be string`.
    if (a.example !== undefined) input[a.name] = String(a.example);
    properties[a.name] = { type: a.type || "string", description: String(a.desc).slice(0, 200) };
    if (a.required) required.push(a.name);
  }
  return { input, inputSchema: { type: "object", properties, required } };
}
// The 402 challenge is what a buyer's client reads BEFORE paying, so one document per route is
// generated from the same table the validator uses. `Chains:` only appears on the routes that
// actually read a chain node — a venue route that claimed to be chain state would be a false term.
const dataChallengeEntries = () => Object.fromEntries(DATA_ROUTES.map((r) => {
  const b = bazaarInputOf(r);
  return [`GET ${r.path}`, {
    accepts: acceptsFor(PRICE_DATA),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: `${r.desc} — ${PRICE_DATA} USDC per call, keyless.${r.chainRoute ? ` Chains: ${CHAIN_KEYS.join(", ")}.` : ""}`,
    mimeType: "application/json",
    tags: r.tags,
    extensions: {
      ...declareDiscoveryExtension({ method: "GET", input: b.input, inputSchema: b.inputSchema, output: { example: r.exampleOut } }),
    },
  }];
}));
// ---- MCP price classes (one resource, per-tool terms) ----
// /mcp is a single x402 resource, so the SDK used to answer every paid tools/call with the audit price
// — a buyer calling chain_balance paid $0.01 for a read that costs $0.001 over GET /chain/balance, and
// the tool's own description said $0.001. `price` may be a function of the request context (the server
// resolves it in buildPaymentRequirementsFromOptions), and the legacy v1 bridge re-reads that same
// requirement, so both envelopes carry the tool's real price by construction. Anything not named here
// stays at the audit price: a new tool is never silently cheaper than we advertise.
const MCP_DATA_TOOLS = new Set([
  ...DATA_ROUTES.map((r) => mcpToolName(r.path)),
  // Tools that shipped before DATA_ROUTES existed, each a mirror of a PRICE_DATA GET.
  "get_token_price", "search_tokens", "top_markets", "chain_tvl", "stablecoin_supply", "trending_tokens", "gas_prices",
]);
const mcpPriceFor = (context) => {
  const body = context?.adapter?.getBody?.();
  const tool = body && !Array.isArray(body) && body.method === "tools/call" ? body?.params?.name : null;
  return typeof tool === "string" && MCP_DATA_TOOLS.has(tool) ? PRICE_DATA : PRICE;
};
const mcpAccepts = () => ([
  { scheme: "exact", price: mcpPriceFor, network: NETWORK, payTo: PAY_TO },
  { scheme: "exact", price: mcpPriceFor, network: SOLANA_NETWORK, payTo: PAY_TO_SOLANA },
]);
{
  const ghost = [...MCP_DATA_TOOLS].filter((n) => !REGISTERED_TOOLS.has(n));
  const unpriced = [...REGISTERED_TOOLS].filter((n) => !FREE_TOOLS.has(n) && !MCP_DATA_TOOLS.has(n) && n !== "audit_bot_code");
  if (ghost.length || unpriced.length) {
    throw new Error(`MCP price classes drift from the registry: not registered=[${ghost.join(", ")}] no price class=[${unpriced.join(", ")}]`);
  }
}
const httpServer = new x402HTTPResourceServer(resourceServer, {
  "POST /mcp": {
    accepts: mcpAccepts(),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    // The gate keys off the path, not the JSON-RPC body, so one resource carries two price classes.
    // The challenge now names the called tool's own price; this text is what a cataloger reads first,
    // so it states the rule instead of quoting only the expensive one.
    description: `Per-call x402 payment for paid MCP tools/call on this server: ${PRICE} for audit_bot_code, ${PRICE_DATA} for every data tool — the same price as the HTTP route it mirrors.`,
    tags: ["mcp", "audit", "security", "agents", "ai"],
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
  "POST /a2a": {
    accepts: acceptsFor(PRICE),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    // A2A buyers resolve /.well-known/agent.json first and then POST message/send to `url`.
    // The card advertises one skill per priced route, so this challenge must be the audit
    // price and must say which skill it unlocks.
    description: `Per-call x402 payment for an A2A message/send task on this agent (${PRICE} for the audit_bot_code skill; see /.well-known/agent.json).`,
    tags: ["a2a", "agent-card", "audit", "security", "agents"],
    mimeType: "application/json",
    extensions: {
      ...declareDiscoveryExtension({
        method: "POST", bodyType: "json",
        input: { jsonrpc: "2.0", id: 1, method: "message/send", params: { message: { role: "user", parts: [{ kind: "data", data: { code: "state.earnings.total_usd += amount;" } }] } } },
        inputSchema: { type: "object", properties: { method: { type: "string" }, params: { type: "object" } }, required: ["method"] },
        output: { example: { result: { kind: "task", status: { state: "completed" }, artifacts: [{ parts: [{ data: { signalCount: 1 } }] }] } } },
      }),
    },
  },
  "POST /audit": {
    accepts: acceptsFor(PRICE),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: "Per-call x402 payment to audit one JS/TS crypto-bot source file over plain HTTP.",
    tags: ["audit", "security", "crypto", "code-analysis", "agents"],
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
  // A bare GET on the audit endpoint must read as PAYABLE, not as a dead end. Measured on the public
  // agentprobe.org x402 census (kind=x402: "GET the resource URL without payment … 402 with payment
  // header 100 · 404/405 20"): our POST-only /audit answered 405 to every one of their daily probes and
  // was scored 20/http-error from 2026-09-21 onward, while /gas — which takes no arguments and so
  // answers 402 — scored 100/ok. The scan itself is still only delivered over POST (below); this entry
  // exists so discovery — a crawler, or an agent that pings the URL to see if it is live — sees real
  // x402 terms and the PAYMENT-REQUIRED header instead of a method error.
  "GET /audit": {
    accepts: acceptsFor(PRICE),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: "x402 payment challenge for the crypto-bot honesty scan. The scan is delivered over POST /audit with the source in the JSON body; this GET carries the terms so a crawler or liveness probe can read them without eating a 405.",
    tags: ["audit", "security", "crypto", "code-analysis", "agents"],
    mimeType: "application/json",
    extensions: {
      // The SDK stamps `input.method` with the verb the challenge is being served on, so this entry
      // cannot claim POST. Therefore it claims NOTHING beyond an empty GET input: publishing a JSON
      // body here would advertise a call shape we refuse to serve, which is the same metadata-lie
      // class as the `|null` field tables and the two-schemas-disagreeing bug. Where the scan actually
      // runs is stated in `description`, which is the field a cataloger or an LLM buyer reads.
      ...declareDiscoveryExtension({
        method: "GET",
        input: {},
        inputSchema: { type: "object", properties: {}, required: [] },
        output: { example: { signalCount: 1, findings: [{ rule: "TESTNET_AS_USD", severity: "high", line: 1 }] } },
      }),
    },
  },
  "GET /price": {
    accepts: acceptsFor(PRICE_DATA),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: `Live DEX spot price + liquidity + FDV + 24h volume for any token by contract address (query ?address=0x.. or a Solana mint); returns the highest-liquidity pair. Cheap per-call market quote. — ${PRICE_DATA} USDC`,
    mimeType: "application/json",
    tags: ["price", "token", "market-data", "quote", "crypto"],
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
    accepts: acceptsFor(PRICE_DATA),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: `Search crypto tokens by name/symbol (query ?q=pepe&limit=12); returns highest-liquidity matched pairs with price, liquidity, FDV and 24h volume. Cheap per-call market lookup. — ${PRICE_DATA} USDC`,
    mimeType: "application/json",
    tags: ["token", "search", "price", "market-data", "crypto"],
    extensions: {
      ...declareDiscoveryExtension({
        method: "GET",
        input: { q: "pepe" },
        inputSchema: { type: "object", properties: { q: { type: "string", description: "token name or symbol to search" }, limit: { type: "number", description: "max results 1-25 (optional)" } }, required: ["q"] },
        output: { example: { query: "pepe", count: 2, results: [{ chainId: "base", symbol: "PEPE", address: "0x..", priceUsd: "0.00001", liquidityUsd: 42000, fdv: 120000, volume24h: 9000, source: "dexscreener" }], source: "dexscreener", ts: "2026-09-20T00:00:00.000Z" } },
      }),
    },
  },
  "GET /markets": {
    accepts: acceptsFor(PRICE_DATA),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: `Top coins by market cap: price, market cap, 24h volume, 1h/24h/7d change (query ?vs=usd&limit=25). Keyless pay-per-call market table for agents. — ${PRICE_DATA} USDC`,
    mimeType: "application/json",
    tags: ["market-cap", "price", "market-data", "crypto", "quote"],
    extensions: {
      ...declareDiscoveryExtension({
        method: "GET",
        input: { vs: "usd", limit: 5 },
        inputSchema: { type: "object", properties: { vs: { type: "string", description: "quote currency: usd, eur, gbp, jpy, btc or eth" }, limit: { type: "number", description: "rows 1-100 (default 25)" } } },
        output: { example: { source: "coingecko", rows: [{ rank: 1, id: "bitcoin", symbol: "btc", name: "Bitcoin", price: 81098, marketCap: 1610000000000, volume: 30000000000, change24h: 1.2 }] } },
      }),
    },
  },
  "GET /tvl": {
    accepts: acceptsFor(PRICE_DATA),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: `DeFi value-locked ranking per chain (query ?limit=25): TVL in USD plus chain id and gas token. — ${PRICE_DATA} USDC`,
    mimeType: "application/json",
    tags: ["tvl", "defi", "market-data", "chains", "crypto"],
    extensions: {
      ...declareDiscoveryExtension({
        method: "GET",
        input: { limit: 5 },
        inputSchema: { type: "object", properties: { limit: { type: "number", description: "rows 1-100 (default 25)" } } },
        output: { example: { source: "defillama", total: 280, rows: [{ chain: "Tron", chainId: null, tvl: 5400000000, gasToken: "TRX" }] } },
      }),
    },
  },
  "GET /stablecoins": {
    accepts: acceptsFor(PRICE_DATA),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: `USD-pegged stablecoin supply by asset, peg mechanism and chain count (query ?limit=20). — ${PRICE_DATA} USDC`,
    mimeType: "application/json",
    tags: ["stablecoins", "usdc", "peg", "supply", "market-data"],
    extensions: {
      ...declareDiscoveryExtension({
        method: "GET",
        input: { limit: 5 },
        inputSchema: { type: "object", properties: { limit: { type: "number", description: "rows 1-100 (default 20)" } } },
        output: { example: { source: "defillama", note: "circulating is USD-pegged supply, not a redemption guarantee", rows: [{ name: "Tether", symbol: "USDT", pegType: "peggedUSD", pegMechanism: "fiat-backed", circulating: 120000000000, onChain: 20 }] } },
      }),
    },
  },
  "GET /trending": {
    accepts: acceptsFor(PRICE_DATA),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: `Currently promoted DEX tokens with live price, liquidity and 24h volume (query ?limit=10&chain=base|solana|..). Note: boosts are paid promotions by token projects. — ${PRICE_DATA} USDC`,
    mimeType: "application/json",
    tags: ["trending", "dex", "token", "solana", "market-data"],
    extensions: {
      ...declareDiscoveryExtension({
        method: "GET",
        input: { limit: 5 },
        inputSchema: { type: "object", properties: { limit: { type: "number", description: "rows 1-50 (default 10)" }, chain: { type: "string", description: "optional chainId filter, e.g. base or solana" } } },
        output: { example: { source: "dexscreener", note: "boosts are paid promotions by token projects, not an endorsement", count: 5, rows: [{ chainId: "solana", tokenAddress: "DezX..", totalAmount: 50, priceUsd: "0.0004", liquidityUsd: 91000, volume24h: 240000, change24h: 12.5 }] } },
      }),
    },
  },
  "GET /gas": {
    accepts: acceptsFor(PRICE_DATA),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: `Live gas + base fee in gwei for Base and Arbitrum from public RPC (query ?chains=base,arbitrum). Costs a transaction before you send it. — ${PRICE_DATA} USDC`,
    mimeType: "application/json",
    tags: ["gas", "fees", "base", "arbitrum", "market-data"],
    extensions: {
      ...declareDiscoveryExtension({
        method: "GET",
        input: { chains: "base,arbitrum" },
        inputSchema: { type: "object", properties: { chains: { type: "string", description: "comma list from: base, arbitrum (default both)" } } },
        output: { example: { source: "public RPC", note: "gwei estimates from a public node; a simple transfer costs ~21000 gas", rows: [{ chain: "base", gasPriceGwei: 0.0061, baseFeeGwei: 0.005, blockNumber: 31200000 }] } },
      }),
    },
  },
  ...dataChallengeEntries(),
});
// Gate the JSON-RPC method level on /mcp; /audit is gated by matching its route config.
httpServer.requiresPayment = function (context) {
  const method = context.method || context.adapter?.getMethod?.();
  const path = context.path;
  if (method === "POST" && path === "/audit") return true;
  // GET /audit challenges (so discovery reads terms, see the "GET /audit" entry) but NEVER SETTLES: the
  // gate stands down the moment a payment header is on a GET, because there is no deliverable for a GET
  // and taking money to then answer 405 is exactly the theft this service exists to detect. A buyer that
  // signs a payment and puts it on a GET keeps its money and gets "resend as POST".
  if (method === "GET" && path === "/audit") {
    return !(context.adapter?.getHeader?.("payment-signature") || context.adapter?.getHeader?.("x-payment"));
  }
  // /a2a is gated twice on purpose. A plain x402 buyer gets the HTTP 402 challenge from the gate
  // below. A buyer that activates the A2A x402 extension cannot read an HTTP status — it wants an
  // A2A task in `input-required` — so the gate stands down for that header and the /a2a handler
  // enforces the same money itself through the same facilitator (verify, then settle, then scan).
  if (method === "POST" && path === "/a2a") {
    return !a2aX402ExtensionRequested({ "x-a2a-extensions": context.adapter?.getHeader?.("x-a2a-extensions") });
  }
  if (method === "GET" && PAID_DATA_PATHS.has(path)) return true;
  if (method === "POST" && path === "/mcp") {
    const body = context.adapter?.getBody?.() || {};
    if (FREE_METHODS.has(body.method)) return false;
    if (body.method === "tools/call") {
      const name = body?.params?.name;
      // A tool we do not serve must never reach the paywall: settling first and then answering
      // "tool not found" taxes a typo, and typos are not hypothetical here (chain_gas_prices is the
      // obvious guess for the route actually mirrored by chain_gas_estimate, and both names exist in
      // the same server). Unknown names are free and fail in the handler, where there is no
      // deliverable to give away.
      if (typeof name !== "string" || !REGISTERED_TOOLS.has(name)) return false;
      // Same rule as the HTTP refusal below, applied to the MCP mirror: when every public source a read
      // depends on is currently failing from this host, the gate stands down and the handler refuses
      // WITHOUT calling run(). The buyer is not charged and nothing is served, so neither a leak nor a
      // paid-502 is possible. `venueDown` expires on its own, so this heals as soon as a source answers.
      const mirrored = TOOL_TO_PATH.get(name);
      if (mirrored && allVenuesDown(mirrored)) return false;
      return !FREE_TOOLS.has(name);
    }
    return true;
  }
  return false; // every other path is free metadata
};

const app = express();
app.set("trust proxy", 1);
// ---- canonical request path (payment-gate integrity) ----
// The gate decides "is this payable?" by looking a path up in an exact-match table, while Express
// routes case-INsensitively and ignores a trailing slash. Those two disagree, so `/Price`, `/PRICE`,
// `/price/` and `/ChAiN/balance` all reached the handler while the gate saw an unknown path and let it
// through — the paid payload served unpaid (measured 2026-09-24 on every one of the 32 priced routes,
// including POST /audit, POST /mcp and POST /a2a). Rewriting the URL once, before the gate and before
// routing, makes both sides read the same canonical string, so no lookup can diverge. The query string
// is left byte-for-byte alone: EVM checksum addresses in it are significant.
app.use((req, _res, next) => {
  const qi = req.url.indexOf("?");
  const path = qi === -1 ? req.url : req.url.slice(0, qi);
  const qs = qi === -1 ? "" : req.url.slice(qi);
  const canon = path.toLowerCase().replace(/\/{2,}/g, "/").replace(/(.)\/+$/, "$1");
  if (canon !== path) req.url = canon + qs;
  next();
});
app.use(express.json({ limit: "2mb" }));
// x402scan's discovery contract fails an origin with "Expected 402, got 400": if body parsing throws
// before the payment gate, a crawler never sees our challenge and skips the service. Swallow the parse
// error here and let the route answer 400 only once the call has actually been paid for.
app.use((err, req, res, next) => {
  if (!(err instanceof SyntaxError && "body" in err)) return next(err);
  req.body = {};
  req.bodyParseError = true;
  next();
});

// Access log: without it we cannot tell a crawler from a payer. 2xx on a paid route = money moved.
// `pay=` records whether a payment was PRESENTED, separately from whether we accepted it: without it
// a buyer whose payment we rejected and a crawler that never intended to pay are the same log line,
// and "nobody ever tried to pay" stops being a claim anyone can check.
app.use((req, res, next) => {
  res.on("finish", () => {
    const q = req.originalUrl.length > 120 ? req.originalUrl.slice(0, 120) + "…" : req.originalUrl;
    const presented = req.get("payment-signature") ? "v2" : req.get("x-payment") ? "v1" : "-";
    // /mcp and /a2a are gated by JSON-RPC method, not path: initialize/tools/list/demo_audit answer 200
    // with no payment on purpose, so a bare "200 POST /mcp pay=-" line cannot tell a free handshake from
    // a paid tools/call that leaked. Record the method so the no-leak claim is attributable.
    let rpc = "";
    if (req.path === "/mcp" || req.path === "/a2a") {
      // Caller-controlled text goes into our own log line, so strip every non-printable: a newline in
      // `method` would otherwise forge a timestamped entry that never happened.
      const safe = (v) => String(v).replace(/[^\x20-\x7e]/g, "_").slice(0, 40);
      const m = req.body?.method;
      const t = req.body?.params?.name;
      rpc = ` rpc=${typeof m === "string" ? safe(m) : "-"}${t ? ` tool=${safe(t)}` : ""}`;
    }
    console.log(
      `[${new Date().toISOString()}] ${res.statusCode} ${req.method} ${q} ua=${(req.get("user-agent") || "-").slice(0, 60)} pay=${presented}${rpc}`,
    );
  });
  next();
});

// ---- free metadata (registered BEFORE the payment gate) ----
// RFC 9727 service catalog: how a crawler finds /openapi.json without being told. x402scan publishes one
// itself, so this mirrors their shape. The Link header goes on every response — including the 402 — so a
// buyer that just got paywalled immediately learns where the machine-readable contract lives.
const API_CATALOG_LINK = '</.well-known/api-catalog>; rel="api-catalog", </openapi.json>; rel="service-desc"; type="application/vnd.oai.openapi+json"';
app.use((_req, res, next) => { res.set("Link", API_CATALOG_LINK); next(); });

app.get("/health", (_req, res) => res.json({ ok: true, kind: "mcp+http",
  // The clock this service publishes, made auditable: `hostTs` is the machine's own wall clock,
  // `ts` is the timestamp a settled buyer receives, and `hostSkewMs` is how far an upstream's own
  // Date header says the host is off. If ts and hostTs differ, the correction is doing real work.
  clock: { ts: new Date(nowMs()).toISOString(), hostTs: new Date().toISOString(),
    hostSkewMs: clockHostSkewMs, correctionMs: clockOffsetMs, samples: clockOffsets.length },
  ...PAYMENT_INFO }));
app.get("/", (_req, res) => res.json({
  name: "crypto-bot-honesty-audit",
  endpoints: { paid: [`POST /audit (crypto-bot honesty scan, ${PRICE})`, "GET /price?address=0x.. (token spot price)", "GET /search_tokens?q=.. (token search)", "GET /markets?vs=usd&limit=25 (top coins by market cap)", "GET /tvl?limit=25 (chain TVL ranking)", "GET /stablecoins?limit=20 (pegged supply)", "GET /trending?limit=10 (promoted DEX tokens with quotes)", "GET /gas?chains=base,arbitrum (live gwei)", ...DATA_ROUTES.map((r) => `GET ${r.path}?${argHint(r)} (${r.title}, ${PRICE_DATA})`), `POST /mcp (${PAID_MCP_TOOL_COUNT} tools, metered per tools/call)`], free: ["GET /", "/health", "/llms.txt", "/openapi.json", "/.well-known/api-catalog", "/.well-known/x402", "/.well-known/x402-info", "MCP demo_audit + x402_rail_heartbeat"] },
  ...PAYMENT_INFO,
}));
// This route is registered in the FREE block, i.e. before the payment gate, so it must not swallow the
// bare probe: falling through with next() lets the gate answer it as a real 402 + PAYMENT-REQUIRED
// challenge (see the "GET /audit" terms entry). Only a GET that already carries a payment header
// reaches the body below — and it is refused, not settled, because a GET has no deliverable.
app.get("/audit", (req, res, next) => {
  if (!(req.headers["payment-signature"] || req.headers["x-payment"])) return next();
  res.status(405).json({
    error: "method_not_allowed", paid_endpoint: "POST /audit", ...PAYMENT_INFO,
    settled: false,
    note: "a payment presented on GET is never verified and never settled, so nothing was taken from you — resend the same payment on POST /audit with the source in the body and it will be honored there.",
    probe: "this service is LIVE; send POST with an x402 payment to use it",
  });
});
// Monitors probe GET /mcp for liveness. The Streamable-HTTP spec says a server that does not
// offer SSE answering GET with 405 — returning 404 made indexers mark this live server dead.
app.get("/mcp", (_req, res) => res.status(405).set("Allow", "POST").json({
  error: "method_not_allowed", protocol: "MCP Streamable HTTP", transport: "POST only",
  endpoint: `${PUBLIC_URL}/mcp`, server: "io.github.kaminariouji/x402-audit-agent",
  paywall: { ...PAYMENT_INFO, tool_prices: { audit_bot_code: PRICE, market_data_tools: PRICE_DATA } },
  free_tools: ["demo_audit", "x402_rail_heartbeat"], probe: "this MCP server is LIVE; POST an initialize to use it",
}));
// Agent Souk publisher verification (trust tier 2): proves this host belongs to our agent id.
const SOUK_AGENT_ID = process.env.AGENTSOUK_AGENT_ID || "";
app.get("/.well-known/agentsouk.txt", (_req, res) => res.type("text/plain").send(SOUK_AGENT_ID ? `agentsouk=${SOUK_AGENT_ID}\n` : "not configured\n"));
// agent-tools.cloud ownership proof — the row for this host already existed, and resubmitting cannot edit
// it ("already_listed … verify domain ownership to edit"), which is how it has kept advertising `price_max
// 0.05` and `resource_count 11` against a service that charges $0.001-$0.01 across 146 resources. Their
// claim API asked for `wellknown_file`: the token must be the WHOLE body of this exact path — no newline,
// no wrapper — or verification fails, so send it verbatim rather than pretty.
// The token is public by design (publishing it on the host IS the proof), but it still comes from the
// environment rather than the source: it is per-claim, it can be reissued, and this file is published on
// GitHub. Missing env answers 404, which is an honest "not configured", never an empty 200 that would look
// like a verification page to their crawler.
const ATC_VERIFY_TOKEN = process.env.AGENT_TOOLS_VERIFY_TOKEN || "";
app.get("/.well-known/agent-tools-verify.txt", (_req, res) => {
  if (!ATC_VERIFY_TOKEN) return res.status(404).type("text/plain").send("not configured\n");
  res.set("cache-control", "no-store").type("text/plain").send(ATC_VERIFY_TOKEN);
});
// x402scan / Bazaar fan-out compat: list payable resources at their absolute URLs.
// Routers (Glimind) publish a pricingUrl that points HERE, and their buyer record only carries an exact
// price once the document states one: `price`/`pricePerCallUsd` were null and `x402Details` absent for
// every x402 tool in the index, because bare URL strings priced nothing. `resources` stays a plain
// string array (that is what x402scan's contract validates), and `payments[]` adds the full per-call
// terms — amount in atomic units AND USD, CAIP-2 network, asset contract, payTo — so a buyer agent can
// construct the payment from metadata alone, without first eating a 402.
const OFFERED_NETS = [
  { network: NETWORK, asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: PAY_TO, decimals: 6 },
  { network: SOLANA_NETWORK, asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", payTo: PAY_TO_SOLANA, decimals: 6 },
];
const atomicOf = (usd) => String(Math.round(parseFloat(String(usd).replace(/[^0-9.]/g, "")) * 1e6));
// Glimind's own contract for a buyer is "payment.x402Details has the exact amount, asset, network and
// pay-to address" — four flat fields, not a list to choose from. `accepts[]` is the correct x402 shape
// for a paying client but reads as no price to a crawler that wants one answer, so each entry also
// states the flat form, pinned to the rail that can actually settle (Base; see acceptsFor above).
const PRIMARY_NET = OFFERED_NETS[0];
function termsFor(route) {
  const amount = atomicOf(route.price);
  const detail = { scheme: "exact", amount, currency: "USDC", decimals: PRIMARY_NET.decimals,
    network: PRIMARY_NET.network, asset: PRIMARY_NET.asset, payTo: PRIMARY_NET.payTo, maxTimeoutSeconds: 300 };
  return {
    url: PUBLIC_URL + route.path, method: route.method, scheme: "exact", currency: "USDC",
    priceUsd: route.price, priceAtomic: amount,
    ...detail,
    x402Details: detail,
    paymentHeaders: { preferred: "PAYMENT-SIGNATURE", legacy: "X-PAYMENT" },
    accepts: OFFERED_NETS.map((n) => ({ ...n, amount, maxTimeoutSeconds: 300 })),
  };
}
// Semantic catalogs (the search index buyer agents query) need per-resource fields, and ours used to
// publish nothing but bare URL strings — no name, no description, no tags, no price to embed. So the
// semantics are published, but NOT in `resources`: measured against the two sellers on this rail that
// demonstrably collect payers, `resources` is a plain array of strings on both of them —
//   https://api.onesource.io/.well-known/x402  → 71 strings, verb-prefixed paths ("GET /api/chain/allowance")
//   https://stableenrich.dev/.well-known/x402 → 39 strings, absolute URLs
// — so a validator that iterates `resources` expecting a URL (which is what x402scan's contract and our
// own published comment said before the enrichment) would have hit an object where a string belongs.
// `resources` therefore stays the string array it always was, `resource_calls` carries the verb-prefixed
// form the other convention uses, and the embeddable fields live in `resources_detail`. Nothing here
// changes what we charge: every `accepts` still comes from the same `acceptsFor()` the live gate calls,
// so manifest and challenge cannot disagree.
const usdOf = (s) => Number(String(s).replace(/[$\s]/g, "")) || 0;
const nameOf = (r) => {
  const head = String(r.description || "").split(/[:.]/)[0].trim();
  return (head || r.path).slice(0, 60);
};
const tagsOf = (r) => (r.tags && r.tags.length ? r.tags : r.path.replace(/^\//, "").split(/[\/_-]+/).filter((w) => w.length > 2).slice(0, 5));
// A published `accepts[]` must be PAYABLE-QUALITY, not just readable. `acceptsFor()` returns
// {scheme, price:"$0.001", network, payTo} — which is the *config* the SDK turns into full terms when it
// writes the 402 header (that is why the live challenge carries amount/asset/decimals/maxTimeoutSeconds),
// but we also pasted that un-enriched array straight into /discovery/resources and resources_detail.
// Measured on the buyer-side aggregator agent-tools.cloud (GET /api/v1/services/<our slug>): it stored
// `resource_count:11`, `health:"down"`, a `price_max` of $0.05 we have not charged in weeks, and accepts
// entries with no amount at all — because the only priced terms it could find were on the live 402, and
// a crawler that reads metadata and finds none fills in whatever an older crawl said. A client that wants
// to build a payment from the document alone could not: no atomic amount, no asset contract, no decimals.
// The gate config stays byte-for-byte alone (the SDK enriches it and the money path is verified by
// challenge-parse-all); ONLY published documents switch to the same enriched form termsFor() already uses
// for payments[], with `price` kept as well so a reader that parsed the old field still works.
const publishedAcceptsFor = (price) => {
  const amount = atomicOf(price);
  return OFFERED_NETS.map((n) => ({ ...n, amount, maxTimeoutSeconds: 300, price }));
};
const manifestResource = (r) => ({
  resource: `${PUBLIC_URL}${r.path}`, type: "http", method: r.method, x402Version: 1,
  name: nameOf(r), description: r.description, tags: tagsOf(r), price_usd: usdOf(r.price),
  accepts: publishedAcceptsFor(r.price),
});
app.get(["/.well-known/x402", "/.well-known/x402.json"], (_req, res) => {
  const detail = PAYABLE_ROUTES.map(manifestResource);
  const resources = detail.map((d) => d.resource);
  res.json({
    version: 1,
    // Both measured sellers that demonstrably collect payers publish a top-level `description` here
    // (api.onesource.io, stableenrich.dev) — because a cataloger stores the head of this document as the
    // seller's identity and does not re-read every per-resource field. We did not, so the buyer-side
    // broker's record of us kept whatever a broken crawl scraped: `service.description` =
    // "ngrok is the fastest way to put anything on the internet with a single command." — ngrok's own
    // boilerplate, from the moment the edge was serving us its interstitial instead of this JSON. A
    // crawler that reads the head now gets an accurate, keyword-rich identity from us instead of
    // guessing, and a stale crawl at least stores the right sentence.
    name: SERVICE_NAME,
    description: `Pay-per-call x402 agent, no account and no API key: ${DATA_ROUTES.length} atomic crypto reads at ${PRICE_DATA} USDC each — live token price and liquidity, token search, market caps, chain TVL and stablecoin supply, DEX trending, gas and base fees, native/token/NFT balances and state from a public RPC on ${CHAIN_KEYS.join(", ")}, order books, candles and funding rates as named venue reads (Kraken, Coinbase, OKX, Bitfinex, Gate, KuCoin, Deribit, Hyperliquid, DeFiLlama, mempool.space, alternative.me, Polymarket, DexScreener, Jupiter, Blockscout) — plus a composed token risk verdict and a ${PRICE} USDC source-code audit that finds the bug patterns that make a crypto bot report income it never earned. Settles in USDC on Base or Solana.`,
    tags: ["crypto", "market-data", "chain-data", "x402", "audit"],
    resources,
    resource_calls: PAYABLE_ROUTES.map((r) => `${r.method} ${r.path}`),
    resources_detail: detail,
    resource_paths: resources.map((u) => new URL(u).pathname),
    count: resources.length,
    ownershipProofs: [PAY_TO],
    payments: PAYABLE_ROUTES.map(termsFor),
    x402Details: { ...termsFor({ path: "/audit", method: "POST", price: PRICE }).x402Details,
      resourceIndex: `${PUBLIC_URL}/.well-known/x402`, perCall: true },
    networks: OFFERED_NETS,
    pricing: { model: "per_call", currency: "USDC", minUsd: PRICE_DATA.replace("$", ""), maxUsd: PRICE.replace("$", "") },
    instructions: `Pay-per-call x402 USDC on Base or Solana, no account and no API key. ${DATA_ROUTES.length} priced GET routes, each one atomic read at ${PRICE_DATA}: /chain/* reads chain state from a public node on ${CHAIN_KEYS.join(", ")} (?chain= plus the identifier); /market/* reads a named public venue — tickers, order books, candles, funding, order blocks, TVL and fee history, Bitcoin fees/mempool/hashrate, fear-and-greed, Polymarket markets, DexScreener pairs, Jupiter tokens, Blockscout explorer records. Legacy routes /price, /search_tokens, /markets, /tvl, /stablecoins, /trending, /gas cost the same. POST /audit (${PRICE}) scans a JS/TS crypto-bot file. Full parameter list per route: /openapi.json and the PAYMENT-REQUIRED challenge. MCP: ${PAID_MCP_TOOL_COUNT} paid tools on POST /mcp, mirrors of the same routes (${FREE_MCP_TOOL_COUNT} free: demo_audit plus the handshake).`,
  });
});
// Catalogers (BrickBlueBot, payai-style spiders) GET this exact path for the machine-readable
// resource list. Dual shape: `resources[]` of absolute URLs for x402scan, `items[]` carrying the
// full 402 terms so a client can pay without first taking the 402.
const PAYABLE_ROUTES = [
  { path: "/audit", method: "POST", price: PRICE, description: "Crypto-bot honesty scan: findings[] with file:line for the bug patterns that make a bot report income it never earned." },
  { path: "/price", method: "GET", price: PRICE_DATA, description: "Live DEX spot price, liquidity, FDV and volume for one token by contract address (EVM 0x.. or Solana base58 mint)." },
  { path: "/search_tokens", method: "GET", price: PRICE_DATA, description: "Token search by name/symbol; highest-liquidity matching pairs." },
  ...Object.entries(DATA_ROUTE_SPEC).map(([p, s]) => ({ path: p, method: "GET", price: PRICE_DATA, description: s.summary })),
  ...DATA_ROUTES.map((r) => ({ path: r.path, method: "GET", price: PRICE_DATA, description: r.summary, tags: r.tags })),
  { path: "/a2a", method: "POST", price: PRICE, description: "A2A JSON-RPC endpoint (message/send). Send source in a text or data part and get back findings[] with line numbers." },
  { path: "/mcp", method: "POST", price: PRICE, description: `MCP Streamable-HTTP server (POST only). Paid tools/call: audit_bot_code at ${PRICE}; every data tool is challenged at ${PRICE_DATA}, the price of the HTTP route it mirrors.` },
];
// A2A agent card: buyers that speak agent-to-agent resolve this BEFORE they can eat a 402,
// so every skill here is a route that actually exists, at the price actually charged.
const A2A_SKILLS = PAYABLE_ROUTES
  .filter((r) => r.path !== "/mcp" && r.path !== "/a2a")
  .map((r) => ({
    id: r.path.slice(1),
    name: `${r.method} ${r.path}`,
    description: `${r.description} Costs ${r.price} USDC per call over x402.`,
    tags: r.tags ?? ["crypto", "audit", "market-data", "agents", "x402"],
    inputModes: [r.method === "POST" ? "application/json" : "text/plain"],
    outputModes: ["application/json"],
    examples: [r.method === "POST" ? `POST ${PUBLIC_URL}${r.path} with {"code":"<one JS/TS file>"} (or an A2A message/send to ${PUBLIC_URL}/a2a)` : `GET ${PUBLIC_URL}${r.path}`],
  }));
app.get("/discovery/resources", (_req, res) => res.json({
  version: 1,
  server: "io.github.kaminariouji/x402-audit-agent",
  name: "crypto-bot-honesty-audit",
  protocol: "x402 (HTTP 402)",
  currency: "USDC",
  networks: [NETWORK, SOLANA_NETWORK],
  payTo: { [NETWORK]: PAY_TO, [SOLANA_NETWORK]: PAY_TO_SOLANA },
  facilitator: FACILITATOR_URL,
  documentationUrl: DOCS_URL,
  resources: PAYABLE_ROUTES.map((r) => PUBLIC_URL + r.path),
  items: PAYABLE_ROUTES.map((r) => ({
    resource: PUBLIC_URL + r.path, method: r.method, x402Version: 2,
    accepts: publishedAcceptsFor(r.price), serviceName: SERVICE_NAME, iconUrl: ICON_URL,
    description: r.description, tags: r.tags ?? ["crypto", "audit", "market-data", "agents", "api"],
  })),
}));
// Catalogers probe the whole verb matrix (PATCH/PUT/DELETE/HEAD) against a payable path before
// trusting it; a 404 reads as "route is dead" and the service gets skipped, so answer with the
// method that works plus the price. OPTIONS stays free for CORS preflight.
const PAYABLE_BY_PATH = new Map(PAYABLE_ROUTES.map((r) => [r.path, r]));
app.use((req, res, next) => {
  const route = PAYABLE_BY_PATH.get(req.path);
  const method = req.method.toUpperCase();
  if (!route || method === route.method || method === "OPTIONS") return next();
  // EXCEPT a bare GET on the audit endpoint: for an x402 resource a 405 is not "live", it is a dead end.
  // Measured on agentprobe.org (kind=x402 grades the unpaid GET on the resource URL: 402 with the
  // PAYMENT-REQUIRED header 100, 402 without 80, 404/405 20) — our POST-only /audit scored 20/http-error
  // on every daily probe from 2026-09-21 while /gas, which answers 402, scored 100/ok. Letting this fall
  // through reaches the payment gate, which now holds a "GET /audit" terms entry and answers 402 +
  // header. A GET that carries a payment header never gets here: the /audit route above refuses it first,
  // so this path cannot settle a request that has no deliverable.
  if (route.path === "/audit" && method === "GET") return next();
  return res.status(405).set("Allow", `${route.method}, OPTIONS`).json({
    error: "method_not_allowed",
    paid_endpoint: `${route.method} ${route.path}`,
    endpoint: PUBLIC_URL + route.path,
    paywall: { ...PAYMENT_INFO, price: route.price },
    probe: `this service is LIVE; send ${route.method} with an x402 payment (${route.price} USDC) to use it`,
  });
});
app.get("/.well-known/api-catalog", (_req, res) => {
  const at = (href) => PUBLIC_URL + href;
  const link = (rel, href, type, title) => ({ rel, href: at(href), type, title });
  res.type("application/linkset+json").json({
    linkset: [{
      anchor: at("/openapi.json"),
      "service-desc": [{ href: at("/openapi.json"), type: "application/vnd.oai.openapi+json", title: "x402 audit + market-data OpenAPI specification" }],
      "service-doc": [{ href: at("/llms.txt"), type: "text/plain", title: "Agent briefing: prices, endpoints, how to pay" }],
      status: [{ href: at("/health"), type: "application/json", title: "Service health" }],
      links: [
        link("service-desc", "/openapi.json", "application/vnd.oai.openapi+json", "OpenAPI 3.1 contract for every paid route"),
        link("service-doc", "/llms.txt", "text/plain", "crypto-bot-honesty-audit agent briefing"),
        link("status", "/health", "application/json", "Liveness + payment info"),
        link("describedby", "/discovery/resources", "application/json", "x402 fan-out: every payable route with its challenge"),
        link("describedby", "/.well-known/x402", "application/json", "x402 resource index with wallet ownership proof"),
      ],
    }, {
      anchor: at("/mcp"),
      "service-desc": [{ href: at("/.well-known/x402"), type: "application/json", title: "x402 resource index" }],
      links: [
        link("service-desc", "/openapi.json", "application/vnd.oai.openapi+json", "HTTP contract"),
        link("sse", "/mcp", "application/json", `MCP Streamable-HTTP endpoint (${REGISTERED_TOOLS.size} tools, ${PAID_MCP_TOOL_COUNT} of them x402-metered per call)`),
      ],
    }],
  });
});
// Deliberately permissive: every route is public (payment is enforced per-request, not by
// crawling policy), and the LLMs field points agents at the machine-readable service terms.
// A2A agent card, at both path spellings the ecosystem actually requests (0.2 used
// agent.json, 0.3 uses agent-card.json; indexers ask for one or the other and a 404
// reads as "no A2A agent here"). Free, because it is what a buyer reads to decide.
// ---- MCP server card + ARD resource catalog (two more published discovery conventions) ----
// Measured on the agentprobe.org census (37 registries + 7 well-known conventions harvested): the
// conventions it crawls include `wellknown-mcp-server-card` and `wellknown-ard-catalog` (43,126 ARD
// endpoints probed). We served A2A card, api-catalog, x402, llms.txt, robots and openapi, but nothing
// on these two paths — so every crawler that speaks them had no way to learn that this origin exists.
// Both documents are GENERATED: the tool list comes from TOOL_META (the same object each regTool call
// advertises), the protocol revisions from the installed SDK, and the prices from the same PRICE /
// PRICE_DATA constants the gate challenges with. Nothing here is typed by hand, so a card cannot claim
// a tool, a version or a price the wire does not serve.
const HOST_AUTHORITY = (() => { try { return new URL(PUBLIC_URL).host; } catch { return "localhost"; } })();
const MCP_CARD = {
  name: "crypto-bot-honesty-audit",
  title: SERVICE_NAME,
  description: `Pay-per-call x402 agent: ${PRICE} USDC for audit_bot_code (a crypto-bot honesty scan that reports the bug patterns behind fake earnings), ${PRICE_DATA} USDC for each of the ${DATA_ROUTES.length} market/chain data tools, and two free tools (demo_audit, x402_rail_heartbeat) to test before paying. No account, no API key — an unpaid call answers HTTP 402 with USDC terms on Base and Solana.`,
  version: "1.0.0",
  url: `${PUBLIC_URL}/mcp`,
  transport: { type: "streamable-http", url: `${PUBLIC_URL}/mcp` },
  protocolVersions: SUPPORTED_PROTOCOL_VERSIONS,
  preferredProtocolVersion: LATEST_PROTOCOL_VERSION,
  // True in the sense the field means: no signup, no credential, no key issued. Payment is separate
  // from authentication and is stated in the description and in every tool's own description.
  authentication: { type: "none" },
  capabilities: { tools: true, resources: false, prompts: false },
  // Which tools answer without money, named exactly — the card is read by installers and by generator
  // scripts, and "free" must never be inferred from the wording of a description (a regex over
  // descriptions once claimed chain_logs was free; it is not, it costs PRICE_DATA like every data tool).
  free_tools: [...FREE_TOOLS],
  paid_tools: { audit_bot_code: PRICE, every_data_tool: PRICE_DATA },
  serverInfo: { name: "crypto-bot-honesty-audit", version: "1.0.0" },
  documentationUrl: DOCS_URL,
  tools: [...TOOL_META.entries()].map(([name, t]) => ({ name, title: t.title, description: t.description })),
};
app.get(["/.well-known/mcp.json", "/.well-known/mcp/server-card.json"], (_req, res) => res.json(MCP_CARD));
const ARD_ENTRY = (suffix, displayName, type, url, description, tags, extra = {}) => ({
  identifier: `urn:air:${HOST_AUTHORITY}:${suffix}`, displayName, type, url, description, tags, ...extra,
});
app.get(["/.well-known/ai-catalog.json", "/.well-known/ard.json"], (_req, res) => res.json({
  "@context": "https://agenticresourcediscovery.org/context/v1",
  specVersion: "1.0",
  host: {
    identifier: PUBLIC_URL, displayName: SERVICE_NAME,
    trustManifest: { identity: PUBLIC_URL, identityType: "https" },
  },
  entries: [
    ARD_ENTRY("mcp:x402-audit-agent", `${SERVICE_NAME} (MCP, pay-per-call)`, "application/mcp-server-card+json",
      `${PUBLIC_URL}/.well-known/mcp/server-card.json`,
      `${TOOL_META.size} tools over MCP Streamable HTTP: one crypto-bot honesty scan at ${PRICE} and ${DATA_ROUTES.length} market/chain reads at ${PRICE_DATA}, two free.`,
      ["x402", "payments", "crypto", "market-data", "audit"], { endpoint: `${PUBLIC_URL}/mcp`, version: "1.0.0" }),
    ARD_ENTRY("a2a:x402-audit-agent", `${SERVICE_NAME} (A2A)`, "application/a2a-agent-card+json",
      `${PUBLIC_URL}/.well-known/agent-card.json`,
      `Agent-to-agent card for the same agent; POST ${PUBLIC_URL}/a2a with an x402 payment runs a message/send task at ${PRICE}.`,
      ["x402", "a2a", "agent-card", "audit"], { version: "1.0.0" }),
    ARD_ENTRY("api:x402-openapi", "OpenAPI 3.1 contract (GET-only routes)", "application/vnd.oai.openapi+json",
      `${PUBLIC_URL}/openapi.json`,
      `Every priced route with its parameters, its 402 response and its field list. ${DATA_ROUTES.length} GET routes plus POST /audit.`,
      ["openapi", "x402", "market-data", "crypto"]),
    ARD_ENTRY("api:x402-terms", "x402 payment terms for every priced resource", "application/json",
      `${PUBLIC_URL}/.well-known/x402`,
      `Per-call USDC terms for all ${PAYABLE_ROUTES.length} payable resources — CAIP-2 network, asset contract, amount in atomic units, USD price and the payTo address — so a buyer can construct a payment without first taking a 402.`,
      ["x402", "payments", "discovery", "pricing"]),
    ARD_ENTRY("doc:agent-briefing", "llms.txt agent briefing", "text/plain",
      DOCS_URL,
      "What this origin sells, at what price, on which networks, and how to pay in two requests.",
      ["llms-txt", "docs", "x402"]),
  ],
}));
app.get(["/.well-known/agent.json", "/.well-known/agent-card.json"], (_req, res) => {
  res.json({
    protocolVersion: "0.3.0",
    name: SERVICE_NAME,
    description:
      "Pay-per-call agent: scans a JS/TS crypto-bot source file for the bug patterns that make it report income it never earned, plus market-data routes (token price, search, market cap, TVL, stablecoins, trending, gas). No account and no API key — payment is x402 (HTTP 402) in USDC.",
    version: "1.0.0",
    // @a2a-js/sdk's legacy path copies preferredTransport straight into protocolBinding, whose
    // core enum is JSONRPC/GRPC/HTTP+JSON — the natural-looking "JSON-RPC" made every v1.x client
    // fail to select our interface. supportedInterfaces is the current (1.0) shape; url stays for
    // 0.2/0.3 readers, and a card that carries both parses on either path.
    url: `${PUBLIC_URL}/a2a`,
    preferredTransport: "JSONRPC",
    supportedInterfaces: [
      { url: `${PUBLIC_URL}/a2a`, protocolBinding: "JSONRPC", protocolVersion: "1.0", tenant: "" },
    ],
    iconUrl: ICON_URL,
    documentationUrl: DOCS_URL,
    provider: { organization: "kaminariouji", url: "https://github.com/kaminariouji" },
    // required:true + the URI below is how the A2A x402 extension client (google-agentic-commerce/
    // a2a-x402) decides this agent takes payment at the task layer; see a2a.mjs handleA2AX402Request.
    capabilities: {
      streaming: false, pushNotifications: false, stateTransitionHistory: false,
      extensions: [{ uri: X402_A2A_EXT_URI, description: "Supports payments using the x402 protocol.", required: true }],
    },
    defaultInputModes: ["application/json", "text/plain"],
    defaultOutputModes: ["application/json"],
    skills: A2A_SKILLS,
    // Not an A2A-standard field: the payment terms an x402 client needs to build the
    // authorization without first eating a 402.
    x402: {
      protocol: "x402 (HTTP 402)", currency: "USDC", prices: { audit: PRICE, market_data: PRICE_DATA },
      networks: OFFERED_NETS.map((n) => n.network), payTo: PAY_TO,
      resourceIndex: `${PUBLIC_URL}/.well-known/x402`, info: `${PUBLIC_URL}/.well-known/x402-info`,
      note: "POST /a2a settles the audit skill; the market-data skills are priced GET routes, called directly with a payment.",
    },
  });
});
app.get("/robots.txt", (_req, res) => res.type("text/plain").send([
  "User-agent: *", "Allow: /", "", `LLMs: ${PUBLIC_URL}/llms.txt`,
  `Sitemap hint: ${PUBLIC_URL}/.well-known/x402-info`,
  `Service catalog (RFC 9727): ${PUBLIC_URL}/.well-known/api-catalog`,
  `x402 resource fan-out: ${PUBLIC_URL}/discovery/resources`, "",
].join("\n")));
app.get("/.well-known/x402-info", (_req, res) => res.json({
  name: "crypto-bot-honesty-audit",
  description: `Paid x402 agent (HTTP + MCP), no account and no API key: (1) scans a JS/TS crypto-bot source file for the bug patterns that make it report income it never earned; (2) ${DATA_ROUTES.length} atomic keyless reads at ${PRICE_DATA} each — ${CHAIN_ROUTES.length} chain-state RPC routes on ${CHAIN_KEYS.join(", ")} and ${MARKET_ROUTES.length} public-venue routes (spot tickers, order books, OHLC candles, funding, derivatives specs, DeFi TVL and fee history, Bitcoin fees/mempool/hashrate, market sentiment, prediction markets, DEX pair discovery, Solana token lookups and explorer contract records).`,
  documentationUrl: DOCS_URL,
  contactUrl: "https://github.com/kaminariouji",
  protocol: "x402 (HTTP 402)",
  pricing: { currency: "USDC", networks: [NETWORK, SOLANA_NETWORK], endpoints: [
    { path: "/audit", method: "POST", price: PRICE },
    { path: "/price", method: "GET", price: PRICE_DATA, note: "token spot price by ?address= (EVM 0x or Solana mint)" },
    { path: "/search_tokens", method: "GET", price: PRICE_DATA, note: "token search by ?q=name-or-symbol" },
    { path: "/markets", method: "GET", price: PRICE_DATA, note: "top coins by market cap by ?vs=usd&limit=25" },
    { path: "/tvl", method: "GET", price: PRICE_DATA, note: "chain TVL ranking by ?limit=25" },
    { path: "/stablecoins", method: "GET", price: PRICE_DATA, note: "USD-pegged supply by ?limit=20" },
    { path: "/trending", method: "GET", price: PRICE_DATA, note: "promoted DEX tokens with quotes by ?limit=10&chain=" },
    { path: "/gas", method: "GET", price: PRICE_DATA, note: "live gwei for base,arbitrum by ?chains=" },
    ...DATA_ROUTES.map((r) => ({ path: r.path, method: "GET", price: PRICE_DATA, note: `${r.title} — ?${r.args.map((a) => a.name).join("&")}` })),
    { path: "/mcp", method: "POST", price: PRICE, note: `per tools/call: ${PRICE} for audit_bot_code, ${PRICE_DATA} for each data tool (same as its GET route)` },
  ], freeEndpoints: ["/", "/health", "/llms.txt", "/robots.txt", "/discovery/resources", "/openapi.json", "/.well-known/api-catalog", "/.well-known/x402-info", "MCP demo_audit + x402_rail_heartbeat"] },
  capabilities: ["analyze", "audit", "classify", "market-data", "price", "search", "markets", "market-cap", "tvl", "defi", "stablecoins", "trending", "gas", "fees", "transaction-cost", "chain-state", "balance", "nonce", "block", "transaction-lookup", "receipt", "event-logs", "contract-read", "token-balance", "nft-ownership", "multi-chain"],
  payTo: { [NETWORK]: PAY_TO, [SOLANA_NETWORK]: PAY_TO_SOLANA },
}));
// The x402scan discovery contract is picky in ways the x402 spec isn't: protocols must be an array of
// PROTOCOL OBJECTS, prices are decimal USD, and a paid operation with no response schema is rejected as
// "Input/Output Schema Missing". All three are silent registration failures, so encode them once here.
const usdPrice = (p) => Number(String(p).slice(1)).toFixed(6);
const xpi = (amount) => ({ protocols: [{ x402: {} }], price: { mode: "fixed", currency: "USD", amount: usdPrice(amount) } });
const OBJ = (description, properties = {}, required = []) => ({
  type: "object", description, additionalProperties: true,
  ...(Object.keys(properties).length ? { properties } : {}), ...(required.length ? { required } : {}),
});
const ROWS = (description, key) => OBJ(description, { [key]: { type: "array", items: { type: "object", additionalProperties: true } } }, [key]);
// Returns a METHOD-KEYED path item (OpenAPI requires paths -> {path} -> {verb} -> operation).
const paidOp = (verb, summary, amount, input, output) => ({ [verb]: {
  summary,
  "x-payment-info": xpi(amount),
  // Declaring `security: [{x402: []}]` here made every buyer-side client that maps OpenAPI security schemes
  // to an auth mode label all 136 paid routes "apiKey+paid" — a credential requirement that does not exist
  // (our own x-guidance says "no signup and no API key"). Measured through agentcash against the deployed
  // origin, and compared with 47620.xyz, a seller that does get paid: its paid routes declare `security: []`
  // and the client still labels them `paid`, because it probes and reads the real 402. Payment is stated
  // where machines read it — x-payment-info, /discovery/resources, and the 402 challenge itself — never as
  // an API key.
  security: [],
  ...(input.body ? { requestBody: { required: true, content: { "application/json": { schema: input.body, ...(input.example ? { example: input.example } : {}) } } } } : {}),
  ...(input.params ? { parameters: input.params.map(([name, required, description, type, example]) => ({ name, in: "query", required, description, schema: { type }, ...(example === undefined ? {} : { example }) })) } : {}),
  responses: {
    200: { description: "Payload, served only after settlement.", content: { "application/json": { schema: output } } },
    402: { description: "Payment required — x402 terms on the PAYMENT-REQUIRED header.", content: { "application/json": { schema: OBJ("payment requirements", { error: { type: "string" }, maxAmountRequired: { type: "string" } }) } } },
  },
} });
const xGuidance = () => [
  `Paid routes, no signup and no API key: ${PAYABLE_ROUTES.length} priced resources on this origin — ${DATA_ROUTES.length} route reads (${CHAIN_ROUTES.length} chain-state under /chain/, ${MARKET_ROUTES.length} public-venue under /market/) at ${PRICE_DATA} per call, the audit at ${PRICE}.`,
  "(1) POST /audit body { code, filename } -> crypto-bot honesty findings.",
  `(2) ${Object.keys(DATA_ROUTE_SPEC).length + 2} legacy GET data routes: /price?address=0x.., /search_tokens?q=name, ${Object.keys(DATA_ROUTE_SPEC).join(", ")}.`,
  `(3) ${CHAIN_ROUTES.length} chain-read routes under /chain/, each taking ?chain= (one of ${CHAIN_KEYS.join(", ")}) plus its identifier: ${DATA_ROUTES.filter((r) => r.chainRoute).map((r) => r.path).join(" ")}.`,
  `(4) ${MARKET_ROUTES.length} public-venue reads under /market/ (tickers, order books, OHLC candles, funding, derivatives specs, DeFi TVL and fee history, Bitcoin fees/mempool/hashrate, sentiment, prediction markets, DEX pairs, Solana tokens, explorer records): ${DATA_ROUTES.filter((r) => r.marketRoute).map((r) => r.path).join(" ")}. Each has its own regex-validated identifier argument, enforced BEFORE payment.`,
  `Unpaid -> HTTP 402 with x402 terms on the PAYMENT-REQUIRED header; pay USDC on Base (${NETWORK}) or Solana (${SOLANA_NETWORK}) via an x402 client and resend with the payment in the PAYMENT-SIGNATURE header (v2 wire). A legacy v1 X-PAYMENT envelope on Base is also accepted on the EVM rail.`,
  `MCP: POST /mcp mirrors every route above as a tool of the same name (${PAID_MCP_TOOL_COUNT} paid tools, ${FREE_MCP_TOOL_COUNT} free); the audit tool is audit_bot_code.`,
].join(" ");
// Same arg table the validators read, so the published OpenAPI cannot promise a parameter shape the
// route would then reject.
const dataOpenApiOp = (r) => [r.path, paidOp("get", r.summary, PRICE_DATA,
  { params: r.args.map((a) => [a.name, !!a.required, String(a.desc).slice(0, 180), a.type || "string",
    a.example === undefined ? undefined : String(a.example)]) },
  // One builder for both protocols: this is literally the same object the MCP mirror derives, so the
  // OpenAPI document and `tools/list` cannot state two different shapes for one settled call.
  { description: `${r.title} result`, ...outputJsonSchemaFor(r) },
)];
// Endpoints we neither charge for nor want probed. Undeclared or unclassified paths get crawled as if
// they were paid, answer no 402, and the scanner logs it as "No 402 challenge" against the whole origin.
const freeOp = (summary) => ({ summary, security: [], responses: { 200: { description: "Public metadata, no payment.", content: { "application/json": { schema: OBJ("metadata", {}, []) } } } } });
app.get("/openapi.json", (_req, res) => res.json({
  openapi: "3.1.0",
  info: {
    title: "crypto-bot-honesty-audit", version: "1.1.0",
    description: "Pay-per-call x402 agent: crypto-bot honesty scan plus keyless per-call crypto market data (price, search, market cap, TVL, stablecoins, trending, gas).",
    contact: { url: DOCS_URL },
    "x-guidance": xGuidance(),
  },
  servers: [{ url: PUBLIC_URL }],
  // No global security requirement: see paidOp. The scheme stays documented for spec-checkers that look it up
  // by name, described as the payment itself and explicitly NOT a credential a buyer must obtain.
  security: [],
  components: { securitySchemes: { x402: { type: "apiKey", in: "header", name: "PAYMENT-SIGNATURE", description: `Documented for reference only — nothing here needs signup or an API key, and no key is issued. This names the header that carries an x402 USDC payment on ${NETWORK} or ${SOLANA_NETWORK}: request the route unpaid, read the 402 challenge on the PAYMENT-REQUIRED header (it lists both accepts), settle one, then resend with the payment in PAYMENT-SIGNATURE (v2 wire). On the Base rail a legacy v1 envelope in the X-PAYMENT header is also verified and settled — this origin supplies the accepted terms itself, so a client cannot negotiate them.` } } },
  paths: { "/audit": paidOp("post", "Audit a crypto-bot source file for fake-earnings bug patterns (paid via x402)", PRICE, {
    body: OBJ("One source file to scan", { code: { type: "string", description: "one JS/TS file, UTF-8" }, filename: { type: "string", description: "optional display name" } }, ["code"]),
    example: { code: 'const provider = new ethers.JsonRpcProvider("https://eth-sepolia.g.alchemy.com/v2/KEY");\nstate.earnings.total_usd += amount;', filename: "bot.js" },
  }, OBJ("Static-analysis findings", {
    scannedBytes: { type: "integer" }, signalCount: { type: "integer" },
    findings: { type: "array", items: OBJ("one signal", { rule: { type: "string" }, file: { type: "string" }, line: { type: "integer" }, severity: { type: "string" }, detail: { type: "string" } }) },
    disclaimer: { type: "string" },
  }, ["signalCount", "findings"])), "/price": paidOp("get", "Live DEX token spot price + liquidity by contract address, EVM or Solana (paid via x402)", PRICE_DATA, {
    params: [["address", true, "Token contract address: EVM (0x…, 42 hex) or Solana base58 mint (32-44 chars)", "string", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"]],
  }, OBJ("Highest-liquidity pair quote", {
    address: { type: "string" }, priceUsd: { type: "string", description: "spot price in USD as a decimal string" },
    liquidityUsd: { type: "number" }, fdv: { type: "number" }, marketCap: { type: "number" }, volume24h: { type: "number" }, source: { type: "string" },
  }, ["priceUsd"])), "/search_tokens": paidOp("get", "Search crypto tokens by name/symbol; returns highest-liquidity matched pairs (paid via x402)", PRICE_DATA, {
    params: [
      ["q", true, "token name or symbol to search (1-64 chars)", "string", "pepe"],
      ["limit", false, "max results 1-25", "number", 12],
    ],
  }, ROWS("Matched token pairs", "results")), ...Object.fromEntries(Object.entries(DATA_ROUTE_SPEC).map(([p, s]) => [p, paidOp(
    "get", s.summary, PRICE_DATA, { params: s.params },
    p === "/markets" ? ROWS("Top coins by market cap", "rows") : OBJ("Market-data snapshot rows, source and caveat", { ts: { type: "string", format: "date-time" }, caveat: { type: "string" } }),
  )])), ...Object.fromEntries(DATA_ROUTES.map(dataOpenApiOp)), "/mcp": { post: {
    summary: "MCP Streamable-HTTP endpoint (handshake and tools/list free; paid tools/call metered in-session)",
    security: [],
    responses: { 200: { description: "JSON-RPC response over server-sent events.", content: { "application/json": { schema: OBJ("JSON-RPC result") } } } },
  } }, ...Object.fromEntries([
    ["/", "Service card: name, endpoints, price and payout address"],
    ["/health", "Liveness plus payment info"],
    ["/llms.txt", "Plain-text agent briefing"],
    ["/openapi.json", "This document"],
    ["/robots.txt", "Crawler conventions, pointing at llms.txt"],
    ["/discovery/resources", "Fan-out list of every payable route with its challenge"],
    ["/.well-known/x402-info", "x402 merchant metadata"],
    ["/.well-known/x402", "x402 resource index with ownership proof"],
    ["/.well-known/api-catalog", "RFC 9727 service catalog (linkset)"],
  ].map(([p, d]) => [p, { get: freeOp(d) }])), },
}));
app.get("/llms.txt", (_req, res) => res.type("text/plain").send([
  "# crypto-bot-honesty-audit", "",
  "> Pay-per-call x402 agent that scans one JS/TS crypto-bot source file for the bug patterns that make it report income it never earned.", "",
  `Price: ${PRICE} USDC for the audit scan, ${PRICE_DATA} USDC for each data read — both on ${NETWORK} (Base) via x402 HTTP-402. No signup, no API key. Recipient: ${PAY_TO}`,
  "Facilitator: " + FACILITATOR_URL, "",
  "## Endpoints",
  "- `POST /audit` (paid): body `{ \"code\": \"<file>\", \"filename\": \"bot.js\" }` -> `{ signalCount, findings[] }`. Unpaid -> HTTP 402.",
  `- \`GET /price?address=0x..\` (paid, ${PRICE_DATA}): live DEX spot price + liquidity + FDV + market cap + 24h volume for any token by address — EVM (Base/etc.) or Solana mint; highest-liquidity pair.`,
  `- \`GET /search_tokens?q=name&limit=12\` (paid, ${PRICE_DATA}): search tokens by name/symbol -> highest-liquidity matched pairs (price/liquidity/FDV/volume across chains).`,
  `- \`GET /markets?vs=usd&limit=25\` (paid, ${PRICE_DATA}): top coins by market cap with price, market cap, 24h volume and 1h/24h/7d change.`,
  `- \`GET /tvl?limit=25\` (paid, ${PRICE_DATA}): DeFi value locked ranked per chain, in USD.`,
  `- \`GET /stablecoins?limit=20\` (paid, ${PRICE_DATA}): USD-pegged supply by asset with peg mechanism and chain count.`,
  `- \`GET /trending?limit=10&chain=base\` (paid, ${PRICE_DATA}): currently promoted DEX tokens with live price, liquidity and 24h volume.`,
  `- \`GET /gas?chains=base,arbitrum\` (paid, ${PRICE_DATA}): live gas price and base fee in gwei from public RPC.`,
  "",
  `### Chain-state reads — ${CHAIN_ROUTES.length} routes, ${PRICE_DATA} each, on ${CHAIN_KEYS.join(", ")}`,
  "Each is one atomic read from a public JSON-RPC node: the argument is regex-validated before the payment gate, so a malformed call costs 400 and no settlement.",
  ...DATA_ROUTES.filter((r) => r.chainRoute).map((r) => `- \`GET ${r.path}?${argHint(r)}\` (paid, ${PRICE_DATA}): ${r.desc}`),
  "",
  `### Public-venue reads — ${MARKET_ROUTES.length} routes, ${PRICE_DATA} each`,
  "One named venue per route; the host is a compile-time constant and only the identifier is variable. A venue that answers 200 with an error body returns `found:false` plus its own reason, never a fabricated number, and a venue hiccup after a good call is served from cache marked `stale:true` rather than billed as an error.",
  ...DATA_ROUTES.filter((r) => r.marketRoute).map((r) => `- \`GET ${r.path}?${argHint(r)}\` (paid, ${PRICE_DATA}): ${r.desc}`),
  `- \`POST /mcp\` (paid): ${PAID_MCP_TOOL_COUNT} tools. \`audit_bot_code\` costs ${PRICE}; every other paid tool is the mirror of one priced GET route above and costs the same ${PRICE_DATA} — \`chain_*\` and \`market_*\` names are the route path with slashes turned into underscores. \`demo_audit\` and the handshake are free.`,
  "- `GET /`, `/health`, `/.well-known/x402-info`, `/discovery/resources`, `/robots.txt` (free metadata)", "",
  "## Buyer quickstart (no signup, no API key — you keep your own funded wallet)",
  "Send the request unpaid first. We answer HTTP 402 with base64 JSON terms on the `payment-required` response header. Build a payment for ONE of the two `accepts[]` entries, then resend with it in the `PAYMENT-SIGNATURE` request header.", "",
  "Legacy v1 buyers are served too, with no extra work: the same 402 carries a v1-shaped JSON body (`x402Version:1`, short network name `base`, `maxAmountRequired`, `asset`, `resource`) that `x402-fetch` / `x402-axios` 1.x parse directly, you reply in `X-PAYMENT`, and the receipt comes back in `X-PAYMENT-RESPONSE`. Verified against the shipped Coinbase client, not just our own envelope.", "",
  "**Pay on Base (`" + NETWORK + "`, USDC 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913).** It is `accepts[0]` because it is the rail that works: measured against our own published acceptance, the facilitator we run (`facilitator.payai.network`) verifies a correctly-signed EIP-712 `TransferWithAuthorization` and only then reports the signer's balance — 3/3 fresh zero-balance keys reached `invalid_exact_evm_insufficient_balance`, which means the payment itself was accepted. No signup, no API key, receiving costs the seller nothing, and your funds only move on a successful settle.", "",
  "**Solana (`" + SOLANA_NETWORK + "`, mint `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`) is `accepts[1]`, and it costs this wallet $0 to receive on — the earlier \"unfunded ATA\" warning here was wrong and is retracted.** Measured on two live Solana x402 settlements: the PAYER's own transaction carried `spl-associated-token-account create` plus `transferChecked`, so the buyer funded our token account (rent-exempt minimum for 165 bytes is 1488440 lamports, not the 2039280 previously quoted) and we signed nothing. One caveat that IS real: the reference `@x402/svm` client sends `transferChecked` only and never creates a destination account, so until our ATA exists, pay us from a client that appends `createAssociatedTokenAccountIdempotent` (or just use Base, `accepts[0]`).", "",
  "**Both wire versions are accepted, on Base.** Preferred is v2: put the payment in the `PAYMENT-SIGNATURE` header. Legacy v1 (`x402-fetch`, and what the Glimind router tells agents to do) also works: send the base64 v1 envelope in `X-PAYMENT` and this origin maps it onto the acceptance WE publish for the route being called, then runs the identical SDK verification and settlement — the EIP-712 `TransferWithAuthorization` a v1 client signs is byte-for-byte the one a v2 client signs, so nothing is trusted from the caller. A v1 payment for another wallet, another amount or another route is left alone and gets the normal 402.", "",
  "```js",
  "// npm i @x402/core@2 @x402/evm@2 viem   (Base USDC is accepts[0]; the path that can settle)",
  "import { x402Client, x402HTTPClient } from \"@x402/core/client\";",
  "import { ExactEvmScheme } from \"@x402/evm/exact/client\";",
  "import { privateKeyToAccount } from \"viem/accounts\";   // any Base account holding USDC",
  "",
  "let accepts = [];",
  "const client = new x402Client(() => accepts[0]);   // accepts[0] = eip155:8453, accepts[1] = solana",
  "client.register(\"" + NETWORK + "\", new ExactEvmScheme(privateKeyToAccount(process.env.BUYER_PRIVATE_KEY)));",
  "const http = new x402HTTPClient(client);",
  "",
  "const url = \"" + PUBLIC_URL + "/audit\";",
  "const init = { method: \"POST\", headers: { \"content-type\": \"application/json\" },",
  "  body: JSON.stringify({ code: SOURCE, filename: \"bot.js\" }) };",
  "",
  "const unpaid = await fetch(url, init);                                  // -> 402",
  "const terms = JSON.parse(Buffer.from(unpaid.headers.get(\"payment-required\"), \"base64\").toString());",
  "accepts = terms.accepts;",
  "const payload = await http.createPaymentPayload(terms);                 // builds the EIP-712 transfer authorization",
  "const res = await fetch(url, { ...init, headers: { ...init.headers,      // -> 200, only after settlement",
  "  ...http.encodePaymentSignatureHeader(payload) } });",
  "const { signalCount, findings } = await res.json();",
  "```",
  "Receiving costs the seller nothing on either rail: on Solana the facilitator is the feePayer, and on Base the buyer submits the EIP-3009 authorization, so USDC lands in our wallet and you pay only your own rail's fee. Docs: https://docs.x402.org/getting-started/quickstart-for-buyers", "",
  "The exact payload we accept on Base is an EIP-712 `TransferWithAuthorization` over `{name: \"USD Coin\", version: \"2\", chainId: 8453, verifyingContract: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913}` — that struct hash matches USDC's live on-chain `DOMAIN_SEPARATOR`, so any spec-compliant x402 client signs the right thing.", "",
  `MCP: point any MCP client at ${PUBLIC_URL}/mcp (Streamable HTTP, POST only). initialize, tools/list and demo_audit are free; the other ${PAID_MCP_TOOL_COUNT} tools are metered per tools/call and mirror the priced HTTP routes one-for-one — including price, so audit_bot_code challenges at ${PRICE} and every data tool at ${PRICE_DATA}. tools/list and this file cannot disagree.`, "",
  "Source: " + DOCS_URL,
].join("\n")));

// ---- legacy x402 v1 CHALLENGE encoder: the other half of the bridge ----
// The bridge below only fixes the REQUEST direction. A genuine v1 buyer (x402-fetch / x402-axios 1.x,
// which is exactly what Glimind's "resend the call with an X-PAYMENT header" instruction drives) reads
// the 402 out of the response BODY and runs every entry through PaymentRequirementsSchema
// (x402@1.2.0 dist/esm/chunk-V3RMM5AE.mjs:437). That schema needs a SHORT network name (it is a z.enum:
// "base", "solana", … — CAIP-2 fails), and requires maxAmountRequired, resource (a URL), description,
// mimeType and asset. Our SDK publishes v2 terms in the PAYMENT-REQUIRED header (network eip155:8453,
// `amount`, no asset), so the real library threw at schema-parse before it could sign anything
// (measured end-to-end in legacy-client-dryrun.mjs).
// The PAYMENT-REQUIRED header is left byte-for-byte alone, so the gate, the bridge's own acceptance
// lookup and every v2 SDK client see exactly what they saw before; only the human-readable body gains
// a v1 view of the SAME server-owned terms. Same money, two envelopes.
const V1_NETWORK = { [NETWORK]: "base", [SOLANA_NETWORK]: "solana" };
const ASSET_BY_NETWORK = {
  [NETWORK]: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  [SOLANA_NETWORK]: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
};
const ROUTE_BLURB = new Map(PAYABLE_ROUTES.map((r) => [`${r.method} ${r.path}`, r.description || r.note || SERVICE_NAME]));
function toV1Accept(a, req) {
  const network = V1_NETWORK[a.network];
  const amount = String(a.amount ?? "");
  if (!network || !/^\d+$/.test(amount)) return null;
  return {
    scheme: "exact",
    network,
    maxAmountRequired: amount,
    resource: `${PUBLIC_URL}${req.path}`,
    description: String(ROUTE_BLURB.get(`${req.method.toUpperCase()} ${req.path}`) ?? SERVICE_NAME).slice(0, 500),
    mimeType: "application/json",
    payTo: a.payTo,
    maxTimeoutSeconds: Number(a.maxTimeoutSeconds ?? 300),
    asset: ASSET_BY_NETWORK[a.network],
    ...(a.extra ? { extra: a.extra } : {}),
  };
}
app.use((req, res, next) => {
  const json = res.json.bind(res);
  res.json = (body) => {
    try {
      if (res.statusCode === 402) {
        // Some SDK paths only set the base64 header; decode it rather than invent terms.
        const raw = res.getHeader("payment-required") ?? res.getHeader("x-payment-required");
        let fromHeader = null;
        if (typeof raw === "string" && raw) {
          try { fromHeader = JSON.parse(Buffer.from(raw, "base64").toString("utf8")); } catch { /* fall through to the SDK body */ }
        }
        const v2 = Array.isArray(body?.accepts) ? body : fromHeader;
        const accepts = (v2?.accepts ?? []).map((a) => toV1Accept(a, req)).filter(Boolean);
        if (accepts.length) {
          // Bazaar indexes THIS response body and skips a resource whose extensions block is missing,
          // while the SDK's own extensions live on the v2 envelope. Carry them over verbatim (they are
          // server-owned terms, never client input): x402-fetch reads only `accepts[]` and the v1 zod
          // schemas are non-strict, so an extra top-level key is invisible to a legacy buyer.
          const extensions = v2?.extensions ?? fromHeader?.extensions;
          return json({
            x402Version: 1,
            error: v2.error ?? "Payment required",
            accepts,
            ...(extensions ? { extensions } : {}),
          });
        }
      }
    } catch {
      // Never let the legacy encoder swallow the challenge: fall through with the SDK's own body.
    }
    return json(body);
  };
  const setHeader = res.setHeader.bind(res);
  res.setHeader = (name, value) => {
    // v1 clients surface the settlement receipt under X-PAYMENT-RESPONSE; v2 dropped the prefix.
    if (String(name).toLowerCase() === "payment-response") {
      setHeader("X-PAYMENT-RESPONSE", value);
      setHeader("Access-Control-Expose-Headers", "X-PAYMENT-RESPONSE, PAYMENT-RESPONSE");
    }
    return setHeader(name, value);
  };
  next();
});
// ---- legacy x402 v1 wire bridge ----
// Glimind is the router buyer agents consult BEFORE calling an external tool, and we are listed there
// live and marked x402/automatable (toolId mcp-registry/io.github.kaminariouji/x402-audit-agent/*) — but
// the howToPay it hands those agents says "resend the call with an X-PAYMENT header", i.e. the retired
// v1 wire name. The installed SDK's extractor reads only PAYMENT-SIGNATURE, so every buyer that followed
// Glimind's own instructions took a 402 and gave up (measured, task #28).
// The EIP-712 TransferWithAuthorization a v1 client signs is byte-identical to the one a v2 client
// signs, so this is a shape mapping, not a second payment system: requirement matching, signature
// verification and settlement all still run through the SDK and the facilitator below. Nothing about
// the payment is trusted from the client — the `accepted` object is OUR OWN published acceptance, and
// translation happens only when network, payTo and amount match it exactly; anything else falls
// through untouched so the normal 402 challenge answers as it always has.
// The matcher (@x402/core paymentRequirementsMatchAccepted) deep-equals the whole requirement, so
// `accepted` must be the enriched acceptance the gate actually publishes (amount/asset/
// maxTimeoutSeconds), not the {scheme, price, network, payTo} we hand acceptsFor. Our own 402 challenge
// is the authoritative source, so each payable route resolves it once from the loopback listener and
// caches it; that probe carries no payment header, so it can never re-enter this bridge.
const v1AcceptedCache = new Map();
async function publishedBaseAcceptance(route) {
  const key = `${route.method} ${route.path}`;
  const cached = v1AcceptedCache.get(key);
  if (cached) return cached;
  // Probe the route the way it is actually served: a GET on a POST-only path answers 405 with no
  // PAYMENT-REQUIRED header, which would make the acceptance unresolvable for POST /audit and /mcp.
  const self = await fetch(`http://127.0.0.1:${PORT}${route.path}`, { method: route.method }).catch(() => null);
  const raw = self?.headers?.get("payment-required");
  if (!raw) return null;
  const terms = JSON.parse(Buffer.from(raw, "base64").toString("utf8"));
  const found = (terms.accepts ?? []).find((a) => a.network === NETWORK && a.scheme === "exact") ?? null;
  if (found) v1AcceptedCache.set(key, found);
  return found;
}
app.use((req, _res, next) => {
  void (async () => {
    try {
      if (req.headers["payment-signature"] || !req.headers["x-payment"]) return next();
      const v1 = JSON.parse(Buffer.from(String(req.headers["x-payment"]), "base64").toString("utf8"));
      if (v1?.x402Version !== 1 || v1?.scheme !== "exact") return next();
      if (v1.network !== "base" && v1.network !== NETWORK) return next();
      const route = PAYABLE_BY_PATH.get(req.path);
      if (!route || req.method.toUpperCase() !== route.method) return next();
      const terms = await publishedBaseAcceptance(route);
      const { authorization, signature } = v1.payload ?? {};
      if (!terms || !authorization || !signature) return next();
      if (String(authorization.to).toLowerCase() !== String(terms.payTo).toLowerCase()) return next();
      if (BigInt(String(authorization.value)) !== BigInt(String(terms.amount))) return next();
      req.headers["payment-signature"] = Buffer.from(JSON.stringify({
        x402Version: 2, payload: { authorization, signature }, accepted: terms,
      })).toString("base64");
      delete req.headers["x-payment"];
      console.log(`[x402-v1-bridge] translated ${req.method} ${req.path} v1 payment (${terms.amount} atomic; verified downstream)`);
    } catch {
      // A malformed X-PAYMENT header is not our problem: fall through and let the gate re-challenge.
    }
    next();
  })();
});
// A buyer that already put money on the table must never be charged for a request we can reject by
// shape alone. Unpaid probes still get the 402 (x402scan's discovery contract fails an origin that
// answers 400 to a probe, so the challenge keeps priority), but once a payment header is present the
// argument validators run BEFORE the gate settles: a malformed call costs 400 and no settlement.
app.use((req, res, next) => {
  const route = DATA_BY_PATH.get(req.path);
  if (!route || req.method.toUpperCase() !== "GET") return next();
  if (!req.headers["payment-signature"] && !req.headers["x-payment"]) return next();
  try {
    req.chainArgs = parseChainArgs(route, req.query);
  } catch (e) {
    if (!(e instanceof HttpError)) return next();
    return res.status(400).json({
      error: "invalid_request", detail: String(e.message).slice(0, 200), route: `${route.method || "GET"} ${route.path}`,
      settlement: "none — the request was rejected before payment was processed",
    });
  }
  next();
});
// ---- payment gate ----
// ---- refuse to sell a reading we cannot take ----
// Which venues a paid data route depends on, derived from the route's own code rather than a second
// hand-kept table: every market handler builds its URL from `MK.<key>`, so the references inside the
// function source ARE the venue list, and a route added tomorrow is covered without anyone editing a list
// that could silently disagree with the wire (the failure class we have hit repeatedly).
const ROUTE_VENUES = new Map(DATA_ROUTES.map((r) => {
  const hosts = new Set();
  for (const m of String(r.run).matchAll(/MK\.([A-Za-z]+)/g)) {
    const v = MK[m[1]];
    if (typeof v === "string") { try { hosts.add(new URL(v).host); } catch { /* not a URL, not a venue */ } }
  }
  // The mempool band can also be served by the mirror instance (see mj), so that host counts as one of
  // its sources: refusing money must require that EVERY way of reading it is dead.
  if (/mj\(["`]mp:/.test(String(r.run))) { try { hosts.add(new URL(MK.mempoolMirror).host); } catch { /* skip */ } }
  return [r.path, [...hosts]];
}));
// A `mk(mp, …)` label is only honest if that handler really binds `mp` to the host that answered. When the
// source string was rewritten for the mirror fallback, one route kept `mk(mp,` without the matching
// `host: mp` destructure — that is a ReferenceError on a PAID call, i.e. money taken and nothing served.
// So the pairing is asserted at boot over the same function source both the label and the binding live in.
const unboundMpLabel = DATA_ROUTES.filter((r) => {
  const src = String(r.run);
  return /mk\(mp,/.test(src) && !/host: mp\s*\}\s*=\s*await mj\(/.test(src);
}).map((r) => r.path);
if (unboundMpLabel.length) throw new Error(`route table invalid: ${unboundMpLabel.join(", ")} labels source=mp without binding host: mp`);
const allVenuesDown = (path) => {
  const hosts = ROUTE_VENUES.get(path);
  return Array.isArray(hosts) && hosts.length > 0 && hosts.every(isVenueDown);
};
// Proactive reachability, within the two rules above: the URL pinged per host is a REAL path lifted from
// the route source that reads it (the first `${MK.<venue>}/some/path` template, with the query string and
// any dynamic segment dropped), never a bare base — and only a THROWN fetch marks a host down. A path
// fetched without its parameters answers 400/404, which proves reachability and clears the marker.
// Nothing user-supplied is ever fetched: these URLs come from our own constant table.
const VENUE_REACH_PING_MS = 150_000;
const venueReachUrls = new Map();
for (const r of DATA_ROUTES) {
  for (const m of String(r.run).matchAll(/`\$\{MK\.([A-Za-z]+)\}([^`]*)`/g)) {
    const base = MK[m[1]];
    if (typeof base !== "string") continue;
    const tail = String(m[2]).split("${")[0].split("?")[0];
    let host; try { host = new URL(base).host; } catch { continue; }
    if (!venueReachUrls.has(host)) venueReachUrls.set(host, base + tail);
  }
}
async function sweepVenueReach() {
  const unreachable = [];
  await Promise.all([...venueReachUrls.entries()].map(async ([host, url]) => {
    try {
      await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(8_000) });
      markVenueUp(url);                       // any HTTP answer = the server is alive
    } catch { markVenueDown(url); unreachable.push(host); }   // only DNS/connect/timeout counts
  }));
  if (unreachable.length) console.log(`[venues] ${unreachable.length}/${venueReachUrls.size} unreachable: ${unreachable.join(", ")}`);
  return unreachable;
}
void sweepVenueReach();
setInterval(() => { sweepVenueReach().catch(() => {}); }, VENUE_REACH_PING_MS).unref?.();
const unavailableBody = (path) => ({
  error: "upstream_unavailable", route: `GET ${path}`, venues: ROUTE_VENUES.get(path), charged: false,
  note: "every public source this read depends on is currently failing from this host, so no payment challenge is issued for a reading we could not deliver — nothing was verified, settled or charged. Retry in a minute.",
  checkedAt: new Date(nowMs()).toISOString(),
});
// Mounted BEFORE the gate on purpose: the gate settles first, so a vendor outage caught after it would
// already have taken the buyer's $0.001 and answered 502 (measured 2026-09-28 with mempool.space dead).
// Only routes whose EVERY venue is marked dead refuse, and the refusal is a fixed error object — no data,
// no terms, so it cannot leak in either direction. `venueDown` entries expire after 90s, so this heals by
// itself as soon as a source answers again.
app.use((req, res, next) => {
  if (req.method !== "GET") return next();
  if (!allVenuesDown(req.path)) return next();
  console.log(`[unavailable] GET ${req.path} refused before the challenge: all ${ROUTE_VENUES.get(req.path).length} venue(s) dead (${ROUTE_VENUES.get(req.path).join(", ")})`);
  return res.status(503).json(unavailableBody(req.path));
});
// The same rule over MCP, enforced where the money is already committed: the /mcp gate stands down for a
// tool whose venues are all dead, and the handler refuses WITHOUT running, so an unpaid tool call cannot
// read the upstream and a settled one cannot take money for a 502.
const mcpUnavailable = (path) => ({
  content: [{ type: "text", text: JSON.stringify({ ...unavailableBody(path), charge: "not billed — this tool call is answered before the payment gate for the mirrored HTTP route as well" }, null, 2) }],
  isError: true,
});
app.use(paymentMiddlewareFromHTTPServer(httpServer, undefined, undefined, true));
app.post("/audit", (req, res) => {
  const { code, filename } = req.body || {};
  if (typeof code !== "string" || code.length === 0) return res.status(400).json({ error: 'body must be { "code": "<source string>" }' });
  const findings = scanText(code, filename || "submitted.js");
  res.json({ scannedBytes: code.length, signalCount: findings.length, findings,
    disclaimer: "Static-analysis signals; each must be confirmed by reading the cited line. Not a guarantee of correctness or profitability." });
});
// Paid market-data route: live DEX spot price for a Base token (only reached after settlement).
// A2A JSON-RPC. The card advertises this path as `url`, so an A2A buyer lands here after
// settling the x402 payment. Everything about which method name and part shape a buyer
// sends is decided by their library, not by us, so the wire handling lives in a2a.mjs and
// is checked against @a2a-js/sdk itself (a2a-contract-check.mjs) rather than assumed;
// anything it does not understand is answered as a JSON-RPC error, never as free work.
const runA2AAudit = (code, filename) => {
  const hits = scanText(code, filename);
  const findings = hits.map((h) => ({
    ruleId: h.rule,
    severity: SEVERITY_BY_RULE.get(h.rule) || "info",
    file: h.file,
    line: h.line,
    evidence: String(h.text || "").slice(0, 400),
    ...(h.note ? { note: h.note } : {}),
  }));
  return { findings, high: findings.filter((f) => f.severity === "high").length };
};
// The extension buyer's payment never touches a header, so the v1->v2 normalization the
// X-PAYMENT bridge does in middleware has to happen here instead — against OUR published
// acceptance for this exact route, never against anything the buyer claims to have paid.
async function payForA2ATask(v1Payload) {
  const terms = await publishedBaseAcceptance({ method: "POST", path: "/a2a" });
  if (!terms) return { ok: false, error: "facilitator_unavailable" };
  const authorization = v1Payload?.payload?.authorization ?? v1Payload?.authorization;
  const signature = v1Payload?.payload?.signature ?? v1Payload?.signature;
  if (!authorization || !signature) return { ok: false, error: "missing_payment_data" };
  if (String(authorization.to).toLowerCase() !== String(terms.payTo).toLowerCase()) return { ok: false, error: "invalid_exact_evm_recipient" };
  if (BigInt(String(authorization.value)) !== BigInt(String(terms.amount))) return { ok: false, error: "invalid_exact_evm_amount" };
  const payment = { x402Version: 2, payload: { authorization, signature }, accepted: terms };
  try {
    const verified = await resourceServer.verifyPayment(payment, terms);
    if (!verified?.isValid) return { ok: false, error: String(verified?.invalidReason ?? "payment_invalid") };
    const settled = await resourceServer.settlePayment(payment, terms);
    if (!settled?.success) return { ok: false, error: String(settled?.errorReason ?? "settlement_failed") };
    console.log(`[a2a-x402] SETTLED ${terms.amount} atomic from ${verified.payer ?? authorization.from} tx=${settled.transaction ?? "-"}`);
    return {
      ok: true,
      receipt: {
        success: true, network: settled.network ?? NETWORK, transaction: settled.transaction ?? null,
        payer: settled.payer ?? verified.payer ?? authorization.from, amount: terms.amount,
      },
    };
  } catch (e) {
    return { ok: false, error: String(e?.shortMessage ?? e?.message ?? e).slice(0, 160) };
  }
}
app.post("/a2a", async (req, res) => {
  if (!a2aX402ExtensionRequested(req.headers)) return res.json(handleA2ARequest(req.body, runA2AAudit));
  res.set("X-A2A-Extensions", X402_A2A_EXT_URI);
  const terms = await publishedBaseAcceptance({ method: "POST", path: "/a2a" });
  if (!terms) return res.status(503).json({ jsonrpc: "2.0", id: req.body?.id ?? null, error: { code: -32000, message: "payment terms are unavailable right now, so nothing can be sold" } });
  res.json(await handleA2AX402Request(req.body, {
    runAudit: runA2AAudit,
    pay: payForA2ATask,
    paymentRequired: () => ({
      x402Version: 1,
      accepts: [toV1Accept(terms, { method: "POST", path: "/a2a" })].filter(Boolean),
      error: `Payment required: ${PRICE} USDC on Base to run one honesty scan over the source in this task.`,
    }),
  }));
});
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
// Paid market-table route (only reached after settlement).
app.get("/markets", async (req, res) => {
  const vs = String(req.query.vs || "usd").toLowerCase();
  if (!CURRENCIES.has(vs)) return res.status(400).json({ error: "query ?vs= must be one of: " + [...CURRENCIES].join(", ") });
  const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
  try {
    const out = await topMarkets(vs, limit);
    res.json({ currency: vs, count: out.rows.length, rows: out.rows, source: out.source, note: out.note, caveat: "public aggregator snapshot, not an oracle", ts: new Date(nowMs()).toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_markets_failed", detail: String(e?.message || e) });
  }
});
app.get("/tvl", async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
  try {
    res.json({ ...(await chainTvl(limit)), caveat: "TVL is a protocol-reported metric, not a risk measure", ts: new Date(nowMs()).toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_tvl_failed", detail: String(e?.message || e) });
  }
});
app.get("/stablecoins", async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
  try {
    res.json({ ...(await stablecoinSnapshot(limit)), ts: new Date(nowMs()).toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_stablecoins_failed", detail: String(e?.message || e) });
  }
});
app.get("/trending", async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 50);
  const chain = String(req.query.chain || "").trim().slice(0, 32) || null;
  try {
    res.json({ ...(await trendingBoosted(chain, limit)), ts: new Date(nowMs()).toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_trending_failed", detail: String(e?.message || e) });
  }
});
app.get("/gas", async (req, res) => {
  const wanted = String(req.query.chains || Object.keys(RPC).join(",")).split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const bad = wanted.filter((c) => !RPC[c]);
  if (bad.length) return res.status(400).json({ error: "unknown chain(s): " + bad.join(","), allowed: Object.keys(RPC) });
  try {
    res.json({ ...(await gasPrices(wanted)), ts: new Date(nowMs()).toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_rpc_failed", detail: String(e?.message || e) });
  }
});
// The exact envelope a settled buyer receives on a chain route, exported so
// .tmp-check/chain-selftest.mjs asserts the shipped shape instead of a copy of it that can drift.
function chainResult(args, out) {
  const c = typeof args.chain === "string" ? args.chain : null;
  return {
    ...(c ? { chain: c, chainId: CHAINS[c].chainId, chainLabel: CHAINS[c].label } : {}),
    ...out,
    source: "public RPC",
    ts: new Date(nowMs()).toISOString(),
  };
}
// Paid data routes (only reached after settlement): one atomic read per published resource URL,
// because distinct endpoint count — not price — is what tracks unique payers. Both bands share the
// validator, the envelope discipline and this loop; they differ only in who answers (`public RPC`
// versus a named venue) and in the chain stamp the node routes carry.
for (const route of DATA_ROUTES) {
  app.get(route.path, async (req, res) => {
    try {
      const args = req.chainArgs ?? parseChainArgs(route, req.query);
      res.json(dataEnvelope(route, args, await route.run(args)));
    } catch (e) {
      const { status, body } = dataError(route, e);
      res.status(status).json(body);
    }
  });
}
app.post("/mcp", async (req, res) => {
  try {
    // The SDK's POST handler rejects unless Accept names BOTH application/json AND
    // text/event-stream, and it checks that even in enableJsonResponse mode, where no response is
    // ever SSE. So a client that only speaks JSON — curl, aiohttp's default `Accept: */*`, most
    // JSON-RPC wrappers — was turned away with 406 before it could call `tools/list`, let alone buy
    // anything. Our answer is JSON whichever way the header reads, so the requirement protects
    // nothing here; satisfy it for any client that can take JSON and keep 406 for the ones that
    // genuinely cannot (e.g. `Accept: text/plain`). Both Node header representations are written
    // because the SDK's Node->Web adapter builds its Headers from `rawHeaders`, not `req.headers`.
    const accept = typeof req.headers.accept === "string" ? req.headers.accept : "";
    if (accept === "" || accept.includes("*/*") || accept.includes("application/json")) {
      req.headers.accept = "application/json, text/event-stream";
      const raw = req.rawHeaders;
      let rewritten = false;
      for (let i = 0; i < raw.length; i += 2) {
        if (raw[i].toLowerCase() === "accept") { raw[i + 1] = req.headers.accept; rewritten = true; }
      }
      if (!rewritten) raw.push("accept", req.headers.accept);
    }
    const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await mcp.connect(t);
    res.on("close", () => t.close().catch(() => {}));
    await t.handleRequest(req, res, req.body);
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: String(e?.message || e) }, id: null });
  }
});

app.listen(PORT, () => {
  // The banner used to print PRICE (the audit-only price) as if it were the whole surface, which it is
  // not — the data routes are PRICE_DATA. An operator reading "costs $0.01/call" overstates every data
  // route by 10x, and this line is what the deploy log and the container health check quote. So both
  // prices and every count are interpolated from the tables: a route added later cannot make it lie.
  console.log(`=== x402 audit agent :${PORT} | USDC on ${NETWORK} -> ${PAY_TO} | ${DATA_ROUTES.length} data routes at ${PRICE_DATA}/call, audit at ${PRICE}/call ===`);
  // Every published `ts` goes through nowMs(), and that correction only exists after upstream `Date:`
  // headers have been sampled — so on a quiet server the host's skew would still be shipped to the
  // first buyer. Prime the sampler from our own pinned node (keyless, one call per tick, stops at 3).
  let primeTicks = 0;
  const primer = setInterval(async () => {
    primeTicks++;
    try { await rpcCall("base", "eth_blockNumber", []); } catch { /* a throttled node is not a timestamp */ }
    if (clockOffsets.length >= 3 || primeTicks >= 8) clearInterval(primer);
  }, 15_000);
  primer.unref?.();
});

// Exported for the data-route selftest (services/x402-mcp/data-selftest.mjs) and the chain-route
// selftest (.tmp-check/chain-selftest.mjs), which run the handlers directly — i.e. the same code the
// paid route calls after settlement — so a wrong ABI selector or decoder fails there, not in a buyer.
export { topMarkets, chainTvl, stablecoinSnapshot, trendingBoosted, gasPrices, isTokenAddress };
export { CHAIN_ROUTES, MARKET_ROUTES, DATA_ROUTES, DATA_BY_PATH, PAID_DATA_PATHS, PAYABLE_ROUTES, CHAINS, parseChainArgs, chainResult, dataEnvelope, dataError, mcpToolName, HttpError, outputSchemaFor, outputJsonSchemaFor };
// Exported only so the selftest can re-derive every selector and topic from keccak. A hand-typed
// 4-byte prefix is otherwise invisible until a paid route answers `readable:false` forever.
// SEL2/SLOT1967/IFACE/KNOWN_SELECTOR join that list because the third band reads contract state
// through them: the same class of invisible typo, on 27 paid routes.
export { SEL, TOPIC, SEL2, SLOT1967, IFACE, KNOWN_SELECTOR, WORD_RE, ADDR_RE };
// The selftest points CHAINS.base.rpcs at a host that does not implement eth_getBlockReceipts to prove
// the per-transaction path actually answers, instead of trusting that a branch nobody exercised works.
export { blockReceipts, RECEIPT_FALLBACK_CAP };
// The venue availability rule is the one piece of money-path logic whose effect (a route refusing the
// challenge unpaid instead of charging for a reading that will fail) is invisible from outside: the HTTP
// surface only shows it once a buyer is turned away, and testing that would mean spending money on our
// own tool. So the marker maps are exported for .tmp-check/venue-blacklist-instrument.mjs, which drives a
// stubbed fetch through the shipped `mj` and asserts exactly when a host is marked unreadable, when a
// single tolerated failure is deliberately NOT enough to do that, and when the marker clears. `memo` joins
// the list for the same reason and for a sharper one: the Bitcoin tip route takes no arguments, so it has
// exactly one cache key per reading — a second phase that ran after a first one succeeded would be served
// from that cache and would "pass" without reaching any source at all. The instrument clears it between
// phases. Nothing on the wire reads these; they are a test seam.
export { isVenueDown, venueDown, venueTolerated, memo, lastGood };
