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
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { z } from "zod";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const { scanText } = require(path.join(__dirname, "audit-bot-honesty.cjs"));

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
const acceptsFor = (price) => ([
  { scheme: "exact", price, network: NETWORK, payTo: PAY_TO },
  { scheme: "exact", price, network: SOLANA_NETWORK, payTo: PAY_TO_SOLANA },
]);
// Bazaar catalog search only reads what the 402 challenge carries: serviceName (<=32 chars),
// the FIRST 5 tags, description and iconUrl (see @x402/extensions sanitize* rules). Facilitators
// soft-drop anything over those limits, so the arrays below are capped at 5, strongest first.
const SERVICE_NAME = "x402 Audit + Market Data";
const ICON_URL = process.env.X402_ICON_URL || "https://github.com/kaminariouji.png";
// Shared pricing block for every human/crawler-facing discovery route.
const PAYMENT_INFO = {
  protocol: "x402 (HTTP 402)", currency: "USDC",
  networks: [
    { network: NETWORK, label: "Base mainnet", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: PAY_TO, prices: { audit: PRICE, data: PRICE_DATA } },
    { network: SOLANA_NETWORK, label: "Solana mainnet", asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", payTo: PAY_TO_SOLANA, prices: { audit: PRICE, data: PRICE_DATA }, note: "facilitator is feePayer; receiving costs the seller $0" },
  ],
};

const FREE_METHODS = new Set(["initialize", "notifications/initialized", "ping", "tools/list", "resources/list", "prompts/list"]);
const FREE_TOOLS = new Set(["demo_audit"]);
// Every GET route below the gate costs PRICE_DATA per call.
const PAID_DATA_PATHS = new Set(["/price", "/search_tokens", "/markets", "/tvl", "/stablecoins", "/trending", "/gas"]);
// Table used to emit the OpenAPI paths for the data routes.
const DATA_ROUTE_SPEC = {
  "/markets": { summary: "Top coins by market cap: price, market cap, volume, 1h/24h/7d change (paid via x402)", params: [["vs", false, "quote currency: usd, eur, gbp, jpy, btc, eth", "string"], ["limit", false, "rows 1-100 (default 25)", "number"]] },
  "/tvl": { summary: "DeFi value-locked ranking per chain in USD (paid via x402)", params: [["limit", false, "rows 1-100 (default 25)", "number"]] },
  "/stablecoins": { summary: "USD-pegged stablecoin supply by asset, peg mechanism and chain count (paid via x402)", params: [["limit", false, "rows 1-100 (default 20)", "number"]] },
  "/trending": { summary: "Currently promoted DEX tokens enriched with live price, liquidity and 24h volume (paid via x402)", params: [["limit", false, "rows 1-50 (default 10)", "number"], ["chain", false, "optional chainId filter, e.g. base or solana", "string"]] },
  "/gas": { summary: "Live gas and base fee in gwei for Base and Arbitrum from public RPC (paid via x402)", params: [["chains", false, "comma list from: base, arbitrum", "string"]] },
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

// ---- market-data helpers for the paid routes ----
// Every upstream host below is a compile-time constant and the variable part is validated or
// percent-encoded, so a caller cannot steer a request off these hosts.
const CACHE_MS = 30_000;
const memo = new Map();
async function cachedJson(key, url, init) {
  const hit = memo.get(key);
  if (hit && hit.exp > Date.now()) return hit.val;
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`upstream ${new URL(url).host} returned HTTP ${r.status}`);
  const val = await r.json();
  if (val && typeof val === "object" && !Array.isArray(val) && val.error) {
    throw new Error(`upstream ${new URL(url).host} returned ${String(val.error).slice(0, 80)}`);
  }
  memo.set(key, { exp: Date.now() + CACHE_MS, val });
  return val;
}
const UP = {
  coingeckoMarkets: "https://api.coingecko.com/api/v3/coins/markets",
  paprikaTickers: "https://api.coinpaprika.com/v1/tickers",
  llamaChains: "https://api.llama.fi/v2/chains",
  llamaStables: "https://stablecoins.llama.fi/stablecoins",
  dexscreenerBoosts: "https://api.dexscreener.com/token-boosts/latest/v1",
};
// Caller picks a chain name out of this map — never a URL.
const RPC = { base: "https://mainnet.base.org", arbitrum: "https://arb1.arbitrum.io/rpc" };
const CURRENCIES = new Set(["usd", "eur", "gbp", "jpy", "btc", "eth"]);
const TX_COST_CURRENCY = process.env.X402_TX_COST_CURRENCY || "usd";

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
    return { source: "coingecko-fallback-coinpaprika", note: String(e?.message || e), rows: j
      .filter((c) => Number(c.rank) > 0).sort((a, b) => a.rank - b.rank).slice(0, limit).map((c) => ({
        rank: c.rank, id: c.id, symbol: c.symbol, name: c.name, price: c.quotes?.[vs]?.price ?? null,
        marketCap: c.quotes?.[vs]?.market_cap ?? null, volume: c.quotes?.[vs]?.volume_24h ?? null,
        circulating: c.circulating_supply, change1h: null, change24h: c.quotes?.[vs]?.percent_change_24h ?? null,
        change7d: c.quotes?.[vs]?.percent_change_7d ?? null,
      })) };
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

const mcp = new McpServer({ name: "crypto-bot-honesty-audit", version: "1.0.0" }, {
  instructions: "Pay-per-call x402 agent: scans a JS/TS crypto-bot source file for the bug patterns that make it report income it never earned, plus keyless market data (token price, search, market cap table, chain TVL, stablecoin supply, trending tokens, gas).",
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
mcp.registerTool("top_markets", {
  title: "Top coins by market cap (paid)",
  description: "Market-cap table with price, market cap, 24h volume and 1h/24h/7d change. Public aggregator snapshot, not an oracle. Metered per call via x402.",
  inputSchema: { vs: z.enum(["usd", "eur", "gbp", "jpy", "btc", "eth"]).optional().describe("quote currency"), limit: z.number().int().min(1).max(100).optional() },
}, async ({ vs = "usd", limit = 25 }) => {
  const out = await topMarkets(vs, limit);
  return { content: [{ type: "text", text: JSON.stringify({ currency: vs, count: out.rows.length, rows: out.rows, source: out.source, caveat: "public aggregator snapshot, not an oracle", ts: new Date().toISOString() }, null, 2) }] };
});
mcp.registerTool("chain_tvl", {
  title: "DeFi TVL ranked per chain (paid)",
  description: "Value locked in USD per chain, ranked. TVL is a protocol-reported metric, not a risk measure. Metered per call via x402.",
  inputSchema: { limit: z.number().int().min(1).max(100).optional() },
}, async ({ limit = 25 }) => ({ content: [{ type: "text", text: JSON.stringify(await chainTvl(limit), null, 2) }] }));
mcp.registerTool("stablecoin_supply", {
  title: "USD-pegged stablecoin supply by asset (paid)",
  description: "Circulating USD-pegged supply with peg mechanism and chain count. Metered per call via x402.",
  inputSchema: { limit: z.number().int().min(1).max(100).optional() },
}, async ({ limit = 20 }) => ({ content: [{ type: "text", text: JSON.stringify(await stablecoinSnapshot(limit), null, 2) }] }));
mcp.registerTool("trending_tokens", {
  title: "Promoted DEX tokens with live quotes (paid)",
  description: "Tokens currently bought into by projects for DEX exposure, enriched with price, liquidity and 24h volume. Boosts are paid promotions, not an endorsement. Metered per call via x402.",
  inputSchema: { limit: z.number().int().min(1).max(50).optional(), chain: z.string().max(32).optional().describe("chainId filter, e.g. base or solana") },
}, async ({ limit = 10, chain }) => ({ content: [{ type: "text", text: JSON.stringify(await trendingBoosted(typeof chain === "string" ? chain.trim().slice(0, 32) : null, limit), null, 2) }] }));
mcp.registerTool("gas_prices", {
  title: "Live gas and base fee in gwei (paid)",
  description: "Gas price, base fee and block height for Base and Arbitrum from public RPC — what a transaction costs before you send it. Metered per call via x402.",
  inputSchema: { chains: z.array(z.enum(["base", "arbitrum"])).max(2).optional() },
}, async ({ chains = ["base", "arbitrum"] }) => ({ content: [{ type: "text", text: JSON.stringify(await gasPrices(chains), null, 2) }] }));

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
const httpServer = new x402HTTPResourceServer(resourceServer, {
  "POST /mcp": {
    accepts: acceptsFor(PRICE),
    serviceName: SERVICE_NAME,
    iconUrl: ICON_URL,
    description: "Per-call x402 payment to run audit_bot_code on one source file.",
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
});
// Gate the JSON-RPC method level on /mcp; /audit is gated by matching its route config.
httpServer.requiresPayment = function (context) {
  const method = context.method || context.adapter?.getMethod?.();
  const path = context.path;
  if (method === "POST" && path === "/audit") return true;
  if (method === "GET" && PAID_DATA_PATHS.has(path)) return true;
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

// Access log: without it we cannot tell a crawler from a payer. 2xx on a paid route = money moved.
app.use((req, res, next) => {
  res.on("finish", () => {
    const q = req.originalUrl.length > 120 ? req.originalUrl.slice(0, 120) + "…" : req.originalUrl;
    console.log(`[${new Date().toISOString()}] ${res.statusCode} ${req.method} ${q} ua=${(req.get("user-agent") || "-").slice(0, 60)}`);
  });
  next();
});

// ---- free metadata (registered BEFORE the payment gate) ----
app.get("/health", (_req, res) => res.json({ ok: true, kind: "mcp+http", ...PAYMENT_INFO }));
app.get("/", (_req, res) => res.json({
  name: "crypto-bot-honesty-audit",
  endpoints: { paid: [`POST /audit (crypto-bot honesty scan, ${PRICE})`, "GET /price?address=0x.. (token spot price)", "GET /search_tokens?q=.. (token search)", "GET /markets?vs=usd&limit=25 (top coins by market cap)", "GET /tvl?limit=25 (chain TVL ranking)", "GET /stablecoins?limit=20 (pegged supply)", "GET /trending?limit=10 (promoted DEX tokens with quotes)", "GET /gas?chains=base,arbitrum (live gwei)", "POST /mcp (tools/call audit_bot_code)"], free: ["GET /", "/health", "/llms.txt", "/openapi.json", "/.well-known/x402-info", "MCP demo_audit"] },
  ...PAYMENT_INFO,
}));
app.get("/audit", (_req, res) => res.status(405).json({
  error: "method_not_allowed", paid_endpoint: "POST /audit", ...PAYMENT_INFO,
  probe: "this service is LIVE; send POST with an x402 payment to use it",
}));
// Monitors probe GET /mcp for liveness. The Streamable-HTTP spec says a server that does not
// offer SSE answering GET with 405 — returning 404 made indexers mark this live server dead.
app.get("/mcp", (_req, res) => res.status(405).set("Allow", "POST").json({
  error: "method_not_allowed", protocol: "MCP Streamable HTTP", transport: "POST only",
  endpoint: `${PUBLIC_URL}/mcp`, server: "io.github.kaminariouji/x402-audit-agent",
  paywall: { ...PAYMENT_INFO, tool_prices: { audit_bot_code: PRICE, market_data_tools: PRICE_DATA } },
  free_tools: ["demo_audit"], probe: "this MCP server is LIVE; POST an initialize to use it",
}));
// Agent Souk publisher verification (trust tier 2): proves this host belongs to our agent id.
const SOUK_AGENT_ID = process.env.AGENTSOUK_AGENT_ID || "";
app.get("/.well-known/agentsouk.txt", (_req, res) => res.type("text/plain").send(SOUK_AGENT_ID ? `agentsouk=${SOUK_AGENT_ID}\n` : "not configured\n"));
// x402scan / Bazaar fan-out compat: list payable resources at their absolute URLs.
app.get(["/.well-known/x402", "/.well-known/x402.json"], (_req, res) => {
  res.json({
    version: 1,
    resources: [`${PUBLIC_URL}/audit`, ...[...PAID_DATA_PATHS].map((p) => PUBLIC_URL + p)],
    ownershipProofs: [PAY_TO],
    instructions: `Pay-per-call x402 USDC on Base or Solana, no account and no API key. POST /audit for a crypto-bot honesty scan; GET /price?address=0x.., /search_tokens?q=.., /markets, /tvl, /stablecoins, /trending, /gas for market data at ${PRICE_DATA}; MCP tool audit_bot_code on POST /mcp.`,
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
  { path: "/mcp", method: "POST", price: PRICE, description: "MCP Streamable-HTTP server (POST only). Paid tools/call: audit_bot_code and the market-data tools." },
];
app.get("/discovery/resources", (_req, res) => res.json({
  version: 1,
  server: "io.github.kaminariouji/x402-audit-agent",
  name: "crypto-bot-honesty-audit",
  protocol: "x402 (HTTP 402)",
  currency: "USDC",
  networks: [NETWORK, SOLANA_NETWORK],
  payTo: { [NETWORK]: PAY_TO, [SOLANA_NETWORK]: PAY_TO_SOLANA },
  facilitator: FACILITATOR_URL,
  documentationUrl: "https://github.com/kaminariouji/x402-audit-agent",
  resources: PAYABLE_ROUTES.map((r) => PUBLIC_URL + r.path),
  items: PAYABLE_ROUTES.map((r) => ({
    resource: PUBLIC_URL + r.path, method: r.method, x402Version: 2,
    accepts: acceptsFor(r.price), serviceName: SERVICE_NAME, iconUrl: ICON_URL,
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
  return res.status(405).set("Allow", `${route.method}, OPTIONS`).json({
    error: "method_not_allowed",
    paid_endpoint: `${route.method} ${route.path}`,
    endpoint: PUBLIC_URL + route.path,
    paywall: { ...PAYMENT_INFO, price: route.price },
    probe: `this service is LIVE; send ${route.method} with an x402 payment (${route.price} USDC) to use it`,
  });
});
// Deliberately permissive: every route is public (payment is enforced per-request, not by
// crawling policy), and the LLMs field points agents at the machine-readable service terms.
app.get("/robots.txt", (_req, res) => res.type("text/plain").send([
  "User-agent: *", "Allow: /", "", `LLMs: ${PUBLIC_URL}/llms.txt`,
  `Sitemap hint: ${PUBLIC_URL}/.well-known/x402-info`,
  `x402 resource fan-out: ${PUBLIC_URL}/discovery/resources`, "",
].join("\n")));
app.get("/.well-known/x402-info", (_req, res) => res.json({
  name: "crypto-bot-honesty-audit",
  description: "Paid x402 agent (HTTP + MCP), no account and no API key: (1) scans a JS/TS crypto-bot source file for the bug patterns that make it report income it never earned; (2) per-call crypto market data — token spot price, token search, top coins by market cap, chain TVL, stablecoin supply, trending DEX tokens, live gas.",
  documentationUrl: "https://github.com/kaminariouji/x402-audit-agent",
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
    { path: "/mcp", method: "POST", price: PRICE, note: "per tools/call audit_bot_code" },
  ], freeEndpoints: ["/", "/health", "/llms.txt", "/robots.txt", "/discovery/resources", "/openapi.json", "/.well-known/x402-info", "MCP demo_audit"] },
  capabilities: ["analyze", "audit", "classify", "market-data", "price", "search", "markets", "market-cap", "tvl", "defi", "stablecoins", "trending", "gas", "fees", "transaction-cost"],
  payTo: { [NETWORK]: PAY_TO, [SOLANA_NETWORK]: PAY_TO_SOLANA },
}));
app.get("/openapi.json", (_req, res) => res.json({
  openapi: "3.0.0",
  info: {
    title: "crypto-bot-honesty-audit", version: "1.0.0",
    description: "Pay-per-call x402 agent: crypto-bot honesty scan plus keyless per-call crypto market data (price, search, market cap, TVL, stablecoins, trending, gas).",
    contact: { url: "https://github.com/kaminariouji/x402-audit-agent" },
    "x-guidance": `Paid routes, no signup and no API key. (1) POST /audit body { code, filename } -> ${PRICE} USDC. (2) GET /price?address=0x.. -> ${PRICE_DATA} USDC. (3) GET /search_tokens?q=name -> ${PRICE_DATA} USDC. (4) GET /markets?vs=usd&limit=25, /tvl?limit=25, /stablecoins?limit=20, /trending?limit=10&chain=base, /gas?chains=base,arbitrum -> ${PRICE_DATA} USDC each. Unpaid -> HTTP 402 with x402 terms on the PAYMENT-REQUIRED header; pay USDC on Base (${NETWORK}) or Solana (${SOLANA_NETWORK}) via an x402 client and resend with the payment in the PAYMENT-SIGNATURE header (v2 wire format — X-PAYMENT is the retired v1 name). MCP tool audit_bot_code on POST /mcp is metered the same way; demo_audit is free.`,
  },
  servers: [{ url: PUBLIC_URL }],
  security: [{ x402: [] }],
  components: { securitySchemes: { x402: { type: "apiKey", in: "header", name: "PAYMENT-SIGNATURE", description: `x402 v2 USDC payment on ${NETWORK} or ${SOLANA_NETWORK}; the 402 challenge on the PAYMENT-REQUIRED header lists both accepts. Settle one, then resend with the payment in PAYMENT-SIGNATURE. (X-PAYMENT is the retired v1 header name and is NOT read here.)` } } },
  paths: { "/audit": { post: {
    summary: "Audit a crypto-bot source file (paid via x402)",
    "x-payment-info": { protocols: ["x402"], price: { mode: "fixed", currency: "USD", amount: PRICE.slice(1) } },
    security: [{ x402: [] }],
    requestBody: { required: true, content: { "application/json": { schema: { type: "object",
      properties: { code: { type: "string", description: "one JS/TS file" }, filename: { type: "string" } }, required: ["code"] } } } },
    responses: { 200: { description: "findings[] after settlement" }, 402: { description: "Payment required (x402 challenge)" } },
  } }, "/price": { get: {
    summary: "Live token spot price + liquidity by contract address, EVM or Solana (paid via x402)",
    "x-payment-info": { protocols: ["x402"], price: { mode: "fixed", currency: "USD", amount: PRICE_DATA.slice(1) } },
    security: [{ x402: [] }],
    parameters: [{ name: "address", in: "query", required: true, description: "Token contract address: EVM (0x…, 42 hex) or Solana base58 mint (32-44 chars)", schema: { type: "string" } }],
    responses: { 200: { description: "priceUsd/liquidity/fdv after settlement" }, 402: { description: "Payment required (x402 challenge)" } },
  } }, "/search_tokens": { get: {
    summary: "Search crypto tokens by name/symbol; returns highest-liquidity matched pairs (paid via x402)",
    "x-payment-info": { protocols: ["x402"], price: { mode: "fixed", currency: "USD", amount: PRICE_DATA.slice(1) } },
    security: [{ x402: [] }],
    parameters: [
      { name: "q", in: "query", required: true, description: "token name or symbol to search (1-64 chars)", schema: { type: "string" } },
      { name: "limit", in: "query", required: false, description: "max results 1-25", schema: { type: "number" } },
    ],
    responses: { 200: { description: "results[] after settlement" }, 402: { description: "Payment required (x402 challenge)" } },
  } }, ...Object.fromEntries(Object.entries(DATA_ROUTE_SPEC).map(([p, s]) => [p, { get: {
    summary: s.summary,
    "x-payment-info": { protocols: ["x402"], price: { mode: "fixed", currency: "USD", amount: PRICE_DATA.slice(1) } },
    security: [{ x402: [] }],
    parameters: s.params.map(([name, required, description, type]) => ({ name, in: "query", required, description, schema: { type } })),
    responses: { 200: { description: "rows[] after settlement" }, 402: { description: "Payment required (x402 challenge)" } },
  } }])), },
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
  `- \`GET /markets?vs=usd&limit=25\` (paid, ${PRICE_DATA}): top coins by market cap with price, market cap, 24h volume and 1h/24h/7d change.`,
  `- \`GET /tvl?limit=25\` (paid, ${PRICE_DATA}): DeFi value locked ranked per chain, in USD.`,
  `- \`GET /stablecoins?limit=20\` (paid, ${PRICE_DATA}): USD-pegged supply by asset with peg mechanism and chain count.`,
  `- \`GET /trending?limit=10&chain=base\` (paid, ${PRICE_DATA}): currently promoted DEX tokens with live price, liquidity and 24h volume.`,
  `- \`GET /gas?chains=base,arbitrum\` (paid, ${PRICE_DATA}): live gas price and base fee in gwei from public RPC.`,
  "- `POST /mcp` (paid per tools/call `audit_bot_code`); MCP `demo_audit` + handshake are free.",
  "- `GET /`, `/health`, `/.well-known/x402-info`, `/discovery/resources`, `/robots.txt` (free metadata)", "",
  "## Buyer quickstart (no signup — your x402 client auto-pays the 402 and retries)",
  "Any funded wallet on Base or Solana can call this; you keep your own keys, we never hold funds. A standard x402 client catches our HTTP 402, reads the header, pays " + PRICE + " USDC on " + NETWORK + " or " + SOLANA_NETWORK + ", and retries transparently.", "",
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
  "Facilitator verify/settle is free for the seller (buyer pays gas; on Solana the facilitator is the feePayer). Docs: https://docs.x402.org/getting-started/quickstart-for-buyers", "",
  "Solana buyers: pick the second `accepts` entry in our 402 challenge (network " + SOLANA_NETWORK + ", USDC mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v) and pay it with `@x402/fetch` plus `registerExactSvmScheme` from `@x402/svm/exact/client`.", "",
  "MCP: point any MCP client at " + PUBLIC_URL + "/mcp (Streamable HTTP, POST only). initialize, tools/list and demo_audit are free; paid tools are audit_bot_code, get_token_price, search_tokens, top_markets, chain_tvl, stablecoin_supply, trending_tokens, gas_prices.", "",
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
// Paid market-table route (only reached after settlement).
app.get("/markets", async (req, res) => {
  const vs = String(req.query.vs || "usd").toLowerCase();
  if (!CURRENCIES.has(vs)) return res.status(400).json({ error: "query ?vs= must be one of: " + [...CURRENCIES].join(", ") });
  const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
  try {
    const out = await topMarkets(vs, limit);
    res.json({ currency: vs, count: out.rows.length, rows: out.rows, source: out.source, note: out.note, caveat: "public aggregator snapshot, not an oracle", ts: new Date().toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_markets_failed", detail: String(e?.message || e) });
  }
});
app.get("/tvl", async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
  try {
    res.json({ ...(await chainTvl(limit)), caveat: "TVL is a protocol-reported metric, not a risk measure", ts: new Date().toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_tvl_failed", detail: String(e?.message || e) });
  }
});
app.get("/stablecoins", async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
  try {
    res.json({ ...(await stablecoinSnapshot(limit)), ts: new Date().toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_stablecoins_failed", detail: String(e?.message || e) });
  }
});
app.get("/trending", async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 50);
  const chain = String(req.query.chain || "").trim().slice(0, 32) || null;
  try {
    res.json({ ...(await trendingBoosted(chain, limit)), ts: new Date().toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_trending_failed", detail: String(e?.message || e) });
  }
});
app.get("/gas", async (req, res) => {
  const wanted = String(req.query.chains || Object.keys(RPC).join(",")).split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const bad = wanted.filter((c) => !RPC[c]);
  if (bad.length) return res.status(400).json({ error: "unknown chain(s): " + bad.join(","), allowed: Object.keys(RPC) });
  try {
    res.json({ ...(await gasPrices(wanted)), ts: new Date().toISOString() });
  } catch (e) {
    res.status(502).json({ error: "upstream_rpc_failed", detail: String(e?.message || e) });
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

// Exported for the data-route selftest (services/x402-mcp/data-selftest.mjs).
export { topMarkets, chainTvl, stablecoinSnapshot, trendingBoosted, gasPrices, isTokenAddress };
