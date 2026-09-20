// Selftest for the paid market-data routes: hits each real upstream and asserts the shape
// the buyer receives. Run from services/x402-mcp: `node data-selftest.mjs`.
import { topMarkets, chainTvl, stablecoinSnapshot, trendingBoosted, gasPrices } from "./server.mjs";

const fails = [];
function check(name, cond, detail) {
  if (cond) console.log(`  ok   ${name}`);
  else { fails.push(name); console.log(`  FAIL ${name} :: ${detail}`); }
}

const m = await topMarkets("usd", 5);
console.log(`markets source=${m.source} rows=${m.rows.length}`);
check("markets returns 5 rows", m.rows.length === 5, m.rows.length);
check("markets rank 1 first", m.rows[0]?.rank === 1, JSON.stringify(m.rows[0]));
check("markets btc price > 0", Number(m.rows[0]?.price) > 0, m.rows[0]?.price);
check("markets has 24h change", m.rows[0]?.change24h !== undefined, "missing change24h");
check("market caps descend", m.rows.every((r, i) => i === 0 || Number(r.marketCap) <= Number(m.rows[i - 1].marketCap)), "not sorted");

const t = await chainTvl(5);
console.log(`tvl total=${t.total} rows=${t.rows.length}`);
check("tvl returns 5 rows", t.rows.length === 5, t.rows.length);
check("tvl all positive", t.rows.every((r) => Number(r.tvl) > 0), JSON.stringify(t.rows[0]));
check("tvl descending", t.rows.every((r, i) => i === 0 || r.tvl <= t.rows[i - 1].tvl), "not sorted");
check("tvl more than 100 chains known", t.total > 100, t.total);

const s = await stablecoinSnapshot(5);
console.log(`stablecoins rows=${s.rows.length}`);
check("stablecoins returns rows", s.rows.length > 0, s.rows.length);
check("top stable > $1B supply", Number(s.rows[0]?.circulating) > 1e9, s.rows[0]?.circulating);
check("stablecoins carry peg mechanism", typeof s.rows[0]?.pegMechanism === "string", s.rows[0]?.pegMechanism);

const tr = await trendingBoosted(null, 5);
console.log(`trending count=${tr.count} enriched=${tr.rows.filter((r) => r.priceUsd).length}`);
check("trending returns rows", tr.rows.length > 0, tr.rows.length);
check("trending carries chainId+tokenAddress", tr.rows.every((r) => r.chainId && r.tokenAddress), JSON.stringify(tr.rows[0]));
check("trending enrichment produced >=1 live quote", tr.rows.some((r) => r.priceUsd && r.liquidityUsd !== undefined), "no quotes resolved");

const g = await gasPrices(["base", "arbitrum"]);
console.log(`gas rows=${g.rows.length} ${g.rows.map((r) => `${r.chain}=${r.gasPriceGwei}gwei`).join(" ")}`);
check("gas returns both chains", g.rows.length === 2, JSON.stringify(g.rows));
check("gas base > 0", Number(g.rows[0]?.gasPriceGwei) > 0, g.rows[0]?.gasPriceGwei);
check("gas base block number sane", Number(g.rows[0]?.blockNumber) > 1_000_000, g.rows[0]?.blockNumber);

// Repeated calls must be served from cache, not by re-hitting the upstream.
const before = g.rows[0].blockNumber;
const g2 = await gasPrices(["base"]);
check("gas is cached within TTL", g2.rows[0].blockNumber === before, `${before} -> ${g2.rows[0].blockNumber}`);

// The gate itself, over HTTP: an unpaid call must 402 and the challenge must offer BOTH
// settlement networks, and liveness probes must answer 405 rather than 404.
const base = `http://127.0.0.1:${process.env.PORT || 10000}`;
let up = false;
for (let i = 0; i < 40 && !up; i++) {
  up = await fetch(base + "/health").then((r) => r.ok).catch(() => false);
  if (!up) await new Promise((r) => setTimeout(r, 250));
}
check("server is listening", up, base);
const challengeOf = async (path, opts) => {
  const r = await fetch(base + path, opts);
  return { status: r.status, body: JSON.parse(Buffer.from(r.headers.get("payment-required") || "{}", "base64").toString()) };
};
const audit = await challengeOf("/audit", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
check("POST /audit unpaid -> 402", audit.status === 402, audit.status);
const aNets = (audit.body.accepts || []).map((a) => a.network);
const aPays = (audit.body.accepts || []).map((a) => a.payTo);
console.log(`audit challenge networks=${aNets.join(",")} amounts=${(audit.body.accepts || []).map((a) => a.amount).join(",")}`);
check("audit 402 offers two networks", aNets.length === 2, aNets.join(","));
check("audit 402 offers Base", aNets.includes("eip155:8453"), aNets.join(","));
check("audit 402 offers Solana mainnet", aNets.some((n) => n.startsWith("solana:5eykt")), aNets.join(","));
check("audit payTo distinct per network", new Set(aPays).size === 2, aPays.join(","));
check("audit payTo is one EVM + one base58", aPays.some((p) => /^0x[a-fA-F0-9]{40}$/.test(p)) && aPays.some((p) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(p)), aPays.join(","));
check("audit priced 0.01 USDC on both", (audit.body.accepts || []).every((a) => a.amount === "10000"), JSON.stringify(audit.body.accepts?.map((a) => a.amount)));
const data = await challengeOf("/markets");
const dNets = (data.body.accepts || []).map((a) => a.network);
check("GET /markets unpaid -> 402", data.status === 402, data.status);
check("data 402 is dual-network too", dNets.length === 2, dNets.join(","));
check("data priced 0.001 USDC on both", (data.body.accepts || []).every((a) => a.amount === "1000"), JSON.stringify(data.body.accepts?.map((a) => a.amount)));
const mcpGet = await fetch(base + "/mcp");
const rm = audit.body.resource || {};
console.log("resource metadata:", JSON.stringify({ serviceName: rm.serviceName, tags: rm.tags, iconUrl: rm.iconUrl }));
check("402 resource carries serviceName (<=32 ascii)", typeof rm.serviceName === "string" && rm.serviceName.length > 0 && rm.serviceName.length <= 32, String(rm.serviceName));
check("402 resource carries <=5 tags", Array.isArray(rm.tags) && rm.tags.length > 0 && rm.tags.length <= 5, JSON.stringify(rm.tags));
check("402 resource carries absolute https iconUrl", String(rm.iconUrl).startsWith("https://") && !/\s/.test(rm.iconUrl), String(rm.iconUrl));
check("GET /mcp -> 405 with Allow: POST", mcpGet.status === 405 && mcpGet.headers.get("allow") === "POST", `${mcpGet.status}/${mcpGet.headers.get("allow")}`);

// Crawler conventions must be FREE (no 402) and complete, or catalogers skip the service.
const disc = await fetch(base + "/discovery/resources");
const dj = await disc.json().catch(() => ({}));
check("GET /discovery/resources -> 200 free", disc.status === 200, disc.status);
check("fan-out lists every paid route", dj.items?.length === 9, `${dj.items?.length}`);
check("fan-out resources are absolute URLs", dj.resources?.every((r) => /^https:\/\//.test(r)), JSON.stringify(dj.resources?.slice(0, 2)));
check("fan-out items each offer both networks", dj.items?.every((i) => i.accepts?.length === 2), "some items are single-network");
check("fan-out audit is priced, market data separately", dj.items?.find((i) => i.resource?.endsWith("/audit"))?.accepts?.[0]?.price === "$0.01", dj.items?.[0]?.accepts?.[0]?.price);
const rob = await fetch(base + "/robots.txt");
const rt = await rob.text();
check("GET /robots.txt -> 200 free", rob.status === 200, rob.status);
check("robots allows all + points at llms.txt", /Allow: \//.test(rt) && /\/llms\.txt/.test(rt), rt.replace(/\n/g, " | "));

if (fails.length) {
  console.log(`\nSELFTEST FAIL (${fails.length}): ${fails.join(", ")}`);
  process.exit(1);
}
console.log("\nSELFTEST OK — all paid data routes return live upstream data");
process.exit(0);
