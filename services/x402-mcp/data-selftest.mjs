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

if (fails.length) {
  console.log(`\nSELFTEST FAIL (${fails.length}): ${fails.join(", ")}`);
  process.exit(1);
}
console.log("\nSELFTEST OK — all paid data routes return live upstream data");
process.exit(0);
