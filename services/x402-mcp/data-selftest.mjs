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

// Indexers walk the whole verb matrix against a payable path; a 404/400 looks like a dead route
// and the service gets skipped, so every mismatch must declare the working method + price.
for (const [path, method] of [["/price", "GET"], ["/markets", "GET"], ["/audit", "POST"], ["/mcp", "POST"]]) {
  for (const verb of [method === "GET" ? "POST" : "GET", "PATCH", "PUT", "DELETE", "HEAD"]) {
    const r = await fetch(base + path, { method: verb, headers: { "content-type": "application/json" }, body: ["POST", "PATCH", "PUT", "DELETE"].includes(verb) ? "{}" : undefined });
    check(`${verb} ${path} -> 405 (never 404/400)`, r.status === 405, String(r.status));
  }
  const gate = await fetch(base + path, { method, headers: { "content-type": "application/json" }, body: method === "POST" ? "{}" : undefined });
  check(`${method} ${path} still gated 402`, gate.status === 402, String(gate.status));
  check(`OPTIONS ${path} free for preflight`, (await fetch(base + path, { method: "OPTIONS" })).status === 200, "not 200");
}
const mm = await (await fetch(base + "/price", { method: "PUT" })).json();
check("405 body names working method + price", mm.paid_endpoint === "GET /price" && mm.paywall?.price === "$0.001", JSON.stringify(mm).slice(0, 160));

// The SDK reads ONLY PAYMENT-SIGNATURE (chunk-UF6R7D6H extractPayment); our own openapi once told
// buyers to send the retired v1 X-PAYMENT header, which would 402 them forever. Never regress.
const oa = await (await fetch(base + "/openapi.json")).json();
const scheme = oa.components?.securitySchemes?.x402?.name;
check("openapi securityScheme is PAYMENT-SIGNATURE", scheme === "PAYMENT-SIGNATURE", String(scheme));
const guidance = String(oa.info?.["x-guidance"] ?? "");
check("openapi guidance has no stale X-PAYMENT advice", !/resend with the X-PAYMENT header/.test(guidance), "still tells buyers to use X-PAYMENT");
check("openapi guidance quotes the live prices", guidance.includes("$0.01") && guidance.includes("$0.001"), guidance.slice(0, 200));

// x402scan's discovery contract (https://www.x402scan.com/discovery/spec.md) rejects an origin for
// specific, silent reasons: protocols must be OBJECTS, a paid op with no response schema is "Input/Output
// Schema Missing", amounts are decimal USD, and a free path that isn't marked security:[] gets probed and
// logged as "No 402 challenge". Registration is the last step before a buyer can find us, so assert it.
const paidOps = Object.entries(oa.paths || {}).flatMap(([p, item]) =>
  Object.entries(item).filter(([, op]) => op?.["x-payment-info"]).map(([m, op]) => [`${m.toUpperCase()} ${p}`, op]));
// 8 HTTP-paid ops. /mcp is declared free on purpose: its handshake answers 200 to an unpaid probe, so a
// scanner that expects 402 there would fault the whole origin even though tools/call is metered.
check("every paid route is declared in openapi", paidOps.length === 8, `${paidOps.length}: ${paidOps.map(([k]) => k).join(" ")}`);
check("protocols are x402 objects, not bare strings", paidOps.every(([, o]) => JSON.stringify(o["x-payment-info"].protocols) === '[{"x402":{}}]'),
  JSON.stringify(paidOps[0]?.[1]?.["x-payment-info"]?.protocols));
check("prices are decimal USD at 6dp", paidOps.every(([, o]) => /^\d+\.\d{6}$/.test(String(o["x-payment-info"].price.amount))),
  paidOps.map(([, o]) => o["x-payment-info"].price.amount).join(","));
const auditDeclared = paidOps.find(([k]) => k === "POST /audit")?.[1]?.["x-payment-info"]?.price?.amount;
const auditAtomic = (await challengeOf("/audit", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).body?.accepts?.[0]?.amount;
check("openapi decimal USD agrees with runtime atomic units", String(Math.round(Number(auditDeclared) * 1e6)) === String(auditAtomic), `${auditDeclared} vs ${auditAtomic}`);
check("every paid op has an output schema", paidOps.every(([, o]) => !!o.responses?.["200"]?.content?.["application/json"]?.schema),
  paidOps.filter(([, o]) => !o.responses?.["200"]?.content?.["application/json"]?.schema).map(([k]) => k).join(" "));
check("every paid op declares responses.402", paidOps.every(([, o]) => !!o.responses?.["402"]), "missing 402 response");
check("every paid op has input (body or params)", paidOps.every(([, o]) => !!o.requestBody || (o.parameters || []).length > 0),
  paidOps.filter(([, o]) => !o.requestBody && !(o.parameters || []).length).map(([k]) => k).join(" "));
const freeOps = Object.entries(oa.paths || {}).flatMap(([p, item]) =>
  Object.entries(item).filter(([, op]) => Array.isArray(op?.security) && op.security.length === 0).map(([m]) => `${m.toUpperCase()} ${p}`));
check("free endpoints are declared security:[] (scanner skips them)", freeOps.length >= 9, `${freeOps.length}: ${freeOps.join(" ")}`);
check("required top-level discovery fields present", oa.openapi === "3.1.0" && !!oa.info?.title && !!oa.info?.version && !!guidance && Object.keys(oa.paths || {}).length > 10,
  `${oa.openapi} paths=${Object.keys(oa.paths || {}).length}`);
// "Expected 402, got 400" is a listed registration failure: a malformed body must still reach the gate.
const badJson = await fetch(base + "/audit", { method: "POST", headers: { "content-type": "application/json" }, body: "not json" });
check("malformed JSON on a paid route -> 402, never 400", badJson.status === 402, String(badJson.status));
const badJsonGet = await fetch(base + "/price", { method: "POST", headers: { "content-type": "application/json" }, body: "{{{" });
check("malformed body on wrong verb still 405", badJsonGet.status === 405, String(badJsonGet.status));

// MCP discovery: autonomous clients gate paid calls unless tools are annotated read-only, and any
// stale price in a tool description contradicts the 402 the buyer actually receives.
const mcpPost = async (obj, sid) => {
  const r = await fetch(base + "/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(sid ? { "mcp-session-id": sid } : {}) },
    body: JSON.stringify(obj),
  });
  return { sid: r.headers.get("mcp-session-id"), text: await r.text(), status: r.status };
};
const ini = await mcpPost({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "selftest", version: "1" } } });
check("MCP initialize -> 200", ini.status === 200, String(ini.status));
await mcpPost({ jsonrpc: "2.0", method: "notifications/initialized" }, ini.sid);
const tl = await mcpPost({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, ini.sid);
const tools = (JSON.parse((tl.text.match(/^data: (.*)$/m) || [, tl.text])[1]).result?.tools) || [];
check("tools/list returns 9 tools", tools.length === 9, String(tools.length));
check("every tool annotated readOnly + non-destructive", tools.length === 9 && tools.every((t) => t.annotations?.readOnlyHint === true && t.annotations?.destructiveHint === false), JSON.stringify(tools.map((t) => t.annotations?.readOnlyHint)));
check("no tool description contradicts the live price", !tools.some((t) => /0\.05 USDC|\(0\.01 USDC via x402\)/.test(t.description || "")), JSON.stringify(tools.filter((t) => /0\.05|0\.01 USDC via/.test(t.description || "")).map((t) => t.name)));
check("every tool carries a human title", tools.every((t) => typeof t.title === "string" && t.title.length > 4), JSON.stringify(tools.filter((t) => !t.title).map((t) => t.name)));

// RFC 9727 catalog: the standards-based route a crawler uses to find /openapi.json unprompted.
const cat = await fetch(base + "/.well-known/api-catalog");
const catJson = await cat.json().catch(() => ({}));
const catLinks = (catJson.linkset || []).flatMap((l) => [...(l.links || []), ...(l["service-desc"] || []).map((x) => ({ rel: "service-desc", ...x }))]);
check("GET /.well-known/api-catalog -> 200 linkset+json", cat.status === 200 && cat.headers.get("content-type")?.includes("application/linkset+json"),
  `${cat.status}/${cat.headers.get("content-type")}`);
check("catalog linkset is non-empty with anchors", (catJson.linkset || []).length >= 2 && catJson.linkset.every((l) => /^https:\/\//.test(String(l.anchor))), JSON.stringify((catJson.linkset || []).map((l) => l.anchor)));
check("catalog points at openapi.json + health + llms.txt", ["openapi.json", "health", "llms.txt"].every((k) => catLinks.some((l) => String(l.href).includes(k))), JSON.stringify(catLinks.map((l) => l.href)));
check("catalog hrefs are all absolute https on our origin", catLinks.every((l) => String(l.href).startsWith("https://")), JSON.stringify(catLinks.map((l) => l.href).slice(0, 3)));
check("every response advertises Link: rel=api-catalog", /rel="api-catalog"/.test(cat.headers.get("link") || ""), String(cat.headers.get("link")));
const gateLink = (await fetch(base + "/gas")).headers.get("link") || "";
check("the 402 challenge itself carries the catalog Link header", /rel="api-catalog"/.test(gateLink), gateLink);

if (fails.length) {
  console.log(`\nSELFTEST FAIL (${fails.length}): ${fails.join(", ")}`);
  process.exit(1);
}
console.log("\nSELFTEST OK — all paid data routes return live upstream data");
process.exit(0);
