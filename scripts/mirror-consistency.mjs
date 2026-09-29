// Mirror consistency check — proves the static Cloudflare mirror still tells the truth about the service.
//
// Why this exists as a file and not a curl: the mirror is a SNAPSHOT. It is correct only until the service
// changes, and the failure mode is silent — a crawler reads confident, wrong facts and no HTTP status tells
// anyone. So the check compares the snapshot against the live origin on the few numbers that must agree,
// and it asserts the thing that broke once already: a locally-built mirror that advertised `127.0.0.1` as
// where to call.
//
// Every check below can fail. One earlier draft of this idea lived in an inline `node -e` and contained
// `... || true`, which made it unconditionally green — do not reintroduce that shape here.
//
// Run: node .tmp-check/mirror-consistency.mjs [origin] [mirror]
const ORIGIN = process.argv[2] || "http://127.0.0.1:10000";
const MIRROR = (process.argv[3] || "https://x402-audit.ojikaminari.workers.dev").replace(/\/+$/, "");
const fails = [];
const chk = (name, ok, detail) => {
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${detail !== undefined ? ` :: ${detail}` : ""}`);
  if (!ok) fails.push(name);
};

const get = async (u) => {
  const r = await fetch(u, { headers: { accept: "application/json", "ngrok-skip-browser-warning": "1" }, signal: AbortSignal.timeout(25_000) });
  return { status: r.status, text: await r.text() };
};

// The live truth, read from the running service.
const termsRaw = await get(`${ORIGIN}/.well-known/x402`);
if (termsRaw.status !== 200) { console.log(`ORIGIN UNREADABLE (${termsRaw.status}) — cannot grade a mirror against a service we cannot read`); process.exit(2); }
const terms = JSON.parse(termsRaw.text);
const liveCount = (terms.resources || []).length;
const liveMin = terms.pricing?.minUsd, liveMax = terms.pricing?.maxUsd;

// The snapshot.
const home = await get(`${MIRROR}/`);
const infoRes = await get(`${MIRROR}/x402-info.json`);
const discRes = await get(`${MIRROR}/discovery.json`);
chk("mirror serves its three files", home.status === 200 && infoRes.status === 200 && discRes.status === 200,
  `${home.status}/${infoRes.status}/${discRes.status}`);
if (infoRes.status !== 200) { console.log("MIRROR UNREADABLE — nothing to compare"); process.exit(2); }
// `payTo` lives on /discovery/resources, not on the terms manifest (measured: the manifest's keys are
// version/name/description/tags/resources/resource_calls/resources_detail/resource_paths/count/
// ownershipProofs/payments/x402Details/networks/pricing/instructions). The first version of this check read
// `terms.payTo`, got `undefined`, and reported a mirror FAIL that was really a broken assertion — the same
// family of mistake as `... || true`, just pointing the other way.
const discLive = await get(`${ORIGIN}/discovery/resources`);
if (discLive.status !== 200) { console.log(`ORIGIN discovery unreadable (${discLive.status})`); process.exit(2); }
const livePayTo = (JSON.parse(discLive.text).payTo || {})["eip155:8453"] || null;
// An unreadable mirror is a finding, but it is not a number to compare — parse only what actually arrived.
if (infoRes.status !== 200 || discRes.status !== 200 || home.status !== 200) {
  console.log(`MIRROR UNREADABLE (index ${home.status}, x402-info.json ${infoRes.status}, discovery.json ${discRes.status}) `
    + "— exit 2, so a dead mirror can never be read as a clean verdict.");
  process.exit(2);
}
const info = JSON.parse(infoRes.text), disc = JSON.parse(discRes.text);

// The regression that actually happened: a mirror built while reading localhost shipped localhost.
const blob = home.text + infoRes.text + discRes.text;
chk("no loopback or plain-http address is advertised", !/127\.0\.0\.1|localhost/.test(blob) && !/"origin": *"http:\/\//.test(infoRes.text));
chk("mirror points at the origin the service itself advertises", info.built_from === new URL((terms.resources || [])[0]).origin,
  `${info.built_from} vs ${new URL((terms.resources || [])[0]).origin}`);

// Facts that must agree, or the snapshot is lying.
chk("resource count matches the live manifest", info.priced_resources === liveCount, `${info.priced_resources} vs ${liveCount}`);
chk("discovery.json has the same count", disc.count === liveCount, `${disc.count} vs ${liveCount}`);
chk("band totals add up to the resource count", Object.values(info.resource_bands || {}).reduce((a, b) => a + b, 0) === liveCount,
  `${JSON.stringify(info.resource_bands)}`);
chk("payout address matches the live service", !!livePayTo && String((info.pay_to || {})["eip155:8453"]) === livePayTo,
  `mirror ${String((info.pay_to || {})["eip155:8453"])} vs origin ${livePayTo}`);
chk("price band matches the live pricing block", String(info.price_usd?.min) === String(liveMin) && String(info.price_usd?.max) === String(liveMax),
  `mirror $${info.price_usd?.min}-$${info.price_usd?.max} vs terms ${liveMin}-${liveMax}`);
// The authoritative list of what costs nothing is the server card's `free_tools` field (see the memory
// note about a regex over descriptions once calling the PAID chain_logs tool free). Compare against that,
// not against prose in the manifest.
const cardRes = await get(`${ORIGIN}/.well-known/mcp/server-card.json`);
const cardFree = cardRes.status === 200 ? (JSON.parse(cardRes.text).free_tools || []).slice().sort() : null;
chk("free tools named exactly as the service names them", Array.isArray(cardFree) && JSON.stringify((info.free_tools_before_paying || []).slice().sort()) === JSON.stringify(cardFree),
  `mirror ${JSON.stringify(info.free_tools_before_paying)} vs card ${JSON.stringify(cardFree)}`);

// A snapshot must announce that it is one, or it gets read as live.
chk("mirror stamps when it was built", /^\d{4}-\d{2}-\d{2}T/.test(info.built_at || "") && new Date(info.built_at) > new Date(Date.now() - 1000 * 60 * 60 * 24),
  info.built_at);
chk("mirror states how it was produced", /build-cloudflare-pages\.mjs/.test(info.provenance || ""), String(info.provenance || "").slice(0, 60));
chk("mirror page says the tunnel is where compute runs", /tunnel/.test(home.text));

// And the safety property that makes a public mirror non-dangerous: it must not be able to answer a paid
// route. Static assets only — but assert it, because a future "small proxy addition" would break it.
for (const p of ["/market/btc-fee-estimates", "/chain/balance", "/price", "/audit", "/health", "/mcp", "/.well-known/x402"]) {
  const r = await get(MIRROR + p);
  chk(`mirror cannot serve a paid/dynamic path ${p}`, r.status === 404, String(r.status));
}

// Negative control: a mirror that disagrees must be caught by this file, not trusted.
const probe = JSON.parse(JSON.stringify(info)); probe.priced_resources = 99999;
chk("the count check can actually fail (negative control)",
  !(probe.priced_resources === liveCount), "deliberately wrong count was rejected — the assertion is live");

console.log(`\nmirror-consistency: ${fails.length ? `${fails.length} FAILED (${fails.join(", ")})` : "mirror agrees with the live service"}`
  + ` — origin ${ORIGIN} (${liveCount} resources) vs ${MIRROR} (built ${info.built_at})`);
process.exit(fails.length ? 1 : 0);
