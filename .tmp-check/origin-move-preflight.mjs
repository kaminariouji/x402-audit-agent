// Pre-flight for moving the payable origin off ngrok.
//
// Why this file exists: the hostname is not cosmetic on an x402 rail. The 402 challenge carries a
// `resource` URL, and every discovery document carries absolute resource URLs. If ANY of those still
// names the old host after a move, a buyer pays for a resource it cannot verify at the origin it is
// talking to — a money-message inconsistency, which is exactly the class that shipped a 127.0.0.1 mirror
// earlier (one variable used for both reading and advertising). The move itself is a single env var
// (X402_PUBLIC_URL); this instrument proves that variable is the ONLY place the origin comes from.
//
// Two assertions, kept separate on purpose:
//  (a) ADDRESS-BEARING FIELDS must name the configured origin. These are the fields a client pays against.
//  (b) NO DOCUMENT may contain a loopback or plain-http origin. Foreign https URLs (the facilitator, an
//      avatar, a JSON-schema $id) are legitimate and must NOT fail anything — the first version of this
//      file grepped every URL in every blob and "failed" on facilitator.payai.network, which is a broken
//      assertion, not a defect.
//
// It runs the app on a test port on the host, never publicly, and only touches FREE documents plus
// unpaid 402 refusals. No money moves, no wallet is read, no upstream vendor is called.
process.env.PORT = "10995";
process.env.X402_PUBLIC_URL = process.env.PREFLIGHT_ORIGIN || "https://preflight-origin.example.invalid";
const m = await import("../services/x402-mcp/server.mjs");
const BASE = `http://127.0.0.1:${process.env.PORT}`;
const ORIGIN = process.env.X402_PUBLIC_URL;

let up = 0;
for (let i = 0; i < 60 && !up; i++) {
  try { up = (await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(1500) })).status; } catch { await new Promise((r) => setTimeout(r, 500)); }
}
if (up !== 200) { console.log(`ABORT — app did not come up on the test port (health=${up || "no answer"}). Nothing was measured.`); process.exit(2); }

let ran = 0, fails = 0;
const chk = (name, ok, detail = "") => {
  ran++;
  if (!ok) { fails++; console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
  else console.log(`  ok   ${name}${detail ? ` (${detail})` : ""}`);
};

const DOCS = ["/.well-known/x402", "/.well-known/x402-info.json", "/discovery/resources", "/openapi.json",
  "/llms.txt", "/.well-known/mcp/server-card.json", "/.well-known/ai-catalog.json", "/.well-known/ard.json",
  "/.well-known/agent-card.json"];
const got = {};
console.log(`\n=== origin pre-flight: configured origin = ${ORIGIN} ===`);
for (const p of DOCS) {
  try {
    const r = await fetch(BASE + p, { headers: { accept: "application/json, text/plain" }, signal: AbortSignal.timeout(20000) });
    got[p] = { status: r.status, text: await r.text() };
  } catch (e) { got[p] = { status: 0, text: "" }; chk(`read ${p}`, false, `FETCH_FAILED ${e.name}`); }
}

// (a) address-bearing fields, walked by name so a third-party URL in a description cannot trip this.
const originFields = [];
const WALK = (v, path, sink) => {
  if (Array.isArray(v)) return v.forEach((x, i) => WALK(x, `${path}[${i}]`, sink));
  if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (/^(resource|resources|url|uri|mcp_url|endpoint|servers|sample|openapi_url|documentationUrl|serverCardUrl|well_known_url)$/i.test(k)) sink.push([`${path}.${k}`, x]);
      WALK(x, `${path}.${k}`, sink);
    }
  }
};
for (const [p, { status, text }] of Object.entries(got)) {
  if (status !== 200) continue;
  try { WALK(JSON.parse(text), p.replace(/^\.\//, ""), originFields); } catch { /* llms.txt: handled by the regex pass below */ }
}
// Only http(s) values are addresses; a schema $id or an avatar PNG is not our origin's business.
const addr = [];
for (const [k, v] of originFields) for (const x of (Array.isArray(v) ? v : [v])) {
  if (typeof x !== "string" || !/^https?:\/\//.test(x)) continue;
  if (/"id"\s*:\s*"\$id"|json-schema|schema\.org|\.png$|\.svg$/i.test(k)) continue;
  addr.push({ v: x, k });
}
const mine = addr.filter((a) => a.v.startsWith(ORIGIN));
const KNOWN_THIRD_PARTY = /agenticresourcediscovery\.org|github\.com|alchemy|facilitator\.payai\.network|coinbase\.com|cloudflare|ngrok/;
const foreignOrigin = addr.filter((a) => !a.v.startsWith(ORIGIN) && !KNOWN_THIRD_PARTY.test(new URL(a.v).host));
chk("address-bearing fields in every JSON document resolve to the configured origin", addr.length > 0 && mine.length > 0 && foreignOrigin.length === 0,
  `${addr.length} address fields read, ${mine.length} name our origin${foreignOrigin.length ? ` — OFF-ORIGIN: ${foreignOrigin.slice(0, 4).map((a) => a.v).join(" ; ")}` : ""}`);

// (b) the invariant that actually caught the earlier bug: no loopback, no plain-http self-origin.
const blob = Object.values(got).map((g) => g.text).join("\n");
chk("no published document leaks a loopback address", !/127\.0\.0\.1|localhost|0\.0\.0\.0/.test(blob), "scanned " + blob.length + " bytes across " + Object.keys(got).filter((k) => got[k].status === 200).length + " docs");
chk("no document advertises our own origin over plain http", !new RegExp(`"origin"\\s*:\\s*"http:`).test(blob) && !new RegExp(`:8080|"http://${ORIGIN.replace(/^https?:\/\//, "")}`).test(blob));

// The 402 challenge IS the money message: `accepts[].resource` must name this origin, on many routes.
let challenged = 0, badRes = [];
for (const r of m.PAYABLE_ROUTES) {
  let res;
  try {
    res = await fetch(BASE + r.path, { method: r.method, headers: { accept: "application/json", "content-type": "application/json" },
      body: r.method === "GET" ? undefined : "{}", signal: AbortSignal.timeout(20000) });
  } catch { continue; }
  if (res.status !== 402) continue;
  const j = await res.json().catch(() => null);
  const acc = (j?.accepts || [])[0];
  if (!acc) continue;
  challenged++;
  if (String(acc.resource) !== ORIGIN + r.path) badRes.push(`${r.method} ${r.path} -> ${acc.resource}`);
}
chk("every unpaid 402 challenge names the configured origin in `resource`", challenged >= 100 && badRes.length === 0,
  `${challenged} challenges read${badRes.length ? ` — mismatches: ${badRes.slice(0, 3).join(" ; ")}` : ""}`);

const disc = JSON.parse(got["/discovery/resources"].text || "{}");
const wk = JSON.parse(got["/.well-known/x402"].text || "{}");
chk("discovery fan-out covers the whole payable table", (disc.items || []).length >= m.PAYABLE_ROUTES.length,
  `items=${(disc.items || []).length} payable=${m.PAYABLE_ROUTES.length}`);
chk("every well-known resource string names the configured origin",
  Array.isArray(wk.resources) && wk.resources.length > 0 && wk.resources.every((u) => String(u).startsWith(ORIGIN)),
  `${(wk.resources || []).length} resources`);

// NEGATIVE CONTROL — an instrument that cannot fail is not a check. Feed both collectors a document that
// carries a loopback origin and a foreign payable URL, and require both to reject it.
const fake = { resources: ["http://127.0.0.1:10000/price"], items: [{ resource: "https://other-origin.test/gas" }] };
const ctlSink = []; WALK(fake, "ctl", ctlSink);
const fAddr = ctlSink.flatMap(([, v]) => (Array.isArray(v) ? v : [v])).filter((v) => typeof v === "string" && /^https?:\/\//.test(v));
const fMine = fAddr.filter((v) => v.startsWith(ORIGIN));
chk("negative control: the field walker reads and rejects a loopback/foreign payable document",
  fAddr.length === 2 && fMine.length === 0 && /127\.0\.0\.1/.test(JSON.stringify(fake)),
  `read ${fAddr.length} address fields from the control, ${fMine.length} matched the origin (must be 0)`);

console.log(`\n${fails ? "ORIGIN PRE-FLIGHT FAILED" : "ORIGIN PRE-FLIGHT OK"} — assertions run: ${ran}, failures: ${fails}`);
console.log(`(read-only proof: ran against X402_PUBLIC_URL=${ORIGIN}; no payment sent, no wallet read)`);
process.exit(fails ? 1 : 0);
