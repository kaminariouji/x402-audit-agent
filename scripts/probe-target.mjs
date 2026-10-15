// Where our own instruments send their requests, and what that costs.
//
// Why this file exists: the ngrok free edge has a MONTHLY byte cap, and it has taken the whole rail dark
// twice (ERR_NGROK_725 / ERR_NGROK_8010). The cause was not buyers — it was our own battery. One leak drill
// alone is 136 routes x 19 path/method variants (~2,600 requests), and every unpaid challenge we serve is
// 1,841 bytes, so a single verification pass spent megabytes of a metered tunnel that a real buyer needs.
//
// The rule this encodes:
//   INVARIANT checks  -> the local container. The gate, the manifest, the schemas and the money MESSAGE are
//                        the same bytes; verified 2026-10-15 by comparing a local `GET /gas` (402, 1,841 B,
//                        `resource` = the public origin, `payTo` = the real wallet) against the public one.
//   EDGE-visible checks -> the public origin, deliberately, in small numbers. These ask "what does a visitor
//                        actually receive?" and a local answer would be a different question — that is how
//                        the /mcp 406 and the interstitial were only ever caught outside.
//   BUILDERS           -> the public origin, and they refuse to run against loopback, because an artifact
//                        generated while reading localhost has shipped localhost before.
export const LOCAL_ORIGIN = process.env.LOCAL_ORIGIN || "http://127.0.0.1:10000";
export const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || "https://labored-safari-islamic.ngrok-free.dev";

// A drill's default. `ORIGIN` still overrides, so a battery can deliberately be run against the edge once
// after a deploy — the point is that day-to-day runs cost the tunnel nothing.
export const PROBE_ORIGIN = process.env.ORIGIN || LOCAL_ORIGIN;
export const isLocal = (o) => /^(https?:\/\/)?(127\.0\.0\.1|localhost|0\.0\.0\.0)(:|$)/.test(o);

export function target(o = PROBE_ORIGIN) {
  return isLocal(o)
    ? `${o}  [LOCAL — 0 bytes of ngrok bandwidth; same deployed build, verified to advertise the public origin]`
    : `${o}  [PUBLIC EDGE — every byte below is charged to the monthly cap]`;
}

// Count what a run actually moved, so "this drill is cheap" is a number and not a claim.
export function meter() {
  const m = { requests: 0, bytes: 0, byPath: new Map() };
  m.fetch = async (url, opt) => {
    const r = await fetch(url, opt);
    const t = await r.clone().text();
    m.requests++;
    m.bytes += Buffer.byteLength(t);
    const key = `${(opt && opt.method) || "GET"} ${new URL(url).pathname}`;
    m.byPath.set(key, (m.byPath.get(key) || 0) + Buffer.byteLength(t));
    return r;
  };
  m.report = (label = "this run") => {
    const edge = isLocal(PROBE_ORIGIN) ? "" : "  <-- charged to the edge";
    console.log(`  ${label}: ${m.requests} requests, ${m.bytes.toLocaleString()} bytes${edge}`);
    if (!isLocal(PROBE_ORIGIN) && m.bytes > 1_000_000) {
      console.log(`  WARNING: over 1 MB of the monthly tunnel cap spent in one run. Biggest paths:`);
      [...m.byPath.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)
        .forEach(([p, b]) => console.log(`    ${b.toLocaleString().padStart(9)} B  ${p}`));
    }
  };
  return m;
}
