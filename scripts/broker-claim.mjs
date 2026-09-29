// Owner-side helper for claiming our row on agent-tools.cloud. Written so that the credential NEVER
// passes through this file's output, an argument, or a chat transcript: it is read from a local file that
// the OWNER creates, and only its existence/length is reported.
//
// Run order (the key mint must be done by the owner — see PENDING-OWNER-ACTIONS.md):
//   1. owner:  curl -s -X POST https://agent-tools.cloud/api/v1/keys -H "content-type: application/json" ^
//                 -d "{\"label\":\"x402-audit-agent-owner\"}" > C:\Codebuddy\.secrets\agent-tools.json
//   2. anyone: node scripts/broker-claim.mjs            <- this file: asks for the claim, prints the TOKEN
//   3. agent:  publish that token in our served descriptor (/.well-known/x402), redeploy
//   4. owner:  node scripts/broker-claim.mjs --verify   <- proves the host, then the row is editable
//
// The token is public by design — publishing it ON our host is the proof — so printing it here is safe.
// The API key is not, which is why step 1 writes it straight to a file from curl and never to a terminal.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Resolve everything from the repo root, not the current working directory: the first run of this script
// was attempted from `C:\Users\ojika` and died as "Cannot find module …\scripts\broker-claim.mjs", and a
// cwd-relative `.secrets/...` would silently read a different (empty) key file from wherever it happened
// to be launched. Secrets paths must not depend on which folder a terminal happens to open in.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AT = (p) => path.join(ROOT, p);

const KEY_FILES = [".secrets/agent-tools.key", ".secrets/agent-tools.json"].map(AT);
const ORIGIN = process.env.BROKER_ORIGIN || "https://labored-safari-islamic.ngrok-free.dev";
const HOST = new URL(ORIGIN).host;
const CLAIM_METHOD = process.env.BROKER_CLAIM_METHOD || "wellknown_file";
const TOKEN_FILE = AT(".secrets/agent-tools-claim.json");

function readKey() {
  for (const p of KEY_FILES) {
    if (!fs.existsSync(p)) continue;
    const raw = fs.readFileSync(p, "utf8").trim();
    let v = raw;
    try { const j = JSON.parse(raw); v = j.api_key || j.key || j.token || (j.data && j.data.api_key); } catch { /* a bare key in the file is fine */ }
    if (typeof v === "string" && v.length > 8) return { path: p, key: v };
  }
  return null;
}

const api = async (path, init) => {
  const r = await fetch(`https://agent-tools.cloud${path}`, { ...init, signal: AbortSignal.timeout(25_000) });
  const t = await r.text();
  let body; try { body = JSON.parse(t); } catch { body = { raw: t.slice(0, 300) }; }
  return { status: r.status, body };
};

const have = readKey();
if (!have) {
  console.log("NO KEY FILE YET — look for .secrets/agent-tools.key or .secrets/agent-tools.json.");
  console.log("The owner must mint it (step 1 in the header of this file). Nothing to verify yet.");
  process.exit(2);
}
console.log(`key found at ${have.path} (length ${have.key.length}; value not read into this session's output)`);

if (process.argv.includes("--verify")) {
  if (!fs.existsSync(TOKEN_FILE)) { console.log(`no ${TOKEN_FILE} — run this file without --verify first`); process.exit(2); }
  const claim = JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));
  // Their verify endpoint is per-claim — `POST /api/v1/claims/{claim_id}/verify` with body `{token}` — as
  // the claim response's own `next` block spells out. The first draft here posted to a generic
  // `/api/v1/claims/verify` with `{hostname, token}`, which is a guessed shape.
  const claimId = claim.claim_id ?? claim.claim_response?.claim_id ?? null;
  if (!claimId) { console.log("claim_id missing in the saved claim — re-run without --verify"); process.exit(2); }
  const served = await fetch(`${ORIGIN}/.well-known/agent-tools-verify.txt`, { signal: AbortSignal.timeout(20_000) })
    .then(async (r) => ({ status: r.status, body: (await r.text()).trim() }))
    .catch((e) => ({ status: "ERR", body: String(e.message) }));
  console.log(`published check -> HTTP ${served.status}, body ${served.body === claim.token ? "MATCHES the claim token" : `does NOT match (${served.body.slice(0, 40)})`}`);
  if (served.body !== claim.token) { console.log("refusing to verify before the token is actually served — a 404 here just burns the claim"); process.exit(1); }
  const res = await api(`/api/v1/claims/${claimId}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${have.key}` },
    body: JSON.stringify({ token: claim.token }),
  });
  console.log("verify ->", res.status, JSON.stringify(res.body).slice(0, 500));
  process.exit(res.status >= 400 ? 1 : 0);
}

// Their own `next` block from the key-mint response says exactly this (read 2026-09-30 from
// .secrets/agent-tools.json): `POST /api/v1/claims`, `Authorization: Bearer <api_key>`, body
// `{ "host": …, "method": "wellknown_file" }`. The first draft here sent `{ hostname, url }` — invented
// field names, which a 400 would have answered with a guess. Send what the API actually documents.
const res = await api("/api/v1/claims", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: `Bearer ${have.key}` },
  body: JSON.stringify({ host: HOST, method: CLAIM_METHOD }),
});
const token = res.body?.token || res.body?.verification_token || (res.body?.data && res.body.data.token);
console.log("claims ->", res.status, JSON.stringify(res.body).slice(0, 500));
if (!token) { console.log("NO TOKEN IN RESPONSE — their docs list other proof paths: descriptor field, well-known file, DNS TXT."); process.exit(1); }
fs.writeFileSync(TOKEN_FILE, JSON.stringify({ hostname: HOST, claim_id: res.body?.claim_id ?? null, token, at: new Date().toISOString(), publish: res.body?.publish || null, claim_response: res.body }, null, 1));
console.log(`\nTOKEN ${token}  (public by design — publishing it on ${HOST} is the proof)`);
console.log(`saved to ${TOKEN_FILE}. Next: serve it from the origin, then run this file with --verify.`);
