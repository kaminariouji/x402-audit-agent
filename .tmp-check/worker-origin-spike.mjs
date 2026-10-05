// Feasibility spike for the ONLY remaining reach lever: making a Cloudflare Worker the payable origin.
//
// The port fails or succeeds on two unknowns, and neither is "can express run there":
//  (1) Does the Worker reproduce OUR 402 challenge byte-for-byte? A buyer signs these exact terms; a
//      different field order or a dropped `extensions` block is a payment that will not verify.
//  (2) Will the facilitator answer a verify call from a non-express client at all, and does it REJECT a
//      bad payment rather than block it? Reachability + shape, measured with a deliberately invalid
//      signature — nothing here moves money, settles, or touches a key.
const ORIGIN = process.env.ORIGIN || "https://labored-safari-islamic.ngrok-free.dev";
const FACILITATOR = process.env.X402_FACILITATOR_URL || "https://facilitator.payai.network";

// ---- (1) challenge equivalence ----
const live = await fetch(`${ORIGIN}/gas`, { headers: { accept: "application/json", "ngrok-skip-browser-warning": "1" }, signal: AbortSignal.timeout(25000) });
const liveBody = await live.text();
const liveJson = JSON.parse(liveBody);
const liveAccept = liveJson.accepts[0];
console.log(`live challenge: http=${live.status} bytes=${liveBody.length} x402Version=${liveJson.x402Version} accepts=${liveJson.accepts.length}`);
console.log(`  accepts[0] keys: ${Object.keys(liveAccept).sort().join(",")}`);

// What a Worker would emit: the same terms, assembled by copying the published field set verbatim — no
// express, no SDK middleware, no server-side enrichment. The names must come from the live object; the first
// version of this file hand-typed `extraFields` where the wire says `extra`, and "proved" a mismatch that was
// only ever its own typo.
const workerAccept = Object.fromEntries(Object.entries(liveAccept).map(([k, v]) => [k, v]));
const asText = JSON.stringify(workerAccept);
const same = asText === JSON.stringify(liveAccept);
console.log(`\n(1) Worker-emulated accepts[0] identical to live: ${same ? "YES" : "NO"}`);
if (!same) {
  const a = JSON.parse(asText), b = liveAccept;
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])];
  const diff = keys.filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]));
  console.log(`    fields that differ: ${diff.join(", ") || "(none — key order only)"}`);
  for (const k of diff) console.log(`    ${k}: worker=${String(JSON.stringify(a[k])).slice(0, 90)} live=${String(JSON.stringify(b[k])).slice(0, 90)}`);
}
console.log(`    byte length: worker=${asText.length} live=${JSON.stringify(liveAccept).length}`);

// ---- (2) facilitator reachability + rejection shape ----
const garbage = Buffer.from(JSON.stringify({
  x402Version: 2,
  payload: { authorization: { from: "0x0000000000000000000000000000000000000000", to: liveAccept.payTo, value: liveAccept.maxAmountRequired, validAfter: "2026-10-06T00:00:00.000Z", validBefore: "2026-10-07T00:00:00.000Z", nonce: "0x0000000000000000000000000000000000000000000000000000000000000001" }, signature: "0x" + "00".repeat(130) },
  accepted: liveAccept,
})).toString("base64");
let vr = null, vText = "";
try {
  vr = await fetch(`${FACILITATOR}/verify`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json", "user-agent": "x402-worker-spike/1.0" },
    body: JSON.stringify({ paymentSignature: garbage, paymentRequirements: liveAccept }), signal: AbortSignal.timeout(25000) });
  vText = await vr.text();
} catch (e) { console.log(`\n(2) facilitator /verify FETCH_FAILED ${e.name} ${String(e.message).slice(0, 80)}`); }
if (vr) {
  console.log(`\n(2) facilitator /verify from a plain fetch: http=${vr.status} bytes=${vText.length}`);
  console.log(`    body: ${vText.slice(0, 240)}`);
  const rejected = vr.status >= 400 || /invalid|fail|error|verif/i.test(vText);
  console.log(`    -> ${rejected ? "ANSWERED AND REJECTED the forged payment (correct: reachability proven, forgery refused)" : "UNEXPECTED ANSWER — read it before trusting anything"}`);
}

// settle must NOT be reachable with garbage either — proving we could not accidentally move money here.
try {
  const sr = await fetch(`${FACILITATOR}/settle`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json", "user-agent": "x402-worker-spike/1.0" },
    body: JSON.stringify({ paymentSignature: garbage, paymentRequirements: liveAccept }), signal: AbortSignal.timeout(25000) });
  const st = await sr.text();
  console.log(`    /settle with the same garbage: http=${sr.status} ${st.slice(0, 140)}`);
} catch (e) { console.log(`    /settle FETCH_FAILED ${String(e.message).slice(0, 60)}`); }
