// Whole-surface buyer-path audit, zero money: for every advertised resource, ask it UNPAID and check four
// things a paying agent depends on.
//   1. it answers 402 (not 200 = leak, not 400 = a validation wall in front of the payment challenge);
//   2. every accepts[] entry passes the official client's PaymentRequirementsSchema;
//   3. selectPaymentRequirements() picks terms whose amount matches what /discovery/resources advertised;
//   4. both networks we claim (Base + Solana) are actually offered on the route.
// This is the check that would have caught the apiKey security-scheme problem as a number instead of a
// guess, and it is the only way to know the 5 newest routes are payable rather than merely described.
import { PROBE_ORIGIN, target, meter } from "../scripts/probe-target.mjs";
const ORIGIN = PROBE_ORIGIN;
const M = meter();
console.log(`target: ${target(ORIGIN)}`);
const { PaymentRequirementsSchema } = await import("x402/types");
const { selectPaymentRequirements } = await import("x402/client");
const H = { "ngrok-skip-browser-warning": "1", accept: "application/json, text/event-stream" };

const disc = await (await M.fetch(`${ORIGIN}/discovery/resources`, { headers: H })).json();
const items = (disc.items || []).filter((i) => i.resource && (i.accepts || []).length);
console.log(`advertised priced resources with accepts: ${items.length}`);
const BASE = "eip155:8453", SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const usd = (a) => { const raw = a.amount ?? a.maxAmountRequired; return raw == null ? null : Number(raw) / 1e6; };
const tally = { ok: 0, compared: 0, uncharged: [], leak200: [], wrongStatus: [], parseFail: [], priceMismatch: [], missingSolana: [], missingBase: [], edgeOutage: [] };
// The positive control this file was blind to until 2026-09-28: `adv` was computed with usd() over the
// advertised accepts, and our published accepts carried only `price:"$0.001"` — no atomic amount. So usd()
// returned null for every item, `Number.isFinite(adv)` was false, and the advertised-vs-charged comparison
// silently NEVER RAN while still printing "advertised price != challenged price: 0". An assertion that
// cannot fail is not a check. This counter proves it executes, and this line proves the advertisement is
// payable-quality: amount + asset + decimals present in the document, not just on the live 402.
const unpriced = items.filter((i) => (i.accepts || []).every((a) => usd(a) == null));
const noAsset = items.filter((i) => (i.accepts || []).every((a) => !a.asset));
console.log(`advertised items whose published accepts carry NO atomic amount: ${unpriced.length}${unpriced.length ? " e.g. " + unpriced.slice(0, 3).map((i) => i.resource).join(", ") : ""}`);
console.log(`advertised items whose published accepts carry NO asset contract: ${noAsset.length}${noAsset.length ? " e.g. " + noAsset.slice(0, 3).map((i) => i.resource).join(", ") : ""}`);

// The advertisement is ABSOLUTE and names the public origin (correctly — that is what a buyer must pay at).
// Reading item.resource verbatim therefore sent all 146 probes over the metered edge even with ORIGIN set to
// localhost, and when the tunnel is out of quota they all came back as ngrok's own 403 page. Two bugs at once:
// the run quietly measured the EDGE and then charged its bytes to nothing. Map the advertised path onto the
// chosen probe target, and name an edge outage instead of burying it in "wrong status".
//
// The outage test must NOT be a substring search for "ngrok": our own valid 402 body contains the word, because
// `accepts[].resource` is an ngrok URL. The first version of this line classified all 146 healthy local
// challenges as an edge outage and printed a confident 0/146. So: ngrok's own error header, or a body that is
// not our JSON and carries ngrok's actual error text.
const toTarget = (u) => { try { return ORIGIN + new URL(u).pathname; } catch { return u; } };
const edgeOutage = (res, body) => {
  if (res.headers.get("ngrok-error-code")) return true;
  return /ERR_NGROK_\d+|bandwidth limit for the month/i.test(body) && !/"x402Version"\s*:\s*[12]/.test(body);
};

async function probe(item) {
  const url = toTarget(item.resource);
  const method = (item.method || (item.accepts?.[0]?.extra?.method) || "GET").toUpperCase();
  const init = method === "GET" ? { headers: H } : { method, headers: { ...H, "content-type": "application/json" }, body: "{}" };
  let res;
  try { res = await M.fetch(url, { ...init, signal: AbortSignal.timeout(25_000) }); }
  catch (e) { tally.wrongStatus.push(`${method} ${url} FETCH_FAILED ${e.name}`); return; }
  const body = await res.text();
  if (edgeOutage(res, body)) { tally.edgeOutage.push(`${method} ${url} -> ${res.status} ${body.slice(0, 70).replace(/\s+/g, " ")}`); return; }
  if (res.status === 200) { tally.leak200.push(`${method} ${url} answered 200 unpaid`); return; }
  // A 503 refusal is the app declining to sell a reading it cannot take (every public source for that
  // route is currently unreachable). It is answered BEFORE the payment gate and carries no accepts[], so
  // nobody was charged and nothing leaked — that is the correct behaviour during a vendor outage, not a
  // buyer-path defect. It is counted, named, and kept out of the failure buckets on purpose.
  if (res.status === 503) {
    let b = null; try { b = JSON.parse(body); } catch { /* falls through to the defect line */ }
    if (b?.error === "upstream_unavailable" && b?.charged === false && !Array.isArray(b?.accepts)) {
      tally.uncharged.push(`${method} ${url} refused unpaid — venues down: ${(b.venues || []).join(", ")}`);
      return;
    }
    tally.wrongStatus.push(`${method} ${url} -> 503 that is NOT the uncharged refusal shape: ${body.slice(0, 70).replace(/\s+/g, " ")}`);
    return;
  }
  if (res.status !== 402) { tally.wrongStatus.push(`${method} ${url} -> ${res.status} ${body.slice(0, 70).replace(/\s+/g, " ")}`); return; }
  let chal; try { chal = JSON.parse(body); } catch { chal = null; }
  const accepts = chal?.accepts || [];
  if (!accepts.length) { tally.parseFail.push(`${method} ${url} 402 body carries no accepts[]`); return; }
  const parsed = [];
  for (const a of accepts) {
    try { parsed.push(PaymentRequirementsSchema.parse(a)); }
    catch (e) { tally.parseFail.push(`${method} ${url} PaymentRequirementsSchema rejected ${a.network}: ${String(e?.message).slice(0, 90)}`); }
  }
  if (!parsed.length) return;
  const nets = new Set(parsed.map((p) => String(p.network).toLowerCase()));
  const hasBase = nets.has(BASE) || nets.has("base"), hasSol = [...nets].some((n) => n.startsWith("solana"));
  if (!hasBase) tally.missingBase.push(`${method} ${url}`);
  if (!hasSol) tally.missingSolana.push(`${method} ${url}`);
  // advertised price vs charged price, in USDC
  const adv = Math.min(...item.accepts.map(usd).filter((v) => Number.isFinite(v) && v > 0));
  const charged = Math.min(...parsed.map(usd).filter((v) => Number.isFinite(v) && v > 0));
  if (Number.isFinite(adv) && Number.isFinite(charged)) {
    tally.compared++;
    if (Math.abs(adv - charged) > 1e-9) {
      tally.priceMismatch.push(`${method} ${url} advertises $${adv} but challenges $${charged}`);
    }
  }
  try { selectPaymentRequirements(parsed, { network: "eip155:8453" }); } catch (e) { tally.parseFail.push(`${url} selectPaymentRequirements(base) threw ${String(e?.message).slice(0, 80)}`); }
  tally.ok++;
}

for (let i = 0; i < items.length; i += 8) {
  await Promise.all(items.slice(i, i + 8).map(probe));
}

console.log(`\n402 + parseable + terms-selected: ${tally.ok}/${items.length}`);
const show = (k, label) => { const a = tally[k]; console.log(`${label}: ${a.length}${a.length ? "\n  " + a.slice(0, 8).join("\n  ") : ""}`); };
show("leak200", "LEAK — answered 200 with no payment");
show("parseFail", "client could not parse / select our challenge");
show("priceMismatch", "advertised price != challenged price");
show("uncharged", "503 refusals before the gate (vendor unreachable — nobody charged, nothing served)");
show("missingBase", "no Base terms offered");
show("missingSolana", "no Solana terms offered");
console.log(`other status before the payment challenge (400 = argument wall in front of the 402): ${tally.wrongStatus.length}`);
if (tally.wrongStatus.length) console.log("  " + tally.wrongStatus.slice(0, 10).join("\n  "));
// An edge outage is NOT a pass and NOT a defect: it means ngrok answered, so nothing about our gate was
// observed. It has to be loud, because this file previously read 146 tunnel error pages as "0 leaks".
if (tally.edgeOutage.length) {
  console.log(`EDGE OUTAGE — ngrok answered instead of our app on ${tally.edgeOutage.length}/${items.length} probes; the gate was NOT observed this run`);
  console.log("  " + tally.edgeOutage.slice(0, 3).join("\n  "));
}
console.log(`price comparison actually executed on: ${tally.compared}/${items.length} advertised items (0 means the advertisement is unpriced and this check is blind — NOT a pass)`);
const clean = !tally.leak200.length && !tally.parseFail.length && !tally.priceMismatch.length;
const ran = tally.compared > 0 && !tally.edgeOutage.length;
const verdict = tally.edgeOutage.length
  ? `TUNNEL/EDGE OUTAGE on ${tally.edgeOutage.length} of ${items.length} probes — nothing here is verified, in either direction. Fix the edge (quota) and re-run; do NOT write "0 leaks" from this run.`
  : !ran ? "CHECK DID NOT RUN — advertised accepts carry no atomic amount on any route, so advertised-vs-charged could not be compared. Fix the advertisement before believing any clean line above."
  : clean ? "every advertised resource is payable by the reference client at its advertised price"
  : "BUYER-PATH DEFECTS ABOVE — a client cannot pay us cleanly on the listed routes";
console.log(`\nVERDICT: ${verdict}`);
// Negative control for the outage detector itself. It must say NO for our own healthy 402 (whose body
// legitimately contains the word "ngrok" inside accepts[].resource) and YES for the tunnel's page. Without
// this the detector is unfalsifiable, and an unfalsifiable detector is not a check.
const hdr = (v) => ({ get: () => v, ...{} });
const fakeRes = (code, hv) => ({ status: code, headers: { get: () => hv } });
const ctl402 = JSON.stringify({ x402Version: 1, error: "Payment required", accepts: [{ resource: "https://labored-safari-islamic.ngrok-free.dev/gas", scheme: "exact" }] });
const ctlPage = '<html>ERR_NGROK_725 ... bandwidth limit for the month</html>';
const ctl = [
  ["own 402 mentioning ngrok is NOT an outage", edgeOutage(fakeRes(402, null), ctl402) === false],
  ["tunnel 403 page IS an outage", edgeOutage(fakeRes(403, null), ctlPage) === true],
  ["ngrok error header IS an outage even on JSON", edgeOutage(fakeRes(403, "ERR_NGROK_725"), ctl402) === true],
];
let ctlFail = 0;
for (const [name, pass] of ctl) { console.log(`  ${pass ? "ok  " : "FAIL"} control: ${name}`); if (!pass) ctlFail++; }
M.report("challenge-parse-all");
process.exit(ran && clean && !ctlFail ? 0 : 1);
