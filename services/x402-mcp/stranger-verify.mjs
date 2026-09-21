// Is payai's Base refusal OUR bug, or everyone's?
// Measured: payai refuses invalid_exact_evm_signature for a Base v2 payment we build, and the same for
// a hand-built v1 payment, while /supported advertises eip155:8453/exact. That leaves two readings:
//   (a) something in the requirements we publish makes the signature un-verifiable, or
//   (b) payai's EIP-3009 path for Base is broken for the whole ecosystem.
// Resolve it by borrowing a stranger's challenge. Take live, already-indexed Base x402 services out of
// payai's own discovery list, fetch the 402 terms they publish, and hand payai /verify a payment built
// to THOSE terms with our throwaway key. Their requirements are the control group: if valid services
// also get invalid_exact_evm_signature, the fault is payai's and no Base buyer can pay us today no
// matter what we change. If a stranger's terms verify (or fail only on balance/allowance), diff their
// acceptance against ours to find the field we are getting wrong.
// /verify is read-only signature validation: nothing is settled, broadcast, or spent, and the payer is
// a zero-balance anvil key.
// Run: cd services/x402-mcp && node stranger-verify.mjs
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";

const FACILITATOR = "https://facilitator.payai.network";
// A FRESH key, not the anvil test key: payai denylists 0x70997970… with invalid_exact_evm_signature,
// which is exactly the confound that made an earlier run of this probe "prove" a broken verifier.
const account = privateKeyToAccount(generatePrivateKey());

const disc = await fetch(`${FACILITATOR}/discovery/resources?limit=1000`).then((r) => r.json());
const items = disc.resources || disc.items || disc.data || [];
// Candidate = a resource URL we can re-challenge ourselves, on an EVM chain.
const candidates = [];
for (const it of items) {
  const url = it.url || it.resource || it.endpoint;
  if (typeof url !== "string" || !/^https:\/\//.test(url)) continue;
  const net = String(it.network || it.accepts?.[0]?.network || "");
  const evm = /eip155:(8453|84532|1|137|42161)$/.test(net) || /8453/.test(JSON.stringify(it).slice(0, 400));
  if (evm) candidates.push({ url, network: net || "?", payTo: it.payTo || it.accepts?.[0]?.payTo || "?" });
  if (candidates.length >= 40) break;
}
console.log(`discovery items=${items.length} evm candidates=${candidates.length}`);

async function challengeOf(url) {
  const r = await fetch(url, { method: "GET", headers: { accept: "application/json" } }).catch(() => null);
  const raw = r?.headers?.get("payment-required") || r?.headers?.get("x-payment-required");
  if (!raw) return null;
  try { return JSON.parse(Buffer.from(raw, "base64").toString()); } catch { return null; }
}

async function verify(terms, req) {
  const client = new x402Client(() => req);
  client.register(req.network, new ExactEvmScheme(account));
  const payload = await new x402HTTPClient(client).createPaymentPayload(terms);
  const res = await fetch(`${FACILITATOR}/verify`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ x402Version: req.x402Version ?? terms.x402Version, paymentPayload: payload, paymentRequirements: req }),
  });
  const text = await res.text();
  let verdict = text.slice(0, 120).replace(/\s+/g, " ");
  try { const j = JSON.parse(text); verdict = `isValid=${j.isValid} reason=${j.invalidReason ?? "-"} payer=${(j.payer || "").slice(0, 10)}`; } catch {}
  return `HTTP ${res.status} ${verdict}`;
}

let tried = 0, balanceOnly = 0, sigRefused = 0;
for (const c of candidates) {
  if (tried >= 8) break;
  const terms = await challengeOf(c.url).catch(() => null);
  if (!terms?.accepts?.length) continue;
  const req = terms.accepts.find((a) => /^eip155:(8453|84532|1|137|42161)$/.test(String(a.network)));
  if (!req) continue;
  tried++;
  let out;
  try { out = await verify(terms, req); } catch (e) { out = "threw " + String(e).slice(0, 90); }
  const sigBad = /invalid.*signature|SignerMismatch/i.test(out);
  if (sigBad) sigRefused++; else if (/isValid=true|balance|allowance|insufficient/i.test(out)) balanceOnly++;
  console.log(`\n[stranger] ${c.url.slice(0, 72)}\n   network=${req.network} amount=${req.amount ?? req.maxAmountRequired} asset=${String(req.asset).slice(0, 12)} extra=${JSON.stringify(req.extra ?? null).slice(0, 90)}\n   -> ${out}  ${sigBad ? "(signature refused)" : ""}`);
}
console.log(`\n=== ${tried} stranger services tested: ${sigRefused} refused on signature, ${balanceOnly} got past signature ===`);
console.log(sigRefused && !balanceOnly
  ? "=> payai refuses EVERY Base EIP-3009 payment, ours included: ecosystem-wide verifier fault, not our challenge."
  : balanceOnly ? "=> some strangers verify: diff their acceptance fields against ours to find the bad one."
               : "=> inconclusive (not enough reachable strangers).");
