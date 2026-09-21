// Paid round-trip harness: our server pointed at a LOCAL mock facilitator, so the path
// "402 -> buyer attaches payment -> verify ok -> handler runs -> settle ok -> 200 with real data"
// is proven without any funds. The mock is a test double: it settles nothing and moves no money.
//
// The payment is built by the OFFICIAL x402 client stack (@x402/core/client x402Client +
// @x402/evm/exact/client ExactEvmScheme + a viem account), so this also proves the standard
// buyer path works against our server: header name, payload nesting and the `accepted` echo all
// come from the library, not from hand-crafting.
// Run: cd services/x402-mcp && node paid-roundtrip.mjs
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { privateKeyToAccount } from "viem/accounts";
import { recoverTypedDataAddress } from "viem";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";

const PORT = Number(process.env.PORT || 10997);
const MOCK_PORT = Number(process.env.MOCK_PORT || 10998);
const BUYER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const EIP3009_TYPES = [
  { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
  { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
];

const seen = [];
const PAYABLE_KINDS = [
  { x402Version: 2, scheme: "exact", network: "eip155:8453" },
  { x402Version: 2, scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" },
];
function readBody(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({ _raw: raw }); }
    });
  });
}
const send = (res, obj) => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(obj));

// The mock does the things a real facilitator does that need no money and no network: it
// re-recovers the EIP-712 signer and re-checks the payment against the terms it was handed
// (amount, payTo, validity window). Anything short of an authentic, on-terms signature comes
// back invalid — so a passing round trip is a real verification, not a rubber stamp.
function inspectPayment(body) {
  const payload = body?.paymentPayload;
  const req = body?.paymentRequirements;
  const auth = payload?.payload?.authorization;
  const sig = payload?.payload?.signature;
  if (!auth || !sig || !req?.extra?.name) return { payer: null, reason: "malformed" };
  if (String(auth.value) !== String(req.amount)) return { payer: null, reason: "amount_mismatch" };
  if (String(auth.to).toLowerCase() !== String(req.payTo).toLowerCase()) return { payer: null, reason: "payTo_mismatch" };
  const now = Math.floor(Date.now() / 1000);
  if (Number(auth.validAfter) > now || Number(auth.validBefore) <= now) return { payer: null, reason: "expired" };
  return { signer: auth, sig, req, payer: null, reason: null };
}
async function verifyPayment(body) {
  const checked = inspectPayment(body);
  if (checked.reason) return checked;
  const { signer: auth, sig, req } = checked;
  try {
    const recovered = await recoverTypedDataAddress({
      domain: {
        name: req.extra.name, version: req.extra.version,
        chainId: Number(String(req.network).split(":")[1]),
        verifyingContract: req.asset,
      },
      types: { TransferWithAuthorization: EIP3009_TYPES },
      primaryType: "TransferWithAuthorization",
      message: {
        from: auth.from, to: auth.to, value: BigInt(auth.value),
        validAfter: BigInt(auth.validAfter), validBefore: BigInt(auth.validBefore), nonce: auth.nonce,
      },
      signature: sig,
    });
    if (recovered.toLowerCase() !== auth.from.toLowerCase()) return { payer: null, reason: "bad_signature" };
    return { payer: recovered, reason: null };
  } catch (e) {
    console.log(`[mock] signature recovery failed: ${String(e?.message).slice(0, 160)}`);
    return { payer: null, reason: "bad_signature" };
  }
}

const mock = createServer(async (req, res) => {
  const body = await readBody(req);
  const { payer, reason } = req.url.endsWith("/verify") || req.url.endsWith("/settle")
    ? await verifyPayment(body) : { payer: null, reason: null };
  seen.push({ method: req.method, path: req.url, body, recoveredPayer: payer, invalidReason: reason });
  console.log(`[mock] ${req.method} ${req.url} payer=${payer ?? "-"} reason=${reason ?? "-"} ${JSON.stringify(body).slice(0, 220)}`);
  if (req.url === "/supported") return send(res, { kinds: PAYABLE_KINDS, extensions: [], signers: {} });
  const requirements = body.paymentRequirements ?? {};
  if (req.url.endsWith("/verify")) {
    return send(res, {
      isValid: !reason, invalidReason: reason,
      invalidMessage: reason ? `mock rejected the payment: ${reason}` : null,
      payer, network: requirements.network,
    });
  }
  if (req.url.endsWith("/settle")) {
    // Test double: reports success, broadcasts nothing. `transaction`/`network` are required
    // by settleResponseSchema (@x402/core/dist/esm/chunk-UF6R7D6H.mjs:337), so they must be present.
    return send(res, {
      success: !reason, errorReason: reason,
      payer, network: requirements.network, amount: requirements.amount,
      transaction: "0x" + "00".repeat(32),
    });
  }
  return send(res, { ok: true });
});
await new Promise((r) => mock.listen(MOCK_PORT, "127.0.0.1", r));

const child = spawn(process.execPath, ["server.mjs"], {
  cwd: process.cwd(),
  env: { ...process.env, PORT: String(PORT), X402_FACILITATOR_URL: `http://127.0.0.1:${MOCK_PORT}` },
  stdio: ["ignore", "pipe", "pipe"],
});
child.stdout.on("data", (d) => {
  const t = String(d);
  if (/invalid|reject|payment|error|missing|expired|mismatch/i.test(t)) process.stdout.write(`[srv] ${t.trim().slice(0, 400)}\n`);
});
child.stderr.on("data", (d) => process.stderr.write(d));

const base = `http://127.0.0.1:${PORT}`;
let up = false;
for (let i = 0; i < 60 && !up; i++) {
  up = await fetch(base + "/health").then((r) => r.ok).catch(() => false);
  if (!up) await new Promise((r) => setTimeout(r, 250));
}
if (!up) { console.error("server did not start"); child.kill(); process.exit(1); }

const fails = [];
function check(name, cond, detail) {
  if (cond) console.log(`  ok   ${name}`);
  else { fails.push(name); console.log(`  FAIL ${name} :: ${detail}`); }
}

// ---- buyer: the real x402 client stack, pointed at a throwaway key ----
const account = privateKeyToAccount(BUYER_KEY);
const client = new x402Client((_version, accepts) =>
  accepts.find((a) => a.network.startsWith("eip155:")) ?? accepts[0]);
client.register("eip155:8453", new ExactEvmScheme(account));
const http = new x402HTTPClient(client);

function decodeChallenge(res) {
  const raw = res.headers.get("payment-required");
  if (!raw) return null;
  return JSON.parse(Buffer.from(raw, "base64").toString());
}
// Standard buyer flow: take the 402 challenge, let the library build the payment, attach it with
// the library's own header encoder, retry.
async function payAndRetry(url, init = {}) {
  const unpaid = await fetch(url, init);
  const terms = decodeChallenge(unpaid);
  if (!terms) throw new Error(`no PAYMENT-REQUIRED header on ${url} (${unpaid.status})`);
  const payload = await http.createPaymentPayload(terms);
  const headers = { ...(init.headers || {}), ...http.encodePaymentSignatureHeader(payload) };
  console.log(`  [buyer] header=${Object.keys(headers).find((h) => /signature|payment/i.test(h))} ` +
    `x402Version=${payload.x402Version} network=${payload.accepted.network} amount=${payload.accepted.amount}`);
  const paid = await fetch(url, { ...init, headers });
  return { paid, payload, terms, headers: Object.keys(headers) };
}

console.log("\n== paid GET /price (real DEX quote after a verified payment) ==");
const priceUrl = base + "/price?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const unpaidPrice = await fetch(priceUrl);
check("unpaid GET /price -> 402", unpaidPrice.status === 402, String(unpaidPrice.status));
const firstTerms = decodeChallenge(unpaidPrice);
check("challenge x402Version is 2", firstTerms?.x402Version === 2, JSON.stringify(firstTerms?.x402Version));
check("challenge advertises Base + Solana", firstTerms?.accepts?.length === 2, JSON.stringify(firstTerms?.accepts?.map((a) => a.network)));
console.log("FULL TERMS accepts:", JSON.stringify(firstTerms.accepts, null, 1).slice(0, 900));

const { paid, payload, headers: priceHeaders } = await payAndRetry(priceUrl);
const paidBody = await paid.json().catch(() => ({}));
if (paid.status !== 200) {
  const rej = decodeChallenge(paid);
  console.log("rejection:", JSON.stringify(rej?.error ?? rej ?? paidBody).slice(0, 400));
}
console.log(`paid GET /price -> ${paid.status} ${JSON.stringify(paidBody).slice(0, 220)}`);
check("paid GET /price -> 200", paid.status === 200, String(paid.status));
check("paid /price returns live data", Number(paidBody.priceUsd ?? 0) > 0, JSON.stringify(paidBody).slice(0, 160));
check("buyer uses the v2 PAYMENT-SIGNATURE header", priceHeaders.some((h) => h.toLowerCase() === "payment-signature"), JSON.stringify(priceHeaders));
check("server echoed a PAYMENT-RESPONSE (settled)", !!paid.headers.get("payment-response"), JSON.stringify([...paid.headers.keys()]));

// ---- what the (mock) facilitator was actually handed ----
const verifyCall = seen.find((s) => s.path.endsWith("/verify"));
const settleCall = seen.find((s) => s.path.endsWith("/settle"));
check("server called facilitator /verify", !!verifyCall, JSON.stringify(seen.map((s) => s.path)));
check("server called facilitator /settle", !!settleCall, JSON.stringify(seen.map((s) => s.path)));
check("facilitator recovered the throwaway buyer from the signature",
  String(verifyCall?.recoveredPayer).toLowerCase() === account.address.toLowerCase(),
  JSON.stringify({ recovered: verifyCall?.recoveredPayer, buyer: account.address }));
for (const [name, call] of [["verify", verifyCall], ["settle", settleCall]]) {
  const sent = call?.body?.paymentPayload ?? {};
  const keys = Object.keys(sent);
  console.log(`  [facilitator ${name}] paymentPayload keys: ${JSON.stringify(keys)}`);
  // CDP issue #767: a payload missing paymentPayload.extensions.bazaar or .resource never indexes.
  check(`${name} payload carries resource`, typeof sent.resource?.url === "string", JSON.stringify(sent.resource ?? null).slice(0, 120));
  check(`${name} payload echoes bazaar extension`, !!sent.extensions?.bazaar, JSON.stringify(Object.keys(sent.extensions ?? {})));
  check(`${name} payload carries accepted + signature`, !!sent.accepted && /^0x[0-9a-f]{130}$/i.test(String(sent.payload?.signature)), JSON.stringify(Object.keys(sent)));
  check(`${name} body carries paymentRequirements`, !!call?.body?.paymentRequirements?.amount, JSON.stringify(Object.keys(call?.body ?? {})));
}
const auth = payload.payload.authorization;
check("payment amount matches the $0.001 quote", String(auth.value) === String(payload.accepted.amount), `${auth.value} vs ${payload.accepted.amount}`);
check("payment pays OUR wallet", String(auth.to).toLowerCase() === "0x7c8a3c26bd579c5176a29a5a8ae80536319fa94b", String(auth.to));

console.log("\n== paid POST /audit (real scan after a verified payment) ==");
const auditBody = JSON.stringify({ code: "state.earnings.total_usd += amount;", filename: "bot.js" });
const audit = await payAndRetry(base + "/audit", {
  method: "POST", headers: { "content-type": "application/json" }, body: auditBody,
});
const auditJson = await audit.paid.json().catch(() => ({}));
console.log(`paid POST /audit -> ${audit.paid.status} ${JSON.stringify(auditJson).slice(0, 200)}`);
check("paid POST /audit -> 200", audit.paid.status === 200, String(audit.paid.status));
check("paid /audit returns real findings", Array.isArray(auditJson.findings) && auditJson.findings.length > 0, JSON.stringify(auditJson).slice(0, 160));

console.log("\n== gate is still a gate: a tampered payment is rejected ==");
const settlesBefore = seen.filter((s) => s.path.endsWith("/settle")).length;
const tampered = structuredClone(payload);
tampered.payload.authorization.value = String(BigInt(payload.accepted.amount) * 1000n);
const badRes = await fetch(priceUrl, { headers: http.encodePaymentSignatureHeader(tampered) });
const badTerms = decodeChallenge(badRes);
const badCall = seen[seen.length - 1];
console.log(`tampered GET /price -> ${badRes.status} error=${JSON.stringify(badTerms?.error)}`);
check("tampered payment -> 402", badRes.status === 402, String(badRes.status));
check("tampered payment -> no real data", !badRes.headers.get("payment-response"), String(badRes.headers.get("payment-response")));
check("facilitator reported why", badCall?.invalidReason === "amount_mismatch", JSON.stringify(badCall?.invalidReason ?? badCall?.path));
check("no settlement ran for the tampered payment",
  seen.filter((s) => s.path.endsWith("/settle")).length === settlesBefore, JSON.stringify(seen.map((s) => s.path)));

const reSigned = structuredClone(payload);
reSigned.payload.signature = "0x" + "11".repeat(65);
const badSigRes = await fetch(priceUrl, { headers: http.encodePaymentSignatureHeader(reSigned) });
console.log(`forged-signature GET /price -> ${badSigRes.status} error=${JSON.stringify(decodeChallenge(badSigRes)?.error)}`);
check("forged signature -> 402", badSigRes.status === 402, String(badSigRes.status));
check("forged signature fails signature recovery, not just terms", seen[seen.length - 1]?.invalidReason === "bad_signature", JSON.stringify(seen[seen.length - 1]?.invalidReason));

console.log("\n== legacy v1 wire: the header the Glimind router tells buyers to send ==");
// A v1 X-PAYMENT payload carries the SAME EIP-712 authorization + signature as v2; only the envelope
// differs. This is what an X-PAYMENT-following buyer actually puts on the wire.
const v1 = (p, over = {}) => Buffer.from(JSON.stringify({
  x402Version: 1, scheme: "exact", network: "base",
  payload: {
    authorization: { ...p.payload.authorization, ...(over.authorization ?? {}) },
    signature: p.payload.signature,
  },
  ...(over.top ?? {}),
})).toString("base64");
const seenBeforeV1 = seen.length;

const v1Price = await fetch(priceUrl, { headers: { "x-payment": v1(payload) } });
const v1PriceJson = await v1Price.json().catch(() => ({}));
console.log(`v1 X-PAYMENT GET /price -> ${v1Price.status} ${JSON.stringify(v1PriceJson).slice(0, 120)}`);
check("v1 payment on /price -> 200", v1Price.status === 200, String(v1Price.status));
check("v1 payment gets live data, not an error", Number(v1PriceJson.priceUsd ?? 0) > 0, JSON.stringify(v1PriceJson).slice(0, 120));
check("v1 payment settles (PAYMENT-RESPONSE echoed)", !!v1Price.headers.get("payment-response"), String(v1Price.headers.get("payment-response")));
const v1Verify = seen.slice(seenBeforeV1).find((s) => s.path.endsWith("/verify"));
check("v1 payment went through facilitator /verify (not a bypass)", !!v1Verify, JSON.stringify(seen.slice(-3).map((s) => s.path)));
check("v1 /verify recovered the real buyer from the signature",
  String(v1Verify?.recoveredPayer ?? "").toLowerCase() === account.address.toLowerCase(), String(v1Verify?.recoveredPayer));
// The bridge must hand the facilitator the terms OUR server published, never terms the client claimed.
const v1Req = v1Verify?.body?.paymentRequirements ?? {};
check("v1 verify saw server-published terms (CAIP-2 network + data-tier amount + our payTo)",
  v1Req.network === "eip155:8453"
    && String(v1Req.amount) === String(payload.accepted.amount)
    && String(v1Req.payTo).toLowerCase() === "0x7c8a3c26bd579c5176a29a5a8ae80536319fa94b",
  JSON.stringify({ network: v1Req.network, amount: v1Req.amount, payTo: v1Req.payTo }));

// Per-route terms: /audit costs PRICE and /price costs PRICE_DATA, so the acceptance the bridge injects
// must belong to the route being called — otherwise a data-priced signature would buy an audit.
const v1Audit = await fetch(base + "/audit", {
  method: "POST", headers: { "content-type": "application/json", "x-payment": v1(audit.payload) }, body: auditBody,
});
const v1AuditJson = await v1Audit.json().catch(() => ({}));
console.log(`v1 X-PAYMENT POST /audit -> ${v1Audit.status} findings=${v1AuditJson.findings?.length}`);
check("v1 payment on /audit -> 200 with findings", v1Audit.status === 200 && Array.isArray(v1AuditJson.findings), String(v1Audit.status));
check("the two tiers really differ (audit != data price)",
  String(audit.payload.accepted.amount) !== String(payload.accepted.amount),
  `${audit.payload.accepted.amount} vs ${payload.accepted.amount}`);
const eip = await fetch(priceUrl, { headers: { "x-payment": v1(payload, { top: { network: "eip155:8453" } }) } });
check("v1 with the CAIP-2 network name also works", eip.status === 200, String(eip.status));

// The bridge is a shape mapper, not a trust grant: anything that does not match OUR published terms for
// that exact route keeps failing, and no client-supplied requirement is ever believed.
const wrongPayee = await fetch(priceUrl, {
  headers: { "x-payment": v1(payload, { authorization: { to: "0x1111111111111111111111111111111111111111" } }) },
});
check("v1 paying a DIFFERENT wallet -> 402", wrongPayee.status === 402, String(wrongPayee.status));
check("v1 paying a different wallet never settles", !wrongPayee.headers.get("payment-response"), String(wrongPayee.headers.get("payment-response")));
const underPay = await fetch(priceUrl, {
  headers: { "x-payment": v1(payload, { authorization: { value: String(BigInt(payload.accepted.amount) - 1n) } }) },
});
check("v1 under-paying -> 402", underPay.status === 402, String(underPay.status));
const crossRoute = await fetch(base + "/audit", {
  method: "POST", headers: { "content-type": "application/json", "x-payment": v1(payload) }, body: auditBody,
});
check("v1 /price signature on /audit -> 402 (no cross-route downgrade)", crossRoute.status === 402, String(crossRoute.status));
const badScheme = await fetch(priceUrl, {
  headers: { "x-payment": Buffer.from(JSON.stringify({ x402Version: 1, scheme: "upto", network: "base", payload: payload.payload })).toString("base64") },
});
check("v1 with an unsupported scheme -> 402", badScheme.status === 402, String(badScheme.status));
const garbage = await fetch(priceUrl, { headers: { "x-payment": "not-even-base64{{{" } });
check("garbage X-PAYMENT -> 402, never 500", garbage.status === 402, String(garbage.status));
const bothHeaders = await fetch(priceUrl, { headers: { ...http.encodePaymentSignatureHeader(payload), "x-payment": v1(payload, { authorization: { to: "0x1111111111111111111111111111111111111111" } }) } });
check("a real v2 header wins: a hostile X-PAYMENT cannot shadow it", bothHeaders.status === 200, String(bothHeaders.status));

child.kill();
mock.close();
if (fails.length) { console.log(`\nROUNDTRIP FAIL (${fails.length}): ${fails.join(", ")}`); process.exit(1); }
console.log("\nROUNDTRIP OK — a verified payment is served real data, with the indexing fields present");
process.exit(0);
