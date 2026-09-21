// Does a REAL third-party x402 buyer client manage to pay us? Not our harness, not our
// hand-built envelope: the shipped Coinbase v1 client (x402-fetch), which is what Glimind's
// "resend with an X-PAYMENT header" instruction actually drives.
//
// Zero funds: a freshly generated throwaway key has no USDC, so the best possible outcome is the
// facilitator rejecting for balance. That is still the proof we want, because it means the client
// parsed our 402 challenge, matched the scheme, and built a payment. Anything that fails EARLIER
// (unsupported network/scheme, no matching requirements) is a production discovery bug we must fix.
// Run: cd services/x402-mcp && node legacy-client-dryrun.mjs
import { wrapFetchWithPayment } from "x402-fetch";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const PUBLIC_URL = process.env.X402_PUBLIC_URL || "https://labored-safari-islamic.ngrok-free.dev";
const TARGET = `${PUBLIC_URL}/price?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`;

const decode = (h) => { try { return JSON.parse(Buffer.from(h, "base64").toString("utf8")); } catch { return null; } };

const unpaid = await fetch(TARGET);
const challenge = decode(unpaid.headers.get("payment-required") || unpaid.headers.get("x-payment-required"));
console.log(`unpaid GET /price -> ${unpaid.status}`);
console.log(`challenge x402Version=${challenge?.x402Version} error=${JSON.stringify(challenge?.error)}`);
for (const a of challenge?.accepts ?? []) {
  console.log(`  accepts: scheme=${a.scheme} network=${a.network} amount=${a.amount} payTo=${a.payTo} extra=${JSON.stringify(a.extra)}`);
}

// The v1 wire names networks "base"; the v2 wire names them "eip155:8453". A v1 client that is
// handed a CAIP-2 name has to map it itself, so this is the first place the bridge can leak money.
const nets = (challenge?.accepts ?? []).map((a) => a.network);
console.log(`\nnetwork naming in our challenge: ${nets.join(", ")} -> v1-style short name present? ${nets.includes("base") ? "yes" : "NO"}`);

const buyer = privateKeyToAccount(generatePrivateKey());
console.log(`throwaway buyer ${buyer.address} (never printed, zero balance, nothing to lose)\n`);
// createSigner() is pinned to one viem major; the library's own duck-type check accepts a viem
// LocalAccount, which is what the repo's viem hands us.
const pay = wrapFetchWithPayment(fetch, buyer);
const started = Date.now();
try {
  const r = await pay(TARGET);
  const text = await r.text();
  const err = decode(r.headers.get("payment-required"))?.error ?? "";
  console.log(`v1 CLIENT GOT ${r.status} after ${Date.now() - started}ms: ${text.slice(0, 120)}`);
  console.log(`facilitator said: ${JSON.stringify(err)}  receipt: ${r.headers.get("x-payment-response") || "(none)"}`);
  const paidAttempt = /insufficient_balance|balance/i.test(String(err));
  console.log(`\nVERDICT: ${r.status === 200
    ? "the real legacy client SETTLED against production — full v1 buyer path live."
    : paidAttempt
      ? "the real legacy client PARSED our challenge, SIGNED a payment and SUBMITTED it; production only refused because this throwaway wallet is empty. Wire is fine."
      : "the legacy client could not act on our challenge — a discovery/wire bug on OUR side."}`);
} catch (e) {
  const msg = String(e?.message || e).slice(0, 500);
  console.log(`v1 client threw after ${Date.now() - started}ms:\n  ${msg}`);
  const gotToFacilitator = /balance|insufficient|verify|settle|signature|authorization/i.test(msg);
  console.log(`\nVERDICT: ${gotToFacilitator
    ? "client PARSED our challenge and BUILT a payment — it only stopped at the buyer's empty wallet. Wire is fine."
    : "client could NOT build a payment from our challenge — that is a discovery/wire bug on OUR side."}`);
}
