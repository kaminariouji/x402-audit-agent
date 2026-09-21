// Is payai's broken EIP-3009 check specific to Base, or every EVM chain it claims to support?
// Why this matters more than any other open question: the facilitator is OUR config, not the buyer's,
// so if payai verifies ANY mainnet EVM chain correctly we can publish that acceptance and a real buyer
// settles with zero capital and zero user action. EVM addresses also need no ATA, unlike Solana, where
// our payTo has no funded token account (sol-receive-probe.mjs) and no keyless alternative exists.
// Method: take the acceptance our own server publishes as a shape template, swap in each chain's real
// native-USDC contract + chainId, build the payment with the official ExactEvmScheme, and ask payai
// /verify. Only the reason for refusal discriminates:
//   invalid_exact_evm_signature -> the verifier cannot do EIP-3009 on that chain at all
//   anything else (balance/simulation/invalid signer) -> the SIGNATURE PASSED, the rail is usable
// Nothing settles: /verify is read-only, the payer is a zero-balance anvil key.
// Run: cd services/x402-mcp && node evm-chains-verify.mjs [origin]
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";

const ORIGIN = process.argv[2] || "http://127.0.0.1:10000";
const FACILITATOR = "https://facilitator.payai.network";
// A fresh zero-balance key per run: proves the refusal is not an artifact of one particular signer.
const account = privateKeyToAccount(generatePrivateKey());

// Circle's native USDC per chain (not the bridged variant).
const CHAINS = [
  { network: "eip155:8453", label: "Base", usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", rpc: "https://mainnet.base.org" },
  { network: "eip155:42161", label: "Arbitrum One", usdc: "0xaf88d065e77c8cC2239327F2832226C2DE4E0D1f", rpc: "https://arb1.arbitrum.io/rpc" },
  { network: "eip155:137", label: "Polygon PoS", usdc: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", rpc: "https://polygon-rpc.com" },
  { network: "eip155:43114", label: "Avalanche C", usdc: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c43a6E", rpc: "https://api.avax.network/ext/bc/C/rpc" },
];

// Real 402 terms from our own server = the authoritative field shape to clone per chain.
const ours = await fetch(ORIGIN + "/price?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
const terms0 = JSON.parse(Buffer.from(ours.headers.get("payment-required") || "{}", "base64").toString());
const template = (terms0.accepts || []).find((a) => String(a.network).includes("8453"));
if (!template) throw new Error("no Base acceptance on our own origin — is the container up?");
console.log("template acceptance:", JSON.stringify(template));

const supported = await fetch(`${FACILITATOR}/supported`).then((r) => r.json()).catch(() => null);
const kinds = new Set((supported?.kinds || []).filter((k) => k.x402Version === 2 && k.scheme === "exact").map((k) => k.network));
console.log("payai v2/exact networks:", [...kinds].join(", ") || "(unknown)");

const refused = [], skipped = [];
for (const c of CHAINS) {
  // Clone verbatim except network + asset, so the 8453 row reproduces the known refusal exactly.
  const req = { ...template, network: c.network, asset: c.usdc };
  const terms = { ...terms0, accepts: [req] };
  let verdict;
  try {
    const client = new x402Client(() => req);
    client.register(c.network, new ExactEvmScheme(account));
    const payload = await new x402HTTPClient(client).createPaymentPayload(terms);
    const res = await fetch(`${FACILITATOR}/verify`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ x402Version: 2, paymentPayload: payload, paymentRequirements: req }),
    });
    const text = await res.text();
    let j = null; try { j = JSON.parse(text); } catch {}
    verdict = `HTTP ${res.status} isValid=${j?.isValid ?? "-"} reason=${j?.invalidReason ?? text.slice(0, 100)}`;
  } catch (e) { verdict = "payload build threw: " + String(e.message || e).slice(0, 100); }
  const sigRefused = /invalid.*signature|signermismatch/i.test(verdict);
  if (sigRefused) refused.push(c.label); else if (/spendControls/i.test(verdict)) skipped.push(`${c.label} (client spendControls rejected the asset before the request: the SDK only defaults to its own asset list, so this chain is untested here)`);
  console.log(`${c.label.padEnd(14)} ${c.network.padEnd(14)} supported=${kinds.has(c.network) ? "yes" : "NO "} -> ${verdict}   ${sigRefused ? "(SIGNATURE REFUSED)" : "(signature path not reached/refused)"}`);
}

console.log(`\n=== payai refused a correct EIP-3009 signature on: ${refused.join(", ") || "nothing"} ===`);
for (const s of skipped) console.log("   not reached: " + s);
console.log(refused.length > 1
  ? "=> EIP-3009 verification is broken on payai for more than one chain, so there is no keyless EVM rail to migrate onto. Only a different facilitator (e.g. a free CDP key) or Solana-with-a-funded-ATA can settle."
  : "=> only one chain refused: re-test it, a working EVM chain on payai would need no facilitator change.");
