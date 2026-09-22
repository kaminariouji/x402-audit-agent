// Does the only rail whose payments payai can even parse (Solana v2) have somewhere to LAND?
// The official x402 SVM client (node_modules/@x402/svm/dist/esm/chunk-FKOM6YTW.mjs:74-90) builds a bare
// getTransferCheckedInstruction and only DERIVES destinationATA = findAssociatedTokenPda(payTo); it never
// issues createAssociatedTokenAccountIdempotentInstruction. So a seller with no USDC ATA makes EVERY buyer's
// transaction fail simulation at account index 2 (source, mint, DESTINATION, authority) — the exact error
// recorded against payai. Existence is asked from the RPC itself (getTokenAccountsByOwner), not from our math.
// Run: node sol-receive-probe.mjs
import fs from "node:fs";
import { address } from "@solana/kit";
import { findAssociatedTokenPda } from "@solana-program/token-2022";
import { TOKEN_PROGRAM_ADDRESS } from "@solana-program/token";

const RPCS = ["https://api.mainnet-beta.solana.com", "https://solana-rpc.publicnode.com"];
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
async function rpc(method, params) {
  const errs = [];
  for (const url of RPCS) {
    try {
      const r = await (await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) })).json();
      if (!r.error) return r.result;
      errs.push(`${new URL(url).host}:${r.error.code ?? r.error.message}`);
    } catch (e) { errs.push(`${new URL(url).host}:${e.message}`); }
  }
  throw new Error(`${method} failed on all RPCs (${errs.join(" ")})`);
}

const payTo = JSON.parse(fs.readFileSync(new URL("../../wallet/wallet-address.json", import.meta.url), "utf8")).solanaAddress;
console.log("payTo in our SVM acceptances:", payTo);

// Authoritative: the node's own index of token accounts for this owner+mint.
const owned = await rpc("getTokenAccountsByOwner", [payTo, { mint: USDC }, { encoding: "jsonParsed" }]);
const hasAta = (owned.value?.length ?? 0) > 0;
console.log(`RPC getTokenAccountsByOwner(payTo, USDC) -> ${owned.value?.length} account(s)`);

// Informational: the address a buyer's client is forced to target, derived with the same helper the SDK uses.
// The verdict above does not depend on this line — getTokenAccountsByOwner is the node's own index of the
// owner's USDC accounts, so a wrong derivation here could not create a false "missing".
const [kitAta] = await findAssociatedTokenPda({ mint: address(USDC), owner: address(payTo), tokenProgram: TOKEN_PROGRAM_ADDRESS });
console.log("expected destination ATA (kit):", kitAta);

const bal = await rpc("getBalance", [payTo]);
const rentMin = await rpc("getMinimumBalanceForRentExemption", [165]);
console.log(`payTo lamports: ${bal.value}  | measured rent-exempt minimum for a 165-byte token account: ${rentMin} lamports`);

// Reading this output correctly (2026-09-23): a missing ATA is NOT a capital blocker for us. Measured on
// two live Solana x402 settlements (.tmp-check/sol-ata-creation-tx.mjs) the PAYER's transaction contained
// spl-associated-token-account create + transferChecked, source = payer, so the rent was funded by the
// buyer and the seller signed nothing. It only means buyers on the create-less reference client fail.
console.log(hasAta
  ? "\n=> ATA exists: every SVM buyer can settle, including the reference @x402/svm client."
  : `\n=> No ATA yet. Costs us $0 (payers can create it inside their own settlement tx — measured). Consequence: a buyer using @x402/svm's ExactSvmScheme, which never issues createAssociatedTokenAccountIdempotent, will fail simulation against ${kitAta} until the first create-capable payment lands.`);
