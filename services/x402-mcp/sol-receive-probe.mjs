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
console.log(`payTo lamports: ${bal.value} (rent for one ATA = 2039280 lamports = 0.00203928 SOL)`);

console.log(hasAta
  ? "\n=> OK: the Solana destination account exists; the rail can settle once a buyer pays."
  : `\n=> BLOCKER: our Solana payTo has no USDC token account and ${bal.value} lamports, so every buyer's x402 Solana payment dies at transferChecked index 2. This is OUR account, not the facilitator: fixing it costs 0.00203928 SOL of one-time ATA rent, which zero-capital cannot pay. Until then the SVM acceptance must not lead accepts[0].`);
process.exit(hasAta ? 0 : 1);
