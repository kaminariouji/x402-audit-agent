// Offline test of the CROO provider worker's decision path. No network, no key:
// a fake AgentClient records what the worker would have done to the marketplace.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const LEDGER = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "croo-selftest-")), "orders.jsonl");
process.env.CROO_AGENT_ID = "ag_provider_me";
process.env.CROO_LEDGER = LEDGER;

const { parseRequirements, buildReport } = await import("./fulfil.mjs");
const { onNegotiation, onOrderPaid } = await import("./worker.mjs");

let fails = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  [${detail}]` : ""}`);
  if (!ok) fails += 1;
};

const BAD_CODE = `async function farm(wallet) {
  const bal = await provider.getBalance(wallet.address);
  let total_usd = 0;
  for (const job of wallet.jobs) {
    claimJob(job);
    totalClaims++;
    total_usd += job.payout;
  }
  return total_usd;
}
`;
const CLEAN_CODE = `const add = (a, b) => a + b;\nmodule.exports = { add };\n`;

check("multi-line plain text counts as code", parseRequirements(BAD_CODE)?.text.length > 100);
check("JSON {code} is unwrapped", parseRequirements(JSON.stringify({ code: "function a() { return 1; }\nfunction b() {}\nlet x = a();" }))?.text.startsWith("function a()"));
check("JSON with a URL only is refused", parseRequirements(JSON.stringify({ url: "https://example.com" })) === null);
check("one line of prose is refused", parseRequirements("tell me something nice about my trading bot please friend") === null);
check("oversized input is refused", parseRequirements("a".repeat(2_100_000)) === null);

const dirty = buildReport(BAD_CODE);
check("report finds planted signals", /signals: [1-9]/.test(dirty), dirty.split("\n")[1]);
check("report names a rule", /\[[A-Z]+\] [A-Z_]+/.test(dirty));
check("report keeps the confirmation caveat", /human confirmation/.test(dirty));
check("clean code reports zero signals", /signals: 0/.test(buildReport(CLEAN_CODE)));

const fakeClient = (negotiation, order) => ({
  calls: [],
  async getNegotiation(id) { this.calls.push(["getNegotiation", id]); return negotiation; },
  async getOrder(id) { this.calls.push(["getOrder", id]); return order; },
  async acceptNegotiation(id) { this.calls.push(["acceptNegotiation", id]); return { order: { orderId: "or_1", price: "100000", paymentToken: "0x8335" } }; },
  async rejectNegotiation(id, reason) { this.calls.push(["rejectNegotiation", id, reason]); },
  async deliverOrder(id, req) { this.calls.push(["deliverOrder", id, req.deliverableType, req.deliverableText.length]); return { txHash: "0xdeliver" }; },
});
const names = (c) => c.calls.map((x) => x[0]).join(",");

const other = fakeClient({ negotiationId: "ng_2", providerAgentId: "ag_someone_else", requirements: BAD_CODE });
await onNegotiation(other, "ng_2");
check("another provider's negotiation is left alone", names(other) === "getNegotiation", names(other));

const unsellable = fakeClient({ negotiationId: "ng_3", providerAgentId: "ag_provider_me", requirements: "tell me something nice" });
await onNegotiation(unsellable, "ng_3");
check("non-code request is rejected, never accepted", names(unsellable) === "getNegotiation,rejectNegotiation", names(unsellable));

const scannable = fakeClient({ negotiationId: "ng_4", providerAgentId: "ag_provider_me", requirements: BAD_CODE });
await onNegotiation(scannable, "ng_4");
check("code request is accepted", names(scannable) === "getNegotiation,acceptNegotiation", names(scannable));

const unpaid = fakeClient({ negotiationId: "ng_4", requirements: BAD_CODE }, { orderId: "or_1", negotiationId: "ng_4", status: "created", payTxHash: "", price: "100000" });
await onOrderPaid(unpaid, "or_1");
check("UNPAID order is never delivered", !names(unpaid).includes("deliverOrder"), names(unpaid));

const paid = fakeClient({ negotiationId: "ng_4", requirements: BAD_CODE }, { orderId: "or_1", negotiationId: "ng_4", status: "paid", payTxHash: "0xpay", price: "100000", paymentToken: "0x8335", providerWalletAddress: "0xAA" });
await onOrderPaid(paid, "or_1");
check("PAID order is delivered once", names(paid).split("deliverOrder").length === 2, names(paid));

const rows = fs.existsSync(LEDGER) ? fs.readFileSync(LEDGER, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : [];
const delivered = rows.find((r) => r.type === "delivered");
check("ledger records the settled order", !!delivered && delivered.usd === "0.1000", JSON.stringify(delivered || {}));
check("ledger records the pay tx for auditing", delivered?.payTxHash === "0xpay");
check("ledger refused-unpaid row exists", rows.some((r) => r.type === "refused-unpaid"));

check("no ledger line contains a key-like string", !/croo_sk_/.test(fs.readFileSync(LEDGER, "utf8")));

console.log(fails ? `\nSELFTEST FAILED (${fails})` : "\nSELFTEST OK");
process.exit(fails ? 1 : 0);
