// CROO (agent.croo.network) provider worker: sells the honesty scanner into the one
// agent marketplace whose per-call payments were verified on-chain (CAPVault
// 0x33ecdcc8...170d took 94 x $0.10 from 92 distinct ERC-4337 wallets in 40 min).
// Escrow is on-chain, so delivery must never happen before payTxHash exists.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AgentClient, EventType, DeliverableType } from "@croo-network/sdk";
import { parseRequirements, buildReport } from "./fulfil.mjs";

const API_URL = process.env.CROO_API_URL || "https://api.croo.network";
const WS_URL = process.env.CROO_WS_URL || "wss://api.croo.network/ws";
const AGENT_ID = process.env.CROO_AGENT_ID || "";
const LEDGER = process.env.CROO_LEDGER || path.join(path.dirname(fileURLToPath(import.meta.url)), "orders.jsonl");
const MAX_DELIVERY_CHARS = Number(process.env.CROO_MAX_DELIVERY || 60_000);

export const log = (...a) => console.log(`[${new Date().toISOString()}]`, ...a);
const usd = (price) => (Number(price || 0) / 1e6).toFixed(4);

function readKey() {
  const fromFile = process.env.CROO_SDK_KEY_FILE ? fs.readFileSync(process.env.CROO_SDK_KEY_FILE, "utf8").trim() : "";
  const key = process.env.CROO_SDK_KEY || fromFile;
  if (!key) throw new Error("set CROO_SDK_KEY (or CROO_SDK_KEY_FILE=/path/to/key) from the CROO dashboard; the key is never logged");
  return key;
}

function record(row) {
  try {
    fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), ...row }) + "\n");
  } catch (e) {
    log("ledger write failed:", e.message);
  }
}

export async function onNegotiation(client, negotiationId) {
  const n = await client.getNegotiation(negotiationId);
  if (AGENT_ID && n.providerAgentId && n.providerAgentId !== AGENT_ID) {
    return log(`skip negotiation ${negotiationId}: provider ${n.providerAgentId} is not us`);
  }
  const req = parseRequirements(n.requirements);
  if (!req) {
    await client.rejectNegotiation(
      negotiationId,
      'This service statically scans submitted source code for earnings-honesty signals. Send the code as plain text or as JSON {"code": "..."}.'
    );
    record({ type: "rejected", negotiationId });
    return log(`rejected ${negotiationId}: requirements contain no scannable code`);
  }
  const { order } = await client.acceptNegotiation(negotiationId);
  record({ type: "accepted", negotiationId, orderId: order.orderId, price: order.price, usd: usd(order.price), paymentToken: order.paymentToken });
  log(`accepted ${order.orderId} ($${usd(order.price)}) — waiting for escrow payment`);
}

export async function onOrderPaid(client, orderId) {
  const o = await client.getOrder(orderId);
  if (!o.payTxHash) {
    record({ type: "refused-unpaid", orderId, status: o.status });
    return log(`REFUSED to deliver ${orderId}: no payTxHash, escrow not confirmed`);
  }
  const n = await client.getNegotiation(o.negotiationId);
  const req = parseRequirements(n.requirements);
  const report = req
    ? buildReport(req.text)
    : "No scannable source was supplied with this order, so nothing was analysed. The escrow is not being held against a result.";
  const deliverableText = report.length > MAX_DELIVERY_CHARS ? `${report.slice(0, MAX_DELIVERY_CHARS)}\n… truncated` : report;
  const res = await client.deliverOrder(orderId, { deliverableType: DeliverableType.Text, deliverableText });
  record({
    type: "delivered",
    orderId,
    price: o.price,
    usd: usd(o.price),
    paymentToken: o.paymentToken,
    payTxHash: o.payTxHash,
    deliverTxHash: res?.txHash || "",
    providerWalletAddress: o.providerWalletAddress,
    chars: deliverableText.length,
  });
  log(`*** PAID ORDER DELIVERED ${orderId} $${usd(o.price)} payTx=${o.payTxHash} ***`);
}

export async function main() {
  const client = new AgentClient({ baseURL: API_URL, wsURL: WS_URL }, readKey());
  const stream = await client.connectWebSocket();
  log(`connected to CROO provider API${AGENT_ID ? ` as agent ${AGENT_ID}` : " (CROO_AGENT_ID unset: accepting every pending negotiation this key owns)"}`);

  const guard = (fn, label) => (e) =>
    fn(client, e.negotiation_id || e.order_id).catch((err) => log(`${label} failed:`, err.message));

  stream.on(EventType.NegotiationCreated, guard(onNegotiation, "negotiation"));
  stream.on(EventType.OrderPaid, guard(onOrderPaid, "delivery"));
  for (const [type, name] of [
    [EventType.NegotiationRejected, "negotiation_rejected"],
    [EventType.NegotiationExpired, "negotiation_expired"],
    [EventType.OrderCompleted, "order_completed"],
    [EventType.OrderRejected, "order_rejected"],
    [EventType.OrderExpired, "order_expired"],
  ]) {
    stream.on(type, (e) => {
      record({ type: name, orderId: e.order_id || "", negotiationId: e.negotiation_id || "", reason: e.reason || "" });
      log(`${name} ${e.order_id || e.negotiation_id || ""}`);
    });
  }

  // Negotiations that arrived while this process was down still need an answer.
  const pending = await client.listNegotiations({ status: "pending", role: "provider" }).catch((err) => {
    log("catch-up list failed:", err.message);
    return [];
  });
  for (const n of pending) onNegotiation(client, n.negotiationId).catch((err) => log("catch-up failed:", err.message));
  if (pending.length) log(`replayed ${pending.length} pending negotiation(s)`);
  return stream;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    log("fatal:", e.message);
    process.exit(1);
  });
}
