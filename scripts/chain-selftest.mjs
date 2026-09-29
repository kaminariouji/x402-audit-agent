// Chain-state route selftest: proves every /chain/* handler returns REAL on-chain data (correct ABI
// selectors and decoders), that every published chain answers, and that the payment gate still owns
// every one of them. Run: node .tmp-check/chain-selftest.mjs
// The port MUST be pinned before server.mjs evaluates: importing it statically would bind the host to
// 10000 and silently take over the origin ngrok publishes.
process.env.PORT ??= "10997";
import fs from "node:fs";
const { CHAIN_ROUTES, DATA_ROUTES, PAYABLE_ROUTES, CHAINS, parseChainArgs, chainResult, HttpError,
  SEL, TOPIC, SEL2, SLOT1967, IFACE, KNOWN_SELECTOR, blockReceipts, RECEIPT_FALLBACK_CAP } =
  await import("../services/x402-mcp/server.mjs");

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // Base mainnet USDC
// Our own wallet: an address with no bytecode, so every "is there a contract here?" control has a real
// negative, and a position we can read honestly (it is the payee, so a zero is a fact about it).
const EOA = "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b";
const BAYC = "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d"; // Ethereum mainnet ERC-721
const ERC721_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ADDR_RE = /^0x[a-fA-F0-9]{40}$/;
const WORD_RE = /^0x[0-9a-fA-F]{64}$/;
const base = `http://127.0.0.1:${process.env.PORT}`;

const fails = [];
function check(name, cond, detail) {
  if (cond) console.log(`  ok   ${name}`);
  else { fails.push(name); console.log(`  FAIL ${name} :: ${String(detail).slice(0, 300)}`); }
}

// Per-route expectations: a live fact each handler must produce. These are the positive controls —
// without them a broken decoder that returns null everywhere would still "run without throwing".
const HEAD = { base: await fetch("https://mainnet.base.org", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }) }).then((r) => r.json()).then((j) => Number(BigInt(j.result))) };
console.log(`live Base head = ${HEAD.base}`);
let sampleTx = null;
for (let back = 0; back < 6 && !sampleTx; back++) {
  const b = await fetch("https://mainnet.base.org", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBlockByNumber", params: [`0x${(HEAD.base - back).toString(16)}`, false] }) }).then((r) => r.json());
  sampleTx = b?.result?.transactions?.[0] ?? null;
}
console.log(`sample Base tx = ${sampleTx || "(none found)"}`);

// A BAYC holder and a minted id, read straight from an event log by RAW fetch — deliberately NOT through
// our own handlers, so the NFT assertions cannot be circular. My first run of this file had a BAYC
// address ending f131 from memory: every "0 owner / not ERC-721" answer was correct and the TEST was
// wrong, which is exactly how a broken decoder hides. Chain-sourced fixtures end that failure mode.
const rpcRaw = async (url, method, params) => (await fetch(url, { method: "POST",
  headers: { "content-type": "application/json", accept: "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) }).then((r) => r.json()));
const ETH_RPC = CHAINS.ethereum.rpcs[0];
const ethHead = Number(BigInt((await rpcRaw(ETH_RPC, "eth_blockNumber", [])).result));
let bayc = { holder: null, tokenId: null, fromBlock: 0 };
for (let w = 0; w < 6 && !bayc.holder; w++) {
  const to = ethHead - w * 999, from = to - 998;
  const j = await rpcRaw(ETH_RPC, "eth_getLogs", [{ address: BAYC, topics: [ERC721_TRANSFER],
    fromBlock: `0x${from.toString(16)}`, toBlock: `0x${to.toString(16)}` }]);
  // Take the NEWEST transfer: its recipient is the one most likely to still hold the id, which is what
  // /chain/nft-balance then asserts.
  const l = (j.result || []).filter((x) => (x.topics || []).length === 4).pop();
  // ERC-721 Transfer is (from, to, tokenId) — topics[2] is the recipient and topics[3] the id. Reading
  // them the other way round was my own first-run bug: it produced a 50-digit "tokenId" and an
  // all-zero "holder", and every NFT route then looked broken.
  if (l) bayc = { holder: `0x${l.topics[2].slice(-40)}`, tokenId: String(BigInt(l.topics[3])), fromBlock: from };
}
console.log(`ethereum head = ${ethHead}; BAYC fixture from chain logs = ${bayc.holder ? `${bayc.holder} id ${bayc.tokenId}` : "(none found)"}`);

// Same discipline for the second band: every "this route returned real state" assertion needs a fixture
// the chain itself provided, read by RAW fetch. A zero from balanceOf is only evidence when some address
// provably holds money goes through the same code path and does not read zero.
const ERC20_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ERC721_APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";
const BASE_RPC = "https://mainnet.base.org";

// a Base USDC holder whose balance is proven non-zero by an independent raw balanceOf
// Three RPC hosts and six block windows, because a free endpoint answering null on eth_getLogs is a READ
// failure, not a chain with no holders: when this loop came up empty the wallet-holder assertions fell
// back to the USDC contract itself (which legitimately holds none of itself) and printed a route FAIL
// that was really an unreadable fixture. Threshold is 1 USDC, not 1000 — the requirement is "non-zero".
const HOLDER_RPCS = [BASE_RPC, "https://base.drpc.org", "https://base-rpc.publicnode.com"];
let usdcRich = null;
for (const host of HOLDER_RPCS) {
  for (let w = 0; w < 6 && !usdcRich; w++) {
    const to = HEAD.base - 1 - w * 150, from = to - 149;
    let ls = [];
    try {
      const j = await rpcRaw(host, "eth_getLogs", [{ address: USDC, topics: [ERC20_TRANSFER],
        fromBlock: `0x${from.toString(16)}`, toBlock: `0x${to.toString(16)}` }]);
      if (j.error) continue;
      ls = (j.result || []).filter((x) => (x.topics || []).length === 3).reverse();
    } catch { continue; }
    for (const l of ls) {
      const candidate = `0x${l.topics[2].slice(-40)}`;
      const r = await rpcRaw(host, "eth_call", [{ to: USDC, data: `0x70a08231${"0".repeat(24)}${l.topics[2].slice(-40)}` }, "latest"]);
      if (/^0x0*[^0]/.test(String(r.result || "")) && BigInt(r.result) > 10n ** 6n) { usdcRich = { address: candidate, raw: String(BigInt(r.result)), via: host }; break; }
    }
    if (usdcRich) break;
  }
  if (usdcRich) break;
}
console.log(`proven non-zero Base USDC holder = ${usdcRich ? `${usdcRich.address} (${usdcRich.raw}) via ${usdcRich.via}` : "(none found — holder-value assertions are NOT VERIFIED, not failed)"}`);
// A route is only as verified as the fixture that pins its numbers. When the holder probe cannot read a
// non-zero balance from ANY host, the value assertions for holder-shaped routes have nothing to compare
// against — and the choice is between reporting that honestly and reporting a route defect that does not
// exist. So those checks record themselves here; the summary prints them and exits 3 (not 0, not 1).
const NOT_VERIFIED = [];
const unverified = (path, why) => { NOT_VERIFIED.push(`${path}: ${why}`); return true; };

// Four storage words at a PINNED block, read raw, so /chain/storage-range is compared against the
// chain rather than against a guess at Circle's slot layout (slot 2 is not `decimals` here — an earlier
// version of this file asserted that and was wrong). Pinned block = no race with the head moving.
const SLOT_BLOCK = HEAD.base - 6;
const rawSlots = await Promise.all([0, 1, 2, 3].map((i) =>
  rpcRaw(BASE_RPC, "eth_getStorageAt", [USDC, `0x${(2 + i).toString(16).padStart(64, "0")}`,
    `0x${SLOT_BLOCK.toString(16)}`]).then((x) => x.result)));
console.log(`raw Base USDC slots 2..5 @ ${SLOT_BLOCK} = ${rawSlots.map((s) => String(s).slice(0, 18) + "…").join(" ")}`);

// a BAYC id whose getApproved is provably non-zero, confirmed by an INDEPENDENT raw eth_call: the
// Approval event alone is not enough, because a later transfer silently revokes it (and because
// "approved == 0x0" events are revocations, not grants).
let baycApproved = null;
{
  const words = [];
  for (let w = 0; w < 8 && !baycApproved; w++) {
    const to = ethHead - w * 400, from = to - 399;
    const j = await rpcRaw(ETH_RPC, "eth_getLogs", [{ address: BAYC, topics: [ERC721_APPROVAL],
      fromBlock: `0x${from.toString(16)}`, toBlock: `0x${to.toString(16)}` }]);
    words.push(...(j.result || []).filter((x) => (x.topics || []).length === 4).reverse());
    for (const l of words) {
      const tokenId = String(BigInt(l.topics[3]));
      const spender = `0x${l.topics[2].slice(-40)}`;
      if (spender === "0x0000000000000000000000000000000000000000") continue;
      const r = await rpcRaw(ETH_RPC, "eth_call", [{ to: BAYC,
        data: `0x081812fc${l.topics[3].slice(-64)}` }, "latest"]);
      const got = String(r.result || "");
      if (/^0x0{24}[0-9a-fA-F]{40}$/.test(got) && `0x${got.slice(-40)}`.toLowerCase() === spender.toLowerCase()) {
        baycApproved = { tokenId, approved: `0x${got.slice(-40)}`.toLowerCase() };
        break;
      }
    }
  }
}
console.log(`BAYC id with a live single-token approval = ${baycApproved ? `${baycApproved.tokenId} -> ${baycApproved.approved}` : "(none found)"}`);

// a (owner, operator) pair provably approved for ALL ids
let baycAll = null;
for (let w = 0; w < 8 && !baycAll; w++) {
  const to = ethHead - w * 400, from = to - 399;
  const j = await rpcRaw(ETH_RPC, "eth_getLogs", [{ address: BAYC, topics: [APPROVAL_FOR_ALL],
    fromBlock: `0x${from.toString(16)}`, toBlock: `0x${to.toString(16)}` }]);
  const l = (j.result || []).filter((x) => (x.topics || []).length === 3 && BigInt(x.data) > 0n).pop();
  if (l) baycAll = { owner: `0x${l.topics[1].slice(-40)}`, operator: `0x${l.topics[2].slice(-40)}` };
}
console.log(`BAYC setApprovalForAll(true) pair = ${baycAll ? `${baycAll.owner} / ${baycAll.operator}` : "(none found)"}`);

// ================= third band (27 routes): measured fixtures + INDEPENDENT raw reads =================
// Every assertion below compares the paid route's answer to a raw RPC read made here, with a selector
// this file derives from its own ABI string. The whole band reads contract state through hand-built
// calldata (SEL2 / SLOT1967), and an index-off-by-one in that decode is indistinguishable from a valid
// answer — that is the exact failure that shipped a hand-typed getApproved selector. Fixtures come from
// .tmp-check/probe-chain-fixtures{6,7,8}.mjs, which are themselves raw-fetch chain probes; if one goes
// stale the comparison below fails loudly instead of quietly passing.
const FIX = JSON.parse(fs.readFileSync(new URL("./chain-fixtures2.json", import.meta.url), "utf8")).found;
const NEED_FIX = ["pinnedBlock", "proxy", "contractWithOwner", "pausedContract", "liveAllowance",
  "baycOwnerAtBlock", "twoDistinctContracts", "erc1155", "permitToken"];
const missingFix = NEED_FIX.filter((k) => !FIX[k]);
check("all nine measured chain fixtures are pinned", missingFix.length === 0,
  `missing: ${missingFix.join(",")} — re-run .tmp-check/probe-chain-fixtures8.mjs`);

const w64 = (v) => String(v).toLowerCase().replace(/^0x/, "").padStart(64, "0");
const hexN = (n) => `0x${BigInt(n).toString(16)}`;
const eqi = (a, b) => String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();
const dec = (hex) => (WORD_RE.test(String(hex || "")) ? String(BigInt(hex)) : null);
const ad = (hex) => (WORD_RE.test(String(hex || "")) ? `0x${String(hex).slice(-40)}` : null);
// sha256 of runtime bytecode, computed here rather than imported from the product's own helper.
const sha256Of = async (hexCode) => {
  const { createHash } = await import("node:crypto");
  return "0x" + createHash("sha256").update(Buffer.from(String(hexCode).slice(2), "hex")).digest("hex");
};
let kid = null;
try { kid = (await import("ethers")).id; } catch { /* the keccak section below reports this */ }
const selOf = (sig) => (kid ? "0x" + kid(sig).slice(2, 10) : null);
const slotMinus1 = (label) => (kid ? `0x${((BigInt(kid(label)) - 1n) % 2n ** 256n).toString(16).padStart(64, "0")}` : null);
const rpcQ = async (url, method, params) => { try { return (await rpcRaw(url, method, params)).result ?? null; } catch { return null; } };
const rpcCallOf = async (url, to, sig, words = [], blockTag = "latest") => {
  const data = selOf(sig); if (!data) return null;
  return rpcQ(url, "eth_call", [{ to, data: data + words.join("") }, blockTag]);
};

// What the node says, read twice: once through our handler (below) and once here. Null means the raw
// read failed, which the assertions treat as "cannot conclude", never as "the route is wrong".
const RAW = {};
if (!missingFix.length) {
  const PERMIT_RPC = FIX.permitToken.chain === "ethereum" ? ETH_RPC : BASE_RPC;
  const [codeA, codeB, pinTx0, receipt] = await Promise.all([
    rpcQ(BASE_RPC, "eth_getCode", [FIX.twoDistinctContracts.a, "latest"]),
    rpcQ(BASE_RPC, "eth_getCode", [FIX.twoDistinctContracts.b, "latest"]),
    rpcQ(BASE_RPC, "eth_getTransactionByBlockNumberAndIndex", [hexN(FIX.pinnedBlock.number), "0x0"]),
    sampleTx ? rpcQ(BASE_RPC, "eth_getTransactionReceipt", [sampleTx]) : null,
  ]);
  const diffBlockA = HEAD.base - 40;
  Object.assign(RAW, {
    owner: await rpcCallOf(BASE_RPC, FIX.contractWithOwner.address, "owner()"),
    paused: await rpcCallOf(BASE_RPC, FIX.pausedContract.address, "paused()"),
    allowance: await rpcCallOf(BASE_RPC, FIX.liveAllowance.token, "allowance(address,address)",
      [w64(FIX.liveAllowance.owner), w64(FIX.liveAllowance.spender)]),
    bal1155: await rpcCallOf(BASE_RPC, FIX.erc1155.token, "balanceOf(address,uint256)",
      [w64(FIX.erc1155.account), w64(FIX.erc1155.tokenId)]),
    // A second id on the same token, so balanceOfBatch's positional decoding can be proven: two equal
    // balances would pass even if rows[0] and rows[1] were swapped. Chosen below from whichever id the
    // contract answers differently — see ERC_ID_B.
    bal1155x1: await rpcCallOf(BASE_RPC, FIX.erc1155.token, "balanceOf(address,uint256)",
      [w64(FIX.erc1155.account), w64(1)]),
    bal1155x3: await rpcCallOf(BASE_RPC, FIX.erc1155.token, "balanceOf(address,uint256)",
      [w64(FIX.erc1155.account), w64(3)]),
    uri1155: await rpcCallOf(BASE_RPC, FIX.erc1155.token, "uri(uint256)", [w64(FIX.erc1155.tokenId)]),
    iface1155: await rpcCallOf(BASE_RPC, FIX.erc1155.token, "supportsInterface(bytes4)",
      [w64("0xd9b67a26").slice(0, 8) + "0".repeat(56)]),
    iface721: await rpcCallOf(BASE_RPC, FIX.erc1155.token, "supportsInterface(bytes4)",
      [w64("0x80ac58cd").slice(0, 8) + "0".repeat(56)]),
    domainSeparator: await rpcCallOf(PERMIT_RPC, FIX.permitToken.token, "DOMAIN_SEPARATOR()"),
    permitNonce: await rpcCallOf(PERMIT_RPC, FIX.permitToken.token, "nonces(address)", [w64(USDC)]),
    // Base USDC is the case the route got wrong and the case a relayer most needs right: its own
    // bytecode is a forwarding shim, so permit() is only findable in the implementation. Measured
    // 2026-09-24 its EIP-1967 slot is EMPTY — Circle's proxy predates the standard, so only
    // implementation() answers. Both conventions are read; the route must agree with whichever did.
    usdcDs: await rpcCallOf(BASE_RPC, USDC, "DOMAIN_SEPARATOR()"),
    usdcNonce: await rpcCallOf(BASE_RPC, USDC, "nonces(address)", [w64(EOA)]),
    usdcImplSlot: await rpcQ(BASE_RPC, "eth_getStorageAt", [USDC, slotMinus1("eip1967.proxy.implementation"), "latest"]),
    usdcImplCall: await rpcCallOf(BASE_RPC, USDC, "implementation()"),
    proxyImplSlot: await rpcQ(BASE_RPC, "eth_getStorageAt", [FIX.proxy.address, slotMinus1("eip1967.proxy.implementation"), "latest"]),
    proxyImplCall: await rpcCallOf(BASE_RPC, FIX.proxy.address, "implementation()"),
    txCount: await rpcQ(BASE_RPC, "eth_getBlockTransactionCountByNumber", [hexN(FIX.pinnedBlock.number)]),
    blockByHash: await rpcQ(BASE_RPC, "eth_getBlockByHash", [FIX.pinnedBlock.hash, false]),
    txAtIndex: pinTx0 ? pinTx0.hash : null,
    supplyAtPin: await rpcCallOf(BASE_RPC, USDC, "totalSupply()", [], hexN(FIX.pinnedBlock.number - 20)),
    slotA: await rpcQ(BASE_RPC, "eth_getStorageAt", [USDC, "0x2", hexN(diffBlockA)]),
    slotB: await rpcQ(BASE_RPC, "eth_getStorageAt", [USDC, "0x2", "latest"]),
    ownerOfThen: await rpcCallOf(ETH_RPC, BAYC, "ownerOf(uint256)", [w64(FIX.baycOwnerAtBlock.tokenId)], hexN(FIX.baycOwnerAtBlock.atBlock)),
    ownerOfNow: await rpcCallOf(ETH_RPC, BAYC, "ownerOf(uint256)", [w64(FIX.baycOwnerAtBlock.tokenId)]),
    baycBalanceRaw: await rpcCallOf(ETH_RPC, BAYC, "balanceOf(address)", [w64(bayc.holder || USDC)]),
    codeA: (codeA && codeA !== "0x") ? await sha256Of(codeA) : null,
    codeB: (codeB && codeB !== "0x") ? await sha256Of(codeB) : null,
    // The capabilities route is checked against the BYTECODE itself, not against a hand-picked list of
    // functions this token "probably" has — see the assertion, which derives the expected selector set
    // from keccak and looks each one up in the raw hex.
    codeHexB: codeB && codeB !== "0x" ? String(codeB).toLowerCase() : null,
    receiptLogs: receipt ? (receipt.logs || []).length : null,
    txBlock: receipt ? Number(BigInt(receipt.blockNumber)) : null,
  });
  // Two dependent reads, so they follow the batch: the implementation address, whichever convention this
  // proxy answers on, then whether THAT bytecode carries permit(). This is the exact fact the route
  // denied on 2026-09-24 — and denied even after its first fix, because the EIP-1967 slot is empty here.
  const slotAddrOf = (word) => (WORD_RE.test(String(word || "")) && !/^0x0+$/i.test(word) ? ad(word) : null);
  RAW.usdcImpl = slotAddrOf(RAW.usdcImplSlot) || slotAddrOf(RAW.usdcImplCall);
  RAW.usdcImplFrom = RAW.usdcImpl === slotAddrOf(RAW.usdcImplSlot) && slotAddrOf(RAW.usdcImplSlot) ? "slot" : RAW.usdcImpl ? "call" : null;
  const usdcImplCode = RAW.usdcImpl ? await rpcQ(BASE_RPC, "eth_getCode", [RAW.usdcImpl, "latest"]) : null;
  RAW.usdcImplHasPermit = usdcImplCode && usdcImplCode !== "0x"
    ? String(usdcImplCode).toLowerCase().includes(SEL2.permit.slice(2).toLowerCase()) : null;
  console.log(`permit control: Base USDC implementation = ${RAW.usdcImpl || "(neither slot nor implementation() answered)"}, found via ${RAW.usdcImplFrom}, permit() in its code = ${RAW.usdcImplHasPermit}`);
  console.log(`independent raw reads for the third band: ${Object.entries(RAW).filter(([, v]) => v !== null && v !== undefined).length}/${Object.keys(RAW).length} answered`);
}
// A block tag comes back either as a hex quantity or as a word; compare them as numbers, because the
// routes echo what they sent the node (`0x315809d`) while the fixtures store decimals (51740829).
const blkNum = (x) => (/^0x[0-9a-f]+$/i.test(String(x)) ? Number(BigInt(String(x))) : /^\d+$/.test(String(x)) ? Number(x) : null);
// balanceOfBatch is positional, so the second id in the batch must be one whose balance DIFFERS from the
// first — two equal rows would also pass if the handler swapped the pairs or read its own length word
// as a balance. Picked from what the contract actually answers, never assumed.
const ERC_ID_B = [1, 3].find((id) => dec(RAW[`bal1155x${id}`]) !== null && dec(RAW[`bal1155x${id}`]) !== dec(RAW.bal1155)) ?? 1;
console.log(`batch pairing control: id ${FIX.erc1155?.tokenId} = ${dec(RAW.bal1155)}, second id = ${ERC_ID_B} = ${dec(RAW[`bal1155x${ERC_ID_B}`])}${String(ERC_ID_B) === "1" && dec(RAW.bal1155x1) === dec(RAW.bal1155) ? " (WEAK: same balance, rows not distinguishable)" : ""}`);

const QUERIES = {
  "/chain/block-number": { chain: "base" },

  "/chain/balance": { chain: "base", address: USDC },
  "/chain/balances": { chain: "base", addresses: `${USDC},0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b` },
  "/chain/nonce": { chain: "base", address: USDC },
  "/chain/code": { chain: "base", address: USDC },
  "/chain/block": { chain: "base", block: "latest" },
  "/chain/block-txids": { chain: "base", block: String(HEAD.base - 1) },
  "/chain/tx": { chain: "base", hash: sampleTx },
  "/chain/receipt": { chain: "base", hash: sampleTx },
  "/chain/logs": { chain: "base", address: USDC, fromBlock: String(HEAD.base - 200), toBlock: String(HEAD.base - 100) },
  "/chain/call": { chain: "base", to: USDC, data: "0x95d89b41" }, // symbol()
  "/chain/storage": { chain: "base", address: USDC, slot: "0x2" },
  "/chain/fee-data": { chain: "base" },
  "/chain/gas-estimate": { chain: "base", to: "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b", data: "0x" },
  "/chain/token-balance": { chain: "base", token: USDC, owner: "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b" },
  "/chain/token-meta": { chain: "base", token: USDC },
  "/chain/allowance": { chain: "base", token: USDC, owner: "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b", spender: "0x0000000000000000000000000000000000000000" },
  "/chain/nft-owner": { chain: "ethereum", token: BAYC, tokenId: bayc.tokenId },
  "/chain/nft-balance": { chain: "ethereum", token: BAYC, owner: bayc.holder },
  "/chain/nft-meta": { chain: "ethereum", token: BAYC },
  "/chain/contract-check": { chain: "ethereum", address: BAYC },
  "/chain/wallet-state": { chains: "base,ethereum", address: USDC },
  // ---- second band (14 routes added 2026-09-24) ----
  "/chain/heads": { chains: "base,ethereum" },
  "/chain/block-stats": { chain: "base", blocks: "20" },
  "/chain/block-receipts": { chain: "base", block: String(HEAD.base - 3) },
  "/chain/fee-history": { chain: "base", blocks: "20" },
  "/chain/storage-range": { chain: "base", address: USDC, fromSlot: "0x2", count: "4", blockTag: String(SLOT_BLOCK) },
  "/chain/multicall": { chain: "base", calls: `${USDC}:0x95d89b41,${USDC}:0x18160ddd` },
  "/chain/token-balances": { chain: "base", token: USDC,
    owners: `${usdcRich?.address || USDC},0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b` },
  "/chain/nft-token-uri": { chain: "ethereum", token: BAYC, tokenId: bayc.tokenId },
  "/chain/nft-approved": { chain: "ethereum", token: BAYC, tokenId: baycApproved?.tokenId || bayc.tokenId },
  "/chain/nft-approved-for-all": { chain: "ethereum", token: BAYC,
    owner: baycAll?.owner || bayc.holder, operator: baycAll?.operator || "0x0000000000000000000000000000000000000000" },
  "/chain/code-at": { chain: "base", address: USDC, block: String(HEAD.base - 1000) },
  "/chain/supply-at": { chain: "base", token: USDC, block: String(HEAD.base - 500) },
  "/chain/approvals-scan": { chain: "base", token: USDC, blocks: "25" },
  "/chain/transfers-scan": { chain: "base", token: USDC, blocks: "25" },
  // ---- third band (27 routes added for the 100-endpoint expansion) ----
  // Every query here is built from a fixture the chain supplied, so a null answer means the handler is
  // wrong, not that we asked for something that does not exist.
  "/chain/client-version": { chain: "base" },
  "/chain/network-id": { chain: "base" },
  "/chain/sync-status": { chain: "base" },
  "/chain/tx-count": { chain: "base", block: String(FIX.pinnedBlock?.number ?? HEAD.base - 1) },
  "/chain/block-by-hash": { chain: "base", blockHash: FIX.pinnedBlock?.hash ?? "0x" + "00".repeat(32) },
  "/chain/tx-at-index": { chain: "base", block: String(FIX.pinnedBlock?.number ?? HEAD.base - 1), index: "0" },
  "/chain/block-series": { chain: "base", blocks: "6" },
  "/chain/block-by-timestamp": { chain: "base", timestamp: String(FIX.pinnedBlock?.timestamp ?? 1758000000) },
  "/chain/contract-owner": { chain: "base", address: FIX.contractWithOwner?.address || USDC },
  "/chain/proxy-check": { chain: "base", address: FIX.proxy?.address || USDC },
  "/chain/paused-check": { chain: "base", address: FIX.pausedContract?.address || USDC },
  "/chain/permit-ready": { chain: "base", token: USDC, owner: EOA },
  "/chain/1155-balance": { chain: FIX.erc1155?.chain || "base", token: FIX.erc1155?.token || USDC,
    account: FIX.erc1155?.account || USDC, tokenId: String(FIX.erc1155?.tokenId ?? 0) },
  "/chain/1155-uri": { chain: FIX.erc1155?.chain || "base", token: FIX.erc1155?.token || USDC,
    tokenId: String(FIX.erc1155?.tokenId ?? 0) },
  "/chain/1155-batch": { chain: FIX.erc1155?.chain || "base", token: FIX.erc1155?.token || USDC,
    accounts: `${FIX.erc1155?.account || USDC},${FIX.erc1155?.account || USDC}`,
    tokenIds: `${FIX.erc1155?.tokenId ?? 0},${ERC_ID_B}` },
  "/chain/1155-check": { chain: FIX.erc1155?.chain || "base", token: FIX.erc1155?.token || USDC,
    tokenId: String(FIX.erc1155?.tokenId ?? 0) },
  "/chain/storage-diff": { chain: "base", address: USDC, slot: "0x2", blockA: String(HEAD.base - 40), blockB: "latest" },
  "/chain/token-meta-at": { chain: "base", token: USDC, block: String(FIX.pinnedBlock?.number != null ? FIX.pinnedBlock.number - 20 : HEAD.base - 20) },
  "/chain/nft-owner-at": { chain: "ethereum", token: BAYC, tokenId: String(FIX.baycOwnerAtBlock?.tokenId ?? bayc.tokenId ?? 1),
    block: String(FIX.baycOwnerAtBlock?.atBlock ?? ethHead - 5000) },
  "/chain/bytecode-fingerprint": { chain: "base", address: FIX.twoDistinctContracts?.a || USDC },
  // USDC on Base is an EIP-1967 proxy, so its own code carries only the upgrade-guard selectors. The
  // full-token control has to be a real token: DEGEN's deployed bytecode is what we scan, and the
  // assertion below derives the expected names from that same code rather than from a guess.
  "/chain/bytecode-capabilities": { chain: "base", address: FIX.twoDistinctContracts?.b || USDC, count: "60" },
  "/chain/contract-diff": { chain: "base", address: FIX.twoDistinctContracts?.a || USDC, other: FIX.twoDistinctContracts?.b || BAYC },
  "/chain/wallet-tokens": { chain: "base", owner: usdcRich?.address || USDC, tokens: USDC },
  "/chain/wallet-nfts": { chain: "ethereum", owner: bayc.holder || USDC, tokens: BAYC },
  "/chain/wallet-approvals": { chain: "base", owner: FIX.liveAllowance?.owner || USDC,
    spender: FIX.liveAllowance?.spender || "0x0000000000000000000000000000000000000000", tokens: USDC },
  "/chain/tx-status": { chain: "base", hash: sampleTx || "0x" + "11".repeat(32) },
  "/chain/tx-events": { chain: "base", hash: sampleTx || "0x" + "11".repeat(32) },
};
const ASSERT = {
  "/chain/block-number": (r) => r.blockNumber > 10_000_000 && r.chainId === 8453,
  "/chain/balance": (r) => /^\d+$/.test(String(r.wei)) && /^\d+\.\d{1,18}$/.test(String(r.balance)) && r.nativeSymbol === "ETH",
  "/chain/balances": (r) => r.rows?.length === 2 && r.rows.every((x) => ADDR_RE.test(x.address) && /^\d+$/.test(x.wei)),
  "/chain/nonce": (r) => Number.isInteger(r.nonce) && r.blockTag === "latest",
  "/chain/code": (r) => r.isContract === true && r.bytecodeSize > 1000,
  "/chain/block": (r) => r.block?.number > 10_000_000 && typeof r.block.baseFeeGwei === "number" && /^\d{4}-\d{2}-\d{2}T/.test(r.block.isoTime),
  // The route caps the array at 1000 and says so with truncated:true, so `count` is the FULL block
  // size — an earlier version asserted count === length and failed on a busy Base block (4311 txs).
  "/chain/block-txids": (r) => Array.isArray(r.transactionHashes) && r.transactionHashes.length > 0
    && r.transactionHashes.every((x) => WORD_RE.test(x)) && r.count >= r.transactionHashes.length
    && (r.truncated ? r.count > 1000 && r.transactionHashes.length === 1000 : r.count === r.transactionHashes.length),
  "/chain/tx": (r) => r.found === true && r.transaction?.hash === sampleTx && ADDR_RE.test(r.transaction.from) && Number.isInteger(r.transaction.nonce),
  "/chain/receipt": (r) => r.found === true && (r.status === 1 || r.status === 0) && Number.isInteger(r.confirmations) && r.confirmations >= 1 && /^\d+$/.test(String(r.gasUsed)),
  "/chain/logs": (r) => Array.isArray(r.rows) && r.range.toBlock - r.range.fromBlock === 100 && r.rows.every((l) => WORD_RE.test(l.topics?.[0] || "")),
  "/chain/call": (r) => r.reverted === false && r.asString === "USDC",
  "/chain/storage": (r) => WORD_RE.test(String(r.value)) && /^\d+$/.test(String(r.asUint)),
  "/chain/fee-data": (r) => r.gasPriceGwei > 0 && r.baseFeeGwei > 0 && /^\d+$/.test(r.nativeTransferCost.wei) && Number(r.nativeTransferCost.native) > 0,
  "/chain/gas-estimate": (r) => r.estimable === true && Number(r.gasEstimate) >= 21000 && Number(r.atSenderGas.wei) > 0,
  "/chain/token-balance": (r) => r.readable !== false && /^\d+$/.test(String(r.raw)) && r.decimals === 6 && r.symbol === "USDC",
  "/chain/token-meta": (r) => r.symbol === "USDC" && r.name === "USD Coin" && r.decimals === 6 && Number(r.totalSupply) > 1e9 && r.isContract === true,
  "/chain/allowance": (r) => r.readable !== false && /^\d+$/.test(String(r.raw)) && r.unlimitedApproval === false,
  "/chain/nft-owner": (r) => r.found === true && r.owner?.toLowerCase() === bayc.holder?.toLowerCase(),
  "/chain/nft-balance": (r) => r.readable !== false && Number.isInteger(r.balance) && r.balance >= 1,
  "/chain/nft-meta": (r) => r.symbol === "BAYC" && r.name === "BoredApeYachtClub" && r.supports?.ERC165 === true && r.supports?.ERC721 === true && r.supports?.ERC1155 === false,
  "/chain/contract-check": (r) => r.isContract === true && r.bytecodeSize > 1000 && r.supports?.ERC165 === true && r.supports?.ERC721 === true && r.supports?.ERC20 === false && r.supports?.ERC1155 === false,
  // Base USDC's address is a contract on Base but a plain EOA-shaped address on mainnet, so isContract
  // is asserted as "the node answered", not as a value copied between chains.
  "/chain/wallet-state": (r) => r.rows?.length === 2 && r.rows.every((x) => x.chainId && x.label && typeof x.isContract === "boolean"
    && Number.isInteger(x.nonce) && /^\d+$/.test(String(x.wei))),
  // ---- second band ----
  "/chain/heads": (r) => r.rows?.length === 2 && r.rows.every((x) => x.blockNumber > 1_000_000 && x.chainId
    && typeof x.baseFeeGwei === "number" && x.baseFeeGwei > 0 && /^\d+$/.test(x.gasUsed) && x.blockHash
    && Number.isInteger(x.ageSeconds) && x.ageSeconds < 600 && x.transactionsCount >= 0),
  "/chain/block-stats": (r) => r.windowBlocks > 0 && r.secondsPerBlock > 0 && r.secondsPerBlock < 60
    && Math.abs(r.blocksPerHour - 3600 / r.secondsPerBlock) < 5 && r.edges?.newest?.number > 1_000_000
    && r.fromBlock === r.edges.oldest.number && r.toBlock === r.edges.newest.number,
  "/chain/block-receipts": (r) => r.count > 0 && r.rows?.length > 0 && Number(r.totalGasUsed) > 0
    && r.rows.every((x) => WORD_RE.test(x.transactionHash) && ADDR_RE.test(x.from) && /^\d+$/.test(x.gasUsed))
    && r.successCount + r.failedCount <= r.count && /^\d+\.\d+$/.test(String(r.feesPaidNative)),
  "/chain/fee-history": (r) => r.blocksCovered >= 20 && r.baseFeeGwei?.last > 0 && r.baseFeeGwei.min <= r.baseFeeGwei.last
    && r.head - r.oldestBlock <= 25 && Array.isArray(r.perBlockBaseFeeGwei) && r.perBlockBaseFeeGwei.length > 1
    && ["p25", "p50", "p75"].every((k) => k in r.priorityFeeGwei) && r.gasUsedRatio.every((x) => x >= 0 && x <= 100),
  "/chain/storage-range": (r) => r.count === 4 && r.rows.length === 4 && r.blockTag === `0x${SLOT_BLOCK.toString(16)}`
    && r.rows.every((x, i) => WORD_RE.test(x.value) && Number(BigInt(x.slot)) === 2 + i
      && String(x.value).toLowerCase() === String(rawSlots[i]).toLowerCase())
    && new Set(r.rows.map((x) => x.value)).size >= 3,
  "/chain/multicall": (r) => r.requested === 2 && r.answered === 2 && r.rows[0].asString === "USDC"
    && r.rows[0].ok === true && r.rows[0].selector === "0x95d89b41" && r.rows[0].calldataSize === 4
    && Number(r.rows[1].asUint) > 1e9 && r.rows[1].returnSize === 32,
  "/chain/token-balances": (r) => r.requested === 2 && r.readableCount === 2 && r.decimals === 6 && r.symbol === "USDC"
    && r.rows.every((x) => x.readable === true && /^\d+$/.test(x.raw) && /^\d+\.\d+$/.test(x.formatted))
    && (!usdcRich || (r.rows[0].owner.toLowerCase() === usdcRich.address.toLowerCase() && BigInt(r.rows[0].raw) > 0n))
    // sumRaw is the route's own arithmetic, so it is checked against the rows it published rather than
    // against `usdcRich.raw` — that control read an earlier block of a live holder whose balance can go
    // DOWN, which made `sum >= control` a race instead of an assertion.
    && r.rows.every((x) => x.readable === true && /^\d+$/.test(String(x.raw)))
    && BigInt(r.sumRaw) === r.rows.reduce((a, x) => a + BigInt(x.raw), 0n),
  "/chain/nft-token-uri": (r) => r.found === true && !!r.tokenUri && r.length > 10 && r.fetchedByUs === false
    && r.isOnChainJson === false && r.scheme === "ipfs" && r.host === null,
  "/chain/nft-approved": (r) => baycApproved
    ? (r.readable === true && r.hasApproval === true && r.approved?.toLowerCase() === baycApproved.approved.toLowerCase())
    : (r.readable === true && r.hasApproval === false && r.approved === "0x0000000000000000000000000000000000000000"),
  "/chain/nft-approved-for-all": (r) => r.readable === true && typeof r.approved === "boolean"
    && (baycAll ? r.approved === true : r.approved === false),
  "/chain/code-at": (r) => r.existedAtBlock === true && r.isContractNow === true && r.bytecodeSize > 1000
    && r.latestBytecodeSize === r.bytecodeSize && r.changedSince === false && /^0x[0-9a-f]{4}/i.test(String(r.codePrefix))
    && r.blockNumber === HEAD.base - 1000,
  "/chain/supply-at": (r) => r.readable !== false && r.decimals === 6 && r.symbol === "USDC"
    && BigInt(r.latestRaw) > 10n ** 12n && /^\d+$/.test(r.atBlockRaw)
    && ["increased", "decreased", "unchanged"].includes(r.direction) && /^-?\d+$/.test(r.deltaRaw)
    && BigInt(r.deltaRaw) === BigInt(r.latestRaw) - BigInt(r.atBlockRaw)
    // changePct is the key the old BigInt division silently zeroed. The route's own two raw supplies
    // pin it, so a formula that rounds a real move to 0 fails here instead of shipping.
    && (BigInt(r.deltaRaw) === 0n ? r.changePct === 0 : r.changePct !== 0
      && Math.abs(r.changePct - (Number(BigInt(r.deltaRaw)) * 100) / Number(BigInt(r.atBlockRaw)))
        <= Math.max(1e-9, Math.abs(r.changePct) * 1e-6)),
  "/chain/approvals-scan": (r) => r.count >= 1 && r.rows.length >= 1 && r.range.toBlock > 1_000_000
    && r.range.toBlock - r.range.fromBlock === 24
    && r.rows.every((x) => ADDR_RE.test(x.owner) && ADDR_RE.test(x.spender) && /^\d+$/.test(x.amountRaw) && WORD_RE.test(x.transactionHash))
    // A decoder that returned 0x0 for every field would satisfy the shape checks above, so at least one
    // row must carry a real spender and a non-zero amount — i.e. the event actually decoded.
    && r.rows.some((x) => x.spender !== "0x0000000000000000000000000000000000000000" && BigInt(x.amountRaw) > 0n
      && x.owner !== x.spender),
  "/chain/transfers-scan": (r) => r.count >= 1 && r.rows.length >= 1 && r.decimals === 6
    && BigInt(r.sumRaw) > 0n && r.range.toBlock - r.range.fromBlock === 24
    && r.rows.every((x) => ADDR_RE.test(x.from) && ADDR_RE.test(x.to) && /^\d+\.\d{1,6}$/.test(x.amountFormatted))
    // Same reasoning as approvals-scan: prove the payload decoded, not just that the shape is right.
    && r.rows.some((x) => BigInt(x.amountRaw) > 0n && x.from !== x.to
      && x.amountFormatted === `${x.amountRaw.slice(0, -6) || "0"}.${x.amountRaw.padStart(7, "0").slice(-6)}`),
  // ---- third band ----
  // Where RAW has a value, the assertion is route-output === independent-raw-read. Where the raw read
  // failed (null) the assertion falls back to the cached measured fixture, and a mismatch there is a
  // real failure — not a silently skipped check.
  "/chain/client-version": (r) => typeof r.clientVersion === "string" && r.clientVersion.length >= 4
    && typeof r.answeredBy === "string" && /\./.test(r.answeredBy),
  "/chain/network-id": (r) => r.chainId === 8453 && r.expectedChainId === 8453 && r.matchesOurConfig === true
    && String(r.netVersion) === "8453" && r.agree === true,
  // HEAD.base is read when this file starts, and section 1 spends minutes walking 63 handlers on a chain
  // that produces a block every ~2s. A fixed +/-12 window therefore failed on the clock, not on the
  // route, so the head is compared as "at least the head we saw, still moving".
  "/chain/sync-status": (r) => r.head > 10_000_000 && r.head >= HEAD.base && r.head - HEAD.base < 3600
    && r.syncing === false && r.currentBlock === r.head && r.highestBlock >= r.currentBlock && r.lagBlocks === 0,
  "/chain/tx-count": (r) => r.count === FIX.pinnedBlock?.count
    && (RAW.txCount === null || r.count === Number(BigInt(RAW.txCount)))
    && blkNum(r.blockTag) === FIX.pinnedBlock?.number && Number.isInteger(r.count),
  "/chain/block-by-hash": (r) => r.found === true && r.requestedHash === FIX.pinnedBlock?.hash
    && r.block?.number === FIX.pinnedBlock.number && r.block?.hash === FIX.pinnedBlock.hash
    && r.block?.timestamp === FIX.pinnedBlock.timestamp && r.block?.transactionsCount === FIX.pinnedBlock.count
    && (RAW.blockByHash === null || Number(BigInt(RAW.blockByHash.number)) === r.block.number),
  "/chain/tx-at-index": (r) => r.found === true && r.index === 0 && r.transaction?.hash === FIX.pinnedBlock?.firstTx
    && (RAW.txAtIndex === null || r.transaction.hash === RAW.txAtIndex)
    && ADDR_RE.test(r.transaction.from) && Number.isInteger(r.transaction.nonce) && r.transaction.blockNumber === FIX.pinnedBlock.number,
  "/chain/block-series": (r) => r.count === r.rows.length && r.count === 6 && r.window.to > 10_000_000
    && r.window.to - r.window.from === 5 && r.rows.every((x, i) => x.number === r.rows[0].number - i)
    && r.rows.every((x) => /^\d+$/.test(x.gasUsed) && x.timestamp > 1_500_000_000 && /^\d{4}-\d{2}-\d{2}T/.test(x.isoTime))
    && r.secondsPerBlock > 0 && r.secondsPerBlock < 60,
  "/chain/block-by-timestamp": (r) => r.found === true && r.requestedTimestamp === FIX.pinnedBlock?.timestamp
    && Math.abs(r.blockNumber - FIX.pinnedBlock.number) <= 3 && r.blockTimestamp >= FIX.pinnedBlock.timestamp
    && r.probes >= 1 && r.probes <= 26 && r.head > r.blockNumber,
  "/chain/contract-owner": (r) => r.readable === true && r.hasCode === true
    && eqi(r.owner, FIX.contractWithOwner?.owner) && (RAW.owner === null || eqi(r.owner, ad(RAW.owner)))
    && r.bytecodeSize === FIX.contractWithOwner?.bytecodeSize,
  "/chain/proxy-check": (r) => r.isProxy === true && r.hasCode === true
    && eqi(r.implementationFromSlot, FIX.proxy?.implementation)
    && eqi(r.implementationFromCall, FIX.proxy?.implementationFromCall)
    && (RAW.proxyImplSlot === null || eqi(r.implementationFromSlot, ad(RAW.proxyImplSlot)))
    && (RAW.proxyImplCall === null || eqi(r.implementationFromCall, ad(RAW.proxyImplCall)))
    && r.slotMatchesCall === true,
  "/chain/paused-check": (r) => r.readable === true && r.paused === false && eqi(r.raw, FIX.pausedContract?.raw)
    && (RAW.paused === null || eqi(r.raw, RAW.paused)),
  // The PROXY case, which is the one this route got wrong: Base USDC's permit() lives behind the
  // EIP-1967 slot, so hasPermitSelector:true is only honest if the implementation was actually scanned.
  // The ICP fixture (permit in the token's own code) is covered by the `/chain/permit-ready answers for
  // a token whose permit is in its own code` control below, so both branches of permitSelectorIn run.
  "/chain/permit-ready": (r) => r.permitReady === true && r.hasPermitSelector === true && eqi(r.token, USDC)
    && r.permitSelectorIn === "implementation" && ADDR_RE.test(String(r.implementation || ""))
    && (RAW.usdcImpl === null || eqi(r.implementation, RAW.usdcImpl))
    && (RAW.usdcImplHasPermit === null || RAW.usdcImplHasPermit === true)
    && (RAW.usdcDs === null || eqi(r.domainSeparator, RAW.usdcDs))
    && (RAW.usdcNonce === null || r.nonce === dec(RAW.usdcNonce))
    && r.domainSeparator !== null && /^\d+$/.test(String(r.nonce)),
  "/chain/1155-balance": (r) => r.readable === true && r.supported === true
    && r.balanceRaw === (RAW.bal1155 === null ? FIX.erc1155?.balanceRaw : dec(RAW.bal1155))
    && BigInt(r.balanceRaw) > 0n && eqi(r.account, FIX.erc1155?.account) && r.tokenId === String(FIX.erc1155?.tokenId),
  // The raw re-read throttles on free nodes (17/24 answered this run), so a null control must not fail
  // the route. What never depends on the node is the DECODE: re-derive the ABI string from the raw the
  // handler returned, here, independently. If `uri` and `raw` agree under a second decoder, the
  // handler's decoder is right regardless of which host answered.
  "/chain/1155-uri": (r) => {
    // abi.encode(string) = 0x + offset word (chars 2..66) + length word (chars 66..130) + data from 130.
    // Slicing the length at 128 rather than 130 silently floor-divides it by 256 and decodes "".
    const abiStr = (hex) => { const h = String(hex || ""); return /^0x[0-9a-f]{130,}$/i.test(h)
      ? Buffer.from(h.slice(130, 130 + Number(BigInt("0x" + h.slice(66, 130))) * 2), "hex").toString("utf8") : null; };
    return r.readable === true && typeof r.uri === "string" && r.uri.length > 3 && r.uri !== "0x"
      && abiStr(r.raw) === r.uri && typeof r.template === "boolean"
      && (RAW.uri1155 === null || eqi(r.raw, RAW.uri1155))
      && r.tokenId === String(FIX.erc1155?.tokenId) && eqi(r.token, FIX.erc1155?.token);
  },
  // rows are positional: the Nth row must answer the Nth (account, tokenId) pair the caller sent, not
  // whatever the contract happened to report first. The second id is chosen because its balance DIFFERS
  // from the first, so a deduped or mis-padded encoding cannot make both rows look the same.
  "/chain/1155-batch": (r) => r.requested === 2 && r.readable === true && r.answered === 2 && r.rows.length === 2
    && r.rows[0].tokenId === String(FIX.erc1155?.tokenId)
    && (RAW.bal1155 === null || r.rows[0].balanceRaw === dec(RAW.bal1155))
    && r.rows[1].tokenId === String(ERC_ID_B)
    && (RAW[`bal1155x${ERC_ID_B}`] === null || r.rows[1].balanceRaw === dec(RAW[`bal1155x${ERC_ID_B}`]))
    && r.rows[0].balanceRaw !== r.rows[1].balanceRaw
    && r.rows.every((x) => eqi(x.account, FIX.erc1155?.account)),
  "/chain/1155-check": (r) => r.supported === true && r.standards?.ERC165 === true && r.standards?.ERC721 === false
    && r.standards?.ERC1155 === true && r.probedTokenId === String(FIX.erc1155?.tokenId),
  // The route echoes the block tags it was given, so `blocks.a` is the NUMBER we sent and `blocks.b` is
  // the string "latest". The old assertion compared a decimal fixture against "latest" and to a head
  // read minutes earlier — it was checking its own typo, not the service.
  // The slot is echoed in padded form ("0x00…02"), so compare it as a number. RAW.slotA/slotB come from
  // a throttled free node, so a null re-read is the instrument's gap, not the route's — the internal
  // `changed` consistency is checked against the payload instead of against a control that may be absent.
  "/chain/storage-diff": (r) => WORD_RE.test(String(r.valueA)) && WORD_RE.test(String(r.valueB))
    && (RAW.slotA === null || eqi(r.valueA, RAW.slotA)) && (RAW.slotB === null || eqi(r.valueB, RAW.slotB))
    && r.changed === (String(r.valueA).toLowerCase() !== String(r.valueB).toLowerCase())
    && r.blocks.b === "latest" && blkNum(r.blocks.a) === HEAD.base - 40
    && blkNum(r.blocks.head) >= HEAD.base - 1 && blkNum(r.blocks.head) >= blkNum(r.blocks.a)
    && r.address === USDC && BigInt(r.slot) === 2n && BigInt(r.asUintA) === BigInt(r.valueA)
    && /^\d+$/.test(String(r.asUintA)) && /^\d+$/.test(String(r.asUintB)),
  "/chain/token-meta-at": (r) => r.name === "USD Coin" && r.symbol === "USDC" && r.decimals === 6
    && (RAW.supplyAtPin === null || r.totalSupplyRaw === dec(RAW.supplyAtPin))
    && Number(r.totalSupply) > 1e9
    && blkNum(r.blockTag) === FIX.pinnedBlock?.number - 20,
  "/chain/nft-owner-at": (r) => r.readable === true && ADDR_RE.test(String(r.ownerThen)) && ADDR_RE.test(String(r.ownerNow))
    && (RAW.ownerOfNow === null || eqi(r.ownerNow, ad(RAW.ownerOfNow)))
    && (RAW.ownerOfThen === null || eqi(r.ownerThen, ad(RAW.ownerOfThen)))
    && r.moved === (String(r.ownerThen).toLowerCase() !== String(r.ownerNow).toLowerCase())
    && r.tokenId === String(FIX.baycOwnerAtBlock?.tokenId),
  "/chain/bytecode-fingerprint": (r) => r.hasCode === true && r.bytecodeSize === FIX.twoDistinctContracts?.sizeA
    && /^0x[0-9a-f]{64}$/.test(String(r.sha256))
    && r.sha256 === (RAW.codeA || FIX.twoDistinctContracts?.shaA) && /^0x[0-9a-f]{18,22}$/.test(String(r.prefix)),
  // The old assertion hardcoded "this address is an ERC-20, so it must carry transfer()". The address is
  // now Base USDC, an EIP-1967 proxy: its code carries the upgrade guards and NOTHING else, so a literal
  // list would have failed on a correct answer. Instead the expected set is re-derived from the raw
  // bytecode this instrument fetched itself, with the same PUSH4 walk and keccak naming done here rather
  // than inside the product.
  "/chain/bytecode-capabilities": (r) => {
    if (!RAW.codeHexB) return false;
    const body = RAW.codeHexB.slice(2);
    const seen = new Set();
    for (let i = 0; i + 10 <= body.length; i += 2) {
      if (body[i] === "6" && body[i + 1] === "3") seen.add("0x" + body.slice(i + 2, i + 10));
    }
    const all = [...seen];
    const known = all.filter((s) => KNOWN_SELECTOR[s]);
    const ok = r.hasCode === true && r.push4Candidates === all.length
      && r.namedCount === r.named.length && r.namedCount === Math.min(known.length, 60)
      && r.unnamedSelectorCount === all.length - known.length
      && r.named.every((x) => /^0x[0-9a-f]{8}$/.test(x.selector) && KNOWN_SELECTOR[x.selector] === x.signature
        && selOf(x.signature) === x.selector && all.includes(x.selector))
      && known.slice(0, 60).every((s) => r.named.some((x) => x.selector === s));
    if (!ok) console.log(`  capabilities drift: route named ${r.namedCount} of ${known.length} known in ${all.length} candidates; expected named [${known.slice(0, 60).map((s) => KNOWN_SELECTOR[s]).join(", ")}], got [${r.named?.map((x) => x.signature).join(", ")}]`);
    return ok;
  },
  "/chain/contract-diff": (r) => r.bothHaveCode === true && r.identicalBytecode === false && r.sameSize === false
    && r.a.bytecodeSize === FIX.twoDistinctContracts?.sizeA && r.b.bytecodeSize === FIX.twoDistinctContracts?.sizeB
    && r.a.sha256 === (RAW.codeA || FIX.twoDistinctContracts?.shaA)
    && r.b.sha256 === (RAW.codeB || FIX.twoDistinctContracts?.shaB)
    && r.a.sha256 !== r.b.sha256,
  // No exact balance equality: `owner` is a live USDC holder and its balance moved between the raw
  // control read and the paid call (397,662.849022 measured mid-run). A strict equality on live state is
  // a race, not a test — so the identity of the token and a strictly-positive balance are asserted, and
  // only the shape/counts that cannot drift.
  "/chain/wallet-tokens": (r) => {
    const shape = r.requested === 1 && r.tokensReadable === 1 && r.rows[0].readable === true
      && r.rows[0].symbol === "USDC" && r.rows[0].decimals === 6 && eqi(r.rows[0].token, USDC)
      && /^\d+$/.test(String(r.rows[0].balanceRaw)) && r.totalRowsWithBalance === (Number(r.rows[0].balanceRaw) > 0 ? 1 : 0);
    if (!usdcRich) { shape && unverified("/chain/wallet-tokens", "no holder fixture readable — balance>0 and owner identity were NOT exercised"); return shape; }
    return shape && BigInt(r.rows[0].balanceRaw) > 0n && Number(r.rows[0].balance) > 0 && eqi(r.owner, usdcRich.address);
  },
  "/chain/wallet-nfts": (r) => r.requested === 1 && r.rows[0].readable === true && r.rows[0].supportsERC721 === true
    && r.rows[0].name === "BoredApeYachtClub" && r.rows[0].symbol === "BAYC"
    && r.rows[0].balance === (RAW.baycBalanceRaw === null ? String(r.rows[0].balance) : dec(RAW.baycBalanceRaw))
    && Number(r.rows[0].balance) >= 1 && r.totalHeld === r.rows[0].balance && r.collectionsWithHoldings === 1,
  "/chain/wallet-approvals": (r) => {
    const raw = RAW.allowance === null ? FIX.liveAllowance?.allowanceRaw : dec(RAW.allowance);
    return r.requested === 1 && r.rows[0].readable === true && r.rows[0].symbol === "USDC"
      && r.rows[0].allowanceRaw === raw && BigInt(r.rows[0].allowanceRaw) > 0n
      && r.openApprovals === 1 && r.rows[0].unrestricted === (BigInt(raw) >= 2n ** 255n)
      && r.unrestrictedApprovals === (BigInt(raw) >= 2n ** 255n ? 1 : 0);
  },
  // `head` only exists on the found:false branch — the success payload has no such key, so the old
  // arithmetic compared undefined against a number. confirmations is pinned by the raw receipt block
  // instead, and only bounded for the rest because the head advances while this instrument runs.
  "/chain/tx-status": (r) => r.found === true && r.status === 1 && r.failed === false && r.pending === false
    && r.blockNumber > 10_000_000 && (RAW.txBlock === null || r.blockNumber === RAW.txBlock)
    && r.confirmations >= 1 && r.head === undefined
    && ADDR_RE.test(String(r.from)) && /^\d+$/.test(String(r.gasUsed)) && r.logCount >= 0 && r.revertReason === null,
  "/chain/tx-events": (r) => r.found === true && r.count === r.rows.length
    && (RAW.receiptLogs === null || r.count === RAW.receiptLogs)
    && r.blockNumber > 10_000_000 && (r.status === 0 || r.status === 1)
    && r.rows.every((x) => WORD_RE.test(String(x.topic0)) && ADDR_RE.test(x.address) && Array.isArray(x.topics)
      && Number.isInteger(x.dataSize) && (x.logIndex === null || Number.isInteger(x.logIndex))),
};

const routeOf = (p) => CHAIN_ROUTES.find((r) => r.path === p);
if (!Array.isArray(CHAIN_ROUTES)) { console.log("server.mjs did not export CHAIN_ROUTES"); process.exit(1); }
check("route table has 63 chain routes", CHAIN_ROUTES.length === 63, CHAIN_ROUTES.length);
check("every route has an on-chain assertion", CHAIN_ROUTES.every((r) => QUERIES[r.path] && ASSERT[r.path]),
  CHAIN_ROUTES.filter((r) => !QUERIES[r.path]).map((r) => r.path).join(" "));

// A hand-typed 4-byte selector is invisible to every other instrument here: the route still answers
// 200, `readable:false`, and a buyer has paid for a null. getApproved shipped as 0x087840dd from
// memory while the real keccak is 0x081812fc — the positive control on an approved BAYC id is what
// caught it. So every prefix and topic the server speaks is re-derived from its ABI string here.
{
  const SIGS = {
    balanceOf: "balanceOf(address)", allowance: "allowance(address,address)", totalSupply: "totalSupply()",
    decimals: "decimals()", name: "name()", symbol: "symbol()", ownerOf: "ownerOf(uint256)",
    supportsInterface: "supportsInterface(bytes4)", tokenURI: "tokenURI(uint256)",
    getApproved: "getApproved(uint256)", isApprovedForAll: "isApprovedForAll(address,address)",
  };
  const TOPICS = {
    Transfer: "Transfer(address,address,uint256)", Approval: "Approval(address,address,uint256)",
  };
  // The third band speaks a SECOND selector table (SEL2) plus the EIP-1967 slots and the selector→
  // signature map. It was never re-derived here, so 27 paid routes could have shipped a hand-typed
  // 0x087840dd-style typo unnoticed. Note the canonical EIP-2612 permit is the SEVEN-argument form —
  // my own fixture probe searched for a six-argument variant and reported "no Base token has permit",
  // which was an instrument error reading like a fact about the chain.
  const SIGS2 = {
    owner: "owner()", implementation: "implementation()", paused: "paused()", nonces: "nonces(address)",
    domainSeparator: "DOMAIN_SEPARATOR()", bal1155: "balanceOf(address,uint256)",
    supply1155: "totalSupply(address,uint256)", uri1155: "uri(uint256)",
    balanceOfBatch: "balanceOfBatch(address[],uint256[])", contractURI: "contractURI()",
    permit: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    revertString: "Error(string)", revertPanic: "Panic(uint256)",
  };
  const SLOTS = {
    implementation: "eip1967.proxy.implementation", admin: "eip1967.proxy.admin", beacon: "eip1967.proxy.beacon",
  };
  try {
    const { id } = await import("ethers");
    for (const [k, sig] of Object.entries(SIGS))
      check(`selector ${k} = keccak("${sig}")`, SEL[k] === id(sig).slice(0, 10), `shipped ${SEL[k]}, keccak ${id(sig).slice(0, 10)}`);
    for (const [k, sig] of Object.entries(TOPICS))
      check(`topic0 ${k} = keccak("${sig}")`, TOPIC[k] === id(sig), `shipped ${TOPIC[k]}`);
    for (const [k, sig] of Object.entries(SIGS2)) {
      const want = "0x" + id(sig).slice(2, 10);
      check(`SEL2.${k} = keccak("${sig}")`, SEL2[k] === want, `shipped ${SEL2[k]}, keccak ${want}`);
    }
    for (const [k, label] of Object.entries(SLOTS)) {
      const want = `0x${((BigInt(id(label)) - 1n) % 2n ** 256n).toString(16).padStart(64, "0")}`;
      check(`SLOT1967.${k} = keccak("${label}") - 1`, SLOT1967[k] === want, `shipped ${SLOT1967[k]}, derived ${want}`);
    }
    // The naming table is allowed to be incomplete but never wrong: an unnamed 4-byte prefix is
    // reported as unknown, a WRONG name under a real prefix is a lie a buyer acts on.
    const sigDrift = Object.entries(KNOWN_SELECTOR)
      .map(([sel, sig]) => [sel, sig, "0x" + id(sig).slice(2, 10)])
      .filter(([sel, , want]) => sel !== want);
    check(`all ${Object.keys(KNOWN_SELECTOR).length} KNOWN_SELECTOR names match their keccak prefix`,
      sigDrift.length === 0, sigDrift.map(([s, sig, w]) => `${s}="${sig}"→${w}`).slice(0, 6).join(" "));
    // ERC-165's interface id IS the supportsInterface(bytes4) selector, so this one constant can be
    // derived rather than trusted — the four others are XOR-foldings of a spec's function set and can
    // only be checked against a live contract, which /chain/nft-meta and /chain/1155-check do.
    check("IFACE.ERC165 equals the keccak-derived supportsInterface selector", IFACE.ERC165 === SEL.supportsInterface,
      `IFACE.ERC165=${IFACE.ERC165}, SEL.supportsInterface=${SEL.supportsInterface}`);
  } catch (e) {
    check("selectors re-derived from keccak", false, `ethers unavailable: ${e?.message}`);
  }
}

// ---- 1. handlers return live data (this is the code path a settled buyer reaches) ----
// The same declared-vs-returned instrument that caught 45 shape failures in the market band runs here
// too: every /chain/* `out` table was hand-typed next to a handler that emitted something else
// (`contract-diff` promises `identical` and answers `identicalBytecode`; `wallet-nfts` declares an
// integer total and publishes a decimal string). A buyer reads the OpenAPI schema, not the source.
// Same exemption list the market generator uses, plus what chainResult injects. `note` is prose the
// handler adds for a caller, not a priced field; `found`/`readable`/`hasCode` ARE buyer-facing, so
// they stay in the tables.
const CHAIN_ENVELOPE = new Set(["chain", "chainId", "chainLabel", "source", "ts", "stale", "note", "reason", "caveat"]);
// `chainId` is the one envelope key that a route can also be SELLING: /chain/network-id answers
// eth_chainId from the node, and chainResult spreads the handler's object after its own stamp, so that
// measured number is what the buyer receives. Dropping it there would undeclare the route's headline
// field, so the filter is conditional on what the handler actually returned.
const CONDITIONAL_ENVELOPE = new Set(["chainId"]);
const envelopeOf = (raw) => new Set([...CHAIN_ENVELOPE].filter((k) => !(k in raw) || !CONDITIONAL_ENVELOPE.has(k)));
const jtype = (v) => (Array.isArray(v) ? "array" : typeof v === "number" ? (Number.isInteger(v) ? "integer" : "number") : typeof v);
console.log("\n-- handler data (positive controls) --");
// What the handlers actually return, saved for .tmp-check/gen-decls.mjs: this band's published field
// tables were hand-typed beside the handler, so the repair has to be measured, not re-typed by hand.
// Is the RPC surface answering us at all right now? Two independent reads decide how every route failure
// below must be worded. Free public nodes throttle this host in bursts — earlier today the same battery
// ran clean — and a null from `eth_call` is an unread, not a route that returns nulls. Calling that a
// route defect would send someone to "fix" working code; calling an unread upstream a PASS would be worse.
const UPSTREAM_PROBES = [
  ["base", BASE_RPC, "eth_blockNumber", []],
  ["base", BASE_RPC, "eth_call", [{ to: USDC, data: "0x95d89b41" }, "latest"]],
  ["ethereum", "https://ethereum-rpc.publicnode.com", "eth_blockNumber", []],
];
const upstream = [];
for (const [chain, host, m, p] of UPSTREAM_PROBES) {
  let v = null;
  try { const j = await rpcRaw(host, m, p); v = j && j.result != null ? String(j.result).slice(0, 20) : `NULL(${String(j?.error?.message || "no result").slice(0, 40)})`; }
  catch (e) { v = `ERR ${String(e.message).slice(0, 40)}`; }
  upstream.push(`${chain} ${new URL(host).host} ${m}=${v}`);
}
const upstreamBad = upstream.filter((s) => /=NULL|=ERR/.test(s)).length;
console.log(`upstream probe: ${upstream.join(" | ")}${upstreamBad ? ` — ${upstreamBad}/${UPSTREAM_PROBES.length} reads UNREADABLE` : " — all reads OK"}`);
const LIVE_PAYLOADS = {};
for (const r of CHAIN_ROUTES) {
  const q = QUERIES[r.path];
  if (!q) continue;
  try {
    const args = parseChainArgs(r, q);
    // chainResult is the shipped envelope, exported for exactly this reason — asserting on a copy of it
    // in the test is how a shape change passes here and ships broken.
    const raw = await r.run(args);
    const merged = chainResult(args, raw);
    const env = envelopeOf(raw);
    const ok = ASSERT[r.path](merged);
    // Classify before accusing. With the control reads failing, a mismatch here says only that we could not
    // check — so it is recorded as UNVERIFIED and the payload is still NOT fed to the table generator
    // below (a fixture built from a throttled null would delete keys the route really does sell).
    if (!ok && upstreamBad) {
      NOT_VERIFIED.push(`${r.path} -> live data: control reads failed (${upstream.filter((s) => /=NULL|=ERR/.test(s)).join(" ")}) — UNVERIFIED right now, not proven wrong`);
      console.log(`  skip ${r.path} (upstream READ_FAILED — no verdict issued)`);
    } else {
      check(`${r.path} -> live data`, ok, JSON.stringify(merged).slice(0, 260));
    }
    const keys = Object.keys(merged);
    const missing = r.out.map(([k]) => k).filter((k) => !(k in merged));
    check(`${r.path} declares every key it returns`, missing.length === 0, `missing from live payload: ${missing.join(", ")}`);
    const undeclared = keys.filter((k) => !env.has(k) && !r.out.some(([o]) => o === k));
    check(`${r.path} returns nothing undeclared`, undeclared.length === 0,
      `undeclared: ${undeclared.join(",")} declared=[${r.out.map(([o]) => o).join(",")}]`);
    const wrongType = [];
    for (const [k, t] of r.out) {
      const v = merged[k];
      if (!(k in merged) || v === null || v === undefined) continue;
      const isArr = Array.isArray(v);
      const good = t === "array" ? isArr
        : t === "object" ? (typeof v === "object" && !isArr)
        : t === "integer" || t === "number" ? typeof v === "number"
        : t === "boolean" ? typeof v === "boolean"
        : t === "string" ? typeof v === "string" : false;
      if (!good) wrongType.push(`${k}:${t}=${isArr ? "array" : jtype(v)}`);
    }
    check(`${r.path} out types match the live payload`, wrongType.length === 0, wrongType.join(" "));
    const bytes = JSON.stringify(merged).length;
    check(`${r.path} payload under 400KB`, bytes < 400_000, bytes);
    // Only a payload that PASSED its control feeds the generator. A throttled free node answers one of
    // these reads with nulls, the handler then takes its not-found branch, and a table generated from
    // that sample would delete keys the route really does sell.
    if (!ok) continue;
    LIVE_PAYLOADS[r.path] = { query: q, keys: Object.keys(merged).filter((k) => !env.has(k)),
      payload: Object.fromEntries(Object.entries(merged).filter(([k]) => !env.has(k))) };
  } catch (e) {
    check(`${r.path} -> live data`, false, `${e?.name}: ${e?.message}`);
  }
  // Every route x up to 5 fan-out reads back-to-back is harsher than any real buyer and does throttle us
  // on free nodes (both Ethereum hosts timed out under it once). A short gap keeps a FAIL meaningful.
  await new Promise((r) => setTimeout(r, 200));
}

// ---- 1b. differentials: an answer of "false"/"not found" must be earned, not defaulted ----
// Section 1 proved getApproved answers for a MINTED id; a wrong selector would answer `readable:false`
// there too if the test only ever looked at an unminted one. Both directions have to be observed, and
// the whole-file positive control (baycApproved above) only exists when the chain happens to supply one.
console.log("\n-- negative controls --");
{
  const probe = async (path, query) => {
    try {
      const r = routeOf(path);
      const args = parseChainArgs(r, query);
      return chainResult(args, await r.run(args));
    } catch (e) { return { __error: `${e?.name}: ${String(e?.message).slice(0, 90)}` }; }
  };
  const neg = await probe("/chain/nft-approved", { chain: "ethereum", token: BAYC, tokenId: String(10n ** 25n) });
  check("/chain/nft-approved on an unminted id is not an approval", !neg.__error && (neg.readable === false || neg.hasApproval === false), JSON.stringify(neg).slice(0, 200));
  const noTok = await probe("/chain/nft-token-uri", { chain: "base", token: USDC, tokenId: "1" });
  check("/chain/nft-token-uri on an ERC-20 reports found:false, not a crash", !noTok.__error && noTok.found === false, JSON.stringify(noTok).slice(0, 200));
  const noCode = await probe("/chain/code-at", { chain: "base", address: "0x7C8A3c26bd579c5176A29a5a8Ae80536319Fa94b", block: String(HEAD.base - 40) });
  check("/chain/code-at on our own EOA says no bytecode", !noCode.__error && noCode.existedAtBlock === false && noCode.isContractNow === false, JSON.stringify(noCode).slice(0, 200));
  const badCall = await probe("/chain/multicall", { chain: "base", calls: `${USDC}:0xdeadbeef,${USDC}:0x95d89b41` });
  check("/chain/multicall answers a junk selector per-row instead of failing the batch",
    !badCall.__error && badCall.requested === 2 && badCall.answered === 1 && badCall.rows[0].ok === false && badCall.rows[1].asString === "USDC",
    JSON.stringify(badCall).slice(0, 240));
  const emptyRange = await probe("/chain/block-receipts", { chain: "base", block: "earliest" });
  check("/chain/block-receipts on block 0 answers, it does not 500", !emptyRange.__error, JSON.stringify(emptyRange).slice(0, 160));

  // eth_getBlockReceipts is NOT universal on free nodes, and which host refuses it changes between
  // runs (measured 2026-09-24: mainnet.base.org answered -32601 for one block, "backend response too
  // large" for another and 2 receipts for a third, while base.drpc.org returned a full 328-receipt list
  // under a 15-request/second cap). Asserting WHICH path ran would make the instrument depend on a
  // third party's mood, so this asserts the buyer-facing invariant on both host sets and logs the path.
  {
    const blkNumHex = hexN(HEAD.base - 3);
    const blkObj = await rpcQ("https://base.drpc.org", "eth_getBlockByNumber", [blkNumHex, false]);
    const hashes = (blkObj?.transactions || []).filter((t) => typeof t === "string");
    const orig = CHAINS.base.rpcs;
    let one = null, many = null;
    try {
      CHAINS.base.rpcs = ["https://mainnet.base.org"];
      one = await blockReceipts("base", blkNumHex);
      CHAINS.base.rpcs = orig;
      many = await blockReceipts("base", blkNumHex);
    } finally { CHAINS.base.rpcs = orig; }
    console.log(`  receipts paths: single-host=${one?.receipts?.length ?? "null"}/${one?.total ?? "-"} partial=${one?.partial} | shipped=${many?.receipts?.length ?? "null"}/${many?.total ?? "-"} partial=${many?.partial} | block has ${hashes.length} txs`);
    // The reference block this assertion compares against is read from the SAME public RPCs the route uses.
    // When that read comes back empty (rate limit, transient RPC failure), `x.receipts.length <= 0` fails for
    // any real answer and the battery accuses the ROUTE of a defect while its own reference data is missing
    // — measured 2026-09-28: `blockTxs:0` against `total:796` on a Base block that cannot have zero
    // transactions. A failed reference read is READ_FAILED, never a FAIL: it proves nothing about the route.
    if (!Array.isArray(hashes) || hashes.length === 0) {
      console.log(`  READ_FAILED reference block ${blkNumHex} returned ${hashes?.length ?? "no array"} txs — the two receipts-shape checks CANNOT run; this is not a route defect`);
    } else {
    const invariant = (x) => Array.isArray(x?.receipts) && x.receipts.length > 0
      && x.receipts.length <= hashes.length
      && x.receipts.every((s) => typeof s?.transactionHash === "string" && typeof s?.blockHash === "string")
      && x.receipts.map((s) => String(s.transactionHash).toLowerCase()).join()
        === hashes.slice(0, x.receipts.length).map((h) => String(h).toLowerCase()).join()
      && (x.partial === true ? (x.total === hashes.length && x.receipts.length <= RECEIPT_FALLBACK_CAP)
                             : (x.total === undefined && x.partial === false));
    check("blockReceipts answers with the block's own receipts on the single public host",
      invariant(one), JSON.stringify({ n: one?.receipts?.length, partial: one?.partial, total: one?.total, blockTxs: hashes.length }));
    check("blockReceipts answers with the block's own receipts on the shipped host set",
      invariant(many), JSON.stringify({ n: many?.receipts?.length, partial: many?.partial, total: many?.total }));
    }
    const viaRoute = await probe("/chain/block-receipts", { chain: "base", block: String(HEAD.base - 3) });
    // This check used to demand rows.length === aggregatedOver, and the ROUTE was right to refuse it: the
    // per-row list has its own cap (300) while the block totals cover every receipt. Two kinds of
    // truncation, so both are asserted separately — and the row cap must announce itself in prose, or a
    // buyer reading truncated:false on a 475-tx block concludes they got 475 rows.
    check("block-receipts publishes count/aggregatedOver/truncated honestly", !viaRoute?.__error
      && viaRoute.found !== false && viaRoute.count >= viaRoute.aggregatedOver && viaRoute.aggregatedOver > 0
      && viaRoute.rows.length === Math.min(viaRoute.cap, viaRoute.aggregatedOver)
      && viaRoute.truncated === (viaRoute.aggregatedOver < viaRoute.count)
      && (viaRoute.rows.length < viaRoute.aggregatedOver
        ? /cap|first|cover/.test(String(viaRoute.caveat ?? viaRoute.note ?? "")) : true)
      && (viaRoute.truncated ? /first|cap|individually|not covered/.test(String(viaRoute.note ?? viaRoute.caveat ?? "")) : true)
      && viaRoute.blockNumber === HEAD.base - 3,
      JSON.stringify(viaRoute).slice(0, 260));
  }

  // A capability list that only ever says "yes" is as useless as one that says "no". Base USDC is an
  // EIP-1967 proxy: its 1.8KB of code carries the upgrade guards and NOT transfer(). The sibling
  // fixture is a full ERC-20 whose raw hex demonstrably does. Both directions, derived from keccak and
  // from the bytecode this instrument fetched — never from a guess about what the token "should" be.
  {
    const TRANSFER = selOf("transfer(address,uint256)");
    const proxy = await probe("/chain/bytecode-capabilities", { chain: "base", address: FIX.twoDistinctContracts?.a || USDC, count: "60" });
    const full = await probe("/chain/bytecode-capabilities", { chain: "base", address: FIX.twoDistinctContracts?.b || USDC, count: "60" });
    const rawHasTransfer = TRANSFER && RAW.codeHexB?.includes(TRANSFER.slice(2));
    console.log(`  capability control: keccak(transfer) = ${TRANSFER}, present in sibling code = ${!!rawHasTransfer}`);
    check("/chain/bytecode-capabilities distinguishes a proxy shim from a real ERC-20", !proxy.__error && !full.__error
      && proxy.hasCode === true && full.hasCode === true
      && !proxy.named.some((x) => x.signature === "transfer(address,uint256)")
      && (rawHasTransfer ? full.named.some((x) => x.signature === "transfer(address,uint256)") : true)
      && proxy.push4Candidates < full.push4Candidates,
      `proxy=${JSON.stringify(proxy.named?.map((x) => x.signature))} fullHasTransfer=${!!full.named?.find((x) => x.signature === "transfer(address,uint256)")}`);
  }

  // ---- third band: the same "a negative must be earned" rule on the 27 new routes ----
  // Each of these is the answer a WRONG selector also produces, so the pair with the positive control
  // above is what proves the decoder rather than the default value.
  const negProxy = await probe("/chain/proxy-check", { chain: "base", address: EOA });
  check("/chain/proxy-check on an EOA earns its isProxy:false", !negProxy.__error && negProxy.isProxy === false
    && negProxy.hasCode === false && negProxy.implementationFromSlot === null, JSON.stringify(negProxy).slice(0, 200));
  const negPaused = await probe("/chain/paused-check", { chain: "ethereum", address: BAYC });
  check("/chain/paused-check keeps \"no pause switch\" apart from \"not paused\"", !negPaused.__error
    && negPaused.readable === false && negPaused.paused === null && !!negPaused.note, JSON.stringify(negPaused).slice(0, 200));
  // This control used to assert "USDC has no permit" and it was the TEST that was wrong: Base USDC
  // answers DOMAIN_SEPARATOR(), nonces() and carries the permit() selector — in its IMPLEMENTATION,
  // which is why the route-level query now covers the proxy. Here the other branch runs: a token whose
  // permit is in its own code must say so, and must not invent an implementation.
  const tokPermit = await probe("/chain/permit-ready", { chain: FIX.permitToken?.chain || "base",
    token: FIX.permitToken?.token, owner: USDC });
  check("/chain/permit-ready answers for a token whose permit is in its own code", !tokPermit.__error
    && tokPermit.permitReady === true && tokPermit.hasPermitSelector === true
    && tokPermit.permitSelectorIn === "token" && tokPermit.implementation === null
    && eqi(tokPermit.domainSeparator, FIX.permitToken?.domainSeparator)
    && (RAW.domainSeparator === null || eqi(tokPermit.domainSeparator, RAW.domainSeparator))
    && (RAW.permitNonce === null || tokPermit.nonce === dec(RAW.permitNonce)),
    JSON.stringify(tokPermit).slice(0, 220));
  const negPermit = await probe("/chain/permit-ready", { chain: "base", token: EOA, owner: USDC });
  check("/chain/permit-ready on an address with no bytecode denies all three inputs", !negPermit.__error
    && negPermit.permitReady === false && negPermit.hasPermitSelector === false
    && negPermit.permitSelectorIn === null && negPermit.implementation === null
    && negPermit.domainSeparator === null && negPermit.nonce === null && !!negPermit.note,
    JSON.stringify(negPermit).slice(0, 200));
  // The AND rule, on the proxy: permitReady must be the conjunction of the route's OWN three reads,
  // never a default. The cross-check against the raw scan is gated on the route actually resolving an
  // implementation — a free node refuses one of these eth_calls now and then, and "the node did not
  // answer" must never be reported as "the route is wrong".
  const posPermit = await probe("/chain/permit-ready", { chain: "base", token: USDC, owner: EOA });
  check("/chain/permit-ready computes permitReady from its own three reads", !posPermit.__error
    && posPermit.permitReady === (!!posPermit.domainSeparator && posPermit.nonce !== null && posPermit.hasPermitSelector)
    && ((posPermit.implementation === null || RAW.usdcImplHasPermit === null)
      ? true : posPermit.hasPermitSelector === RAW.usdcImplHasPermit),
    JSON.stringify(posPermit).slice(0, 200));
  const neg1155 = await probe("/chain/1155-check", { chain: "ethereum", token: BAYC, tokenId: "1" });
  check("/chain/1155-check on BAYC: ERC-721 yes, ERC-1155 no", !neg1155.__error && neg1155.supported === false
    && neg1155.standards?.ERC721 === true && neg1155.standards?.ERC1155 === false, JSON.stringify(neg1155).slice(0, 220));
  const negHash = await probe("/chain/block-by-hash", { chain: "base", blockHash: "0x" + "77".repeat(32) });
  check("/chain/block-by-hash on an unknown hash answers found:false, not a crash", !negHash.__error
    && negHash.found === false && !!negHash.note, JSON.stringify(negHash).slice(0, 200));
  const negCode = await probe("/chain/bytecode-capabilities", { chain: "base", address: EOA });
  check("/chain/bytecode-capabilities on an EOA reports no code", !negCode.__error && negCode.hasCode === false
    && negCode.namedCount === 0 && Array.isArray(negCode.named), JSON.stringify(negCode).slice(0, 200));
  const negOwnerAt = await probe("/chain/nft-owner-at", { chain: "ethereum", token: BAYC,
    tokenId: String(10n ** 24n), block: String(ethHead - 30) });
  check("/chain/nft-owner-at on an id that was never minted is not an owner", !negOwnerAt.__error
    && negOwnerAt.readable === false && negOwnerAt.ownerThen === null && !!negOwnerAt.note, JSON.stringify(negOwnerAt).slice(0, 220));
  const negSeries = await probe("/chain/block-series", { chain: "base", blocks: "3" });
  check("/chain/block-series returns a contiguous run, newest first", !negSeries.__error && negSeries.count === 3
    && negSeries.rows[0].number === negSeries.rows[1].number + 1
    && negSeries.rows[1].number === negSeries.rows[2].number + 1
    && negSeries.rows[0].timestamp > negSeries.rows[2].timestamp, JSON.stringify(negSeries).slice(0, 200));
}

// ---- 2. every published chain answers eth_blockNumber through our own client ----
console.log("\n-- all 7 chains live --");
for (const [key, ch] of Object.entries(CHAINS)) {
  const r = routeOf("/chain/block-number");
  try {
    const args = parseChainArgs(r, { chain: key });
    const out = chainResult(args, await r.run(args));
    check(`chain ${key} answers (chainId ${ch.chainId})`, out.blockNumber > 1000 && out.chainId === ch.chainId && out.chainLabel === ch.label, JSON.stringify(out));
  } catch (e) {
    check(`chain ${key} answers`, false, e?.message);
  }
}

// ---- 2b. the failover actually changes host ----
// `rpcCursor++ + i` inside the attempt loop evaluated to index c and then c+2 = c for a two-host chain,
// so the fallback re-sent the request to the SAME node and the second measured host never ran. Proved
// offline: the first attempt of every call throws, the second answers from a canned response, and the
// two visited hosts must differ.
console.log("\n-- rpc failover --");
{
  const real = globalThis.fetch;
  const visited = [];
  globalThis.fetch = async (url) => {
    const host = new URL(url).host;
    visited.push(host);
    if (visited.length === 1) throw Object.assign(new Error("synthetic outage"), { name: "TypeError", cause: {} });
    return { ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: 1, result: "0x2a" }) };
  };
  let out = null, err = null;
  try { out = await routeOf("/chain/block-number").run({ chain: "base" }); } catch (e) { err = e; }
  globalThis.fetch = real;
  check("a dead first host is survived", !err && out?.blockNumber === 42, err ? err.message : JSON.stringify(out));
  check("the retry goes to a DIFFERENT node", new Set(visited).size === 2 && visited[0] !== visited[1], JSON.stringify(visited));
}

// ---- 3. validators reject hostile/malformed input with 400, never a fetch ----
console.log("\n-- validators --");
const expect400 = async (label, path, query) => {
  const r = routeOf(path);
  try { parseChainArgs(r, query); check(label, false, "accepted, should have been rejected"); }
  catch (e) { check(label, e instanceof HttpError && e.status === 400, `${e?.name}/${e?.message}`); }
};
await expect400("bad chain rejected", "/chain/balance", { chain: "https://evil.example", address: USDC });
await expect400("short address rejected", "/chain/balance", { chain: "base", address: "0x1234" });
await expect400("non-hex address rejected", "/chain/balance", { chain: "base", address: "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" });
await expect400("object query rejected", "/chain/balance", { chain: "base", address: { $ne: null } });
await expect400("missing required address rejected", "/chain/balance", { chain: "base" });
await expect400("odd-length calldata rejected", "/chain/call", { chain: "base", to: USDC, data: "0x123" });
await expect400("oversized calldata rejected", "/chain/call", { chain: "base", to: USDC, data: "0x" + "ab".repeat(5000) });
await expect400("hash too short rejected", "/chain/tx", { chain: "base", hash: "0x1234" });
// ---- second band: a malformed batch must be a pre-gate 400, never a settled payment + error ----
await expect400("multicall pair without a colon rejected", "/chain/multicall", { chain: "base", calls: USDC + "95d89b41" });
await expect400("multicall non-hex calldata rejected", "/chain/multicall", { chain: "base", calls: `${USDC}:https://evil.example/x` });
await expect400("multicall odd-length calldata rejected", "/chain/multicall", { chain: "base", calls: `${USDC}:0x95d89b4` });
await expect400("multicall malformed target rejected", "/chain/multicall", { chain: "base", calls: "0x1234:0x95d89b41" });
await expect400("11 calls over the cap rejected", "/chain/multicall", { chain: "base",
  calls: Array.from({ length: 11 }, () => `${USDC}:0x95d89b41`).join(",") });
await expect400("oversized multicall calldata rejected", "/chain/multicall", { chain: "base",
  calls: `${USDC}:0x${"ab".repeat(2000)}` });
await expect400("21 owners over the cap rejected", "/chain/token-balances", { chain: "base", token: USDC,
  owners: Array.from({ length: 21 }, (_, i) => `0x${(i + 1).toString(16).padStart(40, "0")}`).join(",") });
await expect400("count past the 16-slot ceiling rejected", "/chain/storage-range", { chain: "base", address: USDC, fromSlot: "0x0", count: "17" });
await expect400("non-numeric count rejected", "/chain/storage-range", { chain: "base", address: USDC, count: "1e99; DROP" });
await expect400("blocks past the window ceiling rejected", "/chain/transfers-scan", { chain: "base", token: USDC, blocks: "5000" });
await expect400("slot too wide rejected", "/chain/storage-range", { chain: "base", address: USDC, fromSlot: "0x" + "11".repeat(33) });
await expect400("operator must be an address", "/chain/nft-approved-for-all", { chain: "ethereum", token: BAYC, owner: USDC, operator: "evil" });
// 30 DISTINCT addresses: the list is deduped before the cap is applied, so repeating one address tests
// nothing (an earlier run of this file passed a 30-item list down as a single address).
await expect400("30 addresses over the cap rejected", "/chain/balances", { chain: "base",
  addresses: Array.from({ length: 30 }, (_, i) => `0x${(i + 1).toString(16).padStart(40, "0")}`).join(",") });
await expect400("unfiltered log scan rejected", "/chain/logs", { chain: "base", fromBlock: "1", toBlock: "2" });
await expect400("10k-block log range rejected", "/chain/logs", { chain: "base", address: USDC, fromBlock: "1", toBlock: "10000" });
// A window past the head is NOT a 400: parseChainArgs cannot know the head, and by the time the handler
// runs the buyer has already settled — so an empty range must be answered, not billed as an error.
{
  const lg = routeOf("/chain/logs");
  const future = HEAD.base + 10_000;
  try {
    const out = await lg.run(parseChainArgs(lg, { chain: "base", address: USDC, fromBlock: String(future), toBlock: String(future) }));
    check("log range past the head answers empty instead of 400", out.count === 0 && out.rows.length === 0 && !!out.note, JSON.stringify(out).slice(0, 200));
  } catch (e) {
    check("log range past the head answers empty instead of 400", false, `${e?.name}/${e?.message}`);
  }
}
// A duplicated query key normalizes to the first value — safe because every chain value is a key into a
// fixed host map, and rejecting it would 400 a client that merely retried with a repeated param.
check("duplicated chain key resolves to the first", parseChainArgs(routeOf("/chain/balance"), { chain: ["base", "ethereum"], address: USDC }).chain === "base", "");
await expect400("block number beyond range rejected", "/chain/block", { chain: "base", block: "99999999999999999" });
await expect400("6 chains over the cap rejected", "/chain/wallet-state", { chains: "base,ethereum,arbitrum,bsc,polygon,optimism", address: USDC });
await expect400("tokenId non-integer rejected", "/chain/nft-owner", { chain: "ethereum", token: BAYC, tokenId: "1; DROP" });
const arr = parseChainArgs(routeOf("/chain/balances"), { chain: "base", addresses: `${USDC},${USDC}` });
check("duplicate addresses dedupe", arr.addresses.length === 1, arr.addresses.length);
check("block tag passthrough", parseChainArgs(routeOf("/chain/block"), { chain: "base", block: "finalized" }).block === "finalized", "");
check("decimal block becomes hex", parseChainArgs(routeOf("/chain/block"), { chain: "base", block: String(HEAD.base) }).block === `0x${HEAD.base.toString(16)}`, "");

// ---- 4. the gate still owns every new route ----
console.log("\n-- payment gate over HTTP --");
let up = false;
for (let i = 0; i < 60 && !up; i++) {
  up = await fetch(base + "/health").then((r) => r.ok).catch(() => false);
  if (!up) await new Promise((rr) => setTimeout(rr, 250));
}
check("local server is listening", up, base);
const b64hdr = (r) => { try { return JSON.parse(Buffer.from(r.headers.get("payment-required") || "{}", "base64").toString()); } catch { return {}; } };
for (const r of CHAIN_ROUTES) {
  const q = new URLSearchParams(QUERIES[r.path]).toString();
  const unpaid = await fetch(`${base}${r.path}?${q}`);
  const terms = b64hdr(unpaid);
  const nets = (terms.accepts || []).map((a) => a.network);
  const amounts = (terms.accepts || []).map((a) => String(a.amount));
  const v1body = await unpaid.json().catch(() => ({}));
  const okGate = unpaid.status === 402 && amounts.every((a) => a === "1000") && nets[0] === "eip155:8453"
    && (terms.accepts || []).every((a) => a.payTo) && (v1body.accepts || []).length === 2
    && v1body.accepts?.[0]?.maxAmountRequired === "1000" && !!v1body.extensions?.bazaar
    // The v2 header is the SDK's own document, so it is the one that silently loses the extension when a
    // query example has the wrong JSON type (numbers for fromBlock/tokenId/value did exactly that).
    && !!terms.extensions?.bazaar;
  check(`GET ${r.path} unpaid -> 402 @ $0.001 dual-rail + bazaar`, okGate,
    `${unpaid.status} nets=${nets.join(",")} amounts=${amounts.join(",")} v1=${(v1body.accepts || []).length} bazaar=v1:${!!v1body.extensions?.bazaar}/v2:${!!terms.extensions?.bazaar}`);
  // Payload must never appear without money: the 402 body may advertise an OUTPUT EXAMPLE inside
  // extensions.bazaar, but no declared result key may sit at the top level of an unpaid answer.
  const body = await fetch(`${base}${r.path}?${q}`).then((x) => x.json().catch(() => ({})));
  const firstOut = r.out?.[0]?.[0];
  check(`GET ${r.path} leaks no payload unpaid`, body?.x402Version === 1 && body?.accepts?.length === 2 && body[firstOut] === undefined,
    JSON.stringify(body).slice(0, 160));
}
// A buyer that presented a payment but a bad query must be refused BEFORE settlement; a buyer that
// presented garbage payment with a good query must still be refused.
const fakePay = Buffer.from(JSON.stringify({ x402Version: 1, scheme: "exact", network: "base", payload: { authorization: { to: USDC, value: "1" }, signature: "0x1234" } })).toString("base64");
const badArgs = await fetch(`${base}/chain/balance?chain=base&address=nope`, { headers: { "x-payment": fakePay } });
check("paid-shaped request + invalid args -> 400 before settlement", badArgs.status === 400, String(badArgs.status));
const bj = await badArgs.json().catch(() => ({}));
check("400 body states no settlement was taken", /none/.test(String(bj.settlement)), JSON.stringify(bj).slice(0, 160));
const garbage = await fetch(`${base}/chain/balance?chain=base&address=${USDC}`, { headers: { "x-payment": fakePay } });
check("garbage payment + valid args -> 402, never 200", garbage.status === 402, String(garbage.status));
const v2junk = await fetch(`${base}/chain/token-meta?chain=base&token=${USDC}`, { headers: { "payment-signature": "not-base64!!" } });
check("malformed PAYMENT-SIGNATURE -> 402, never 500", v2junk.status === 402, String(v2junk.status));
// Wrong verb on a chain route must declare the working method instead of 404ing (crawler contract).
const wrongVerb = await fetch(`${base}/chain/balance`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
check("POST /chain/balance -> 405 naming GET", wrongVerb.status === 405, String(wrongVerb.status));
// Free metadata must stay free even with 22 more paid paths registered.
for (const p of ["/health", "/", "/llms.txt", "/openapi.json", "/robots.txt", "/discovery/resources", "/.well-known/x402", "/.well-known/x402-info", "/.well-known/agent-card.json", "/.well-known/api-catalog"]) {
  const s = await fetch(base + p).then((r) => r.status).catch(() => 0);
  check(`${p} still free (200)`, s === 200, String(s));
}
const oa = await (await fetch(base + "/openapi.json")).json();
check("openapi declares every chain path", CHAIN_ROUTES.every((r) => !!oa.paths?.[r.path]?.get), CHAIN_ROUTES.filter((r) => !oa.paths?.[r.path]?.get).map((r) => r.path).join(" "));
check("every chain op in openapi has input params + output schema + 402", CHAIN_ROUTES.every((r) => {
  const op = oa.paths?.[r.path]?.get;
  return !!op && (op.parameters || []).length > 0 && op["x-payment-info"]?.price?.amount === "0.001000"
    && !!op.responses?.["200"]?.content?.["application/json"]?.schema && !!op.responses?.["402"];
}), CHAIN_ROUTES.filter((r) => { const op = oa.paths?.[r.path]?.get; return !op || !(op.parameters || []).length
  || op["x-payment-info"]?.price?.amount !== "0.001000" || !op.responses?.["402"]
  || !op.responses?.["200"]?.content?.["application/json"]?.schema; }).map((r) => r.path).join(" "));
const llms = await (await fetch(base + "/llms.txt")).text();
check("llms.txt lists every chain route", CHAIN_ROUTES.every((r) => llms.includes(r.path)), CHAIN_ROUTES.filter((r) => !llms.includes(r.path)).map((r) => r.path).join(" "));
const wkx = await (await fetch(base + "/.well-known/x402")).json();
check("x402 fan-out lists every chain route", CHAIN_ROUTES.every((r) => wkx.resources.some((u) => u.endsWith(r.path))), "");
check("x402 fan-out prices chain routes at 1000 atomic", wkx.payments.filter((p) => p.url.includes("/chain/")).length === CHAIN_ROUTES.length
  && wkx.payments.filter((p) => p.url.includes("/chain/")).every((p) => String(p.priceAtomic) === "1000"), "");
const disc = await (await fetch(base + "/discovery/resources")).json();
// Hardcoding 46 here is how this check went stale the moment the surface grew; the count it must match
// is the same table the gate charges from, so a silent drop in the fan-out still fails.
check(`discovery fan-out carries all ${PAYABLE_ROUTES.length} payable items`, disc.items?.length === PAYABLE_ROUTES.length,
  `items=${disc.items?.length} payable=${PAYABLE_ROUTES.length}`);
const card = await (await fetch(base + "/.well-known/agent-card.json")).json();
check("A2A card advertises the chain skills", CHAIN_ROUTES.every((r) => card.skills.some((s) => s.id === r.path.slice(1))), "");
const sse = await fetch(base + "/chain/block-number?chain=base", { headers: { "payment-required": "x" } });
check("a request with only a response-header name is not special", sse.status === 402, String(sse.status));

// Save the measured payloads BEFORE the verdict so a failing run still hands the exact live keys to
// gen-decls.mjs. This band's declared tables were hand-typed beside the handler; the repair reads this
// file instead of a second human guess.
fs.writeFileSync(".tmp-check/chain-live-payloads.json", JSON.stringify(LIVE_PAYLOADS, null, 1));
console.log(`measured payloads written: .tmp-check/chain-live-payloads.json (${Object.keys(LIVE_PAYLOADS).length} routes)`);

if (NOT_VERIFIED.length) {
  console.log(`\nCHAIN SELFTEST NOT FULLY VERIFIED (${NOT_VERIFIED.length}) — these checks ran their shape but not their values, because a control fixture could not be read:`);
  for (const n of NOT_VERIFIED) console.log(` - NOT VERIFIED ${n}`);
}
if (fails.length) {
  console.log(`\nCHAIN SELFTEST FAIL (${fails.length}):\n - ${fails.join("\n - ")}`);
  process.exit(1);
}
if (NOT_VERIFIED.length) {
  console.log("Reading this as 'all clear' would be a lie: the holder-value assertions did not run. Fix the fixture (an RPC that answers eth_getLogs + eth_call) and re-run.");
  process.exit(3);
}
console.log(`\nCHAIN SELFTEST OK — ${CHAIN_ROUTES.length} routes return live chain data, all ${Object.keys(CHAINS).length} chains answer, gate intact`);
process.exit(0);
