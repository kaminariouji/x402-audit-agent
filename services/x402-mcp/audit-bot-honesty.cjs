#!/usr/bin/env node
/**
 * crypto-bot-honesty-audit — finds the bug patterns that make a crypto bot
 * report income it never earned.
 *
 * Usage:  node scripts/audit-bot-honesty.cjs [path/to/src]
 *
 * Static, regex-based, no dependencies. Every finding cites file:line so a
 * human can confirm it. These are *signals*, not verdicts — a flagged line may
 * be correct in context. Do not deliver this output to a client without reading
 * each hit yourself.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(process.argv[2] || "src");

const JS_EXT = new Set([".js", ".cjs", ".mjs", ".ts"]);
const SCAN_EXT = new Set([".js", ".cjs", ".mjs", ".ts", ".md"]);

function walk(dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name.startsWith(".")) continue;
      walk(full, out);
    } else if (SCAN_EXT.has(path.extname(e.name))) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Each rule: id, title, why, severity, and scan(lines, file) yielding hits.
 */
const RULES = [
  {
    id: "TESTNET_AS_USD",
    title: "Token amount added to a USD total with no testnet guard",
    why: "Adding a token amount to a USD field only makes sense if testnet value is excluded first. Testnet tokens (Sepolia/Amoy/Devnet/Holesky/Görli) are permanently worthless.",
    severity: "high",
    scan(lines) {
      const out = [];
      lines.forEach((line, i) => {
        if (/total_?usd\s*(\+=|=)/i.test(line) &&
            !/testnet|sepolia|devnet|amoy|holesky|goerli|isTestnet|usdValue/i.test(line)) {
          const window = lines.slice(Math.max(0, i - 14), i).join("\n");
          if (!/isTestnet|testnet/i.test(window)) {
            out.push({ line: i + 1, text: line.trim() });
          }
        }
      });
      return out;
    },
  },
  {
    id: "BALANCE_FROM_FAILED_RPC",
    title: "RPC failure reported as a balance of zero",
    why: "`catch { balance: 0 }` and `BigInt(res?.result || '0')` turn a dead endpoint into a confident 'you have 0'. The reader cannot tell a real zero from a failed lookup.",
    severity: "high",
    scan(lines) {
      const out = [];
      lines.forEach((line, i) => {
        if (/balance\s*[:=]\s*0\b/.test(line) && /catch|err|error/i.test(lines.slice(Math.max(0, i - 4), i + 1).join("\n"))) {
          out.push({ line: i + 1, text: line.trim() });
        }
        if (/BigInt\([^)]*\|\|\s*["']0["']\s*\)/.test(line)) {
          out.push({ line: i + 1, text: line.trim(), note: "missing result is coerced to 0" });
        }
      });
      return out;
    },
  },
  {
    id: "CHAIN_NOT_VERIFIED",
    title: "Chain RPC used without verifying eth_chainId",
    why: "An endpoint can answer correctly for a different network, or a mislabelled URL can serve another chain. Assert eth_chainId before trusting a balance.",
    severity: "medium",
    scan(lines) {
      const out = [];
      const src = lines.join("\n");
      const usesBalance = /eth_getBalance|getBalance\s*\(/.test(src);
      const verifies = /eth_chainId|\.getNetwork\s*\(|verifyNetwork/i.test(src);
      if (usesBalance && !verifies) {
        const idx = lines.findIndex((l) => /eth_getBalance|getBalance\s*\(/.test(l));
        out.push({ line: idx + 1, text: (lines[idx] || "").trim(), note: "no eth_chainId check in this file" });
      }
      return out;
    },
  },
  {
    id: "ATTEMPT_COUNTED_AS_RESULT",
    title: "Counter incremented on attempt, not on success",
    why: "Counting every try as a completed claim inflates 'success' stats into real numbers.",
    severity: "medium",
    scan(lines) {
      const out = [];
      lines.forEach((line, i) => {
        if (/\b(total\w*(?:claims|success|completed|earned|payout)|\w*(?:Claims|Success|Completed|Earned|Payout))\s*\+\+/.test(line)) {
          const window = lines.slice(Math.max(0, i - 6), i + 1).join("\n");
          if (!/if\s*\(\s*result\.success|if\s*\(.*success|status\s*===\s*["']success/.test(window)) {
            out.push({ line: i + 1, text: line.trim() });
          }
        }
      });
      return out;
    },
  },
  {
    id: "COOLDOWN_KEY_MISMATCH",
    title: "State-map key written with a prefix but read without it",
    why: "If a write uses `obj['x_'+id]` and a read uses `obj[id]`, the lookup never matches and cooldowns silently never apply.",
    severity: "high",
    scan(lines) {
      const out = [];
      const src = lines.join("\n");
      // Only true object-member assignments: obj.prop[`prefix${expr}`] = ...
      const writes = [...src.matchAll(/([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\[\s*`([^`]*?)\$\{[^}]+\}`\s*\]\s*=[^=]/g)];
      for (const w of writes) {
        const obj = w[1];
        const prefix = w[2];
        if (!prefix) continue;
        const esc = obj.replace(/\./g, "\\.");
        // A read of the same object using a bare identifier key (not a template literal)
        const readRe = new RegExp(`${esc}\\[\\s*([A-Za-z_$][\\w$]*)\\s*\\]`);
        for (let readIdx = 0; readIdx < lines.length; readIdx++) {
          const m = lines[readIdx].match(readRe);
          if (!m || lines[readIdx].includes("${")) continue;
          const varName = m[1];
          // If that bare variable is itself assigned the prefixed template
          // (e.g. `const key = \`micro_${id}\``), both sides agree — not a bug.
          const prefixEsc = prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const assignedPrefixed = new RegExp(
            "(?:const|let|var)\\s+" + varName + "\\s*=\\s*`[^`]*?" + prefixEsc + "[^`]*?\\$\\{"
          );
          if (lines.some((l) => assignedPrefixed.test(l))) continue;
          out.push({
            line: readIdx + 1,
            text: lines[readIdx].trim(),
            note: `written as "${prefix}<key>" via ${obj}, but read with a bare key here — confirm both sides match`,
          });
          break;
        }
      }
      return out;
    },
  },
  {
    id: "SPECULATIVE_EARNINGS_TEXT",
    title: "Marketing copy promising profit from a zero-capital bot",
    why: "Claims like '0 → Profit' or 'earn from zero capital' are unbackable and are the reason owners conclude the bot is a scam when $0 arrives.",
    severity: "low",
    scan(lines, file) {
      if (!/README|\.md$/i.test(file)) return [];
      const out = [];
      lines.forEach((line, i) => {
        if (!/0\s*→\s*Profit|earns? crypto from zero|guaranteed (daily )?(income|profit)|passive income|airdrop rewards start arriving/i.test(line)) return;
        // Skip lines that quote the phrase only to debunk it (honesty disclaimers).
        if (/honest|does not|doesn't|not real|never|no real|cannot|old |used to say|require.*fund yourself/i.test(line)) return;
        out.push({ line: i + 1, text: line.trim().slice(0, 120) });
      });
      return out;
    },
  },
];

function scanFiles(files) {
  const findings = [];
  const selfPath = path.resolve(__filename);
  for (const file of files) {
    // Skip this scanner's own source: its rule descriptions quote the exact patterns it greps for.
    if (path.resolve(file) === selfPath) continue;
    const isMarkdown = path.extname(file).toLowerCase() === ".md";
    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
    for (const rule of RULES) {
      // Markdown is only scanned by the copy-text rule; code rules false-positive on fenced snippets.
      if (rule.id !== "SPECULATIVE_EARNINGS_TEXT" && isMarkdown) continue;
      for (const hit of rule.scan(lines, file)) {
        findings.push({ ...hit, rule: rule.id, file: path.relative(process.cwd(), file) });
      }
    }
  }
  return findings;
}

function printFindings(findings, fileCount, rootLabel) {
  const byRule = new Map();
  for (const f of findings) {
    if (!byRule.has(f.rule)) byRule.set(f.rule, []);
    byRule.get(f.rule).push(f);
  }
  console.log(`\n=== crypto-bot-honesty-audit ===`);
  console.log(`scanned: ${fileCount} file(s) under ${rootLabel}`);
  console.log(`signals: ${findings.length}\n`);
  for (const rule of RULES) {
    const hits = byRule.get(rule.id) || [];
    if (!hits.length) continue;
    console.log(`[${rule.severity.toUpperCase()}] ${rule.id} — ${rule.title}`);
    console.log(`   why: ${rule.why}`);
    for (const h of hits) {
      console.log(`   ${h.file}:${h.line}  ${h.text}`);
      if (h.note) console.log(`      → ${h.note}`);
    }
    console.log("");
  }
  console.log("These are signals requiring human confirmation. Read each line before reporting it.\n");
}

function main() {
  if (!fs.existsSync(ROOT)) {
    console.error(`Path not found: ${ROOT}`);
    process.exit(1);
  }
  const files = walk(ROOT);
  const findings = scanFiles(files);
  printFindings(findings, files.length, path.relative(process.cwd(), ROOT) || ".");
  process.exitCode = 0;
}

// --- Self-test: prove the rules fire on a known-bad sample and stay quiet on a hardened one. ---
// Runs entirely in memory; writes nothing to disk.
const BAD_SAMPLE = `import { ethers } from "ethers";
const provider = new ethers.JsonRpcProvider("https://eth-sepolia.example");
export function record(a) { state.earnings.total_usd += a; }
export async function claim(wallet) {
  let balance;
  try { balance = BigInt(await provider.send("eth_getBalance", [wallet.address]) || "0"); }
  catch (e) { balance = 0; }
  const id = wallet.id;
  const last = state.faucet.lastClaim[id];
  if (!last) { state.faucet.lastClaim[\`micro_\${id}\`] = new Date().toISOString(); state.stats.totalFaucetClaims++; }
  return balance;
}`;

const CLEAN_SAMPLE = `import { ethers } from "ethers";
const provider = new ethers.JsonRpcProvider("https://eth-sepolia.example");
export async function claim(wallet, result) {
  let balance = null;
  try {
    const net = await provider.getNetwork();
    if (net.chainId !== 11155111n) throw new Error("chain mismatch");
    balance = BigInt(await provider.send("eth_getBalance", [wallet.address]));
  } catch (e) { balance = null; }
  const isTestnet = /sepolia|testnet|devnet/i.test(wallet.network);
  if (!isTestnet) state.earnings.total_usd += result.amountUsd;
  const key = \`micro_\${wallet.id}\`;
  const last = state.faucet.lastClaim[key];
  if (!last) state.faucet.lastClaim[\`micro_\${wallet.id}\`] = new Date().toISOString();
  if (result.success) state.stats.totalFaucetClaims++;
  return balance;
}`;

function selfTest() {
  const bad = scanText(BAD_SAMPLE, "bad-sample.js");
  const clean = scanText(CLEAN_SAMPLE, "clean-sample.js");
  const expectedBad = ["TESTNET_AS_USD", "BALANCE_FROM_FAILED_RPC", "CHAIN_NOT_VERIFIED", "ATTEMPT_COUNTED_AS_RESULT", "COOLDOWN_KEY_MISMATCH"];
  const badRules = new Set(bad.map((f) => f.rule));
  let ok = true;
  console.log("\n=== self-test ===");
  for (const r of expectedBad) {
    const hit = badRules.has(r);
    if (!hit) ok = false;
    console.log(`  ${hit ? "PASS" : "FAIL"}  bad sample triggers ${r}`);
  }
  console.log(`  ${clean.length === 0 ? "PASS" : "FAIL"}  clean sample triggers nothing (got ${clean.length})`);
  if (clean.length) for (const f of clean) console.log(`        unexpected ${f.rule} @ ${f.line}: ${f.text}`);
  console.log(`\n${ok && clean.length === 0 ? "SELF-TEST PASSED" : "SELF-TEST FAILED"}`);
  process.exitCode = ok && clean.length === 0 ? 0 : 1;
}

function scanText(text, name) {
  const lines = text.split(/\r?\n/);
  const out = [];
  for (const rule of RULES) {
    if (rule.id === "SPECULATIVE_EARNINGS_TEXT") continue;
    for (const hit of rule.scan(lines, name)) out.push({ ...hit, rule: rule.id, file: name });
  }
  return out;
}

if (require.main === module) {
  if (process.argv.includes("--selftest")) {
    selfTest();
  } else {
    main();
  }
}

module.exports = { RULES, scanFiles, scanText, walk };
