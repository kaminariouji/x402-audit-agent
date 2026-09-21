import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { RULES, scanText } = require("../../scripts/audit-bot-honesty.cjs");

const MAX_INPUT_CHARS = 2_000_000;
const CODE_FIELDS = ["code", "source", "text", "contents", "files"];

// Prose is not source code, and scanning prose would bill a buyer for a report
// that structurally cannot say anything about their bot.
export function looksLikeCode(text) {
  const lines = text.split(/\r?\n/);
  if (lines.length >= 3) return true;
  const codeish = (/[{};]/.test(text) ? 1 : 0)
    + (/\b(?:function|const|let|async|await|require|import|module\.exports|def|class|pragma|solidity)\b/.test(text) ? 1 : 0)
    + (/\b(?:if|for|while|try|catch|return)\s*\(/.test(text) ? 1 : 0);
  return codeish >= 2 && text.trim().length >= 40;
}

export function parseRequirements(raw) {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (!s || s.length > MAX_INPUT_CHARS) return null;
  let text = s;
  if (s.startsWith("{") || s.startsWith("[")) {
    try {
      const j = JSON.parse(s);
      const value = CODE_FIELDS.map((k) => j?.[k]).find((v) => typeof v === "string" && v.trim());
      if (!value) return null;
      text = value.trim();
    } catch {
      // A snippet that merely starts with a brace is still source code.
    }
  }
  return looksLikeCode(text) ? { text } : null;
}

export function buildReport(text) {
  const findings = scanText(text, "submitted");
  const out = [
    "crypto-bot-honesty-audit — static scan of the submitted source",
    `signals: ${findings.length}`,
    "",
  ];
  for (const rule of RULES) {
    const hits = findings.filter((f) => f.rule === rule.id);
    if (!hits.length) continue;
    out.push(`[${rule.severity.toUpperCase()}] ${rule.id} — ${rule.title}`);
    out.push(`   why: ${rule.why}`);
    for (const h of hits) {
      out.push(`   ${h.file}:${h.line}  ${h.text}`);
      if (h.note) out.push(`      → ${h.note}`);
    }
    out.push("");
  }
  out.push("These are signals requiring human confirmation. Read each line before acting on it.");
  return out.join("\n");
}
