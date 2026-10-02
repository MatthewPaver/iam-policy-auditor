'use strict';

// Deterministic checks for the optional LLM explanation layer. These run
// offline and fail CI without calling a model. A live-model run can feed its
// captured output into the same evaluator.

const CITE = /\[(S\d+) · ([^:\]\n]+):(\d+)\]/g;
const CLAIM = /\b(allow(?:s|ed)?|grant(?:s|ed)?|den(?:y|ies|ied)|can\s+(?:read|write|delete|assume|change|perform)|reach(?:es)?\s+admin)\b/i;
const UNCERTAINTY = /\b(unknown|uncertain|depends|condition|not evaluated|cannot determine)\b/i;
const ABSOLUTE_SAFETY = /\b(safe|secure|compliant|no risk|risk[- ]free)\b/i;

function allowedCitations(facts) {
  const allowed = new Set();
  for (const group of [facts?.statements?.before || [], facts?.statements?.after || []]) {
    for (const statement of group) allowed.add(`${statement.id}|${statement.doc}|${statement.line}`);
  }
  return allowed;
}

function extractCitations(text) {
  const out = [];
  for (const match of String(text).matchAll(CITE)) {
    out.push({ id: match[1], doc: match[2], line: Number(match[3]), raw: match[0] });
  }
  return out;
}

function factualSentences(text) {
  return String(text)
    .split(/(?<=[.!?])\s+|\n+/)
    .map((line) => line.trim())
    .filter((line) => line && CLAIM.test(line));
}

function evaluateExplanation({ text, facts, expectedStatus }) {
  const value = String(text || '').trim();
  const allowed = allowedCitations(facts);
  const citations = extractCitations(value);
  const invalidCitations = citations.filter((citation) => !allowed.has(`${citation.id}|${citation.doc}|${citation.line}`));
  const unsupportedClaims = factualSentences(value).filter((sentence) => !extractCitations(sentence).length);
  const needsUncertainty = facts?.access?.after?.decision === 'ConditionalAllow'
    || (facts?.limits || []).length > 0;
  const statusLanguage = {
    stop: /\b(stop|block|do not approve|needs review)\b/i,
    review: /\b(needs context|review|depends|conditional)\b/i,
    pass: /\b(no checked access increase|pass|does not broaden)\b/i,
  };

  const checks = {
    nonEmpty: value.length > 0,
    verdictAligned: !expectedStatus || Boolean(statusLanguage[expectedStatus]?.test(value)),
    citationPrecision: citations.length > 0 && invalidCitations.length === 0,
    claimGrounding: unsupportedClaims.length === 0,
    uncertaintyCalibrated: !needsUncertainty || UNCERTAINTY.test(value),
    avoidsAbsoluteSafety: !ABSOLUTE_SAFETY.test(value),
    concise: value.length <= 1800,
  };
  const weights = {
    nonEmpty: 0.05,
    verdictAligned: 0.20,
    citationPrecision: 0.20,
    claimGrounding: 0.25,
    uncertaintyCalibrated: 0.15,
    avoidsAbsoluteSafety: 0.10,
    concise: 0.05,
  };
  const score = Object.entries(checks).reduce((total, [name, passed]) => total + (passed ? weights[name] : 0), 0);
  return {
    passed: score >= 0.85
      && checks.verdictAligned
      && checks.citationPrecision
      && checks.claimGrounding
      && checks.uncertaintyCalibrated
      && checks.avoidsAbsoluteSafety,
    score: Number(score.toFixed(2)),
    checks,
    diagnostics: { citations, invalidCitations, unsupportedClaims },
  };
}

module.exports = { evaluateExplanation, extractCitations, allowedCitations };
