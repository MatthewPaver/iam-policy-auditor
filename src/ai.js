'use strict';

// Optional Claude layer. The deterministic engine always runs first; Claude
// only rephrases/expands on ENGINE_FACTS and is instructed never to assert
// permissions the engine did not derive. Without an API key the app falls
// back to fully deterministic answers.

const MODEL = process.env.AUDITOR_MODEL || 'claude-sonnet-5';
const TEMPERATURE = Number(process.env.AUDITOR_TEMPERATURE || 0);
const CHANGE_PROMPT_VERSION = 'change-review-v2';

const SYSTEM = `You are the explanation layer of PolicyLens, a deterministic IAM policy analyzer.
The user asks questions about IAM policies. You receive ENGINE_FACTS: the normalized
statements, the rule findings, and the engine's own deterministic answer.

Hard rules:
- Ground every claim in ENGINE_FACTS. Never assert that a permission exists, or does not
  exist, unless the facts show it. If the facts are insufficient, say exactly what is
  unknown and why (e.g. "role not in the engine's map", "group membership not visible").
- Cite statements inline as [S2 · filename:line] using the ids and line numbers provided.
- Where a grant is conditional, state the condition. Where a Deny overrides, say so.
- Plain language for a busy security engineer. Under 220 words. Lead with the direct answer
  (Yes / No / It depends / Unknown). Use short bullets for multiple principals.
- If the question is unrelated to the provided policies, say so briefly.
- Identifiers may be pseudonymized (e.g. «ACCT_1»); keep placeholders exactly as written.`;

const CHANGE_SYSTEM = `You explain a PolicyLens IAM change review to a human approver.
The supplied REVIEW_FACTS come from a deterministic policy engine. You cannot change its verdict.

Hard rules:
- Start with the review label: Stop and review, Needs context, or No checked access increase.
- Every claim that an action is allowed, denied, granted, or removed must cite the relevant
  statement as [S2 · after.json:10] or [S1 · before.json:4]. Use only citations in REVIEW_FACTS.
- State the exact checked action and resource. Distinguish Allow, ConditionalAllow,
  ExplicitDeny, and ImplicitDeny.
- Name omitted controls from REVIEW_FACTS. Never call a policy or account safe, secure,
  compliant, or risk-free.
- A suggested correction is unverified until the deterministic correction check passes.
- Keep the answer under 180 words. Use plain language and short bullets when helpful.`;

function aiAvailable() {
  return Boolean(process.env.ANTHROPIC_API_KEY);
}

// --- redaction: pseudonymize identifiers before they leave the machine -----

function buildRedactor() {
  const map = new Map(); // placeholder -> original
  const seen = new Map(); // original -> placeholder
  let counters = {};
  const alias = (kind, original) => {
    if (seen.has(original)) return seen.get(original);
    counters[kind] = (counters[kind] || 0) + 1;
    const ph = `«${kind}_${counters[kind]}»`;
    map.set(ph, original);
    seen.set(original, ph);
    return ph;
  };
  const redact = (s) => String(s)
    .replace(/\b\d{12}\b/g, (m) => alias('ACCT', m))
    .replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, (m) => alias('EMAIL', m))
    .replace(/\bIBMid-[A-Za-z0-9]+\b/g, (m) => alias('IBMID', m))
    .replace(/\bAccessGroupId-(?!PublicAccess)[A-Za-z0-9-]+\b/g, (m) => alias('GROUP', m));
  const unredact = (s) => {
    let out = String(s);
    for (const [ph, original] of map) out = out.split(ph).join(original);
    return out;
  };
  return { redact, unredact };
}

async function askAI({ question, statements, findings, engineAnswer, redactIdentifiers = true }) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return null;

  const facts = {
    statements: statements.map((s) => ({
      id: s.id, doc: s.doc, line: s.line, provider: s.provider, kind: s.kind, sid: s.sid,
      effect: s.effect, principals: s.principals, actions: s.actions, notActions: s.notActions,
      resources: s.resources, conditions: s.conditions,
    })),
    findings: findings.map((f) => ({
      severity: f.severity, title: f.title, description: f.description,
      statements: f.statements, at: f.evidence.map((e) => `${e.doc}:${e.line}`),
    })),
    deterministic_answer: engineAnswer,
  };

  const { redact, unredact } = buildRedactor();
  const payload = redactIdentifiers ? redact(JSON.stringify(facts)) : JSON.stringify(facts);
  const q = redactIdentifiers ? redact(question) : question;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 1024,
        system: SYSTEM,
        messages: [{
          role: 'user',
          content: `QUESTION: ${q}\n\nENGINE_FACTS:\n${payload}`,
        }],
      }),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      return { error: `Claude API error ${resp.status}: ${body.slice(0, 300)}` };
    }
    const data = await resp.json();
    const text = (data.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
    return { text: redactIdentifiers ? unredact(text) : text, model: MODEL };
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'Claude API timed out after 45s' : `Claude API request failed: ${e.message}` };
  } finally {
    clearTimeout(timer);
  }
}

async function explainChangeAI({ review, redactIdentifiers = true }) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return null;

  const facts = {
    verdict: review.verdict,
    request: review.request,
    access: review.access,
    findings: {
      introduced: review.findings.introduced.map((finding) => ({
        severity: finding.severity,
        ruleId: finding.ruleId,
        title: finding.title,
        description: finding.description,
      })),
      resolved: review.findings.resolved.map((finding) => ({
        severity: finding.severity,
        ruleId: finding.ruleId,
        title: finding.title,
      })),
    },
    statements: review.statements,
    limits: review.limits,
  };
  const { redact, unredact } = buildRedactor();
  const payload = redactIdentifiers ? redact(JSON.stringify(facts)) : JSON.stringify(facts);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  const startedAt = Date.now();
  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 768,
        temperature: TEMPERATURE,
        system: CHANGE_SYSTEM,
        messages: [{ role: 'user', content: `REVIEW_FACTS:\n${payload}` }],
      }),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      return { error: `Claude API error ${resp.status}: ${body.slice(0, 300)}` };
    }
    const data = await resp.json();
    const text = (data.content || []).filter((item) => item.type === 'text').map((item) => item.text).join('\n');
    return {
      text: redactIdentifiers ? unredact(text) : text,
      model: MODEL,
      temperature: TEMPERATURE,
      promptVersion: CHANGE_PROMPT_VERSION,
      latencyMs: Date.now() - startedAt,
      usage: data.usage || null,
      requestId: resp.headers.get('request-id') || null,
      facts,
    };
  } catch (error) {
    return { error: error.name === 'AbortError' ? 'Claude API timed out after 45s' : `Claude API request failed: ${error.message}` };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { askAI, explainChangeAI, aiAvailable, MODEL, TEMPERATURE, CHANGE_PROMPT_VERSION };
