'use strict';

// Optional Claude layer. The deterministic engine always runs first; Claude
// only rephrases/expands on ENGINE_FACTS and is instructed never to assert
// permissions the engine did not derive. Without an API key the app falls
// back to fully deterministic answers.

const MODEL = process.env.AUDITOR_MODEL || 'claude-sonnet-5';

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

module.exports = { askAI, aiAvailable, MODEL };
