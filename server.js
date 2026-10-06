#!/usr/bin/env node
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const { analyzeDocuments, publicStatements } = require('./src/engine');
const { runRules, SEV_ORDER } = require('./src/rules');
const { answerQuestion } = require('./src/query');
const { evaluateRequest } = require('./src/evaluate');
const { buildOrg, whoCan, reachAdmin } = require('./src/graph');
const { analyzeResourcePolicies } = require('./src/resource_policy');
const { lintModel } = require('./src/lint');
const actionsCatalogue = require('./src/actions');
const { askAI, explainChangeAI, aiAvailable, MODEL } = require('./src/ai');
const { reviewChange, verifyCorrection } = require('./src/change_review');
const { evaluateExplanation } = require('./src/ai_eval');

const PORT = Number(process.env.PORT || 4177);
// Platforms (Fly/Render) set PORT — bind all interfaces so the app is reachable.
const HOSTED = process.env.HOSTED === '1'
  || Boolean(process.env.FLY_APP_NAME)
  || Boolean(process.env.RENDER)
  || Boolean(process.env.RAILWAY_ENVIRONMENT);
const HOST = process.env.HOST || (HOSTED ? '0.0.0.0' : '127.0.0.1');
const PUB = path.join(__dirname, 'public');
const SAMPLES = path.join(__dirname, 'samples');
const MAX_BODY = 5 * 1024 * 1024;

/** Account snapshots are for Org tab — not single-policy Analyze. */
const POLICY_SAMPLE_SKIP = new Set(['aws-account-snapshot.json']);

/** Default Org demo query (matches the UI 90-second path). */
const DEMO_ACTION = 'rds:DeleteDBInstance';
const DEMO_RESOURCE = 'arn:aws:rds:eu-west-1:111122223333:db:prod-1';

// Tiny per-IP throttle so a public hosted demo isn't trivial to DOS.
const RATE = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = HOSTED ? 60 : 1000;

function rateOk(ip) {
  const now = Date.now();
  let b = RATE.get(ip);
  if (!b || now - b.t > RATE_WINDOW_MS) { b = { t: now, n: 0 }; RATE.set(ip, b); }
  b.n += 1;
  return b.n <= RATE_MAX;
}

function loadDemoSnapshot() {
  const file = path.join(SAMPLES, 'aws-account-snapshot.json');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function runOrgDemo(snapshot) {
  const org = buildOrg(snapshot);
  return {
    action: DEMO_ACTION,
    resource: DEMO_RESOURCE,
    who: {
      action: DEMO_ACTION,
      resource: DEMO_RESOURCE,
      principals: org.principals.length,
      rows: whoCan(org, { action: DEMO_ACTION, resource: DEMO_RESOURCE, context: {} }),
      caveat: 'Models identity + group + role-trust only. SCPs, permission boundaries and session policies are not evaluated.',
    },
    reach: {
      principals: org.principals.length,
      results: reachAdmin(org),
      caveat: 'Escalation catalogue (self-admin, become-user, become-role incl. pass-role variants) + transitive assume-role chains. Not evaluated: SCPs, permission boundaries, session policies, and instance-profile / SSM-command paths that need live instance data.',
    },
    exposure: {
      accountId: org.accountId,
      supplied: org.resourcePolicies.length,
      findings: analyzeResourcePolicies(org.resourcePolicies, org.accountId),
      caveat: 'Only resource policies supplied in the snapshot are scanned. Not evaluated: SCPs, permission boundaries, session policies, instance-profile / SSM-command paths. External grants are reported as exposures, not reach-admin paths.',
    },
  };
}


const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function send(res, code, body, type = 'application/json; charset=utf-8') {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(code, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('Body too large (5MB limit)')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { reject(new Error('Invalid JSON request body')); }
    });
    req.on('error', reject);
  });
}

function analyze(documents) {
  if (!Array.isArray(documents) || !documents.length) throw new Error('Provide documents: [{name, text}]');
  const model = analyzeDocuments(documents.map((d) => ({ name: String(d.name || 'policy.json').slice(0, 200), text: String(d.text || '') })));
  // Preflight first so grammar issues surface alongside (and often before) risk rules
  const findings = [...lintModel(model), ...runRules(model)];
  findings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  return { model, findings };
}

function counts(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

function findingKey(f) {
  return `${f.ruleId}|${f.title}`;
}

// Attach catalogue-backed blast radius to each AWS statement (mutating them in
// place) and return an aggregate over the Allow statements — i.e. how much this
// policy set actually grants, deduped across statements. Returns null when the
// action catalogue is not loaded so the UI can degrade gracefully.
function attachBlast(statements) {
  if (!actionsCatalogue.isLoaded()) return null;
  const grantUnion = new Set();
  for (const s of statements) {
    if (s.provider !== 'aws') continue;
    const stmtLike = { actions: s.actions, notActions: s.notActions };
    s.blast = actionsCatalogue.grantedBlast(stmtLike);
    // Only Allow statements add to what the identity can actually do. (Deny is
    // reflected in findings; folding it into the headline would over-complicate
    // an at-a-glance number, so we label the aggregate as "granted by Allow".)
    if (s.effect === 'Allow') {
      for (const a of actionsCatalogue.grantedActions(stmtLike)) grantUnion.add(a);
    }
  }
  return actionsCatalogue.tally([...grantUnion]);
}

const routes = {
  'GET /api/health': async () => ({
    ok: true,
    hosted: HOSTED,
    ai: aiAvailable(),
    model: aiAvailable() ? MODEL : null,
    catalogue: actionsCatalogue.isLoaded()
      ? { loaded: true, actions: actionsCatalogue.meta().actions, services: actionsCatalogue.meta().services }
      : { loaded: false },
  }),

  /** One-shot hosted demo path: no client upload of the snapshot. */
  'GET /api/demo/run': async () => runOrgDemo(loadDemoSnapshot()),

  'GET /api/samples': async () => {
    const files = fs.readdirSync(SAMPLES).filter((f) => f.endsWith('.json')).sort();
    return files
      .filter((f) => !POLICY_SAMPLE_SKIP.has(f))
      .map((f) => ({
        name: f,
        label: f
          .replace(/\.json$/, '')
          .replace(/^aws-/, 'AWS · ')
          .replace(/^gcp-/, 'GCP · ')
          .replace(/^azure-/, 'Azure · ')
          .replace(/^ibm-/, 'IBM · ')
          .replace(/-/g, ' '),
      }));
  },

  'GET /api/product': async () => ({
    name: 'PolicyLens',
    tagline: 'Ask who can do what in IAM — get cited, deterministic answers.',
    thesis: 'The engine produces the facts. The LLM only explains them. Every answer cites a source line.',
    demo: {
      seconds: 90,
      steps: [
        'Org → Load demo snapshot',
        'Who can delete the prod DB?',
        'Reach administrator (multi-hop paths)',
        'Resource-policy exposures (KMS / S3)',
      ],
    },
    limits: [
      'SCPs, permission boundaries, and session policies are not evaluated',
      'Instance-profile / SSM paths need an extended snapshot (not yet)',
      'Access Analyzer oracle needs iam:SimulateCustomPolicy credentials',
    ],
  }),

  'POST /api/analyze': async (body) => {
    const { model, findings } = analyze(body.documents);
    const statements = publicStatements(model);
    const blast = attachBlast(statements);
    return {
      providers: model.providers,
      documents: model.documents.map((d) => ({ name: d.name, provider: d.provider, lines: d.lines.length, error: d.error || null })),
      statements,
      findings,
      counts: counts(findings),
      blast,
    };
  },

  'POST /api/ask': async (body) => {
    const { model, findings } = analyze(body.documents);
    const question = String(body.question || '').slice(0, 2000);
    if (!question.trim()) throw new Error('Provide a question');
    const engineAnswer = answerQuestion(question, model, findings);
    const out = {
      mode: 'deterministic',
      engineText: engineAnswer.text,
      text: engineAnswer.text,
      intent: engineAnswer.intent,
      data: engineAnswer.data || null,
      // Aggregate grant scope, so the Ask panel can show it at a glance without a
      // separate analyze round-trip.
      blast: attachBlast(publicStatements(model)),
      aiError: null,
    };
    const useAI = body.useAI !== false && aiAvailable();
    if (useAI) {
      const ai = await askAI({
        question,
        statements: publicStatements(model),
        findings,
        engineAnswer: engineAnswer.text,
        redactIdentifiers: body.redactIdentifiers !== false,
      });
      if (ai && ai.text) { out.mode = 'ai'; out.text = ai.text; out.aiModel = ai.model; }
      else if (ai && ai.error) out.aiError = ai.error;
    }
    return out;
  },

  'POST /api/simulate': async (body) => {
    const { model } = analyze(body.documents);
    if (!body.action) throw new Error('Provide action, e.g. "s3:DeleteObject"');
    return evaluateRequest(model, {
      action: String(body.action),
      resource: body.resource ? String(body.resource) : undefined,
      context: body.context && typeof body.context === 'object' ? body.context : {},
    });
  },

  // --- G2: org-wide entity graph over an account snapshot -------------------
  // Snapshot is the shape of `aws iam get-account-authorization-details`.
  'POST /api/org/whocan': async (body) => {
    if (!body.snapshot || typeof body.snapshot !== 'object') throw new Error('Provide an account snapshot (aws iam get-account-authorization-details JSON)');
    if (!body.action) throw new Error('Provide action, e.g. "rds:DeleteDBInstance"');
    const org = buildOrg(body.snapshot);
    return {
      action: String(body.action),
      resource: body.resource ? String(body.resource) : '*',
      principals: org.principals.length,
      rows: whoCan(org, {
        action: String(body.action),
        resource: body.resource ? String(body.resource) : undefined,
        context: body.context && typeof body.context === 'object' ? body.context : {},
      }),
      caveat: 'Models identity + group + role-trust only. SCPs, permission boundaries and session policies are not evaluated.',
    };
  },

  'POST /api/org/reach-admin': async (body) => {
    if (!body.snapshot || typeof body.snapshot !== 'object') throw new Error('Provide an account snapshot');
    const org = buildOrg(body.snapshot);
    return {
      principals: org.principals.length,
      results: reachAdmin(org),
      caveat: 'Escalation catalogue (self-admin, become-user, become-role incl. pass-role variants) + transitive assume-role chains. Not evaluated: SCPs, permission boundaries, session policies, and instance-profile / SSM-command paths that need live instance data.',
    };
  },

  // Resource policies (KMS key / S3 bucket / similar) that grant a foreign
  // account or the public. Reported as findings only — deliberately NOT modelled
  // as reach-admin paths, since the foreign principal's permissions are unknown.
  'POST /api/org/resource-exposure': async (body) => {
    if (!body.snapshot || typeof body.snapshot !== 'object') throw new Error('Provide an account snapshot');
    const org = buildOrg(body.snapshot);
    return {
      accountId: org.accountId,
      supplied: org.resourcePolicies.length,
      findings: analyzeResourcePolicies(org.resourcePolicies, org.accountId),
      caveat: 'Only resource policies supplied in the snapshot are scanned. Not evaluated: SCPs, permission boundaries, session policies, instance-profile / SSM-command paths. External grants are reported as exposures, not reach-admin paths.',
    };
  },

  'POST /api/compare': async (body) => {
    const before = analyze([{ name: body.beforeName || 'before.json', text: String(body.before || '') }]);
    const after = analyze([{ name: body.afterName || 'after.json', text: String(body.after || '') }]);
    const bk = new Map(before.findings.map((f) => [findingKey(f), f]));
    const ak = new Map(after.findings.map((f) => [findingKey(f), f]));
    const introduced = after.findings.filter((f) => !bk.has(findingKey(f)));
    const resolved = before.findings.filter((f) => !ak.has(findingKey(f)));
    const worst = (list) => list.reduce((m, f) => Math.min(m, SEV_ORDER[f.severity]), 9);
    let verdict;
    if (!introduced.length && !resolved.length) verdict = 'No change in findings between the two versions.';
    else if (introduced.length && worst(introduced) <= 1) verdict = '⚠ The change INTRODUCES high/critical-severity risk.';
    else if (!introduced.length && resolved.length) verdict = '✓ The change strictly reduces risk.';
    else verdict = 'The change alters the risk profile — review both lists below.';
    return {
      verdict,
      introduced, resolved,
      beforeCounts: counts(before.findings),
      afterCounts: counts(after.findings),
      beforeStatements: publicStatements(before.model),
      afterStatements: publicStatements(after.model),
    };
  },

  'POST /api/change/review': async (body) => {
    const review = reviewChange({
      before: body.before,
      after: body.after,
      request: {
        action: body.action,
        resource: body.resource,
        context: body.context,
      },
    });
    const out = { ...review, ai: null, aiEvaluation: null, aiError: null };
    if (body.useAI !== false && aiAvailable()) {
      const ai = await explainChangeAI({
        review,
        redactIdentifiers: body.redactIdentifiers !== false,
      });
      if (ai?.text) {
        const evaluation = evaluateExplanation({
          text: ai.text,
          facts: ai.facts,
          expectedStatus: review.verdict.status,
        });
        out.aiEvaluation = evaluation;
        if (evaluation.passed) out.ai = { text: ai.text, model: ai.model };
        else out.aiError = 'The model explanation failed the grounding gate, so PolicyLens withheld it.';
      } else if (ai?.error) out.aiError = ai.error;
    }
    return out;
  },

  'POST /api/change/verify': async (body) => verifyCorrection({
    proposed: body.proposed,
    candidate: body.candidate,
    riskRequest: body.riskRequest,
    requiredAccess: Array.isArray(body.requiredAccess) ? body.requiredAccess : [],
  }),
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const key = `${req.method} ${url.pathname}`;
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim()
    || req.socket.remoteAddress
    || 'unknown';

  // Hosted demos get a soft POST throttle (GET demo stays free).
  if (HOSTED && req.method === 'POST' && !rateOk(ip)) {
    return send(res, 429, { error: 'Too many requests — try again in a minute.' });
  }

  try {
    if (routes[key]) {
      const body = req.method === 'POST' ? await readBody(req) : null;
      const result = await routes[key](body);
      return send(res, 200, result);
    }

    if (req.method === 'GET' && url.pathname.startsWith('/samples/')) {
      const name = path.basename(url.pathname); // strips any traversal
      const file = path.join(SAMPLES, name);
      if (!file.startsWith(SAMPLES) || !fs.existsSync(file)) return send(res, 404, { error: 'Not found' });
      return send(res, 200, fs.readFileSync(file), 'application/json; charset=utf-8');
    }

    if (req.method === 'GET') {
      const rel = url.pathname === '/' ? '/index.html' : url.pathname;
      const file = path.join(PUB, path.normalize(rel));
      if (file.startsWith(PUB) && fs.existsSync(file) && fs.statSync(file).isFile()) {
        return send(res, 200, fs.readFileSync(file), MIME[path.extname(file)] || 'application/octet-stream');
      }
      return send(res, 404, { error: 'Not found' });
    }

    return send(res, 404, { error: 'Not found' });
  } catch (e) {
    return send(res, 400, { error: e.message });
  }
});

server.listen(PORT, HOST, () => {
  const where = HOST === '0.0.0.0' || HOST === '::'
    ? `http://localhost:${PORT}  (listening on ${HOST} — LAN/tunnel reachable)`
    : `http://${HOST}:${PORT}`;
  console.log(`
  ┌──────────────────────────────────────────────────────┐
  │  PolicyLens — ask IAM questions, get cited answers     │
  │                                                       │
  │  ${where.padEnd(51)}│
  │  Mode: ${(HOSTED ? 'HOSTED public demo' : 'local').padEnd(44)}│
  │                                                       │
  │  AI layer: ${aiAvailable() ? `ENABLED (${MODEL})`.padEnd(41) : 'disabled — set ANTHROPIC_API_KEY to enable'.padEnd(41)} │
  │  Hosted demo: /?demo=1  →  GET /api/demo/run          │
  └──────────────────────────────────────────────────────┘`);
});
