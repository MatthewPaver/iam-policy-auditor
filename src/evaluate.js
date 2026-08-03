'use strict';

// Condition-aware AWS policy evaluation.
//
// This implements AWS's actual decision algorithm for a single account's
// identity+resource policies: explicit Deny overrides everything, otherwise an
// Allow is required, otherwise implicit deny. Crucially it EVALUATES the
// Condition block against a request context instead of merely noting that a
// condition exists — so an answer can say "allowed ONLY when aws:SourceIp is in
// 10.0.0.0/8" rather than guessing.
//
// Scope + honesty: this is a faithful reimplementation of the documented
// semantics, not a formal solver. It does NOT model SCPs, permission
// boundaries, session policies, or cross-account resource-policy interplay.
// For authoritative decisions the roadmap routes to IAM Access Analyzer /
// policy simulator; this engine is the fast, offline, explainable first pass.

const { globMatch } = require('./util');

// --- condition operators ---------------------------------------------------
// Each operator: (policyValues[], contextValue) -> boolean, matching one key.
// AWS semantics: multiple values under one key are OR'd; multiple keys AND'd.

const ipInCidr = (ip, cidr) => {
  const v4 = (s) => {
    const p = s.split('.');
    if (p.length !== 4) return null;
    let n = 0;
    for (const o of p) { const x = Number(o); if (!(x >= 0 && x <= 255)) return null; n = (n * 256) + x; }
    return n >>> 0;
  };
  if (!cidr.includes('/')) return v4(ip) === v4(cidr);
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const b = v4(base); const a = v4(ip);
  if (a == null || b == null || !(bits >= 0 && bits <= 32)) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
};

const toDate = (v) => {
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
};

const OPS = {
  StringEquals: (pv, cv) => pv.some((p) => p === cv),
  StringNotEquals: (pv, cv) => !pv.some((p) => p === cv),
  StringEqualsIgnoreCase: (pv, cv) => pv.some((p) => String(p).toLowerCase() === String(cv).toLowerCase()),
  StringNotEqualsIgnoreCase: (pv, cv) => !pv.some((p) => String(p).toLowerCase() === String(cv).toLowerCase()),
  StringLike: (pv, cv) => pv.some((p) => globMatch(p, cv)),
  StringNotLike: (pv, cv) => !pv.some((p) => globMatch(p, cv)),
  Bool: (pv, cv) => pv.some((p) => String(p) === String(cv)),
  Null: (pv, cv, present) => pv.some((p) => (String(p) === 'true') === !present),
  IpAddress: (pv, cv) => pv.some((p) => ipInCidr(cv, p)),
  NotIpAddress: (pv, cv) => !pv.some((p) => ipInCidr(cv, p)),
  ArnEquals: (pv, cv) => pv.some((p) => globMatch(p, cv)),
  ArnLike: (pv, cv) => pv.some((p) => globMatch(p, cv)),
  ArnNotEquals: (pv, cv) => !pv.some((p) => globMatch(p, cv)),
  ArnNotLike: (pv, cv) => !pv.some((p) => globMatch(p, cv)),
  NumericEquals: (pv, cv) => pv.some((p) => Number(p) === Number(cv)),
  NumericNotEquals: (pv, cv) => !pv.some((p) => Number(p) === Number(cv)),
  NumericLessThan: (pv, cv) => pv.some((p) => Number(cv) < Number(p)),
  NumericLessThanEquals: (pv, cv) => pv.some((p) => Number(cv) <= Number(p)),
  NumericGreaterThan: (pv, cv) => pv.some((p) => Number(cv) > Number(p)),
  NumericGreaterThanEquals: (pv, cv) => pv.some((p) => Number(cv) >= Number(p)),
  DateEquals: (pv, cv) => pv.some((p) => toDate(p) === toDate(cv)),
  DateLessThan: (pv, cv) => pv.some((p) => toDate(cv) < toDate(p)),
  DateLessThanEquals: (pv, cv) => pv.some((p) => toDate(cv) <= toDate(p)),
  DateGreaterThan: (pv, cv) => pv.some((p) => toDate(cv) > toDate(p)),
  DateGreaterThanEquals: (pv, cv) => pv.some((p) => toDate(cv) >= toDate(p)),
};

const asArr = (x) => (Array.isArray(x) ? x : [x]);

// Evaluate one Condition block against a context.
// Returns { result: true|false|'unknown', unmet: [...], missingKeys: [...] }.
// 'unknown' when a required key is absent from the context and the operator is
// not *IfExists / Null — we must not silently assume it passes or fails.
function evaluateCondition(condition, context) {
  if (!condition) return { result: true, unmet: [], missingKeys: [] };
  const unmet = [];
  const missingKeys = [];
  let sawUnknown = false;

  for (const [rawOp, keyMap] of Object.entries(condition)) {
    let op = rawOp;
    let ifExists = false;
    let setQuantifier = null;
    if (op.endsWith('IfExists')) { ifExists = true; op = op.slice(0, -'IfExists'.length); }
    if (op.startsWith('ForAllValues:')) { setQuantifier = 'all'; op = op.slice('ForAllValues:'.length); }
    else if (op.startsWith('ForAnyValue:')) { setQuantifier = 'any'; op = op.slice('ForAnyValue:'.length); }

    const fn = OPS[op];
    for (const [key, policyValRaw] of Object.entries(keyMap)) {
      const policyVals = asArr(policyValRaw).map(String);
      const present = Object.prototype.hasOwnProperty.call(context, key);

      if (op === 'Null') { // Null takes present-state, not the value
        if (!OPS.Null(policyVals, undefined, present)) unmet.push(`${rawOp} ${key}`);
        continue;
      }
      if (!present) {
        if (ifExists) continue; // IfExists: absent key passes
        missingKeys.push(key);
        sawUnknown = true;
        continue;
      }
      if (!fn) { sawUnknown = true; unmet.push(`${rawOp} (operator not modeled)`); continue; }

      const ctxVals = asArr(context[key]).map(String);
      let ok;
      if (setQuantifier === 'all') ok = ctxVals.every((cv) => fn(policyVals, cv, present));
      else ok = ctxVals.some((cv) => fn(policyVals, cv, present)); // default + ForAnyValue
      if (!ok) unmet.push(`${rawOp} ${key}=${JSON.stringify(policyValRaw)}`);
    }
  }

  if (unmet.length) return { result: false, unmet, missingKeys };
  if (sawUnknown) return { result: 'unknown', unmet: [], missingKeys };
  return { result: true, unmet: [], missingKeys };
}

// --- statement / request matching ------------------------------------------

function matchesAction(stmt, action) {
  if (stmt.notActions.length) return !stmt.notActions.some((p) => globMatch(p, action));
  return stmt.actions.some((p) => globMatch(p, action));
}

function matchesResource(stmt, resource) {
  if (!resource) return true; // caller didn't scope to a resource
  if (stmt.notResources.length) return !stmt.notResources.some((p) => globMatch(p, resource));
  if (!stmt.resources.length) return stmt.kind === 'identity'; // identity stmt w/o Resource is unusual; treat as none
  return stmt.resources.some((p) => globMatch(p, resource));
}

// Evaluate whether `request` is allowed by the AWS statements in `model`.
// request = { action, resource?, context?: {conditionKey: value|[values]} }
function evaluateRequest(model, request) {
  const context = request.context || {};
  const stmts = model.statements.filter((s) => s.provider === 'aws');
  const allowMatches = [];
  const denyMatches = [];
  const conditionalAllows = [];
  const unknowns = [];

  for (const s of stmts) {
    if (!matchesAction(s, request.action)) continue;
    if (!matchesResource(s, request.resource)) continue;
    const cond = evaluateCondition(s.conditions, context);
    const rec = { id: s.id, doc: s.doc, line: s.line, sid: s.sid, condition: s.conditions, cond };

    if (s.effect === 'Deny') {
      if (cond.result === true) denyMatches.push(rec);
      else if (cond.result === 'unknown') { rec.note = `Deny applies unless condition keys are provided (${cond.missingKeys.join(', ')})`; unknowns.push({ ...rec, effect: 'Deny' }); }
      continue;
    }
    // Allow
    if (cond.result === true) allowMatches.push(rec);
    else if (cond.result === 'unknown') { rec.note = `Allow depends on unprovided condition keys: ${cond.missingKeys.join(', ')}`; conditionalAllows.push(rec); unknowns.push({ ...rec, effect: 'Allow' }); }
    // cond.result === false → statement does not apply under this context
  }

  let decision;
  if (denyMatches.length) decision = 'ExplicitDeny';
  else if (allowMatches.length) decision = 'Allow';
  else if (conditionalAllows.length) decision = 'ConditionalAllow';
  else decision = 'ImplicitDeny';

  return {
    action: request.action,
    resource: request.resource || '*',
    decision,
    allowMatches,
    denyMatches,
    conditionalAllows,
    unknowns,
    explanation: explain(decision, { allowMatches, denyMatches, conditionalAllows }),
  };
}

function explain(decision, m) {
  const cite = (r) => `[${r.id} · ${r.doc}:${r.line}]`;
  if (decision === 'ExplicitDeny') return `Denied — explicit Deny in ${m.denyMatches.map(cite).join(', ')} overrides any Allow.`;
  if (decision === 'Allow') return `Allowed by ${m.allowMatches.map(cite).join(', ')} with all conditions satisfied by the given context.`;
  if (decision === 'ConditionalAllow') return `Allowed ONLY if the condition holds — ${m.conditionalAllows.map((r) => `${cite(r)} requires ${JSON.stringify(r.condition)}`).join('; ')}. Provide the condition keys to resolve.`;
  return 'Implicitly denied — no statement allows this action/resource under the given context.';
}

module.exports = { evaluateRequest, evaluateCondition, ipInCidr, OPS };
