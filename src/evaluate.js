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
  // IAM accepts Unix epoch seconds as well as ISO dates. Date.parse('0')
  // means January 2000 in JavaScript, not the Unix epoch.
  if (/^[+-]?\d+(?:\.\d+)?$/.test(String(v))) {
    const epoch = Number(v) * 1000;
    return Number.isFinite(epoch) && Math.abs(epoch) <= 8.64e15 ? epoch : null;
  }
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
  DateNotEquals: (pv, cv) => !pv.some((p) => toDate(p) === toDate(cv)),
  DateLessThan: (pv, cv) => pv.some((p) => toDate(cv) < toDate(p)),
  DateLessThanEquals: (pv, cv) => pv.some((p) => toDate(cv) <= toDate(p)),
  DateGreaterThan: (pv, cv) => pv.some((p) => toDate(cv) > toDate(p)),
  DateGreaterThanEquals: (pv, cv) => pv.some((p) => toDate(cv) >= toDate(p)),
};

const asArr = (x) => (Array.isArray(x) ? x : [x]);

// Evaluate one Condition block against a context.
// Returns { result: true|false|'unknown', unmet: [...], missingKeys: [...] }.
// 'unknown' when request information or operator semantics are unresolved.
// Only contextComplete=true declares omitted keys actually absent, including
// for IfExists / Null. Incomplete input must not silently pass or fail.
function evaluateCondition(condition, context, contextComplete = false) {
  if (!condition) return { result: true, unmet: [], missingKeys: [] };
  const unmet = [];
  const missingKeys = [];
  const unsupportedOperators = [];
  const invalidValues = [];
  let sawUnknown = false;

  for (const [rawOp, keyMap] of Object.entries(condition)) {
    let op = rawOp;
    let ifExists = false;
    let setQuantifier = null;
    if (op.endsWith('IfExists')) { ifExists = true; op = op.slice(0, -'IfExists'.length); }
    if (op.startsWith('ForAllValues:')) { setQuantifier = 'all'; op = op.slice('ForAllValues:'.length); }
    else if (op.startsWith('ForAnyValue:')) { setQuantifier = 'any'; op = op.slice('ForAnyValue:'.length); }

    const fn = OPS[op];
    if (!Object.prototype.hasOwnProperty.call(OPS, op)) {
      unsupportedOperators.push(rawOp);
      sawUnknown = true;
      continue;
    }
    for (const [key, policyValRaw] of Object.entries(keyMap)) {
      const policyVals = asArr(policyValRaw).map(String);
      const present = Object.prototype.hasOwnProperty.call(context, key);

      // An omitted input is missing knowledge unless the caller explicitly
      // declares a complete request context. This also applies to Null/IfExists.
      if (!present && !contextComplete) {
        missingKeys.push(key);
        sawUnknown = true;
        continue;
      }

      if (op === 'Null') { // Null takes present-state, not the value
        if (!OPS.Null(policyVals, undefined, present)) unmet.push(`${rawOp} ${key}`);
        continue;
      }
      if (!present) {
        if (ifExists) continue; // IfExists: absent key passes
        // AWS set operators and negated operators have defined absence rules.
        const absentMatches = setQuantifier === 'all'
          || (setQuantifier !== 'any' && /^(StringNot|ArnNot|NumericNot|DateNot|NotIp)/.test(op));
        if (!absentMatches) unmet.push(`${rawOp} ${key} (key absent)`);
        continue;
      }

      const ctxVals = asArr(context[key]).map(String);
      if (op.startsWith('Date') && [...policyVals, ...ctxVals].some(value => toDate(value) === null)) {
        invalidValues.push(`${rawOp} ${key} (invalid date)`);
        sawUnknown = true;
        continue;
      }
      let ok;
      if (setQuantifier === 'all') ok = ctxVals.every((cv) => fn(policyVals, cv, present));
      else ok = ctxVals.some((cv) => fn(policyVals, cv, present)); // default + ForAnyValue
      if (!ok) unmet.push(`${rawOp} ${key}=${JSON.stringify(policyValRaw)}`);
    }
  }

  const details = { unmet, missingKeys, unsupportedOperators, invalidValues };
  if (unmet.length) return { result: false, ...details };
  if (sawUnknown) return { result: 'unknown', ...details };
  return { result: true, ...details };
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
// request = { action, resource?, context?: {conditionKey: value|[values]}, contextComplete?: boolean }
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
    const cond = evaluateCondition(s.conditions, context, request.contextComplete === true);
    const rec = { id: s.id, doc: s.doc, line: s.line, sid: s.sid, condition: s.conditions, cond };

    if (s.effect === 'Deny') {
      if (cond.result === true) denyMatches.push(rec);
      else if (cond.result === 'unknown') { rec.note = 'This Deny may apply; resolve missing context or unsupported conditions before relying on access.'; unknowns.push({ ...rec, effect: 'Deny' }); }
      continue;
    }
    // Allow
    if (cond.result === true) allowMatches.push(rec);
    else if (cond.result === 'unknown') { rec.note = 'This Allow depends on unresolved context or condition semantics.'; conditionalAllows.push(rec); unknowns.push({ ...rec, effect: 'Allow' }); }
    // cond.result === false → statement does not apply under this context
  }

  let decision;
  if (denyMatches.length) decision = 'ExplicitDeny';
  else if ((allowMatches.length || conditionalAllows.length) && unknowns.some(item => item.effect === 'Deny')) decision = 'ConditionalAllow';
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
    explanation: explain(decision, { allowMatches, denyMatches, conditionalAllows, unknowns }),
  };
}

function explain(decision, m) {
  const cite = (r) => `[${r.id} · ${r.doc}:${r.line}]`;
  if (decision === 'ExplicitDeny') return `Denied — explicit Deny in ${m.denyMatches.map(cite).join(', ')} overrides any Allow.`;
  if (decision === 'Allow') return `Allowed by ${m.allowMatches.map(cite).join(', ')} with all conditions satisfied by the given context.`;
  if (decision === 'ConditionalAllow') return `Not determined — ${m.unknowns.map((r) => `${r.effect} ${cite(r)} depends on ${JSON.stringify(r.condition)}`).join('; ')}. Supply missing context and resolve unsupported or invalid conditions before relying on this result.`;
  return 'Implicitly denied — no statement allows this action/resource under the given context.';
}

module.exports = { evaluateRequest, evaluateCondition, ipInCidr, OPS };
