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
    for (const o of p) { const x = Number(o); if (!/^\d{1,3}$/.test(o) || !(x >= 0 && x <= 255)) return null; n = (n * 256) + x; }
    return n >>> 0;
  };
  if (!cidr.includes('/')) {
    const a = v4(ip), b = v4(cidr);
    return a === null || b === null ? null : a === b;
  }
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const b = v4(base); const a = v4(ip);
  if (a == null || b == null || cidr.split('/').length !== 2 || !/^\d+$/.test(bitsRaw) || !Number.isInteger(bits) || !(bits >= 0 && bits <= 32)) return null;
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
  // Keep unsupported date formats unresolved rather than using host-local time.
  const iso = String(v).match(/^(\d{4})-(\d{2})-(\d{2})(?:T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d{1,3})?)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d))?$/);
  if (!iso) return null;
  const day = new Date(0);
  day.setUTCFullYear(Number(iso[1]), Number(iso[2]) - 1, Number(iso[3]));
  if (day.getUTCFullYear() !== Number(iso[1]) || day.getUTCMonth() !== Number(iso[2]) - 1 || day.getUTCDate() !== Number(iso[3])) return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
};

const arnParts = value => {
  const parts = String(value).split(':');
  return parts.length < 6 ? null : [...parts.slice(0, 5), parts.slice(5).join(':')];
};
const arnMatch = (pattern, value) => arnParts(pattern).every((part, index) => globMatch(part, arnParts(value)[index], true));

const OPS = {
  StringEquals: (pv, cv) => pv.some((p) => p === cv),
  StringNotEquals: (pv, cv) => !pv.some((p) => p === cv),
  StringEqualsIgnoreCase: (pv, cv) => pv.some((p) => String(p).toLowerCase() === String(cv).toLowerCase()),
  StringNotEqualsIgnoreCase: (pv, cv) => !pv.some((p) => String(p).toLowerCase() === String(cv).toLowerCase()),
  StringLike: (pv, cv) => pv.some((p) => globMatch(p, cv, true)),
  StringNotLike: (pv, cv) => !pv.some((p) => globMatch(p, cv, true)),
  Bool: (pv, cv) => pv.some((p) => String(p) === String(cv)),
  Null: (pv, cv, present) => pv.some((p) => (String(p) === 'true') === !present),
  IpAddress: (pv, cv) => pv.some((p) => ipInCidr(cv, p)),
  NotIpAddress: (pv, cv) => !pv.some((p) => ipInCidr(cv, p)),
  ArnEquals: (pv, cv) => pv.some((p) => arnMatch(p, cv)),
  ArnLike: (pv, cv) => pv.some((p) => arnMatch(p, cv)),
  ArnNotEquals: (pv, cv) => !pv.some((p) => arnMatch(p, cv)),
  ArnNotLike: (pv, cv) => !pv.some((p) => arnMatch(p, cv)),
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
const validNumber = value => /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(value) && Number.isFinite(Number(value));

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
      if (op.startsWith('Numeric') && policyVals.some(value => !validNumber(value))) {
        invalidValues.push(`${rawOp} ${key} (invalid numeric policy value)`);
        sawUnknown = true;
        continue;
      }
      if ((op === 'Bool' || op === 'Null') && policyVals.some(value => !/^(true|false)$/.test(value))) {
        invalidValues.push(`${rawOp} ${key} (expected true or false)`);
        sawUnknown = true;
        continue;
      }
      const contextKeys = Object.keys(context).filter(item => item.toLowerCase() === key.toLowerCase());
      const present = contextKeys.length > 0;
      if (policyVals.some(value => value.includes('${')) || contextKeys.some(item => JSON.stringify(context[item]) !== JSON.stringify(context[contextKeys[0]]))) {
        invalidValues.push(`${rawOp} ${key} (unmodeled policy variable or ambiguous context keys)`);
        sawUnknown = true;
        continue;
      }

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

      const ctxVals = asArr(context[contextKeys[0]]).map(String);
      if ((op.startsWith('Numeric') && ctxVals.some(value => !validNumber(value)))
        || (op === 'Bool' && ctxVals.some(value => !/^(true|false)$/.test(value)))) {
        invalidValues.push(`${rawOp} ${key} (invalid numeric or boolean value)`);
        sawUnknown = true;
        continue;
      }
      if ((op === 'IpAddress' || op === 'NotIpAddress') && ctxVals.some(value => policyVals.some(pattern => ipInCidr(value, pattern) === null))) {
        invalidValues.push(`${rawOp} ${key} (IPv6 or invalid IPv4 range is not evaluated locally)`);
        sawUnknown = true;
        continue;
      }
      if (op.startsWith('Arn') && [...policyVals, ...ctxVals].some(value => !arnParts(value))) {
        invalidValues.push(`${rawOp} ${key} (unmodeled ARN format)`);
        sawUnknown = true;
        continue;
      }
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
  if ([...stmt.resources, ...stmt.notResources].some(pattern => pattern.includes('${'))) return 'unknown';
  if (stmt.notResources.length) return !stmt.notResources.some((p) => globMatch(p, resource, true));
  if (!stmt.resources.length) return stmt.kind === 'identity'; // identity stmt w/o Resource is unusual; treat as none
  return stmt.resources.some((p) => globMatch(p, resource, true));
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
    const resourceMatch = matchesResource(s, request.resource);
    if (!resourceMatch) continue;
    let cond = evaluateCondition(s.conditions, context, request.contextComplete === true);
    if (resourceMatch === 'unknown' && cond.result !== false) cond = { ...cond, result: 'unknown', invalidValues: [...(cond.invalidValues || []), 'Resource contains an unmodeled policy variable'] };
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
