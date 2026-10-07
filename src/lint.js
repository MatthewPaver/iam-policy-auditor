'use strict';

/**
 * Lightweight policy preflight — parliament-style grammar/sanity checks
 * without pulling in a Python dependency. Catches the mistakes that make
 * the rest of the engine look "wrong" when the JSON was already broken.
 *
 * We only inspect the normalised statement model the
 * parser already produced, so line numbers stay honest.
 */

const KNOWN_CONDITION_OPS = new Set([
  'StringEquals', 'StringNotEquals', 'StringEqualsIgnoreCase', 'StringNotEqualsIgnoreCase',
  'StringLike', 'StringNotLike',
  'NumericEquals', 'NumericNotEquals', 'NumericLessThan', 'NumericLessThanEquals',
  'NumericGreaterThan', 'NumericGreaterThanEquals',
  'DateEquals', 'DateNotEquals', 'DateLessThan', 'DateLessThanEquals',
  'DateGreaterThan', 'DateGreaterThanEquals',
  'Bool', 'Null',
  'IpAddress', 'NotIpAddress',
  'ArnEquals', 'ArnNotEquals', 'ArnLike', 'ArnNotLike',
  'BinaryEquals',
]);

const ARN_RE = /^arn:(aws|aws-cn|aws-us-gov):[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:.+/i;

function lintModel(model) {
  const findings = [];
  if (!model || !Array.isArray(model.statements)) return findings;

  for (const s of model.statements) {
    if (s.provider && s.provider !== 'aws') continue;

    if (!s.effect || (s.effect !== 'Allow' && s.effect !== 'Deny')) {
      findings.push(make(model, s, 'LINT-EFFECT', 'high',
        'Statement has a missing or invalid Effect',
        `Effect must be Allow or Deny (got \`${JSON.stringify(s.effect)}\`).`,
        'Set `"Effect": "Allow"` or `"Effect": "Deny"`.',
      ));
    }

    const acts = [...(s.actions || []), ...(s.notActions || [])];
    if (!acts.length) {
      findings.push(make(model, s, 'LINT-NO-ACTION', 'high',
        'Statement has no Action / NotAction',
        'IAM will not match this statement to any request.',
        'Add at least one Action (or NotAction).',
      ));
    }

    for (const a of acts) {
      if (a === '*' || (typeof a === 'string' && a.endsWith(':*'))) continue;
      if (typeof a !== 'string' || !/^[a-z0-9-]+:[A-Za-z0-9*_]+$/.test(a)) {
        findings.push(make(model, s, 'LINT-BAD-ACTION', 'medium',
          `Suspicious action name: ${a}`,
          'AWS actions look like `service:Verb` (e.g. `s3:GetObject`).',
          'Check spelling against the AWS service authorization reference.',
        ));
      }
    }

    for (const r of (s.resources || [])) {
      if (r === '*') continue;
      if (typeof r === 'string' && r.startsWith('arn:') && !ARN_RE.test(r)) {
        findings.push(make(model, s, 'LINT-BAD-ARN', 'high',
          `Malformed resource ARN: ${r}`,
          'ARN shape should be `arn:partition:service:region:account:resource`.',
          'Fix the ARN or use `"*"` only when intentionally broad.',
        ));
      }
    }

    const cond = s.conditions || null;
    if (cond && typeof cond === 'object') {
      for (const op of Object.keys(cond)) {
        const base = op.replace(/IfExists$/, '').replace(/^For(All|Any)Values:/, '');
        if (!KNOWN_CONDITION_OPS.has(base) && !KNOWN_CONDITION_OPS.has(op)) {
          findings.push(make(model, s, 'LINT-BAD-CONDITION-OP', 'medium',
            `Unknown condition operator: ${op}`,
            'Typos here silently fail open or closed depending on evaluation path.',
            'Use a documented IAM condition operator (`StringEquals`, `IpAddress`, …).',
          ));
        }
      }
    }

    const allActions = (s.actions || []).includes('*');
    const allResources = (s.resources || []).includes('*');
    if (s.effect === 'Allow' && allActions && allResources && !cond) {
      findings.push(make(model, s, 'LINT-ADMIN-STAR', 'critical',
        'Unconditional Allow on Action * and Resource *',
        'This is effectively AdministratorAccess with no guardrails.',
        'Scope Action and Resource, or add a Condition that actually constrains callers.',
      ));
    }
  }

  return findings;
}

function make(model, stmt, ruleId, severity, title, description, remediationSummary) {
  const doc = (model.documents || []).find((d) => d.name === stmt.doc);
  const from = stmt.line || 1;
  const end = stmt.endLine || from;
  const to = Math.min(end, from + 13);
  const snippet = doc && Array.isArray(doc.lines)
    ? doc.lines.slice(from - 1, to).join('\n')
    : '';
  return {
    ruleId,
    severity,
    title,
    description,
    statements: stmt.id ? [stmt.id] : [],
    evidence: [{
      doc: stmt.doc || 'policy.json',
      line: from,
      endLine: end,
      snippet,
      truncated: to < end,
    }],
    remediation: { summary: remediationSummary },
    category: 'preflight',
  };
}

module.exports = { lintModel, KNOWN_CONDITION_OPS };
