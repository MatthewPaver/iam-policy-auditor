'use strict';

// A focused pre-merge workflow for one question:
// "Did this IAM change introduce a sensitive access path, and does the
// proposed correction close it without removing access we still need?"
//
// This module deliberately keeps the decision path deterministic. An LLM may
// explain this result, but it cannot change the verdict.

const engine = require('./engine_identity');
const { analyzeDocuments, publicStatements } = require('./engine');
const { evaluateRequest } = require('./evaluate');
const { runRules, SEV_ORDER } = require('./rules');
const { lintModel } = require('./lint');
const { normalizePolicyInput, ACCEPTED_FORMATS } = require('./adapters');
const actions = require('./actions');
const { listNewlyAllowed, verdictFromNewlyAllowed } = require('./newly_allowed');

const DECISION_RANK = {
  ExplicitDeny: 0,
  ImplicitDeny: 0,
  ConditionalAllow: 1,
  Allow: 2,
};

// Accept any shape normalizePolicyInput knows; evaluate every document together
// so a Deny in any of them still wins, matching how AWS merges attached policies.
function analyzePolicy(name, input) {
  const { documents } = normalizePolicyInput(input, name);
  const model = analyzeDocuments(documents);
  for (const doc of model.documents) {
    if (!doc || doc.error) throw new Error(`${doc?.name || name}: ${doc?.error || 'could not parse policy'}`);
    if (doc.provider !== 'aws') {
      // Re-use the adapter's wording so CLI / UI get one consistent sentence.
      throw new Error(`${doc.name || name}: Expected an IAM policy. Accepted formats: ${ACCEPTED_FORMATS.join('; ')}.`);
    }
  }
  const findings = [...lintModel(model), ...runRules(model)]
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  return { model, findings };
}

// Expand statement Action / NotAction patterns into a stable, sorted set.
// Prefer mutating actions when any exist so adding a pure read (PowerUserAccess
// v4→v5) does not look like a new finding; otherwise keep the full set so
// read-only widenings still show up.
function affectedActionSet(stmt) {
  const patterns = (stmt.notActions && stmt.notActions.length)
    ? stmt.notActions
    : (stmt.actions || []);
  const expanded = [];
  for (const pattern of patterns) {
    const { actions: list } = actions.expand(pattern, { cap: 100000 });
    // Keep catalogue casing until after isMutating — levels are keyed that way.
    if (list.length) expanded.push(...list);
    else expanded.push(String(pattern));
  }
  const mutating = expanded.filter((a) => actions.isMutating(a) === true);
  const chosen = mutating.length ? mutating : expanded;
  return [...new Set(chosen.map((a) => a.toLowerCase()))].sort();
}

function findingResources(finding, model) {
  const resources = [];
  for (const id of finding.statements || []) {
    const stmt = model.statements.find((statement) => statement.id === id);
    if (!stmt) continue;
    resources.push(...(stmt.resources || []).map((r) => String(r).toLowerCase()));
    resources.push(...(stmt.notResources || []).map((r) => `!${String(r).toLowerCase()}`));
  }
  return [...new Set(resources)].sort();
}

function findingActionSet(finding, model) {
  const set = new Set();
  for (const id of finding.statements || []) {
    const stmt = model.statements.find((statement) => statement.id === id);
    if (!stmt) continue;
    for (const action of affectedActionSet(stmt)) set.add(action);
  }
  return [...set].sort();
}

// Stable identity ignores action-set growth (that is `widened` instead).
function findingBaseKey(finding, model) {
  return `${finding.ruleId}|${findingResources(finding, model).join(',')}`;
}

function findingKey(finding, model) {
  return `${finding.ruleId}|${findingActionSet(finding, model).join(',')}|${findingResources(finding, model).join(',')}`;
}

function decisionRank(decision) {
  return DECISION_RANK[decision] ?? -1;
}

function isPermitted(decision) {
  return decision === 'Allow' || decision === 'ConditionalAllow';
}

function normalizeRequest(request = {}) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('Declare a request object with action and resource.');
  if (typeof request.action !== 'string' || !request.action.trim()) throw new Error('Provide the sensitive action to review, for example rds:DeleteDBInstance');
  if (typeof request.resource !== 'string' || !request.resource.trim()) throw new Error('Provide the exact resource or an explicit wildcard scope for the request.');
  const context = request.context === undefined ? {} : request.context;
  if (!context || typeof context !== 'object' || Array.isArray(context) || Object.getPrototypeOf(context) !== Object.prototype) throw new Error('Condition context must be a plain JSON object.');
  if (request.contextComplete !== undefined && typeof request.contextComplete !== 'boolean') throw new Error('contextComplete must be a boolean.');
  // principal is optional: 'anonymous', a 12-digit account id, or an IAM ARN.
  let principal;
  if (request.principal !== undefined && request.principal !== null) {
    if (typeof request.principal !== 'string' || !request.principal.trim()) {
      throw new Error('principal must be a non-empty string when provided.');
    }
    principal = request.principal.trim();
  }
  return {
    action: request.action.trim(),
    resource: request.resource.trim(),
    context,
    ...(principal !== undefined ? { principal } : {}),
    ...(request.contextComplete !== undefined ? { contextComplete: request.contextComplete } : {}),
  };
}

function diffFindings(before, after, beforeModel, afterModel) {
  // Match on ruleId + resources; action-set growth is reported as widened.
  const beforeByBase = new Map();
  for (const finding of before) {
    beforeByBase.set(findingBaseKey(finding, beforeModel), finding);
  }
  const afterByBase = new Map();
  for (const finding of after) {
    afterByBase.set(findingBaseKey(finding, afterModel), finding);
  }

  const introduced = [];
  const widened = [];
  for (const [base, afterFinding] of afterByBase) {
    const beforeFinding = beforeByBase.get(base);
    if (!beforeFinding) {
      introduced.push(afterFinding);
      continue;
    }
    const beforeActions = findingActionSet(beforeFinding, beforeModel);
    const afterActions = findingActionSet(afterFinding, afterModel);
    const beforeSet = new Set(beforeActions);
    // Pure growth (after has every before action, plus more) counts as widened.
    const isSuperset = beforeActions.every((action) => afterActions.includes(action))
      && afterActions.some((action) => !beforeSet.has(action));
    if (isSuperset) widened.push(afterFinding);
  }

  const resolved = before.filter((finding) => !afterByBase.has(findingBaseKey(finding, beforeModel)));
  return { introduced, resolved, widened };
}

function buildVerdict({ beforeDecision, afterDecision, introduced, widened = [] }) {
  const broadened = decisionRank(afterDecision) > decisionRank(beforeDecision);
  // Widened findings count as introduced for the verdict (same risk, bigger blast radius).
  const forVerdict = [...introduced, ...widened];
  const severe = forVerdict.some((finding) => ['critical', 'high'].includes(finding.severity));
  const conditional = beforeDecision === 'ConditionalAllow' || afterDecision === 'ConditionalAllow';

  if (broadened || severe) {
    return {
      status: 'stop',
      label: 'Stop and review',
      reason: broadened
        ? `The proposed policy broadens the checked request from ${beforeDecision} to ${afterDecision}.`
        : 'The proposed policy introduces a high or critical finding.',
    };
  }
  if (conditional) {
    return {
      status: 'review',
      label: 'Needs context',
      reason: 'The comparison depends on missing context or unsupported condition semantics.',
    };
  }
  return {
    status: 'pass',
    label: 'No checked access increase',
    reason: 'The checked request is not broader and no new high or critical finding was introduced.',
  };
}

function reviewChange({ before, after, request } = {}) {
  const beforePolicy = analyzePolicy('before.json', before);
  const afterPolicy = analyzePolicy('after.json', after);
  const findings = diffFindings(beforePolicy.findings, afterPolicy.findings, beforePolicy.model, afterPolicy.model);
  const newlyAllowed = listNewlyAllowed({
    beforeModel: beforePolicy.model,
    afterModel: afterPolicy.model,
  });

  // Request is optional: without one, the verdict comes from newlyAllowed alone.
  const hasRequest = request != null && request !== undefined
    && typeof request === 'object'
    && (request.action != null || request.resource != null);

  if (!hasRequest) {
    return {
      schemaVersion: 1,
      engine,
      verdict: verdictFromNewlyAllowed(newlyAllowed),
      request: null,
      access: null,
      findings,
      newlyAllowed,
      evidence: [],
      suggestedCorrections: findings.introduced
        .filter((finding) => finding.remediation)
        .map((finding) => ({
          ruleId: finding.ruleId,
          title: finding.title,
          summary: finding.remediation.summary,
          rewrite: finding.remediation.rewrite || null,
          evidence: finding.evidence,
        })),
      statements: {
        before: publicStatements(beforePolicy.model),
        after: publicStatements(afterPolicy.model),
      },
      limits: [
        'Only the supplied policy documents are evaluated.',
        'SCPs, permission boundaries, session policies, and cross-account resource-policy interplay are not evaluated.',
        'A pass means no sensitive newly allowed access under the local rule set. It does not prove the policy is safe.',
      ],
    };
  }

  const checkedRequest = normalizeRequest(request);
  const beforeEvaluation = evaluateRequest(beforePolicy.model, checkedRequest);
  const afterEvaluation = evaluateRequest(afterPolicy.model, checkedRequest);
  const verdict = buildVerdict({
    beforeDecision: beforeEvaluation.decision,
    afterDecision: afterEvaluation.decision,
    introduced: findings.introduced,
    widened: findings.widened,
  });

  return {
    schemaVersion: 1,
    engine,
    verdict,
    request: { ...checkedRequest, resource: checkedRequest.resource || '*' },
    access: {
      before: beforeEvaluation,
      after: afterEvaluation,
      broadened: decisionRank(afterEvaluation.decision) > decisionRank(beforeEvaluation.decision),
    },
    findings,
    newlyAllowed,
    evidence: [
      ...afterEvaluation.allowMatches,
      ...afterEvaluation.conditionalAllows,
      ...afterEvaluation.denyMatches,
      ...afterEvaluation.unknowns.filter(item => item.effect === 'Deny'),
    ],
    suggestedCorrections: findings.introduced
      .filter((finding) => finding.remediation)
      .map((finding) => ({
        ruleId: finding.ruleId,
        title: finding.title,
        summary: finding.remediation.summary,
        rewrite: finding.remediation.rewrite || null,
        evidence: finding.evidence,
      })),
    statements: {
      before: publicStatements(beforePolicy.model),
      after: publicStatements(afterPolicy.model),
    },
    limits: [
      'Only the supplied policy documents are evaluated.',
      'SCPs, permission boundaries, session policies, and cross-account resource-policy interplay are not evaluated.',
      'A pass means no increase for the checked request and rule set. It does not prove the policy is safe.',
    ],
  };
}

function verifyCorrection({ proposed, candidate, riskRequest, requiredAccess = [] }) {
  if (!Array.isArray(requiredAccess) || !requiredAccess.length) throw new Error('Declare at least one required-access request before verifying a correction.');
  const checkedRisk = normalizeRequest(riskRequest);
  const proposedPolicy = analyzePolicy('proposed.json', proposed);
  const candidatePolicy = analyzePolicy('candidate.json', candidate);
  const proposedRisk = evaluateRequest(proposedPolicy.model, checkedRisk);
  const candidateRisk = evaluateRequest(candidatePolicy.model, checkedRisk);

  const preservation = requiredAccess.map((request, index) => {
    const normalized = normalizeRequest(request);
    const before = evaluateRequest(proposedPolicy.model, normalized);
    const after = evaluateRequest(candidatePolicy.model, normalized);
    return {
      id: request.id || `required-${index + 1}`,
      request: { ...normalized, resource: normalized.resource || '*' },
      before,
      after,
      preserved: before.decision === 'Allow' && after.decision === 'Allow',
    };
  });

  const riskClosed = proposedRisk.decision === 'Allow' && ['ImplicitDeny', 'ExplicitDeny'].includes(candidateRisk.decision);
  const requiredPreserved = preservation.every((item) => item.preserved);
  const introducedSevere = diffFindings(proposedPolicy.findings, candidatePolicy.findings, proposedPolicy.model, candidatePolicy.model).introduced.filter(finding => ['high', 'critical'].includes(finding.severity));
  return {
    schemaVersion: 1,
    engine,
    verified: riskClosed && requiredPreserved && introducedSevere.length === 0,
    introducedSevere,
    riskClosed,
    requiredPreserved,
    risk: { proposed: proposedRisk, candidate: candidateRisk },
    preservation,
    candidateFindings: candidatePolicy.findings,
    limits: [
      'Verification covers the declared risk request and required-access checks only.',
      'Production approval still needs the organisation-level controls that this local model does not evaluate.',
    ],
  };
}

module.exports = {
  reviewChange,
  verifyCorrection,
  analyzePolicy,
  findingKey,
  diffFindings,
  decisionRank,
  isPermitted,
};
