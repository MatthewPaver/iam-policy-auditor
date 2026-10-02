'use strict';

// A focused pre-merge workflow for one question:
// "Did this IAM change introduce a sensitive access path, and does the
// proposed correction close it without removing access we still need?"
//
// This module deliberately keeps the decision path deterministic. An LLM may
// explain this result, but it cannot change the verdict.

const { analyzeDocuments, publicStatements } = require('./engine');
const { evaluateRequest } = require('./evaluate');
const { runRules, SEV_ORDER } = require('./rules');
const { lintModel } = require('./lint');

const DECISION_RANK = {
  ExplicitDeny: 0,
  ImplicitDeny: 0,
  ConditionalAllow: 1,
  Allow: 2,
};

function analyzePolicy(name, text) {
  const model = analyzeDocuments([{ name, text: String(text || '') }]);
  const doc = model.documents[0];
  if (!doc || doc.error) throw new Error(`${name}: ${doc?.error || 'could not parse policy'}`);
  if (doc.provider !== 'aws') throw new Error(`${name}: change review currently supports AWS IAM JSON only`);
  const findings = [...lintModel(model), ...runRules(model)]
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  return { model, findings };
}

function findingKey(finding) {
  return `${finding.ruleId}|${finding.title}`;
}

function decisionRank(decision) {
  return DECISION_RANK[decision] ?? -1;
}

function isPermitted(decision) {
  return decision === 'Allow' || decision === 'ConditionalAllow';
}

function normalizeRequest(request = {}) {
  const action = String(request.action || '').trim();
  if (!action) throw new Error('Provide the sensitive action to review, for example rds:DeleteDBInstance');
  return {
    action,
    resource: request.resource ? String(request.resource) : undefined,
    context: request.context && typeof request.context === 'object' ? request.context : {},
  };
}

function diffFindings(before, after) {
  const beforeKeys = new Set(before.map(findingKey));
  const afterKeys = new Set(after.map(findingKey));
  return {
    introduced: after.filter((finding) => !beforeKeys.has(findingKey(finding))),
    resolved: before.filter((finding) => !afterKeys.has(findingKey(finding))),
  };
}

function buildVerdict({ beforeDecision, afterDecision, introduced }) {
  const broadened = decisionRank(afterDecision) > decisionRank(beforeDecision);
  const severe = introduced.some((finding) => ['critical', 'high'].includes(finding.severity));
  const conditional = afterDecision === 'ConditionalAllow';

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
      reason: 'The result depends on condition keys that were not supplied.',
    };
  }
  return {
    status: 'pass',
    label: 'No checked access increase',
    reason: 'The checked request is not broader and no new high or critical finding was introduced.',
  };
}

function reviewChange({ before, after, request }) {
  const checkedRequest = normalizeRequest(request);
  const beforePolicy = analyzePolicy('before.json', before);
  const afterPolicy = analyzePolicy('after.json', after);
  const beforeEvaluation = evaluateRequest(beforePolicy.model, checkedRequest);
  const afterEvaluation = evaluateRequest(afterPolicy.model, checkedRequest);
  const findings = diffFindings(beforePolicy.findings, afterPolicy.findings);
  const verdict = buildVerdict({
    beforeDecision: beforeEvaluation.decision,
    afterDecision: afterEvaluation.decision,
    introduced: findings.introduced,
  });

  return {
    verdict,
    request: { ...checkedRequest, resource: checkedRequest.resource || '*' },
    access: {
      before: beforeEvaluation,
      after: afterEvaluation,
      broadened: decisionRank(afterEvaluation.decision) > decisionRank(beforeEvaluation.decision),
    },
    findings,
    evidence: [
      ...afterEvaluation.allowMatches,
      ...afterEvaluation.conditionalAllows,
      ...afterEvaluation.denyMatches,
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
      'A pass means no increase for the checked request and rule set. It is not a proof that the policy is safe.',
    ],
  };
}

function verifyCorrection({ proposed, candidate, riskRequest, requiredAccess = [] }) {
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
      preserved: !isPermitted(before.decision) || isPermitted(after.decision),
    };
  });

  const riskClosed = isPermitted(proposedRisk.decision) && !isPermitted(candidateRisk.decision);
  const requiredPreserved = preservation.every((item) => item.preserved);
  return {
    verified: riskClosed && requiredPreserved,
    riskClosed,
    requiredPreserved,
    risk: { proposed: proposedRisk, candidate: candidateRisk },
    preservation,
    candidateFindings: candidatePolicy.findings,
    limits: [
      'Verification covers the declared risk request and required-access checks only.',
      'Production approval still needs the organization controls omitted from this local model.',
    ],
  };
}

module.exports = {
  reviewChange,
  verifyCorrection,
  analyzePolicy,
  decisionRank,
  isPermitted,
};
