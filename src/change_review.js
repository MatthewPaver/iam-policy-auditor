'use strict';

// A focused pre-merge workflow for one question:
// "Did this IAM change introduce a sensitive access path, and does the
// proposed correction close it without removing access we still need?"
//
// This module deliberately keeps the decision path deterministic. An LLM may
// explain this result, but it cannot change the verdict.

const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');
const { version: engineVersion } = require('../package.json');
const sourceHash = createHash('sha256');
for (const name of fs.readdirSync(__dirname).filter(name => name.endsWith('.js')).sort()) {
  sourceHash.update(name); sourceHash.update(fs.readFileSync(path.join(__dirname, name)));
}
const cataloguePath = path.join(__dirname, '..', 'data', 'aws-actions.json');
if (fs.existsSync(cataloguePath)) sourceHash.update(fs.readFileSync(cataloguePath));
const engine = { name: 'PolicyLens', version: engineVersion, sourceIdentity: sourceHash.digest('hex') };
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

function findingKey(finding, model) {
  const sources = (finding.statements || []).map(id => model.statements.find(statement => statement.id === id)).filter(Boolean).map(statement => JSON.stringify({ effect: statement.effect, actions: statement.actions, notActions: statement.notActions, resources: statement.resources, notResources: statement.notResources, conditions: statement.conditions, principals: statement.principals })).sort();
  return `${finding.ruleId}|${finding.title}|${sources.join('|')}`;
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
  return { action: request.action.trim(), resource: request.resource.trim(), context };
}

function diffFindings(before, after, beforeModel, afterModel) {
  const beforeKeys = new Set(before.map(finding => findingKey(finding, beforeModel)));
  const afterKeys = new Set(after.map(finding => findingKey(finding, afterModel)));
  return {
    introduced: after.filter((finding) => !beforeKeys.has(findingKey(finding, afterModel))),
    resolved: before.filter((finding) => !afterKeys.has(findingKey(finding, beforeModel))),
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
  const findings = diffFindings(beforePolicy.findings, afterPolicy.findings, beforePolicy.model, afterPolicy.model);
  const verdict = buildVerdict({
    beforeDecision: beforeEvaluation.decision,
    afterDecision: afterEvaluation.decision,
    introduced: findings.introduced,
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
  decisionRank,
  isPermitted,
};
