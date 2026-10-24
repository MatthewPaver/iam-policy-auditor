'use strict';

const assert = require('node:assert/strict');
const { analyzeDocuments } = require('../src/engine');
const { evaluateRequest, evaluateCondition } = require('../src/evaluate');
const { reviewChange, verifyCorrection } = require('../src/change_review');
const { lintModel } = require('../src/lint');

const read = { Sid: 'ReadReports', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/daily.csv' };
const destroy = { Sid: 'DeleteProduction', Effect: 'Allow', Action: 'rds:DeleteDBInstance', Resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1' };
const policy = (...Statement) => JSON.stringify({ Version: '2012-10-17', Statement });
const required = { action: read.Action, resource: read.Resource, context: {} };
const risk = { action: destroy.Action, resource: destroy.Resource, context: {} };
const model = text => analyzeDocuments([{ name: 'policy.json', text }]);
const mfaDeny = { ...read, Sid: 'DenyWithoutMfa', Effect: 'Deny', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } } };
const at = '2026-10-24T00:00:00Z';
const dateCondition = { DateNotEquals: { 'aws:CurrentTime': at } };
let checks = 0;
function check(name, run) {
  try { run(); checks++; }
  catch (error) { error.message = `${name}: ${error.message}`; throw error; }
}

check('a retained destructive grant with DateNotEquals cannot verify', () => {
  const result = verifyCorrection({ proposed: policy(read, destroy), candidate: policy(read, { ...destroy, Condition: dateCondition }), riskRequest: { ...risk, context: { 'aws:CurrentTime': '2026-10-23T00:00:00Z' } }, requiredAccess: [required] });
  assert.equal(result.risk.candidate.decision, 'Allow');
  assert.equal(result.riskClosed, false);
  assert.equal(result.verified, false);
});
check('unresolved Deny prevents required-access proof', () => {
  const result = verifyCorrection({ proposed: policy(read, mfaDeny, destroy), candidate: policy(read, mfaDeny), riskRequest: risk, requiredAccess: [required] });
  assert.equal(result.preservation[0].after.decision, 'ConditionalAllow');
  assert.equal(result.requiredPreserved, false);
  assert.equal(result.verified, false);
  assert.match(result.preservation[0].after.explanation, /DenyWithoutMfa|aws:MultiFactorAuthPresent/);
});
check('epoch zero must not be mistaken for January 2000 and falsely close risk', () => {
  const result = verifyCorrection({ proposed: policy(read, destroy), candidate: policy(read, { ...destroy, Condition: { DateNotEquals: { 'aws:CurrentTime': '0' } } }), riskRequest: { ...risk, context: { 'aws:CurrentTime': '2000-01-01T00:00:00Z' } }, requiredAccess: [required] });
  assert.equal(result.risk.candidate.decision, 'Allow');
  assert.equal(result.verified, false);
});
check('supplying MFA resolves preservation in both directions', () => {
  for (const [value, expected] of [['false', false], ['true', true]]) {
    const result = verifyCorrection({ proposed: policy(read, mfaDeny, destroy), candidate: policy(read, mfaDeny), riskRequest: risk, requiredAccess: [{ ...required, context: { 'aws:MultiFactorAuthPresent': value } }] });
    assert.equal(result.verified, expected);
  }
});
check('unsupported operators remain unknown for both effects', () => {
  for (const Effect of ['Allow', 'Deny']) {
    const unknown = { ...read, Effect, Condition: { BinaryEquals: { 'example:key': 'aGVsbG8=' } } };
    const result = evaluateRequest(model(policy(...(Effect === 'Deny' ? [read] : []), unknown)), { ...required, context: { 'example:key': 'aGVsbG8=' } });
    assert.equal(result.decision, 'ConditionalAllow');
    assert.deepEqual(result.unknowns[0].cond.unsupportedOperators, ['BinaryEquals']);
    assert.ok(lintModel(model(policy(unknown))).some(f => f.ruleId === 'LINT-UNMODELED-CONDITION-OP'));
  }
});
check('unsupported candidate Allow cannot count as risk closed', () => {
  const result = verifyCorrection({ proposed: policy(read, destroy), candidate: policy(read, { ...destroy, Condition: { BinaryEquals: { 'example:key': 'aGVsbG8=' } } }), riskRequest: { ...risk, context: { 'example:key': 'aGVsbG8=' } }, requiredAccess: [required] });
  assert.equal(result.riskClosed, false);
  assert.equal(result.verified, false);
});
check('unsupported IfExists cannot become a definite Allow', () => {
  assert.equal(evaluateCondition({ BinaryEqualsIfExists: { 'example:key': 'aGVsbG8=' } }, {}, true).result, 'unknown');
});
check('a known false conjunct can conclusively exclude an unsupported statement', () => {
  assert.equal(evaluateCondition({ BinaryEquals: { 'example:key': 'aGVsbG8=' }, StringEquals: { 'aws:RequestedRegion': 'eu-west-1' } }, { 'example:key': 'aGVsbG8=', 'aws:RequestedRegion': 'us-east-1' }).result, false);
});
check('a definite Deny still overrides unresolved statements', () => {
  assert.equal(evaluateRequest(model(policy(read, mfaDeny, { ...read, Effect: 'Deny' })), required).decision, 'ExplicitDeny');
});
check('a definite Allow is not weakened by an irrelevant unknown Allow', () => {
  assert.equal(evaluateRequest(model(policy(read, { ...read, Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } })), required).decision, 'Allow');
});
check('removing an unresolved Deny cannot receive a pass', () => {
  const result = reviewChange({ before: policy(read, mfaDeny), after: policy(read), request: required });
  assert.notEqual(result.verdict.status, 'pass');
  assert.equal(result.access.before.decision, 'ConditionalAllow');
});
check('unchanged unresolved Deny asks for context and cites the Deny', () => {
  const text = policy(read, mfaDeny);
  const result = reviewChange({ before: text, after: text, request: required });
  assert.equal(result.verdict.status, 'review');
  assert.ok(result.evidence.some(item => item.effect === 'Deny'));
});
check('unprovided context differs from explicitly complete context', () => {
  const text = model(policy(read, mfaDeny));
  assert.equal(evaluateRequest(text, required).decision, 'ConditionalAllow');
  assert.equal(evaluateRequest(text, { ...required, contextComplete: true }).decision, 'Allow');
  for (const Condition of [{ Null: { 'aws:TokenIssueTime': 'true' } }, { StringEqualsIfExists: { 'aws:PrincipalTag/team': 'platform' } }]) {
    assert.equal(evaluateCondition(Condition, {}).result, 'unknown');
    assert.equal(evaluateCondition(Condition, {}, true).result, true);
  }
});
check('contextComplete requires an explicit boolean and survives review normalization', () => {
  assert.throws(() => reviewChange({ before: policy(read), after: policy(read), request: { ...required, contextComplete: 'true' } }), /boolean/);
  assert.equal(reviewChange({ before: policy(read), after: policy(read), request: { ...required, contextComplete: true } }).request.contextComplete, true);
});
check('invalid dates cannot produce a correction proof', () => {
  assert.equal(evaluateCondition(dateCondition, { 'aws:CurrentTime': 'invalid-date' }).result, 'unknown');
});

console.log(`condition verification — ${checks} regression groups passed`);
