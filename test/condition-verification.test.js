'use strict';

const assert = require('node:assert/strict');
const { analyzeDocuments } = require('../src/engine');
const { evaluateRequest, evaluateCondition } = require('../src/evaluate');
const { reviewChange, verifyCorrection } = require('../src/change_review');
const { lintModel } = require('../src/lint');
const { parseWithPointers } = require('../src/parse');
const { buildEdges } = require('../src/graph');

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
check('prototype-named JSON keys remain visible to unsupported-condition checks', () => {
  const unsupported = JSON.parse('{"__proto__":{"example:key":"value"}}');
  const parsed = parseWithPointers(JSON.stringify(unsupported)).value;
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.equal(Object.hasOwn(parsed, '__proto__'), true);
  assert.deepEqual(parsed, unsupported);
  const candidate = policy(read, destroy, { ...destroy, Effect: 'Deny', Condition: unsupported });
  const result = verifyCorrection({ proposed: policy(read, destroy), candidate, riskRequest: risk, requiredAccess: [required] });
  assert.equal(result.verified, false);
  assert.ok(result.candidateFindings.some(finding => finding.ruleId === 'LINT-BAD-CONDITION-OP'));
  assert.ok(result.risk.candidate.unknowns.some(item => item.cond.unsupportedOperators.includes('__proto__')));
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
  assert.equal(evaluateCondition(dateCondition, { 'aws:CurrentTime': '2026-10-24T00:00:00' }).result, 'unknown');
  assert.equal(evaluateCondition(dateCondition, { 'aws:CurrentTime': '2026-02-30T00:00:00Z' }).result, 'unknown');
  // Calendar-only ISO input is a local UTC-midnight interpretation, distinct
  // from an offset-less date-time. Neither case is live AWS evidence.
  assert.equal(evaluateCondition(dateCondition, { 'aws:CurrentTime': '2026-10-24' }).result, false);
});
check('IPv6, policy variables and case-sensitive text cannot falsely close risk', () => {
  for (const [Condition, context, decision] of [
    [{ IpAddress: { 'aws:SourceIp': '2001:db8::/32' } }, { 'aws:SourceIp': '2001:db8::10' }, 'ConditionalAllow'],
    [{ StringNotLike: { 'aws:PrincipalTag/team': 'dba*' } }, { 'aws:PrincipalTag/team': 'DBA-oncall' }, 'Allow'],
    [{ StringEquals: { 'aws:PrincipalTag/owner': '${aws:username}' } }, { 'aws:PrincipalTag/owner': 'alice', 'aws:username': 'alice' }, 'ConditionalAllow'],
    [{ StringEquals: { 'aws:RequestedRegion': 'eu-west-1' } }, { 'aws:requestedregion': 'eu-west-1' }, 'Allow'],
  ]) {
    const result = verifyCorrection({ proposed: policy(read, destroy), candidate: policy(read, { ...destroy, Condition }), riskRequest: { ...risk, context, contextComplete: true }, requiredAccess: [required] });
    assert.equal(result.risk.candidate.decision, decision);
    assert.equal(result.verified, false);
  }
});
check('IPv6 and variable-bearing Denies cannot prove preservation', () => {
  for (const statement of [
    { ...read, Effect: 'Deny', Condition: { NotIpAddress: { 'aws:SourceIp': '2001:db8::1' } } },
    { ...read, Effect: 'Deny', Resource: 'arn:aws:s3:::reports/${aws:username}.csv' },
  ]) {
    const result = verifyCorrection({ proposed: policy(read, statement, destroy), candidate: policy(read, statement), riskRequest: risk, requiredAccess: [{ ...required, context: { 'aws:SourceIp': '2001:db8::99', 'aws:username': 'daily' } }] });
    assert.equal(result.requiredPreserved, false);
    assert.equal(result.verified, false);
  }
});
check('a variable resource grant stays unresolved, not implicitly denied', () => {
  const candidate = { ...destroy, Resource: 'arn:aws:rds:eu-west-1:111122223333:db:${aws:PrincipalTag/database}' };
  const result = verifyCorrection({ proposed: policy(read, destroy), candidate: policy(read, candidate), riskRequest: { ...risk, context: { 'aws:PrincipalTag/database': 'prod-1' } }, requiredAccess: [required] });
  assert.equal(result.risk.candidate.decision, 'ConditionalAllow');
  assert.equal(result.verified, false);
});
check('ARN conditions compare case and each component separately', () => {
  assert.equal(evaluateCondition({ ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::reports/*' } }, { 'aws:SourceArn': 'arn:aws:s3:::reports/a' }).result, true);
  assert.equal(evaluateCondition({ ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::reports/A' } }, { 'aws:SourceArn': 'arn:aws:s3:::reports/a' }).result, false);
  assert.equal(evaluateCondition({ ArnLike: { 'aws:SourceArn': 'arn:aws:*:us-east-1:111122223333:report' } }, { 'aws:SourceArn': 'arn:aws:s3:us-west-2:111122223333:us-east-1:111122223333:report' }).result, false);
});
check('wildcards include line breaks and single Unicode code points', () => {
  assert.equal(evaluateCondition({ StringLike: { 's3:prefix': 'allowed/*' } }, { 's3:prefix': 'allowed/\nsecret' }).result, true);
  assert.equal(evaluateCondition({ StringLike: { 's3:prefix': 'allowed/?' } }, { 's3:prefix': 'allowed/😀' }).result, true);
  const list = { Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::data' };
  const request = { action: list.Action, resource: list.Resource, context: { 's3:prefix': 'allowed/\nsecret' } };
  const result = verifyCorrection({ proposed: policy(read, list), candidate: policy(read, { ...list, Condition: { StringLike: { 's3:prefix': 'allowed/*' } } }), riskRequest: request, requiredAccess: [required] });
  assert.equal(result.risk.candidate.decision, 'Allow');
  assert.equal(result.verified, false);
});
check('context casing ambiguity is unresolved and set-operator lint agrees', () => {
  assert.equal(evaluateCondition({ StringEquals: { 'aws:RequestedRegion': 'eu-west-1' } }, { 'aws:requestedregion': 'eu-west-1', 'aws:RequestedRegion': 'us-east-1' }, true).result, 'unknown');
  for (const [operator, valid] of [['ForAnyValue:StringLike', true], ['ForAnyValues:StringLike', false]]) {
    const hits = lintModel(model(policy({ ...read, Condition: { [operator]: { 'aws:TagKeys': 'team-*' } } })));
    assert.equal(hits.some(finding => finding.ruleId === 'LINT-BAD-CONDITION-OP'), !valid);
  }
});
check('conditional administrator and group paths remain visible as uncertain', () => {
  const user = { arn: 'arn:aws:iam::111122223333:user/reviewer', name: 'reviewer', type: 'user', attachedManaged: [] };
  const group = { arn: 'arn:aws:iam::111122223333:group/admins', name: 'admins', docs: [{ name: 'group.json', text: policy({ Effect: 'Allow', Action: '*', Resource: '*' }, { Effect: 'Deny', Action: '*', Resource: '*', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } } }) }] };
  const org = { principals: [user], groups: { admins: group }, effectiveModel: () => model(policy({ Effect: 'Allow', Action: 'iam:AddUserToGroup', Resource: group.arn })) };
  const edge = buildEdges(org).find(item => item.technique === 'add-user-to-group');
  assert.ok(edge);
  assert.match(edge.note, /condition/);
  const conditionalRole = { ...user, type: 'role' };
  const adminModel = model(group.docs[0].text);
  const direct = buildEdges({ ...org, principals: [conditionalRole], effectiveModel: () => adminModel }).find(item => item.technique === 'conditional-administrator');
  assert.ok(direct);
  assert.match(direct.note, /unresolved/);
});

console.log(`condition verification — ${checks} regression groups passed`);
