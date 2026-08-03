'use strict';

const { analyzeDocuments } = require('../src/engine');
const { evaluateRequest, evaluateCondition, ipInCidr } = require('../src/evaluate');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.error(`  ✗ ${name}\n    ${e.message}`); fail++; }
}
function assert(c, m) { if (!c) throw new Error(m); }

const model = (text) => analyzeDocuments([{ name: 'p.json', text }]);

console.log('\nevaluate.js — CIDR + operators');
t('ipInCidr basic /8 /24 /32', () => {
  assert(ipInCidr('10.3.4.5', '10.0.0.0/8'), '10/8');
  assert(!ipInCidr('11.0.0.1', '10.0.0.0/8'), '!11/8');
  assert(ipInCidr('192.168.1.7', '192.168.1.0/24'), '/24');
  assert(!ipInCidr('192.168.2.7', '192.168.1.0/24'), '!/24');
});
t('StringEquals AND across keys, OR within key', () => {
  const c = { StringEquals: { 'aws:PrincipalOrgID': ['o-1', 'o-2'] } };
  assert(evaluateCondition(c, { 'aws:PrincipalOrgID': 'o-2' }).result === true, 'OR match');
  assert(evaluateCondition(c, { 'aws:PrincipalOrgID': 'o-9' }).result === false, 'no match');
});
t('missing key without IfExists → unknown, not silent pass', () => {
  const c = { StringEquals: { 'aws:PrincipalOrgID': 'o-1' } };
  const r = evaluateCondition(c, {});
  assert(r.result === 'unknown', `got ${r.result}`);
  assert(r.missingKeys.includes('aws:PrincipalOrgID'), r.missingKeys.join(','));
});
t('Bool MFA condition', () => {
  const c = { Bool: { 'aws:MultiFactorAuthPresent': 'true' } };
  assert(evaluateCondition(c, { 'aws:MultiFactorAuthPresent': 'true' }).result === true, 'mfa true');
  assert(evaluateCondition(c, { 'aws:MultiFactorAuthPresent': 'false' }).result === false, 'mfa false');
});

console.log('\nevaluate.js — full request decisions');
const ip = model(JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Sid: 'AllowFromCorp', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::data/*',
      Condition: { IpAddress: { 'aws:SourceIp': '10.0.0.0/8' } } },
    { Sid: 'DenyNoMfa', Effect: 'Deny', Action: 's3:*', Resource: '*',
      Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } } },
  ],
}));

t('allow when in-range IP and MFA present', () => {
  const r = evaluateRequest(ip, { action: 's3:GetObject', resource: 'arn:aws:s3:::data/report.csv',
    context: { 'aws:SourceIp': '10.1.2.3', 'aws:MultiFactorAuthPresent': 'true' } });
  assert(r.decision === 'Allow', `${r.decision}: ${r.explanation}`);
});
t('explicit deny wins when MFA absent (false)', () => {
  const r = evaluateRequest(ip, { action: 's3:GetObject', resource: 'arn:aws:s3:::data/report.csv',
    context: { 'aws:SourceIp': '10.1.2.3', 'aws:MultiFactorAuthPresent': 'false' } });
  assert(r.decision === 'ExplicitDeny', `${r.decision}: ${r.explanation}`);
});
t('out-of-range IP → implicit deny (allow condition fails)', () => {
  const r = evaluateRequest(ip, { action: 's3:GetObject', resource: 'arn:aws:s3:::data/report.csv',
    context: { 'aws:SourceIp': '203.0.113.5', 'aws:MultiFactorAuthPresent': 'true' } });
  assert(r.decision === 'ImplicitDeny', `${r.decision}: ${r.explanation}`);
});
t('no context provided → conditional allow, surfaced not guessed', () => {
  const r = evaluateRequest(ip, { action: 's3:GetObject', resource: 'arn:aws:s3:::data/report.csv' });
  assert(r.decision === 'ConditionalAllow', `${r.decision}`);
  assert(r.conditionalAllows.length === 1 && /SourceIp/.test(r.explanation), r.explanation);
});
t('unrelated action → implicit deny', () => {
  const r = evaluateRequest(ip, { action: 'ec2:TerminateInstances', resource: '*', context: {} });
  assert(r.decision === 'ImplicitDeny', r.decision);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
