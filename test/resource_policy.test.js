'use strict';

// Resource-policy exposure tests: foreign-account and public grants in KMS/S3
// (and similar) policies are detected as cited findings, same-account grants are
// not (no false positives), and a scoping condition downgrades severity.

const fs = require('fs');
const path = require('path');
const { parseSnapshot } = require('../src/snapshot');
const { analyzeResourcePolicies, classifyPrincipal, isScoped } = require('../src/resource_policy');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.error(`  ✗ ${name}\n    ${e.message}`); fail++; }
}
function assert(c, m) { if (!c) throw new Error(m); }

const snapshot = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'samples', 'aws-account-snapshot.json'), 'utf8'));
const org = parseSnapshot(snapshot);

console.log('\nsnapshot.js — resource-policy + account parsing');
t('audit account id derived from principals', () => {
  assert(org.accountId === '111122223333', org.accountId);
});
t('resource policies parsed (4 supplied)', () => {
  assert(org.resourcePolicies.length === 4, `got ${org.resourcePolicies.length}`);
});

console.log('\nresource_policy.js — principal classification');
t('public / external / internal classified relative to audit account', () => {
  assert(classifyPrincipal({ type: 'any', id: '*' }, '111122223333') === 'public', 'star = public');
  assert(classifyPrincipal({ type: 'AWS', id: 'arn:aws:iam::999988887777:root' }, '111122223333') === 'external', 'other acct = external');
  assert(classifyPrincipal({ type: 'AWS', id: 'arn:aws:iam::111122223333:role/x' }, '111122223333') === 'internal', 'same acct = internal');
});
t('scoping conditions detected', () => {
  assert(isScoped({ StringEquals: { 'aws:PrincipalOrgID': 'o-1' } }) === true, 'orgid scopes');
  assert(isScoped({ StringEquals: { 'foo': 'bar' } }) === false, 'unrelated does not');
});

console.log('\nresource_policy.js — findings');
const findings = analyzeResourcePolicies(org.resourcePolicies, org.accountId);
const byRule = (id) => findings.filter((f) => f.ruleId === id);

t('exactly 3 exposures found (internal same-account excluded)', () => {
  assert(findings.length === 3, `got ${findings.length}: ${findings.map((f) => f.title).join(' | ')}`);
});
t('S3 public bucket policy → critical', () => {
  const pub = byRule('AWS-RESOURCE-POLICY-PUBLIC');
  assert(pub.length === 1 && pub[0].severity === 'critical', JSON.stringify(pub.map((f) => f.severity)));
  assert(/s3/i.test(pub[0].title) && /acme-prod-exports/.test(pub[0].description), pub[0].description);
});
t('KMS foreign-account grant (unscoped) → high', () => {
  const kms = findings.find((f) => /KMS/.test(f.title) && /999988887777/.test(f.title));
  assert(kms, 'KMS external finding missing');
  assert(kms.severity === 'high', kms.severity);
  assert(kms.ruleId === 'AWS-RESOURCE-POLICY-EXTERNAL', kms.ruleId);
});
t('external grant WITH org condition → downgraded to medium', () => {
  const scoped = findings.find((f) => /888877776666/.test(f.title));
  assert(scoped && scoped.severity === 'medium', scoped ? scoped.severity : 'missing');
  assert(/scoped by a condition/.test(scoped.description), scoped.description);
});
t('same-account KMS grant produces NO finding (no false positive)', () => {
  assert(!findings.some((f) => /internal-only/.test(f.description)), 'same-account must not be flagged');
});
t('every finding cites a real policy line with an evidence snippet', () => {
  for (const f of findings) {
    assert(f.evidence.length && f.evidence[0].line >= 1, `bad evidence line: ${JSON.stringify(f.evidence)}`);
    assert(/Principal/.test(f.evidence[0].snippet), `snippet should show the Principal: ${f.evidence[0].snippet}`);
  }
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
