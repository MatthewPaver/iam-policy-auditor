'use strict';

const actions = require('../src/actions');
const { analyzeDocuments } = require('../src/engine');
const { runRules } = require('../src/rules');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.error(`  ✗ ${name}\n    ${e.message}`); fail++; }
}
function assert(c, m) { if (!c) throw new Error(m); }

console.log('\nactions.js — catalogue loaded');
t('catalogue loads with expected scale', () => {
  assert(actions.isLoaded(), 'data/aws-actions.json not loaded — run scripts/ingest-aws-actions.js');
  const m = actions.meta();
  assert(m.actions > 15000, `expected >15k actions, got ${m.actions}`);
  assert(m.services > 300, `expected >300 services, got ${m.services}`);
});

console.log('\nactions.js — access-level classification (authoritative, not name-guessed)');
t('read vs write vs permissions-management', () => {
  assert(actions.accessLevel('s3:GetObject') === 'Read', actions.accessLevel('s3:GetObject'));
  assert(actions.accessLevel('s3:DeleteObject') === 'Write', actions.accessLevel('s3:DeleteObject'));
  assert(actions.accessLevel('iam:AttachUserPolicy') === 'Permissions management', actions.accessLevel('iam:AttachUserPolicy'));
  assert(actions.accessLevel('s3:PutBucketPolicy') === 'Permissions management', actions.accessLevel('s3:PutBucketPolicy'));
});
t('authoritative levels the name-verb heuristic cannot infer', () => {
  // These are exactly the cases a name regex gets wrong. The catalogue is
  // AWS's own metadata, so it wins.
  assert(actions.isMutating('s3:GetObject') === false, 'GetObject → non-mutating');
  assert(actions.isMutating('s3:DeleteObject') === true, 'DeleteObject → mutating');
  // "GetSecretValue" starts with Get but is genuinely Read-level (sensitive, not mutating).
  assert(actions.isMutating('secretsmanager:GetSecretValue') === false, 'GetSecretValue is Read in the catalogue');
  // "Decrypt" has no write verb yet AWS classifies it Write — non-obvious.
  assert(actions.isMutating('kms:Decrypt') === true, 'Decrypt is Write in the catalogue');
});
t('unknown action returns null, never a false classification', () => {
  assert(actions.levelCode('madeup:NotARealAction') === null, 'unknown action');
  assert(actions.isMutating('madeup:NotARealAction') === null, 'unknown mutating → null');
});

console.log('\nactions.js — wildcard expansion');
t('service wildcard expands to real actions', () => {
  const r = actions.expand('s3:*', { cap: 100000 });
  assert(r.total > 100, `s3:* should expand to >100 actions, got ${r.total}`);
  assert(r.actions.includes('s3:DeleteObject') && r.actions.includes('s3:GetObject'), 'known actions present');
});
t('glob within service', () => {
  const r = actions.expand('ec2:Describe*', { cap: 100000 });
  assert(r.total > 20, `ec2:Describe* expansion ${r.total}`);
  assert(r.actions.every((a) => /^ec2:Describe/.test(a)), 'all match prefix');
});
t('cap limits materialized list but reports true total', () => {
  const r = actions.expand('s3:*', { cap: 5 });
  assert(r.actions.length === 5 && r.total > 5 && r.capped, `cap ${r.actions.length}/${r.total}`);
});

console.log('\nactions.js — blast radius');
t('blast radius counts by access level', () => {
  const br = actions.blastRadius(['s3:*']);
  assert(br.total > 100, `total ${br.total}`);
  assert(br.permissionsManagement > 0, 'S3 has permissions-management actions (bucket policy etc.)');
  assert(br.mutating > br.byLevel.Read === false || br.mutating > 0, 'has mutating actions');
});

console.log('\nrules.js — catalogue-backed AWS-RESOURCE-WILDCARD');
t('permissions-management action on Resource:* is escalated to high', () => {
  const model = analyzeDocuments([{ name: 'p.json', text: JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'X', Effect: 'Allow', Action: ['s3:GetObject', 's3:PutBucketPolicy'], Resource: '*' }],
  }) }]);
  const f = runRules(model).find((x) => x.ruleId === 'AWS-RESOURCE-WILDCARD');
  assert(f, 'rule should fire');
  assert(f.severity === 'high', `expected high (has permissions-management), got ${f.severity}`);
  assert(/permissions-management/.test(f.description), f.description);
});
t('read-only actions on Resource:* do NOT trip the mutating rule', () => {
  const model = analyzeDocuments([{ name: 'p.json', text: JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'R', Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: '*' }],
  }) }]);
  const f = runRules(model).find((x) => x.ruleId === 'AWS-RESOURCE-WILDCARD');
  assert(!f, 'read-only actions should not fire the state-changing rule');
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
