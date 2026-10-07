'use strict';

// Entity-graph tests: group inheritance, org-wide "who can X", assume-role
// edges, and reach-to-admin (direct / assume-chain / escalation).

const fs = require('fs');
const path = require('path');
const { buildOrg, whoCan, reachAdmin, assumeTargets, trustAllows } = require('../src/graph');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.error(`  ✗ ${name}\n    ${e.message}`); fail++; }
}
function assert(c, m) { if (!c) throw new Error(m); }

const snapshot = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'samples', 'aws-account-snapshot.json'), 'utf8'));
const org = buildOrg(snapshot);
const arn = (n, type) => `arn:aws:iam::111122223333:${type}/${n}`;
const names = (rows) => rows.map((r) => r.name).sort();

console.log('\ngraph.js — org parsing + group inheritance');
t('parses all principals (7 users + 2 roles)', () => {
  assert(org.principals.length === 9, `got ${org.principals.length}`);
});
t('alice inherits ReadOnlyAccess from the developers group', () => {
  const alice = org.byArn.get(arn('alice', 'user'));
  const model = org.effectiveModel(alice);
  const allow = model.statements.some((s) => s.actions.some((a) => a === 's3:Get*'));
  assert(allow, 'alice should inherit s3:Get* via developers → ReadOnlyAccess');
});

console.log('\ngraph.js — who can X across the org');
t('who can delete production databases → dave + admin-role only', () => {
  const rows = whoCan(org, { action: 'rds:DeleteDBInstance', resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1' });
  assert(JSON.stringify(names(rows)) === JSON.stringify(['admin-role', 'dave']), names(rows).join(','));
});
t('answer cites the granting statement', () => {
  const rows = whoCan(org, { action: 'rds:DeleteDBInstance', resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1' });
  const dave = rows.find((r) => r.name === 'dave');
  assert(dave.via.length && /DaveDbCleanup/.test(dave.via[0].doc), JSON.stringify(dave.via));
});
t('alice (read-only) cannot delete databases', () => {
  const rows = whoCan(org, { action: 'rds:DeleteDBInstance', resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1' });
  assert(!rows.some((r) => r.name === 'alice'), 'alice must not appear');
});
t('who can attach user policies → bob (via group) + admin-role', () => {
  const rows = whoCan(org, { action: 'iam:AttachUserPolicy', resource: '*' });
  assert(names(rows).includes('bob') && names(rows).includes('admin-role'), names(rows).join(','));
});

console.log('\ngraph.js — assume-role trust edges');
t('carol can assume admin-role; alice cannot', () => {
  const adminRole = org.byArn.get(arn('admin-role', 'role'));
  assert(trustAllows(adminRole, arn('carol', 'user')), 'carol should be trusted');
  assert(!trustAllows(adminRole, arn('alice', 'user')), 'alice should not be trusted');
});
t('assumeTargets(carol) includes admin-role', () => {
  const carol = org.byArn.get(arn('carol', 'user'));
  assert(assumeTargets(org, carol).some((r) => r.name === 'admin-role'), 'carol → admin-role');
});

console.log('\ngraph.js — reach admin (direct / assume / escalation / transitive)');
const reach = reachAdmin(org);
const find = (n) => reach.find((r) => r.name === n);
t('exactly the right principals can reach admin', () => {
  const expected = ['admin-role', 'bob', 'carol', 'ci-deploy', 'erin', 'frank', 'grace'];
  assert(JSON.stringify(names(reach)) === JSON.stringify(expected), names(reach).join(','));
});
t('alice and dave cannot reach admin', () => {
  assert(!find('alice') && !find('dave'), names(reach).join(','));
});
t('carol reaches admin via an assume-role step', () => {
  const carol = find('carol');
  assert(/assume-role chain/.test(carol.reason), carol.reason);
  assert(carol.path.some((step) => /assume/.test(step.how || '')), JSON.stringify(carol.path));
});
t('bob reaches admin via a single-step escalation', () => {
  const bob = find('bob');
  assert(/privilege escalation \(attach-user-policy\)/.test(bob.reason) && bob.hops === 1, bob.reason);
});
t('erin reaches admin TRANSITIVELY (create-access-key → frank → self-admin)', () => {
  const erin = find('erin');
  assert(erin.hops === 2, `expected 2 hops, got ${erin.hops}`);
  assert(/create-access-key/.test(erin.reason) && /put-user-policy/.test(erin.reason), erin.reason);
  assert(erin.path.some((s) => s.arn && /frank/.test(s.arn)), JSON.stringify(erin.path));
});
t('grace reaches admin via trust-edit then pass-role (multi-hop)', () => {
  const grace = find('grace');
  assert(grace.hops >= 2, `hops ${grace.hops}`);
  assert(/update-assume-role-policy/.test(grace.reason) && /pass-role/.test(grace.reason), grace.reason);
  assert(grace.path.some((s) => s.arn && /ci-deploy/.test(s.arn)) && grace.path.some((s) => s.arn && /admin-role/.test(s.arn)), JSON.stringify(grace.path));
});
t('every escalation step carries a citation', () => {
  const erin = find('erin');
  const escalationSteps = erin.path.filter((s) => s.technique && s.technique !== 'assume-role');
  assert(escalationSteps.length && escalationSteps.every((s) => s.via && s.via.length), JSON.stringify(erin.path));
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
