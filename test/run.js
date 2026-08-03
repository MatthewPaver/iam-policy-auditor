'use strict';

// Correctness tests: every sample must trigger the expected rules (and ONLY
// plausible ones), and Q&A answers must cite real statements with real lines.

const fs = require('fs');
const path = require('path');
const { analyzeDocuments } = require('../src/engine');
const { runRules } = require('../src/rules');
const { answerQuestion } = require('../src/query');
const { parseWithPointers } = require('../src/parse');

let pass = 0;
let fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.error(`  ✗ ${name}\n    ${e.message}`); fail++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

function load(name) {
  const text = fs.readFileSync(path.join(__dirname, '..', 'samples', name), 'utf8');
  return { name, text };
}
function audit(...names) {
  const model = analyzeDocuments(names.map(load));
  const findings = runRules(model);
  return { model, findings, rules: findings.map((f) => f.ruleId) };
}

console.log('\nparse.js — position tracking');
t('pointers record correct lines', () => {
  const { value, pointers } = parseWithPointers('{\n  "a": 1,\n  "b": [\n    {"c": true}\n  ]\n}');
  assert(value.b[0].c === true, 'value parsed');
  assert(pointers['/a'].line === 2, `expected /a at line 2, got ${pointers['/a'].line}`);
  assert(pointers['/b/0'].line === 4, `expected /b/0 at line 4, got ${pointers['/b/0'].line}`);
});
t('rejects trailing garbage', () => {
  let threw = false;
  try { parseWithPointers('{"a":1} extra'); } catch { threw = true; }
  assert(threw, 'should throw');
});

console.log('\nAWS identity policy — overbroad sample');
{
  const { model, findings, rules } = audit('aws-identity-overbroad.json');
  t('detects full admin wildcard', () => assert(rules.includes('AWS-ADMIN-WILDCARD'), rules.join(',')));
  t('detects PassRole on *', () => assert(rules.includes('AWS-PASSROLE-WILDCARD'), rules.join(',')));
  t('detects NotAction allow', () => assert(rules.includes('AWS-NOTACTION-ALLOW'), rules.join(',')));
  t('detects privesc primitives', () => assert(rules.includes('AWS-PRIVESC-PRIMITIVES'), rules.join(',')));
  t('detects destructive actions without conditions', () => assert(rules.includes('AWS-SENSITIVE-NO-CONDITION'), rules.join(',')));
  t('evidence cites real lines', () => {
    const f = findings.find((x) => x.ruleId === 'AWS-ADMIN-WILDCARD');
    const ev = f.evidence[0];
    assert(ev.line > 1 && ev.snippet.includes('"Action": "*"'), `line=${ev.line} snippet=${ev.snippet}`);
  });
  t('statements normalized (5 statements)', () => assert(model.statements.length === 5, `got ${model.statements.length}`));
}

console.log('\nAWS trust policy — risky sample');
{
  const { rules } = audit('aws-trust-risky.json');
  t('detects public principal on trust', () => assert(rules.includes('AWS-PUBLIC-PRINCIPAL'), rules.join(',')));
  t('detects cross-account trust without ExternalId', () => assert(rules.includes('AWS-CROSS-ACCOUNT-NO-EXTERNAL-ID'), rules.join(',')));
  t('detects service confused-deputy exposure', () => assert(rules.includes('AWS-SERVICE-CONFUSED-DEPUTY'), rules.join(',')));
}

console.log('\nAWS least-privilege sample — no false positives');
{
  const { findings } = audit('aws-least-privilege.json');
  t('no critical/high findings on clean policy', () => {
    const bad = findings.filter((f) => ['critical', 'high'].includes(f.severity));
    assert(bad.length === 0, bad.map((f) => f.ruleId).join(','));
  });
}

console.log('\nGCP bindings sample');
{
  const { rules } = audit('gcp-project-bindings.json');
  t('detects public member (allUsers)', () => assert(rules.includes('GCP-PUBLIC-MEMBER'), rules.join(',')));
  t('detects primitive role (editor)', () => assert(rules.includes('GCP-PRIMITIVE-ROLE'), rules.join(',')));
  t('detects SA impersonation role', () => assert(rules.includes('GCP-SA-IMPERSONATION'), rules.join(',')));
}

console.log('\nAzure custom role sample');
{
  const { rules } = audit('azure-custom-role.json');
  t('detects Actions ["*"]', () => assert(rules.includes('AZ-ACTION-WILDCARD'), rules.join(',')));
  t('detects broad assignable scope', () => assert(rules.includes('AZ-BROAD-SCOPE'), rules.join(',')));
}

console.log('\nIBM Cloud policy sample');
{
  const { rules } = audit('ibm-account-admin.json');
  t('detects account-wide Administrator', () => assert(rules.includes('IBM-ACCOUNT-ADMIN'), rules.join(',')));
}

console.log('\nNatural-language Q&A (deterministic path)');
{
  const { model, findings } = audit('aws-identity-overbroad.json');
  t('"who can delete production databases" finds the grants', () => {
    const a = answerQuestion('Who can delete production databases?', model, findings);
    assert(a.intent === 'who-can', `intent=${a.intent}`);
    assert(a.data.hits.length >= 2, `hits=${a.data.hits.length}`); // admin *, DbCleanup, NotAction stmt
    assert(a.text.includes('rds:DeleteDBInstance'), 'names the matched action');
    assert(/\[S\d+ · aws-identity-overbroad\.json:\d+\]/.test(a.text), 'cites statement + line');
  });
  t('"who has admin access" flags the * statement', () => {
    const a = answerQuestion('Who has admin access?', model, findings);
    assert(a.data.hits.some((h) => h.matchedActions.some((m) => m.includes('*'))), JSON.stringify(a.data.hits));
  });
  t('"is this overly permissive" summarizes with verdict', () => {
    const a = answerQuestion('Is this policy overly permissive?', model, findings);
    assert(a.intent === 'risk-summary' && /Yes/.test(a.text), a.text.slice(0, 80));
  });
  t('explicit action query works', () => {
    const a = answerQuestion('Who can call dynamodb:DeleteTable?', model, findings);
    assert(a.data.hits.length >= 1, JSON.stringify(a.data));
  });
}

{
  const { model, findings } = audit('aws-least-privilege.json');
  t('no hallucinated grants on read-only policy', () => {
    const a = answerQuestion('Who can delete production databases?', model, findings);
    assert(a.data.hits.length === 0, JSON.stringify(a.data.hits));
    assert(/No\b/.test(a.text), a.text.slice(0, 80));
  });
  t('deny is respected in answer for s3 deletes', () => {
    const a = answerQuestion('Who can delete storage buckets?', model, findings);
    assert(a.data.hits.length === 0, JSON.stringify(a.data.hits));
  });
}

{
  const { model, findings } = audit('gcp-project-bindings.json');
  t('unknown GCP custom role → uncertainty, not a guess', () => {
    const a = answerQuestion('Who can delete databases?', model, findings);
    const notes = (a.data && a.data.notes) || [];
    assert(notes.some((n) => n.includes('custom.deployHelper')), JSON.stringify(notes));
    assert(a.data.hits.every((h) => !h.principal.includes('deploy@')), 'custom role must not produce a hit');
  });
  t('editor role matches with caveat', () => {
    const a = answerQuestion('Who can delete databases?', model, findings);
    const hit = a.data.hits.find((h) => h.principal.includes('sam@acme.io'));
    assert(hit, JSON.stringify(a.data.hits));
    assert(hit.caveats.some((c) => c.includes('editor')), JSON.stringify(hit.caveats));
  });
}

{
  const { model, findings } = audit('ibm-account-admin.json');
  t('IBM administrator matches delete-database concept', () => {
    const a = answerQuestion('Who can delete databases?', model, findings);
    assert(a.data.hits.some((h) => h.principal.includes('IBMid-655000ABCD')), JSON.stringify(a.data.hits));
  });
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
