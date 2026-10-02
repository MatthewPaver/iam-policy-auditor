'use strict';

const assert = require('assert');
const { evaluateExplanation } = require('../src/ai_eval');

const facts = {
  verdict: { status: 'stop' },
  access: { after: { decision: 'Allow' } },
  statements: {
    before: [{ id: 'S1', doc: 'before.json', line: 4 }],
    after: [{ id: 'S1', doc: 'after.json', line: 4 }, { id: 'S2', doc: 'after.json', line: 10 }],
  },
  limits: ['SCPs are not evaluated.'],
};

const good = evaluateExplanation({
  facts,
  expectedStatus: 'stop',
  text: 'Stop and review. The proposed policy allows rds:DeleteDBInstance on the production database [S2 · after.json:10]. SCPs and permission boundaries are not evaluated, so this is a scoped result.',
});
assert.equal(good.passed, true, JSON.stringify(good));

const inventedCitation = evaluateExplanation({
  facts,
  expectedStatus: 'stop',
  text: 'Stop. The policy grants administrator access [S9 · after.json:99]. Other controls are not evaluated.',
});
assert.equal(inventedCitation.passed, false);
assert.equal(inventedCitation.checks.citationPrecision, false);

const uncited = evaluateExplanation({
  facts,
  expectedStatus: 'stop',
  text: 'Stop. The policy allows deletion of every database. Other controls are not evaluated.',
});
assert.equal(uncited.passed, false);
assert.equal(uncited.checks.claimGrounding, false);

const overclaim = evaluateExplanation({
  facts,
  expectedStatus: 'stop',
  text: 'Stop. The policy allows the action [S2 · after.json:10]. The corrected account is now safe. Other controls are not evaluated.',
});
assert.equal(overclaim.passed, false);
assert.equal(overclaim.checks.avoidsAbsoluteSafety, false);

console.log('ai-eval — 12 passed');
