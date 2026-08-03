'use strict';

/**
 * Preflight lint tests — keep these fast and fixture-free.
 */
const assert = require('assert');
const { analyzeDocuments } = require('../src/engine');
const { lintModel } = require('../src/lint');

function modelFrom(text, name = 't.json') {
  return analyzeDocuments([{ name, text }]);
}

{
  const m = modelFrom(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
  }));
  const hits = lintModel(m);
  assert.ok(hits.some((f) => f.ruleId === 'LINT-ADMIN-STAR'), 'star-admin should flag');
}

{
  const m = modelFrom(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::bucket/key',
      Condition: { StringEqals: { 'aws:username': 'bob' } }, // typo on purpose
    }],
  }));
  const hits = lintModel(m);
  assert.ok(hits.some((f) => f.ruleId === 'LINT-BAD-CONDITION-OP'), 'typo operator should flag');
}

{
  const m = modelFrom(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:bucket-without-account',
    }],
  }));
  const hits = lintModel(m);
  assert.ok(hits.some((f) => f.ruleId === 'LINT-BAD-ARN'), 'bad ARN should flag');
}

{
  const m = modelFrom(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::ok/key' }],
  }));
  const hits = lintModel(m);
  assert.equal(hits.length, 0, 'clean statement should be quiet');
}

console.log('lint.js — 4 passed');
