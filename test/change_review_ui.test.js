'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const { reviewChange } = require('../src/change_review');

const sample = name => fs.readFileSync(path.join(__dirname, `../samples/aws-change-${name}.json`), 'utf8');
const inputs = { before: sample('before'), after: sample('after'), action: 'rds:DeleteDBInstance',
  resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1', context: {}, useAI: false };
const result = reviewChange({ before: inputs.before, after: inputs.after,
  request: { action: inputs.action, resource: inputs.resource, context: inputs.context } });
const source = fs.readFileSync(path.join(__dirname, '../public/app.js'), 'utf8');

async function renderedReview(review) {
  const nodes = new Map();
  const select = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: '', classList: { remove() {} } });
    return nodes.get(selector);
  };
  const mdStart = source.indexOf('function md(');
  const mdEnd = source.indexOf('\n}\n', mdStart) + 3;
  const handlerStart = source.indexOf("$('#compareBtn').onclick = async () => {");
  const handlerEnd = source.indexOf('\n};', handlerStart) + 3;
  const escapeSource = source.match(/^const esc = .*;$/m)?.[0];
  assert.ok(escapeSource && mdStart >= 0 && mdEnd > mdStart && handlerStart >= 0 && handlerEnd > handlerStart);
  const context = { $: select, changeBusy: false, changeRevision: 0, changeRecord: null,
    currentChangeInputs: () => inputs, fingerprint: async () => 'fixture-input-identity',
    api: async (url, body) => {
      assert.equal(url, '/api/change/review');
      assert.equal(body.useAI, false);
      assert.equal(body.redactIdentifiers, true);
      return { ...review, ai: null };
    }, changeError: message => { throw new Error(message); } };
  vm.runInNewContext(escapeSource + '\n' + source.slice(mdStart, mdEnd) + source.slice(handlerStart, handlerEnd), context);
  await select('#compareBtn').onclick();
  return select('#compareResult').innerHTML;
}

test('AI-off review shows both engine explanations', async () => {
  const html = await renderedReview(result);
  assert.ok(html.includes(result.access.before.explanation), 'current-policy explanation must be visible');
  assert.ok(html.includes(result.access.after.explanation), 'proposed-policy explanation must be visible');
});

test('AI-off review has one main verdict and no AI fallback panel', async () => {
  const html = await renderedReview(result);
  assert.equal(html.split(result.verdict.sentence).length - 1, 1);
  assert.ok(!html.includes('Optional AI explanation'));
});

test('existing MFA suggestion includes its exact JSON and remains unapplied', async () => {
  const suggestion = result.suggestedCorrections.find(item => item.rewrite?.includes('aws:MultiFactorAuthPresent'));
  assert.ok(suggestion, 'checked-in destructive-action sample must return its MFA suggestion');
  const html = await renderedReview(result);
  assert.ok(html.includes(suggestion.summary));
  assert.ok(html.includes(`<pre>${suggestion.rewrite.replace(/"/g, '&quot;')}</pre>`));
  assert.ok(html.includes('not applied'));
});

test('engine explanation and suggested JSON are escaped as text', async () => {
  const hostile = { ...result, access: { ...result.access,
    before: { ...result.access.before, explanation: '<img src=x onerror=alert(1)>' } },
  suggestedCorrections: [{ title: 'Example', summary: 'Inspect the supplied change.', rewrite: '<script>alert(1)</script>' }] };
  const html = await renderedReview(hostile);
  assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<script>'));
});

test('request-free review does not invent per-request explanations', async () => {
  const review = reviewChange({ before: inputs.before, after: inputs.after });
  assert.equal(review.access, null);
  const html = await renderedReview(review);
  assert.ok(html.includes('Request-free review'));
  assert.ok(!html.includes('Current policy:'));
  assert.ok(!html.includes('Proposed policy:'));
});
