'use strict';

// Regression runner for the public real-case suite. Never edit expect to make
// a case pass — fix the engine instead. Pass --write to refresh README.md.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { reviewChange } = require('../../src/change_review');
const { cases, omitted } = require('./cases');

function runCase(c) {
  const review = reviewChange({
    before: c.before,
    after: c.after,
    request: c.request,
  });
  return {
    id: c.id,
    title: c.title,
    kind: c.kind,
    status: review.verdict.status,
    beforeDecision: review.access.before.decision,
    afterDecision: review.access.after.decision,
    expect: c.expect,
  };
}

function assertCase(c, result) {
  assert.equal(result.status, c.expect.status, `${c.id} status`);
  if (c.expect.beforeDecision) {
    assert.equal(result.beforeDecision, c.expect.beforeDecision, `${c.id} beforeDecision`);
  }
  if (c.expect.afterDecision) {
    assert.equal(result.afterDecision, c.expect.afterDecision, `${c.id} afterDecision`);
  }
}

function writeReadme(results) {
  const lines = [
    '# Public real-case regression suite',
    '',
    'Fixtures are public AWS managed policies (see `fixtures/SOURCE.md`) or modelled from public descriptions.',
    '',
    '## Omitted',
    '',
    ...omitted.map((item) => `- **${item.id}**: ${item.reason}`),
    '',
    '## Results',
    '',
    '| Case | Kind | Expected | Got | Match |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const r of results) {
    const expected = `${r.expect.beforeDecision || '—'} → ${r.expect.afterDecision || '—'}, ${r.expect.status}`;
    const got = `${r.beforeDecision} → ${r.afterDecision}, ${r.status}`;
    const ok = r.status === r.expect.status
      && (!r.expect.beforeDecision || r.beforeDecision === r.expect.beforeDecision)
      && (!r.expect.afterDecision || r.afterDecision === r.expect.afterDecision);
    lines.push(`| ${r.id} | ${r.kind} | ${expected} | ${got} | ${ok ? 'yes' : 'NO'} |`);
  }
  lines.push('');
  fs.writeFileSync(path.join(__dirname, 'README.md'), `${lines.join('\n')}\n`);
}

const results = [];
let failed = 0;
for (const c of cases) {
  try {
    const result = runCase(c);
    assertCase(c, result);
    results.push(result);
    console.log(`  ✓ ${c.id} ${result.beforeDecision}→${result.afterDecision} ${result.status}`);
  } catch (err) {
    failed += 1;
    console.error(`  ✗ ${c.id}: ${err.message}`);
    try {
      results.push(runCase(c));
    } catch {
      results.push({
        id: c.id,
        title: c.title,
        kind: c.kind,
        status: 'error',
        beforeDecision: '—',
        afterDecision: '—',
        expect: c.expect,
      });
    }
  }
}

if (process.argv.includes('--write')) writeReadme(results);

assert.equal(failed, 0, `${failed} real-case(s) failed`);
console.log(`real-cases — ${cases.length} passed (${omitted.length} omitted)`);
