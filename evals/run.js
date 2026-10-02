'use strict';

const fs = require('fs');
const path = require('path');
const { evaluateExplanation } = require('../src/ai_eval');

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, 'cases.json'), 'utf8'));
let failed = 0;
for (const testCase of cases) {
  const result = evaluateExplanation({
    text: testCase.output,
    facts: testCase.facts,
    expectedStatus: testCase.expectedStatus,
  });
  const matched = result.passed === testCase.expectedPass;
  if (!matched) failed += 1;
  console.log(`${matched ? '✓' : '✗'} ${testCase.id}: score=${result.score} pass=${result.passed}`);
  if (!matched) console.log(JSON.stringify(result.diagnostics, null, 2));
}

console.log(`\n${cases.length - failed}/${cases.length} eval expectations matched`);
process.exit(failed ? 1 : 0);
