'use strict';
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

function run(args) {
  return spawnSync(process.execPath, [path.join(__dirname, '../benchmark/run.js'), ...args], {
    encoding: 'utf8', env: { PATH: '/nonexistent' },
  });
}
const offline = run(['--json']);
assert.equal(offline.status, 0);
assert.equal(JSON.parse(offline.stdout).evidenceType, 'authored-regression-corpus');
assert.equal(JSON.parse(offline.stdout).oracle.status, 'not-requested');
const unavailable = run(['--oracle', 'aws', '--json']);
assert.equal(unavailable.status, 1, 'requested but unavailable AWS comparison must not pass');
assert.equal(JSON.parse(unavailable.stdout).oracle.status, 'not-run');
assert.notEqual(run(['--threshold', 'invalid']).status, 0);
assert.notEqual(run(['--oracle', 'awz', '--json']).status, 0);
assert.notEqual(run(['--oracle']).status, 0);
console.log('benchmark-contract — 6 passed (no AWS CLI or credentials used)');
