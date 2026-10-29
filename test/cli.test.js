'use strict';

// CLI contract: exit codes, JSON verdict, SARIF shape, and plain input errors.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const bin = path.join(__dirname, '..', 'bin', 'policylens.js');
const examples = path.join(__dirname, '..', 'examples', 'policies');
const v19 = path.join(examples, 'AWSSupportServiceRolePolicy.v19.json');
const v20 = path.join(examples, 'AWSSupportServiceRolePolicy.v20.json');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [bin, ...args], {
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
    ...opts,
  });
}

// Risky pair → exit 1, JSON verdict stop.
{
  const result = run(['review', '--before', v19, '--after', v20, '--format', 'json']);
  assert.equal(result.status, 1, result.stderr);
  const body = JSON.parse(result.stdout);
  const verdict = body.verdict || (body.results && body.results[0] && body.results[0].verdict);
  assert.equal(verdict.status, 'stop');
}

// Identical files → exit 0.
{
  const result = run(['review', '--before', v19, '--after', v19, '--format', 'json']);
  assert.equal(result.status, 0, result.stderr);
}

// Non-policy file → exit 3, one-line stderr.
{
  const junk = path.join(os.tmpdir(), `policylens-junk-${process.pid}.txt`);
  fs.writeFileSync(junk, 'not a policy at all');
  const result = run(['review', '--before', junk, '--after', junk, '--format', 'json']);
  fs.unlinkSync(junk);
  assert.equal(result.status, 3);
  const errLine = String(result.stderr || '').trim().split('\n').filter(Boolean);
  assert.equal(errLine.length, 1);
  assert.match(errLine[0], /Expected an IAM policy|could not|not/i);
}

// SARIF 2.1.0.
{
  const result = run(['review', '--before', v19, '--after', v20, '--format', 'sarif']);
  assert.ok(result.status === 1 || result.status === 0 || result.status === 2);
  const sarif = JSON.parse(result.stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.ok(Array.isArray(sarif.runs));
}

console.log('cli — passed');
