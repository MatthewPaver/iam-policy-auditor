'use strict';

// CLI contract: exit codes, JSON verdict, removed-format rejection, and plain input errors.

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

// Removed formats fail with an input error rather than silently changing output.
{
  const result = run(['review', '--before', v19, '--after', v20, '--format', 'sarif']);
  assert.equal(result.status, 3);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /Unknown format/);
}

// R3: newly allowed privilege-escalation action exits stop without a request.
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'policylens-r3-'));
  const beforePath = path.join(dir, 'before.json');
  const afterPath = path.join(dir, 'after.json');
  const doc = (...Statement) => JSON.stringify({ Version: '2012-10-17', Statement }, null, 2);
  fs.writeFileSync(beforePath, doc({ Effect: 'Allow', Action: 'lambda:GetFunction', Resource: '*' }));
  fs.writeFileSync(afterPath, doc({
    Effect: 'Allow',
    Action: ['lambda:GetFunction', 'lambda:UpdateFunctionCode'],
    Resource: '*',
  }));
  const result = run(['review', '--before', beforePath, '--after', afterPath, '--format', 'json']);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(result.status, 1, result.stderr || result.stdout);
  const body = JSON.parse(result.stdout);
  assert.equal(body.verdict.status, 'stop');
}

console.log('cli — passed');
