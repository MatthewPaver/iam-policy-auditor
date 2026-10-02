'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const dataPath = path.join(root, 'data', 'aws-actions.json');
const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
const provenance = JSON.parse(fs.readFileSync(path.join(root, 'data', 'aws-actions.provenance.json'), 'utf8'));
const outputSha256 = crypto.createHash('sha256').update(fs.readFileSync(dataPath)).digest('hex');

assert.match(data._meta.sourceCommit, /^[a-f0-9]{40}$/);
assert.match(data._meta.sourceSha256, /^[a-f0-9]{64}$/);
assert.equal(provenance.sourceCommit, data._meta.sourceCommit);
assert.equal(provenance.sourceSha256, data._meta.sourceSha256);
assert.equal(provenance.outputSha256, outputSha256);
assert.equal(data._meta.actions, 21656);
assert.equal(data._meta.services, 453);

console.log('provenance — 7 passed');
