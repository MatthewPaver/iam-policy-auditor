'use strict';

const assert = require('assert');
const { reviewChange, verifyCorrection } = require('../src/change_review');

const policy = (statements) => JSON.stringify({ Version: '2012-10-17', Statement: statements }, null, 2);
const read = { Sid: 'ReadReports', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/*' };
const deleteProd = { Sid: 'DeleteProd', Effect: 'Allow', Action: 'rds:DeleteDBInstance', Resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1' };
const riskRequest = { action: 'rds:DeleteDBInstance', resource: deleteProd.Resource };

const before = policy([read]);
const after = policy([read, deleteProd]);
const review = reviewChange({ before, after, request: riskRequest });

assert.equal(review.verdict.status, 'stop');
assert.equal(review.access.before.decision, 'ImplicitDeny');
assert.equal(review.access.after.decision, 'Allow');
assert.equal(review.access.broadened, true);
assert.ok(review.evidence.some((item) => item.sid === 'DeleteProd'));
assert.ok(review.limits.some((item) => item.includes('not evaluated')));

const fixed = policy([read]);
const verification = verifyCorrection({
  proposed: after,
  candidate: fixed,
  riskRequest,
  requiredAccess: [{ id: 'reports-still-readable', action: 's3:GetObject', resource: 'arn:aws:s3:::reports/daily.csv' }],
});
assert.equal(verification.riskClosed, true);
assert.equal(verification.requiredPreserved, true);
assert.equal(verification.verified, true);

const broken = policy([]);
const brokenVerification = verifyCorrection({
  proposed: after,
  candidate: broken,
  riskRequest,
  requiredAccess: [{ action: 's3:GetObject', resource: 'arn:aws:s3:::reports/daily.csv' }],
});
assert.equal(brokenVerification.riskClosed, true);
assert.equal(brokenVerification.requiredPreserved, false);
assert.equal(brokenVerification.verified, false);

assert.throws(() => verifyCorrection({ proposed: after, candidate: fixed, riskRequest }), /required-access/);
const neverGranted = verifyCorrection({ proposed: after, candidate: fixed, riskRequest, requiredAccess: [{ action: 's3:PutObject', resource: 'arn:aws:s3:::reports/daily.csv' }] });
assert.equal(neverGranted.verified, false);
const conditionalRead = { ...read, Condition: { StringEquals: { 'aws:RequestedRegion': 'eu-west-1' } } };
const unknownContext = verifyCorrection({ proposed: policy([conditionalRead, deleteProd]), candidate: policy([conditionalRead]), riskRequest, requiredAccess: [{ action: 's3:GetObject', resource: 'arn:aws:s3:::reports/daily.csv' }] });
assert.equal(unknownContext.requiredPreserved, false);
assert.equal(unknownContext.verified, false);
assert.throws(() => reviewChange({ before, after, request: { action: riskRequest.action } }), /resource/);
assert.throws(() => reviewChange({ before, after, request: { ...riskRequest, context: [] } }), /plain JSON/);
assert.throws(() => verifyCorrection({ proposed: after, candidate: fixed, riskRequest, requiredAccess: [{ action: 's3:GetObject' }] }), /resource/);
assert.equal(review.schemaVersion, 1);
assert.match(review.engine.sourceIdentity, /^[a-f0-9]{64}$/);
assert.deepEqual(verification.engine, review.engine);
const newlyDangerous = verifyCorrection({ proposed: after, candidate: policy([read, { Effect: 'Allow', Action: '*', Resource: '*' } , { Effect: 'Deny', Action: riskRequest.action, Resource: riskRequest.resource }]), riskRequest, requiredAccess: [{ action: 's3:GetObject', resource: 'arn:aws:s3:::reports/daily.csv' }] });
assert.equal(newlyDangerous.riskClosed, true);
assert.equal(newlyDangerous.requiredPreserved, true);
assert.ok(newlyDangerous.introducedSevere.length);
assert.equal(newlyDangerous.verified, false);

// PowerUserAccess v4 → v5 only adds a read action; iam:CreateUser must stay pass
// with no introduced findings (same NotAction risk, same mutating Resource "*").
{
  const fs = require('fs');
  const path = require('path');
  const unwrap = (text) => JSON.stringify(JSON.parse(text).PolicyVersion.Document, null, 2);
  const fixture = (name) => unwrap(fs.readFileSync(path.join(__dirname, 'fixtures/aws-managed', name), 'utf8'));
  const powerReview = reviewChange({
    before: fixture('PowerUserAccess.v4.json'),
    after: fixture('PowerUserAccess.v5.json'),
    request: { action: 'iam:CreateUser', resource: 'arn:aws:iam::111122223333:user/eve' },
  });
  assert.equal(powerReview.findings.introduced.length, 0);
  assert.equal(powerReview.verdict.status, 'pass');
}

// Adding iam:* beside existing s3:* on "*" widens the finding and must stop.
{
  const beforeWide = policy([{ Effect: 'Allow', Action: 's3:*', Resource: '*' }]);
  const afterWide = policy([{ Effect: 'Allow', Action: ['s3:*', 'iam:*'], Resource: '*' }]);
  const wideReview = reviewChange({
    before: beforeWide,
    after: afterWide,
    request: { action: 's3:GetObject', resource: 'arn:aws:s3:::bucket/obj' },
  });
  assert.ok((wideReview.findings.widened || []).length >= 1);
  assert.equal(wideReview.verdict.status, 'stop');
}

console.log('change-review — passed');
