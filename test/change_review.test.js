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

console.log('change-review — 14 passed');
