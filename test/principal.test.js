'use strict';

// Principal + policy-variable cases drawn from the real-case suite (C16, C17,
// C17b, C05). Without these, bucket-policy mistakes look like "no change".

const assert = require('assert');
const { reviewChange } = require('../src/change_review');
const { matchesPrincipal, evaluateRequest } = require('../src/evaluate');
const { analyzeDocuments } = require('../src/engine');

const doc = (...Statement) => JSON.stringify({ Version: '2012-10-17', Statement }, null, 2);

const bucketNamed = doc({
  Sid: 'ReportingRead',
  Effect: 'Allow',
  Principal: { AWS: 'arn:aws:iam::111122223333:role/reporting' },
  Action: 's3:GetObject',
  Resource: 'arn:aws:s3:::amzn-s3-demo-bucket/*',
});
const bucketPublic = doc({
  Sid: 'PublicReadGetObject',
  Effect: 'Allow',
  Principal: '*',
  Action: ['s3:GetObject'],
  Resource: ['arn:aws:s3:::amzn-s3-demo-bucket/*'],
});
const bucketWrongAccountRole = doc({
  Sid: 'ReportingRead',
  Effect: 'Allow',
  Principal: { AWS: 'arn:aws:iam::444455556666:role/reporting' },
  Action: 's3:GetObject',
  Resource: 'arn:aws:s3:::amzn-s3-demo-bucket/*',
});
const bucketWrongAccountRoot = doc({
  Sid: 'ReportingRead',
  Effect: 'Allow',
  Principal: { AWS: 'arn:aws:iam::444455556666:root' },
  Action: 's3:GetObject',
  Resource: 'arn:aws:s3:::amzn-s3-demo-bucket/*',
});

const resource = 'arn:aws:s3:::amzn-s3-demo-bucket/report.csv';

// C16: named role -> Principal "*"; anonymous goes ImplicitDeny -> Allow, stop.
{
  const review = reviewChange({
    before: bucketNamed,
    after: bucketPublic,
    request: { action: 's3:GetObject', resource, principal: 'anonymous' },
  });
  assert.equal(review.access.before.decision, 'ImplicitDeny');
  assert.equal(review.access.after.decision, 'Allow');
  assert.equal(review.verdict.status, 'stop');
}

// C17: grant to role ARN in 444455556666; for that role, ImplicitDeny -> Allow, stop.
{
  const review = reviewChange({
    before: bucketNamed,
    after: bucketWrongAccountRole,
    request: {
      action: 's3:GetObject',
      resource,
      principal: 'arn:aws:iam::444455556666:role/reporting',
    },
  });
  assert.equal(review.access.before.decision, 'ImplicitDeny');
  assert.equal(review.access.after.decision, 'Allow');
  assert.equal(review.verdict.status, 'stop');
}

// C17b: external principal written as account :root.
{
  const review = reviewChange({
    before: bucketNamed,
    after: bucketWrongAccountRoot,
    request: {
      action: 's3:GetObject',
      resource,
      principal: 'arn:aws:iam::444455556666:root',
    },
  });
  assert.equal(review.access.before.decision, 'ImplicitDeny');
  assert.equal(review.access.after.decision, 'Allow');
  assert.equal(review.verdict.status, 'stop');
}

// Account root principal matches any principal in that account.
{
  const model = analyzeDocuments([{ name: 'p.json', text: bucketWrongAccountRoot }]);
  assert.equal(
    matchesPrincipal(model.statements[0], 'arn:aws:iam::444455556666:role/reporting'),
    true,
  );
  assert.equal(
    matchesPrincipal(model.statements[0], 'arn:aws:iam::111122223333:role/reporting'),
    false,
  );
}

// Missing principal on a Principal-bearing statement -> ConditionalAllow note.
{
  const model = analyzeDocuments([{ name: 'p.json', text: bucketPublic }]);
  const result = evaluateRequest(model, { action: 's3:GetObject', resource });
  assert.equal(result.decision, 'ConditionalAllow');
  assert.ok(
    (result.conditionalAllows[0]?.note || result.explanation || '')
      .includes('Add a principal to check who this applies to')
    || result.unknowns.some((u) => (u.note || '').includes('Add a principal')),
  );
}

// C05: ${aws:username} resolves from context so PutUserPolicy on alice is Allow.
{
  const after = doc(
    {
      Sid: 'ManageOwnPassword',
      Effect: 'Allow',
      Action: ['iam:ChangePassword', 'iam:GetUser'],
      Resource: 'arn:aws:iam::111122223333:user/${aws:username}',
    },
    {
      Sid: 'ManageOwnPolicies',
      Effect: 'Allow',
      Action: ['iam:AttachUserPolicy', 'iam:PutUserPolicy'],
      Resource: 'arn:aws:iam::111122223333:user/${aws:username}',
    },
  );
  const before = doc({
    Sid: 'ManageOwnPassword',
    Effect: 'Allow',
    Action: ['iam:ChangePassword', 'iam:GetUser'],
    Resource: 'arn:aws:iam::111122223333:user/${aws:username}',
  });
  const review = reviewChange({
    before,
    after,
    request: {
      action: 'iam:PutUserPolicy',
      resource: 'arn:aws:iam::111122223333:user/alice',
      context: { 'aws:username': 'alice' },
    },
  });
  assert.equal(review.access.after.decision, 'Allow');
  assert.notEqual(review.access.after.decision, 'ConditionalAllow');
  assert.equal(review.verdict.status, 'stop');
}

console.log('principal — passed');
