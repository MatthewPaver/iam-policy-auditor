'use strict';

// Request-free "what did this change newly allow?" — the cases that made the
// lift-and-shift verdict fail when the reviewer declared the wrong request.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { reviewChange } = require('../src/change_review');

const doc = (...Statement) => JSON.stringify({ Version: '2012-10-17', Statement }, null, 2);
const unwrap = (text) => JSON.stringify(JSON.parse(text).PolicyVersion.Document, null, 2);
const fixture = (name) => unwrap(fs.readFileSync(path.join(__dirname, 'fixtures/aws-managed', name), 'utf8'));

const kmsKey = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

// AWSSupportServiceRolePolicy v19 → v20: stop without a request; includes s3:GetObject.
{
  const started = Date.now();
  const review = reviewChange({
    before: fixture('AWSSupportServiceRolePolicy.v19.json'),
    after: fixture('AWSSupportServiceRolePolicy.v20.json'),
  });
  const elapsed = Date.now() - started;
  assert.equal(review.verdict.status, 'stop');
  assert.ok(review.newlyAllowed);
  const getObject = review.newlyAllowed.items.find((item) => /s3:getobject/i.test(item.action));
  assert.ok(getObject, 'expected newlyAllowed to include s3:GetObject');
  assert.ok(Number.isInteger(getObject.line) && getObject.line > 0);
  assert.ok(elapsed < 2000, `v19→v20 review took ${elapsed}ms (limit 2000)`);
}

// Capital One modelled (C01) and ARN-wildcard form (C01b).
{
  const c1Before = doc({ Sid: 'WriteWafLogs', Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-waf-logs/*' });
  const c1After = doc(
    { Sid: 'WriteWafLogs', Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-waf-logs/*' },
    { Sid: 'ListAndReadAllBuckets', Effect: 'Allow', Action: ['s3:ListAllMyBuckets', 's3:ListBucket', 's3:GetObject'], Resource: '*' },
  );
  const c1 = reviewChange({ before: c1Before, after: c1After });
  assert.equal(c1.verdict.status, 'stop');

  const c1bAfter = doc(
    { Sid: 'WriteWafLogs', Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-waf-logs/*' },
    { Sid: 'ListAndReadAllBuckets', Effect: 'Allow', Action: ['s3:ListBucket', 's3:GetObject'], Resource: ['arn:aws:s3:::*', 'arn:aws:s3:::*/*'] },
  );
  const c1b = reviewChange({ before: c1Before, after: c1bAfter });
  assert.equal(c1b.verdict.status, 'stop');
}

// C04: PassRole on role/* plus lambda:CreateFunction → stop.
{
  const before = doc({ Sid: 'ReadLambda', Effect: 'Allow', Action: ['lambda:GetFunction', 'lambda:ListFunctions'], Resource: '*' });
  const after = doc(
    { Sid: 'ReadLambda', Effect: 'Allow', Action: ['lambda:GetFunction', 'lambda:ListFunctions'], Resource: '*' },
    { Sid: 'DeployFunctions', Effect: 'Allow', Action: ['lambda:CreateFunction', 'lambda:InvokeFunction'], Resource: 'arn:aws:lambda:eu-west-1:111122223333:function:*' },
    { Sid: 'PassAnyRoleInAccount', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::111122223333:role/*' },
  );
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
}

// C18: kms:Decrypt widened to * → stop.
{
  const before = doc({ Sid: 'DecryptAppKey', Effect: 'Allow', Action: 'kms:Decrypt', Resource: kmsKey });
  const after = doc({ Sid: 'DecryptAppKey', Effect: 'Allow', Action: 'kms:Decrypt', Resource: '*' });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
}

// PowerUserAccess v4 → v5 with no request: pass; only account:GetAccountInformation (read).
{
  const review = reviewChange({
    before: fixture('PowerUserAccess.v4.json'),
    after: fixture('PowerUserAccess.v5.json'),
  });
  assert.equal(review.verdict.status, 'pass');
  assert.ok(review.newlyAllowed);
  assert.equal(review.newlyAllowed.items.length, 1);
  assert.match(review.newlyAllowed.items[0].action, /account:GetAccountInformation/i);
  assert.equal(review.newlyAllowed.items[0].sensitivity, 'read');
}

console.log('newly-allowed — passed');
