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

// R1: removing or narrowing a Deny is new access (guardrail gone).
{
  const role = 'arn:aws:iam::111122223333:role/AppReader';
  const bucket = 'arn:aws:s3:::corp-data/*';
  const before = doc(
    { Sid: 'AllowGet', Effect: 'Allow', Principal: { AWS: role }, Action: 's3:GetObject', Resource: bucket },
    {
      Sid: 'DenyInsecure',
      Effect: 'Deny',
      Principal: { AWS: role },
      Action: 's3:*',
      Resource: bucket,
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
  );
  const after = doc(
    { Sid: 'AllowGet', Effect: 'Allow', Principal: { AWS: role }, Action: 's3:GetObject', Resource: bucket },
  );
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  const removed = review.newlyAllowed.items.find((item) => item.reason === 'deny-removed');
  assert.ok(removed, 'expected a deny-removed item when SecureTransport Deny is gone');
  assert.match(removed.action, /s3:GetObject/i);
  assert.ok(
    review.findings.introduced.some((f) => f.ruleId === 'AWS-DENY-GUARDRAIL-REMOVED'),
    'expected AWS-DENY-GUARDRAIL-REMOVED finding',
  );
}

{
  const before = doc(
    { Sid: 'AllowEc2', Effect: 'Allow', Action: 'ec2:*', Resource: '*' },
    {
      Sid: 'DenyOutsideHome',
      Effect: 'Deny',
      Action: 'ec2:*',
      Resource: '*',
      Condition: { StringNotEquals: { 'aws:RequestedRegion': 'eu-west-2' } },
    },
  );
  const after = doc(
    { Sid: 'AllowEc2', Effect: 'Allow', Action: 'ec2:*', Resource: '*' },
  );
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  assert.ok(review.newlyAllowed.items.some((item) => item.reason === 'deny-removed'));
}

{
  const before = doc(
    { Sid: 'AllowWrite', Effect: 'Allow', Action: ['s3:PutObject', 's3:DeleteBucket'], Resource: '*' },
    { Sid: 'DenyAllS3', Effect: 'Deny', Action: 's3:*', Resource: '*', Condition: { Bool: { 'aws:SecureTransport': 'false' } } },
  );
  const after = doc(
    { Sid: 'AllowWrite', Effect: 'Allow', Action: ['s3:PutObject', 's3:DeleteBucket'], Resource: '*' },
    { Sid: 'DenyDeleteOnly', Effect: 'Deny', Action: 's3:DeleteBucket', Resource: '*', Condition: { Bool: { 'aws:SecureTransport': 'false' } } },
  );
  const review = reviewChange({ before, after });
  const put = review.newlyAllowed.items.find(
    (item) => item.reason === 'deny-removed' && /s3:PutObject/i.test(item.action),
  );
  assert.ok(put, 'narrowing Deny Action from s3:* to s3:DeleteBucket should free s3:PutObject');
}

// R2: who is newly allowed (resource and trust Principal changes).
{
  const bucket = 'arn:aws:s3:::reports/*';
  const roleA = 'arn:aws:iam::111122223333:role/Reporter';
  const rootB = 'arn:aws:iam::444455556666:root';
  const before = doc({
    Sid: 'ReadReports',
    Effect: 'Allow',
    Principal: { AWS: roleA },
    Action: 's3:GetObject',
    Resource: bucket,
  });
  const after = doc({
    Sid: 'ReadReports',
    Effect: 'Allow',
    Principal: { AWS: rootB },
    Action: 's3:GetObject',
    Resource: bucket,
  });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  const widened = review.newlyAllowed.items.find((item) => item.reason === 'principal-widened');
  assert.ok(widened, 'expected principal-widened when the grant moves to another account');
  assert.equal(widened.sensitivity, 'cross-account');
}

{
  const before = doc({
    Sid: 'TrustPartner',
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111122223333:root' },
    Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': 'partner-unique-id' } },
  });
  const after = doc({
    Sid: 'TrustAnyone',
    Effect: 'Allow',
    Principal: { AWS: '*' },
    Action: 'sts:AssumeRole',
  });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  const widened = review.newlyAllowed.items.find((item) => item.reason === 'principal-widened');
  assert.ok(widened);
  assert.equal(widened.sensitivity, 'public');
}

{
  const before = doc({
    Sid: 'OwnerOnly',
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111122223333:role/App' },
    Action: 'sqs:SendMessage',
    Resource: 'arn:aws:sqs:eu-west-1:111122223333:orders',
  });
  const after = doc({
    Sid: 'AnyoneCanSend',
    Effect: 'Allow',
    Principal: '*',
    Action: 'sqs:SendMessage',
    Resource: 'arn:aws:sqs:eu-west-1:111122223333:orders',
  });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  assert.ok(review.newlyAllowed.items.some(
    (item) => item.reason === 'principal-widened' && item.sensitivity === 'public',
  ));
}

{
  const bucket = 'arn:aws:s3:::reports/*';
  const roleA = 'arn:aws:iam::111122223333:role/Reporter';
  const roleB = 'arn:aws:iam::111122223333:role/Auditor';
  const before = doc({
    Sid: 'ReadReports',
    Effect: 'Allow',
    Principal: { AWS: roleA },
    Action: 's3:GetObject',
    Resource: bucket,
  });
  const after = doc({
    Sid: 'ReadReports',
    Effect: 'Allow',
    Principal: { AWS: [roleA, roleB] },
    Action: 's3:GetObject',
    Resource: bucket,
  });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'pass');
}

// R3: full privilege-escalation list and per-action line numbers.
{
  const before = doc({ Sid: 'ReadFn', Effect: 'Allow', Action: 'lambda:GetFunction', Resource: '*' });
  const after = doc({
    Sid: 'EditFn',
    Effect: 'Allow',
    Action: ['lambda:GetFunction', 'lambda:UpdateFunctionCode'],
    Resource: '*',
  });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  const item = review.newlyAllowed.items.find((i) => /lambda:UpdateFunctionCode/i.test(i.action));
  assert.ok(item);
  assert.equal(item.sensitivity, 'privesc');
}

{
  const before = doc({ Sid: 'ReadUsers', Effect: 'Allow', Action: 'iam:GetUser', Resource: '*' });
  const after = doc({
    Sid: 'Login',
    Effect: 'Allow',
    Action: 'iam:CreateLoginProfile',
    Resource: 'arn:aws:iam::111122223333:user/*',
  });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  assert.ok(review.newlyAllowed.items.some(
    (item) => /iam:CreateLoginProfile/i.test(item.action) && item.sensitivity === 'privesc',
  ));
}

{
  const before = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BucketRead",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}`;
  const after = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BucketRead",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "*"
    }
  ]
}`;
  const review = reviewChange({ before, after });
  const getObject = review.newlyAllowed.items.find((item) => /s3:GetObject/i.test(item.action));
  assert.ok(getObject, 'expected s3:GetObject in newlyAllowed');
  // GetObject sits on its own line in the Action array (not the statement's first line).
  const getObjectLine = after.split('\n').findIndex((line) => /s3:GetObject/.test(line)) + 1;
  assert.equal(getObject.line, getObjectLine);
}

// S1: conditions narrow; conditional read-only additions pass.
{
  const before = doc({
    Sid: 'PassAny',
    Effect: 'Allow',
    Action: 'iam:PassRole',
    Resource: '*',
  });
  const after = doc({
    Sid: 'PassToRds',
    Effect: 'Allow',
    Action: 'iam:PassRole',
    Resource: '*',
    Condition: { StringEquals: { 'iam:PassedToService': 'rds.amazonaws.com' } },
  });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'pass');
  assert.equal(review.newlyAllowed.items.length, 0);
  assert.ok(review.newlyAllowed.narrowed);
  assert.equal(review.newlyAllowed.narrowed.length, 1);
  assert.equal(review.newlyAllowed.narrowed[0].reason, 'condition-added');
  assert.match(review.newlyAllowed.narrowed[0].action, /iam:PassRole/i);
}

{
  const before = doc({ Sid: 'Base', Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' });
  const after = doc(
    { Sid: 'Base', Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' },
    {
      Sid: 'Metrics',
      Effect: 'Allow',
      Action: 'cloudwatch:GetMetricData',
      Resource: '*',
      Condition: { StringEquals: { 'aws:SourceAccount': '111122223333' } },
    },
  );
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'pass');
  const added = review.newlyAllowed.items.find((item) => /cloudwatch:GetMetricData/i.test(item.action));
  assert.ok(added, 'expected cloudwatch:GetMetricData as newly allowed');
  assert.equal(added.conditional, true);
  assert.equal(added.sensitivity, 'read');
}

{
  const before = doc({ Sid: 'List', Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::logs' });
  const after = doc(
    { Sid: 'List', Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::logs' },
    {
      Sid: 'DeleteLogs',
      Effect: 'Allow',
      Action: 's3:DeleteObject',
      Resource: 'arn:aws:s3:::logs/*',
      Condition: { StringEquals: { 'aws:PrincipalTag/team': 'platform' } },
    },
  );
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'review');
  assert.ok(review.newlyAllowed.items.some(
    (item) => /s3:DeleteObject/i.test(item.action) && item.conditional,
  ));
}

// S2: remote execution and message / data reads.
{
  const before = doc({ Sid: 'Describe', Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' });
  const after = doc(
    { Sid: 'Describe', Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' },
    {
      Sid: 'SendCmd',
      Effect: 'Allow',
      Action: 'ssm:SendCommand',
      Resource: 'arn:aws:ec2:*:*:instance/*',
    },
  );
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  const item = review.newlyAllowed.items.find((i) => /ssm:SendCommand/i.test(i.action));
  assert.ok(item);
  assert.equal(item.sensitivity, 'remote-exec');
}

{
  const queue = 'arn:aws:sqs:eu-west-1:111122223333:orders';
  const before = doc({
    Sid: 'OwnerSend',
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111122223333:role/App' },
    Action: 'sqs:SendMessage',
    Resource: queue,
  });
  const after = doc(
    {
      Sid: 'OwnerSend',
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::111122223333:role/App' },
      Action: 'sqs:SendMessage',
      Resource: queue,
    },
    {
      Sid: 'PublicReceive',
      Effect: 'Allow',
      Principal: '*',
      Action: 'sqs:ReceiveMessage',
      Resource: queue,
    },
  );
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  assert.ok(review.newlyAllowed.items.some(
    (item) => item.reason === 'principal-widened'
      && /sqs:ReceiveMessage/i.test(item.action)
      && item.sensitivity === 'public',
  ));
}

{
  const table = 'arn:aws:dynamodb:eu-west-1:111122223333:table/Customers';
  const before = doc({
    Sid: 'OwnerRead',
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111122223333:role/App' },
    Action: 'dynamodb:GetItem',
    Resource: table,
  });
  const after = doc({
    Sid: 'CrossAccountScan',
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::444455556666:root' },
    Action: 'dynamodb:Scan',
    Resource: table,
  });
  const review = reviewChange({ before, after });
  assert.equal(review.verdict.status, 'stop');
  assert.ok(review.newlyAllowed.items.some(
    (item) => item.reason === 'principal-widened'
      && /dynamodb:Scan/i.test(item.action)
      && item.sensitivity === 'cross-account',
  ));
}

console.log('newly-allowed — passed');
