'use strict';

// Adapter coverage: every AWS CLI / IaC shape we claim to accept must decode
// into plain IAM JSON documents before the engine sees them.

const assert = require('assert');
const {
  normalizePolicyInput,
  fromTerraformPlan,
} = require('../src/adapters');
const { reviewChange } = require('../src/change_review');

const plainPolicy = {
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }],
};

// --- plain policy ----------------------------------------------------------
{
  const result = normalizePolicyInput(JSON.stringify(plainPolicy), 'plain.json');
  assert.equal(result.sourceFormat, 'policy');
  assert.equal(result.documents.length, 1);
  assert.equal(result.documents[0].name, 'plain.json');
  assert.deepEqual(JSON.parse(result.documents[0].text), plainPolicy);
}

{
  const result = normalizePolicyInput(plainPolicy, 'obj.json');
  assert.equal(result.sourceFormat, 'policy');
  assert.equal(result.documents.length, 1);
}

// --- get-policy-version (object Document and URL-encoded string) -----------
{
  const wrapped = {
    PolicyVersion: {
      Document: plainPolicy,
      VersionId: 'v1',
      IsDefaultVersion: true,
    },
  };
  const result = normalizePolicyInput(wrapped, 'gpv.json');
  assert.equal(result.sourceFormat, 'get-policy-version');
  assert.equal(result.documents.length, 1);
  assert.deepEqual(JSON.parse(result.documents[0].text), plainPolicy);
}

{
  const encoded = encodeURIComponent(JSON.stringify(plainPolicy));
  const wrapped = {
    PolicyVersion: {
      Document: encoded,
      VersionId: 'v1',
    },
  };
  const result = normalizePolicyInput(JSON.stringify(wrapped), 'gpv-encoded.json');
  assert.equal(result.sourceFormat, 'get-policy-version');
  assert.deepEqual(JSON.parse(result.documents[0].text), plainPolicy);
}

// --- get-role-policy -------------------------------------------------------
{
  const rolePolicy = {
    RoleName: 'demo-role',
    PolicyName: 'inline-one',
    PolicyDocument: plainPolicy,
  };
  const result = normalizePolicyInput(rolePolicy, 'role-policy.json');
  assert.equal(result.sourceFormat, 'get-role-policy');
  assert.equal(result.documents.length, 1);
  assert.match(result.documents[0].name, /inline-one/);
  assert.deepEqual(JSON.parse(result.documents[0].text), plainPolicy);
}

// --- authorization-details role entry: 2 inline + 1 attached ---------------
{
  const authRole = {
    RoleName: 'app-role',
    Arn: 'arn:aws:iam::111122223333:role/app-role',
    RolePolicyList: [
      { PolicyName: 'inline-a', PolicyDocument: plainPolicy },
      {
        PolicyName: 'inline-b',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [{ Effect: 'Allow', Action: 's3:PutObject', Resource: '*' }],
        },
      },
    ],
    AttachedManagedPolicies: [
      {
        PolicyName: 'attached-read',
        PolicyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess',
        // Some exports embed the document; we accept that when present.
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [{ Effect: 'Allow', Action: 'ec2:Describe*', Resource: '*' }],
        },
      },
    ],
  };
  const result = normalizePolicyInput(authRole, 'auth-role.json');
  assert.equal(result.sourceFormat, 'authorization-details');
  assert.equal(result.documents.length, 3);
}

// --- array of two policies -------------------------------------------------
{
  const other = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Deny', Action: 's3:*', Resource: '*' }],
  };
  const result = normalizePolicyInput([plainPolicy, other], 'bundle.json');
  assert.equal(result.sourceFormat, 'policy-array');
  assert.equal(result.documents.length, 2);
}

// --- CloudFormation JSON ---------------------------------------------------
{
  const cfn = {
    Resources: {
      AppManaged: {
        Type: 'AWS::IAM::ManagedPolicy',
        Properties: {
          PolicyDocument: plainPolicy,
        },
      },
      AppRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' }],
          },
          Policies: [
            {
              PolicyName: 'role-inline',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [{ Effect: 'Allow', Action: 'logs:*', Resource: '*' }],
              },
            },
          ],
        },
      },
      BucketPol: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          Bucket: 'demo-bucket',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [{
              Effect: 'Allow',
              Principal: '*',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::demo-bucket/*',
            }],
          },
        },
      },
    },
  };
  const result = normalizePolicyInput(cfn, 'template.json');
  assert.equal(result.sourceFormat, 'cloudformation');
  assert.equal(result.documents.length, 3);
}

// --- CloudFormation YAML ---------------------------------------------------
{
  const yamlText = `
Resources:
  AppManaged:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: '*'
`;
  const result = normalizePolicyInput(yamlText, 'template.yaml');
  assert.equal(result.sourceFormat, 'cloudformation');
  assert.ok(result.documents.length >= 1);
}

// --- Terraform plan with one aws_iam_policy update -------------------------
{
  const plan = {
    resource_changes: [
      {
        address: 'aws_iam_policy.app',
        type: 'aws_iam_policy',
        change: {
          actions: ['update'],
          before: { policy: JSON.stringify(plainPolicy) },
          after: {
            policy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }],
            }),
          },
        },
      },
    ],
  };
  const result = normalizePolicyInput(plan, 'plan.json');
  assert.equal(result.sourceFormat, 'terraform-plan');
  assert.equal(result.documents.length, 1);

  const pairs = fromTerraformPlan(plan);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].address, 'aws_iam_policy.app');
  assert.equal(pairs[0].unknown, false);
  assert.ok(pairs[0].before);
  assert.ok(pairs[0].after);
}

// --- malformed input -------------------------------------------------------
{
  assert.throws(
    () => normalizePolicyInput('{"foo":1}'),
    (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /Expected an IAM policy/);
      assert.match(err.message, /get-policy-version/);
      assert.match(err.message, /cloudformation/);
      assert.match(err.message, /terraform-plan/);
      return true;
    },
  );
}

// --- Terraform after_unknown.policy ----------------------------------------
{
  const plan = {
    resource_changes: [
      {
        address: 'aws_iam_policy.unknown',
        type: 'aws_iam_policy',
        change: {
          actions: ['update'],
          before: { policy: JSON.stringify(plainPolicy) },
          after: { policy: null },
          after_unknown: { policy: true },
        },
      },
    ],
  };
  const pairs = fromTerraformPlan(plan);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].unknown, true);
}

// --- reviewChange: Deny in one of two attached policies wins ---------------
{
  const allowDoc = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/*' }],
  };
  const denyDoc = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/*' }],
  };
  const before = [allowDoc];
  const after = [allowDoc, denyDoc];
  const review = reviewChange({
    before,
    after,
    request: { action: 's3:GetObject', resource: 'arn:aws:s3:::reports/a.csv' },
  });
  assert.equal(review.access.after.decision, 'ExplicitDeny');
}

console.log('adapters — passed');
