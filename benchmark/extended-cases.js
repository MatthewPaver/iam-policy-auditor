'use strict';

// Boundary pairs for IAM constructs that were underrepresented in the original
// hand-written corpus. Expected decisions come from AWS's documented policy
// evaluation and condition-operator semantics; `benchmark:aws` can diff them
// against SimulateCustomPolicy when credentials are available.

const allow = (id, note, condition, context, expected = 'Allow', extra = {}) => ({
  id,
  note,
  policy: {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: extra.actionPattern || 's3:GetObject', Resource: extra.resourcePattern || 'arn:aws:s3:::data/*', ...(condition ? { Condition: condition } : {}), ...(extra.notResource ? { NotResource: extra.notResource, Resource: undefined } : {}) }],
  },
  request: { action: extra.action || 's3:GetObject', resource: extra.resource || 'arn:aws:s3:::data/report.csv', ...(context ? { context } : {}) },
  expected,
});

const cases = [
  allow('array-action-match', 'one action in an Action array matches', null, null, 'Allow', { actionPattern: ['s3:GetObject', 's3:ListBucket'] }),
  allow('array-action-no-match', 'no action in an Action array matches', null, null, 'ImplicitDeny', { actionPattern: ['s3:PutObject', 's3:ListBucket'] }),
  allow('resource-wildcard-segment', 'resource wildcard matches one object key', null, null, 'Allow', { resourcePattern: 'arn:aws:s3:::data/reports/*', resource: 'arn:aws:s3:::data/reports/july.csv' }),
  allow('resource-wildcard-outside', 'resource wildcard does not match a sibling prefix', null, null, 'ImplicitDeny', { resourcePattern: 'arn:aws:s3:::data/reports/*', resource: 'arn:aws:s3:::data/private/july.csv' }),
  allow('not-resource-included', 'Allow NotResource covers resources outside the exclusion', null, null, 'Allow', { notResource: 'arn:aws:s3:::data/private/*', resource: 'arn:aws:s3:::data/public/a.csv' }),
  allow('not-resource-excluded', 'Allow NotResource excludes the named private prefix', null, null, 'ImplicitDeny', { notResource: 'arn:aws:s3:::data/private/*', resource: 'arn:aws:s3:::data/private/a.csv' }),
  allow('string-not-equals-pass', 'StringNotEquals passes for a different org id', { StringNotEquals: { 'aws:PrincipalOrgID': 'o-good' } }, { 'aws:PrincipalOrgID': 'o-other' }),
  allow('string-not-equals-fail', 'StringNotEquals fails for the excluded org id', { StringNotEquals: { 'aws:PrincipalOrgID': 'o-good' } }, { 'aws:PrincipalOrgID': 'o-good' }, 'ImplicitDeny'),
  allow('string-ignore-case', 'StringEqualsIgnoreCase normalizes case', { StringEqualsIgnoreCase: { 'aws:username': 'ALICE' } }, { 'aws:username': 'alice' }),
  allow('string-not-like', 'StringNotLike rejects a matching protected path', { StringNotLike: { 's3:prefix': 'private/*' } }, { 's3:prefix': 'public/a' }),
  allow('bool-true', 'Bool matches a true secure-transport value', { Bool: { 'aws:SecureTransport': 'true' } }, { 'aws:SecureTransport': 'true' }),
  allow('bool-false', 'Bool does not match a false secure-transport value', { Bool: { 'aws:SecureTransport': 'true' } }, { 'aws:SecureTransport': 'false' }, 'ImplicitDeny'),
  allow('null-key-absent', 'Null true matches an absent context key', { Null: { 'aws:TokenIssueTime': 'true' } }, {}),
  allow('null-key-present', 'Null true fails when the context key is present', { Null: { 'aws:TokenIssueTime': 'true' } }, { 'aws:TokenIssueTime': '2026-08-11T00:00:00Z' }, 'ImplicitDeny'),
  allow('not-ip-pass', 'NotIpAddress passes outside the excluded network', { NotIpAddress: { 'aws:SourceIp': '10.0.0.0/8' } }, { 'aws:SourceIp': '192.0.2.8' }),
  allow('not-ip-fail', 'NotIpAddress fails inside the excluded network', { NotIpAddress: { 'aws:SourceIp': '10.0.0.0/8' } }, { 'aws:SourceIp': '10.2.3.4' }, 'ImplicitDeny'),
  allow('arn-equals', 'ArnEquals matches the exact caller ARN', { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::111122223333:role/Reader' } }, { 'aws:PrincipalArn': 'arn:aws:iam::111122223333:role/Reader' }),
  allow('arn-not-like', 'ArnNotLike passes for a principal outside an admin path', { ArnNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/Admin*' } }, { 'aws:PrincipalArn': 'arn:aws:iam::111122223333:role/Reader' }),
  allow('numeric-equals', 'NumericEquals compares numeric context values', { NumericEquals: { 's3:max-keys': '10' } }, { 's3:max-keys': 10 }),
  allow('numeric-less-than', 'NumericLessThan enforces the upper bound', { NumericLessThan: { 's3:max-keys': '20' } }, { 's3:max-keys': 19 }),
  allow('numeric-less-equal-boundary', 'NumericLessThanEquals includes the boundary', { NumericLessThanEquals: { 's3:max-keys': '20' } }, { 's3:max-keys': 20 }),
  allow('numeric-greater-than', 'NumericGreaterThan enforces the lower bound', { NumericGreaterThan: { 's3:max-keys': '20' } }, { 's3:max-keys': 21 }),
  allow('numeric-greater-equal-boundary', 'NumericGreaterThanEquals includes the boundary', { NumericGreaterThanEquals: { 's3:max-keys': '20' } }, { 's3:max-keys': 20 }),
  allow('date-equals', 'DateEquals matches an ISO timestamp', { DateEquals: { 'aws:CurrentTime': '2026-08-11T12:00:00Z' } }, { 'aws:CurrentTime': '2026-08-11T12:00:00Z' }),
  allow('date-less-equal', 'DateLessThanEquals includes the end instant', { DateLessThanEquals: { 'aws:CurrentTime': '2026-08-11T12:00:00Z' } }, { 'aws:CurrentTime': '2026-08-11T12:00:00Z' }),
  allow('date-greater-equal', 'DateGreaterThanEquals includes the start instant', { DateGreaterThanEquals: { 'aws:CurrentTime': '2026-08-11T12:00:00Z' } }, { 'aws:CurrentTime': '2026-08-11T12:00:00Z' }),
  allow('forall-values-pass', 'ForAllValues requires every context value to match', { 'ForAllValues:StringLike': { 'aws:TagKeys': ['team-*', 'cost-*'] } }, { 'aws:TagKeys': ['team-alpha', 'cost-123'] }),
  allow('forall-values-fail', 'ForAllValues fails when one context value does not match', { 'ForAllValues:StringLike': { 'aws:TagKeys': ['team-*', 'cost-*'] } }, { 'aws:TagKeys': ['team-alpha', 'owner'] }, 'ImplicitDeny'),
  allow('forany-values-pass', 'ForAnyValue passes when one context value matches', { 'ForAnyValue:StringLike': { 'aws:TagKeys': 'team-*' } }, { 'aws:TagKeys': ['owner', 'team-alpha'] }),
  allow('ifexists-present-fail', 'IfExists still evaluates a key when it is present', { StringEqualsIfExists: { 's3:x-amz-server-side-encryption': 'AES256' } }, { 's3:x-amz-server-side-encryption': 'aws:kms' }, 'ImplicitDeny'),
  allow('multiple-keys-and', 'separate keys in one condition block are ANDed', { StringEquals: { 'aws:PrincipalOrgID': 'o-good', 'aws:RequestedRegion': 'eu-west-1' } }, { 'aws:PrincipalOrgID': 'o-good', 'aws:RequestedRegion': 'us-east-1' }, 'ImplicitDeny'),
  allow('multiple-policy-values-or', 'multiple policy values for one key are ORed', { StringEquals: { 'aws:RequestedRegion': ['eu-west-1', 'eu-west-2'] } }, { 'aws:RequestedRegion': 'eu-west-2' }),
];

module.exports = cases.map((item) => {
  // JSON.stringify drops undefined Resource when NotResource is used.
  if (item.policy.Statement[0].Resource === undefined) delete item.policy.Statement[0].Resource;
  return item;
});
