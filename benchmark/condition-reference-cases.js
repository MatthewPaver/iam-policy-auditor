'use strict';

// Authored fixtures derived from AWS documentation, not captured AWS responses.
// Fully specified cases can be checked independently with benchmark:aws.
const operators = 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html';
const precedence = 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html';
const allow = { Sid: 'Read', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::data/report.csv' };
const at = '2026-10-24T00:00:00Z';
const other = '2026-10-23T00:00:00Z';
const request = { action: allow.Action, resource: allow.Resource };
const fixture = (id, Statement, context, expected, extra = {}) => ({
  id, note: id.replaceAll('-', ' '),
  policy: { Version: '2012-10-17', Statement },
  request: { ...request, context, ...(extra.request || {}) },
  expected, reference: operators,
  ...Object.fromEntries(Object.entries(extra).filter(([key]) => key !== 'request')),
});
const date = Effect => ({ ...allow, Effect, Condition: { DateNotEquals: { 'aws:CurrentTime': at } } });
const denyMfa = { ...allow, Effect: 'Deny', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } } };
const unknown = { oracleSkip: true, oracleReason: 'Input context is incomplete, not a declaration that keys are absent. ConditionalAllow is local uncertainty, not an AWS authorization outcome.' };

module.exports = [
  fixture('reference-date-not-equals-allow-different', [date('Allow')], { 'aws:CurrentTime': other }, 'Allow'),
  fixture('reference-date-not-equals-allow-same', [date('Allow')], { 'aws:CurrentTime': at }, 'ImplicitDeny'),
  fixture('reference-date-not-equals-same-instant-offset', [date('Allow')], { 'aws:CurrentTime': '2026-10-24T01:00:00+01:00' }, 'ImplicitDeny'),
  fixture('reference-date-not-equals-epoch-zero-different', [{ ...allow, Condition: { DateNotEquals: { 'aws:CurrentTime': '0' } } }], { 'aws:CurrentTime': '2000-01-01T00:00:00Z' }, 'Allow'),
  fixture('reference-date-not-equals-epoch-zero-same', [{ ...allow, Condition: { DateNotEquals: { 'aws:CurrentTime': '0' } } }], { 'aws:CurrentTime': '1970-01-01T00:00:00Z' }, 'ImplicitDeny'),
  fixture('reference-date-equals-epoch-and-iso', [{ ...allow, Condition: { DateEquals: { 'aws:CurrentTime': '0' } } }], { 'aws:CurrentTime': '1970-01-01T00:00:00Z' }, 'Allow'),
  fixture('reference-date-not-equals-epoch-context', [date('Allow')], { 'aws:CurrentTime': String(Date.parse(at) / 1000) }, 'ImplicitDeny'),
  fixture('reference-date-not-equals-deny-different', [allow, date('Deny')], { 'aws:CurrentTime': other }, 'ExplicitDeny'),
  fixture('reference-date-not-equals-deny-same', [allow, date('Deny')], { 'aws:CurrentTime': at }, 'Allow'),
  fixture('reference-date-negated-multiple-values-match', [{ ...allow, Condition: { DateNotEquals: { 'aws:CurrentTime': [at, other] } } }], { 'aws:CurrentTime': other }, 'ImplicitDeny'),
  fixture('reference-date-negated-multiple-values-outside', [{ ...allow, Condition: { DateNotEquals: { 'aws:CurrentTime': [at, other] } } }], { 'aws:CurrentTime': '2026-10-22T00:00:00Z' }, 'Allow'),
  fixture('reference-mfa-deny-matching', [allow, denyMfa], { 'aws:MultiFactorAuthPresent': 'false' }, 'ExplicitDeny', { reference: precedence }),
  fixture('reference-mfa-deny-nonmatching', [allow, denyMfa], { 'aws:MultiFactorAuthPresent': 'true' }, 'Allow'),
  fixture('reference-mfa-key-known-absent', [allow, denyMfa], {}, 'Allow', { request: { contextComplete: true } }),
  fixture('reference-positive-key-known-absent', [{ ...allow, Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } }], {}, 'ImplicitDeny', { request: { contextComplete: true } }),
  fixture('reference-negated-key-known-absent', [{ ...allow, Condition: { StringNotEquals: { 'aws:PrincipalTag/team': 'restricted' } } }], {}, 'Allow', { request: { contextComplete: true } }),
  fixture('reference-null-key-known-absent', [{ ...allow, Condition: { Null: { 'aws:TokenIssueTime': 'true' } } }], {}, 'Allow', { request: { contextComplete: true } }),
  fixture('reference-ifexists-key-known-absent', [{ ...allow, Condition: { StringEqualsIfExists: { 'aws:PrincipalTag/team': 'platform' } } }], {}, 'Allow', { request: { contextComplete: true } }),
  fixture('regression-mfa-key-unprovided', [allow, denyMfa], {}, 'ConditionalAllow', unknown),
  fixture('regression-date-key-unprovided', [allow, date('Deny')], {}, 'ConditionalAllow', unknown),
  fixture('regression-null-key-unprovided', [{ ...allow, Condition: { Null: { 'aws:TokenIssueTime': 'true' } } }], {}, 'ConditionalAllow', unknown),
  fixture('regression-ifexists-key-unprovided', [{ ...allow, Condition: { StringEqualsIfExists: { 'aws:PrincipalTag/team': 'platform' } } }], {}, 'ConditionalAllow', unknown),
  fixture('reference-string-not-like-case-sensitive', [{ ...allow, Condition: { StringNotLike: { 'aws:PrincipalTag/team': 'dba*' } } }], { 'aws:PrincipalTag/team': 'DBA-oncall' }, 'Allow'),
  fixture('reference-string-like-case-sensitive', [{ ...allow, Condition: { StringLike: { 'aws:PrincipalTag/team': 'dba*' } } }], { 'aws:PrincipalTag/team': 'DBA-oncall' }, 'ImplicitDeny'),
  fixture('reference-arn-case-sensitive', [{ ...allow, Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::Reports/*' } } }], { 'aws:SourceArn': 'arn:aws:s3:::reports/a' }, 'ImplicitDeny'),
  fixture('reference-arn-component-boundary', [{ ...allow, Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:*:us-east-1:111122223333:report' } } }], { 'aws:SourceArn': 'arn:aws:s3:us-west-2:111122223333:us-east-1:111122223333:report' }, 'ImplicitDeny'),
  fixture('reference-context-key-case-insensitive', [{ ...allow, Condition: { StringEquals: { 'aws:RequestedRegion': 'eu-west-1' } } }], { 'aws:requestedregion': 'eu-west-1' }, 'Allow', { reference: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html', request: { contextComplete: true } }),
  fixture('regression-unmodeled-ipv6-allow', [{ ...allow, Condition: { IpAddress: { 'aws:SourceIp': '2001:db8::/32' } } }], { 'aws:SourceIp': '2001:db8::10' }, 'ConditionalAllow', { ...unknown, oracleReason: 'IPv6 matching is not implemented locally; the result remains unresolved instead of pretending to match AWS.' }),
  fixture('regression-unmodeled-ipv6-deny', [allow, { ...allow, Effect: 'Deny', Condition: { NotIpAddress: { 'aws:SourceIp': '2001:db8::1' } } }], { 'aws:SourceIp': '2001:db8::99' }, 'ConditionalAllow', { ...unknown, oracleReason: 'IPv6 matching is not implemented locally; a potential Deny prevents definite Allow.' }),
  fixture('regression-unmodeled-condition-variable', [{ ...allow, Condition: { StringEquals: { 'aws:PrincipalTag/owner': '${aws:username}' } } }], { 'aws:PrincipalTag/owner': 'alice', 'aws:username': 'alice' }, 'ConditionalAllow', { ...unknown, oracleReason: 'Policy variables are not substituted locally; matching access remains unresolved.' }),
  // aws:username in Resource is modelled (Task 2); an unmodelled key still stays ConditionalAllow.
  fixture('regression-modelled-resource-variable', [{ ...allow, Resource: 'arn:aws:s3:::data/${aws:username}.csv' }], { 'aws:username': 'report' }, 'Allow', { oracleSkip: true, oracleReason: 'Local substitution of aws:username in Resource; not compared to the AWS simulator in this corpus.' }),
  fixture('regression-unmodeled-resource-variable', [{ ...allow, Resource: 'arn:aws:s3:::data/${aws:ResourceTag/Name}.csv' }], { 'aws:ResourceTag/Name': 'report' }, 'ConditionalAllow', { ...unknown, oracleReason: 'Unmodelled Resource policy variables stay unresolved locally.' }),
];
