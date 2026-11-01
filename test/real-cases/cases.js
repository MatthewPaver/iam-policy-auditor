'use strict';

// Public real-case suite. Modelled cases say so; real JSON comes from
// fixtures/ with SOURCE.md. C19 (SCPs) is intentionally omitted — see README.

const fs = require('fs');
const path = require('path');

const FIX = path.join(__dirname, 'fixtures');
const raw = (file) => fs.readFileSync(path.join(FIX, file), 'utf8');
const unwrap = (text) => JSON.stringify(JSON.parse(text).PolicyVersion.Document, null, 2);
const doc = (...Statement) => ({ Version: '2012-10-17', Statement });

const SRC = {
  mit: 'https://web.mit.edu/smadnick/www/wp/2020-07.pdf',
  rhino: 'https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/',
  bulletin: 'https://aws.amazon.com/security/security-bulletins/AWS-2021-007',
  mamip: 'https://github.com/zoph-io/MAMIP',
  variables: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html',
  mfa: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html',
  denyIp: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-ip.html',
  s3Examples: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html',
  s3Website: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteAccessPermissionsReqd.html',
  kms: 'https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html',
  notAction: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html',
  supportDoc: 'https://docs.aws.amazon.com/awssupport/latest/user/aws-support-service-link-role-updates.html',
};

const iamRead = { Sid: 'IamReadOnly', Effect: 'Allow', Action: ['iam:Get*', 'iam:List*'], Resource: '*' };
const ec2Read = { Sid: 'Ec2Describe', Effect: 'Allow', Action: 'ec2:Describe*', Resource: '*' };
const c1Before = doc({ Sid: 'WriteWafLogs', Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-waf-logs/*' });
const c1After = doc(
  { Sid: 'WriteWafLogs', Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-waf-logs/*' },
  { Sid: 'ListAndReadAllBuckets', Effect: 'Allow', Action: ['s3:ListAllMyBuckets', 's3:ListBucket', 's3:GetObject'], Resource: '*' },
);
const c1bAfter = doc(
  { Sid: 'WriteWafLogs', Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-waf-logs/*' },
  { Sid: 'ListAndReadAllBuckets', Effect: 'Allow', Action: ['s3:ListBucket', 's3:GetObject'], Resource: ['arn:aws:s3:::*', 'arn:aws:s3:::*/*'] },
);
const booksPolicy = doc(
  { Sid: 'TableActions', Effect: 'Allow', Action: 'dynamodb:*', Resource: 'arn:aws:dynamodb:*:111122223333:table/Books' },
  { Sid: 'ListTables', Effect: 'Allow', Action: 'dynamodb:ListTables', Resource: '*' },
);
const booksWidened = doc(
  { Sid: 'TableActions', Effect: 'Allow', Action: 'dynamodb:*', Resource: '*' },
  { Sid: 'ListTables', Effect: 'Allow', Action: 'dynamodb:ListTables', Resource: '*' },
);
const powerUser = JSON.parse(raw('PowerUserAccess.current.json')).PolicyVersion.Document.Statement;
const ec2MfaBefore = doc({ Effect: 'Allow', Action: ['ec2:StopInstances', 'ec2:TerminateInstances'], Resource: ['*'], Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } });
const ec2MfaAfter = doc({ Effect: 'Allow', Action: ['ec2:StopInstances', 'ec2:TerminateInstances'], Resource: ['*'] });
const s3App = { Sid: 'AppDataAccess', Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::corp-data/*' };
const denyIp = { Sid: 'DenyOutsideCorpRanges', Effect: 'Deny', Action: '*', Resource: '*', Condition: { NotIpAddress: { 'aws:SourceIp': ['192.0.2.0/24', '203.0.113.0/24'] } } };
const orgBefore = doc({ Sid: 'AllowGetObject', Principal: { AWS: '*' }, Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::amzn-s3-demo-bucket/*', Condition: { StringEquals: { 'aws:PrincipalOrgID': ['o-aa111bb222'] } } });
const orgAfter = doc({ Sid: 'AllowGetObject', Principal: { AWS: '*' }, Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::amzn-s3-demo-bucket/*' });
const bucketNamed = doc({ Sid: 'ReportingRead', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111122223333:role/reporting' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::amzn-s3-demo-bucket/*' });
const bucketPublic = doc({ Sid: 'PublicReadGetObject', Effect: 'Allow', Principal: '*', Action: ['s3:GetObject'], Resource: ['arn:aws:s3:::amzn-s3-demo-bucket/*'] });
const bucketWrongAccountRole = doc({ Sid: 'ReportingRead', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:role/reporting' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::amzn-s3-demo-bucket/*' });
const bucketWrongAccountRoot = doc({ Sid: 'ReportingRead', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::amzn-s3-demo-bucket/*' });
const kmsKey = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

function caseFrom(id, title, source, kind, before, after, request, expect) {
  return {
    id,
    title,
    source: Array.isArray(source) ? source : [source],
    kind,
    before: typeof before === 'string' ? before : JSON.stringify(before, null, 2),
    after: typeof after === 'string' ? after : JSON.stringify(after, null, 2),
    request,
    expect,
  };
}

const cases = [
  caseFrom('C01', 'WAF role gains list + read on every S3 bucket', [SRC.mit], 'modelled', c1Before, c1After,
    { action: 's3:GetObject', resource: 'arn:aws:s3:::example-customer-applications/2019/03/applications.csv', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C01b', 'Same widening as arn:aws:s3:::*', [SRC.mit], 'modelled', c1Before, c1bAfter,
    { action: 's3:GetObject', resource: 'arn:aws:s3:::example-customer-applications/2019/03/applications.csv', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C02', 'Rhino #1 CreatePolicyVersion on team-*', [SRC.rhino], 'modelled', doc(iamRead),
    doc(iamRead, { Sid: 'ManageTeamPolicies', Effect: 'Allow', Action: 'iam:CreatePolicyVersion', Resource: 'arn:aws:iam::111122223333:policy/team-*' }),
    { action: 'iam:CreatePolicyVersion', resource: 'arn:aws:iam::111122223333:policy/team-app-policy', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C03', 'Rhino #3 PassRole + RunInstances on *', [SRC.rhino], 'modelled', doc(ec2Read),
    doc(ec2Read, { Sid: 'LaunchInstances', Effect: 'Allow', Action: ['ec2:RunInstances', 'iam:PassRole'], Resource: '*' }),
    { action: 'iam:PassRole', resource: 'arn:aws:iam::111122223333:role/AdminRole', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C03b', 'Rhino #3 PassRole on named admin role', [SRC.rhino], 'modelled',
    doc(ec2Read, { Sid: 'LaunchInstances', Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' }),
    doc(ec2Read, { Sid: 'LaunchInstances', Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' }, { Sid: 'PassEc2Role', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::111122223333:role/ec2-admin-role' }),
    { action: 'iam:PassRole', resource: 'arn:aws:iam::111122223333:role/ec2-admin-role', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C04', 'Rhino #15 PassRole on role/* + CreateFunction', [SRC.rhino], 'modelled',
    doc({ Sid: 'ReadLambda', Effect: 'Allow', Action: ['lambda:GetFunction', 'lambda:ListFunctions'], Resource: '*' }),
    doc(
      { Sid: 'ReadLambda', Effect: 'Allow', Action: ['lambda:GetFunction', 'lambda:ListFunctions'], Resource: '*' },
      { Sid: 'DeployFunctions', Effect: 'Allow', Action: ['lambda:CreateFunction', 'lambda:InvokeFunction'], Resource: 'arn:aws:lambda:eu-west-1:111122223333:function:*' },
      { Sid: 'PassAnyRoleInAccount', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::111122223333:role/*' },
    ),
    { action: 'iam:PassRole', resource: 'arn:aws:iam::111122223333:role/AdminRole', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C05', 'Rhino #7/#10 PutUserPolicy via ${aws:username}', [SRC.rhino, SRC.variables], 'modelled',
    doc({ Sid: 'ManageOwnPassword', Effect: 'Allow', Action: ['iam:ChangePassword', 'iam:GetUser'], Resource: 'arn:aws:iam::111122223333:user/${aws:username}' }),
    doc(
      { Sid: 'ManageOwnPassword', Effect: 'Allow', Action: ['iam:ChangePassword', 'iam:GetUser'], Resource: 'arn:aws:iam::111122223333:user/${aws:username}' },
      { Sid: 'ManageOwnPolicies', Effect: 'Allow', Action: ['iam:AttachUserPolicy', 'iam:PutUserPolicy'], Resource: 'arn:aws:iam::111122223333:user/${aws:username}' },
    ),
    { action: 'iam:PutUserPolicy', resource: 'arn:aws:iam::111122223333:user/alice', context: { 'aws:username': 'alice' } },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C06', 'Rhino #14 UpdateAssumeRolePolicy on role/*', [SRC.rhino], 'modelled', doc(iamRead),
    doc(iamRead, { Sid: 'ManageRoleTrust', Effect: 'Allow', Action: ['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'], Resource: 'arn:aws:iam::111122223333:role/*' }),
    { action: 'iam:UpdateAssumeRolePolicy', resource: 'arn:aws:iam::111122223333:role/AdminRole', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C07', 'sts:AssumeRole widened to *', [SRC.rhino], 'modelled',
    doc({ Sid: 'AssumeDeploy', Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::111122223333:role/deploy-role' }),
    doc({ Sid: 'AssumeDeploy', Effect: 'Allow', Action: 'sts:AssumeRole', Resource: '*' }),
    { action: 'sts:AssumeRole', resource: 'arn:aws:iam::111122223333:role/AdminRole', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C08', 'AWSSupportServiceRolePolicy v19 → v20', [SRC.bulletin, SRC.mamip], 'real',
    unwrap(raw('AWSSupportServiceRolePolicy.v19.json')), unwrap(raw('AWSSupportServiceRolePolicy.v20.json')),
    { action: 's3:GetObject', resource: 'arn:aws:s3:::example-customer-bucket/secret.txt', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C10a', 'Support policy v19 → v21 GetObject unchanged', [SRC.supportDoc, SRC.mamip], 'real',
    unwrap(raw('AWSSupportServiceRolePolicy.pre-20220218.json')), unwrap(raw('AWSSupportServiceRolePolicy.20220218.json')),
    { action: 's3:GetObject', resource: 'arn:aws:s3:::example-customer-bucket/secret.txt', context: {} },
    { status: 'pass', beforeDecision: 'ImplicitDeny', afterDecision: 'ImplicitDeny' }),
  caseFrom('C10b', 'Support policy v19 → v21 ListBucketVersions added', [SRC.supportDoc, SRC.mamip], 'real',
    unwrap(raw('AWSSupportServiceRolePolicy.pre-20220218.json')), unwrap(raw('AWSSupportServiceRolePolicy.20220218.json')),
    { action: 's3:ListBucketVersions', resource: 'arn:aws:s3:::example-customer-bucket', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C11a', 'PowerUserAccess NotAction: DeleteBucket', [SRC.notAction, SRC.mamip], 'real',
    booksPolicy, doc(...booksPolicy.Statement, ...powerUser),
    { action: 's3:DeleteBucket', resource: 'arn:aws:s3:::prod-data', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C11b', 'PowerUserAccess NotAction: CreateUser stays denied but stop', [SRC.notAction, SRC.mamip], 'real',
    booksPolicy, doc(...booksPolicy.Statement, ...powerUser),
    { action: 'iam:CreateUser', resource: 'arn:aws:iam::111122223333:user/eve', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'ImplicitDeny' }),
  caseFrom('C12', 'DynamoDB resource widened to *', [SRC.mfa], 'modelled', booksPolicy, booksWidened,
    { action: 'dynamodb:DeleteTable', resource: 'arn:aws:dynamodb:eu-west-1:111122223333:table/Payments', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C13', 'MFA condition removed', [SRC.mfa], 'modelled', ec2MfaBefore, ec2MfaAfter,
    { action: 'ec2:TerminateInstances', resource: 'arn:aws:ec2:eu-west-1:111122223333:instance/i-0123456789abcdef0', context: { 'aws:MultiFactorAuthPresent': 'false' } },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C14', 'SourceIp deny removed', [SRC.denyIp], 'modelled', doc(s3App, denyIp), doc(s3App),
    { action: 's3:GetObject', resource: 'arn:aws:s3:::corp-data/payroll.csv', context: { 'aws:SourceIp': '198.51.100.7' } },
    { status: 'stop', beforeDecision: 'ExplicitDeny', afterDecision: 'Allow' }),
  // Principal required: resource policy with Principal AWS:"*" — scenario is an outsider principal.
  caseFrom('C15', 'PrincipalOrgID removed from bucket policy', [SRC.s3Examples], 'modelled', orgBefore, orgAfter,
    { action: 's3:GetObject', resource: 'arn:aws:s3:::amzn-s3-demo-bucket/report.csv', context: { 'aws:PrincipalOrgID': 'o-zz999yy888' }, principal: 'arn:aws:iam::999988887777:user/outsider' },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C16', 'Bucket policy Principal * for anonymous', [SRC.s3Website, SRC.s3Examples], 'modelled', bucketNamed, bucketPublic,
    { action: 's3:GetObject', resource: 'arn:aws:s3:::amzn-s3-demo-bucket/report.csv', context: {}, principal: 'anonymous' },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C17', 'Bucket policy wrong external role', [SRC.s3Examples], 'modelled', bucketNamed, bucketWrongAccountRole,
    { action: 's3:GetObject', resource: 'arn:aws:s3:::amzn-s3-demo-bucket/report.csv', context: {}, principal: 'arn:aws:iam::444455556666:role/reporting' },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C17b', 'Bucket policy wrong external :root', [SRC.s3Examples], 'modelled', bucketNamed, bucketWrongAccountRoot,
    { action: 's3:GetObject', resource: 'arn:aws:s3:::amzn-s3-demo-bucket/report.csv', context: {}, principal: 'arn:aws:iam::444455556666:root' },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C18', 'kms:Decrypt widened to *', [SRC.kms], 'modelled',
    doc({ Sid: 'DecryptAppKey', Effect: 'Allow', Action: 'kms:Decrypt', Resource: kmsKey }),
    doc({ Sid: 'DecryptAppKey', Effect: 'Allow', Action: 'kms:Decrypt', Resource: '*' }),
    { action: 'kms:Decrypt', resource: 'arn:aws:kms:eu-west-1:111122223333:key/0987dcba-09fe-87dc-65ba-ab0987654321', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
  caseFrom('C20a', 'PowerUserAccess v4 → v5 CreateUser unchanged', [SRC.mamip], 'real',
    unwrap(raw('PowerUserAccess.v4.json')), unwrap(raw('PowerUserAccess.v5.json')),
    { action: 'iam:CreateUser', resource: 'arn:aws:iam::111122223333:user/eve', context: {} },
    { status: 'pass', beforeDecision: 'ImplicitDeny', afterDecision: 'ImplicitDeny' }),
  caseFrom('C20b', 'PowerUserAccess v4 → v5 GetAccountInformation', [SRC.mamip], 'real',
    unwrap(raw('PowerUserAccess.v4.json')), unwrap(raw('PowerUserAccess.v5.json')),
    { action: 'account:GetAccountInformation', resource: '*', context: {} },
    { status: 'stop', beforeDecision: 'ImplicitDeny', afterDecision: 'Allow' }),
];

module.exports = {
  cases,
  omitted: [{
    id: 'C19',
    reason: 'SCPs are out of scope. Intersection semantics cannot be expressed by merging SCP Allow statements into an identity document.',
  }],
};
