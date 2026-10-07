'use strict';

const { uniq, globMatch } = require('./util');
const actions = require('./actions');

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const RISKY_AWS_SERVICES = ['iam', 'sts', 'kms', 'ec2', 's3', 'lambda', 'cloudtrail', 'organizations', 'secretsmanager', 'ssm', 'rds', 'dynamodb'];

const AWS_SENSITIVE_ACTIONS = [
  's3:DeleteBucket', 's3:PutBucketPolicy', 'rds:DeleteDBInstance', 'rds:DeleteDBCluster',
  'dynamodb:DeleteTable', 'kms:ScheduleKeyDeletion', 'kms:DisableKey', 'cloudtrail:DeleteTrail',
  'cloudtrail:StopLogging', 'ec2:TerminateInstances', 'iam:DeleteUser', 'lambda:DeleteFunction',
  'logs:DeleteLogGroup', 'redshift:DeleteCluster',
];

const AWS_ESCALATION_ACTIONS = [
  'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion', 'iam:AttachUserPolicy',
  'iam:AttachRolePolicy', 'iam:AttachGroupPolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy',
  'iam:PutGroupPolicy', 'iam:CreateAccessKey', 'iam:CreateLoginProfile', 'iam:UpdateLoginProfile',
  'iam:UpdateAssumeRolePolicy', 'iam:AddUserToGroup',
];

const AWS_COMPUTE_LAUNCH = ['lambda:CreateFunction', 'ec2:RunInstances', 'ecs:RunTask', 'glue:CreateDevEndpoint', 'sagemaker:CreateNotebookInstance'];

const READ_VERB = /^(Get|List|Describe|Head|View|Read)/i;

// Catalogue-backed summary of state-changing actions in a set of patterns.
// Falls back to the name-verb heuristic when the action catalogue is not loaded,
// so findings still work (just less precisely). Returns
// { count, pm, examples, source: 'catalogue'|'heuristic' }.
function mutatingSummary(patterns) {
  if (actions.isLoaded()) {
    const mutating = [];
    let pm = 0;
    const seen = new Set();
    for (const pat of patterns) {
      const { actions: expanded } = actions.expand(pat, { cap: 100000 });
      const list = expanded.length ? expanded : (actions.exists(pat) ? [pat] : []);
      for (const a of list) {
        if (seen.has(a)) continue;
        seen.add(a);
        if (actions.isMutating(a)) {
          mutating.push(a);
          if (actions.accessLevel(a) === 'Permissions management') pm++;
        }
      }
    }
    // Prefer permissions-management + recognizable destructive verbs as examples.
    mutating.sort((a, b) => {
      const pa = actions.accessLevel(a) === 'Permissions management' ? 0 : 1;
      const pb = actions.accessLevel(b) === 'Permissions management' ? 0 : 1;
      return pa - pb || a.localeCompare(b);
    });
    return { count: mutating.length, pm, examples: mutating.slice(0, 5), source: 'catalogue' };
  }
  // Fallback heuristic
  const writeActions = patterns.filter((a) => {
    const verb = a.includes(':') ? a.split(':')[1] : a;
    return verb === '*' || !READ_VERB.test(verb);
  });
  return { count: writeActions.length, pm: 0, examples: writeActions.slice(0, 5), source: 'heuristic' };
}

// Human note on how far a wildcard pattern actually reaches, from the catalogue.
function expansionNote(pattern) {
  if (!actions.isLoaded()) return '';
  const { total } = actions.expand(pattern, { cap: 1 });
  if (!total) return '';
  const br = actions.blastRadius([pattern]);
  return ` (${pattern} expands to ${total} actions: ${br.byLevel.Write} write, ${br.permissionsManagement} permissions-management, ${br.byLevel.Read} read)`;
}

// --- helpers ---------------------------------------------------------------

function evidenceFor(model, stmt, path) {
  const doc = model.documents.find((d) => d.name === stmt.doc);
  const pos = (path && doc.pointers[path]) || { line: stmt.line, endLine: stmt.endLine };
  const from = pos.line;
  const to = Math.min(pos.endLine, from + 13);
  return {
    doc: doc.name,
    line: from,
    endLine: pos.endLine,
    snippet: doc.lines.slice(from - 1, to).join('\n'),
    truncated: to < pos.endLine,
  };
}

function stmtExplicitlyAllows(stmt, action) {
  return stmt.effect === 'Allow' && stmt.actions.some((p) => globMatch(p, action));
}

// Allow via NotAction counts too (everything except the listed actions).
function stmtAllows(stmt, action) {
  if (stmt.effect !== 'Allow') return false;
  if (stmt.notActions.length) return !stmt.notActions.some((p) => globMatch(p, action));
  return stmt.actions.some((p) => globMatch(p, action));
}

function conditionText(stmt) {
  return JSON.stringify(stmt.conditions || {});
}

function cite(stmt) {
  return `[${stmt.id} · ${stmt.doc}:${stmt.line}]`;
}

function makeFinding(model, opts) {
  const stmts = opts.stmts;
  return {
    ruleId: opts.ruleId,
    severity: opts.severity,
    title: opts.title,
    description: opts.description,
    statements: stmts.map((s) => s.id),
    evidence: stmts.map((s) => evidenceFor(model, s, opts.path)),
    remediation: opts.remediation || null,
  };
}

// --- AWS -------------------------------------------------------------------

function awsRules(model, out) {
  const stmts = model.statements.filter((s) => s.provider === 'aws');
  const adminIds = new Set();

  for (const s of stmts) {
    if (s.effect !== 'Allow') continue;

    // Full admin: Action * on Resource *
    if (s.actions.includes('*') && (s.resources.includes('*') || (!s.resources.length && s.kind === 'identity'))) {
      adminIds.add(s.id);
      out.push(makeFinding(model, {
        ruleId: 'AWS-ADMIN-WILDCARD', severity: 'critical',
        title: 'Full administrative access (Action "*" on Resource "*")',
        description: `Statement ${cite(s)} grants every action on every resource. Any principal with this policy can do anything in the account, including escalating their own privileges and deleting audit trails.`,
        stmts: [s],
        remediation: {
          summary: 'Replace "*" with the specific actions this identity actually needs, scoped to specific resource ARNs. If broad access is genuinely required, add a permissions boundary and conditions (e.g. aws:MultiFactorAuthPresent).',
          rewrite: JSON.stringify({ Sid: s.sid || 'ScopedAccess', Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::your-app-bucket/*' }, null, 2),
        },
      }));
      continue;
    }

    // Allow + NotAction
    if (s.notActions.length) {
      out.push(makeFinding(model, {
        ruleId: 'AWS-NOTACTION-ALLOW', severity: 'high',
        title: 'Allow with NotAction grants everything not listed',
        description: `Statement ${cite(s)} uses "NotAction" with Effect "Allow": it grants every AWS action EXCEPT ${s.notActions.join(', ')}. New services and actions launched by AWS are granted automatically. This is far broader than it reads.`,
        stmts: [s],
        remediation: {
          summary: 'Invert the statement: enumerate the actions to allow instead of the ones to exclude. If the intent was "everything except IAM", explicitly list the required service actions.',
        },
      }));
    }

    // Service-level wildcards (svc:*) or bare *
    const wilds = s.actions.filter((a) => a === '*' || /:\*$/.test(a));
    if (wilds.length && !adminIds.has(s.id)) {
      const risky = wilds.some((w) => w === '*' || RISKY_AWS_SERVICES.includes(w.split(':')[0].toLowerCase()));
      out.push(makeFinding(model, {
        ruleId: 'AWS-SERVICE-WILDCARD', severity: risky ? 'high' : 'medium',
        title: `Wildcard action${wilds.length > 1 ? 's' : ''}: ${wilds.join(', ')}`,
        description: `Statement ${cite(s)} grants all actions for ${wilds.map((w) => w === '*' ? 'every service' : `the ${w.split(':')[0]} service`).join(', ')}.${wilds.map(expansionNote).join('')} Service wildcards include destructive and permission-changing actions you may not intend.`,
        stmts: [s],
        remediation: { summary: `List only the needed actions (e.g. read-only: ${wilds[0] === '*' ? 's3:GetObject' : wilds[0].split(':')[0] + ':Get*, ' + wilds[0].split(':')[0] + ':List*'}) and scope Resource to specific ARNs.` },
      }));
    }

    // Resource * with state-changing actions (access levels from the catalogue)
    if (s.resources.includes('*') && !adminIds.has(s.id) && s.kind === 'identity') {
      const mut = mutatingSummary(s.actions);
      if (mut.count) {
        const totalNote = mut.count > mut.examples.length ? `, … (${mut.count} state-changing actions in total)` : '';
        const pmNote = mut.pm ? ` This includes ${mut.pm} permissions-management action${mut.pm > 1 ? 's' : ''} that can alter who has access.` : '';
        out.push(makeFinding(model, {
          ruleId: 'AWS-RESOURCE-WILDCARD', severity: mut.pm ? 'high' : 'medium',
          title: `${mut.count} state-changing action${mut.count > 1 ? 's' : ''} on all resources (Resource "*")`,
          description: `Statement ${cite(s)} allows ${mut.examples.join(', ')}${totalNote} against every resource in the account, not just the ones this identity owns.${pmNote}${mut.source === 'heuristic' ? ' (access levels estimated — action catalogue not loaded)' : ''}`,
          stmts: [s],
          remediation: { summary: 'Scope Resource to the specific ARNs (or ARN patterns like arn:aws:s3:::team-prefix-*) this identity should touch.' },
        }));
      }
    }

    // iam:PassRole on *
    if (stmtExplicitlyAllows(s, 'iam:PassRole') && s.resources.includes('*') && !adminIds.has(s.id)) {
      const combos = stmts.filter((o) => o.effect === 'Allow' && AWS_COMPUTE_LAUNCH.some((a) => stmtExplicitlyAllows(o, a)));
      out.push(makeFinding(model, {
        ruleId: 'AWS-PASSROLE-WILDCARD', severity: 'critical',
        title: 'iam:PassRole on all roles — privilege escalation path',
        description: `Statement ${cite(s)} allows passing ANY role to a service.` + (combos.length
          ? ` Combined with compute-launch permissions (${combos.map(cite).join(', ')}), the holder can launch a service with a more privileged role (e.g. an admin role) and act as it. This is a classic escalation chain.`
          : ` If this identity can also start compute (EC2, Lambda, ECS), it can attach a more privileged role to that compute and escalate.`),
        stmts: [s],
        remediation: {
          summary: 'Restrict Resource to the specific role ARN(s) and pin the receiving service with a condition.',
          rewrite: JSON.stringify({ Sid: s.sid || 'PassAppRoleOnly', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::<account>:role/app-worker-role', Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } }, null, 2),
        },
      }));
    }
  }

  // Privilege-escalation IAM primitives (per document, excluding admin stmts)
  const docs = uniq(stmts.map((s) => s.doc));
  for (const docName of docs) {
    const docStmts = stmts.filter((s) => s.doc === docName && s.effect === 'Allow' && !adminIds.has(s.id));
    const found = [];
    for (const s of docStmts) {
      const prims = AWS_ESCALATION_ACTIONS.filter((a) => stmtExplicitlyAllows(s, a));
      if (prims.length) found.push({ s, prims });
    }
    if (found.length) {
      const all = uniq(found.flatMap((f) => f.prims));
      const anyStar = found.some((f) => f.s.resources.includes('*'));
      out.push(makeFinding(model, {
        ruleId: 'AWS-PRIVESC-PRIMITIVES', severity: anyStar ? 'critical' : 'high',
        title: `IAM privilege-escalation primitives granted: ${all.slice(0, 3).join(', ')}${all.length > 3 ? ` (+${all.length - 3} more)` : ''}`,
        description: `${found.map((f) => cite(f.s)).join(', ')} grant IAM actions that let the holder rewrite their own (or another principal's) permissions: ${all.join(', ')}. Even when scoped to the holder's own user, actions like iam:CreatePolicyVersion or iam:AttachUserPolicy allow self-escalation to admin.`,
        stmts: found.map((f) => f.s),
        remediation: { summary: 'Remove IAM write actions from workload/developer policies. Manage IAM changes through a separate, audited pipeline (IaC + review). If delegation is required, use permissions boundaries so granted policies cannot exceed a ceiling.' },
      }));
    }
  }

  // Destructive actions without any Condition
  for (const s of stmts) {
    if (s.effect !== 'Allow' || adminIds.has(s.id) || s.conditions) continue;
    const sens = AWS_SENSITIVE_ACTIONS.filter((a) => stmtExplicitlyAllows(s, a));
    if (sens.length) {
      out.push(makeFinding(model, {
        ruleId: 'AWS-SENSITIVE-NO-CONDITION', severity: 'medium',
        title: `Destructive action${sens.length > 1 ? 's' : ''} without conditions: ${sens.join(', ')}`,
        description: `Statement ${cite(s)} allows ${sens.join(', ')} with no Condition block. There is no MFA, source-IP, or org guardrail on ${sens.length > 1 ? 'these irreversible operations' : 'this irreversible operation'}.`,
        stmts: [s],
        remediation: {
          summary: 'Add a guardrail condition, e.g. require MFA for destructive calls.',
          rewrite: JSON.stringify({ Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } }, null, 2),
        },
      }));
    }
  }

  // Trust / resource policy checks
  for (const s of stmts) {
    if (s.effect !== 'Allow' || (s.kind !== 'trust' && s.kind !== 'resource')) continue;
    const condText = conditionText(s);

    if (s.principals.some((p) => p.type === 'any' || p.id === '*')) {
      const hasScoping = /(PrincipalOrgID|SourceArn|SourceAccount|ExternalId|aud|oaud|sub)/i.test(condText);
      out.push(makeFinding(model, {
        ruleId: 'AWS-PUBLIC-PRINCIPAL', severity: hasScoping ? 'high' : 'critical',
        title: s.kind === 'trust' ? 'Role can be assumed by ANY principal (Principal "*")' : 'Resource is accessible to ANY principal (Principal "*")',
        description: `Statement ${cite(s)} names Principal "*"${hasScoping ? ', partially scoped by conditions — verify the condition keys are unforgeable' : ' with no scoping condition. Anyone on the internet with AWS credentials can use it'}.`,
        stmts: [s],
        remediation: { summary: 'Name the exact principals (account/role ARNs), or if federation is intended, pin the audience/subject claims in a Condition block.' },
      }));
    }

    for (const p of s.principals) {
      if (p.type === 'AWS' && /arn:aws:iam::\d{12}:root$/.test(p.id)) {
        const guarded = /(ExternalId|PrincipalOrgID|SourceIdentity)/i.test(condText);
        if (!guarded) {
          out.push(makeFinding(model, {
            ruleId: 'AWS-CROSS-ACCOUNT-NO-EXTERNAL-ID', severity: 'high',
            title: `Cross-account trust of ${p.id.match(/::(\d{12}):/)[1]} without ExternalId`,
            description: `Statement ${cite(s)} trusts the entire account ${p.id} ("root" means every principal that account's admin delegates to). Without an sts:ExternalId or aws:PrincipalOrgID condition, this is exposed to the confused-deputy problem if the trusted account is itself multi-tenant or compromised.`,
            stmts: [s],
            remediation: {
              summary: 'Add an ExternalId condition (for third parties) or narrow the principal to a specific role.',
              rewrite: JSON.stringify({ Condition: { StringEquals: { 'sts:ExternalId': '<unique-per-customer-id>' } } }, null, 2),
            },
          }));
        }
      }
      if (p.type === 'Service' && s.kind === 'trust' && !/(SourceAccount|SourceArn)/i.test(condText)) {
        out.push(makeFinding(model, {
          ruleId: 'AWS-SERVICE-CONFUSED-DEPUTY', severity: 'medium',
          title: `Service trust (${p.id}) without SourceAccount/SourceArn pin`,
          description: `Statement ${cite(s)} lets ${p.id} assume this role on behalf of any customer of that service. Add aws:SourceAccount (and ideally aws:SourceArn) so only YOUR resources can trigger the assumption.`,
          stmts: [s],
          remediation: { rewrite: JSON.stringify({ Condition: { StringEquals: { 'aws:SourceAccount': '<your-account-id>' } } }, null, 2), summary: 'Pin the calling resource with aws:SourceAccount / aws:SourceArn conditions.' },
        }));
      }
    }
  }
}

// --- GCP -------------------------------------------------------------------

function gcpRules(model, out) {
  for (const s of model.statements.filter((x) => x.provider === 'gcp')) {
    const role = s.actions[0] || '';
    const pub = s.principals.filter((p) => p.id === 'allUsers' || p.id === 'allAuthenticatedUsers');
    if (pub.length) {
      out.push(makeFinding(model, {
        ruleId: 'GCP-PUBLIC-MEMBER', severity: 'critical',
        title: `${role} granted to ${pub.map((p) => p.id).join(', ')}`,
        description: `Binding ${cite(s)} grants "${role}" to ${pub[0].id === 'allUsers' ? 'everyone on the internet, no authentication required' : 'every authenticated Google account in the world (any Gmail user), which is effectively public'}.`,
        stmts: [s],
        remediation: { summary: 'Remove the public member. If public read of specific objects is intended, prefer signed URLs or a dedicated public bucket with only that content.' },
      }));
    }
    if (['roles/owner', 'roles/editor'].includes(role)) {
      out.push(makeFinding(model, {
        ruleId: 'GCP-PRIMITIVE-ROLE', severity: role === 'roles/owner' ? 'critical' : 'high',
        title: `Primitive role ${role} granted to ${s.principals.map((p) => p.id).join(', ')}`,
        description: `Binding ${cite(s)} uses the legacy primitive role "${role}", which spans thousands of permissions across every service in the project${role === 'roles/editor' ? ' (nearly everything except IAM administration)' : ', including IAM administration'}. Google recommends predefined or custom roles instead.`,
        stmts: [s],
        remediation: { summary: `Replace with the narrowest predefined roles for what the member actually does (e.g. roles/cloudsql.client, roles/storage.objectAdmin on a specific bucket).` },
      }));
    }
    if (['roles/iam.serviceAccountTokenCreator', 'roles/iam.serviceAccountUser'].includes(role)) {
      out.push(makeFinding(model, {
        ruleId: 'GCP-SA-IMPERSONATION', severity: 'high',
        title: `${role} allows service-account impersonation`,
        description: `Binding ${cite(s)} grants ${s.principals.map((p) => p.id).join(', ')} the ability to ${role.endsWith('TokenCreator') ? 'mint access tokens for' : 'act as'} service accounts in scope. If granted at project level, this is an escalation path to ANY service account's permissions in the project.`,
        stmts: [s],
        remediation: { summary: 'Grant impersonation on the specific service account resource only, never at project level.' },
      }));
    }
    if (!s.conditions && /\.(admin)$/.test(role)) {
      out.push(makeFinding(model, {
        ruleId: 'GCP-ADMIN-NO-CONDITION', severity: 'low',
        title: `${role} granted without an IAM condition`,
        description: `Binding ${cite(s)} grants an admin-level role unconditionally. Consider an IAM condition (resource name prefix, expiry) to bound it.`,
        stmts: [s],
        remediation: { summary: 'Add a condition, e.g. expression limiting resource.name prefix or request.time for time-boxed access.' },
      }));
    }
  }
}

// --- Azure -----------------------------------------------------------------

function azureRules(model, out) {
  for (const s of model.statements.filter((x) => x.provider === 'azure')) {
    const scopes = s.resources;
    const broad = scopes.some((sc) => sc === '/' || /^\/subscriptions\/[^/]+$/.test(sc));
    if (s.actions.includes('*')) {
      out.push(makeFinding(model, {
        ruleId: 'AZ-ACTION-WILDCARD', severity: 'critical',
        title: `Custom role "${s.sid || 'unnamed'}" grants Actions ["*"]`,
        description: `Role definition ${cite(s)} allows every management-plane action${s.notActions.length ? ` except ${s.notActions.join(', ')} (NotActions only subtract from this role — they are not a deny)` : ''}, assignable at ${scopes.join(', ')}. This is Owner-equivalent${s.notActions.some((n) => /Authorization/i.test(n)) ? ' minus role assignment' : ''}.`,
        stmts: [s],
        remediation: { summary: 'Enumerate the specific resource-provider actions needed (e.g. Microsoft.Web/sites/*, Microsoft.Insights/components/read) instead of "*". Prefer built-in roles where one fits.' },
      }));
    }
    if (s.actions.some((a) => a !== '*' && /\/\*$/.test(a) && /^Microsoft\.(Authorization|KeyVault|Sql|Storage)\b/i.test(a))) {
      out.push(makeFinding(model, {
        ruleId: 'AZ-SENSITIVE-PROVIDER-WILDCARD', severity: 'high',
        title: 'Wildcard over a sensitive resource provider',
        description: `Role definition ${cite(s)} wildcards a sensitive provider (${s.actions.filter((a) => /^Microsoft\.(Authorization|KeyVault|Sql|Storage)\b/i.test(a)).join(', ')}). Authorization/* allows changing RBAC itself; KeyVault/Sql/Storage wildcards include data-destroying operations.`,
        stmts: [s],
        remediation: { summary: 'Split into explicit read/write actions per provider and drop write access to Microsoft.Authorization entirely.' },
      }));
    }
    if (broad && (s.actions.includes('*') || s.actions.length > 0)) {
      out.push(makeFinding(model, {
        ruleId: 'AZ-BROAD-SCOPE', severity: s.actions.includes('*') ? 'high' : 'low',
        title: `Assignable at ${scopes.find((sc) => sc === '/' || /^\/subscriptions\/[^/]+$/.test(sc))}`,
        description: `Role ${cite(s)} is assignable at ${scopes.join(', ')} — the whole subscription${scopes.includes('/') ? ' (tenant root!)' : ''}. Anyone assigned this role gets it across every resource group.`,
        stmts: [s],
        remediation: { summary: 'Narrow assignableScopes to the specific resource groups this role is for.' },
      }));
    }
  }
}

// --- IBM Cloud -------------------------------------------------------------

const IBM_SCOPING_ATTRS = ['serviceName', 'serviceInstance', 'resourceGroupId', 'resource', 'region', 'serviceType'];

function ibmRules(model, out) {
  for (const s of model.statements.filter((x) => x.provider === 'ibm')) {
    const roles = s.actions;
    const scoped = s.resources.some((r) => IBM_SCOPING_ATTRS.some((a) => r.startsWith(`${a}=`)));

    if (s.principals.some((p) => /PublicAccess/i.test(p.id))) {
      out.push(makeFinding(model, {
        ruleId: 'IBM-PUBLIC-ACCESS', severity: 'critical',
        title: 'Policy grants access to the Public Access group',
        description: `Policy ${cite(s)} targets the Public Access access group — its members are ALL users, including unauthenticated ones. Roles granted: ${roles.join(', ')}.`,
        stmts: [s],
        remediation: { summary: 'Remove the Public Access group from this policy; grant access to a specific access group with named members instead.' },
      }));
    }
    if (roles.includes('Administrator') && !scoped) {
      out.push(makeFinding(model, {
        ruleId: 'IBM-ACCOUNT-ADMIN', severity: 'critical',
        title: 'Administrator role across the entire account',
        description: `Policy ${cite(s)} grants the platform Administrator role with no serviceName / resourceGroupId / region scoping — the subject (${s.principals.map((p) => p.id).join(', ')}) can manage every service instance in the account AND assign access to others (Administrator includes access management).`,
        stmts: [s],
        remediation: { summary: 'Scope the policy with resource attributes (serviceName, resourceGroupId) and downgrade to Editor/Operator unless the subject genuinely administers IAM. Reserve account-wide Administrator for break-glass identities with MFA.' },
      }));
    } else if (roles.some((r) => ['Administrator', 'Manager'].includes(r)) && !scoped) {
      out.push(makeFinding(model, {
        ruleId: 'IBM-BROAD-MANAGER', severity: 'high',
        title: `${roles.filter((r) => ['Administrator', 'Manager'].includes(r)).join(', ')} role with no service scoping`,
        description: `Policy ${cite(s)} grants ${roles.join(', ')} across all services in the account (no serviceName attribute on the resource block).`,
        stmts: [s],
        remediation: { summary: 'Add a serviceName (and ideally serviceInstance or resourceGroupId) attribute to the resources block.' },
      }));
    } else if (!scoped && roles.length) {
      out.push(makeFinding(model, {
        ruleId: 'IBM-BROAD-SCOPE', severity: 'medium',
        title: `Account-wide grant of ${roles.join(', ')}`,
        description: `Policy ${cite(s)} applies to every service in the account. Even lower roles (Viewer/Reader) account-wide can expose metadata and configuration broadly.`,
        stmts: [s],
        remediation: { summary: 'Scope to the specific services or resource groups the subject works with.' },
      }));
    }
  }
}

// --- entry -----------------------------------------------------------------

function runRules(model) {
  const out = [];
  for (const d of model.documents) {
    if (d.provider === 'invalid') {
      out.push({ ruleId: 'PARSE-ERROR', severity: 'info', title: `Could not parse ${d.name}`, description: d.error, statements: [], evidence: [{ doc: d.name, line: 1, endLine: 1, snippet: d.lines.slice(0, 6).join('\n'), truncated: d.lines.length > 6 }], remediation: null });
    } else if (d.provider === 'unknown') {
      out.push({ ruleId: 'UNRECOGNIZED-FORMAT', severity: 'info', title: `${d.name}: format not recognized`, description: 'Supported formats: AWS IAM policy JSON (identity/resource/trust), GCP IAM binding policies, Azure RBAC role definitions, IBM Cloud IAM access policies. The document parsed as JSON but matched none of these shapes, so it was not audited.', statements: [], evidence: [{ doc: d.name, line: 1, endLine: 1, snippet: d.lines.slice(0, 6).join('\n'), truncated: d.lines.length > 6 }], remediation: null });
    }
  }
  awsRules(model, out);
  gcpRules(model, out);
  azureRules(model, out);
  ibmRules(model, out);
  out.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  return out;
}

module.exports = { runRules, SEV_ORDER, stmtAllows, stmtExplicitlyAllows };
