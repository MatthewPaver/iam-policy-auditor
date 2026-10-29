'use strict';

// Diff what an Allow statement newly grants without needing a reviewer to
// guess the right request. Catalogue expansion must never be capped silently.

const actions = require('./actions');
const { globMatch } = require('./util');

// Sensitivity buckets used by the request-free verdict. Keep them in one place
// so the UI / CLI / rules can share the same wording.
const SENSITIVITY = {
  privesc: [
    'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
    'iam:AttachUserPolicy', 'iam:AttachRolePolicy', 'iam:AttachGroupPolicy',
    'iam:PutUserPolicy', 'iam:PutRolePolicy', 'iam:PutGroupPolicy',
    'iam:CreateAccessKey', 'iam:CreateLoginProfile', 'iam:UpdateLoginProfile',
    'iam:UpdateAssumeRolePolicy', 'iam:AddUserToGroup', 'iam:PassRole',
    'sts:AssumeRole',
  ],
  destructive: [
    's3:DeleteBucket', 's3:PutBucketPolicy', 'rds:DeleteDBInstance', 'rds:DeleteDBCluster',
    'dynamodb:DeleteTable', 'kms:ScheduleKeyDeletion', 'kms:DisableKey',
    'cloudtrail:DeleteTrail', 'cloudtrail:StopLogging', 'ec2:TerminateInstances',
    'iam:DeleteUser', 'lambda:DeleteFunction', 'logs:DeleteLogGroup',
    'redshift:DeleteCluster',
  ],
  'sensitive-read': [
    's3:GetObject', 'kms:Decrypt', 'secretsmanager:GetSecretValue',
    'ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParameter*', 'ssm:GetParametersByPath',
  ],
  write: [], // filled from catalogue Write / Tagging when classifying
  read: [],
};

const SENSITIVE_READ_RESOURCES = new Set(['*', 'arn:aws:s3:::*', 'arn:aws:s3:::*/*']);

function classifySensitivity(action, resource) {
  const lower = String(action).toLowerCase();
  for (const name of SENSITIVITY.privesc) {
    if (globMatch(name, action) || name.toLowerCase() === lower) return 'privesc';
  }
  for (const name of SENSITIVITY.destructive) {
    if (globMatch(name, action) || name.toLowerCase() === lower) return 'destructive';
  }
  for (const name of SENSITIVITY['sensitive-read']) {
    if (globMatch(name, action) || name.toLowerCase() === lower) {
      // Sensitive reads only escalate when scoped to everything / every bucket.
      if (SENSITIVE_READ_RESOURCES.has(String(resource)) || resource === '*') {
        return 'sensitive-read';
      }
      // Still a read of sensitive data on a narrower ARN — treat as read unless
      // the resource pattern itself is a full-service wildcard shape.
      if (/^arn:aws:s3:::\*/i.test(String(resource))) return 'sensitive-read';
      if (String(resource) === '*') return 'sensitive-read';
    }
  }
  // kms:Decrypt on * is sensitive-read even if the list check above used glob.
  if (/^kms:decrypt$/i.test(action) && (resource === '*' || SENSITIVE_READ_RESOURCES.has(String(resource)))) {
    return 'sensitive-read';
  }
  const level = actions.accessLevel(action);
  if (level === 'Write' || level === 'Tagging' || level === 'Permissions management') return 'write';
  return 'read';
}

function actionLine(model, stmt) {
  // Prefer the Action / NotAction pointer so the UI can cite the exact grant.
  const doc = model.documents.find((d) => d.name === stmt.doc);
  if (!doc || !doc.pointers) return stmt.line;
  const base = stmt.path || '';
  for (const suffix of ['/Action', '/NotAction', '/Action/0', '/NotAction/0']) {
    const pos = doc.pointers[`${base}${suffix}`];
    if (pos) return pos.line;
  }
  return stmt.line;
}

// Collect every concrete (action, resource) grant an Allow statement makes.
// Returns { grants: Map key→item, capped: boolean }.
function collectGrants(model) {
  const grants = new Map();
  let capped = false;
  // Cap high enough for the full catalogue; if we still truncate, say so.
  const CAP = Number.MAX_SAFE_INTEGER;

  for (const stmt of model.statements) {
    if (stmt.provider !== 'aws' || stmt.effect !== 'Allow') continue;
    const resources = (stmt.resources && stmt.resources.length)
      ? stmt.resources
      : (stmt.kind === 'identity' ? ['*'] : []);
    if (!resources.length) continue;

    let granted;
    if (stmt.notActions && stmt.notActions.length) {
      const all = actions.allActions();
      granted = all.filter((a) => !stmt.notActions.some((p) => globMatch(p, a)));
      // NotAction always walks the full catalogue; never silently shorter.
      if (!actions.isLoaded()) capped = true;
    } else {
      const set = new Set();
      for (const pattern of stmt.actions || []) {
        const raw = String(pattern);
        // Concrete actions need no catalogue walk.
        if (!/[*?]/.test(raw)) {
          set.add(raw);
          continue;
        }
        const result = actions.expand(raw, { cap: CAP });
        if (result.capped) capped = true;
        if (result.unavailable) {
          set.add(raw);
          capped = true;
        } else if (result.actions.length) {
          for (const a of result.actions) set.add(a);
        } else {
          set.add(raw);
        }
      }
      granted = [...set];
    }

    const conditional = Boolean(stmt.conditions);
    const line = actionLine(model, stmt);
    for (const action of granted) {
      for (const resource of resources) {
        // Include conditional so dropping a Condition block counts as new access.
        const key = `${String(action).toLowerCase()}|${resource}|${conditional ? 'c' : 'u'}`;
        if (grants.has(key)) continue;
        grants.set(key, {
          action,
          resource,
          doc: stmt.doc,
          line,
          sid: stmt.sid || null,
          conditional,
          sensitivity: classifySensitivity(action, resource),
        });
      }
    }
  }
  return { grants, capped };
}

function listNewlyAllowed({ beforeModel, afterModel }) {
  const before = collectGrants(beforeModel);
  const after = collectGrants(afterModel);
  const items = [];
  for (const [key, item] of after.grants) {
    if (before.grants.has(key)) continue;
    items.push(item);
  }
  // Stable order: sensitivity severity then action name.
  const rank = { privesc: 0, destructive: 1, 'sensitive-read': 2, write: 3, read: 4 };
  items.sort((a, b) => (rank[a.sensitivity] - rank[b.sensitivity])
    || a.action.localeCompare(b.action)
    || a.resource.localeCompare(b.resource));
  return {
    items,
    capped: before.capped || after.capped,
  };
}

function verdictFromNewlyAllowed(newlyAllowed) {
  const items = newlyAllowed.items || [];
  if (items.some((item) => ['privesc', 'destructive', 'sensitive-read'].includes(item.sensitivity))) {
    return {
      status: 'stop',
      label: 'Stop and review',
      reason: 'The change newly allows privilege-escalation, destructive, or sensitive-read access.',
    };
  }
  if (items.length && items.every((item) => item.conditional)) {
    return {
      status: 'review',
      label: 'Needs context',
      reason: 'Every newly allowed grant is conditional; supply context before relying on the result.',
    };
  }
  if (items.some((item) => item.conditional) && !items.some((item) => !item.conditional)) {
    return {
      status: 'review',
      label: 'Needs context',
      reason: 'Every newly allowed grant is conditional; supply context before relying on the result.',
    };
  }
  return {
    status: 'pass',
    label: 'No checked access increase',
    reason: items.length
      ? 'Newly allowed access is limited to non-sensitive actions under the local rule set.'
      : 'No newly allowed access was detected under the local rule set.',
  };
}

module.exports = {
  SENSITIVITY,
  listNewlyAllowed,
  verdictFromNewlyAllowed,
  classifySensitivity,
};
