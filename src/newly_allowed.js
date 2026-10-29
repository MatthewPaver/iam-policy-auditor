'use strict';

// Diff what an Allow statement newly grants without needing a reviewer to
// guess the right request. Catalogue expansion must never be capped silently.

const actions = require('./actions');
const { denyGuardrailRemovedFinding } = require('./rules');
const { globMatch } = require('./util');

// Sensitivity buckets used by the request-free verdict. Keep them in one place
// so the UI / CLI / rules can share the same wording.
// Privilege-escalation actions follow Rhino Security Labs' list:
// https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
const SENSITIVITY = {
  privesc: [
    'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
    'iam:CreateAccessKey',
    'iam:CreateLoginProfile', 'iam:UpdateLoginProfile',
    'iam:AttachUserPolicy', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy',
    'iam:PutUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy',
    'iam:AddUserToGroup', 'iam:UpdateAssumeRolePolicy',
    'iam:PassRole',
    'lambda:UpdateFunctionCode', 'lambda:UpdateFunctionConfiguration',
    'glue:UpdateDevEndpoint',
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

// Deny removal is still a guardrail loss even when the Allow is bucket-scoped,
// so sensitive-read actions escalate without the usual resource wildcard check.
function classifyDenyRemovedSensitivity(action, resource) {
  const lower = String(action).toLowerCase();
  for (const name of SENSITIVITY.privesc) {
    if (globMatch(name, action) || name.toLowerCase() === lower) return 'privesc';
  }
  for (const name of SENSITIVITY.destructive) {
    if (globMatch(name, action) || name.toLowerCase() === lower) return 'destructive';
  }
  for (const name of SENSITIVITY['sensitive-read']) {
    if (globMatch(name, action) || name.toLowerCase() === lower) return 'sensitive-read';
  }
  return classifySensitivity(action, resource);
}

// Line of the specific action string (or the wildcard that expanded to it).
function actionLine(model, stmt, action) {
  const doc = model.documents.find((d) => d.name === stmt.doc);
  if (!doc || !doc.pointers) return stmt.line;
  const base = stmt.path || '';

  const patterns = (stmt.notActions && stmt.notActions.length)
    ? stmt.notActions
    : (stmt.actions || []);
  const keyRoot = (stmt.notActions && stmt.notActions.length) ? 'NotAction' : 'Action';

  if (action != null && patterns.length) {
    let matchIdx = -1;
    for (let i = 0; i < patterns.length; i++) {
      const pat = String(patterns[i]);
      if (!/[*?]/.test(pat)) {
        if (pat.toLowerCase() === String(action).toLowerCase()) {
          matchIdx = i;
          break;
        }
      } else if (globMatch(pat, action)) {
        // Wildcard matches cite the wildcard's own line, not an expanded name.
        matchIdx = i;
        break;
      }
    }
    if (matchIdx >= 0) {
      const indexed = doc.pointers[`${base}/${keyRoot}/${matchIdx}`];
      if (indexed) return indexed.line;
    }
  }

  for (const suffix of [`/${keyRoot}`, `/${keyRoot}/0`]) {
    const pos = doc.pointers[`${base}${suffix}`];
    if (pos) return pos.line;
  }
  return stmt.line;
}

function stmtMatchesAction(stmt, action) {
  if (stmt.notActions && stmt.notActions.length) {
    return !stmt.notActions.some((p) => globMatch(p, action));
  }
  return (stmt.actions || []).some((p) => globMatch(p, action));
}

function stmtMatchesResource(stmt, resource) {
  const resources = (stmt.resources && stmt.resources.length)
    ? stmt.resources
    : (stmt.kind === 'identity' ? ['*'] : []);
  if (!resources.length) return false;
  if (stmt.notResources && stmt.notResources.length) {
    if (stmt.notResources.some((p) => globMatch(p, resource))) return false;
  }
  return resources.some((p) => globMatch(p, resource));
}

// Snapshot every Deny that can still block an (action, resource) pair.
function collectDenies(model) {
  const denies = [];
  for (const stmt of model.statements) {
    if (stmt.provider !== 'aws' || stmt.effect !== 'Deny') continue;
    denies.push(stmt);
  }
  return denies;
}

function denyCovers(stmt, action, resource) {
  return stmtMatchesAction(stmt, action) && stmtMatchesResource(stmt, resource);
}

function denySnippet(model, stmt) {
  const doc = model.documents.find((d) => d.name === stmt.doc);
  if (!doc || !doc.lines) {
    return stmt.conditions ? JSON.stringify(stmt.conditions) : 'Effect: Deny';
  }
  const from = stmt.line;
  const to = Math.min(stmt.endLine || from, from + 13);
  return doc.lines.slice(from - 1, to).join('\n');
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

    const conditions = stmt.conditions || null;
    const conditional = Boolean(conditions);
    for (const action of granted) {
      const line = actionLine(model, stmt, action);
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
          conditions,
          sensitivity: classifySensitivity(action, resource),
        });
      }
    }
  }
  return { grants, capped };
}

function grantPairKey(item) {
  return `${String(item.action).toLowerCase()}|${item.resource}`;
}

// True when every constraint in `weaker` also appears in `stronger` (same op/key/value).
// An empty / missing condition is the weakest grant and covers any after-side condition.
function conditionIsSubset(weaker, stronger) {
  if (!weaker) return true;
  if (!stronger) return false;
  for (const [op, keys] of Object.entries(weaker)) {
    if (!stronger[op] || typeof stronger[op] !== 'object') return false;
    for (const [key, val] of Object.entries(keys || {})) {
      if (!(key in stronger[op])) return false;
      if (JSON.stringify(stronger[op][key]) !== JSON.stringify(val)) return false;
    }
  }
  return true;
}

// Before covers after when before has no condition, the same condition, or a weaker one.
function beforeCoversAfter(beforeCond, afterCond) {
  if (!beforeCond) return true;
  if (!afterCond) return false;
  if (JSON.stringify(beforeCond) === JSON.stringify(afterCond)) return true;
  return conditionIsSubset(beforeCond, afterCond);
}

// action|resource pairs that appear as Allow grants, ignoring the conditional bit.
function allowPairs(grants) {
  const pairs = new Map();
  for (const item of grants.values()) {
    const key = `${String(item.action).toLowerCase()}|${item.resource}`;
    if (!pairs.has(key)) pairs.set(key, item);
  }
  return pairs;
}

// Condition keys that pin who can use a Principal grant (confused-deputy guards).
const PRINCIPAL_SCOPE_KEYS = /sts:ExternalId|aws:SourceArn|aws:SourceAccount|aws:PrincipalOrgID/i;

function hasPrincipalScope(conditions) {
  if (!conditions) return false;
  return PRINCIPAL_SCOPE_KEYS.test(JSON.stringify(conditions));
}

function principalAccountId(principalId) {
  const id = String(principalId || '');
  if (/^\d{12}$/.test(id)) return id;
  const m = id.match(/^arn:aws:iam::(\d{12}):/);
  return m ? m[1] : null;
}

function isPublicPrincipal(entry) {
  return entry.type === 'any' || entry.id === '*';
}

function expandStmtActions(stmt, state) {
  if (stmt.notActions && stmt.notActions.length) {
    const all = actions.allActions();
    if (!actions.isLoaded()) state.capped = true;
    return all.filter((a) => !stmt.notActions.some((p) => globMatch(p, a)));
  }
  const set = new Set();
  for (const pattern of stmt.actions || []) {
    const raw = String(pattern);
    if (!/[*?]/.test(raw)) {
      set.add(raw);
      continue;
    }
    const result = actions.expand(raw, { cap: Number.MAX_SAFE_INTEGER });
    if (result.capped) state.capped = true;
    if (result.unavailable) {
      set.add(raw);
      state.capped = true;
    } else if (result.actions.length) {
      for (const a of result.actions) set.add(a);
    } else {
      set.add(raw);
    }
  }
  return [...set];
}

function stmtResourcesForPrincipal(stmt) {
  if (stmt.resources && stmt.resources.length) return stmt.resources;
  // Trust policies rarely name a Resource; treat as *.
  if (stmt.kind === 'trust' || stmt.kind === 'identity') return ['*'];
  return ['*'];
}

// Collect Allow grants that name Principal / NotPrincipal (resource + trust).
function collectPrincipalGrants(model) {
  const grants = new Map();
  const state = { capped: false };
  const accounts = new Set();

  for (const stmt of model.statements) {
    if (stmt.provider !== 'aws' || stmt.effect !== 'Allow') continue;
    const hasPrincipal = (stmt.principals && stmt.principals.length)
      || (stmt.notPrincipals && stmt.notPrincipals.length);
    if (!hasPrincipal) continue;

    for (const entry of stmt.principals || []) {
      const account = principalAccountId(entry.id);
      if (account) accounts.add(account);
    }

    const granted = expandStmtActions(stmt, state);
    const resources = stmtResourcesForPrincipal(stmt);
    const scoped = hasPrincipalScope(stmt.conditions);

    for (const entry of stmt.principals || []) {
      for (const action of granted) {
        const line = actionLine(model, stmt, action);
        for (const resource of resources) {
          const key = `${entry.type}|${entry.id}|${String(action).toLowerCase()}|${resource}|${scoped ? 's' : 'u'}`;
          if (grants.has(key)) continue;
          grants.set(key, {
            action,
            resource,
            principal: entry.id,
            principalType: entry.type,
            doc: stmt.doc,
            line,
            sid: stmt.sid || null,
            conditional: Boolean(stmt.conditions),
            scoped,
          });
        }
      }
    }

    // NotPrincipal: remember exclusions so a removed exclusion counts as widening.
    for (const entry of stmt.notPrincipals || []) {
      for (const action of granted) {
        const line = actionLine(model, stmt, action);
        for (const resource of resources) {
          const key = `not|${entry.type}|${entry.id}|${String(action).toLowerCase()}|${resource}|${scoped ? 's' : 'u'}`;
          if (grants.has(key)) continue;
          grants.set(key, {
            action,
            resource,
            principal: entry.id,
            principalType: entry.type,
            notPrincipal: true,
            doc: stmt.doc,
            line,
            sid: stmt.sid || null,
            conditional: Boolean(stmt.conditions),
            scoped,
          });
        }
      }
    }
  }
  return { grants, accounts, capped: state.capped };
}

function classifyPrincipalSensitivity(entry, beforeAccounts, scoped) {
  if (isPublicPrincipal(entry) && !scoped) return 'public';
  const account = principalAccountId(entry.id);
  if (account && !beforeAccounts.has(account)) return 'cross-account';
  return null;
}

function principalActionIsStopWorthy(action, resource) {
  if (/^sts:AssumeRole$/i.test(action)) return true;
  const sens = classifyDenyRemovedSensitivity(action, resource);
  return ['write', 'sensitive-read', 'destructive', 'privesc'].includes(sens);
}

function listNewlyAllowed({ beforeModel, afterModel }) {
  const before = collectGrants(beforeModel);
  const after = collectGrants(afterModel);
  const items = [];
  const narrowed = [];
  const narrowedSeen = new Set();
  const beforeByPair = new Map();
  for (const item of before.grants.values()) {
    const pair = grantPairKey(item);
    if (!beforeByPair.has(pair)) beforeByPair.set(pair, []);
    beforeByPair.get(pair).push(item);
  }
  const afterSeen = new Set();
  for (const item of after.grants.values()) {
    const pair = grantPairKey(item);
    // Same action|resource can appear as both conditional and unconditional keys;
    // only report each pair once for the after side.
    const dedupe = `${pair}|${item.conditional ? 'c' : 'u'}`;
    if (afterSeen.has(dedupe)) continue;
    afterSeen.add(dedupe);

    const befores = beforeByPair.get(pair) || [];
    const covering = befores.find((b) => beforeCoversAfter(b.conditions, item.conditions));
    if (covering) {
      // Unconditional before + conditional after is a narrowing, not new access.
      if (!covering.conditions && item.conditions && !narrowedSeen.has(pair)) {
        narrowedSeen.add(pair);
        narrowed.push({
          action: item.action,
          resource: item.resource,
          line: item.line,
          reason: 'condition-added',
        });
      }
      continue;
    }
    items.push(item);
  }

  // Same Allow on both sides, but a Deny that used to cover it is gone / narrower.
  const beforeDenies = collectDenies(beforeModel);
  const afterDenies = collectDenies(afterModel);
  const beforePairs = allowPairs(before.grants);
  const afterPairs = allowPairs(after.grants);
  const findings = [];
  const seenFinding = new Set();

  for (const [key, afterItem] of afterPairs) {
    if (!beforePairs.has(key)) continue;
    const coveringBefore = beforeDenies.filter((d) => denyCovers(d, afterItem.action, afterItem.resource));
    if (!coveringBefore.length) continue;
    const stillCovered = afterDenies.some((d) => denyCovers(d, afterItem.action, afterItem.resource));
    if (stillCovered) continue;

    // Prefer the first covering Deny for evidence (stable statement order).
    const removed = coveringBefore[0];
    const sensitivity = classifyDenyRemovedSensitivity(afterItem.action, afterItem.resource);
    items.push({
      action: afterItem.action,
      resource: afterItem.resource,
      doc: afterItem.doc,
      line: afterItem.line,
      sid: afterItem.sid,
      conditional: afterItem.conditional,
      sensitivity,
      reason: 'deny-removed',
      denyLine: removed.line,
      denyCondition: removed.conditions || null,
    });

    const findingKey = `${removed.doc}|${removed.line}|${JSON.stringify(removed.conditions || null)}`;
    if (!seenFinding.has(findingKey)) {
      seenFinding.add(findingKey);
      findings.push(denyGuardrailRemovedFinding({
        action: afterItem.action,
        resource: afterItem.resource,
        denyDoc: removed.doc,
        denyLine: removed.line,
        denyEndLine: removed.endLine,
        denyCondition: removed.conditions || null,
        snippet: denySnippet(beforeModel, removed),
      }));
    }
  }

  // Principal / NotPrincipal set growth (and scope-key removal).
  const beforePrinc = collectPrincipalGrants(beforeModel);
  const afterPrinc = collectPrincipalGrants(afterModel);

  for (const [key, afterItem] of afterPrinc.grants) {
    if (afterItem.notPrincipal) continue; // exclusions are handled below
    if (beforePrinc.grants.has(key)) continue;

    // Same principal+action+resource already present with a scope pin → dropping
    // ExternalId / SourceArn / SourceAccount / PrincipalOrgID is widening.
    const scopedKey = key.replace(/\|u$/, '|s');
    const hadScoped = beforePrinc.grants.has(scopedKey);
    const isNewPrincipal = ![...beforePrinc.grants.values()].some((b) => (
      !b.notPrincipal
      && b.principal === afterItem.principal
      && b.principalType === afterItem.principalType
      && String(b.action).toLowerCase() === String(afterItem.action).toLowerCase()
      && b.resource === afterItem.resource
    ));

    if (!isNewPrincipal && !hadScoped && !afterItem.scoped) {
      // Same principal, still unscoped — not a widening we track here.
      // (Action/resource changes fall through the normal Allow path.)
      const sameUnscoped = [...beforePrinc.grants.values()].some((b) => (
        !b.notPrincipal
        && b.principal === afterItem.principal
        && !b.scoped
        && String(b.action).toLowerCase() === String(afterItem.action).toLowerCase()
        && b.resource === afterItem.resource
      ));
      if (sameUnscoped) continue;
    }

    const entry = { type: afterItem.principalType, id: afterItem.principal };
    const principalSens = classifyPrincipalSensitivity(entry, beforePrinc.accounts, afterItem.scoped);
    const sensitivity = principalSens || classifySensitivity(afterItem.action, afterItem.resource);
    items.push({
      action: afterItem.action,
      resource: afterItem.resource,
      doc: afterItem.doc,
      line: afterItem.line,
      sid: afterItem.sid,
      conditional: afterItem.conditional,
      sensitivity,
      reason: 'principal-widened',
      principal: afterItem.principal,
    });
  }

  // NotPrincipal shrinkage: an exclusion present before but not after.
  for (const [key, beforeItem] of beforePrinc.grants) {
    if (!beforeItem.notPrincipal) continue;
    if (afterPrinc.grants.has(key)) continue;
    const entry = { type: beforeItem.principalType, id: beforeItem.principal };
    const principalSens = classifyPrincipalSensitivity(entry, beforePrinc.accounts, false);
    const sensitivity = principalSens || classifySensitivity(beforeItem.action, beforeItem.resource);
    items.push({
      action: beforeItem.action,
      resource: beforeItem.resource,
      doc: beforeItem.doc,
      line: beforeItem.line,
      sid: beforeItem.sid,
      conditional: beforeItem.conditional,
      sensitivity,
      reason: 'principal-widened',
      principal: beforeItem.principal,
    });
  }

  // Stable order: sensitivity severity then action name.
  const rank = {
    public: 0,
    'cross-account': 1,
    privesc: 2,
    destructive: 3,
    'sensitive-read': 4,
    write: 5,
    read: 6,
  };
  items.sort((a, b) => ((rank[a.sensitivity] ?? 9) - (rank[b.sensitivity] ?? 9))
    || a.action.localeCompare(b.action)
    || a.resource.localeCompare(b.resource));
  return {
    items,
    narrowed,
    capped: before.capped || after.capped || beforePrinc.capped || afterPrinc.capped,
    findings,
  };
}

function verdictFromNewlyAllowed(newlyAllowed) {
  const items = newlyAllowed.items || [];
  // Unconditional sensitive grants still stop; conditional ones are handled below.
  if (items.some((item) => !item.conditional
    && ['privesc', 'destructive', 'sensitive-read'].includes(item.sensitivity))) {
    return {
      status: 'stop',
      label: 'Stop and review',
      reason: 'The change newly allows privilege-escalation, destructive, or sensitive-read access.',
    };
  }
  // A removed Deny over write (or the buckets above) is still a stop — the
  // Allow was already there; the guardrail was the only thing holding it back.
  if (items.some((item) => item.reason === 'deny-removed'
    && ['privesc', 'destructive', 'sensitive-read', 'write'].includes(item.sensitivity))) {
    return {
      status: 'stop',
      label: 'Stop and review',
      reason: 'The change removes or narrows a Deny guardrail over sensitive access.',
    };
  }
  if (items.some((item) => item.reason === 'principal-widened'
    && ['public', 'cross-account'].includes(item.sensitivity)
    && principalActionIsStopWorthy(item.action, item.resource))) {
    return {
      status: 'stop',
      label: 'Stop and review',
      reason: 'The change newly allows a public or cross-account principal on sensitive access.',
    };
  }
  // Conditional non-read access still needs a human (Review Focus 3).
  if (items.some((item) => item.conditional && item.sensitivity !== 'read')) {
    return {
      status: 'review',
      label: 'Needs context',
      reason: 'The change newly allows conditional access that is not read-only; supply context before relying on the result.',
    };
  }
  if (items.some((item) => item.conditional && item.sensitivity === 'read')) {
    return {
      status: 'pass',
      label: 'No checked access increase',
      reason: 'Newly allowed access is conditional read-only under the local rule set.',
      note: 'One or more new grants are conditional; confirm the condition keys match the intended callers.',
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
