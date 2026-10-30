'use strict';

// Diff what an Allow statement newly grants without needing a reviewer to
// guess the right request. Catalogue expansion must never be capped silently.

const actions = require('./actions');
const { denyGuardrailRemovedFinding, AWS_ESCALATION_ACTIONS, AWS_SENSITIVE_ACTIONS,
  AWS_SENSITIVE_READ, AWS_SENSITIVE_READ_RESOURCES } = require('./rules');
const { globMatch } = require('./util');

// Sensitivity buckets used by the request-free verdict. Keep them in one place
// so the UI / CLI / rules can share the same wording.
// Privilege-escalation actions follow Rhino Security Labs' list:
// https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
const SENSITIVITY = {
  privesc: [
    ...AWS_ESCALATION_ACTIONS, 'iam:PassRole',
    'sts:AssumeRole',
    'sagemaker:CreatePresignedNotebookInstanceUrl', 'sagemaker:CreatePresignedDomainUrl',
  ],
  // Shell / serial / SSM / ECS exec paths — stop like privilege escalation.
  'remote-exec': [
    'ssm:SendCommand', 'ssm:StartSession', 'ssm:StartAutomationExecution',
    'ec2-instance-connect:SendSSHPublicKey',
    'ec2-instance-connect:SendSerialConsoleSSHPublicKey',
    'ecs:ExecuteCommand',
    'ec2:ModifyInstanceAttribute',
  ],
  destructive: AWS_SENSITIVE_ACTIONS,
  'sensitive-read': [
    ...AWS_SENSITIVE_READ, 'ssm:GetParameter*',
    'sqs:ReceiveMessage',
    'dynamodb:GetItem', 'dynamodb:BatchGetItem', 'dynamodb:Query', 'dynamodb:Scan',
    'rds-data:ExecuteStatement',
    'logs:GetLogEvents', 'logs:FilterLogEvents',
  ],
  read: ['account:GetAccountInformation'],
};

// Message / data-service reads are sensitive even when scoped to one queue/table.
const ALWAYS_SENSITIVE_READ = new Set([
  'sqs:receivemessage',
  'dynamodb:getitem', 'dynamodb:batchgetitem', 'dynamodb:query', 'dynamodb:scan',
  'rds-data:executestatement',
  'logs:getlogevents', 'logs:filterlogevents',
  'ssm:getparameter', 'ssm:getparameters', 'ssm:getparametersbypath',
]);

function matchesSensitivityList(list, action, lower) {
  return list.some((name) => globMatch(name, action) || name.toLowerCase() === lower);
}

function broadResource(resource) {
  if (resource === '*') return true;
  const parts = String(resource).split(':');
  if (parts[0] !== 'arn') return false;
  if (/[*?]/.test(parts[4] || '')) return true;
  const name = parts.slice(5).join(':');
  return /^[*?]/.test(name) || /(?:^|[:/])[*?]$/.test(name) && !/^s3$/.test(parts[2]);
}

function classifySensitivity(action, resource, conditional = false) {
  const lower = String(action).toLowerCase();
  if (matchesSensitivityList(SENSITIVITY.read, action, lower)) return 'read';
  if (matchesSensitivityList(SENSITIVITY.privesc, action, lower)) return 'privesc';
  if (matchesSensitivityList(SENSITIVITY['remote-exec'], action, lower)) return 'remote-exec';
  if (matchesSensitivityList(SENSITIVITY.destructive, action, lower)) return 'destructive';
  if (matchesSensitivityList(SENSITIVITY['sensitive-read'], action, lower)) {
    // Queue/table/log/parameter reads are sensitive on any resource ARN.
    if (ALWAYS_SENSITIVE_READ.has(lower)) return 'sensitive-read';
    // Classic secrets/object reads only escalate when scoped to everything.
    if (AWS_SENSITIVE_READ_RESOURCES.includes(String(resource))) {
      return 'sensitive-read';
    }
    if (/^arn:aws:s3:::\*/i.test(String(resource))) return 'sensitive-read';
  }
  const level = actions.accessLevel(action);
  const name = String(action).split(':')[1] || '';
  if (level === 'Permissions management') return broadResource(resource) ? 'privesc' : 'write';
  if (level === 'Write' && broadResource(resource)
    && /^(Delete|Terminate|Destroy|Remove|Purge|Disable|Stop|Reset|Modify|Update|Put|Create|Run|Start|Invoke|Execute)/i.test(name)) return 'destructive';
  if (!conditional && level === 'Read' && broadResource(resource)
    && !/(Status|Configuration|Policy)$/i.test(name)
    && /^(Get|BatchGet|Query|Scan|Receive|Download|Export|Decrypt|Retrieve|Select|CreatePresigned)/i.test(name)) return 'sensitive-read';
  if (level === 'Write' || level === 'Tagging') return 'write';
  return 'read';
}

// Deny removal is still a guardrail loss even when the Allow is bucket-scoped,
// so sensitive-read actions escalate without the usual resource wildcard check.
function classifyDenyRemovedSensitivity(action, resource) {
  const lower = String(action).toLowerCase();
  if (matchesSensitivityList(SENSITIVITY.privesc, action, lower)) return 'privesc';
  if (matchesSensitivityList(SENSITIVITY['remote-exec'], action, lower)) return 'remote-exec';
  if (matchesSensitivityList(SENSITIVITY.destructive, action, lower)) return 'destructive';
  if (matchesSensitivityList(SENSITIVITY['sensitive-read'], action, lower)) return 'sensitive-read';
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
      const matches = /[*?]/.test(pat)
        ? globMatch(pat, action) : pat.toLowerCase() === String(action).toLowerCase();
      if (matches) {
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
  const state = { capped: false };

  for (const stmt of model.statements) {
    if (stmt.provider !== 'aws' || stmt.effect !== 'Allow') continue;
    const resources = (stmt.resources && stmt.resources.length)
      ? stmt.resources
      : (stmt.kind === 'identity' ? ['*'] : []);
    if (!resources.length) continue;

    const granted = expandStmtActions(stmt, state);

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
          principal: (stmt.principals || []).map((p) => p.id).join(", ") || undefined,
          sensitivity: classifySensitivity(action, resource, conditional),
        });
      }
    }
  }
  return { grants, capped: state.capped };
}

function grantPairKey(item) {
  return `${String(item.action).toLowerCase()}|${item.resource}`;
}

// Before covers after when before has no condition, the same condition, or a weaker one.
// True when every constraint in `weaker` also appears in `stronger` (same op/key/value).
// An empty / missing condition is the weakest grant and covers any after-side condition.
function conditionIsSubset(weaker, stronger) {
  if (!weaker) return true;
  if (!stronger) return false;
  if (JSON.stringify(weaker) === JSON.stringify(stronger)) return true;
  for (const [op, keys] of Object.entries(weaker)) {
    if (!stronger[op] || typeof stronger[op] !== 'object') return false;
    for (const [key, val] of Object.entries(keys || {})) {
      if (!(key in stronger[op])) return false;
      if (JSON.stringify(stronger[op][key]) !== JSON.stringify(val)) return false;
    }
  }
  return true;
}

const SECURITY_KEYS = new Set([
  'aws:multifactorauthpresent', 'aws:sourceip', 'aws:principalorgid',
  'aws:securetransport', 'aws:sourcearn', 'aws:sourceaccount',
  'sts:externalid', 'aws:requestedregion',
]);

function ipv4Range(cidr) {
  const [address, width = '32'] = String(cidr).split('/');
  const octets = address.split('.');
  const bits = Number(width);
  if (octets.length !== 4 || !/^\d+$/.test(width) || bits < 0 || bits > 32
    || octets.some((n) => !/^\d+$/.test(n) || Number(n) > 255)) return null;
  const ip = octets.reduce((value, n) => value * 256 + Number(n), 0);
  const size = 2 ** (32 - bits);
  const start = Math.floor(ip / size) * size;
  return { start, end: start + size - 1 };
}

function securityConditionWeakened(before, after) {
  for (const [op, keys] of Object.entries(before || {})) {
    for (const [key, value] of Object.entries(keys || {})) {
      if (!SECURITY_KEYS.has(key.toLowerCase()) && !/^s3:existingobjecttag\//i.test(key)) continue;
      const entries = Object.entries(after || {}).flatMap(([nextOp, nextKeys]) =>
        Object.entries(nextKeys || {}).filter(([k]) => k.toLowerCase() === key.toLowerCase())
          .map(([, v]) => ({ op: nextOp, values: [].concat(v).map(String) })));
      if (!entries.length) return true;
      const oldValues = [].concat(value).map(String);
      for (const entry of entries) {
        if (entry.op === `${op}IfExists`) return true;
        if (op === 'StringEquals' && entry.op === 'StringLike'
          && entry.values.some((v) => /[*?]/.test(v))) return true;
        if (entry.op !== op) continue;
        if (entry.values.length > oldValues.length && oldValues.every((v) => entry.values.includes(v))) return true;
        if (op === 'IpAddress' && entry.values.some((v) => {
          const next = ipv4Range(v);
          return next && oldValues.some((old) => {
            const previous = ipv4Range(old);
            return previous && next.start <= previous.start && next.end >= previous.end
              && (next.start < previous.start || next.end > previous.end);
          });
        })) return true;
      }
    }
  }
  return false;
}

// action|resource pairs that appear as Allow grants, ignoring the conditional bit.
function allowPairs(grants) {
  const pairs = new Map();
  for (const item of grants.values()) {
    const key = grantPairKey(item);
    if (!pairs.has(key)) pairs.set(key, item);
  }
  return pairs;
}

// Condition keys that pin who can use a Principal grant (confused-deputy guards).
const PRINCIPAL_SCOPE_KEYS = /sts:ExternalId|aws:SourceArn|aws:SourceAccount|aws:PrincipalOrgID/i;

function hasPrincipalScope(conditions) {
  if (!conditions) return false;
  if (PRINCIPAL_SCOPE_KEYS.test(JSON.stringify(conditions))) return true;
  return Object.entries(conditions.StringEquals || {}).some(([key, value]) =>
    key.toLowerCase() === 'kms:calleraccount' && [].concat(value).length > 0
    && [].concat(value).every((account) => /^\d{12}$/.test(String(account))));
}

function principalAccountId(principalId) {
  const id = String(principalId || '');
  if (/^\d{12}$/.test(id)) return id;
  const m = id.match(/^arn:aws:iam::(\d{12}):/);
  return m ? m[1] : null;
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
    // Trust policies rarely name a Resource; treat as *.
    const resources = stmt.resources?.length ? stmt.resources : ['*'];
    const scoped = hasPrincipalScope(stmt.conditions);

    // NotPrincipal: remember exclusions so a removed exclusion counts as widening.
    for (const [entries, notPrincipal] of [[stmt.principals, false], [stmt.notPrincipals, true]]) {
      for (const entry of entries || []) {
        for (const action of granted) {
          const line = actionLine(model, stmt, action);
          for (const resource of resources) {
            const key = `${notPrincipal ? 'not|' : ''}${entry.type}|${entry.id}|${String(action).toLowerCase()}|${resource}|${scoped ? 's' : 'u'}`;
            if (grants.has(key)) continue;
            grants.set(key, {
              action,
              resource,
              principal: entry.id,
              principalType: entry.type,
              ...(notPrincipal ? { notPrincipal: true } : {}),
              doc: stmt.doc,
              line,
              sid: stmt.sid || null,
              conditional: Boolean(stmt.conditions),
              conditions: stmt.conditions || null,
              scoped,
            });
          }
        }
      }
    }
  }
  return { grants, accounts, capped: state.capped };
}

function classifyPrincipalSensitivity(entry, beforeAccounts, scoped) {
  if ((entry.type === 'any' || entry.id === '*') && !scoped) return 'public';
  const account = principalAccountId(entry.id);
  if (account && !beforeAccounts.has(account)) return 'cross-account';
  return null;
}

function listNewlyAllowed({ beforeModel, afterModel }) {
  const before = collectGrants(beforeModel);
  const after = collectGrants(afterModel);
  const commandInstances = [...after.grants.values()].filter((i) => /^ssm:SendCommand$/i.test(i.action)
    && (i.resource === '*' || /:instance\//.test(i.resource)));
  const commandScoped = commandInstances.length > 0 && commandInstances.every(scopedSensitive);
  const items = [];
  const narrowed = [];
  const narrowedSeen = new Set();
  const beforeByPair = new Map();
  const beforeByAction = new Map();
  for (const item of before.grants.values()) {
    const action = item.action.toLowerCase();
    if (!beforeByAction.has(action)) beforeByAction.set(action, []);
    beforeByAction.get(action).push(item);
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

    const befores = [...(beforeByPair.get(pair) || []), ...(beforeByAction.get(item.action.toLowerCase()) || []).filter((b) =>
      b.action.toLowerCase() === item.action.toLowerCase() && b.resource !== item.resource
      && (b.resource === '*' || !/[*?]/.test(item.resource) && globMatch(b.resource, item.resource)))];
    const covering = befores.find((b) => conditionIsSubset(b.conditions, item.conditions));
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
    const weakened = befores.find((b) => securityConditionWeakened(b.conditions, item.conditions));
    items.push(weakened ? {
      ...item,
      reason: 'condition-weakened',
      beforeCondition: weakened.conditions,
      afterCondition: item.conditions,
      beforeConditionText: JSON.stringify(weakened.conditions),
      afterConditionText: JSON.stringify(item.conditions),
    } : item);
  }

  // Same Allow on both sides, but a Deny that used to cover it is gone / narrower.
  const beforeDenies = beforeModel.statements.filter((stmt) => stmt.provider === 'aws' && stmt.effect === 'Deny');
  const afterDenies = afterModel.statements.filter((stmt) => stmt.provider === 'aws' && stmt.effect === 'Deny');
  // Without an Allow, a lost Deny is only potential access in another policy.
  if (!before.grants.size && !after.grants.size) {
    for (const deny of beforeDenies) {
      for (const action of expandStmtActions(deny, { capped: false })) {
        for (const resource of deny.resources || ['*']) {
          if (afterDenies.some((d) => stmtMatchesAction(d, action) && stmtMatchesResource(d, resource)
            && conditionIsSubset(d.conditions, deny.conditions))) continue;
          items.push({ action, resource, line: deny.line, doc: deny.doc,
            sensitivity: 'write', reason: 'deny-removed', potentialOnly: true });
        }
      }
    }
  }
  const beforePairs = allowPairs(before.grants);
  const afterPairs = allowPairs(after.grants);
  const findings = [];
  const seenFinding = new Set();

  for (const [key, afterItem] of afterPairs) {
    if (!beforePairs.has(key)) continue;
    const coveringBefore = beforeDenies.filter((d) => stmtMatchesAction(d, afterItem.action) && stmtMatchesResource(d, afterItem.resource));
    if (!coveringBefore.length) continue;
    const stillCovered = afterDenies.some((d) => stmtMatchesAction(d, afterItem.action) && stmtMatchesResource(d, afterItem.resource));
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
      conditions: afterItem.conditions,
      principal: afterItem.principal,
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
    if (afterItem.notPrincipal) {
      const existed = [...beforePrinc.grants.values()].some((entry) => entry.notPrincipal
        && String(entry.action).toLowerCase() === String(afterItem.action).toLowerCase()
        && entry.resource === afterItem.resource);
      if (!existed) {
        items.push({ ...afterItem, excludedPrincipal: afterItem.principal, principal: '*', sensitivity: 'public', reason: 'principal-widened' });
      }
      continue;
    } // exclusions removed from existing grants are handled below
    if (beforePrinc.grants.has(key)) continue;
    if ([...beforePrinc.grants.values()].some((b) => !b.notPrincipal
      && b.principal === afterItem.principal && b.principalType === afterItem.principalType
      && b.action.toLowerCase() === afterItem.action.toLowerCase()
      && (b.resource === '*' || !/[*?]/.test(afterItem.resource) && globMatch(b.resource, afterItem.resource))
      && conditionIsSubset(b.conditions, afterItem.conditions))) continue;

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
    const existingPrincipal = [...beforePrinc.grants.values()].some((b) =>
      b.principal === afterItem.principal && !b.notPrincipal);
    const principalSens = classifyPrincipalSensitivity(entry,
      existingPrincipal ? new Set() : beforePrinc.accounts, afterItem.scoped);
    const sensitivity = principalSens || classifySensitivity(afterItem.action, afterItem.resource);
    items.push({
      action: afterItem.action,
      resource: afterItem.resource,
      doc: afterItem.doc,
      line: afterItem.line,
      sid: afterItem.sid,
      conditional: afterItem.conditional,
      conditions: afterItem.conditions,
      principal: afterItem.principal,
      sensitivity,
      reason: 'principal-widened',
    });
  }

  // NotPrincipal shrinkage: an exclusion present before but not after.
  for (const [key, beforeItem] of beforePrinc.grants) {
    if (!beforeItem.notPrincipal) continue;
    if (afterPrinc.grants.has(key)) continue;
    if (![...afterPrinc.grants.values()].some((entry) =>
      String(entry.action).toLowerCase() === String(beforeItem.action).toLowerCase()
      && entry.resource === beforeItem.resource)) continue;
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
    'remote-exec': 3,
    destructive: 4,
    'sensitive-read': 5,
    write: 6,
    read: 7,
  };
  if (commandScoped) for (const item of items) {
    if (/^ssm:SendCommand$/i.test(item.action)) item.commandScoped = true;
  }
  items.sort((a, b) => ((rank[a.sensitivity] ?? 9) - (rank[b.sensitivity] ?? 9))
    || Number(matchesSensitivityList(AWS_SENSITIVE_READ, b.action, b.action.toLowerCase()))
      - Number(matchesSensitivityList(AWS_SENSITIVE_READ, a.action, a.action.toLowerCase()))
    || a.action.localeCompare(b.action)
    || a.resource.localeCompare(b.resource));
  const principalLines = new Set(items.filter((item) => item.reason === 'principal-widened')
    .map((item) => `${grantPairKey(item)}|${item.doc}|${item.line}`));
  return {
    items: items.filter((item) => item.reason || !principalLines.has(`${grantPairKey(item)}|${item.doc}|${item.line}`))
      .map((item) => ({ ...item, sentence: explainItem(item), risk: classifyVerdict({ items: [item] }).status })),
    narrowed,
    capped: before.capped || after.capped || beforePrinc.capped || afterPrinc.capped,
    findings,
  };
}

function scopedSensitive(item) {
  if (item.commandScoped) return true;
  if (item.sensitivity === 'sensitive-read' && /^logs:/i.test(item.action)
    && /^arn:[^:]+:logs:[^*?:]+:\d{12}:log-group:[^*?:]+(?::\*)?$/.test(item.resource)) return true;
  if (!['remote-exec', 'destructive', 'privesc'].includes(item.sensitivity)) return false;
  const parts = String(item.resource).split(':');
  // Attaching an arbitrary policy can escalate even a single named identity.
  if (/^iam:(?:Attach|Put)(?:User|Group|Role)Policy$/i.test(item.action)) return false;
  const named = parts[0] === 'arn' && !/[*?]/.test(parts[4] || '')
    && !item.resource.includes('${') && !broadResource(item.resource);
  const tagged = Object.entries({ ...item.conditions?.StringEquals, ...item.conditions?.StringLike }).some(([key]) =>
    /^(aws|ec2|ssm):resourcetag\//i.test(key));
  return named || tagged;
}

function classifyVerdict(newlyAllowed) {
  const items = newlyAllowed.items || [];
  if (items.some((item) => item.reason === 'condition-weakened')) {
    return { status: 'stop', label: 'Stop and review', reason: 'The change weakens a security condition.' };
  }
  // Unconditional sensitive grants still stop; conditional ones are handled below.
  if (items.some((item) => !item.conditional && !scopedSensitive(item)
    && ['privesc', 'remote-exec', 'destructive', 'sensitive-read'].includes(item.sensitivity))) {
    return {
      status: 'stop',
      label: 'Stop and review',
      reason: 'The change newly allows privilege-escalation, remote-execution, destructive, or sensitive-read access.',
    };
  }
  // A removed Deny over write (or the buckets above) is still a stop — the
  // Allow was already there; the guardrail was the only thing holding it back.
  if (items.some((item) => item.reason === 'deny-removed'
    && !item.potentialOnly
    && ['privesc', 'remote-exec', 'destructive', 'sensitive-read', 'write'].includes(item.sensitivity))) {
    return {
      status: 'stop',
      label: 'Stop and review',
      reason: 'The change removes or narrows a Deny guardrail over sensitive access.',
    };
  }
  if (items.some((item) => item.reason === 'principal-widened'
    && ['public', 'cross-account'].includes(item.sensitivity)
    && actions.accessLevel(item.action) !== 'List')) {
    return {
      status: 'stop',
      label: 'Stop and review',
      reason: 'The change newly allows a public or cross-account principal on sensitive access.',
    };
  }
  if (items.some(scopedSensitive)) {
    return { status: 'review', label: 'Needs context', reason: 'The change adds scoped or tag-conditioned sensitive access.' };
  }
  if (items.some((item) => item.potentialOnly)) {
    return { status: 'review', label: 'Needs context', reason: 'A Deny was removed; another policy could now grant this access.' };
  }
  if (items.some((item) => !item.conditional && item.sensitivity === 'write'
    && !broadResource(item.resource))) {
    return { status: 'review', label: 'Needs context', reason: 'The change adds scoped write or permissions-management access.' };
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

function explainItem(item) {
  const level = actions.accessLevel(item.action);
  const service = actions.serviceName(item.action);
  const resource = String(item.resource || '*');
  const principal = item.principal;
  const who = item.notPrincipal ? `Everyone except ${item.excludedPrincipal || principal}`
    : principal === '*' ? (!item.conditional || item.sensitivity === 'public' ? 'Anyone on the internet' : 'Callers matching the supplied conditions')
      : principal ? `Principal ${principal}` : 'This identity';
  let what = level === 'Read' ? `read ${service} data` : level === 'List' ? `list ${service} resources`
    : level === 'Permissions management' ? `change who has access through ${service}`
      : level === 'Tagging' ? `change ${service} tags` : level === 'Write' ? `change ${service} data`
        : `request ${item.action}`;
  let where = resource === '*' ? ' on any resource' : ` on ${resource}`;
  if (/^s3:GetObject$/i.test(item.action)) {
    what = resource === '*' ? 'read any object in any S3 bucket' : `read objects in S3 bucket ${resource.replace(/^arn:[^:]+:s3:::/, '')}`;
    where = '';
  } else if (/^sqs:ReceiveMessage$/i.test(item.action) && resource !== '*') {
    what = `read messages from queue ${resource.split(':').pop()}`;
    where = '';
  }
  const condition = item.conditional ? ' when the supplied conditions match' : '';
  if (item.reason === 'deny-removed') {
    return `The rule that blocked ${who === 'This identity' ? 'this identity' : who} from being able to ${what}${where} was removed${item.potentialOnly ? '; an Allow in another policy is still needed' : ''}.`;
  }
  if (item.reason === 'condition-weakened') {
    return `The restriction was weakened: ${who} can now ${what}${where}${condition}.`;
  }
  return `${who} can now ${what}${where}${condition}.`;
}

function verdictFromNewlyAllowed(newlyAllowed) {
  const verdict = classifyVerdict(newlyAllowed);
  const items = newlyAllowed.items || [];
  const top = items.find((item) => (item.risk || classifyVerdict({ items: [item] }).status) === verdict.status);
  const lower = items.filter((item) => (item.risk || classifyVerdict({ items: [item] }).status) === 'pass').length;
  const label = verdict.status === 'stop' ? 'Stop' : verdict.status === 'review' ? 'Check' : 'Pass';
  const detail = top ? explainItem(top) : verdict.reason;
  return { ...verdict, sentence: `${label}: ${detail}${lower && verdict.status !== 'pass' ? ` ${lower} lower-risk addition${lower === 1 ? ' is' : 's are'} listed below.` : ''}` };
}

module.exports = {
  SENSITIVITY,
  listNewlyAllowed,
  verdictFromNewlyAllowed,
  classifySensitivity,
  explainItem,
};
