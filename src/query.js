'use strict';

const { uniq, globMatch } = require('./util');
const { stmtAllows, stmtExplicitlyAllows } = require('./rules');

// ---------------------------------------------------------------------------
// Concept knowledge base: maps plain-English intents to concrete permissions
// per provider. IBM Cloud is role-based, so concepts carry a minimum-role set.
// ---------------------------------------------------------------------------

const CONCEPTS = [
  {
    id: 'delete-database', label: 'delete databases',
    verbs: ['delete', 'drop', 'destroy', 'remove', 'terminate', 'wipe'],
    nouns: ['database', 'databases', 'db', 'dbs', 'rds', 'dynamodb', 'table', 'tables', 'cluster'],
    aws: ['rds:DeleteDBInstance', 'rds:DeleteDBCluster', 'dynamodb:DeleteTable', 'redshift:DeleteCluster', 'elasticache:DeleteCacheCluster'],
    gcp: ['cloudsql.instances.delete', 'spanner.instances.delete', 'bigtable.instances.delete', 'datastore.databases.delete'],
    azure: ['Microsoft.Sql/servers/databases/delete', 'Microsoft.DBforPostgreSQL/flexibleServers/delete', 'Microsoft.DocumentDB/databaseAccounts/delete'],
    ibmMinRoles: ['Administrator', 'Editor', 'Manager'],
  },
  {
    id: 'delete-storage', label: 'delete storage buckets/objects',
    verbs: ['delete', 'destroy', 'remove', 'wipe', 'empty'],
    nouns: ['bucket', 'buckets', 'storage', 's3', 'object', 'objects', 'blob', 'blobs'],
    aws: ['s3:DeleteBucket', 's3:DeleteObject'],
    gcp: ['storage.buckets.delete', 'storage.objects.delete'],
    azure: ['Microsoft.Storage/storageAccounts/delete', 'Microsoft.Storage/storageAccounts/blobServices/containers/delete'],
    ibmMinRoles: ['Administrator', 'Manager', 'Writer'],
  },
  {
    id: 'read-secrets', label: 'read secrets / decrypt data',
    verbs: ['read', 'get', 'access', 'view', 'decrypt', 'retrieve', 'exfiltrate', 'steal'],
    nouns: ['secret', 'secrets', 'credentials', 'keys', 'kms', 'vault', 'parameter', 'parameters', 'password', 'passwords'],
    aws: ['secretsmanager:GetSecretValue', 'ssm:GetParameter', 'ssm:GetParameters', 'kms:Decrypt'],
    gcp: ['secretmanager.versions.access'],
    azure: ['Microsoft.KeyVault/vaults/secrets/getSecret/action', 'Microsoft.KeyVault/vaults/secrets/read'],
    ibmMinRoles: ['Administrator', 'Manager', 'Writer', 'SecretsReader'],
  },
  {
    id: 'admin', label: 'full administrative access',
    verbs: ['have', 'has', 'hold', 'get', 'gets'],
    nouns: ['admin', 'administrator', 'administrative', 'root', 'full access', 'everything', 'god mode', 'superuser'],
    aws: ['*:*'], awsSpecial: 'admin',
    gcp: ['__admin__'],
    azure: ['*'],
    ibmMinRoles: ['Administrator'],
  },
  {
    id: 'assume-role', label: 'assume roles / cross-account access',
    verbs: ['assume', 'switch', 'impersonate', 'federate', 'use'],
    nouns: ['role', 'roles', 'cross-account', 'cross account', 'sts', 'identity', 'identities'],
    aws: ['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity', 'sts:AssumeRoleWithSAML'],
    gcp: ['iam.serviceAccounts.getAccessToken', 'iam.serviceAccounts.actAs'],
    azure: [],
    ibmMinRoles: [],
  },
  {
    id: 'manage-iam', label: 'change permissions / manage IAM',
    verbs: ['change', 'modify', 'manage', 'edit', 'grant', 'escalate', 'attach', 'update', 'alter'],
    nouns: ['iam', 'permission', 'permissions', 'policy', 'policies', 'access', 'privilege', 'privileges', 'rbac'],
    aws: ['iam:CreatePolicyVersion', 'iam:AttachUserPolicy', 'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy', 'iam:CreateAccessKey', 'iam:AddUserToGroup'],
    gcp: ['resourcemanager.projects.setIamPolicy', 'iam.roles.update', 'iam.serviceAccounts.setIamPolicy'],
    azure: ['Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleDefinitions/write'],
    ibmMinRoles: ['Administrator'],
  },
  {
    id: 'delete-logs', label: 'delete or disable audit logs',
    verbs: ['delete', 'disable', 'stop', 'tamper', 'remove', 'clear'],
    nouns: ['log', 'logs', 'logging', 'trail', 'cloudtrail', 'audit', 'auditing'],
    aws: ['cloudtrail:DeleteTrail', 'cloudtrail:StopLogging', 'logs:DeleteLogGroup'],
    gcp: ['logging.sinks.delete', 'logging.logs.delete'],
    azure: ['Microsoft.Insights/diagnosticSettings/delete'],
    ibmMinRoles: ['Administrator', 'Manager'],
  },
  {
    id: 'pass-role', label: 'pass roles to services',
    verbs: ['pass', 'attach', 'assign'],
    nouns: ['passrole', 'pass role', 'role to service', 'instance profile'],
    aws: ['iam:PassRole'],
    gcp: ['iam.serviceAccounts.actAs'],
    azure: [],
    ibmMinRoles: [],
  },
  {
    id: 'read-data', label: 'read data (objects/tables)',
    verbs: ['read', 'get', 'download', 'access', 'view', 'list', 'see'],
    nouns: ['data', 'object', 'objects', 'file', 'files', 'bucket', 'buckets', 'table', 'tables', 'records'],
    aws: ['s3:GetObject', 'dynamodb:GetItem', 'dynamodb:Scan', 'rds:DescribeDBInstances'],
    gcp: ['storage.objects.get', 'bigquery.tables.getData'],
    azure: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'],
    ibmMinRoles: ['Administrator', 'Manager', 'Writer', 'Reader', 'Viewer', 'Editor', 'Operator'],
  },
  {
    id: 'create-users', label: 'create users / access keys',
    verbs: ['create', 'add', 'provision', 'make'],
    nouns: ['user', 'users', 'access key', 'access keys', 'account', 'accounts', 'login'],
    aws: ['iam:CreateUser', 'iam:CreateAccessKey', 'iam:CreateLoginProfile'],
    gcp: ['iam.serviceAccounts.create', 'iam.serviceAccountKeys.create'],
    azure: [],
    ibmMinRoles: ['Administrator'],
  },
  {
    id: 'launch-compute', label: 'launch or modify compute',
    verbs: ['launch', 'run', 'start', 'create', 'deploy', 'execute'],
    nouns: ['instance', 'instances', 'ec2', 'vm', 'vms', 'lambda', 'function', 'functions', 'container', 'containers', 'compute'],
    aws: ['ec2:RunInstances', 'lambda:CreateFunction', 'lambda:InvokeFunction', 'ecs:RunTask'],
    gcp: ['compute.instances.create', 'cloudfunctions.functions.create'],
    azure: ['Microsoft.Compute/virtualMachines/write', 'Microsoft.Web/sites/write'],
    ibmMinRoles: ['Administrator', 'Editor', 'Writer'],
  },
];

// GCP roles → permissions. Explicit map only: unknown roles are reported as
// "cannot determine" instead of guessed (anti-hallucination by design).
const GCP_ROLE_GRANTS = {
  'roles/owner': ['*'],
  'roles/editor': ['*'],
  'roles/viewer': ['*.get', '*.list', '*.read'],
  'roles/storage.admin': ['storage.*'],
  'roles/storage.objectviewer': ['storage.objects.get', 'storage.objects.list'],
  'roles/storage.objectadmin': ['storage.objects.*'],
  'roles/cloudsql.admin': ['cloudsql.*'],
  'roles/compute.admin': ['compute.*'],
  'roles/bigquery.admin': ['bigquery.*'],
  'roles/logging.admin': ['logging.*'],
  'roles/iam.securityadmin': ['iam.*', 'resourcemanager.projects.setIamPolicy'],
  'roles/iam.serviceaccounttokencreator': ['iam.serviceAccounts.getAccessToken', 'iam.serviceAccounts.signBlob', 'iam.serviceAccounts.signJwt'],
  'roles/iam.serviceaccountuser': ['iam.serviceAccounts.actAs'],
  'roles/secretmanager.secretaccessor': ['secretmanager.versions.access'],
};

const GCP_EDITOR_CAVEAT = 'roles/editor covers nearly all permissions but NOT IAM policy administration.';

function gcpRoleAllows(role, perm) {
  const grants = GCP_ROLE_GRANTS[String(role).toLowerCase()];
  if (!grants) return 'unknown';
  if (perm === '__admin__') return ['roles/owner', 'roles/editor'].includes(String(role).toLowerCase());
  return grants.some((g) => globMatch(g, perm));
}

// ---------------------------------------------------------------------------
// Principal labelling
// ---------------------------------------------------------------------------

function principalLabel(stmt) {
  if (stmt.kind === 'identity' || stmt.kind === 'roleDefinition') {
    return stmt.kind === 'roleDefinition'
      ? `any principal assigned role "${stmt.sid || stmt.doc}"`
      : `the identity this policy is attached to (${stmt.doc})`;
  }
  if (stmt.principals.length) return stmt.principals.map((p) => p.id).join(', ');
  return `(no principal) ${stmt.doc}`;
}

// ---------------------------------------------------------------------------
// Core: who can <concept>?
// ---------------------------------------------------------------------------

function resourceScope(stmt, hint) {
  if (!stmt.resources.length) return 'all';
  if (stmt.resources.some((r) => r === '*' || r === '(entire account)')) return 'all';
  if (hint) {
    return stmt.resources.some((r) => r.toLowerCase().includes(hint.toLowerCase())) ? 'match' : 'other';
  }
  return 'scoped';
}

function whoCan(model, concept, { resourceHint } = {}) {
  const hits = [];
  const denies = [];
  const notes = [];

  for (const stmt of model.statements) {
    if (stmt.provider === 'aws' || stmt.provider === 'azure') {
      const cands = concept[stmt.provider === 'azure' ? 'azure' : 'aws'] || [];
      if (concept.awsSpecial === 'admin' && stmt.provider === 'aws') {
        // admin = literally everything: Action "*" (or NotAction-allow) on Resource *
        const isAdmin = stmt.effect === 'Allow'
          && (stmt.actions.includes('*') || (stmt.notActions.length > 0))
          && (stmt.resources.includes('*') || !stmt.resources.length);
        if (isAdmin) {
          hits.push(makeHit(stmt, stmt.actions.includes('*') ? ['* (all actions)'] : [`everything except ${stmt.notActions.join(', ')}`], resourceScope(stmt, resourceHint)));
        }
        continue;
      }
      if (stmt.effect === 'Deny') {
        const den = cands.filter((a) => stmt.actions.some((p) => globMatch(p, a)));
        if (den.length) denies.push({ stmt, actions: den });
        continue;
      }
      const matched = cands.filter((a) => stmtAllows(stmt, a));
      if (matched.length) {
        const viaNotAction = stmt.notActions.length > 0 && !cands.some((a) => stmtExplicitlyAllows(stmt, a));
        const hit = makeHit(stmt, matched, resourceScope(stmt, resourceHint));
        if (viaNotAction) hit.caveats.push(`granted implicitly via NotAction (everything except ${stmt.notActions.join(', ')})`);
        hits.push(hit);
      }
    } else if (stmt.provider === 'gcp') {
      const cands = concept.gcp || [];
      const role = stmt.actions[0];
      let matched = [];
      let unknown = false;
      for (const cand of cands) {
        const r = gcpRoleAllows(role, cand);
        if (r === 'unknown') unknown = true;
        else if (r) matched.push(cand === '__admin__' ? `${role} (project-wide primitive role)` : cand);
      }
      if (matched.length) {
        const hit = makeHit(stmt, uniq(matched), resourceScope(stmt, resourceHint));
        if (String(role).toLowerCase() === 'roles/editor') hit.caveats.push(GCP_EDITOR_CAVEAT);
        hits.push(hit);
      } else if (unknown && cands.length) {
        notes.push(`Cannot determine whether ${principalLabel(stmt)} can ${concept.label}: role "${role}" is not in the built-in role→permission map (${stmt.id} · ${stmt.doc}:${stmt.line}). Verify against the GCP role reference rather than assuming.`);
      }
    } else if (stmt.provider === 'ibm') {
      const need = concept.ibmMinRoles || [];
      const matched = stmt.actions.filter((r) => need.includes(r));
      if (matched.length) {
        const hit = makeHit(stmt, matched.map((r) => `${r} role`), resourceScope(stmt, resourceHint));
        hits.push(hit);
      }
    }
  }

  // Apply broad explicit denies as caveats on hits
  for (const d of denies) {
    if (d.stmt.resources.includes('*')) {
      for (const h of hits) {
        if (h.stmt.doc === d.stmt.doc) h.caveats.push(`explicit Deny in ${d.stmt.id} (${d.stmt.doc}:${d.stmt.line}) overrides for: ${d.actions.join(', ')}`);
      }
    }
  }
  return { hits, denies, notes };
}

function makeHit(stmt, matchedActions, scope) {
  return {
    stmt,
    stmtId: stmt.id,
    principal: principalLabel(stmt),
    matchedActions,
    resources: stmt.resources,
    conditions: stmt.conditions,
    scope, // all | match | scoped | other
    caveats: stmt.conditions ? [`only when condition is satisfied: ${JSON.stringify(stmt.conditions)}`] : [],
  };
}

// ---------------------------------------------------------------------------
// Question parsing
// ---------------------------------------------------------------------------

function matchConcept(q) {
  const ql = ` ${q.toLowerCase().replace(/[?!.,]/g, ' ')} `;
  let best = null;
  let bestScore = 0;
  for (const c of CONCEPTS) {
    const v = c.verbs.some((w) => ql.includes(` ${w}`));
    const n = c.nouns.filter((w) => ql.includes(` ${w}`)).length;
    const score = (v ? 2 : 0) + n;
    if (v && n > 0 && score > bestScore) { best = c; bestScore = score; }
  }
  // noun-only fallback for strong nouns like "admin"
  if (!best) {
    for (const c of CONCEPTS) {
      if (c.id === 'admin' && c.nouns.some((w) => ql.includes(` ${w}`))) return c;
    }
  }
  return best;
}

function extractExplicitActions(q) {
  const awsish = q.match(/\b[a-z0-9-]{2,}:[A-Za-z][A-Za-z0-9*]+\b/g) || [];
  const gcpish = q.match(/\b[a-z]+\.[a-z]+\.[a-zA-Z*]+\b/g) || [];
  return [...awsish, ...gcpish];
}

function extractResourceHint(q) {
  if (/\bprod(uction)?\b/i.test(q)) return 'prod';
  const quoted = q.match(/["'“”]([^"'“”]{2,40})["'“”]/);
  if (quoted) return quoted[1];
  return null;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderHits(question, concept, result, checkedActions) {
  const { hits, notes } = result;
  const lines = [];
  const scopePrimary = hits.filter((h) => h.scope !== 'other');
  const scopeOther = hits.filter((h) => h.scope === 'other');

  if (!scopePrimary.length && !scopeOther.length) {
    lines.push(`**No.** No statement in the provided documents grants any of the checked permissions for "${concept ? concept.label : question}".`);
  } else {
    for (const h of scopePrimary) {
      const res = h.resources.length ? h.resources.join(', ') : '(unscoped)';
      lines.push(`- **${h.principal}** — via [${h.stmtId} · ${h.stmt.doc}:${h.stmt.line}]${h.stmt.sid ? ` (Sid: ${h.stmt.sid})` : ''}: matches ${h.matchedActions.join(', ')} on \`${res}\`${h.caveats.length ? `\n  - ⚠ ${h.caveats.join('\n  - ⚠ ')}` : ''}`);
    }
    if (scopeOther.length) {
      lines.push('', 'Grants that exist but whose resources do not obviously match the asked scope:');
      for (const h of scopeOther) {
        lines.push(`- ${h.principal} — [${h.stmtId} · ${h.stmt.doc}:${h.stmt.line}] on \`${h.resources.join(', ')}\` (resource names don't contain the scope you asked about — verify naming conventions before ruling it out)`);
      }
    }
  }
  for (const n of notes) lines.push(`- ❓ ${n}`);
  lines.push('', `_Checked permissions: ${checkedActions.join(', ') || '(role-based match for IBM/GCP)'}. Analysis covers only the ${'documents provided'}; group memberships and policies outside these files are not visible to this tool._`);
  return lines.join('\n');
}

function summarizeFindings(findings) {
  const real = findings.filter((f) => f.severity !== 'info');
  const counts = {};
  for (const f of real) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const parts = ['critical', 'high', 'medium', 'low'].filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);
  const verdict = counts.critical ? '**Yes — this policy set is overly permissive.**'
    : counts.high ? '**Yes — significant over-permissioning found.**'
      : counts.medium ? '**Partially — some medium-risk patterns to tighten.**'
        : '**No high-risk patterns detected** in the checks this engine runs (wildcards, escalation paths, public/cross-account trust, missing conditions).';
  const lines = [verdict, ''];
  if (parts.length) lines.push(`Findings: ${parts.join(', ')}.`, '');
  for (const f of real.slice(0, 5)) {
    const ev = f.evidence[0];
    lines.push(`- **[${f.severity.toUpperCase()}]** ${f.title} — [${f.statements[0] || '-'} · ${ev.doc}:${ev.line}]`);
  }
  if (real.length > 5) lines.push(`- …and ${real.length - 5} more in the Findings tab.`);
  lines.push('', '_This is a pattern-based audit of the supplied documents only — a clean result here does not certify the policy safe._');
  return lines.join('\n');
}

function capabilities(model, subject) {
  const sl = subject.toLowerCase();
  const matched = model.statements.filter((s) =>
    principalLabel(s).toLowerCase().includes(sl)
    || s.principals.some((p) => p.id.toLowerCase().includes(sl))
    || s.doc.toLowerCase().includes(sl));
  if (!matched.length) return `No principal or document matching "${subject}" found in the provided policies. Principals present: ${uniq(model.statements.flatMap((s) => s.principals.map((p) => p.id))).join(', ') || '(identity policies only — permissions attach to whoever the policy is bound to)'}`;
  const lines = [`Statements applying to "${subject}":`, ''];
  for (const s of matched) {
    lines.push(`- [${s.id} · ${s.doc}:${s.line}] **${s.effect}** ${s.actions.join(', ') || `(NotAction: ${s.notActions.join(', ')})`} on \`${s.resources.join(', ') || '*'}\`${s.conditions ? ` — conditional: ${JSON.stringify(s.conditions)}` : ''}`);
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Entry: deterministic natural-language answering
// ---------------------------------------------------------------------------

function answerQuestion(question, model, findings) {
  const q = question.trim();
  const ql = q.toLowerCase();
  const result = { question: q, mode: 'deterministic', text: '', data: null };

  // Intent: overall risk
  if (/(overly permissive|over-permissive|too permissive|is (this|it) (safe|risky|secure)|risk(y|s)?\b|audit|what('| i)s wrong|misconfig)/i.test(ql)) {
    result.intent = 'risk-summary';
    result.text = summarizeFindings(findings);
    return result;
  }

  // Intent: what can X do
  const whatCan = ql.match(/what (?:can|does|may) (.{2,60}?) (?:do|access|touch)/);
  if (whatCan) {
    result.intent = 'capabilities';
    result.text = capabilities(model, whatCan[1].trim());
    return result;
  }

  // Explicit action names beat concept matching
  const explicit = extractExplicitActions(q);
  const hint = extractResourceHint(q);
  const concept = matchConcept(q);

  let candidates = null;
  let conceptUsed = concept;
  if (explicit.length) {
    conceptUsed = { id: 'explicit', label: explicit.join(', '), aws: explicit, azure: explicit, gcp: explicit, ibmMinRoles: [] };
    candidates = explicit;
  } else if (concept) {
    candidates = uniq([...(concept.aws || []), ...(concept.gcp || []), ...(concept.azure || [])]).filter((a) => a !== '__admin__' && a !== '*:*');
  }

  if (conceptUsed) {
    const res = whoCan(model, conceptUsed, { resourceHint: hint });
    result.intent = 'who-can';
    result.concept = conceptUsed.id;

    // "can X ..." → filter hits to the named subject and give yes/no
    const canX = ql.match(/^can ([\w@ .:\-/]+?) (?:delete|drop|read|get|access|assume|create|launch|run|modify|change|manage|pass|escalate|write|view|list|see|stop|disable|terminate|destroy)/);
    if (canX) {
      const subj = canX[1].trim();
      const subjHits = res.hits.filter((h) => h.principal.toLowerCase().includes(subj) || h.stmt.doc.toLowerCase().includes(subj) || h.stmt.principals.some((p) => p.id.toLowerCase().includes(subj)));
      if (subjHits.length) {
        result.text = `**Yes.**\n\n${renderHits(q, conceptUsed, { hits: subjHits, denies: res.denies, notes: [] }, candidates || [])}`;
      } else {
        result.text = `**Not based on these documents.** No statement grants "${subj}" the checked permissions (${(candidates || []).join(', ')}).${res.notes.length ? `\n\n${res.notes.map((n) => `❓ ${n}`).join('\n')}` : ''}\n\n_Caveat: this tool only sees the pasted policies — group memberships or other attached policies could still grant it._`;
      }
      result.data = { hits: subjHits.map(publicHit), notes: res.notes };
      return result;
    }

    result.text = renderHits(q, conceptUsed, res, candidates || []);
    result.data = { hits: res.hits.map(publicHit), denies: res.denies.map((d) => ({ stmtId: d.stmt.id, actions: d.actions })), notes: res.notes };
    return result;
  }

  // Fallback: no intent matched
  result.intent = 'unmatched';
  result.text = [
    `I could not map that question to a permission check I can answer deterministically.`,
    '',
    'Things I can answer about the loaded policies:',
    '- "Who can delete production databases?"',
    '- "Who has admin access?"',
    '- "Can external accounts assume this role?" / "Who can assume roles?"',
    '- "Who can read secrets?" · "Who can change IAM permissions?" · "Who can delete logs?"',
    '- "What can <principal> do?"',
    '- "Is this policy overly permissive?"',
    '- Or name an exact action, e.g. "who can call s3:DeleteObject?"',
    aiHintLine(),
  ].join('\n');
  return result;
}

function aiHintLine() {
  return process.env.ANTHROPIC_API_KEY ? '' : '\n_Tip: set ANTHROPIC_API_KEY before starting the server to enable free-form questions via Claude (grounded in this engine\'s analysis)._';
}

function publicHit(h) {
  return { stmtId: h.stmtId, principal: h.principal, matchedActions: h.matchedActions, resources: h.resources, conditions: h.conditions, scope: h.scope, caveats: h.caveats, doc: h.stmt.doc, line: h.stmt.line };
}

module.exports = { answerQuestion, whoCan, CONCEPTS, summarizeFindings };
