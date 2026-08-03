'use strict';

// G2 — entity graph and org-wide reachability (AWS-first).
//
// Given a parsed account snapshot, answer questions across the WHOLE org rather
// than one pasted policy: "who can delete production databases?", "who can reach
// admin?", "who can assume this role?". It resolves each identity's effective
// permissions (inline + attached + inherited group policies) and runs them
// through the same condition-aware evaluator used everywhere else, so every
// answer is grounded and points at the exact policy that granted access.
//
// Scope + honesty: this models identity policies, group inheritance, and
// role-trust (sts:AssumeRole) edges, plus a STARTER privilege-escalation
// catalogue. It does not yet model SCPs, permission boundaries, or session
// policies — those are labelled "not evaluated", never silently ignored. The
// escalation catalogue is a documented starter set (well-known public
// techniques), to be widened as the roadmap's G2 edge-catalogue work continues.

const { analyzeDocuments } = require('./engine');
const { evaluateRequest } = require('./evaluate');
const { parseSnapshot } = require('./snapshot');
const { globMatch } = require('./util');

// Compute services you can hand a role to (via iam:PassRole) and immediately run
// code as. If a principal can PassRole a target role AND create one of these,
// it can act as that role. (Clean-room from public escalation write-ups.)
const COMPUTE_LAUNCH = [
  { id: 'lambda', action: 'lambda:CreateFunction', label: 'a new Lambda function' },
  { id: 'ec2', action: 'ec2:RunInstances', label: 'a new EC2 instance' },
  { id: 'ecs', action: 'ecs:RunTask', label: 'a new ECS task' },
  { id: 'glue', action: 'glue:CreateDevEndpoint', label: 'a Glue dev endpoint' },
  { id: 'cloudformation', action: 'cloudformation:CreateStack', label: 'a CloudFormation stack' },
  { id: 'datapipeline', action: 'datapipeline:CreatePipeline', label: 'a Data Pipeline' },
];

const ACCOUNT_OF = (arn) => (String(arn).match(/arn:aws:iam::(\d{12}):/) || [])[1] || null;
const shortArn = (arn) => (arn === '__admin__' ? 'administrator' : String(arn).split('/').pop());

// Build the org model and a per-principal effective-permission cache.
function buildOrg(snapshot) {
  const org = parseSnapshot(snapshot);
  org.byArn = new Map(org.principals.map((p) => [p.arn, p]));

  // Every doc that applies to a principal: its own, plus (for users) the inline
  // and attached policies of every group it belongs to.
  org.effectiveDocs = (p) => {
    const docs = [...p.docs];
    for (const gname of p.groups) {
      const g = org.groups[gname];
      if (g) docs.push(...g.docs);
    }
    return docs;
  };

  // Cache the analysed model (line-cited normalised statements) per principal.
  const modelCache = new Map();
  org.effectiveModel = (p) => {
    if (modelCache.has(p.arn)) return modelCache.get(p.arn);
    const docs = org.effectiveDocs(p).filter((d) => d.text); // skip missing-body managed policies
    const model = analyzeDocuments(docs);
    model._missing = org.effectiveDocs(p).filter((d) => d.missing).map((d) => d.policyArn);
    modelCache.set(p.arn, model);
    return model;
  };

  return org;
}

// Does `principal` allow `action` on `resource`? Thin wrapper over the shared
// evaluator, returning the decision plus the statements that drove it.
function principalAllows(org, p, action, resource, context) {
  const model = org.effectiveModel(p);
  const r = evaluateRequest(model, { action, resource, context: context || {} });
  return r;
}

// WHO across the org can perform `action` (optionally on `resource`)?
// Returns one row per principal that is allowed or conditionally allowed, with
// the citing statements and any "permissions not fully visible" caveat.
function whoCan(org, { action, resource, context }) {
  const rows = [];
  for (const p of org.principals) {
    const r = principalAllows(org, p, action, resource, context);
    if (r.decision === 'Allow' || r.decision === 'ConditionalAllow') {
      const model = org.effectiveModel(p);
      rows.push({
        principal: p.arn,
        type: p.type,
        name: p.name,
        decision: r.decision,
        via: (r.allowMatches.concat(r.conditionalAllows)).map((m) => ({ doc: m.doc, line: m.line, sid: m.sid })),
        explanation: r.explanation,
        incompleteVisibility: model._missing && model._missing.length ? model._missing : null,
      });
    }
  }
  return rows;
}

// --- role-trust (assume-role) edges ----------------------------------------

// Can `principalArn` assume `role` given the role's trust policy?
// Matches Principal AWS entries: exact ARN, the principal's account root, or "*".
function trustAllows(role, principalArn) {
  if (!role.trust) return false;
  const account = ACCOUNT_OF(principalArn);
  const stmts = Array.isArray(role.trust.Statement) ? role.trust.Statement : [role.trust.Statement].filter(Boolean);
  return stmts.some((st) => {
    if (st.Effect !== 'Allow') return false;
    const actions = [].concat(st.Action || []);
    if (!actions.some((a) => globMatch(a, 'sts:AssumeRole'))) return false;
    const aws = st.Principal && st.Principal.AWS;
    const list = [].concat(aws == null ? [] : aws).map(String);
    if (st.Principal === '*' || list.includes('*')) return true;
    return list.some((pr) => pr === principalArn
      || (account && pr === `arn:aws:iam::${account}:root`)
      || (account && pr === account));
  });
}

// Direct roles a principal can assume in one hop.
function assumeTargets(org, p) {
  return org.principals.filter((o) => o.type === 'role' && trustAllows(o, p.arn));
}

// Like trustAllows, but also returns the citing statement so an assume-role edge
// can point at where in the trust policy the access comes from.
function trustAllowsVia(role, principalArn) {
  if (!trustAllows(role, principalArn)) return null;
  // The trust document lives in the snapshot, not the analysed identity model, so
  // cite it by name + a nominal line (statement position isn't line-tracked here).
  return [{ doc: `role/${role.name}/trust`, line: 1, sid: null }];
}

// --- admin detection --------------------------------------------------------

// A principal is a direct admin if its effective policies allow "*" on "*".
// Probing a spread of unrelated privileged actions approximates that cheaply.
function isDirectAdmin(org, p) {
  return principalAllows(org, p, 'iam:PutUserPolicy', '*').decision === 'Allow'
    && principalAllows(org, p, 's3:DeleteObject', '*').decision === 'Allow'
    && principalAllows(org, p, 'ec2:TerminateInstances', '*').decision === 'Allow';
}

// Is this group, on its own, administrator? (Used by the add-user-to-group edge.)
function groupIsAdmin(org, g) {
  const model = analyzeDocuments(g.docs.filter((d) => d.text));
  const probe = (a) => evaluateRequest(model, { action: a, resource: '*', context: {} }).decision === 'Allow';
  return probe('iam:PutUserPolicy') && probe('s3:DeleteObject') && probe('ec2:TerminateInstances');
}

// --- edge construction ------------------------------------------------------

// Does principal p allow `action` on `resource`? Returns the citing statements so
// each escalation edge can be justified, and whether it was only conditional.
function allowedWith(org, p, action, resource) {
  const r = evaluateRequest(org.effectiveModel(p), { action, resource, context: {} });
  if (r.decision === 'Allow') return { ok: true, conditional: false, via: r.allowMatches.map((m) => ({ doc: m.doc, line: m.line, sid: m.sid })) };
  if (r.decision === 'ConditionalAllow') return { ok: true, conditional: true, via: r.conditionalAllows.map((m) => ({ doc: m.doc, line: m.line, sid: m.sid })) };
  return { ok: false };
}

// The virtual target that means "becomes administrator directly".
const ADMIN = '__admin__';

// All the ways `p` can gain another principal's access (or admin outright).
// Each edge: { from, to, technique, note, via[] }. `to` is a principal ARN or ADMIN.
// The BFS in reachAdmin then finds transitive paths (escalate → assume → escalate).
function escalationEdges(org, p, ctx) {
  const out = [];
  const add = (to, technique, note, a) => out.push({ from: p.arn, to, technique, note: a.conditional ? `${note} (only if a condition holds)` : note, via: a.via });

  // --- self-admin: become administrator directly ---
  if (p.type === 'user') {
    const au = allowedWith(org, p, 'iam:AttachUserPolicy', p.arn);
    if (au.ok) add(ADMIN, 'attach-user-policy', 'attach AdministratorAccess to itself', au);
    const pu = allowedWith(org, p, 'iam:PutUserPolicy', p.arn);
    if (pu.ok) add(ADMIN, 'put-user-policy', 'inline an allow-* policy onto itself', pu);
    // add itself to an admin group
    for (const g of ctx.adminGroups) {
      const ag = allowedWith(org, p, 'iam:AddUserToGroup', g.arn);
      if (ag.ok) add(ADMIN, 'add-user-to-group', `add itself to the admin group ${g.name}`, ag);
    }
  }
  // rewrite one of its own attached managed policies to allow everything
  for (const policyArn of [...(p.attachedManaged || []), '*']) {
    const cpv = allowedWith(org, p, 'iam:CreatePolicyVersion', policyArn);
    if (cpv.ok) { add(ADMIN, 'create-policy-version', `rewrite attached policy ${shortArn(policyArn)} to allow *`, cpv); break; }
  }
  for (const policyArn of [...(p.attachedManaged || []), '*']) {
    const sdv = allowedWith(org, p, 'iam:SetDefaultPolicyVersion', policyArn);
    if (sdv.ok) { add(ADMIN, 'set-default-policy-version', `roll ${shortArn(policyArn)} back to a permissive version`, sdv); break; }
  }

  // --- become a specific user (get their credentials) ---
  for (const u of ctx.users) {
    if (u.arn === p.arn) continue;
    const ck = allowedWith(org, p, 'iam:CreateAccessKey', u.arn);
    if (ck.ok) add(u.arn, 'create-access-key', `mint access keys for ${u.name}`, ck);
    const cl = allowedWith(org, p, 'iam:CreateLoginProfile', u.arn);
    if (cl.ok) add(u.arn, 'create-login-profile', `set a console password for ${u.name}`, cl);
    const ul = allowedWith(org, p, 'iam:UpdateLoginProfile', u.arn);
    if (ul.ok) add(u.arn, 'update-login-profile', `reset the console password for ${u.name}`, ul);
  }

  // --- become a specific role ---
  for (const r of ctx.roles) {
    if (r.arn === p.arn) continue;
    // rewrite the role's trust to allow itself, then assume it
    const ut = allowedWith(org, p, 'iam:UpdateAssumeRolePolicy', r.arn);
    if (ut.ok) add(r.arn, 'update-assume-role-policy', `rewrite the trust policy of ${r.name} and assume it`, ut);
    // if it can both re-permission a role AND act as it, that role becomes admin
    const canActAsR = ut.ok || trustAllows(r, p.arn);
    const arp = allowedWith(org, p, 'iam:AttachRolePolicy', r.arn);
    const prp = allowedWith(org, p, 'iam:PutRolePolicy', r.arn);
    if (canActAsR && (arp.ok || prp.ok)) add(ADMIN, arp.ok ? 'attach-role-policy' : 'put-role-policy', `grant ${r.name} admin then act as it`, arp.ok ? arp : prp);
    // pass the role to a compute service it can launch, and run as it
    const pr = allowedWith(org, p, 'iam:PassRole', r.arn);
    if (pr.ok) {
      for (const comp of COMPUTE_LAUNCH) {
        const c = allowedWith(org, p, comp.action, '*');
        if (c.ok) { add(r.arn, `pass-role-${comp.id}`, `pass ${r.name} to ${comp.label} and run code as it`, { conditional: pr.conditional || c.conditional, via: [...pr.via, ...c.via] }); break; }
      }
    }
  }
  return out;
}

// Build the full edge set for the org: assume-role trust edges + escalation edges.
// Principals that are already administrators are skipped as sources — their
// outgoing edges are never needed to prove that someone else reaches admin, and
// an admin would otherwise generate an edge to nearly everything.
function buildEdges(org, directAdmin) {
  const users = org.principals.filter((p) => p.type === 'user');
  const roles = org.principals.filter((p) => p.type === 'role');
  const adminGroups = Object.values(org.groups).filter((g) => groupIsAdmin(org, g));
  const ctx = { users, roles, adminGroups };
  const skip = directAdmin || new Set(org.principals.filter((p) => isDirectAdmin(org, p)).map((p) => p.arn));

  const edges = [];
  for (const p of org.principals) {
    if (skip.has(p.arn)) continue;
    for (const r of roles) {
      if (r.arn === p.arn) continue;
      const via = trustAllowsVia(r, p.arn);
      if (via) edges.push({ from: p.arn, to: r.arn, technique: 'assume-role', note: `assume ${r.name}`, via });
    }
    edges.push(...escalationEdges(org, p, ctx));
  }
  return edges;
}

// --- reach admin (transitive) ----------------------------------------------

// Turn the winning BFS trail into a readable, cited path and a reason string.
function describePath(org, startArn, trail, terminal) {
  const nameOf = (arn) => (org.byArn.get(arn) ? org.byArn.get(arn).name : shortArn(arn));
  const steps = [{ arn: startArn, how: null, via: null }];
  for (const e of trail) steps.push({ arn: e.to, how: e.note, via: e.via && e.via.length ? e.via : null, technique: e.technique });
  if (terminal === 'admin-node') {
    const lastArn = trail.length ? trail[trail.length - 1].to : startArn;
    steps.push({ arn: ADMIN, how: `${nameOf(lastArn)} is administrator`, via: null });
  }

  const techs = trail.map((e) => e.technique);
  let reason;
  if (!trail.length) reason = 'direct administrator';
  else if (trail.every((e) => e.technique === 'assume-role')) reason = 'assume-role chain to an administrator role';
  else if (trail.length === 1) reason = `privilege escalation (${techs[0]})`;
  else reason = `multi-step path (${techs.join(' → ')})`;
  return { reason, path: steps, hops: trail.length };
}

// Breadth-first search from `startArn` to administrator over the edge set.
// Shortest path wins, so the explanation is the simplest true route.
function bfsToAdmin(org, startArn, adj, directAdmin) {
  if (directAdmin.has(startArn)) return describePath(org, startArn, [], 'admin-node-self');
  const seen = new Set([startArn]);
  const queue = [{ arn: startArn, trail: [] }];
  while (queue.length) {
    const { arn, trail } = queue.shift();
    for (const e of adj.get(arn) || []) {
      if (e.to === ADMIN) return describePath(org, startArn, [...trail, e], 'admin-edge');
      if (directAdmin.has(e.to)) return describePath(org, startArn, [...trail, e], 'admin-node');
      if (!seen.has(e.to)) { seen.add(e.to); queue.push({ arn: e.to, trail: [...trail, e] }); }
    }
  }
  return null;
}

// Who can reach administrator, and by what path? Combines direct admin,
// assume-role chains, and the escalation catalogue — transitively.
function reachAdmin(org) {
  const directAdmin = new Set(org.principals.filter((p) => isDirectAdmin(org, p)).map((p) => p.arn));
  const edges = buildEdges(org, directAdmin);
  const adj = new Map();
  for (const e of edges) { if (!adj.has(e.from)) adj.set(e.from, []); adj.get(e.from).push(e); }

  const results = [];
  for (const p of org.principals) {
    const res = bfsToAdmin(org, p.arn, adj, directAdmin);
    if (res) {
      // Direct admins reached themselves with an empty trail — describe cleanly.
      const reason = directAdmin.has(p.arn) && !res.hops ? 'direct administrator' : res.reason;
      const path = directAdmin.has(p.arn) && !res.hops ? [{ arn: p.arn, how: 'is administrator', via: null }] : res.path;
      results.push({ principal: p.arn, type: p.type, name: p.name, reason, path, hops: res.hops });
    }
  }
  return results;
}

module.exports = { buildOrg, whoCan, reachAdmin, buildEdges, assumeTargets, trustAllows, isDirectAdmin, COMPUTE_LAUNCH };
