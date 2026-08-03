'use strict';

const { parseWithPointers } = require('./parse');
const { asArray } = require('./util');

// ---------------------------------------------------------------------------
// Provider detection
// ---------------------------------------------------------------------------

function detectProvider(v) {
  if (Array.isArray(v)) {
    if (v.length && v[0] && typeof v[0] === 'object' && v[0].Effect) return 'aws';
    return 'unknown';
  }
  if (!v || typeof v !== 'object') return 'unknown';
  if (v.Statement || (v.PolicyDocument && v.PolicyDocument.Statement)) return 'aws';
  if (Array.isArray(v.bindings)) return 'gcp';
  if (v.properties && (v.properties.permissions || v.properties.roleDefinitionId)) return 'azure';
  if ((v.permissions || v.actions) && v.assignableScopes) return 'azure';
  if (v.roles && v.resources && (v.subjects || v.type === 'access' || v.type === 'authorization')) return 'ibm';
  return 'unknown';
}

// ---------------------------------------------------------------------------
// Normalization: every provider maps to a common statement shape:
// { id, doc, provider, kind, sid, effect, principals[], notPrincipals[],
//   actions[], notActions[], resources[], notResources[], conditions,
//   path, line, endLine }
// ---------------------------------------------------------------------------

function normPrincipal(p) {
  if (p == null) return [];
  if (p === '*') return [{ type: 'any', id: '*' }];
  const out = [];
  for (const [type, vals] of Object.entries(p)) {
    for (const v of asArray(vals)) out.push({ type, id: String(v) });
  }
  return out;
}

function blankStmt() {
  return {
    sid: null, effect: 'Allow', kind: 'identity',
    principals: [], notPrincipals: [],
    actions: [], notActions: [], resources: [], notResources: [],
    conditions: null, path: '', line: 1, endLine: 1,
  };
}

function normalizeAws(doc, pointers) {
  let root = doc;
  let base = '';
  if (doc && doc.PolicyDocument) { root = doc.PolicyDocument; base = '/PolicyDocument'; }

  let stmts;
  let stmtBase;
  if (Array.isArray(root)) { stmts = root; stmtBase = base; }
  else { stmts = asArray(root.Statement); stmtBase = `${base}/Statement`; }
  const isArr = Array.isArray(root) || Array.isArray(root.Statement);

  return stmts.map((s, idx) => {
    const path = isArr ? `${stmtBase}/${idx}` : stmtBase;
    const pos = pointers[path] || pointers[''] || { line: 1, endLine: 1 };
    const allActions = [...asArray(s.Action), ...asArray(s.NotAction)].map(String);
    let kind = 'identity';
    if (s.Principal != null || s.NotPrincipal != null) {
      kind = allActions.some((a) => /^sts:AssumeRole/i.test(a)) ? 'trust' : 'resource';
    }
    return {
      ...blankStmt(),
      sid: s.Sid || null,
      effect: s.Effect || 'Allow',
      kind,
      principals: normPrincipal(s.Principal),
      notPrincipals: normPrincipal(s.NotPrincipal),
      actions: asArray(s.Action).map(String),
      notActions: asArray(s.NotAction).map(String),
      resources: asArray(s.Resource).map(String),
      notResources: asArray(s.NotResource).map(String),
      conditions: s.Condition || null,
      path, line: pos.line, endLine: pos.endLine,
    };
  });
}

function normalizeGcp(doc, docName, pointers) {
  return asArray(doc.bindings).map((b, idx) => {
    const path = `/bindings/${idx}`;
    const pos = pointers[path] || { line: 1, endLine: 1 };
    return {
      ...blankStmt(),
      kind: 'binding',
      principals: asArray(b.members).map((m) => ({ type: String(m).split(':')[0], id: String(m) })),
      actions: [String(b.role || '')],
      resources: [String(doc.resource || docName)],
      conditions: b.condition || null,
      path, line: pos.line, endLine: pos.endLine,
    };
  });
}

function normalizeAzure(doc, pointers) {
  const props = doc.properties || doc;
  const base = doc.properties ? '/properties' : '';
  const scopes = asArray(props.assignableScopes || props.AssignableScopes).map(String);
  const roleName = props.roleName || doc.name || doc.Name || null;
  const hasPermsArray = Array.isArray(props.permissions);
  const perms = hasPermsArray
    ? props.permissions
    : [{ actions: props.actions, notActions: props.notActions, dataActions: props.dataActions, notDataActions: props.notDataActions }];

  return perms.map((p, idx) => {
    const path = hasPermsArray ? `${base}/permissions/${idx}` : (base || '');
    const pos = pointers[path] || pointers[''] || { line: 1, endLine: 1 };
    return {
      ...blankStmt(),
      sid: roleName,
      kind: 'roleDefinition',
      actions: [...asArray(p.actions), ...asArray(p.dataActions)].map(String),
      notActions: [...asArray(p.notActions), ...asArray(p.notDataActions)].map(String),
      resources: scopes.length ? scopes : ['(no assignableScopes)'],
      path, line: pos.line, endLine: pos.endLine,
    };
  });
}

function normalizeIbm(doc, pointers) {
  const subjects = asArray(doc.subjects).flatMap((s) =>
    asArray(s.attributes).map((a) => ({ type: String(a.name || 'attribute'), id: String(a.value) })));
  const roles = asArray(doc.roles).map((r) => {
    const id = String(r.role_id || r.id || '');
    const m = id.match(/role:([^:]+)$/);
    return m ? m[1] : String(r.display_name || id);
  });
  const resources = asArray(doc.resources).flatMap((r) =>
    asArray(r.attributes).map((a) => `${a.name}=${a.value}`));
  const pos = pointers['/roles'] || pointers[''] || { line: 1, endLine: 1 };
  const end = pointers['/resources'] || pos;
  return [{
    ...blankStmt(),
    kind: 'ibm-policy',
    sid: doc.description || null,
    principals: subjects,
    actions: roles,
    resources: resources.length ? resources : ['(entire account)'],
    path: '', line: pos.line, endLine: end.endLine,
  }];
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function analyzeDocuments(documents) {
  const model = { documents: [], statements: [], providers: [] };
  let sn = 0;
  for (const d of documents) {
    const name = d.name || `policy-${model.documents.length + 1}.json`;
    let parsed;
    try {
      parsed = parseWithPointers(d.text);
    } catch (e) {
      model.documents.push({ name, provider: 'invalid', error: e.message, text: d.text, lines: String(d.text).split('\n'), pointers: {} });
      continue;
    }
    const { value, pointers } = parsed;
    const provider = detectProvider(value);
    let stmts = [];
    if (provider === 'aws') stmts = normalizeAws(value, pointers);
    else if (provider === 'gcp') stmts = normalizeGcp(value, name, pointers);
    else if (provider === 'azure') stmts = normalizeAzure(value, pointers);
    else if (provider === 'ibm') stmts = normalizeIbm(value, pointers);
    for (const s of stmts) {
      s.id = `S${++sn}`;
      s.doc = name;
      s.provider = provider;
    }
    model.documents.push({ name, provider, value, pointers, text: d.text, lines: d.text.split('\n') });
    model.statements.push(...stmts);
    if (!model.providers.includes(provider)) model.providers.push(provider);
  }
  return model;
}

// Strip heavy fields for API responses.
function publicStatements(model) {
  return model.statements.map((s) => ({
    id: s.id, doc: s.doc, provider: s.provider, kind: s.kind, sid: s.sid,
    effect: s.effect, principals: s.principals, actions: s.actions,
    notActions: s.notActions, resources: s.resources, notResources: s.notResources,
    conditions: s.conditions, line: s.line, endLine: s.endLine,
  }));
}

module.exports = { analyzeDocuments, publicStatements, detectProvider };
