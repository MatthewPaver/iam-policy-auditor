'use strict';

// Parse an AWS account "authorization details" snapshot into a normalised org
// model that the entity graph reasons over.
//
// The input is exactly what `aws iam get-account-authorization-details` returns
// (UserDetailList / GroupDetailList / RoleDetailList / Policies), so an operator
// can hand us a read-only export without us ever touching their live account.
// A small hand-written format (the same field names, fewer of them) also works,
// which is handy for tests and demos.
//
// Everything downstream is offline and deterministic — the snapshot is the only
// source of truth, so answers can cite exactly which policy granted what.

// Policy documents in a real snapshot may arrive either as an object (CLI JSON
// output) or as a URL-encoded JSON string (raw API). Accept both.
function decodePolicyDoc(doc) {
  if (doc == null) return null;
  if (typeof doc === 'object') return doc;
  try {
    return JSON.parse(decodeURIComponent(String(doc)));
  } catch {
    try { return JSON.parse(String(doc)); } catch { return null; }
  }
}

function asArray(x) {
  return x == null ? [] : Array.isArray(x) ? x : [x];
}

// Turn a managed-policy entry into its effective (default-version) document.
function defaultVersionDoc(policy) {
  const versions = asArray(policy.PolicyVersionList);
  const def = versions.find((v) => v.IsDefaultVersion) || versions.find((v) => v.VersionId === policy.DefaultVersionId) || versions[0];
  return def ? decodePolicyDoc(def.Document) : null;
}

// Collect a principal's inline + attached-managed policies as {name, text} docs,
// where text is a JSON string so the existing engine can parse and line-cite it.
function collectDocs(owner, inlineKey, managedByArn, prefix) {
  const docs = [];
  for (const inline of asArray(owner[inlineKey])) {
    const d = decodePolicyDoc(inline.PolicyDocument);
    if (d) docs.push({ name: `${prefix}/inline:${inline.PolicyName}`, text: JSON.stringify(d, null, 2) });
  }
  for (const att of asArray(owner.AttachedManagedPolicies)) {
    const doc = managedByArn.get(att.PolicyArn);
    if (doc) docs.push({ name: `${prefix}/managed:${att.PolicyName}`, text: JSON.stringify(doc, null, 2) });
    // If the managed policy body is not in the snapshot we record the gap so the
    // graph can flag "permissions not fully visible" rather than silently under-report.
    else docs.push({ name: `${prefix}/managed:${att.PolicyName}`, text: '', missing: true, policyArn: att.PolicyArn });
  }
  return docs;
}

function parseSnapshot(snapshot) {
  const s = snapshot || {};

  // Index managed policies by ARN → default-version document.
  const managedByArn = new Map();
  for (const p of asArray(s.Policies)) {
    const doc = defaultVersionDoc(p);
    if (doc) managedByArn.set(p.Arn, doc);
  }

  const groups = {};
  for (const g of asArray(s.GroupDetailList)) {
    groups[g.GroupName] = {
      name: g.GroupName,
      arn: g.Arn,
      docs: collectDocs(g, 'GroupPolicyList', managedByArn, `group/${g.GroupName}`),
    };
  }

  // ARNs of the managed policies attached to an owner — the escalation catalogue
  // needs these to scope techniques like iam:CreatePolicyVersion to a real target.
  const attachedArns = (owner) => asArray(owner.AttachedManagedPolicies).map((a) => a.PolicyArn).filter(Boolean);

  const principals = [];
  for (const u of asArray(s.UserDetailList)) {
    principals.push({
      type: 'user',
      name: u.UserName,
      arn: u.Arn,
      groups: asArray(u.GroupList),
      docs: collectDocs(u, 'UserPolicyList', managedByArn, `user/${u.UserName}`),
      attachedManaged: attachedArns(u),
    });
  }
  for (const r of asArray(s.RoleDetailList)) {
    principals.push({
      type: 'role',
      name: r.RoleName,
      arn: r.Arn,
      groups: [],
      docs: collectDocs(r, 'RolePolicyList', managedByArn, `role/${r.RoleName}`),
      attachedManaged: attachedArns(r),
      trust: decodePolicyDoc(r.AssumeRolePolicyDocument),
    });
  }

  // The account under audit — derived from any principal ARN. Used to tell
  // "external" principals in resource policies apart from same-account ones.
  const accountId = principals
    .map((p) => (String(p.arn).match(/arn:aws:iam::(\d{12}):/) || [])[1])
    .find(Boolean) || null;

  // Optional resource policies (KMS key policies, S3 bucket policies, and any
  // other service resource policy). These are NOT part of
  // get-account-authorization-details, so an operator supplements them (e.g.
  // `aws kms get-key-policy`, `aws s3api get-bucket-policy`). Each entry is
  // { service, resource, policy } — service is just a label so this stays generic.
  const resourcePolicies = asArray(s.ResourcePolicies).map((rp) => ({
    service: rp.service || 'resource',
    resource: rp.resource || '(unknown resource)',
    policy: decodePolicyDoc(rp.policy),
  })).filter((rp) => rp.policy);

  return { principals, groups, managedByArn, accountId, resourcePolicies };
}

module.exports = { parseSnapshot, decodePolicyDoc, defaultVersionDoc };
