'use strict';

// Turn the many shapes AWS CLI / Terraform / CloudFormation spit out into
// plain IAM policy documents the engine already understands. Keep the
// verdict path deterministic: this layer only unwraps and names documents.

const yaml = require('yaml');

// Human-readable list; the sourceFormat tokens sit in the same sentence so
// callers (and our own tests) can match on 'cloudformation', 'terraform-plan', etc.
const ACCEPTED_FORMATS = [
  'policy (plain IAM JSON with Version + Statement)',
  'policy-array',
  'get-policy-version ({PolicyVersion:{Document}})',
  'get-role-policy ({RoleName, PolicyName, PolicyDocument})',
  'authorization-details (get-account-authorization-details role entry)',
  'cloudformation (AWS::IAM::ManagedPolicy / Role Policies / AWS::S3::BucketPolicy)',
  'terraform-plan (resource_changes for IAM / S3 bucket policies)',
];

const TF_POLICY_TYPES = new Set([
  'aws_iam_policy',
  'aws_iam_role_policy',
  'aws_iam_user_policy',
  'aws_iam_group_policy',
  'aws_s3_bucket_policy',
]);

function expectedPolicyError() {
  return new Error(
    `Expected an IAM policy. Accepted formats: ${ACCEPTED_FORMATS.join('; ')}.`,
  );
}

// AWS CLI sometimes returns Document as a URL-encoded JSON string.
function decodeDocument(doc) {
  if (doc == null) return null;
  if (typeof doc === 'object') return doc;
  if (typeof doc !== 'string') return null;
  const trimmed = doc.trim();
  if (!trimmed) return null;
  // Try plain JSON first, then URL-decode once if needed.
  try {
    return JSON.parse(trimmed);
  } catch {
    try {
      return JSON.parse(decodeURIComponent(trimmed));
    } catch {
      return null;
    }
  }
}

function stringifyPolicy(doc) {
  return JSON.stringify(doc, null, 2);
}

function isPlainPolicy(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (value.Statement !== undefined) return true;
  if (value.PolicyDocument && value.PolicyDocument.Statement !== undefined) return true;
  return false;
}

function looksLikeTerraformPlan(value) {
  return value
    && typeof value === 'object'
    && Array.isArray(value.resource_changes);
}

function looksLikeCloudFormation(value) {
  return value
    && typeof value === 'object'
    && value.Resources
    && typeof value.Resources === 'object'
    && !Array.isArray(value.Resources);
}

function looksLikeGetPolicyVersion(value) {
  return value
    && typeof value === 'object'
    && value.PolicyVersion
    && typeof value.PolicyVersion === 'object'
    && value.PolicyVersion.Document !== undefined;
}

function looksLikeGetRolePolicy(value) {
  return value
    && typeof value === 'object'
    && value.PolicyDocument !== undefined
    && (value.PolicyName !== undefined || value.RoleName !== undefined);
}

function looksLikeAuthorizationDetailsRole(value) {
  if (!value || typeof value !== 'object') return false;
  // Role / User / Group entries from get-account-authorization-details.
  const hasInline = Array.isArray(value.RolePolicyList)
    || Array.isArray(value.UserPolicyList)
    || Array.isArray(value.GroupPolicyList);
  const hasAttached = Array.isArray(value.AttachedManagedPolicies);
  return (hasInline || hasAttached)
    && (value.RoleName || value.UserName || value.GroupName || value.Arn);
}

function policyTextFromMaybeWrapped(doc) {
  const decoded = decodeDocument(doc);
  if (!decoded) return null;
  // get-*-policy may nest PolicyDocument; flatten to a Statement-bearing doc.
  if (decoded.PolicyDocument && decoded.PolicyDocument.Statement !== undefined) {
    return stringifyPolicy(decoded.PolicyDocument);
  }
  if (decoded.Statement !== undefined) return stringifyPolicy(decoded);
  return null;
}

function extractTfPolicyString(attrs) {
  if (!attrs || typeof attrs !== 'object') return null;
  if (typeof attrs.policy === 'string') return attrs.policy;
  if (attrs.policy && typeof attrs.policy === 'object') return stringifyPolicy(attrs.policy);
  return null;
}

function isUnknownPolicy(change) {
  if (!change || typeof change !== 'object') return false;
  if (change.after_unknown && change.after_unknown.policy === true) return true;
  // Terraform may leave the string as "(known after apply)".
  const after = change.after;
  if (after && typeof after.policy === 'string' && /known after apply/i.test(after.policy)) {
    return true;
  }
  return false;
}

function fromTerraformPlan(planJson) {
  const plan = typeof planJson === 'string' ? JSON.parse(planJson) : planJson;
  if (!looksLikeTerraformPlan(plan)) return [];
  const out = [];
  for (const rc of plan.resource_changes) {
    if (!rc || !TF_POLICY_TYPES.has(rc.type)) continue;
    const change = rc.change || {};
    const unknown = isUnknownPolicy(change);
    out.push({
      address: rc.address || rc.type,
      before: extractTfPolicyString(change.before),
      after: unknown ? null : extractTfPolicyString(change.after),
      unknown,
    });
  }
  return out;
}

function documentsFromCloudFormation(template, name) {
  const docs = [];
  const resources = template.Resources || {};
  for (const [logicalId, resource] of Object.entries(resources)) {
    if (!resource || typeof resource !== 'object') continue;
    const type = resource.Type;
    const props = resource.Properties || {};
    if (type === 'AWS::IAM::ManagedPolicy' || type === 'AWS::IAM::Policy') {
      const text = policyTextFromMaybeWrapped(props.PolicyDocument);
      if (text) docs.push({ name: `${name}:${logicalId}`, text });
    } else if (type === 'AWS::IAM::Role') {
      for (const inline of props.Policies || []) {
        const text = policyTextFromMaybeWrapped(inline && inline.PolicyDocument);
        if (text) {
          const pname = (inline && inline.PolicyName) || 'inline';
          docs.push({ name: `${name}:${logicalId}:${pname}`, text });
        }
      }
    } else if (type === 'AWS::S3::BucketPolicy') {
      const text = policyTextFromMaybeWrapped(props.PolicyDocument);
      if (text) docs.push({ name: `${name}:${logicalId}`, text });
    }
  }
  return docs;
}

function documentsFromAuthorizationDetails(entry, name) {
  const docs = [];
  const inlineLists = [
    entry.RolePolicyList,
    entry.UserPolicyList,
    entry.GroupPolicyList,
  ];
  for (const list of inlineLists) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      const text = policyTextFromMaybeWrapped(item && item.PolicyDocument);
      if (text) {
        docs.push({
          name: `${name}:${item.PolicyName || 'inline'}`,
          text,
        });
      }
    }
  }
  if (Array.isArray(entry.AttachedManagedPolicies)) {
    for (const attached of entry.AttachedManagedPolicies) {
      // Only emit a document when the export actually includes the body.
      const text = policyTextFromMaybeWrapped(attached && attached.PolicyDocument);
      if (text) {
        docs.push({
          name: `${name}:${attached.PolicyName || attached.PolicyArn || 'attached'}`,
          text,
        });
      }
    }
  }
  return docs;
}

function parseInputValue(input) {
  if (input !== null && typeof input === 'object') return { value: input, rawWasString: false };
  if (typeof input !== 'string') throw expectedPolicyError();
  const trimmed = input.trim();
  if (!trimmed) throw expectedPolicyError();
  // JSON first (policies, CLI wrappers, TF plans, CFN JSON).
  try {
    return { value: JSON.parse(trimmed), rawWasString: true };
  } catch {
    // Fall through to YAML for CloudFormation templates.
  }
  try {
    const value = yaml.parse(trimmed);
    if (value === null || value === undefined) throw expectedPolicyError();
    return { value, rawWasString: true, fromYaml: true };
  } catch (err) {
    if (err && err.message && /Expected an IAM policy/.test(err.message)) throw err;
    throw expectedPolicyError();
  }
}

function normalizePolicyInput(input, name = 'policy.json') {
  // A string that is already a plain policy document should stay a single doc
  // with the caller's name, even when it also parses as JSON.
  const { value } = parseInputValue(input);

  if (Array.isArray(value)) {
    // Array of policies (or of already-normalised document wrappers).
    if (!value.length) throw expectedPolicyError();
    const documents = value.map((item, idx) => {
      if (item && typeof item === 'object' && typeof item.text === 'string' && item.name) {
        return { name: item.name, text: item.text };
      }
      const nested = normalizePolicyInput(item, `${name}[${idx}]`);
      if (nested.documents.length !== 1) {
        // Flatten nested multi-doc formats into the array result.
        return nested.documents;
      }
      return nested.documents[0];
    }).flat();
    return { documents, sourceFormat: 'policy-array' };
  }

  if (looksLikeGetPolicyVersion(value)) {
    const text = policyTextFromMaybeWrapped(value.PolicyVersion.Document);
    if (!text) throw expectedPolicyError();
    return {
      documents: [{ name, text }],
      sourceFormat: 'get-policy-version',
    };
  }

  if (looksLikeAuthorizationDetailsRole(value)) {
    const documents = documentsFromAuthorizationDetails(value, name);
    if (!documents.length) throw expectedPolicyError();
    return { documents, sourceFormat: 'authorization-details' };
  }

  if (looksLikeGetRolePolicy(value)) {
    const text = policyTextFromMaybeWrapped(value.PolicyDocument);
    if (!text) throw expectedPolicyError();
    const label = value.PolicyName
      ? `${name}:${value.PolicyName}`
      : name;
    return {
      documents: [{ name: label, text }],
      sourceFormat: 'get-role-policy',
    };
  }

  if (looksLikeTerraformPlan(value)) {
    const pairs = fromTerraformPlan(value);
    // For normalizePolicyInput we expose the *after* side (or before if create
    // has no after yet). Unknown policies are reported as empty text with a
    // sentinel comment so callers can detect "cannot be checked until apply".
    const documents = [];
    for (const pair of pairs) {
      if (pair.unknown) {
        documents.push({
          name: pair.address,
          text: stringifyPolicy({
            Version: '2012-10-17',
            Statement: [],
            _policylensUnknown: true,
          }),
          unknown: true,
        });
        continue;
      }
      const text = pair.after || pair.before;
      if (text) documents.push({ name: pair.address, text });
    }
    if (!documents.length) throw expectedPolicyError();
    return { documents, sourceFormat: 'terraform-plan' };
  }

  if (looksLikeCloudFormation(value)) {
    const documents = documentsFromCloudFormation(value, name);
    if (!documents.length) throw expectedPolicyError();
    return { documents, sourceFormat: 'cloudformation' };
  }

  if (isPlainPolicy(value)) {
    // Prefer PolicyDocument when present (rare but valid).
    const text = value.PolicyDocument && value.PolicyDocument.Statement !== undefined
      ? stringifyPolicy(value.PolicyDocument)
      : stringifyPolicy(value);
    return {
      documents: [{ name, text }],
      sourceFormat: 'policy',
    };
  }

  throw expectedPolicyError();
}

module.exports = {
  normalizePolicyInput,
  fromTerraformPlan,
  ACCEPTED_FORMATS,
};
