'use strict';

// Resource-policy exposure analysis (offline).
//
// A resource policy is the policy attached to a *resource* rather than an
// identity — an S3 bucket policy, a KMS key policy, an SNS/SQS/Secrets Manager
// policy, and so on. They are dangerous in a different way from identity
// policies: they can hand access to principals in OTHER accounts, or to the
// whole world, without any identity policy in your account granting it.
//
// This detects statements that grant to a foreign (different-account) principal
// or to the public, and reports them as cited findings. It deliberately does
// NOT claim these are reach-admin paths — resolving that would need to know the
// permissions of the foreign principal, which the snapshot does not contain.
//
// Reuses the same parse → normalise pipeline as everything else, so each finding
// cites the exact policy line.

const { analyzeDocuments } = require('./engine');

// Condition keys that scope a cross-account/public grant down to something
// defensible (an org, a specific source, the caller's own account). Their
// presence downgrades severity but still warrants a look — a condition is only
// as good as the key being unforgeable.
const SCOPE_KEYS = /(aws:PrincipalOrgID|aws:PrincipalOrgPaths|aws:SourceArn|aws:SourceAccount|aws:SourceOwner|aws:PrincipalAccount|kms:CallerAccount|kms:ViaService)/i;

const accountOf = (arn) => (String(arn).match(/(\d{12})/) || [])[1] || null;

// Classify one principal relative to the account under audit.
function classifyPrincipal(p, accountId) {
  if (p.type === 'any' || p.id === '*') return 'public';
  if (p.type === 'AWS') {
    if (p.id === '*') return 'public';
    const acct = accountOf(p.id);
    if (acct && accountId && acct !== accountId) return 'external';
    return 'internal';
  }
  // Service / Federated / CanonicalUser principals are a separate concern; this
  // slice focuses on foreign-account and public exposure, so they are ignored.
  return 'other';
}

function isScoped(conditions) {
  return conditions ? SCOPE_KEYS.test(JSON.stringify(conditions)) : false;
}

// Build the evidence snippet for a statement, mirroring the identity-policy rules.
function evidenceFor(model, stmt) {
  const doc = model.documents.find((d) => d.name === stmt.doc);
  const from = stmt.line;
  const to = Math.min(stmt.endLine, from + 13);
  return {
    doc: doc.name,
    line: from,
    endLine: stmt.endLine,
    snippet: doc.lines.slice(from - 1, to).join('\n'),
    truncated: to < stmt.endLine,
  };
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Analyse a list of { service, resource, policy } entries against the audit
// account, returning findings in the same shape the identity-policy rules use.
function analyzeResourcePolicies(resourcePolicies, accountId) {
  const findings = [];

  for (const rp of resourcePolicies) {
    const name = `${rp.service}:${rp.resource}`;
    // Run the resource policy through the normal pipeline so statements are
    // normalised and line-tracked exactly like any other policy.
    const model = analyzeDocuments([{ name, text: JSON.stringify(rp.policy, null, 2) }]);

    for (const stmt of model.statements) {
      if (stmt.effect !== 'Allow' || !stmt.principals.length) continue;

      const exposed = stmt.principals
        .map((p) => ({ p, cls: classifyPrincipal(p, accountId) }))
        .filter((c) => c.cls === 'public' || c.cls === 'external');
      if (!exposed.length) continue;

      const anyPublic = exposed.some((c) => c.cls === 'public');
      const scoped = isScoped(stmt.conditions);
      const severity = anyPublic
        ? (scoped ? 'high' : 'critical')
        : (scoped ? 'medium' : 'high');

      const svc = rp.service.toUpperCase();
      const cite = `[${rp.service} ${rp.resource}:${stmt.line}]`;
      const actions = stmt.actions.length ? stmt.actions.join(', ') : '(all actions)';
      const extAccounts = [...new Set(exposed.filter((c) => c.cls === 'external').map((c) => accountOf(c.p.id)).filter(Boolean))];

      let title;
      let description;
      if (anyPublic) {
        title = `${svc} resource policy grants access to ANY principal (Principal "*")`;
        description = `${cite} on \`${rp.resource}\` allows ${actions} to Principal "*"${scoped ? ', partially narrowed by a condition — verify the condition keys cannot be forged' : ' with no scoping condition, so anyone (any AWS account, or the public for S3) can use it'}.`;
      } else {
        title = `${svc} resource policy grants access to external account${extAccounts.length > 1 ? 's' : ''} ${extAccounts.join(', ')}`;
        description = `${cite} on \`${rp.resource}\` allows ${actions} to a principal in account ${extAccounts.join(', ')}, which is outside the account under audit (${accountId || 'unknown'})${scoped ? ', scoped by a condition — confirm it restricts to the intended org/source' : ' with no scoping condition'}.`;
      }

      findings.push({
        ruleId: anyPublic ? 'AWS-RESOURCE-POLICY-PUBLIC' : 'AWS-RESOURCE-POLICY-EXTERNAL',
        severity,
        title,
        description,
        statements: [stmt.id],
        evidence: [evidenceFor(model, stmt)],
        remediation: {
          summary: anyPublic
            ? 'Remove Principal "*". Name the specific accounts/roles that need access; for S3, prefer blocking public access and using explicit principals or pre-signed URLs.'
            : 'Restrict to the specific external role ARNs that need access and add a scoping condition (aws:PrincipalOrgID, aws:SourceArn, or for KMS kms:CallerAccount) so only the intended party qualifies.',
          rewrite: anyPublic
            ? undefined
            : JSON.stringify({ Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-your-org-id' } } }, null, 2),
        },
      });
    }
  }

  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  return findings;
}

module.exports = { analyzeResourcePolicies, classifyPrincipal, isScoped };
