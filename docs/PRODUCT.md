# PolicyLens — product story

**One line:** Review an IAM change before approval, show the new access path with citations, and verify the correction without trusting a chatbot verdict.

## The problem we sell against

Security and platform teams already have policy validators, scanners, and cloud security platforms. PolicyLens is not another findings feed. It addresses a narrower review question with receipts:

> “Did this proposed change make `rds:DeleteDBInstance` reachable on `prod-1`, and does the correction remove that path without breaking the report reader?”

That question is small enough to evaluate deterministically and important enough to block a change. A reviewer gets a scoped verdict, the matching statement, declared limits, and a repeatable correction check.

## Thesis (non-negotiable)

1. **The engine produces the facts.** Condition-aware evaluation, action catalogue, org graph, resource-policy scan.
2. **The LLM only explains them** (optional). It never decides what a policy permits.
3. **Every answer cites a source line** (or an explicit “not evaluated” caveat).

If a claim cannot be cited, it does not ship as a fact.

## The primary demo

1. Open **Change review** and load the example.
2. Review `rds:DeleteDBInstance` on the production database.
3. See the access change from `ImplicitDeny` to `Allow`, with the granting statement and introduced finding.
4. Verify a correction closes that request while `s3:GetObject` on the reports bucket remains allowed.
5. If AI is enabled, show its explanation only after the grounding evaluator passes it.

That path is the product. Org-wide who-can and reach-admin are a second evidence workflow. Single-policy Analyze and Ask are supporting tools.

## Design-partner pitch (copy/paste)

> PolicyLens checks one sensitive IAM request before and after a proposed policy change, cites the statement that changed the decision, and verifies a correction against both the risk and access that must remain. Analysis is local and deterministic. Claude is optional, cannot alter the verdict, and is hidden if its explanation fails the grounding checks. We are looking for a design partner willing to replay real, sanitized IAM changes and label where the scoped review helps or misses context. Honest limits today: no SCPs, permission boundaries, or session policies; no live collector yet; the AWS simulator oracle needs `iam:SimulateCustomPolicy`.

## What “usable product” means here

| Bar | Status |
|---|---|
| Cold start → value in &lt; 2 minutes | One-click change-review example |
| Shareable on a LAN / tunnel | `HOST=0.0.0.0 npm start` |
| Policy samples ≠ account snapshot | Snapshot filtered from Analyze dropdown |
| Preflight before risk rules | `src/lint.js` (typos / star-admin / bad ARNs) |
| Packaging | `Dockerfile` + `./demo.sh` |
| AI quality gate | Offline adversarial fixtures + runtime grounding check |
| Not a startup yet | Needs design partner + live ingest |

## What we are not claiming

- Not a replacement for Access Analyzer, Prowler, or a CSPM.
- Not “your account is safe” — only “these checks on these documents / this snapshot”.
- Not multi-cloud deep: AWS is the depth; GCP/Azure/IBM are policy-document support.
