# PolicyLens: evidence-first IAM change review

**Product story:** [docs/PRODUCT.md](docs/PRODUCT.md) · **LinkedIn kit:** [docs/LINKEDIN.md](docs/LINKEDIN.md)

**Try the included example:** [Quick start](#quick-start). It runs on your own computer with Node.js, without an AWS account, API key or package installation. You will see a permission change turn a denied action into an allowed one, then test a correction. Start with the sample policies before using any sensitive inputs.

**Release boundary:** this checkout includes local change-review work. It is not evidence that a hosted deployment or the previously published release contains that interface. Clone-and-run is the supported entry point; no hosted availability is promised. Label screenshots with the commit used to generate them. Reuse terms are in [LICENSE](LICENSE); support is best-effort prototype maintenance.


Review an AWS IAM policy change before it is approved. PolicyLens shows whether a declared sensitive action became reachable, cites the exact statement, and verifies that a proposed correction closes the path without removing access that must still work.

**The so what:** a reviewer can turn “this diff looks risky” into a reproducible stop or pass decision with evidence. The engine produces the facts. The LLM may explain them, but its answer is withheld if it fails the grounding eval.

AWS change review is the primary workflow. Org-wide “who can” and reach-admin analysis are the second workflow. GCP, Azure, and IBM policy documents remain available in the supporting Analyze view but are not presented as equivalent in depth.

```
┌────────────┐   ┌──────────────────────┐   ┌────────────────────────────┐
│ paste /    │ → │ position-aware JSON   │ → │ normalized statement model │
│ upload     │   │ parser (line-mapped)  │   │ (S1, S2, … with lines)     │
└────────────┘   └──────────────────────┘   └──────────┬─────────────────┘
                                                        │
                    ┌───────────────────────────────────┼────────────────────┐
                    ▼                                   ▼                  ▼
          ┌──────────────────┐              ┌────────────────────┐  ┌──────────────┐
          │ rule engine       │              │ effective-permission│  │ change review │
          │ + preflight lint  │              │ query engine        │  │ risk diff    │
          │ patterns          │              │ (who-can / can-X)   │  └──────────────┘
          └────────┬─────────┘              └─────────┬──────────┘
                   ▼                                   ▼
          findings w/ severity,            deterministic answer w/ citations
          evidence lines, fixes                        │
                                            ┌──────────▼──────────┐
                                            │ optional Claude layer│  ← shown only when
                                            │ + grounding eval     │    its claims pass
                                            └─────────────────────┘
```

## Quick start

The example runs locally without a cloud account or an API key. Use a Node.js version supported by [`package.json`](package.json).

```bash
git clone https://github.com/MatthewPaver/iam-policy-auditor.git
cd iam-policy-auditor
npm run demo              # http://127.0.0.1:4177, local machine only
```

1. Open the app and select **Change review**.
2. Click **Load example**, then **Review this change**.
3. Inspect the `ImplicitDeny → Allow` stop verdict and its source statement.
4. Open **Verify a proposed correction** and check that the risk closes while report access still works.

The original **Run the 90-second demo** remains available for org-wide who-can, reach-admin, and resource-policy results.

For an intentional LAN demonstration, `./demo.sh` binds to `0.0.0.0` by default. That exposes the server beyond localhost; do not use it with sensitive policies on an untrusted network.

```bash
npm test                  # correctness suite (rules + evaluator + graph + lint + …)
npm run benchmark         # authored regression corpus, not independent AWS validation
npm run eval              # offline AI grounding contract, including adversarial failures
```

Docker (optional):

```bash
docker build -t policylens .
docker run --rm -p 4177:4177 policylens
```

No cloud account or API key is needed for the example, tests, benchmark, or AI-eval fixtures. `ANTHROPIC_API_KEY` enables optional explanations. Policy data is pseudonymized before that call.

## What is reproducible

| Claim | Evidence in this repository |
|---|---|
| The checked request became reachable | `src/change_review.js` evaluates the same action and resource before and after |
| A correction closes the path | `POST /api/change/verify` re-runs the sensitive request against the candidate |
| Required access still works | the same correction check evaluates declared required-access cases |
| Authored supported-case expectations have not regressed | `npm run benchmark`, with a separate optional AWS simulator comparison |
| AI explanations stay grounded | `npm run eval` rejects invented citations, uncited claims, wrong verdicts, and safety overclaims |

This is a local decision-support tool, not an authorization oracle. SCPs, permission boundaries, session policies, and some cross-account interactions remain outside the current model and are named in every review.

The [AWS comparison status](docs/AWS_SIMULATOR_STATUS.md) records the outstanding independent-validation gate. An explicitly requested AWS benchmark exits nonzero if unavailable, blocked, incomplete or mismatched; an offline corpus pass cannot make that check green.

### Enterprise hardening (G1 — in progress)

Beyond the hackathon build, three pieces of the [enterprise roadmap](ROADMAP.md) are now in:

- **Condition-aware evaluation** (`src/evaluate.js`, `POST /api/simulate`) — actually
  *evaluates* the `Condition` block (Ip/Bool/Arn/Numeric/Date/Null, `IfExists`,
  `ForAllValues`/`ForAnyValue`) with correct explicit-deny > allow > implicit-deny ordering.
  A missing context key is surfaced as `ConditionalAllow`, never silently denied.
- **Real action catalogue** (`scripts/ingest-aws-actions.js` → `data/aws-actions.json`) —
  21,656 AWS actions / 453 services ingested from [iann0036/iam-dataset](https://github.com/iann0036/iam-dataset)
  (MIT) with catalogue access levels, replacing the name-verb heuristic. The ingest URL is pinned to an upstream commit; source and output SHA-256 values live in `data/aws-actions.provenance.json`. Refresh with `npm run ingest`.
- **Authored regression corpus** (`benchmark/`) — 55 cases encoding the author's interpretation of documented AWS semantics
  (55/55 regression agreement, not independent accuracy), plus a pluggable AWS oracle. `npm run benchmark:aws` diffs the engine
  against live `iam:SimulateCustomPolicy` when you have credentials with that permission. The committed oracle manifest says not run, so the repository does not currently claim AWS-validated agreement.
- **Blast radius in the UI** — the Findings tab, Ask panel and Statements table now show
  catalogue-backed grant scope at a glance ("grants N actions · X write · Y
  permissions-management"; a `2P` in the Grants column means two permissions-management
  actions), so a reviewer sees how far a statement reaches without reading raw JSON.

### Org-wide reachability (G2 — started)

`src/graph.js` answers questions across a whole account, not one pasted policy. Feed it an
account snapshot (`aws iam get-account-authorization-details` JSON — no live access needed):

- **`POST /api/org/whocan`** `{ snapshot, action, resource?, context? }` — every principal that
  can perform the action, with group inheritance resolved and the granting statement cited.
- **`POST /api/org/reach-admin`** `{ snapshot }` — who can reach administrator and how, over a
  principal→principal edge graph: direct admin, assume-role chains, and named
  privilege-escalation techniques (self-admin, become-user, become-role incl. pass-role to
  lambda/ec2/ecs/glue/cloudformation/datapipeline). **Transitive multi-hop** paths (escalate →
  assume → escalate) are resolved and returned node-by-node with per-step citations.

- **`POST /api/org/resource-exposure`** `{ snapshot }` — scans resource policies supplied in a
  `ResourcePolicies` array (KMS key policies, S3 bucket policies, or any service policy —
  `{ service, resource, policy }`) for grants to a foreign account or the public, returned as
  cited findings. External grants scoped by an org/source condition are downgraded. These are
  reported as exposures, **not** reach-admin paths (the foreign principal's permissions aren't
  in the snapshot).

Both the queries and the resource-policy scan are driveable from the **Org tab** in the web UI:
load the demo snapshot (or upload your own), run "who can `<action>` on `<resource>`", compute
reach-admin, and scan resource-policy exposures — each result shows the granting statement or
the escalation/assume-role path. Sample snapshot:
`samples/aws-account-snapshot.json`. Scope note: identity + group + role-trust only — SCPs,
permission boundaries and session policies are labelled "not evaluated", never silently ignored.

Optional AI layer (free-form questions, better phrasing — never required):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# optional: export AUDITOR_MODEL=claude-opus-4-8   (default: claude-sonnet-5)
node server.js
```

Load a sample from the dropdown (or paste your own policy), hit **Analyze**, then triage in
the **Findings** tab or interrogate in the **Ask** tab. **Compare** diffs the risk of a
before/after policy pair. **Statements** shows the exact normalized model the engine reasons
over, so every answer is verifiable.

## How it answers without hallucinating

This is the core design decision: **the LLM never decides what a policy permits.**

1. A position-aware JSON parser maps every statement to its source lines.
2. Policies normalize into a common statement model (effect, principals, actions,
   resources, conditions) across all four providers.
3. A deterministic engine evaluates questions: IAM-style glob matching for actions
   (`s3:*` vs `s3:DeleteBucket`), NotAction inversion, explicit-Deny overrides,
   resource-scope matching (e.g. "production" → ARNs containing `prod`), and a
   concept knowledge base mapping intents like *"delete databases"* to concrete
   permissions per provider (`rds:DeleteDBInstance`, `cloudsql.instances.delete`,
   `Microsoft.Sql/servers/databases/delete`, IBM role thresholds).
4. If `ANTHROPIC_API_KEY` is set, Claude receives ONLY the engine's facts (statements,
   findings, deterministic answer) with a hard system prompt: cite `[S2 · file:line]`,
   never assert permissions the facts don't show, state what is unknown. The raw engine
   answer stays one click away ("Show raw engine facts") for verification.
5. **Uncertainty is explicit by construction**: GCP custom roles outside the built-in
   role→permission map produce *"cannot determine — verify against the role reference"*,
   never a guess. Every answer carries the caveat that only the supplied documents are
   visible (group memberships / other attachments are not).

## Security depth (what the rules catch)

| Area | Examples |
|---|---|
| Wildcards | `Action:"*"` + `Resource:"*"` (admin), service wildcards, Azure `actions:["*"]` |
| Hidden breadth | `Allow` + `NotAction` (grants everything not listed — incl. future AWS services) |
| Privilege escalation | `iam:PassRole` on `*` (+compute-launch combo), `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, GCP `serviceAccountTokenCreator` impersonation |
| Trust / cross-account | `Principal:"*"` on trust or resource policies, cross-account root trust without `sts:ExternalId`, service principals without `aws:SourceAccount` (confused deputy) |
| Missing guardrails | destructive actions (`DeleteDBInstance`, `ScheduleKeyDeletion`, `DeleteTrail`…) with no Condition |
| Public exposure | GCP `allUsers` / `allAuthenticatedUsers`, IBM Public Access group |
| Provider-specific | GCP primitive roles (owner/editor), Azure subscription/tenant-root scopes, IBM account-wide Administrator |

Every finding carries: severity, plain-language blast-radius description, the exact
source lines as evidence, and a least-privilege rewrite or guardrail condition.

## Responsible AI & sensitive-input handling

- **Local by default** — `npm start` binds to 127.0.0.1; `./demo.sh` binds `0.0.0.0` for LAN/tunnels.
- **Preflight lint** — malformed Effects, suspicious actions, bad ARNs, unknown condition operators, and unconditional `*/*` admin land as findings before risk rules.
- **Pseudonymization before the API** — account IDs, emails, and IBM IAM IDs are replaced
  with placeholders (`«ACCT_1»`) before any Claude call and restored in the response, so
  real identifiers never reach the API. Toggleable in the UI.
- **Citations everywhere** — statement IDs + file:line on findings and answers; the
  Statements tab exposes the full model for human verification.
- **Honest limits** — a clean scan is reported as "no high-risk patterns *in the checks
  this engine runs*", never "safe"; unknown roles produce explicit uncertainty.

## Project layout

```
server.js          zero-dependency HTTP server + API (analyze / ask / compare / org / samples)
src/parse.js       position-aware JSON parser (line-mapped JSON pointers)
src/engine.js      provider detection + normalization to the common statement model
src/rules.js       misconfiguration rules for AWS / GCP / Azure / IBM
src/lint.js        parliament-style preflight (grammar / star-admin / bad ARNs)
src/query.js       concept KB + deterministic who-can / can-X / risk-summary answering
src/graph.js       org snapshot: who-can + reach-admin (multi-hop)
src/resource_policy.js  external/public grants on resource policies
src/ai.js          optional Claude layer: grounding prompt, redaction, timeout handling
public/            web UI (hero demo, findings, Ask, Org, compare)
samples/           demo policies + aws-account-snapshot.json for the Org path
docs/PRODUCT.md    product story, design-partner pitch, LinkedIn copy
demo.sh / Dockerfile  stranger-usable local / LAN / container demo
test/              correctness suite (rules, evaluate, graph, resource, lint)
```
