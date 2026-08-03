# PolicyLens — ask who can do what in IAM

**Product story:** [docs/PRODUCT.md](docs/PRODUCT.md) · **LinkedIn kit:** [docs/LINKEDIN.md](docs/LINKEDIN.md)


Ask plain-English questions about IAM and get **grounded, cited, actionable** answers.
Built for the IBM AI Security track: *make cloud IAM policies understandable and safer*.

**Thesis:** the engine produces the facts; the LLM only explains them; every answer cites a source line.

Supports **AWS IAM JSON** (identity, resource, and trust policies) deeply, plus **GCP / Azure / IBM** policy documents in Analyze.

```
┌────────────┐   ┌──────────────────────┐   ┌────────────────────────────┐
│ paste /    │ → │ position-aware JSON   │ → │ normalized statement model │
│ upload     │   │ parser (line-mapped)  │   │ (S1, S2, … with lines)     │
└────────────┘   └──────────────────────┘   └──────────┬─────────────────┘
                                                        │
                    ┌───────────────────────────────────┼──────────────────┐
                    ▼                                   ▼                  ▼
          ┌──────────────────┐              ┌────────────────────┐  ┌──────────────┐
          │ rule engine       │              │ effective-permission│  │ before/after │
          │ + preflight lint  │              │ query engine        │  │ risk diff    │
          │ patterns          │              │ (who-can / can-X)   │  └──────────────┘
          └────────┬─────────┘              └─────────┬──────────┘
                   ▼                                   ▼
          findings w/ severity,            deterministic answer w/ citations
          evidence lines, fixes                        │
                                            ┌──────────▼──────────┐
                                            │ optional Claude layer│  ← only rephrases
                                            │ (grounded, redacted) │    engine facts
                                            └─────────────────────┘
```

## Quick start (stranger-usable in ~90 seconds)

```bash
cd iam-policy-auditor
./demo.sh                 # → http://localhost:4177  (binds 0.0.0.0 by default)
# or: npm start           # → 127.0.0.1 only unless HOST=0.0.0.0
```

1. Open the app.
2. Click **Run the 90-second demo**.
3. Org tab fills with who-can / reach-admin / resource-policy results — each with citations.

```bash
npm test                  # correctness suite (rules + evaluator + graph + lint + …)
npm run benchmark         # G1 ground-truth benchmark (engine vs documented AWS semantics)
```

Docker (optional):

```bash
docker build -t policylens .
docker run --rm -p 4177:4177 policylens
```

### Enterprise hardening (G1 — in progress)

Beyond the hackathon build, three pieces of the [enterprise roadmap](ROADMAP.md) are now in:

- **Condition-aware evaluation** (`src/evaluate.js`, `POST /api/simulate`) — actually
  *evaluates* the `Condition` block (Ip/Bool/Arn/Numeric/Date/Null, `IfExists`,
  `ForAllValues`/`ForAnyValue`) with correct explicit-deny > allow > implicit-deny ordering.
  A missing context key is surfaced as `ConditionalAllow`, never silently denied.
- **Real action catalogue** (`scripts/ingest-aws-actions.js` → `data/aws-actions.json`) —
  21,625 AWS actions / 452 services ingested from [iann0036/iam-dataset](https://github.com/iann0036/iam-dataset)
  (MIT) with authoritative access levels, replacing the name-verb heuristic. Refresh with
  `npm run ingest`.
- **Ground-truth benchmark** (`benchmark/`) — 23 cases encoding documented AWS semantics
  (100% agreement), plus a pluggable AWS oracle. `npm run benchmark:aws` diffs the engine
  against live `iam:SimulateCustomPolicy` when you have credentials with that permission —
  this is the roadmap's G1 exit gate.
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
