# PolicyLens → Enterprise-Grade: Gated Roadmap

**Thesis (survives scrutiny):** deterministic engine produces the facts, LLM only explains
them, every answer cites source lines. That's the same shape credible tools use, and the
*grounded natural-language interrogation* of policies is a genuine market gap (Prowler,
Cloudsplaining, Access Analyzer all produce findings; none let a reviewer ask "who can X"
conversationally with verifiable citations).

**Reality:** ~70% of "enterprise-grade" is completing permission data, evaluation semantics,
live ingestion, and trust infrastructure — not AI work. The trap is going shallow on four
clouds at once. **We scope AWS-first**: depth on one beats breadth on four for security buyers.

---

## Scope cut

| In for v1 | Deferred |
|---|---|
| AWS: identity, resource, trust, SCP-aware notes | Full SCP + permission-boundary *evaluation* (v1.5) |
| Live read-only ingestion of one AWS org | GCP / Azure / IBM deep support (v2, model already normalizes them) |
| Condition-aware local evaluation + Access Analyzer ground-truth | Formal "policy A ⊆ policy B" proofs via Cedar (v2) |
| Entity graph (users→groups→roles) + "who can X across org" | IaC/PR scanning at scale (v1.5) |
| Self-hostable explanation model for on-prem buyers | SaaS multi-tenant control plane (v2) |

---

## Open-source leverage (verified 1 Aug 2026, license-aware)

**Safe to embed (MIT / BSD-3 / Apache-2.0):**

| Project | License | Reuse |
|---|---|---|
| **iann0036/iam-dataset** | MIT | **Primary permission DB.** Covers AWS+Azure+GCP, auto-updated daily. `aws/iam_definition.json` (actions, access levels, resource types, condition keys), `aws/map.json` (SDK-call→action, unique), Azure `provider-operations.json` + `built-in-roles.json`, GCP `role_permissions.json` + `predefined_roles.json`. **This replaces our toy ~10-concept KB.** |
| **salesforce/policy_sentry** | MIT | Battle-tested AWS `iam-definition.json` + a query API (`get_actions_matching_arn`, wildcard expansion, access-level filter) and `access_level_overrides` for known AWS metadata bugs. |
| **salesforce/cloudsplaining** | BSD-3 | Finding taxonomy + `policy_document`/`statement_detail` analysis classes to cross-check our rule coverage (privesc, resource exposure, data exfil). |
| **duo-labs/parliament** | BSD-3 | Policy-grammar validation (malformed ARNs, bad condition operators, impossible statements) as a pre-flight linter before our rules run. |
| **cloud-copilot/iam-simulate** (npm `@cloud-copilot/iam-simulate`) | verify before vendoring | **Biggest find — it's TypeScript, our stack.** A deterministic *offline* evaluator covering identity + resource + SCP + RCP + permission boundaries with per-statement "explain" output. Sibling `iam-lens` evaluates against real collected account data. This is a candidate substrate for our evaluator rather than hand-rolling all of it. Known gap: permissive global-condition-key validation today. |
| **cedar-policy/cedar** (+ **Cedar Analysis**, cvc5-based SMT, open-sourced Jun 2025) | Apache-2.0 | Formal foundation for *provable* policy-subset comparison (v2) and prior art for the SMT encoding. Needs a lossy IAM→Cedar translator — that's where correctness risk moves. Adopt only for the "prove this change grants nothing new" feature. |
| **bridgecrewio/checkov** | Apache-2.0 | **Best IaC embed** — importable Python lib, 1000+ policies (TF/CloudFormation/K8s), strong IAM misconfig coverage. (tfsec is folded into Trivy now; Regula is dormant — moved to snyk/policy-engine.) |
| **prowler-cloud/prowler** | Apache-2.0 | Vendor its multi-cloud auth/session + IAM check framework to bootstrap live collectors instead of writing them from scratch. |

**Research-grade references (do not depend on):** `WithSecureLabs/IAMSpy` (Z3, open "mini-Zelkova", incomplete), `vlab-cs-ucsb/quacky` (SMT permissiveness quantification, academic).

**Reference only — do NOT link/vendor (copyleft):**
- **nccgroup/PMapper** (AGPL-3.0, unmaintained since 2022) — the *only* purpose-built IAM
  principal-graph/privesc-reachability engine. Reimplement its **edge catalogue** (which API
  calls create "principal A → principal B" edges: IAM, STS, Lambda, EC2, CloudFormation, SSM…)
  from its algorithms; don't depend on the code.
- **nccgroup/ScoutSuite** (GPL-2.0) — finding definitions as a reference catalogue only.

## HuggingFace — honest role (not central)

IAM auditing is a **symbolic** problem; there's no pretrained model that reliably decides
"is this over-permissive," and model fuzziness must never enter the *decision* path. Two
legitimate uses:

1. **Self-hostable explanation model** (real enterprise selling point). On-prem/air-gapped
   buyers won't send IAM policies to an external API. Ship the explanation layer on an
   open-weight instruct model, served via vLLM with grammar-constrained decoding so the
   LLM only narrates verdicts the engine produced:
   - **Default: `Qwen/Qwen3-14B` or `Qwen3-32B` (Apache-2.0)** — strong JSON-schema
     adherence, license procurement won't fight, single-GPU (~8-24 GB INT4).
   - **Premium: `meta-llama/Llama-3.3-70B-Instruct` INT4** for buyers with 48-80 GB cards.
   - **Cheap fallback: `microsoft/phi-4` (14B, MIT)**.
2. **Embeddings as a *suggestion* layer only.** ~18k AWS actions have descriptions; embed
   them and retrieve nearest actions for "who can delete backups?" — deterministic engine
   still decides. Use **`Qwen/Qwen3-Embedding-0.6B` (Apache-2.0)** or `BAAI/bge-m3` (MIT).

**No canonical HuggingFace *dataset* for IAM policies exists** (the few that do are tiny/
unvetted). Permission data comes from iam-dataset/policy_sentry; build our own eval corpus
by pairing generated policies with **`SimulateCustomPolicy` / Access Analyzer custom-policy-
check verdicts as labels** (see G1).

---

## Gated phases

Each gate has a hard exit criterion. No gate opens until the prior one's criterion is met.

### G0 — Foundation (DONE / current repo)
Deterministic engine, normalized cross-provider model, line-cited findings, grounded Q&A,
28 tests. **Exit ✓.**

### G1 — Correct AWS evaluation *(in progress — started today)*
- [x] Condition-aware evaluator (`src/evaluate.js`): explicit-deny > allow > implicit-deny,
      real operator semantics (String/Bool/Ip/Arn/Numeric/Date/Null, IfExists, ForAllValues/
      ForAnyValue), missing keys surfaced as `unknown` not silently passed. **9 tests.**
- [x] **Toy KB replaced** — `scripts/ingest-aws-actions.js` ingests `iann0036/iam-dataset`
      into `data/aws-actions.json`: **21,625 actions / 452 services** with authoritative
      access levels. `src/actions.js` gives wildcard expansion + access-level classification +
      blast-radius; `rules.js` now uses real levels (caught that `kms:Decrypt` is Write and
      `secretsmanager:GetSecretValue` is Read — both invisible to a name regex). **10 tests.**
- [x] **Ground-truth benchmark built** — `benchmark/` runs 23 cases encoding documented AWS
      semantics (**23/23, 100%**) and ships a pluggable AWS oracle (`aws iam
      simulate-custom-policy`, fail-fast, graceful degrade). Run: `npm run benchmark[:aws]`.
- [x] **Blast radius surfaced in the UI** — catalogue-backed grant scope now shows at a glance:
      a Findings chip and Ask banner ("grants N actions · X write · Y permissions-management")
      and a per-statement Grants column (e.g. `2P` = two permissions-management actions).
- [ ] **Run the AWS oracle** — needs credentials with `iam:SimulateCustomPolicy` (+
      `access-analyzer:CheckAccessNotGranted`). Verified reachable here but the available
      principal lacks the permission. This is the real exit-gate metric.
- [ ] Pre-flight lint via parliament grammar checks; evaluate `@cloud-copilot/iam-simulate`
      (TS, our stack; covers SCP/RCP/boundaries) as substrate — build-vs-adopt after coverage diff.
- **Exit:** ≥99% engine↔Access-Analyzer agreement on a 200-policy benchmark; every
  disagreement explained. (The corpus doubles as the eval dataset HF lacks — grow it by
  labelling generated policies with `SimulateCustomPolicy` verdicts.)

### G2 — Entity graph + org-wide reachability *(started)*
- [x] **Snapshot ingestion** — `src/snapshot.js` parses `aws iam
      get-account-authorization-details` (offline; no live-account access needed yet) into a
      normalised org model. A live read-only collector is deferred until creds/authorisation exist.
- [x] **Effective permissions with group inheritance** — `src/graph.js` resolves each identity's
      inline + attached + inherited-group policies and runs them through the shared
      condition-aware evaluator, so org answers stay consistent with single-policy answers.
- [x] **Org-wide "who can X" + reachability** — `whoCan(action, resource)` across all principals
      with citing statements; assume-role (`sts:AssumeRole`) trust edges. Exposed at
      `/api/org/whocan` and `/api/org/reach-admin`, driveable from the **Org tab**.
- [x] **Edge-based reach-admin with transitive multi-hop paths** — `reachAdmin()` now builds a
      principal→principal edge graph (PMapper-style, clean-room) and BFS's the shortest route to
      admin. Widened catalogue: self-admin (attach/put-user-policy, create/set-policy-version,
      add-user-to-group), become-user (create-access-key, create/update-login-profile),
      become-role (update-assume-role-policy, attach/put-role-policy, and pass-role to
      lambda/ec2/ecs/glue/cloudformation/datapipeline). Escalate → assume → escalate chains are
      resolved and rendered node-by-node with per-step citations. **15 tests.**
- [x] **Resource-policy exposures** — `src/resource_policy.js` scans supplied resource policies
      (KMS key / S3 bucket / any service policy in a `ResourcePolicies` snapshot array) for
      foreign-account and public grants, reported as cited findings (severity downgraded when an
      org/source condition scopes the grant). Reported as exposures, **not** reach-admin paths,
      since the foreign principal's permissions aren't in the snapshot. Shown in the Org tab as
      finding cards. **10 tests.**
- [ ] Remaining PMapper coverage that needs live data (instance-profile / SSM-command paths);
      the live read-only collector.
- **Exit:** "Who can delete production databases?" answered over a live test org with the
  full principal set and the escalation paths that lead there, each step cited.

### G3 — Enterprise trust infrastructure
- [ ] Self-hosted deployment (container + Helm); no policy data leaves buyer infra.
- [ ] SSO (OIDC/SAML), RBAC, full audit log of who queried what.
- [ ] Self-hosted explanation model wired as the default AI layer; external API opt-in only.
- [ ] Suppression/waiver workflow with expiry + owner.
- **Exit:** passes a mock enterprise security review (data residency, authz, auditability).

### G4 — Workflow integration
- [ ] CI/PR check: comment risk diff on IaC PRs (Terraform/CloudFormation), SARIF export.
- [ ] Scheduled drift scans + alerting on newly-introduced critical findings.
- [ ] Before/after gate: block a PR that grants net-new access (Cedar-backed subset proof).
- **Exit:** a policy change that adds `iam:PassRole` on `*` is caught in PR, with the blast
  radius and a least-privilege rewrite, before merge.

### G5 — Breadth + formal depth (v2)
GCP/Azure/IBM deep support (model already normalizes them), Cedar-backed provable comparisons,
SaaS multi-tenant option.

---

## Effort estimate (small team)

G1: 3–4 wks · G2: 6–8 wks · G3: 4–6 wks · G4: 3–4 wks → **credible v1 in ~4–6 months**
for 2–3 engineers. G1 is the highest-leverage and lowest-risk (it's data ingestion + a
verification harness against an authoritative API), which is why we started there today.

## Top risks

1. **False negatives at enterprise stakes.** A wrong "no" is a security incident. Mitigation:
   Access Analyzer as ground truth (G1 exit gate), and never claim "safe" — only "no findings
   in the checks run."
2. **Ingestion breadth.** Real orgs have thousands of policies + SCPs + boundaries. Mitigation:
   scope to identity/resource/trust first; label SCP/boundary interplay as "not yet evaluated"
   explicitly rather than silently ignoring.
3. **License contamination.** PMapper/ScoutSuite are copyleft. Mitigation: reference-only,
   clean-room reimplementation of edge semantics; everything vendored is MIT/BSD/Apache.
