# PolicyLens — product story

**One line:** Ask *who can do what* in AWS IAM and get a cited, deterministic answer — not a chatbot guess.

## The problem we sell against

Security and platform teams already have scanners (Prowler, Access Analyzer, CSPM). What they still struggle with in an incident or change review is a **workflow question with receipts**:

> “Who can delete `prod-1`, and how did they get there?”

Answers today are either tribal knowledge, a half-day of IAM console archaeology, or an LLM that invents permissions. PolicyLens is built for that question.

## Thesis (non-negotiable)

1. **The engine produces the facts.** Condition-aware evaluation, action catalogue, org graph, resource-policy scan.
2. **The LLM only explains them** (optional). It never decides what a policy permits.
3. **Every answer cites a source line** (or an explicit “not evaluated” caveat).

If a claim cannot be cited, it does not ship as a fact.

## The 90-second demo (what a stranger should feel)

1. Open the app → **Run the 90-second demo**.
2. Org tab loads a baked-in account snapshot.
3. **Who can** `rds:DeleteDBInstance` on the prod DB — principals + granting statements.
4. **Reach administrator** — direct, assume-role, and multi-hop escalation paths.
5. **Resource-policy exposures** — external/public grants on KMS/S3-style policies in the snapshot.

That path is the product. Single-policy Analyze / Ask / Compare are supporting tools.

## Design-partner pitch (copy/paste)

> PolicyLens answers “who can do X in this AWS account?” from an IAM authorization-details snapshot, with citations to the granting statement or escalation path. Analysis is local and deterministic; Claude is optional and only rephrases engine facts. We are looking for a design partner who will (a) export a real snapshot weekly, (b) tell us which escalation paths we still miss, and (c) use the Org tab in a change review. In return you get early influence on the roadmap and a private deploy (Docker / LAN bind). Honest limits today: no SCPs, permission boundaries, or session policies; no live collector yet; Access Analyzer oracle needs `iam:SimulateCustomPolicy`.

## LinkedIn (credibility + conversations)

Full kit: **[LINKEDIN.md](LINKEDIN.md)** — primary post, first comment, reply templates, DM script, Day-5 follow-up, success metrics.

Attach when you post:

- `docs/assets/demo-org.png` — Org results after the 90-second demo (best still)
- `docs/assets/demo-hero.png` — landing / CTA
- Or a 20–40s screen recording of **Run the 90-second demo**

One-line stance for comments: *engine decides, LLM explains, every answer cites a line.*

## What “usable product” means here

| Bar | Status |
|---|---|
| Cold start → value in &lt; 2 minutes | One-click Org demo |
| Shareable on a LAN / tunnel | `HOST=0.0.0.0 npm start` |
| Policy samples ≠ account snapshot | Snapshot filtered from Analyze dropdown |
| Preflight before risk rules | `src/lint.js` (typos / star-admin / bad ARNs) |
| Packaging | `Dockerfile` + `./demo.sh` |
| Not a startup yet | Needs design partner + live ingest |

## What we are not claiming

- Not a replacement for Access Analyzer, Prowler, or a CSPM.
- Not “your account is safe” — only “these checks on these documents / this snapshot”.
- Not multi-cloud deep: AWS is the depth; GCP/Azure/IBM are policy-document support.
