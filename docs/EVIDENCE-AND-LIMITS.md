# PolicyLens: evidence and limits

UK English. Short public note for reviewers. Last updated 11 November 2026.

## Who it is for

Cloud engineers and security reviewers who need to inspect a **proposed AWS IAM policy change** before they approve it.

## What it does

Compare a current policy version with a proposed one. Return **Stop**, **Check** or **Pass** for declared requests, with the policy lines behind newly allowed access. The browser demo uses the deterministic engine. An optional local AI layer may explain a result only if a grounding gate accepts the explanation.

## Evidence you can inspect

| Set | Score | Role |
| --- | --- | --- |
| 4 | 15/15 | Cases that shaped the rules (regression evidence) |
| 5 | 21/30 | Committed fixture; floor 21 |

Reproduce with `npm run bench:real`. Fixtures and sources live in [`bench/real-cases/`](../bench/real-cases/).

**Named miss on set 5:** case `PLH5-A21` expected **Stop** for a modelled role-trust change that lets a named user assume a role without MFA. The engine returned **Pass**.

The published browser example uses the public AWS Support policy change in [AWS-2021-007](https://aws.amazon.com/security/security-bulletins/AWS-2021-007/). That is a real public incident, separate from the set-5 fixture.

## What the grounding gate checks

When the optional AI explanation is on, the gate rejects invented citations, uncited permission claims, “safe”/“compliant” overclaims and wrong verdicts (offline contract: `npm run eval`). It checks form and citation presence. It cannot prove that a cited statement semantically supports the sentence.

## What it does not do

- Assess a whole AWS account, SCPs, permission boundaries or session policies.
- Replace AWS Access Analyzer or `iam:SimulateCustomPolicy` (cross-check not run; see `docs/AWS_SIMULATOR_STATUS.md`).
- Approve a change for production. A person makes that call.
- Guarantee that a Pass means the change is safe. Set 5 already shows a dangerous false pass.

## Next

- [Open the example policy comparison](https://matthewpaver.github.io/iam-policy-auditor/)
- [Case study](https://matthewpaver.github.io/work/policylens/)
- [README](../README.md)
