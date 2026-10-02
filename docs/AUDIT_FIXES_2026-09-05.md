# Audit fixes — 2026-09-05

Scope: PolicyLens findings from `repo-usability-audit-2026-09-05.md`. Existing uncommitted change-review, evaluation, catalogue provenance, MIT LICENSE and CI work was preserved. No commit, push, deployment, live model/API call or credential access was performed.

## Changes

- README, corpus metadata and benchmark output now call the 55-case result an **authored regression corpus**, not independent ground truth.
- JSON output labels the evidence type and distinguishes AWS not-requested, not-run, blocked, incomplete and completed statuses. An explicitly requested unavailable/incomplete/mismatched AWS comparison exits nonzero; malformed thresholds fail instead of silently passing.
- Added offline benchmark-contract regression checks; tests simulate an absent AWS CLI with an empty PATH and do not inspect credentials. Independent review found a mistyped/missing oracle argument could bypass the gate; both now fail explicitly and have reproducing tests.
- Clone-and-run is the unambiguous supported entry point. Release/screenshot boundaries, best-effort prototype support and LICENSE are explicit.
- `docs/AWS_SIMULATOR_STATUS.md` documents the owner's credentialed comparison, report fields and exclusions. Existing manifest remains **not run**.

## Verification

- RED: `node test/benchmark-contract.test.js` failed on the absent evidence type before implementation.
- GREEN/full suite: `npm test` passed all reported groups: 28 parser/rules/query, 9 evaluator, 10 action catalogue, 15 graph, 10 resource-policy, 4 lint, 14 change-review, 12 AI contract, 7 provenance, 6 benchmark-contract, 3 demo API checks (118 reported authored checks).
- `npm run eval`: 6/6 adversarial/grounded fixture expectations matched; intentionally invalid explanations were rejected.
- `npm run benchmark`: 55/55 authored expectations matched. No independent accuracy claim.
- `npm ci --ignore-scripts`: clean lockfile installation passed; one package audited, zero reported vulnerabilities. There are no runtime package dependencies.
- Existing HTTP demo tests start and stop their local test process. No server was left running.

## Remaining release gates

- **Owner action:** run and disclose the AWS simulator comparison with authorized credentials. No report was fabricated and no credentialed run was attempted.
- Hosted deployment and publication of local changes remain unverified/unperformed. Local screenshots must not be represented as the released interface until published and checked.
- No browser-only visual regression run in this slice; API and deterministic workflow checks do not establish browser presentation quality.
- Independent review by `prototype_design`; required oracle-argument finding addressed with RED/GREEN regression evidence.
