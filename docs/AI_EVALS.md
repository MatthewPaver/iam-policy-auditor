# AI evaluation strategy

PolicyLens uses AI only to explain evidence produced by the policy engine. The evaluation target is therefore not general writing quality. It is whether the explanation stays faithful to the access decision.

## What runs in CI

`npm run eval` checks captured model outputs without an API key. The first suite covers:

- verdict alignment: stop, review, or pass must match the engine result;
- citation precision: every citation must resolve to a supplied statement and line;
- claim grounding: permission claims need an inline engine citation;
- uncertainty calibration: conditional decisions and omitted controls must be named;
- safety language: the explanation must not call an account safe, secure, or compliant;
- concision: a reviewer should be able to scan the answer in a pull request.

The fixtures include positive and deliberately bad outputs. This makes the evaluator itself regression-testable rather than assuming every model answer should pass.

## Live model gate

The offline suite tests the contract, not model quality. `npm run eval:live -- --repeats 5` runs the real change-review explanation repeatedly and records model, prompt version, temperature, request id, latency, token usage, text and every deterministic evaluator check under the ignored `evals/results/` directory. Cost remains null unless versioned input/output token rates are explicitly supplied; the runner will not silently bake in a price that can change.

This is the adapter and run-record contract, not yet a statistically useful evaluation. A release candidate should grow to at least 50 versioned policy changes and send every failure or ambiguity to human review. The dataset should cover:

- direct new grants and explicit denies;
- conditions with missing and supplied context;
- wildcard and `NotAction` changes;
- contradictory findings;
- irrelevant or adversarial user questions;
- correction proposals that close the risk but break required access;
- requests outside the engine's declared scope.

Promptfoo is the closest fit if cross-model comparison and red teaming become regular needs. It now requires a newer Node runtime than PolicyLens and would add a large dependency surface, so the repository keeps a small zero-dependency contract suite and documents Promptfoo as an optional adapter. Inspect AI and DeepEval are capable alternatives, but both would introduce Python into an otherwise JavaScript-only project.

## The pass bar

A live model release should require:

- 100% valid citations;
- 100% deterministic-verdict agreement;
- no unsupported permission claims;
- at least 95% correct uncertainty statements;
- zero absolute safety claims;
- human review of every failed or ambiguous case.

The deterministic policy benchmark remains separate. `npm run benchmark` now covers 55 documented boundary cases; `npm run benchmark:aws` optionally checks the same corpus against AWS `SimulateCustomPolicy`. The committed `benchmark/oracle-manifest.json` deliberately says **not run** until a credentialed result exists. `npm run eval` tests the AI explanation contract. Passing one does not imply passing the other.
