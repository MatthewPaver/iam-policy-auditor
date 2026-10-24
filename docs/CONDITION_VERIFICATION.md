# Condition verification and reference cases

PolicyLens evaluates supplied requests locally. It does not authorize AWS operations.

## Corrected behavior

- `DateNotEquals` compares instants and requires the request date to differ from every policy date. Equivalent timezone representations match the same instant. Unix epoch seconds are supported in both policy and context values, including zero; they are not parsed as calendar years.
- An unsupported condition operator is unresolved, not false. A known false conjunct can still conclusively exclude a statement because condition clauses are ANDed.
- A potentially applicable Deny prevents a definite Allow when another statement might allow the request. `ConditionalAllow` is the existing API name for this unresolved decision; the interface asks for information.
- Explicit Deny still takes precedence. An unresolved Allow does not weaken an independently conclusive Allow when no Deny is unresolved.
- Required-access proof needs definite Allow before and after. Risk closure needs a definite proposed Allow and definite candidate denial. Unresolved results cannot satisfy either proof.
- Invalid date values remain unresolved.
- Numeric conditions require finite numeric values; Bool and Null policy values require canonical true/false values. Invalid supplied values remain unresolved rather than producing a failed condition or coercing empty text to zero.
- JSON keys such as `__proto__` remain ordinary data. They cannot disappear during parsing and bypass unsupported-operator checks. This rejects a false proof from invalid IAM input; it is not evidence of an AWS enforcement bypass.
- IPv6 and policy-variable substitution are not implemented locally. Relevant conditions and variable-bearing resource patterns stay unresolved instead of becoming false or unconditional. Use AWS for these cases.
- String/ARN condition matching is case-sensitive; ARN condition components are compared separately. Condition key lookup is case-insensitive, with conflicting case variants unresolved. Resource matching is case-sensitive; action names retain their case-insensitive match.
- Date-time values without a timezone, unsupported formats and impossible calendar dates remain unresolved. A calendar-only ISO date (`YYYY-MM-DD`) is interpreted as UTC midnight locally; this interpretation has not been compared live with AWS. Use a full timestamp with an explicit timezone or epoch seconds for precise checks. A date-dependent result covers the supplied request time, not future requests.
- Account analysis retains possible administrator and group paths as conditional when unresolved conditions prevent certainty. Its three administrator probes remain an approximation, not a complete privilege model.

## Missing information versus known absence

By default, omitted context keys mean information was not supplied. This includes `Null` and `IfExists`: the engine cannot infer actual absence from incomplete input.

Advanced callers can explicitly set `contextComplete: true` on a request. Only use this when the context is known complete for every condition relevant to that request. Then omitted keys mean known absence and follow AWS's operator-specific absence rules. For example, an absent `Bool` key does not match; `Null` and `IfExists` evaluate actual absence. The setting is a caller assertion, not something PolicyLens verifies or a substitute for AWS context collection.

The optional boolean is supported by `evaluateRequest`, `reviewChange` request objects, `verifyCorrection` risk/required request objects and the review API's top-level request fields. The web form keeps the default incomplete-context behavior and has no automatic override.

The older simulate and organization-analysis API routes keep the conservative default and do not expose this opt-in. Their omitted `Null`/`IfExists` context may now produce an unresolved result where older versions assumed absence.

## Evidence and limits

`benchmark/condition-reference-cases.js` adds 23 fully specified reference cases derived from [AWS condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html), [condition key matching](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html) and [explicit Deny precedence](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html). Eight additional cases cover PolicyLens's conservative incomplete-context and unsupported-feature behavior; these deliberately skip direct AWS comparison. The full corpus has 86 cases. The fixtures are authored interpretations, not recorded AWS responses or independent ground truth.

`test/condition-verification.test.js` reproduces the two original false-verification paths and checks unsupported operators, correction proof, Deny precedence, missing information, explicit context completeness and invalid dates. The benchmark participates in the existing CI gate.

Run `npm run benchmark -- --json` for offline reference checks. Run `npm run benchmark:aws -- --json` for an independent AWS comparison with the CLI and a scoped `iam:SimulateCustomPolicy` permission. Explicit AWS runs fail if unavailable; they never silently count offline cases as AWS validation. See [AWS comparison status](AWS_SIMULATOR_STATUS.md).

The simulator itself has limits. Neither these fixtures nor the local engine establish production authorization, organization-control coverage or exhaustive AWS semantic equivalence. No live AWS comparison was possible for this change because the AWS CLI was unavailable.
