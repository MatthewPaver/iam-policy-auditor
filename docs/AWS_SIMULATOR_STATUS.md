# AWS simulator comparison status

As of 2026-10-25: **not run in this repository**. The current environment has no AWS CLI on PATH; no AWS credentials were read or used for the condition-verification fixes. The 86-case corpus includes 23 new documented AWS reference cases and eight incomplete-context or unsupported-feature regressions. Offline agreement is not AWS authorization accuracy.

The executable adapter is `benchmark/oracle-aws.js`; the machine-readable disclosure is `benchmark/oracle-manifest.json`. An owner may run `npm run benchmark:aws -- --json` with the AWS CLI and a deliberately scoped principal permitted to call `iam:SimulateCustomPolicy`. This command contacts AWS and is not part of offline CI.

Retain a reviewed, redacted result alongside the exact commit, UTC run date, AWS CLI version and supported scope. Report `checked`, `engineVsAws`, `agreementPct`, every mismatch/error and every skipped case. Do not publish credentials, account policy contents or account identifiers. Do not replace this status with a success statement until a real report exists.

The corpus covers single identity-policy requests: action/resource matching, explicit deny, NotAction/NotResource and supported condition operators. Incomplete-context cases are disclosed and excluded from direct comparison because the local `ConditionalAllow` vocabulary intentionally differs. Explicitly complete context uses AWS's absence rules; see [condition verification](CONDITION_VERIFICATION.md). This does not validate SCPs, permission boundaries, session policies, resource-policy composition, service-specific behavior or full cross-account/live-account authorization. The simulator itself is a comparison source, not proof that an actual request will succeed.

Explicit AWS runs fail closed on missing tools/credentials, blocked calls, incomplete results, zero comparisons or mismatches. Offline tests simulate CLI absence without inspecting local credentials.
