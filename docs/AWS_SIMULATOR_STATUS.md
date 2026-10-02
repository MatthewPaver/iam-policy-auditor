# AWS simulator comparison status

As of 2026-09-05: **not run in this repository**. No AWS credentials were read or used during the audit fixes. The 55/55 result is an authored regression corpus, not AWS authorization accuracy.

The executable adapter is `benchmark/oracle-aws.js`; the machine-readable disclosure is `benchmark/oracle-manifest.json`. An owner may run `npm run benchmark:aws -- --json` with the AWS CLI and a deliberately scoped principal permitted to call `iam:SimulateCustomPolicy`. This command contacts AWS and is not part of offline CI.

Retain a reviewed, redacted result alongside the exact commit, UTC run date, AWS CLI version and supported scope. Report `checked`, `engineVsAws`, `agreementPct`, every mismatch/error and every skipped case. Do not publish credentials, account policy contents or account identifiers. Do not replace this status with a success statement until a real report exists.

The corpus covers single identity-policy requests: action/resource matching, explicit deny, NotAction/NotResource and supported condition operators. The `missing-key-conditional` case is disclosed and excluded from comparison because the local `ConditionalAllow` vocabulary intentionally differs. This does not validate SCPs, permission boundaries, session policies, resource-policy composition, service-specific behavior or full cross-account/live-account authorization. The simulator itself is a comparison source, not proof that an actual request will succeed.

Explicit AWS runs fail closed on missing tools/credentials, blocked calls, incomplete results, zero comparisons or mismatches. Offline tests simulate CLI absence without inspecting local credentials.
