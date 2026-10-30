# Use PolicyLens on your own policies

Give PolicyLens the current and proposed versions of an AWS IAM policy. It lists what the change newly allows, who gains access and the source lines, with a **Stop**, **Check** or **Pass** verdict. Explanations use fixed rules, with no AI or AWS account needed for the review itself.

Try your own policy in 60 seconds from a cloned repository with Node.js 18 or later. Run `npm ci` once. Use your policy ARN and two retained version IDs in place of the examples below. The AWS export commands need credentials with `iam:GetPolicyVersion`; the local review needs none.

```bash
POLICYLENS_POLICY_ARN='arn:aws:iam::123456789012:policy/YourPolicy'
aws iam get-policy-version --policy-arn "$POLICYLENS_POLICY_ARN" --version-id v1 > before.json
aws iam get-policy-version --policy-arn "$POLICYLENS_POLICY_ARN" --version-id v2 > after.json
node bin/policylens.js review --before before.json --after after.json --format text
```

**Measured accuracy:** set 4: **15/15, seen**; set 5: **pending, not supplied or scored**. Sets 1-4 shaped these rules and are regression evidence. A separate set 5 must supply the next unseen headline score. See the [real-case benchmark](../bench/real-cases/), including public sources and unchanged floors. A pass is not production approval.

## 1. Browser

1. Open the [browser demo](https://matthewpaver.github.io/iam-policy-auditor/) or run `npm run build:demo` and open `site/index.html`.
2. Choose **Use your own policies**.
3. Paste or drop current and proposed documents. Accepted shapes include plain IAM JSON, `get-policy-version`, `get-role-policy`, authorization-details role entries, CloudFormation (JSON or YAML), Terraform plan JSON, and arrays of policies.
4. Leave the action blank for a verdict sentence, followed by **Stop**, **Check** and collapsed **Lower risk** items. Each sentence names the caller when supplied. Select a line number to highlight the normalised policy source used by the engine. Wrapped or formatted input can have different line numbers.
5. Select **Copy review for a pull request** to copy the verdict and stop items, including action names and line numbers. **Try a real AWS incident** loads the public AWSSupportServiceRolePolicy v19 to v20 change. Its [AWS bulletin](https://aws.amazon.com/security/security-bulletins/AWS-2021-007/) explains the added permission, its reversal and why AWS support systems could not use it.
6. Name an action, resource and optional principal to check one path.
7. Optionally mark **Context is complete** and add several required-access rows before verifying a correction.

## 2. Command line

```bash
npm ci
node bin/policylens.js review --before before.json --after after.json --format text
node bin/policylens.js review --before before.json --after after.json --format json
node bin/policylens.js review --before before.json --after after.json --request '{"action":"s3:GetObject","resource":"arn:aws:s3:::bucket/obj","principal":"anonymous"}' --format json
node bin/policylens.js review --terraform-plan plan.json --format text
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every result is `pass` |
| 1 | Any result is `stop` |
| 2 | Any result is `review` and none is `stop` |
| 3 | Input error (one plain sentence on stderr) |

## How to export from AWS and IaC

```bash
# Managed policy version (URL-encoded Document is accepted)
aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/PowerUserAccess --version-id v5 > after.json

# Inline + attached policies for a role
aws iam get-account-authorization-details --filter Role > auth.json

# Terraform plan JSON
terraform plan -out=plan.out
terraform show -json plan.out > plan.json
```

CloudFormation: paste the template (JSON or YAML). PolicyLens extracts `AWS::IAM::ManagedPolicy`, role `Policies`, and `AWS::S3::BucketPolicy` documents.

Example fixtures with licence notes live in `examples/policies/`.

## What is and is not covered

Covered: the supplied identity / resource / trust policy documents, Principal and NotPrincipal when you declare a principal, modelled policy variables (`aws:username`, `aws:userid`, `aws:PrincipalAccount`, `aws:PrincipalTag/*`), and request-free newly allowed grants.

Not covered: SCPs, permission boundaries, session policies, and cross-account trust interplay beyond what the supplied documents say. A pass is not production approval.

## Privacy

Reviews run locally (browser, CLI or your own CI runner). Policy text is not sent to a PolicyLens service. Optional AI explanation (local server only) sends extracted facts only when you opt in and configure a key.
