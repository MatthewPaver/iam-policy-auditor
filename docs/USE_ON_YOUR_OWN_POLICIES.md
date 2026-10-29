# Use PolicyLens on your own policies

Three ways to run the same deterministic engine. Nothing is uploaded; policies stay on your machine or in your browser.

## 1. Browser

1. Open the [browser demo](https://matthewpaver.github.io/iam-policy-auditor/) or run `npm run build:demo` and open `site/index.html`.
2. Choose **Use your own policies**.
3. Paste or drop current and proposed documents. Accepted shapes include plain IAM JSON, `get-policy-version`, `get-role-policy`, authorization-details role entries, CloudFormation (JSON or YAML), Terraform plan JSON, and arrays of policies.
4. Leave the action blank to see **What this change newly allows**, or name an action, resource and optional principal to check one path.
5. Optionally mark **Context is complete** and add several required-access rows before verifying a correction.

## 2. Command line

```bash
npm install
node bin/policylens.js review --before before.json --after after.json --format text
node bin/policylens.js review --before before.json --after after.json --format json
node bin/policylens.js review --before before.json --after after.json --request '{"action":"s3:GetObject","resource":"arn:aws:s3:::bucket/obj","principal":"anonymous"}' --format sarif
node bin/policylens.js review --terraform-plan plan.json --format text
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every result is `pass` |
| 1 | Any result is `stop` |
| 2 | Any result is `review` and none is `stop` |
| 3 | Input error (one plain sentence on stderr) |

## 3. GitHub Action

Copy `examples/github-actions/policylens.yml` into `.github/workflows/`. The composite action at the repository root reviews files changed between the pull request base SHA and `HEAD`. It fails the step on exit code 1 (`stop`).

```yaml
- uses: MatthewPaver/iam-policy-auditor@main
  with:
    paths: '**/*.json'
    format: sarif
```

Optional: pass `terraform-plan` to a `terraform show -json` file instead of a path glob.

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
