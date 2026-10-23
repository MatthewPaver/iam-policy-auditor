# PolicyLens

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

The user confirmed engineers reviewing an AWS permission change as the main product story: see the new risk, inspect its source, verify a correction, then export the evidence. Portfolio visitors also need to understand the job, try the working engine and inspect its evidence. Specific buyer roles, practitioner demand and measured benefits remain unvalidated.

## Product Purpose

Make a permission change's effect, source evidence and bounded correction understandable. The user approved the change-review direction in the three-flagship design round and now requests the same product-first treatment as ProjectLens: a proper landing page, polished interactive demo, before-and-after captures and tested end-to-end journeys.

## Positioning

A small, inspectable permission-change workflow: declare a sensitive request, compare current and proposed documents, inspect cited evidence, verify a corrected candidate against required access and export the review record. AWS Access Analyzer already offers new-access checks. PolicyLens must not claim novel policy analysis, independent AWS parity, comprehensive safety or production approval.

## Operating Context

The public GitHub Pages demo runs the existing deterministic modules in the browser. Policies are not uploaded by that route. The Node server separately offers account-snapshot and single-policy tools plus optional AI explanations. Those server capabilities are not available in the static demo. The existing codebase uses plain HTML, CSS and JavaScript without runtime package dependencies.

## Capabilities and Constraints

- The engine compares supplied policy documents for one declared action, resource and context. It returns a decision and source line citations.
- A correction must close the declared risk, preserve definite required access and introduce no high or critical rule finding. Missing or unsupported context cannot establish preservation.
- Keep the original proposal separate from the corrected candidate. Edits invalidate affected results; late responses cannot replace newer inputs.
- Export exact inputs, results, SHA-256 identities, schema and engine/source identity. A person remains responsible for interpreting and acting on the record.
- SCPs, permission boundaries, session policies and cross-account interactions are excluded. A verified correction covers checked requests, not the whole policy or live AWS environment.
- AI explanations are optional and disabled by default. They explain deterministic results and never determine verdicts. Captured explanation evaluations are not live model measurements.
- Preserve local-server account and single-policy routes, hosted privacy controls and the existing deterministic engine during UI work.

## Brand Commitments

Keep PolicyLens and its recognizable dark operational interface with blue actions. The user requests the design care applied to ProjectLens, purposeful interaction and clear value, while rejecting generic AI-generated website styling. Preserve product truth and evidence rather than copying another brand.

## Evidence on Hand

The bundled synthetic example introduces rds:DeleteDBInstance on prod-1, changing ImplicitDeny to Allow. The granting statement is S2 at after.json:10, DeleteProductionDatabase. The corrected candidate removes this access while retaining s3:GetObject for a report. These are demonstration facts, not client outcomes.

Existing evidence includes source modules, tests, authored benchmarks, captured AI grounding fixtures and browser/server parity checks. Independent AWS simulator comparison remains outstanding. No verified customers, testimonials, adoption, time savings or business results may be invented.

## Product Principles

1. Explain the consequence, show its source and make the next review action clear.
2. Keep original and corrected outcomes distinct, including failures and stale states.
3. Use the real engine and clearly labelled synthetic inputs for demonstrations.
4. Place scope limits beside conclusions, not only in documentation.
5. Keep the complete evidence handoff inspectable and portable.
