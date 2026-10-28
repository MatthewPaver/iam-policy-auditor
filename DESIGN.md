---
name: PolicyLens
description: A dark, evidence-led permission-change review interface.
colors:
  ground: "#0d1117"
  panel: "#161b22"
  panel-raised: "#1c2330"
  review-surface: "#141b24"
  review-line: "#344150"
  border: "#2d3646"
  text: "#e6edf3"
  muted: "#b4c2d4"
  accent: "#66b5ff"
  action: "#2086f4"
  action-hover: "#0b5db5"
  risk: "#ff929c"
  verified: "#90dbb3"
  critical: "#ff4d5e"
  warning: "#f5c542"
  source-ground: "#0d141d"
  source-text: "#c8ddf2"
  source-number: "#a0b6cb"
  active-tab: "#4da3ff"
  control-text: "#f5f7fa"
  white: "#fff"
  secondary-line: "#6c7f94"
  secondary-hover: "#202d3c"
  secondary-hover-line: "#9db1c8"
  disabled-ground: "#242f3b"
  disabled-line: "#465462"
  trace: "#91caff"
  trace-ground: "#24364b"
  risk-ground: "#211b24"
  risk-line: "#ae535f"
  verified-line: "#4b9274"
typography:
  display:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "52px"
    fontWeight: 700
    lineHeight: 1.06
    letterSpacing: "-.025em"
  headline:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "32px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-.02em"
  body:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "16px"
    lineHeight: 1.5
  introduction:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "24px"
    lineHeight: 1.2
  evidence-heading:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "33px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-.02em"
  brand:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "23px"
    fontWeight: 700
    lineHeight: 1
  statement-title:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "22px"
    lineHeight: 1.3
  statement-group:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "17px"
    fontWeight: 600
  evidence-label:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "14px"
    lineHeight: 1.6
  statement-name:
    fontFamily: "'Atkinson Hyperlegible Next', sans-serif"
    fontSize: "15px"
  secondary-control:
    fontFamily: "Arial, sans-serif"
    fontSize: "18px"
    fontWeight: 400
    lineHeight: 1.5
  primary-control:
    fontFamily: "Arial, sans-serif"
    fontSize: "19px"
    fontWeight: 700
    lineHeight: 1.5
  source:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "13px"
    lineHeight: "21px"
rounded:
  compact: "4px"
  field: "5px"
  control: "6px"
  surface: "8px"
spacing:
  tight: "8px"
  inset: "12px"
  regular: "16px"
  section: "24px"
components:
  button-primary:
    backgroundColor: "{colors.action}"
    textColor: "#fff"
    typography: "{typography.primary-control}"
    rounded: "{rounded.control}"
    padding: "11px 14px"
  button-primary-hover:
    backgroundColor: "{colors.action-hover}"
    textColor: "#fff"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "#f5f7fa"
    rounded: "{rounded.control}"
    padding: "11px 14px"
  review-card:
    backgroundColor: "{colors.review-surface}"
  source-field:
    backgroundColor: "#0d141d"
    textColor: "#c8ddf2"
    typography: "{typography.source}"
    padding: "5px 12px"
---

# Design System: PolicyLens

## Overview

**Creative North Star: "Guided review"**

PolicyLens preserves an operational dark world: near-black ground, slate working surfaces, pale humanist lettering and blue rectangular actions. The approved guided-review direction makes the consequence readable before asking the reader to inspect source. Thin boundaries and restrained semantic colour keep evidence central.

The default public entrance is a product landing with a working synthetic review. The separate own-policy workbench retains denser editing and comparison. These are two expressions of the same world, not interchangeable states: sample outcomes must never masquerade as results for a visitor's inputs.

**Key Characteristics:**
- Consequence first, cited source close behind.
- Humanist headings and prose; monospace policy content.
- Flat dark surfaces, thin rules and blue actions.
- Written outcomes and nearby scope limits.

## Colors

### Primary

Action blue drives the large product buttons. A lighter accent carries links, interactive text and focus. The existing workbench uses a deeper primary button fill; retain that distinction rather than replacing every blue with one value.

### Neutral

Ground is the page canvas. Panel and raised panel support existing tools; review surface and review line organise the guided desk. Pale text carries conclusions, while muted text carries explanations and secondary navigation. The product stylesheet overrides the older muted and accent custom properties; the frontmatter records the active product values.

Risk pink marks the proposed granting statement and introduced deletion access. Verified green belongs to the bounded corrected outcome. Existing tool severity colours remain severity cues, not brand accents.

**The Written Outcome Rule.** Pair semantic colour with explicit result text. Green never means whole-policy safety or production approval.

## Typography

Display and body use self-hosted Atkinson Hyperlegible Next, with sans-serif fallback. Font files and their OFL licence live under `public/assets/fonts/`. Product buttons use Arial; retain this deliberate ordinary-control voice. Policy documents, actions, ARNs, source lines and hashes use the existing monospace stack.

The frontmatter records desktop roles. Landing display contracts to 46px at 1100px and 36px at 760px. Chapter headings contract from 32px to 28px and then 26px. Introductory prose uses 24px, 20px and 18px across those widths. Supporting explanations use 17–19px; compact evidence uses 13–15px. Long explanation blocks are generally bounded at 65–75ch.

Primary product buttons use the recorded large, bold type. Preserve that size and weight when retaining their blue fill; do not reuse this pairing for small ordinary copy. Normal copy uses the higher-contrast pale text and lighter accents. This document records source values, not a computed contrast audit.

**The Evidence Type Rule.** Keep JSON editors and source monospace while labels, prose and verdicts retain the humanist face. Mobile editors increase to 16px.

## Layout

The landing begins with a centred promise, paired actions and a processing/privacy line. A broad, flat review desk follows, with three ordered chapters: risk, correction and export. Desktop risk places current and proposed outcomes above two source/explanation columns. Correction and record summaries also use two columns. The desk gutter is fluid (`clamp(18px,3.19vw,60px)`); the own-policy workbench caps at 1440px.

At 1100px, typography and column gaps tighten. At 760px, navigation wraps, landing actions stack, chapter labels shorten and chapter controls arrange number above label. The current/proposed comparison remains adjacent with smaller type; the evidence, correction and record grids stack. Explanation precedes source on mobile. Evidence rows and footer stack; controls expand to usable widths. Source retains internal scrolling rather than forcing the page wider.

Own-policy review bypasses the guided chapters. Its original and corrected regions stack at 760px, and Current/Proposed controls select one policy editor. The inherited general editor grid also has a 900px breakpoint. Keep these separate responsive behaviours instead of assuming every comparison uses the same breakpoint.

## Elevation & Depth

The current product landing and review desk use tonal layering and thin borders, without drop shadows. Nested ground, surface and source backgrounds establish depth. Existing local account hero styling includes a restrained background gradient; it does not define the new landing or authorise decorative gradients on operational results.

The replay trace briefly outlines proposed access, cited source and evidence in sequence (650ms, staggered by 180ms). Reduced motion removes animation and preserves static emphasis. Result comprehension must not depend on watching the trace.

## Shapes

The guided desk is a flat working surface with top and bottom rules, no outer rounded frame. Access outcomes use horizontal rules; data fields and source excerpts avoid enclosing borders. Verification uses a top rule and ruled data rows. Product actions retain the control radius; compact utilities and workbench verdicts use the compact radius. Editable fields and inherited tool surfaces retain their existing radii. Do not apply a shared card silhouette to every evidence region. Chapter numbers are circular; document chips and existing pills retain their specific compact forms.

## Components

### Buttons

Product actions are at least 51px tall, with a thin border and the primary or outlined secondary treatment. Hover darkens the primary and lifts the secondary surface tone. Disabled buttons become slate and retain readable labels. Pressed buttons scale to 0.98 over 100ms; there is no press scale under reduced motion. Workbench buttons are denser, use the incumbent 8px radius and deeper blue fill, and reach 44px height in review. Keep visible 3px keyboard focus with a 3px offset.

### Navigation

Header links are secondary until interaction. The walkthrough at /impact/ uses the same header (wordmark, How it works, Source code, Product home). Chapter tabs use numbered circles and an active blue bottom rule, with `aria-selected`, roving focus and Arrow/Home/End navigation. Shortened phone labels preserve the three ordered steps. Phone actions use concise labels such as “Check the correction”, “Export the record” and “Open policy review”; preserve their full-width targets. Product home navigation retains session work. Local account routes remain accessible on the server; the static browser build does not offer those services.

### Chips

Existing document chips use raised slate, thin borders, compact monospace labels and a 6px radius. They identify loaded documents in existing tools. Do not introduce them as decorative landing badges.

### Cards / Containers

The guided desk contains the comparison, source and explanation within a single working surface. Proposed access uses a restrained tinted risk panel. Verification sits on the same working surface behind a top rule; success changes that rule and heading, leaving the original proposal unchanged. Retain loading, incomplete, not-verified and stale states as first-class content.

### Inputs / Fields

Policy textareas are resizable dark fields with monospace content. Request fields retain code typography and visible labels. The own-policy route accepts pasted JSON or local files and exposes condition context. Policy editors close after successful review and remain available to edit. Input edits invalidate affected results; late responses cannot replace newer input. Inline errors name the repair action.

### Evidence trace and record

The risk consequence and “Check the correction” action precede “Inspect the request and source evidence”. “View policy” and “Replay trace” open that disclosure. Verified correction leads with “Deletion access removed and required access kept”, followed by an “Export the record” action that opens the export step. Failure headings identify unresolved deletion risk, required access not preserved, or new high or critical findings needing review; “Inspect checked requests and decisions” retains exact checks and decisions. Limits are stated once, in the Limits block on the landing page; every other mention links to it.

Source displays real line numbers, a cited excerpt and restrained risk emphasis on granting values. The full-policy toggle preserves inspectability. Request, citation and source copy controls use authored SVGs, descriptive accessible names and copied/error status messages. Phone copy targets reach 44px. Icons support written meaning rather than replacing it.

### Statement comparison

The guided candidate preview and completed own-policy verification show whole statements grouped as Removed, Retained and, when present, Added. Each group counts statements and lists their name, effect, action and resource. An “Exact statement” disclosure exposes JSON and the original/candidate JSON pointers; values render as escaped text. Unnamed statements retain a written fallback.

Comparison ignores object-key order, preserves array order and consumes duplicate statements individually. Editing a statement appears as removal plus addition. Adding a Deny retains an unchanged Allow; it does not portray that grant as removed. This is structural comparison, not semantic equivalence or an access conclusion. The guided preview refreshes when candidate inputs change; own-policy comparison belongs to the completed verification result.

**The Statement Is Not Access Rule.** “Retained” means an exact whole statement remains. Only independent request verification establishes required access preservation.

### Verified outcome and portable record

Plain-language risk outcomes lead: Allowed, Not allowed, Explicitly denied and Needs context. Preserve the exact AWS decision names alongside them, including Allow, ImplicitDeny, ExplicitDeny and ConditionalAllow. Correction results retain the risk closure, required preservation and introduced severe-finding checks.

The original proposal, corrected candidate and exact export remain distinct. Verification checks risk closure, definite required access before and after, and introduced high or critical findings. Exports retain exact inputs, results, SHA-256 identities and schema/engine identity. Candidate or required-request edits immediately invalidate verification and remove stale correction evidence from the current export; the original review may remain exportable. Late responses cannot restore stale evidence. “What the record includes” is a disclosure; scope limits, exclusions and outstanding independent AWS comparison remain visible outside it.

**The Bounded Evidence Rule.** Place scope beside the outcome: supplied documents and declared requests only. Excluded organisation controls and unverified AWS parity remain explicit. Browser-local privacy text must differ accurately from the separate server and optional-AI routes.

## Do's and Don'ts

### Do:
- **Do** keep the dark ground, humanist display, thin boundaries and blue actions together.
- **Do** preserve source lines, semantic value emphasis and functional copy controls.
- **Do** distinguish the labelled synthetic example from own-policy review.
- **Do** keep original results visible beside bounded correction outcomes and export their exact evidence.
- **Do** distinguish retained statements from verified required access and keep exact JSON/pointers inspectable.
- **Do** preserve keyboard focus, readable mobile editors and reduced-motion comprehension.

### Don't:
- **Don't** treat a green correction result as production approval or whole-policy safety.
- **Don't** imply an added Deny removed the original Allow, or collapse duplicate statement counts.
- **Don't** replace policy monospace with the global form-control font.
- **Don't** substitute glyph icons for the existing authored SVG vocabulary.
- **Don't** present optional server AI or account analysis as a static-browser capability.
- **Don't** turn the landing's chapter composition into a mandatory layout for every future surface.
