---
name: PolicyLens interactive walkthrough
description: Two-task rehearsal with real permission checks and authored sandbox effects.
colors:
  ground: "#0d1117"
  surface: "#141f2c"
  line: "#405366"
  text: "#e6edf3"
  muted: "#b4c2d4"
  blue: "#66b5ff"
  button: "#0868c9"
  good: "#90dbb3"
  bad: "#ff929c"
  amber: "#f5c542"
typography:
  display:
    fontFamily: "Atkinson, sans-serif"
    fontSize: "clamp(28px,3vw,40px)"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "-.025em"
  body:
    fontFamily: "Atkinson, sans-serif"
    fontSize: "17px"
    lineHeight: 1.5
  title:
    fontFamily: "Atkinson, sans-serif"
    fontSize: "22px"
    fontWeight: 700
    lineHeight: 1.3
  label:
    fontFamily: "Atkinson, sans-serif"
    fontSize: "15px"
  source:
    fontFamily: "ui-monospace, monospace"
    fontSize: "13px"
    lineHeight: 1.6
rounded:
  control: "5px"
spacing:
  tight: "8px"
  small: "12px"
  regular: "16px"
  section: "24px"
components:
  button-primary:
    backgroundColor: "{colors.button}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "9px 14px"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "9px 14px"
  walkthrough-control:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
    height: "44px"
  stage:
    backgroundColor: "#111924"
---

# Design System: PolicyLens interactive walkthrough

## Overview

**Creative North Star: "Guided review, rehearsed"**

The default walkthrough is a compact 2D request view. A five-chapter silent guide exposes proposed deletion access, removes the deletion grant, then repeats both checked tasks. The existing deterministic engine supplies every verdict; a separately labelled in-memory sandbox reveals a sample report or clears fictional rows only for definite Allow.

Dark slate, self-hosted Atkinson lettering, blue controls and written outcomes retain PolicyLens’s operational world. This contract applies only to the interactive walkthrough; the engine, account-analysis views and historical previews remain outside its scope. No human impact, enterprise coverage or production approval is claimed.

**Key Characteristics:**
- One caption and one current result precede the working visual.
- One compact request view. No 3D scene (removed 28 Oct 2026: decorative, not needed to understand the check).
- All three policies have persistent engine-derived comparison rows.
- Exact evidence distinguishes permission decisions from fictional effects.

## Colors

### Primary

Blue carries primary actions, links, focus and active request emphasis. Slate surfaces and thin boundaries retain an operational feel.

### Neutral

Near-black ground supports slightly brighter working surfaces. Pale text carries results; muted text carries explanations, limits and exact source context. The updated surface and line tokens record the simplified build.

Semantic green and pink describe success or failure relative to each task: report allowed is favourable, while deletion allowed is risk. Amber denotes incomplete information. Both ImplicitDeny and ExplicitDeny appear as Blocked in plain UI; exact evidence preserves their distinction.

**The Written Outcome Rule.** Pair semantic colour with written outcomes; a green result establishes only the two checked requirements.

## Typography

Atkinson aliases self-hosted Atkinson Hyperlegible Next. The display is compact and fluid; phone uses 29px. Body contracts from 17px to 16px. Captions use 19px with 1.35 line height, contracting to 17px on phone. The current result uses 23px, or 21px on phone. Policy JSON and exact engine records use the recorded monospace role. Tables use tabular numerals and readable labels.

## Layout

Header and main cap at 1240px with desktop horizontal gutters (28px). Caption, playback controls and current result form one compact block above the visual. The default request view has one full-width workspace: the diagram above a compact disclosure/tools region. Its desktop diagram places reader, permission check and the two request destinations across one row.

At 700px, gutters become 16px. The reader and policy check share one row; the two request destinations share the next. Caption and current result remain above the visual. Three-way comparison converts to labelled rows using each cell’s data label. Sample content, transcript and exact evidence remain disclosures. Completed task lists and task content hide after two actions, and guided mode hides them throughout.


## Elevation & Depth

Flat tonal surfaces and thin rules create interface depth without drop shadows. The default request view uses restrained progress emphasis, not spatial theatre. Optional model-space perspective supports inspection. Its labels have dark backing; rendered geometry is illustrative rather than AWS topology.

## Shapes

Actions have gently rounded corners (5px) and minimum height (44px). Request destinations are rectangular controls with clear task, decision and fictional-data labels. Numbered circles identify manual task progress. Thin rows organise evidence and three-way comparison rather than enclosing every section in a card.

## Components

### Request view and current result

The compact request view is the only view. Each destination starts as Not tried. A user or guide action highlights the checked request for 650ms, then reveals its written outcome. The current result stays above the visual, avoiding dependence on camera state or remembered selections. Reduced motion skips spatial/progress animation.

### Captioned guide and controls

Five chapters cover the proposed run, narrow correction and comparison. A completed guide accumulates seven captions. Block everything remains a manual experiment and a persistent comparison row rather than another autoplay chapter. The guide calls existing selectChoice and attempt paths; it does not script verdicts independently.

Task chapters have an authored lead minimum (1600ms). All caption dwell uses a 200-wpm reading floor plus 500ms, extended by chapter-specific minimums. The observed controlled-clock guide is roughly 29 seconds; timing illustrates pacing, not cloud or network execution. Play/Pause/Resume have state-matching accessible names. Replay resets story and transcript. Try it yourself cancels pending guided effects and exposes manual tasks; `?mode=manual` starts there. No cancelled action may apply a late effect.

**The Read Before Motion Rule.** Keep action captions readable before request movement and preserve outcome reading dwell.

The guide plays once without audio or looping. Both caption and visual must meet the 50% vertical-visibility threshold. Hiding the document or losing either visibility condition pauses story and animation. Resuming requires an explicit user action with both visible. Reduced motion starts paused. No automatic scrolling or focus theft occurs.

**The Deliberate Resume Rule.** Pause when either caption or working visual is insufficiently visible; require explicit Resume with both visible.

### Manual policy choices and persistent comparison

Choice names are Proposed access, Block everything, and Keep report access only. All three receive real correction checks independent of scene playback. The comparison retains exact task results and whether both requirements pass. Manual selection restores the same fictional data. Rewind restarts the current candidate; Reset example clears the retained original and returns to proposed access.

**The Retained Original Rule.** Keep the completed proposed run while each intervention restores the same authored starting data.

### Fictional report and database

Sample-data disclosure reveals authored report content and three fictional database rows. Definite Allow reveals the report or clears the rows; blocked or indeterminate requests do not enact those sample effects. The source and export explicitly separate permission analysis from authored in-memory activity.

**The Permission And Effect Rule.** Only the existing engine establishes permission; the sandbox enacts explicitly authored sample effects for definite Allow.

**The Independent Stores Rule.** The stored report is independent of the fictional database; deleting database rows never removes report content.

### Source and exact export

Source rules and correction disclose the checked statement, citation and structural changes. Technical evidence stays directly linked. Download includes review/correction inputs and identities plus all three comparison inputs, results and SHA-256 hashes. A separately labelled simulation object records synthetic activity, no cloud actions, independent report storage, current run and retained original. Only supplied policies and two declared requests are checked; other account rules and actual cloud execution remain outside scope.

## Do's and Don'ts

### Do:
- Do keep the current caption and result above visual inspection, including on phone.
- Do use the same three choice names in controls, comparison and evidence.
- Do retain exact implicit and explicit deny distinctions in evidence while plain UI says Blocked.
- Do preserve immutable original evidence, independent stores, cancellation and three-way export identities.

### Don't:
- Don't claim cloud execution, network timing, enterprise coverage or measured human benefit.
- Don't make report content depend on database rows or present fictional effects as engine outputs.
- Don't automatically resume, steal focus, scroll the user, loop the story or add audio.
- This contract describes the walkthrough; it does not approve changes to unrelated product views.
