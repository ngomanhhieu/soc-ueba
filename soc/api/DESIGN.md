---
version: alpha
name: SOC/UEBA console
description: Analyst console for a SOC/UEBA system – dark-first, data-dense, calm, IBM Carbon-aligned.
colors:
  dark:
    background: "#161616"
    surface: "#1f1f1f"
    surface-raised: "#2a2a2a"
    hairline: "#333333"
    hairline-strong: "#474747"
    ink: "#f4f4f4"
    ink-muted: "#b4b4b4"
    ink-subtle: "#8d8d8d"
    accent: "#4589ff"
  light:
    background: "#f4f4f4"
    surface: "#ffffff"
    surface-raised: "#ececec"
    hairline: "#e0e0e0"
    hairline-strong: "#c6c6c6"
    ink: "#161616"
    ink-muted: "#525252"
    ink-subtle: "#8d8d8d"
    accent: "#0f62fe"
  severity:
    critical: "#fa4d56"
    high: "#ff832b"
    medium: "#f1c21b"
    low: "#42be65"
  data:
    rules: "#33b1ff"
    ml: "#be95ff"
typography:
  page-title:
    fontFamily: IBM Plex Sans
    fontSize: 22px
    fontWeight: 600
  section-title:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    fontWeight: 600
    letterSpacing: 0.16px
  body:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.55
  caption:
    fontFamily: IBM Plex Sans
    fontSize: 12px
    letterSpacing: 0.32px
  data:
    fontFamily: IBM Plex Mono
    fontSize: 13px
    fontFeature: tnum
  metric:
    fontFamily: IBM Plex Mono
    fontSize: 30px
    fontWeight: 500
rounded:
  container: 0px
  badge: 999px
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
components:
  button-primary:
    backgroundColor: "{colors.dark.accent}"
    textColor: "#ffffff"
    rounded: "{rounded.container}"
    padding: 10px 16px
  panel:
    backgroundColor: "{colors.dark.surface}"
    border: 1px solid {colors.dark.hairline}
    rounded: "{rounded.container}"
    padding: 16px 18px
  severity-badge:
    backgroundColor: 13% of the severity colour
    textColor: "{colors.severity.*}"
    rounded: "{rounded.badge}"
    padding: 2px 10px
---

## Overview

The console is used by SOC analysts for long sessions, often in dim rooms. It should feel calm,
precise and trustworthy – closer to IBM QRadar / Carbon than to a "hacker" aesthetic. Dark theme is
the default; a light theme exists for projectors and printing. Every screen answers one question
first ("what needs attention?", "what happened?", "why was it flagged?"), in plain sentences.

## Colors

- Grey layers (background → surface → surface-raised) create depth; there are no drop shadows.
- Blue is reserved for interaction: links, the primary button, focus, the selected nav item, and the
  heat-map scale. It never decorates.
- Severity colours appear only on severity badges and the left edge of incident rows.
- Chart series: Sigma rules = cyan, machine learning = purple, with a legend (never colour alone).

## Typography

- IBM Plex Sans for interface text, IBM Plex Mono for **data**: user / host / incident IDs, ATT&CK
  technique IDs, counts and metrics (tabular figures so columns align). Mono is not used for labels.
- Sentence case everywhere – page titles, section titles, labels, buttons. No tracked all-caps
  eyebrows. Acronyms keep their own case (LANL, CERT, IOC, MTTD).
- Fonts are self-hosted in `static/fonts/` (SIL OFL) so the strict CSP needs no external origin.

## Layout

- 4 px grid; panels use 16–18 px padding; gaps of 16 px between panels.
- Overview fits one screen: one row of four metrics, then two rows of two panels.
- Lists over tables where the analyst reads sentences; tables only for raw records.

## Elevation & Depth

Flat. Surfaces and 1 px hairlines carry hierarchy; metric cards get a 2 px top rule (accent on the
primary metric).

## Shapes

Containers, buttons and inputs are square (0 px). Badges and status tags are fully rounded pills –
the only rounded shapes, so they read as "labels", not structure.

## Motion & Micro-interaction

Almost none: hover tints, no entrance animations. `prefers-reduced-motion` disables all transitions.

## Voice & Content Strategy

Plain English written for the analyst: "Account U66@DOM1 signed in from unfamiliar hosts; the trail
leads to C17693…". Buttons name their action ("Open queue", "Save verdict", "Approve"). No arrows
appended to links or buttons.

## Components

- **Severity badge** – pill, tinted background, sentence-case word **and a distinct shape** per level
  so it works without colour: ▲ critical (triangle with "!"), ● high (filled circle with "!"),
  ○ medium (ring), • low (dot).
- **Ranked list (Riskiest)** – rank number, entity in mono, type in words, evidence ("56 detections
  over 9 days"), severity badge. No decorative meter.
- **Heat map** – ATT&CK stage × time, log scale, blue ramp, legend "fewer → more".
- **Metric card** – caption label, mono value, one small visual that carries data (severity mix bar,
  LANL detection sparkline, MTTD progress bar) and one line of context; a 3 px top rule in the card's
  data colour (critical red, ML purple, success green, accent blue). Empty metrics say what to do
  ("Save a verdict on any incident to start the clock") instead of showing a dash.
- **UI shell** – the sidebar stays dark (#0d0d0d / #161616) in both themes, as in Carbon's UI shell,
  so the light theme reads clearly as "dark shell + white canvas".
- **Status pill** – a dot that pulses only while a demo is running (disabled by reduced motion).
- **Panel titles** – a 16 px line icon in the panel's data colour before the sentence-case title.

## Do's and Don'ts

- Do keep text contrast ≥ 4.5:1 and a visible 2 px focus outline.
- Do show evidence next to every risk signal.
- Don't use neon colours, gradients as decoration, glow, or glitch effects.
- Don't nest cards, add an eyebrow above every heading, or rely on colour alone.
- Don't load fonts, scripts or styles from other origins (CSP `default-src 'self'`).

Sources: IBM Carbon (via VoltAgent/awesome-design-md), ui-ux-pro-max-skill (MIT), Anthropic
frontend-design skill, Impeccable (Apache-2.0) and Hallmark (MIT) anti-pattern lists. Format:
google-labs-code/design.md (Apache-2.0).
