# Project plan

## Goal

Build a demonstrable application for analyzing AI and deepfake threats: scenario → target → campaign stages → consequences → baseline risk → defenses → residual risk → report.

## MVP requirements

- Three predefined scenarios covering text, voice, and video.
- Fictional target profile with role, access level, and relevant context.
- Ordered campaign stages with warning signs and defensive intervention points.
- Financial, confidentiality, operational, and reputational consequences.
- Validated likelihood and impact ratings in the range 1–5.
- Explained baseline and residual scores, with applicable controls only.
- CLI for selecting a scenario, configuring a profile, and exporting a report.
- TXT and versioned JSON exports containing assumptions and model version.
- A reusable service interface for the later GUI.

## Later scope

PySide6 GUI, additional impersonation and disinformation scenarios, PDF exports, comparison history, and optional Polish interface text. These are not prerequisites for the CLI MVP.

## Deliverables

Shared Python engine, scenario catalog, CLI, automated checks, sample fictional reports, GUI integration documentation, and a short presentation demo.

## Decisions still open

Submission date, GUI contributor identity, application language, PDF priority, and final calibration of scenario rules. No implementation dates are committed yet.
