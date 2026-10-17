# Planned user guide

## Availability

This is a walkthrough of the intended behavior, not instructions for an executable release. The repository contains documentation only. Installation and actual command names will be added when the CLI is implemented.

## First analysis

1. Open the future console interface and select a scenario. Start with **Voice deepfake**.
2. Enter a fictional organization and target role, such as **Example Company / accounting employee**. Specify payment authority and any relevant access.
3. Select defenses already in place. Leave these empty for an unprotected teaching example.
4. Read the fictional campaign stages, warning signs, and possible consequences.
5. Review baseline likelihood, impact, score, level, and the reasons for the assessment.
6. Add proposed defenses, such as callback to a previously known number and independent payment approval.
7. Compare the baseline with residual risk. Read which assumptions changed and which consequences remain possible.
8. Choose TXT for a readable report or JSON for structured data, then select a destination.

## Example presentation

| Field | Illustrative value |
| --- | --- |
| Scenario | Voice deepfake |
| Target | Fictional accounting employee |
| Existing controls | None |
| Baseline likelihood / impact | 4 / 5 |
| Baseline score | 20 — Critical |
| Proposed controls | Verified callback and independent approval |
| Residual likelihood / impact | 2 / 5 |
| Residual score | 10 — High |

These are design examples, not output from an implemented engine or evidence of real-world effectiveness. Final scenario rules must be agreed and tested.

## Understanding the result

Likelihood and impact are ordinal ratings from 1 to 5. A score of 20 is not a 20% probability. A lower residual score means that the teaching model assessed a different set of conditions; it does not guarantee that an attack will fail.

A defense can be relevant to one scenario and irrelevant to another. Authentication protection can help against account theft while having no direct effect on a fraudulent transfer performed by an already authenticated employee.

## Planned report contents

Scenario and target, narrative stages, warning signs, potential consequences, existing and proposed controls, both assessments, adjustment explanations, assumptions, model version, and report timestamp.

## Planned error handling

| Situation | Expected behavior |
| --- | --- |
| Unknown scenario or control | Explain the invalid selection and request correction |
| Missing required profile value | Identify the field that needs completion |
| Duplicate control | Count it once |
| Irrelevant defense | Explain why it does not change the assessment |
| Unwritable report path | Show a readable error and allow another destination |

## Future desktop interface

The GUI will offer the same workflow through scenario cards, a profile form, a result view, defense selection, and an export dialog. It will use the same service as the CLI. See [GUI handoff](GUI_HANDOFF.md).
