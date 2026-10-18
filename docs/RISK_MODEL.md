# Risk model — educational-1.0

## Ratings

Likelihood is an ordinal scenario judgment: 1 = strong barriers; 2 = several barriers; 3 = mixed conditions; 4 = few effective barriers; 5 = highly favorable conditions in the fictional scenario.

Impact is an ordinal consequence judgment: 1 = limited inconvenience; 2 = limited local harm; 3 = material departmental harm; 4 = substantial organizational harm; 5 = severe organizational consequences.

Implemented starting ratings are phishing 4/4, voice deepfake 4/5, and video deepfake 3/4. Low/normal/high urgency adjusts likelihood by -1/0/+1; low/medium/high access adjusts impact by -1/0/+1. Clamp to 1–5 before applying controls. Organization and role are descriptive only. These provisional rules need team review and are teaching aids rather than empirical frequency estimates.

Score = likelihood × impact. Labels: 1–4 Low, 5–9 Moderate, 10–14 High, 15–19 Very high, 20–25 Critical. Some integers within these bands are not reachable by multiplication of two integer ratings.

## Control application

Record existing defenses first, then evaluate proposed additions. Deduplicate controls and reject unknown IDs. Explain irrelevant controls without lowering the score. For each control group and dimension, take the maximum reduction; sum groups with a cap of 2 per dimension. Subtract from the profile-adjusted starting rating with a floor of 1. Related identity-verification controls do not stack. Catalog rules declare reductions of 0–2 and include rationales. Ratings remain between 1 and 5.

Authentication controls apply to account compromise paths. They do not automatically prevent a payment approved by a deceived but legitimately authenticated employee. Payment verification and approval workflows address that scenario directly.

## Illustrative worked example

A fictional voice-deepfake payment scenario starts at likelihood 4 and impact 5: score 20, Critical. The implemented illustrative rule for verified callback plus independent approval changes likelihood to 2 and leaves impact at 5: score 10, High. An enforced transaction cap may change impact separately if the scenario supports that assumption.

This example is an implemented provisional educational rule, not a validated estimate of control effectiveness. Residual risk never means guaranteed protection.

## Reporting limitations

Include rating rationales, selected controls, assumptions, and model version in every report. Avoid percentage claims about defense effectiveness and predicted monetary losses. Any fictional amount must be clearly marked as user-provided. Ordinal score reductions are not percentage reductions in real-world risk.
