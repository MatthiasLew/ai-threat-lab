# Scenario catalog

| ID | Target | Objective described by the simulation | Consequences | Relevant defenses |
| --- | --- | --- | --- | --- |
| ai_phishing | Fictional employee | Obtain account access through a misleading message | Data exposure and account misuse | Message filtering, reporting, phishing-resistant authentication |
| voice_deepfake | Fictional accounting employee | Request an unauthorized payment using a supposed executive voice | Financial loss and business disruption | Callback to a known number, independent approval, transaction limits |
| video_deepfake | Fictional employee or communications team | Use a fabricated video to influence a decision | Disclosure or reputational harm | Independent source verification, another trusted channel, approval workflow |

## Packaged data for each scenario

Stable ID, title, description, fictional target defaults, stages, warning signs, consequences, baseline rating rationale, applicable control IDs, assumptions, and schema version. See `src/ai_threat_lab/data/catalog.json` for the implemented values.

## Campaign stages

Explain context gathering, synthetic-content preparation, fictional delivery, persuasion, potential impact, and defensive intervention. These are narrative stages only; the application performs no real delivery or content impersonation.

## Optional extensions

Fake profiles and coordinated disinformation may be added after the three MVP scenarios. Media detection is a separate possible research task and is not part of the planned risk engine.

## Authentication and code-security extensions

| ID | Target | AI contribution described | Relevant defenses |
| --- | --- | --- | --- |
| brute_force | Fictional application account | Potential prioritization of password guesses; no actual attempts | Rate limiting, progressive lockout, strong authentication, password quality |
| credential_stuffing | Fictional customer account | Potential organization of previously exposed credentials; no credential lists loaded | Unique passwords, strong authentication, attempt controls |
| insecure_generated_code | Fictional application developer | Generated suggestions may contain unsafe constructs or unverified assumptions | Human review, relevant static checks, dependency review, least privilege |

All six scenarios are packaged in JSON and discovered through the same service. A separate `review-code` command checks selected Python AST patterns; it does not compute scenario risk from findings. See CODE_REVIEW.md and EXTENDING_SCENARIOS.md.
