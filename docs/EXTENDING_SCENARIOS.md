# Extending the offline scenario catalog

The project supports three complementary modules:

| Module | Implemented examples | Runtime behavior |
| --- | --- | --- |
| Social engineering | AI phishing, voice and video deepfake | Fictional narrative and risk model |
| Authentication threats | Brute force, credential stuffing | Fictional narrative and control comparison |
| Code security | Insecure generated code; separate Python AST reviewer | Narrative plus optional local pattern checks |

## Add a scenario

1. Add an object to `src/ai_threat_lab/data/catalog.json`, retaining schema_version 1.
2. Give it a unique stable ID, title, description, default_role, starting likelihood/impact, and rationale.
3. Supply stages (title, narrative, warning_sign, intervention), consequences and applicable control rules.
4. Reuse existing control IDs or add new documented controls to the controls array.
5. Every rule specifies control_id, group, likelihood_reduction, impact_reduction and rationale. Reductions must be integers from 0 to 2.
6. Use the same group for overlapping controls. The engine takes the maximum per group/dimension and caps the total reduction at 2.
7. Add a scenario-specific test and an end-to-end CLI case, then update the scenario table and user guide.

The CLI and future GUI discover catalog entries through `list_scenarios()`; no scenario-specific UI branches are needed. The analyzer validates unknown IDs and malformed entries before analysis.

## Distinguish the AI contribution

AI may assist text generation, prioritization or code review, but does not inherently bypass authentication, defeat sound cryptography, or prove exploitability. Describe what AI contributes and what assumptions still govern the attack outcome.

Brute force describes guessing unknown passwords. Credential stuffing describes trying credentials already exposed elsewhere. Their controls overlap, but password reuse is central to the second scenario.

## Future backlog

Possible additions: unsafe SQL construction, path traversal, exposed secrets, dependency provenance, and prompt injection. Each needs its own validated educational scope and tests. They are not currently implemented detections. The local reviewer is Python-only and does not query vulnerability feeds.

## Future AI integration boundary

For now every module is offline. No SDK, provider token, API key, OAuth login, placeholder network client or subscription-dependent fallback is configured. If AI is added later, introduce a separate optional adapter consuming explicit requests and returning structured results. Keep the current deterministic engine and local reviewer usable without that adapter.

Before integration, agree the supported access method, account entitlement, budget, which source data may leave the machine, and how outputs will be checked. Provider output must not automatically replace established risk rules or label vulnerabilities as validated.
