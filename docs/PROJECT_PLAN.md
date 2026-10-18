# Product plan

## Goal

A console application accepts a target (repository URL, website, local project/program, exported mail, mailbox account or mail domain), routes it to relevant checks, and returns evidence, possible consequences, confidence/limitations and remediation priorities. Separate authorized training modules cover email, voice and video social engineering.

## Current delivery

- Shared immutable Python models and CLI adapters.
- Local Python AST review, project scanning limits and exported `.eml` observations.
- Target recognition with explicit not-configured results for missing remote/binary integrations.
- Six explanatory risk scenarios and control comparisons.
- Three prepared training scenarios: email, voice, video.
- Preview/approval digest, recipient scope/expiry checks, transport contracts, cancellation and delivery ledgers.
- Offline simulated dispatch and event aggregation.
- Tests, build packaging, CI and integration documentation.

## Read-only integrations delivered in 0.4.0

- Concrete pinned-commit GitHub source collector, passive HTTPS header audit and basic DNS mail-policy observations.
- Authenticated Gmail owner/settings collector, with external OAuth consent/refresh and required scopes.
- Additional local secret/manifest inventory and program metadata.
- Concrete OpenAI Responses explanations with evidence opt-in, optional TTL caching, persistent budgets and no automatic retries.
- Deterministic HTTP fixtures and real CLI subprocess tests; no paid/live account validation.

## Next implementation order

1. Validate the existing read-only integrations against controlled resources and actual provider grants.
2. Select a real AI model, verify prices/access and test explanation quality and billing controls.
3. Expand source/dependency rules and validate candidates with appropriate specialist tools.
4. Define a separate, approved training deployment before selecting mail/telephony/media services; it requires more than a model key.
5. Add trusted event collection, delivery/provider controls and retention policies if live training enters scope.
6. Connect GUI to the same services.

Current collectors perform partial read-only checks. Active exploitation, credential attacks, live communications, generated audio/video and a production telemetry backend are absent. Existing narrative scores remain teaching models, not real scan conclusions. See LIVE_SETUP.md for precise limits.

## Open product choices

Interface language, submission deadline, GUI ownership, report/PDF priority, first provider, and permitted live test environments remain to be agreed. Offline work does not require an API or credential setup.

## Additional delivery in 0.5.0

Pinned dependency inventory and opt-in OSV advisory/version matching are implemented without model calls. Combined JSON/HTML reports preserve findings, source provenance and gaps, with an explicit human-triage order. Live API/media/campaign limits above remain; dependency matches do not establish exploitability. See DEPENDENCIES_AND_REPORTS.md.

## Additional delivery in 0.6.0

Approved local text rehearsals now run from CLI with durable sessions, structured choices, bounded voice policy, expiry/stop/revocation and JSON/HTML reports. They prepare and test practice flows without model calls. They do not observe real email/call behavior, prove identity verification or implement any live communication/media service.
