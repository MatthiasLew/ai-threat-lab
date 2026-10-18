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

## Next implementation order

1. Agree the first remote target module and implement its bounded, scope-aware adapter.
2. Implement GitHub retrieval and reuse local review on selected source files, or implement a passive HTTP/TLS adapter first if web assessment is prioritized.
3. Integrate a chosen mailbox/DNS provider for evidence-backed mail checks.
4. Add optional AI for structured interpretation/preview generation after access, budget and data-sharing choices.
5. Add selected mail/telephony/media transports in a controlled environment with authenticated approvals, idempotency, stop handling and trusted event ingestion.
6. Connect GUI to the same services and prepare the class demonstration.

Only steps implemented in the current-delivery list are available. Live remote assessment, active testing, actual communications and media generation are not provided by the current CLI. Existing narrative scores are teaching models, not real scan conclusions.

## Open product choices

Interface language, submission deadline, GUI ownership, report/PDF priority, first provider, and permitted live test environments remain to be agreed. Offline work does not require an API or credential setup.
