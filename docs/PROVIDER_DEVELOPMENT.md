# Adding a concrete provider

The core and CLI can now use explicitly registered content, assessment and transport adapters. The bundled providers remain offline. Configuration names do not load Python packages, execute import paths, read credentials or create remote sessions.

## Registry and JSON configuration

```bash
python -m ai_threat_lab providers
python -m ai_threat_lab --config examples/providers.json doctor
```

Configuration schema:

```json
{
  "schema_version": 1,
  "content": "template",
  "assessment": {}
}
```

`assessment` maps target kinds to names of registered adapters. Unknown keys, including credential fields, are rejected. A selected but unregistered provider makes `doctor` report `missing_provider` with exit code 3. `ready_offline` means only that registrations exist; it does not validate credentials or remote health.

## Concrete adapter responsibilities

| Family | Implement | Register |
| --- | --- | --- |
| Content | prepare(scenario, approved_facts, identity_reference) → TrainingContent | register_content(name, instance) |
| Target assessment | assess(target) → AssessmentResult | register_target(kind, name, instance) |
| Training delivery | channel and deliver(plan, recipient) → DeliveryReceipt | register_transport(channel, name, instance) |

A target result must match the exact requested target and kind. A content provider must return structured TrainingContent. A transport receipt must match the recipient. Wrappers convert malformed output and integration exceptions into a redacted ProviderError, without retrying. Host applications must avoid logging underlying SDK secrets or source data. Provider cancellation (KeyboardInterrupt) remains a cancellation, not a retry.

A registered training transport is usable through the application API only. `campaign-simulate` always selects DemoTransport and cannot turn a configuration file into live dispatch. That command is suitable for exercising the complete file workflow before implementing a live UI/integration.

## Offline adapter example

```python
from ai_threat_lab.assessment import AssessmentFinding, AssessmentResult
from ai_threat_lab.providers import ProviderRegistry, ProviderConfig

class FixtureWebAdapter:
    def assess(self, target):
        return AssessmentResult(
            target, "website", "partial",
            (AssessmentFinding("fixture", "candidate", "Synthetic observation", "Review fixture"),),
            ("No HTTP request performed",),
        )

registry = ProviderRegistry()
registry.register_target("website", "fixture", FixtureWebAdapter())
service = registry.assessment_service(ProviderConfig(assessment=(("website", "fixture"),)))
result = service.assess("https://example.invalid")
assert result.status == "partial"
```

For a trusted application entrypoint, call `cli.main(arguments, registry=registry)`. The future GUI can call the same service or registry. Actual SDK/authentication/network logic belongs in the concrete adapter; it is not implemented by a provider name or API key alone.

## Saved campaign artifacts

Schemas are implemented in `contracts.py` with strict field/type/version checks. Files are capped at 1 MiB. Duplicate keys and non-finite values are rejected. The plan digest covers exact content, recipients, approved facts, identity and scope. These digests detect changes relative to an approval; they are not digital signatures and do not establish organizational authorization.

`workflows.py` exposes example_request, prepare_campaign, approve_campaign and simulate_campaign for both CLI and GUI callers. Timestamps require timezones. Output files are created exclusively. An existing output is rejected before simulated dispatch or ledger creation.

## Integration checklist

Use the fake-provider and CLI tests as contract examples, then add controlled integration tests for the selected SDK. Remote web/repository/mailbox adapters need real bounded retrieval/audit implementations. Mail, telephony and media need their own providers. Do not infer that all integrations exist because the common orchestration passes tests.
