"""Local configuration preflight; no credential inspection or remote health claims."""

from dataclasses import asdict

from .ai_costs import AIConfig
from .contracts import read_document
from .installation import installation_report
from .setup_profiles import integration_profiles


def setup_check(path=None, *, smtp_path=None, speech_path=None):
    installation = installation_report()
    config = AIConfig.from_document(read_document(path)) if path is not None else None
    placeholder = bool(config and any(
        token in config.model.lower() for token in ("replace_", "fixture", "example-model")
    ))
    remaining = []
    if config is None:
        remaining.append("Choose an available model and supply its current input/output rates.")
    elif placeholder:
        remaining.append("Replace the example model before requesting a live interpretation.")
    remaining.extend([
        "Verify the configured prices against your provider account; examples are synthetic.",
        "Configure the account credential outside source control when ready for live tests.",
        "For ai-review, choose a model supporting Responses structured JSON outputs.",
        "Run a small consented test and verify permissions, output quality and billing.",
    ])
    return {
        "schema_version": 1, "mode": "local_setup_check",
        "status": "installation_inconsistent" if installation["status"] != "ready"
                  else "configuration_needed" if config is None or placeholder
                  else "local_configuration_valid",
        "installation": installation, "ai_config": asdict(config) if config else None,
        "integrations": integration_profiles(smtp_path=smtp_path, speech_path=speech_path),
        "network_called": False, "credentials_inspected": False,
        "live_ready": False, "remaining_live_checks": remaining,
        "notice": "Configuration validation is not account, model, price or service validation. "
                  "Prepared local assessments, summaries and training do not need an AI key.",
    }
