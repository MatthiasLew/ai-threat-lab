"""Accept a saved Bandit report without invoking a scanner."""

from .local_history import write_new_report
from .models import ValidationError
from .sarif_review import import_sarif
from .scan_bundle import encoded
from .scanner_plan import SUPPORTED_VERSION, network_syntax


def save_bandit_report(source, output):
    """Validate and publish the supported SARIF projection exclusively."""
    if network_syntax(source) or network_syntax(output):
        raise ValidationError("Network and device paths are not supported for Bandit reports")
    report, failures = import_sarif(source)
    if failures or any(run["producer_succeeded"] is not True for run in report["runs"]):
        raise ValidationError("Bandit report does not describe a complete successful analysis")
    if any(
        (run["producer"] or "").casefold() != "bandit"
        or run["producer_version"] != SUPPORTED_VERSION
        for run in report["runs"]
    ):
        raise ValidationError("Expected a report declaring the supported Bandit version")
    if any(run["outside_page"] for run in report["runs"]):
        raise ValidationError("Bandit report exceeds the publication result limit")
    write_new_report(output, encoded(report))
    return report
