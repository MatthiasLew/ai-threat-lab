"""Local installation diagnostics without environment, credentials or network access."""

import json
import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from importlib.resources import files

from ._version import __version__


def installation_report() -> dict:
    try:
        distribution = version("ai-threat-lab")
    except PackageNotFoundError:
        distribution = None
    catalog_ok = False
    try:
        with files("ai_threat_lab").joinpath("data/catalog.json").open("rb") as resource:
            raw = resource.read(1024 * 1024 + 1)
        if len(raw) <= 1024 * 1024:
            document = json.loads(raw)
            catalog_ok = (
                isinstance(document, dict)
                and isinstance(document.get("scenarios"), list)
                and bool(document["scenarios"])
                and isinstance(document.get("controls"), list)
                and bool(document["controls"])
            )
    except (OSError, ValueError, RecursionError):
        pass
    checks = {
        "python_supported": sys.version_info >= (3, 12),
        "version_consistent": distribution in (None, __version__),
        "bundled_catalog": catalog_ok,
    }
    return {
        "schema_version": 1,
        "status": "ready" if all(checks.values()) else "inconsistent_installation",
        "runtime_version": __version__,
        "distribution_version": distribution,
        "mode": "source_checkout" if distribution is None else "installed_distribution",
        "python_version": platform.python_version(),
        "checks": checks,
        "network_checked": False,
        "credentials_checked": False,
        "notice": "Local packaging checks only; provider availability is checked separately.",
    }
