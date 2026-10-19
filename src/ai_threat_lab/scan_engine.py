"""One-target scan orchestration over existing collectors; no automatic model calls."""

import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .assessment import AssessmentResult, identify_target
from .audit_report import merge_reports, render_html
from .dependencies import inventory
from .dependency_paths import linked
from .models import ValidationError
from .providers import ProviderError
from .remote_audit import GithubSnapshot
from .scan_bundle import (
    compare_bundles,
    document,
    encoded,
    publish_bundle,
    read_bundle,
    scope_digest,
)


@dataclass(frozen=True)
class ScanOptions:
    target: str
    network: bool = False
    allowed_hosts: tuple[str, ...] = ()
    max_files: int = 50
    dkim_selector: str | None = None
    share_packages: bool = False
    max_pages: int = 10
    advisory_cache: Path | None = None
    recursive_dependencies: bool = False

    def __post_init__(self):
        kind = identify_target(self.target)
        if any(
            type(v) is not bool
            for v in (self.network, self.share_packages, self.recursive_dependencies)
        ):
            raise ValidationError("Network, sharing and recursive settings must be booleans")
        if (
            type(self.max_files) is not int
            or not 1 <= self.max_files <= 100
            or type(self.max_pages) is not int
            or not 1 <= self.max_pages <= 20
        ):
            raise ValidationError("Invalid scan file/page limit")
        if not isinstance(self.allowed_hosts, (tuple, list)) or any(
            not isinstance(h, str) or not h.strip() or h != h.strip() or "*" in h
            for h in self.allowed_hosts
        ):
            raise ValidationError("Approved hosts must be explicit exact names")
        object.__setattr__(
            self, "allowed_hosts", tuple(sorted(set(h.lower() for h in self.allowed_hosts)))
        )
        if kind in ("local_project", "python_source", "program_file", "mail_message"):
            if linked(Path(self.target)):
                raise ValidationError("Scan root must not be a symlink/junction")
            object.__setattr__(self, "target", str(Path(self.target).resolve()))
        else:
            expected = {
                "website": urlsplit(self.target).hostname,
                "github_repository": "github.com",
                "mail_domain": self.target.removeprefix("mail-domain:").lower(),
                "mailbox_account": "gmail.googleapis.com",
            }[kind]
            if not self.network or expected not in self.allowed_hosts:
                raise ValidationError(
                    "Remote scan requires --network and exact --allow-host approval"
                )
            if kind == "website" and (
                urlsplit(self.target).scheme != "https"
                or urlsplit(self.target).fragment
                or urlsplit(self.target).port not in (None, 443)
            ):
                raise ValidationError("Website scans require HTTPS without a fragment")
        if self.dkim_selector is not None and (
            kind != "mail_domain"
            or not isinstance(self.dkim_selector, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", self.dkim_selector)
        ):
            raise ValidationError("DKIM selector applies only to a mail-domain target")
        if self.share_packages and (
            not self.network or kind not in ("local_project", "github_repository")
        ):
            raise ValidationError("OSV sharing requires a local/GitHub project and --network")
        if self.recursive_dependencies and kind not in ("local_project", "github_repository"):
            raise ValidationError("Recursive dependency discovery requires a local/GitHub project")
        if self.advisory_cache is not None and not self.share_packages:
            raise ValidationError("Advisory cache requires explicit package sharing")

    def scope(self):
        return {
            "target": self.target,
            "target_kind": identify_target(self.target),
            "engine": "read-only-pipeline-17",
            "network": self.network,
            "allowed_hosts": list(self.allowed_hosts),
            "max_files": self.max_files,
            "dkim_selector": self.dkim_selector,
            "share_packages": self.share_packages,
            "max_pages": self.max_pages,
            "advisory_cache": self.advisory_cache is not None,
            "recursive_dependencies": self.recursive_dependencies,
        }


class ScanService:
    def __init__(self, assessor, *, inventory_loader=inventory, advisory_lookup=None, clock=None):
        self.assessor, self.inventory_loader, self.advisory_lookup = (
            assessor,
            inventory_loader,
            advisory_lookup,
        )
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(self, options: ScanOptions, output: Path, *, baseline: Path | None = None):
        output = Path(output)
        if output.exists() or output.is_symlink():
            raise FileExistsError("Scan output directory already exists; select a new path")
        if baseline is not None and output.resolve().is_relative_to(Path(baseline).resolve()):
            raise ValidationError("Output must not be inside the baseline bundle")
        if options.advisory_cache is not None:
            cache = Path(options.advisory_cache).resolve()
            if cache.is_relative_to(output.resolve()) or (
                baseline is not None and cache.is_relative_to(Path(baseline).resolve())
            ):
                raise ValidationError("Advisory cache must stay outside scan bundles")
        previous = read_bundle(baseline) if baseline is not None else None
        scope = options.scope()
        if previous is not None and previous["manifest"]["scope"]["target"] != scope["target"]:
            raise ValidationError("Baseline target differs; select a scan of the same target")
        artifacts = {}
        modules = {
            key: {"status": "not_applicable", "notice": "Not applicable to this target type."}
            for key in ("target_assessment", "dependency_inventory", "dependency_advisories")
        }
        failures = []
        snapshot = None
        try:
            result = self.assessor(options)
            if isinstance(result, GithubSnapshot):
                snapshot, result = result, result.assessment
            if (
                not isinstance(result, AssessmentResult)
                or result.target != options.target
                or result.target_kind != scope["target_kind"]
            ):
                raise ProviderError("Invalid target assessment result")
            if result.status == "not_configured":
                raise ProviderError("Target collector is unavailable")
            modules["target_assessment"] = {
                "status": "partial",
                "notice": "Selected collector returned partial evidence.",
            }
        except Exception:
            failures.append("target_assessment")
            modules["target_assessment"] = {
                "status": "failed",
                "notice": "Target collector failed; no security conclusion is available.",
            }
            result = AssessmentResult(
                options.target,
                scope["target_kind"],
                "not_configured",
                (),
                ("Target collector failed; no security conclusion is available.",),
            )
        documents = [document(encoded(asdict(result)))]
        artifacts["assessment.json"] = encoded(documents[0])
        if scope["target_kind"] in ("local_project", "github_repository"):
            dependency_result = None
            try:
                if scope["target_kind"] == "github_repository":
                    if snapshot is None or "target_assessment" in failures:
                        raise ProviderError("Pinned repository snapshot unavailable")
                    if snapshot.recursive_dependencies != options.recursive_dependencies:
                        raise ProviderError("Repository dependency coverage does not match scope")
                    collected = snapshot.inventory()
                else:
                    collected = self.inventory_loader(
                        Path(options.target),
                        **({"recursive": True} if options.recursive_dependencies else {}),
                    )
                artifacts["dependency-inventory.json"] = encoded(collected.document())
                modules["dependency_inventory"] = {
                    "status": "collected" if collected.packages else "empty_inventory",
                    "notice": "Selected recursive supported manifests; exact versions only."
                    if options.recursive_dependencies
                    else "Root-directory supported manifests and exact versions only.",
                }
            except Exception:
                collected = None
                failures.append("dependency_inventory")
                modules["dependency_inventory"] = {
                    "status": "failed",
                    "notice": "Dependency inventory failed; versions were not established.",
                }
            if options.share_packages and collected is not None and collected.packages:
                try:
                    if self.advisory_lookup is None:
                        raise ProviderError("No advisory lookup is configured")
                    dependency_result = document(encoded(self.advisory_lookup(collected, options)))
                    # Validate the returned result through the common assessment contract.
                    merge_reports([dependency_result])
                    if (
                        dependency_result["target"] != options.target
                        or dependency_result["target_kind"] != "dependency_manifest"
                    ):
                        raise ProviderError("Invalid advisory result scope")
                    modules["dependency_advisories"] = {
                        "status": "partial",
                        "notice": "OSV returned version matches; applicability remains unverified.",
                    }
                except Exception:
                    dependency_result = None
                    failures.append("dependency_advisories")
                    modules["dependency_advisories"] = {
                        "status": "failed",
                        "notice": "OSV lookup failed; do not interpret missing findings "
                        "as no vulnerabilities.",
                    }
            else:
                modules["dependency_advisories"] = {
                    "status": "not_requested",
                    "notice": "No OSV query: package sharing was not enabled or "
                    "no exact package inventory is available.",
                }
            if dependency_result is None:
                dependency_result = asdict(
                    AssessmentResult(
                        options.target,
                        "dependency_manifest",
                        "not_configured",
                        (),
                        tuple(
                            [
                                modules["dependency_advisories"]["notice"],
                                modules["dependency_inventory"]["notice"],
                                *(collected.not_checked if collected is not None else ()),
                            ]
                        ),
                    )
                )
            dependency_result = document(encoded(dependency_result))
            documents.append(dependency_result)
            artifacts["dependencies.json"] = encoded(dependency_result)
        report = merge_reports(documents)
        artifacts.update(
            {
                "report.json": encoded(report),
                "report.html": render_html(report).encode(),
                "modules.json": encoded(modules),
            }
        )
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValidationError("Scan time must be timezone-aware")
        metadata = {
            "run_id": uuid.uuid4().hex,
            "created_at": now.astimezone(timezone.utc).isoformat(),
            "scope": scope,
            "scope_digest": scope_digest(scope),
        }
        comparison = None
        if previous is not None:
            current = {
                "manifest": metadata,
                "documents": {"report.json": report, "modules.json": modules},
            }
            comparison = compare_bundles(previous, current)
            artifacts["comparison.json"] = encoded(comparison)
        manifest = publish_bundle(output, artifacts, metadata)
        return {
            "run_id": manifest["run_id"],
            "output_directory": str(output.resolve()),
            "status": "partial_with_module_failures" if failures else "partial",
            "failed_modules": failures,
            "unique_findings": report["summary"]["unique_findings"],
            "modules": modules,
            "ai_calls": 0,
            "comparison": {key: comparison[key] for key in ("comparable", "reason", "counts")}
            if comparison is not None
            else None,
            "notice": "Only selected read-only checks ran. Unchecked areas and "
            "errors remain in the bundle.",
        }
