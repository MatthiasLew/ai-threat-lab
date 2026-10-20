"""Stable Python API contract for future GUI integration without parsing CLI text.

Provides structured functions and typed exceptions (`ValidationError`, `ProviderError`,
`FileExistsError`, `OSError`) so a desktop/web GUI can discover analyzers, inspect
capabilities and limitations, configure and run audits, check run status, retrieve
detailed findings and reports (in English or Polish), browse history, and prepare
minimized AI evidence packets without rewriting the audit engine.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from .ai_costs import AIConfig
from .ai_review import attach_ai_interpretation, build_multilingual_ai_packet
from .audit_report import render_html
from .evidence import brief, load_evidence
from .finding_details import (
    SUPPORTED_LANGUAGES,
    DetailedFinding,
    describe_finding,
    detailed_findings,
    validate_report_language,
)
from .local_history import MAX_EXPORT_BYTES, history_list, load_saved_run, write_new_report
from .local_history import export_report as export_saved_report
from .models import ValidationError
from .readiness import readiness
from .sarif import SCHEMA_URI as SARIF_SCHEMA_URI
from .scan_bundle import encoded
from .scan_cli import advisory_lookup, assessor
from .scan_engine import ScanOptions, ScanService
from .tool_plan import TOOLS, plan_target

REMOTE_TARGET_KINDS = frozenset(("github_repository", "website", "mail_domain", "mailbox_account"))


def list_analyzers() -> list[dict]:
    """Return the deterministic catalog of available target and auxiliary analyzers."""
    items = []
    for target_kind, (tool_id, purpose, limitation) in TOOLS.items():
        items.append(
            {
                "id": tool_id,
                "target_kind": target_kind,
                "purpose": purpose,
                "limitations": limitation,
                "requires_network_opt_in": target_kind in REMOTE_TARGET_KINDS,
            }
        )
    items.extend(
        [
            {
                "id": "mail_attachment_structures",
                "target_kind": "mail_message",
                "purpose": "Decoded attachment size/hash and selected PE/ELF/ZIP structures",
                "limitations": (
                    "First 20 discovered attachments within byte/part bounds; "
                    "no extraction, execution, signature trust or malware detection."
                ),
                "requires_network_opt_in": False,
            },
            {
                "id": "dependency_inventory",
                "target_kind": "local_project",
                "purpose": "Exact versions in supported root/opt-in nested manifests",
                "limitations": "No package installation, resolution or reachability analysis.",
                "requires_network_opt_in": False,
            },
            {
                "id": "osv_advisories",
                "target_kind": "local_project",
                "purpose": "Known package/version advisories via OSV",
                "limitations": "Version matches do not establish exploitability.",
                "requires_network_opt_in": True,
            },
            {
                "id": "verified_report_bundle",
                "target_kind": "all",
                "purpose": "Preserve evidence, module failures, limitations and readable reports",
                "limitations": "Local integrity is not authenticity or proof of security.",
                "requires_network_opt_in": False,
            },
        ]
    )
    return items


def get_capabilities() -> dict:
    """Return static capability and limitation inventory without probing accounts or network."""
    caps = dict(readiness())
    caps["supported_languages"] = list(SUPPORTED_LANGUAGES)
    caps["export_formats"] = ["json", "html", "sarif"]
    return caps


def create_audit_options(
    target: str | Path = ".",
    *,
    network: bool = False,
    allowed_hosts: tuple[str, ...] | list[str] = (),
    max_files: int = 50,
    dkim_selector: str | None = None,
    share_packages: bool = False,
    max_pages: int = 10,
    advisory_cache: Path | str | None = None,
    recursive_dependencies: bool = False,
    language: str = "en",
) -> ScanOptions:
    """Validate and construct immutable ScanOptions for a target audit."""
    validate_report_language(language)
    cache_path = Path(advisory_cache) if advisory_cache is not None else None
    return ScanOptions(
        target=str(target),
        network=network,
        allowed_hosts=tuple(allowed_hosts),
        max_files=max_files,
        dkim_selector=dkim_selector,
        share_packages=share_packages,
        max_pages=max_pages,
        advisory_cache=cache_path,
        recursive_dependencies=recursive_dependencies,
    )


def plan_audit(
    target: str | Path,
    *,
    network: bool = False,
    allowed_hosts: tuple[str, ...] | list[str] = (),
    max_files: int = 50,
    recursive_dependencies: bool = False,
    share_packages: bool = False,
    dkim_selector: str | None = None,
    max_pages: int = 10,
    language: str = "en",
) -> dict:
    """Preview prepared analyzers, scope, and disclosures for a target without running checks."""
    validate_report_language(language)
    plan = plan_target(
        str(target),
        network=network,
        allowed_hosts=tuple(allowed_hosts),
        max_files=max_files,
        recursive_dependencies=recursive_dependencies,
        share_packages=share_packages,
        dkim_selector=dkim_selector,
        max_pages=max_pages,
    )
    plan["report_language"] = language
    return plan


def run_audit(
    target_or_options: ScanOptions | str | Path,
    output_dir: Path | str,
    *,
    options: ScanOptions | None = None,
    language: str = "en",
    baseline: Path | str | None = None,
    service: ScanService | None = None,
) -> dict:
    """Execute a scoped audit and publish a verified report bundle."""
    validate_report_language(language)
    if isinstance(target_or_options, ScanOptions):
        resolved_options = target_or_options
    elif isinstance(target_or_options, (str, Path)):
        if options is not None:
            if not isinstance(options, ScanOptions):
                raise ValidationError("options must be a ScanOptions instance")
            resolved_options = replace(options, target=str(target_or_options))
        else:
            resolved_options = create_audit_options(target_or_options, language=language)
    else:
        raise ValidationError("run_audit requires a target path/URI or a ScanOptions instance")
    engine = service or ScanService(assessor, advisory_lookup=advisory_lookup)
    baseline_path = Path(baseline) if baseline is not None else None
    result = engine.run(resolved_options, Path(output_dir), baseline=baseline_path)
    result["report_language"] = language
    return result


def get_audit_status(run_dir: Path | str) -> dict:
    """Read and verify the execution status of a saved scan or batch directory."""
    saved = load_saved_run(Path(run_dir))
    report = saved["report"]
    failed = saved["failed_components"]
    status_value = "partial_with_module_failures" if failed else report["status"]
    return {
        "schema_version": 1,
        "kind": saved["kind"],
        "run_id": saved["run_id"],
        "created_at": saved["created_at"],
        "status": status_value,
        "state": status_value,
        "integrity_verified": True,
        "target_count": saved["target_count"],
        "failed_components": failed,
        "unique_findings": report["summary"]["unique_findings"],
        "triage_counts": dict(report["summary"]["triage_counts"]),
        "comparison": saved["comparison"],
        "not_checked_count": len(report["not_checked"]),
    }


def get_audit_results(
    run_or_report: Path | str,
    *,
    language: str = "en",
) -> dict:
    """Load verified audit results, detailed findings, and formatted offline reports."""
    validate_report_language(language)
    loaded = load_evidence(Path(run_or_report))
    report = loaded["report"]
    details = [item.to_dict() for item in detailed_findings(report, language=language)]
    summary_text = brief(loaded, language=language)
    html_report = render_html(report, language=language)
    summary_dict = dict(report["summary"])
    summary_dict.setdefault("finding_count", summary_dict.get("unique_findings", len(details)))
    return {
        "schema_version": 1,
        "origin": loaded["origin"],
        "language": language,
        "failed_components": loaded["failed_components"],
        "report": report,
        "summary": summary_dict,
        "detailed_findings": details,
        "summary_text": summary_text,
        "brief_text": summary_text,
        "html_report": html_report,
        "html": html_report,
        "not_checked": report["not_checked"],
        "notice": report["notice"],
    }


def _render_report_sarif(report: dict, *, language: str = "en") -> str:
    details = detailed_findings(report, language=language)
    by_rule = {item.rule_code: item for item in details}
    rule_ids = sorted(by_rule)
    indexes = {rid: idx for idx, rid in enumerate(rule_ids)}
    rules = [
        {
            "id": rid,
            "shortDescription": {"text": by_rule[rid].title},
            "fullDescription": {"text": by_rule[rid].mechanism},
            "help": {"text": by_rule[rid].recommendation},
            "defaultConfiguration": {"level": "warning"},
        }
        for rid in rule_ids
    ]
    results = []
    for item in details:
        loc_uri = item.file_path or item.target
        phys: dict = {"artifactLocation": {"uri": loc_uri}}
        if item.line_number is not None:
            phys["region"] = {"startLine": item.line_number}
        results.append(
            {
                "ruleId": item.rule_code,
                "ruleIndex": indexes[item.rule_code],
                "level": "warning",
                "message": {
                    "text": f"{item.title}. {item.mechanism} Recommendation: {item.recommendation}"
                },
                "locations": [{"physicalLocation": phys}],
                "properties": {
                    "findingId": item.id,
                    "confirmationStatus": item.confirmation_status,
                    "triagePriority": item.triage_priority,
                    "threatCategory": item.threat_category,
                },
            }
        )
    payload = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AI Threat Lab", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def export_audit_report(
    run_dir: Path | str,
    output: Path | str | None = None,
    *,
    format: str = "json",
    language: str = "en",
) -> str:
    """Export a verified saved scan or batch report as JSON, SARIF, or localized HTML."""
    validate_report_language(language)
    root = Path(run_dir)
    target_out = Path(output) if output is not None else None
    if (
        target_out is not None
        and root.exists()
        and target_out.resolve().is_relative_to(root.resolve())
    ):
        raise ValidationError("Export must stay outside the saved run")
    if format == "sarif":
        saved = load_saved_run(root)
        raw = _render_report_sarif(saved["report"], language=language).encode("utf-8")
        if len(raw) > MAX_EXPORT_BYTES:
            raise ValidationError("Saved report export exceeds its 8 MiB byte limit")
        if target_out is not None:
            write_new_report(target_out, raw)
        return raw.decode("utf-8")
    if format == "html" and language != "en":
        saved = load_saved_run(root)
        raw = render_html(saved["report"], language=language).encode("utf-8")
        if len(raw) > MAX_EXPORT_BYTES:
            raise ValidationError("Saved report export exceeds its 8 MiB byte limit")
        if target_out is not None:
            write_new_report(target_out, raw)
        return raw.decode("utf-8")
    return export_saved_report(root, format=format, output=target_out)


def get_audit_history(history_root: Path | str) -> dict:
    """List and verify saved audit runs in a local history directory."""
    return history_list(Path(history_root))


def prepare_ai_packets(
    evidence_path: Path | str,
    config: AIConfig | None = None,
    *,
    language: str = "en",
    structured: bool = True,
    split: bool = True,
    packet_index: int | None = None,
    group_size: int = 3,
) -> dict:
    """Prepare minimized AI evidence packets and cost estimates without calling any API."""
    if config is None:
        config = AIConfig(
            model="offline-contract-v1",
            input_usd_per_million="0.50",
            output_usd_per_million="1.50",
        )
    elif not isinstance(config, AIConfig):
        raise ValidationError("prepare_ai_packets requires an AIConfig instance")
    from .workbench_cli import prepare_evidence

    return prepare_evidence(
        Path(evidence_path),
        config,
        structured=structured,
        split=split,
        packet_index=packet_index,
        group_size=group_size,
        language=language,
    )


__all__ = [
    "SUPPORTED_LANGUAGES",
    "DetailedFinding",
    "attach_ai_interpretation",
    "build_multilingual_ai_packet",
    "create_audit_options",
    "describe_finding",
    "detailed_findings",
    "encoded",
    "export_audit_report",
    "get_audit_history",
    "get_audit_results",
    "get_audit_status",
    "get_capabilities",
    "list_analyzers",
    "plan_audit",
    "prepare_ai_packets",
    "run_audit",
    "validate_report_language",
]
