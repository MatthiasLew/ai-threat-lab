"""Validated saved evidence for human summaries and optional model interpretation.

No collectors, credentials or network are used here. A bare report is a saved
claim; a bundle additionally provides consistency checks, never authenticity.
"""

import hashlib
import json
from pathlib import Path

from .audit_report import merge_reports
from .contracts import fields
from .local_history import load_saved_run
from .models import ValidationError
from .report_io import read_regular, report_read_budget
from .scan_bundle import document

MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
CORE_FINDING = {"check", "status", "evidence", "recommendation"}


def validate_combined(value):
    """Rebuild all derived fields from validated source claims, including IDs/counts."""
    fields(value, {"schema_version", "status", "assessments", "summary", "findings",
                   "not_checked", "notice"})
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValidationError("Unsupported combined evidence version")
    rows = value["assessments"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 20:
        raise ValidationError("Combined evidence requires 1..20 assessments")
    if not isinstance(value["findings"], list) or len(value["findings"]) > 40000:
        raise ValidationError("Combined evidence finding limit exceeded")
    if not isinstance(value["not_checked"], list):
        raise ValidationError("Combined evidence limitations must be an array")
    sources = []
    for index, row in enumerate(rows, 1):
        fields(row, {"source", "target", "target_kind", "status", "finding_count"})
        if type(row["source"]) is not int or row["source"] != index:
            raise ValidationError("Invalid assessment source sequence")
        if type(row["finding_count"]) is not int or row["finding_count"] < 0:
            raise ValidationError("Invalid assessment finding count")
        sources.append({k: row[k] for k in ("target", "target_kind", "status")}
                       | {"findings": [], "not_checked": []})
    for finding in value["findings"]:
        fields(finding, CORE_FINDING | {"id", "target", "triage_priority", "sources"})
        refs = finding["sources"]
        if (not isinstance(refs, list) or not refs
                or any(type(i) is not int or not 1 <= i <= len(sources) for i in refs)
                or len(set(refs)) != len(refs)):
            raise ValidationError("Invalid finding source references")
        for ref in refs:
            if finding["target"] != sources[ref - 1]["target"]:
                raise ValidationError("Finding target does not match its source")
            if len(sources[ref - 1]["findings"]) >= 2000:
                raise ValidationError("At most 2000 findings per evidence source")
            sources[ref - 1]["findings"].append({k: finding[k] for k in CORE_FINDING})
    for limitation in value["not_checked"]:
        fields(limitation, {"source", "target", "notice"})
        ref = limitation["source"]
        if (type(ref) is not int or not 1 <= ref <= len(sources)
                or limitation["target"] != sources[ref - 1]["target"]):
            raise ValidationError("Invalid limitation source")
        sources[ref - 1]["not_checked"].append(limitation["notice"])
    rebuilt = merge_reports(sources)
    for original, derived in zip(rows, rebuilt["assessments"], strict=True):
        count = original["finding_count"]
        # Merging removes duplicate findings. Their original multiplicity is a
        # saved claim and cannot be reconstructed from the unique finding list.
        if not derived["finding_count"] <= count <= 2000 or (
            derived["finding_count"] == 0 and count != 0
        ):
            raise ValidationError("Inconsistent source finding count")
        derived["finding_count"] = count
    # Canonical JSON also distinguishes booleans from integer counts.
    if json.dumps(rebuilt, sort_keys=True) != json.dumps(value, sort_keys=True):
        raise ValidationError("Combined evidence has inconsistent derived fields")
    return rebuilt


def load_evidence(path):
    path = Path(path)
    if path.is_dir():
        with report_read_budget(128 * 1024 * 1024):
            saved = load_saved_run(path)
        return {"report": saved["report"], "origin": "verified_" + saved["kind"],
                "failed_components": saved["failed_components"],
                "ai_document": interpretation_evidence(saved["report"])}
    value = document(read_regular(path, MAX_EVIDENCE_BYTES))
    if "assessments" in value:
        report = validate_combined(value)
        origin = "unverified_combined_report"
    else:
        if not isinstance(value.get("findings"), list):
            raise ValidationError("Assessment document must contain a findings array")
        projection = {
            "target": value.get("target", "(target not supplied)"),
            "target_kind": value.get("target_kind", "unspecified"),
            "status": value.get("status", "partial"),
            "findings": value["findings"], "not_checked": value.get("not_checked", []),
        }
        report = merge_reports([projection])
        origin = "unverified_assessment"
    return {"report": report, "origin": origin, "failed_components": [],
            "ai_document": value if origin == "unverified_assessment"
            else interpretation_evidence(report)}


def interpretation_evidence(report):
    """Remove target fields, retain stable references and all limitations.

Evidence strings may still contain sensitive details. This is minimization,
not an anonymizer; the user must review the exact outgoing preview.
"""
    targets = list(dict.fromkeys(row["target"] for row in report["assessments"]))
    aliases = {target: f"T{index:03d}" for index, target in enumerate(targets, 1)}
    findings = []
    for row in report["findings"]:
        findings.append({k: row[k] for k in CORE_FINDING} | {
            "evidence_id": row["id"],
            "evidence": f'[{aliases[row["target"]]}] {row["evidence"]}',
        })
    limitations = list(dict.fromkeys(
        f'[{aliases[row["target"]]}] {row["notice"]}' for row in report["not_checked"]
    ))
    return {"target_kind": "saved_assessment_evidence", "status": "partial",
            "findings": findings, "not_checked": limitations}


def evidence_digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")).hexdigest()


def brief(value, *, language: str = "en"):
    from .finding_details import describe_finding, validate_report_language

    validate_report_language(language)
    pl = language == "pl"
    report = value["report"]
    header = (
        "AI Threat Lab — podsumowanie audytu offline"
        if pl
        else "AI Threat Lab — review summary"
    )
    lines = [
        header,
        "",
        f'Evidence: {value["origin"]}',
        f'Observations to review: {report["summary"]["unique_findings"]}',
        "Priorities order review; they do not prove severity or exploitability.",
        "",
    ]
    if value["failed_components"]:
        lines += ["Some collectors failed. Missing results are not a clean assessment.", ""]
    for row in report["findings"]:
        detail = describe_finding(row, target=row.get("target"), language=language)
        loc = detail.file_path or row["target"]
        if detail.line_number is not None:
            loc = f"{loc}:{detail.line_number}"
        lines += [
            f'{row["triage_priority"]} | {row["check"]} | {row["status"]} '
            f'({detail.threat_category})',
            f'Where: {row["target"]}',
            f"Location: {loc}",
            f'Observation: {row["evidence"]}',
            f'Co wykryto? (What was detected?): {detail.what_was_detected}',
            f"Dlaczego jest to potencjalnie niebezpieczne? (Why dangerous?): {detail.mechanism}",
            f"Do czego może doprowadzić? (Potential consequences?): {detail.consequences}",
            f'Jak to naprawić? / Review: {row["recommendation"]}',
        ]
        if detail.code_example:
            example_one_line = " | ".join(
                part.strip()
                for part in detail.code_example.splitlines()
                if part.strip() and not part.strip().startswith("#")
            )
            if example_one_line:
                lines.append(f"Example fix: {example_one_line}")
        lines += [
            f"Jak sprawdzić poprawkę? (Verification): {detail.verification_steps}",
            f"Czego analizator nie ustalił? (Limitations): {detail.analysis_limitations}",
            f'Reference: {row["id"]}',
            "",
        ]
    if not report["findings"]:
        lines += [
            "No observations were returned by the selected checks.",
            "This does not establish that the target is secure.",
            "",
        ]
    lines.append("Not checked / limitations:")
    lines.extend(f'- {row["target"]}: {row["notice"]}' for row in report["not_checked"])
    lines += ["", report["notice"], "No model or target was contacted to create this summary."]
    # Do not allow terminal control characters from saved evidence to affect the terminal.
    text = "\n".join(lines) + "\n"
    return "".join(
        c if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) <= 159) else f"\\u{ord(c):04x}"
        for c in text
    )
