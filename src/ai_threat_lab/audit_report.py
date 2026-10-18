"""Merge structured partial assessments into deterministic, escaped remediation reports."""

import hashlib
import html
import json
from dataclasses import asdict

from .assessment import AssessmentFinding, AssessmentResult
from .contracts import fields
from .models import ValidationError

# Triage order only. This deliberately does not infer CVSS or exploitability.
PRIORITIES = {
    "possible_secret": "P1",
    "known_dependency_advisory": "P2",
    "PY001": "P2",
    "PY002": "P2",
    "PY003": "P2",
    "PY004": "P2",
    **{f"PY00{number}": "P2" for number in range(5, 10)},
    "mailbox_auto_forwarding": "P2",
    "mailbox_filter_forwarding": "P2",
}


def merge_reports(documents: list[dict]) -> dict:
    if not 1 <= len(documents) <= 20:
        raise ValidationError("Merge between 1 and 20 assessment reports")
    results, findings, limits = [], {}, []
    for index, document in enumerate(documents, 1):
        fields(
            document,
            {"target", "target_kind", "status", "findings", "not_checked"},
            {"dependency_audit"},
        )
        if not isinstance(document["findings"], list):
            raise ValidationError("Report findings must be an array")
        if len(document["findings"]) > 2000:
            raise ValidationError("At most 2000 findings per assessment report")
        parsed = []
        for item in document["findings"]:
            fields(item, {"check", "status", "evidence", "recommendation"})
            parsed.append(AssessmentFinding(**item))
        result = AssessmentResult(
            document["target"],
            document["target_kind"],
            document["status"],
            tuple(parsed),
            document["not_checked"],
        )
        results.append(
            {
                "source": index,
                "target": result.target,
                "target_kind": result.target_kind,
                "status": result.status,
                "finding_count": len(result.findings),
            }
        )
        limits.extend(
            {"source": index, "target": result.target, "notice": value}
            for value in result.not_checked
        )
        for item in result.findings:
            value = asdict(item)
            canonical = json.dumps({"target": result.target, **value}, sort_keys=True)
            identifier = hashlib.sha256(canonical.encode()).hexdigest()
            if identifier not in findings:
                findings[identifier] = {
                    "id": identifier,
                    "target": result.target,
                    **value,
                    "triage_priority": PRIORITIES.get(item.check, "P3"),
                    "sources": [],
                }
            if index not in findings[identifier]["sources"]:
                findings[identifier]["sources"].append(index)
    ordered = sorted(
        findings.values(), key=lambda f: (f["triage_priority"], f["target"], f["check"], f["id"])
    )
    return {
        "schema_version": 1,
        "status": "partial",
        "assessments": results,
        "summary": {
            "unique_findings": len(ordered),
            "input_reports": len(results),
            "triage_counts": {
                p: sum(f["triage_priority"] == p for f in ordered) for p in ("P1", "P2", "P3")
            },
        },
        "findings": ordered,
        "not_checked": limits,
        "notice": "Triage priorities order human review; they are not CVSS or verified severity. "
        "No finding or empty report establishes a complete security audit.",
    }


def render_html(report: dict) -> str:
    def escaped(value):
        return html.escape(str(value), quote=True)

    summaries = "".join(
        f"<li><strong>{p}</strong>: {n}</li>" for p, n in report["summary"]["triage_counts"].items()
    )
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{escaped(f[key])}</td>"
            for key in (
                "triage_priority",
                "target",
                "check",
                "status",
                "evidence",
                "recommendation",
            )
        )
        + "</tr>"
        for f in report["findings"]
    )
    sources = "".join(
        f"<li>#{escaped(s['source'])} {escaped(s['target'])} — "
        f"{escaped(s['target_kind'])} / {escaped(s['status'])}</li>"
        for s in report["assessments"]
    )
    limitations = "".join(
        f"<li>#{escaped(s['source'])}: {escaped(s['notice'])}</li>" for s in report["not_checked"]
    )
    return (
        """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" 
content="default-src 'none'; style-src 'unsafe-inline';
base-uri 'none'; form-action 'none'">
<title>AI Threat Lab — remediation report</title>
<style>body{font:16px system-ui;margin:2rem auto;max-width:1200px;padding:0 1rem;color:#182536}
h1,h2{color:#123959}table{border-collapse:collapse;width:100%}td,th{border:1px solid #cad4dc;
padding:.6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf3f8}
.notice{background:#fff3cc;padding:1rem}li{margin:.4rem 0}.scroll{overflow-x:auto}
@media print{body{margin:0;max-width:none}td,th{font-size:10px}}</style>
<h1>Security assessment — remediation queue</h1>
<p class="notice">"""
        + escaped(report["notice"])
        + """</p>
<h2>Triage counts</h2><ul>"""
        + summaries
        + """</ul>
<h2>Assessment sources</h2><ul>"""
        + sources
        + """</ul>
<h2>Findings</h2><div class="scroll"><table><thead><tr><th>Priority</th><th>Target</th>
<th>Check</th><th>Status</th><th>Evidence</th><th>Recommended action</th></tr></thead><tbody>"""
        + rows
        + """</tbody></table></div>
<h2>Not checked and limitations</h2><ul>"""
        + limitations
        + """</ul></html>"""
    )
