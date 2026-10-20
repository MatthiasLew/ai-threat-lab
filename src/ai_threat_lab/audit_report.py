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
    "cookie_none_without_secure": "P2",
    "cookie_prefix_constraints": "P2",
    "csp_script_unsafe_eval": "P2",
    **{
        check: "P2"
        for check in (
            "k8s_host_namespace",
            "k8s_privileged_container",
            "k8s_privilege_escalation",
            "k8s_root_user",
            "k8s_non_root_disabled",
            "k8s_unconfined_seccomp",
            "k8s_added_capabilities",
            "k8s_host_path",
            "k8s_host_port",
        )
    },
    **{
        check: "P2"
        for check in (
            "message_link_credentials",
            "message_link_active_scheme",
            "message_link_display_mismatch",
            "message_attachment_active_type",
            "message_attachment_double_extension",
        )
    },
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


def render_html(report: dict, *, language: str = "en") -> str:
    from .finding_details import describe_finding, validate_report_language

    validate_report_language(language)
    pl = language == "pl"

    def escaped(value):
        return html.escape(str(value), quote=True)

    summaries = "".join(
        f"<li><strong>{escaped(p)}</strong>: {escaped(n)}</li>"
        for p, n in report["summary"]["triage_counts"].items()
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
    cards = []
    for f in report["findings"]:
        detail = describe_finding(f, target=f.get("target"), language=language)
        loc_parts = []
        if detail.file_path:
            loc_parts.append(f'<code class="path">{escaped(detail.file_path)}</code>')
        if detail.line_number is not None:
            line_lbl = "Linia" if pl else "Line"
            loc_parts.append(
                f'<span class="badge">{line_lbl}: {escaped(detail.line_number)}</span>'
            )
        loc_html = (
            " ".join(loc_parts)
            if loc_parts
            else f'<code class="path">{escaped(detail.target)}</code>'
        )
        example_html = (
            f'<pre class="code-block"><code>{escaped(detail.code_example)}</code></pre>'
            if detail.code_example
            else ""
        )
        if pl:
            q_detected = "Co wykryto?"
            q_why = "Dlaczego jest to potencjalnie niebezpieczne?"
            q_impact = "Do czego może doprowadzić?"
            q_fix = "Jak to naprawić?"
            q_verify = "Jak sprawdzić poprawkę?"
            q_limits = "Czego analizator nie ustalił?"
            meta_cat = "Kategoria"
            meta_status = "Status potwierdzenia"
            meta_loc = "Lokalizacja"
        else:
            q_detected = "What was detected? (Co wykryto?)"
            q_why = (
                "Why is it potentially dangerous? (Dlaczego jest to potencjalnie niebezpieczne?)"
            )
            q_impact = "What could it lead to? (Do czego może doprowadzić?)"
            q_fix = "How to fix it? (Jak to naprawić?)"
            q_verify = "How to verify the fix? (Jak sprawdzić poprawkę?)"
            q_limits = "What did the analyzer not establish? (Czego analizator nie ustalił?)"
            meta_cat = "Category"
            meta_status = "Confirmation status"
            meta_loc = "Location"
        cards.append(
            f'<article class="finding-card">'
            f'<header class="finding-header">'
            f'<span class="priority priority-{escaped(detail.triage_priority)}">'
            f"{escaped(detail.triage_priority)}</span> "
            f"<strong>{escaped(detail.rule_code)}</strong> — {escaped(detail.title)} "
            f'<span class="badge">{meta_cat}: {escaped(detail.threat_category)}</span> '
            f'<span class="badge">{meta_status}: {escaped(detail.confirmation_status)}</span>'
            f'<div class="finding-meta">{meta_loc}: {loc_html} | '
            f"ID: <code>{escaped(detail.id)}</code></div>"
            f"</header>"
            f'<dl class="finding-details">'
            f"<dt>{q_detected}</dt><dd>{escaped(detail.what_was_detected)}</dd>"
            f"<dt>{q_why}</dt><dd>{escaped(detail.mechanism)}</dd>"
            f"<dt>{q_impact}</dt><dd>{escaped(detail.consequences)}</dd>"
            f"<dt>{q_fix}</dt><dd><p>{escaped(detail.recommendation)}</p>{example_html}</dd>"
            f"<dt>{q_verify}</dt><dd>{escaped(detail.verification_steps)}</dd>"
            f"<dt>{q_limits}</dt><dd>{escaped(detail.analysis_limitations)}</dd>"
            f"</dl></article>"
        )
    cards_html = (
        "".join(cards)
        if cards
        else (
            '<p class="empty-state">Brak wykrytych obserwacji w wybranych kontrolach. '
            "Nie oznacza to, że cel jest wolny od błędów bezpieczeństwa.</p>"
            if pl
            else '<p class="empty-state">No observations were returned by the selected checks. '
            "This does not establish that the target is secure.</p>"
        )
    )
    sources = "".join(
        f'<li>#{escaped(s["source"])} <code class="path">{escaped(s["target"])}</code> — '
        f"{escaped(s['target_kind'])} / {escaped(s['status'])}</li>"
        for s in report["assessments"]
    )
    limitations = "".join(
        f"<li>#{escaped(s['source'])}: {escaped(s['notice'])}</li>" for s in report["not_checked"]
    )
    lang_attr = "pl" if pl else "en"
    heading_main = (
        "Ocena bezpieczeństwa — kolejka naprawcza i szczegółowy raport offline"
        if pl
        else "Security assessment — remediation queue"
    )
    heading_details = (
        "Szczegółowe ustalenia bezpieczeństwa (przewodnik naprawczy)"
        if pl
        else "Detailed security findings (offline remediation guide)"
    )
    style_css = (
        "body{font:16px/1.5 system-ui,-apple-system,sans-serif;margin:2rem auto;"
        "max-width:1200px;padding:0 1rem;color:#182536;background:#fafbfc}\n"
        "h1,h2,h3{color:#123959}table{border-collapse:collapse;width:100%;background:#fff}"
        "td,th{border:1px solid #cad4dc;\n"
        "padding:.6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}"
        "th{background:#edf3f8}\n"
        ".notice{background:#fff3cc;border-left:4px solid #d9a300;padding:1rem;border-radius:4px}"
        "li{margin:.4rem 0}.scroll{overflow-x:auto}\n"
        ".finding-card{background:#fff;border:1px solid #cad4dc;border-radius:6px;"
        "margin:1rem 0;padding:1rem;box-shadow:0 1px 2px rgba(0,0,0,.04)}\n"
        ".finding-header{border-bottom:1px solid #e2e8f0;padding-bottom:.6rem;"
        "margin-bottom:.8rem;overflow-wrap:anywhere}\n"
        ".finding-meta{font-size:.88rem;color:#475569;margin-top:.35rem;overflow-wrap:anywhere}\n"
        ".finding-details{margin:0}"
        ".finding-details dt{font-weight:700;color:#123959;margin-top:.65rem}\n"
        ".finding-details dd{margin:.2rem 0 0 0;overflow-wrap:anywhere}\n"
        ".badge{display:inline-block;background:#edf3f8;color:#1e293b;padding:.1rem .45rem;"
        "border-radius:4px;font-size:.82rem;margin-left:.3rem}\n"
        ".priority{display:inline-block;font-weight:700;padding:.1rem .5rem;"
        "border-radius:4px;font-size:.85rem}\n"
        ".priority-P1{background:#fee2e2;color:#991b1b}"
        ".priority-P2{background:#fef3c7;color:#92400e}"
        ".priority-P3{background:#e0f2fe;color:#075985}\n"
        "code,.path{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9em;"
        "background:#f1f5f9;padding:.1rem .3rem;border-radius:3px;overflow-wrap:anywhere}\n"
        ".code-block{background:#0f172a;color:#f8fafc;padding:.75rem;border-radius:4px;"
        "overflow-x:auto;margin:.4rem 0}\n"
        ".code-block code{background:none;color:inherit;padding:0}\n"
        "@media print{body{margin:0;max-width:none;background:#fff}td,th{font-size:10px}"
        ".finding-card{break-inside:avoid}}"
    )
    return (
        f"""<!doctype html>
<html lang="{lang_attr}"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; style-src 'unsafe-inline';
base-uri 'none'; form-action 'none'">
<title>AI Threat Lab — remediation report</title>
<style>{style_css}</style>
<h1>{heading_main}</h1>
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
        + f"""</tbody></table></div>
<h2>{heading_details}</h2>
<div class="findings-guide">"""
        + cards_html
        + """</div>
<h2>Not checked and limitations</h2><ul>"""
        + limitations
        + """</ul></html>"""
    )
