"""Bounded offline interchange for external SARIF results; never invoke a scanner."""

import json
from dataclasses import asdict

from .assessment import AssessmentFinding, AssessmentResult
from .audit_report import merge_reports
from .models import ValidationError
from .report_io import read_regular
from .scan_bundle import document

NOTICE = (
    "Imported SARIF is an unverified producer claim, not a new scan or validated vulnerability. "
    "Source freshness, scanner configuration, suppressions and analysis completeness need review. "
    "Messages, rule names and locations may contain private data; inspect them before AI sharing. "
    "No scanner, source file, external property file, URL, fix or code snippet is executed/opened. "
    "Code flows, related locations, fixes and external message catalogs are not imported."
)


def text(value, maximum=256):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValidationError("Unsupported SARIF text field")
    # Keep multiline prose but escape controls in the evidence, not in terminal commands.
    return json.dumps(value, ensure_ascii=False)


def array(value, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValidationError("Unsupported SARIF array or limit")
    return value


def rule_id(result, driver):
    if "rule" in result:
        raise ValidationError("Tool-component rule references are not imported")
    identifier = result.get("ruleId")
    if "ruleIndex" in result:
        index = result["ruleIndex"]
        rules = array(driver.get("rules", []), 10000)
        if type(index) is not int or not 0 <= index < len(rules):
            raise ValidationError("Unsupported SARIF rule index")
        referenced = rules[index]["id"]
        if identifier is not None and identifier != referenced:
            raise ValidationError("Contradictory SARIF rule identity")
        identifier = referenced
    return text(identifier) if identifier is not None else '"not reported"'


def location(value, run):
    physical = value["physicalLocation"]
    artifact = physical["artifactLocation"]
    uri, base = artifact.get("uri"), artifact.get("uriBaseId")
    if "index" in artifact:
        index = artifact["index"]
        artifacts = array(run.get("artifacts", []), 10000)
        if type(index) is not int or not 0 <= index < len(artifacts):
            raise ValidationError("Unsupported SARIF artifact index")
        referenced = artifacts[index]["location"]
        if uri is not None and uri != referenced.get("uri"):
            raise ValidationError("Contradictory SARIF artifact identity")
        if base is not None and base != referenced.get("uriBaseId"):
            raise ValidationError("Contradictory SARIF base identity")
        uri, base = referenced.get("uri"), referenced.get("uriBaseId")
    place = text(uri, 1024)
    if base is not None:
        place += " (unresolved base " + text(base) + ")"
    region = physical.get("region", {})
    if "startLine" in region:
        line = region["startLine"]
        if type(line) is not int or not 1 <= line <= 1000000000:
            raise ValidationError("Unsupported SARIF source line")
        place += f":{line}"
    return place


def finding(result, run, driver, index):
    rule = rule_id(result, driver)
    message = text(result["message"]["text"], 2000)
    level, kind = result.get("level", "not_reported"), result.get("kind", "not_reported")
    baseline = result.get("baselineState", "not_reported")
    if (level not in ("none", "note", "warning", "error", "not_reported")
            or kind not in ("notApplicable", "pass", "fail", "review", "open",
                            "informational", "not_reported")
            or baseline not in ("new", "unchanged", "updated", "absent", "not_reported")):
        raise ValidationError("Unsupported SARIF result classification")
    suppressions = array(result.get("suppressions", []), 20)
    states = []
    for suppression in suppressions:
        state = suppression.get("status", "not_reported")
        if state not in ("accepted", "underReview", "rejected", "not_reported"):
            raise ValidationError("Unsupported SARIF suppression status")
        states.append(state)
    locations = array(result.get("locations", []), 100)
    selected = [location(item, run) for item in locations[:3]]
    return AssessmentFinding(
        "external_sarif_result", "unverified",
        f"Result {index}; rule={rule}; reported_level={level}; reported_kind={kind}; "
        f"baseline={baseline}; suppression_statuses={','.join(states) or 'none reported'}; "
        f"locations={'; '.join(selected) or 'not reported'}; "
        f"locations_omitted={max(0, len(locations) - 3)}; message={message}",
        "Review the original scanner result, referenced source and current configuration. "
        "A suppressed, absent or passing result is not an active vulnerability; "
        "reported severity is not independently verified.",
    )


def invocation_failed(run):
    invocations = array(run.get("invocations", []), 100)
    failed = False
    for invocation in invocations:
        successful = invocation["executionSuccessful"]
        if type(successful) is not bool:
            raise ValidationError("Invalid SARIF invocation outcome")
        failed |= not successful
        for field in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            for item in array(invocation.get(field, []), 1000):
                level = item.get("level", "warning")
                if level not in ("none", "note", "warning", "error"):
                    raise ValidationError("Invalid SARIF notification level")
                failed |= level == "error"
    return failed, bool(invocations)


def review_sarif(path, *, start=1, max_entries=200):
    if type(start) is not int or start < 1:
        raise ValidationError("SARIF start must be a positive integer")
    if type(max_entries) is not int or not 1 <= max_entries <= 200:
        raise ValidationError("Import between 1 and 200 SARIF results per page")
    value = document(read_regular(path, 8 * 1024 * 1024))
    if value.get("version") != "2.1.0":
        raise ValidationError("Only saved SARIF 2.1.0 is supported")
    runs = array(value.get("runs"), 20)
    if not runs:
        raise ValidationError("SARIF must contain at least one run")
    reports, failures, offset = [], 0, 0
    for run_index, run in enumerate(runs, 1):
        findings, gaps, broken = [], [NOTICE], False
        try:
            rows = array(run.get("results"), 10000)
            run_start, offset = offset, offset + len(rows)
            driver = run["tool"]["driver"]
            tool = text(driver["name"])
            try:
                properties = run.get("properties", {})
                for limitation in array(properties.get("limitations", []), 100):
                    gaps.append("Producer-supplied limitation: " + text(limitation, 2000))
            except (ValidationError, TypeError, AttributeError):
                broken = True
                gaps.append("Producer limitation metadata is incomplete or unsupported.")
            try:
                failed, invocation_present = invocation_failed(run)
                broken |= failed
                gaps.append(f"Producer={tool}; invocation outcome supplied={invocation_present}; "
                            f"producer failure reported={failed}. Outcomes are unverified.")
            except (ValidationError, KeyError, TypeError, AttributeError):
                broken = True
                gaps.append(f"Producer={tool}; malformed invocation metadata; "
                            "retained results do not establish scanner completion.")
            if run.get("externalPropertyFileReferences"):
                broken = True
                gaps.append("External property references were not loaded; evidence is incomplete.")
            omitted, malformed = 0, 0
            for result_index, result in enumerate(rows, 1):
                if not start <= run_start + result_index < start + max_entries:
                    omitted += 1
                    continue
                try:
                    findings.append(finding(result, run, driver, result_index))
                except (ValidationError, KeyError, TypeError, AttributeError):
                    malformed += 1
            broken |= bool(malformed)
            gaps.append(f"Results outside selected global page: {omitted}; "
                        f"selected unsupported results: {malformed}.")
        except (ValidationError, KeyError, TypeError, AttributeError):
            broken = True
            gaps.append("Run metadata/results are unavailable or unsupported; no clean conclusion.")
        if broken:
            failures += 1
        reports.append(asdict(AssessmentResult(
            f"SARIF run {run_index:04d}", "external_static_analysis",
            "partial" if findings or not broken else "not_configured",
            tuple(findings), tuple(gaps),
        )))
    if start > max(1, offset):
        raise ValidationError("SARIF start is beyond the available results")
    return merge_reports(json.loads(json.dumps(reports))), failures
