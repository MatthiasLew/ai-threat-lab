"""Bounded offline interchange for external SARIF results; never invoke a scanner."""

import json
import re
import unicodedata
from dataclasses import asdict
from urllib.parse import unquote
from uuid import uuid4

from .assessment import AssessmentFinding, AssessmentResult
from .audit_report import merge_reports
from .code_snippet import redact_snippet_secrets
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


def safe_text(value, maximum=256):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValidationError("Unsupported SARIF text field")
    value = redact_snippet_secrets(value)
    value = re.sub(
        r"(?i)\b(?:password|secret|token|api[_-]?key|credential)\s*[:=]\s*\S+",
        "[REDACTED_SECRET]", value,
    )
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char) in ("Cc", "Cf", "Cs") else char
        for char in value
    )


def text(value, maximum=256):
    return json.dumps(safe_text(value, maximum), ensure_ascii=False)


def array(value, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValidationError("Unsupported SARIF array or limit")
    return value


def merge_reference(outer, inner):
    if (
        outer is not None and inner is not None
        and (type(outer) is not type(inner) or outer != inner)
    ):
        raise ValidationError("Contradictory SARIF references")
    return outer if outer is not None else inner


def resolve_rule(result, tool):
    component = tool["driver"]
    reference = result.get("rule", {})
    if "toolComponent" in reference:
        link = reference["toolComponent"]
        extensions = array(tool.get("extensions", []), 100)
        index = link.get("index")
        if type(index) is not int or not 0 <= index < len(extensions):
            raise ValidationError("Unsupported SARIF tool component")
        component = extensions[index]
        for key in ("name", "guid"):
            if key in link and link[key] != component.get(key):
                raise ValidationError("Contradictory SARIF tool component")
    identifier = merge_reference(result.get("ruleId"), reference.get("id"))
    index = merge_reference(result.get("ruleIndex"), reference.get("index"))
    rules = array(component.get("rules", []), 10000)
    descriptor = {}
    if index is not None:
        if type(index) is not int or not 0 <= index < len(rules):
            raise ValidationError("Unsupported SARIF rule index")
        descriptor = rules[index]
        identifier = merge_reference(identifier, descriptor["id"])
    elif identifier is not None:
        descriptor = next(
            (rule for rule in rules if isinstance(rule, dict) and rule.get("id") == identifier), {}
        )
    return identifier, descriptor, component


def safe_location(uri, *, opaque_target=False):
    if not isinstance(uri, str) or not uri.strip() or len(uri) > 1024:
        raise ValidationError("Unsupported SARIF location")
    decoded = unquote(uri, errors="strict").replace("\\", "/")
    if re.match(r"^[A-Za-z]:", decoded):
        return None
    if opaque_target and re.fullmatch(
        r"[\w.-]+(?::[0-9]+)?(?:/[\w.-]+)*(?::[\w.-]+)?(?:@sha256:[a-fA-F0-9]{64})?",
        decoded,
    ) and ".." not in decoded.split("/"):
        return safe_text(decoded, 1024)
    if (
        decoded.startswith("/") or any(char in decoded for char in ":?#%")
        or ".." in decoded.split("/")
        or any(unicodedata.category(char) in ("Cc", "Cf", "Cs") for char in decoded)
    ):
        return None
    return safe_text(decoded, 1024)


def location(value, run, *, secret_source=False, target_source=False):
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
    safe_uri = None if secret_source else safe_location(uri, opaque_target=target_source)
    region = physical.get("region", {})
    line = region.get("startLine")
    if "startLine" in region:
        if type(line) is not int or not 1 <= line <= 1000000000:
            raise ValidationError("Unsupported SARIF source line")
    place = {
        "label": safe_uri,
        "base_id": safe_text(base) if safe_uri is not None and base is not None else None,
        "line": line if not secret_source else None,
        "kind": "target" if target_source else "artifact",
    }
    if target_source:
        label = value.get("message", {}).get("text")
        if isinstance(label, str) and len(label) <= 1024:
            target, separator, package = label.rpartition(": ")
            match = re.fullmatch(r"([\w.+-]{1,128})@([\w.+:~-]{1,128})", package)
            if separator and target == uri and match:
                place["package"] = safe_text(match[1])
                place["package_version"] = safe_text(match[2])
    return place


def render_location(place):
    label = place["label"]
    if label is None:
        return "[location withheld]"
    rendered = json.dumps(label, ensure_ascii=False)
    if place["base_id"] is not None:
        rendered += " (unresolved base " + json.dumps(place["base_id"], ensure_ascii=False) + ")"
    if place["line"] is not None:
        rendered += f':{place["line"]}'
    return rendered


def message_text(message, descriptor, component):
    if "text" in message:
        return safe_text(message["text"], 2000)
    identifier = message["id"]
    catalogs = (descriptor.get("messageStrings", {}), component.get("globalMessageStrings", {}))
    for catalog in catalogs:
        if identifier in catalog:
            template = catalog[identifier]["text"]
            arguments = array(message.get("arguments", []), 20)
            values = [safe_text(argument, 256) for argument in arguments]
            if not isinstance(template, str) or len(template) > 2000:
                raise ValidationError("Unsupported SARIF message template")
            return safe_text(re.sub(
                r"\{(\d{1,2})\}",
                lambda match: values[int(match[1])] if int(match[1]) < len(values) else match[0],
                template,
            ), 2000)
    raise ValidationError("Unsupported SARIF message reference")


def optional_text(record, key):
    value = record.get(key)
    return None if value in (None, "<MASKED>") else safe_text(value)


def reported_version(record):
    return optional_text(record, "version") or optional_text(record, "semanticVersion")


def producer_classification(producer, properties, descriptor):
    if "gitleaks" in producer:
        return None, None, None
    category = optional_text(properties, "category")
    if producer == "bandit":
        return (
            optional_text(properties, "issue_severity"),
            optional_text(properties, "issue_confidence"),
            category,
        )
    severity = optional_text(properties, "severity")
    if producer == "trivy":
        tags = array(descriptor.get("properties", {}).get("tags", []), 100)
        severity = severity or next(
            (tag for tag in tags if tag in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")),
            None,
        )
        categories = ("vulnerability", "misconfiguration", "secret", "license")
        category = category or next((tag for tag in tags if tag in categories), None)
    return severity, optional_text(properties, "confidence"), category


def finding(result, run, index, *, structured):
    tool = run["tool"]
    driver = tool["driver"]
    producer = driver["name"].casefold()
    secret_source = "gitleaks" in producer
    identifier, descriptor, component = resolve_rule(result, tool)
    rule = text(identifier) if identifier is not None else '"not reported"'
    message = (
        "[secret scanner message withheld]" if secret_source else
        message_text(result["message"], descriptor, component)
    )
    level, kind = result.get("level", "not_reported"), result.get("kind", "not_reported")
    baseline = result.get("baselineState", "not_reported")
    if (
        level not in ("none", "note", "warning", "error", "not_reported")
        or kind
        not in ("notApplicable", "pass", "fail", "review", "open", "informational", "not_reported")
        or baseline not in ("new", "unchanged", "updated", "absent", "not_reported")
    ):
        raise ValidationError("Unsupported SARIF result classification")
    suppressions = array(result.get("suppressions", []), 20)
    states = []
    for suppression in suppressions:
        state = suppression.get("status", "not_reported")
        if state not in ("accepted", "underReview", "rejected", "not_reported"):
            raise ValidationError("Unsupported SARIF suppression status")
        suppression_kind = suppression.get("kind")
        if suppression_kind not in (None, "inSource", "external"):
            raise ValidationError("Unsupported SARIF suppression kind")
        states.append({"status": None if state == "not_reported" else state,
                       "kind": suppression_kind})
    locations = array(result.get("locations", []), 100)
    selected = [
        location(item, run, secret_source=secret_source, target_source="trivy" in producer)
        for item in locations[:3]
    ]
    omitted = max(0, len(locations) - 3)
    if structured:
        properties = result.get("properties", {})
        if not isinstance(properties, dict):
            raise ValidationError("Unsupported SARIF result properties")
        severity, confidence, category = producer_classification(producer, properties, descriptor)
        return {
            "component": optional_text(component, "name"),
            "component_version": reported_version(component),
            "rule_id": safe_text(identifier) if identifier is not None else None,
            "rule_name": None if secret_source else optional_text(descriptor, "name"),
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "sarif_level": None if level == "not_reported" else level,
            "result_kind": None if kind == "not_reported" else kind,
            "baseline_state": None if baseline == "not_reported" else baseline,
            "suppressions": states,
            "locations": selected,
            "locations_omitted": omitted,
            "code_flows_omitted": len(array(result.get("codeFlows", []), 1000)),
            "message": message,
            "status": "unverified",
        }
    return AssessmentFinding(
        "external_sarif_result",
        "unverified",
        f"Result {index}; rule={rule}; reported_level={level}; reported_kind={kind}; "
        f"baseline={baseline}; suppression_statuses="
        f"{','.join(item['status'] or 'not_reported' for item in states) or 'none reported'}; "
        f"locations={'; '.join(map(render_location, selected)) or 'not reported'}; "
        f"locations_omitted={omitted}; "
        f"message={json.dumps(message, ensure_ascii=False)}",
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


def validate_depth(value, remaining=48):
    if isinstance(value, (dict, list)):
        if remaining == 0:
            raise ValidationError("SARIF nesting exceeds its limit")
        for item in value.values() if isinstance(value, dict) else value:
            validate_depth(item, remaining - 1)


def review_sarif(path, *, start=1, max_entries=200):
    """Return the compatible assessment report and the count of incomplete runs."""
    return _import(path, start, max_entries, structured=False)


def import_sarif(path, *, start=1, max_entries=200):
    """Return versioned external observations and the count of incomplete runs."""
    return _import(path, start, max_entries, structured=True)


def _import(path, start, max_entries, *, structured):
    if type(start) is not int or start < 1:
        raise ValidationError("SARIF start must be a positive integer")
    if type(max_entries) is not int or not 1 <= max_entries <= 200:
        raise ValidationError("Import between 1 and 200 SARIF results per page")
    value = document(read_regular(path, 8 * 1024 * 1024))
    validate_depth(value)
    if value.get("version") != "2.1.0":
        raise ValidationError("Only saved SARIF 2.1.0 is supported")
    runs = array(value.get("runs"), 20)
    if not runs:
        raise ValidationError("SARIF must contain at least one run")
    reports, failures, offset = [], 0, 0
    run_details, observations = [], []
    import_id = uuid4().hex if structured else None
    for run_index, run in enumerate(runs, 1):
        findings, gaps, broken = [], [NOTICE], False
        producer, version, outcome = None, None, None
        target_kind = None
        omitted, malformed, duplicates = 0, 0, 0
        seen = {}
        try:
            rows = array(run.get("results"), 10000)
            run_start, offset = offset, offset + len(rows)
            driver = run["tool"]["driver"]
            tool = text(driver["name"])
            producer = safe_text(driver["name"])
            if structured:
                version = reported_version(driver)
            try:
                properties = run.get("properties", {})
                if producer.casefold() == "trivy" and any(
                    key in properties for key in ("imageID", "imageName", "repoDigests")
                ):
                    target_kind = "image"
                for limitation in array(properties.get("limitations", []), 100):
                    if "gitleaks" not in producer.casefold():
                        gaps.append("Producer-supplied limitation: " + text(limitation, 2000))
            except (ValidationError, TypeError, AttributeError):
                broken = True
                gaps.append("Producer limitation metadata is incomplete or unsupported.")
            try:
                failed, invocation_present = invocation_failed(run)
                broken |= failed
                outcome = not failed if invocation_present else None
                gaps.append(
                    f"Producer={tool}; invocation outcome supplied={invocation_present}; "
                    f"producer failure reported={failed}. Outcomes are unverified."
                )
            except (ValidationError, KeyError, TypeError, AttributeError):
                broken = True
                gaps.append(
                    f"Producer={tool}; malformed invocation metadata; "
                    "retained results do not establish scanner completion."
                )
            if run.get("externalPropertyFileReferences"):
                broken = True
                gaps.append("External property references were not loaded; evidence is incomplete.")
            for result_index, result in enumerate(rows, 1):
                if not start <= run_start + result_index < start + max_entries:
                    omitted += 1
                    continue
                try:
                    observation = finding(result, run, result_index, structured=structured)
                    if structured:
                        key = json.dumps(result, sort_keys=True, separators=(",", ":"))
                        if key in seen:
                            seen[key]["provenance"]["result_ordinals"].append(result_index)
                            duplicates += 1
                            continue
                        observation.update({
                            "producer": producer, "producer_version": version,
                            "producer_succeeded": outcome, "import_id": import_id,
                            "provenance": {"run": run_index, "result_ordinals": [result_index]},
                        })
                        seen[key] = observation
                        observations.append(observation)
                    else:
                        findings.append(observation)
                except (ValidationError, KeyError, TypeError, AttributeError, UnicodeError):
                    malformed += 1
            broken |= bool(malformed)
            gaps.append(
                f"Results outside selected global page: {omitted}; "
                f"selected unsupported results: {malformed}."
            )
        except (ValidationError, KeyError, TypeError, AttributeError):
            broken = True
            gaps.append("Run metadata/results are unavailable or unsupported; no clean conclusion.")
        if broken:
            failures += 1
        if structured:
            run_details.append({
                "run": run_index, "producer": producer, "producer_version": version,
                "producer_succeeded": outcome, "incomplete": broken,
                "target_kind": target_kind,
                "outside_page": omitted, "unsupported": malformed, "duplicates": duplicates,
                "limitations": gaps,
            })
            continue
        reports.append(
            asdict(
                AssessmentResult(
                    f"SARIF run {run_index:04d}",
                    "external_static_analysis",
                    "partial" if findings or not broken else "not_configured",
                    tuple(findings),
                    tuple(gaps),
                )
            )
        )
    if start > max(1, offset):
        raise ValidationError("SARIF start is beyond the available results")
    if structured:
        return {
            "schema_version": 1, "kind": "external_sarif_import", "import_id": import_id,
            "start": start, "max_entries": max_entries, "total_results": offset,
            "incomplete_runs": failures, "runs": run_details, "observations": observations,
        }, failures
    return merge_reports(json.loads(json.dumps(reports))), failures
