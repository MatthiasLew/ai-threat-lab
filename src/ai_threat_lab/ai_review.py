"""Grounded advisory interpretation. Model output is data, never a command plan."""

import json

from .ai_costs import INSTRUCTIONS, BudgetedAI, OpenAIResponses, compact_evidence
from .contracts import fields
from .evidence import evidence_digest
from .models import ValidationError, require_text
from .review_packets import select_packet
from .scan_bundle import document

SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "observations": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "properties": {key: {"type": "string"} for key in (
                "evidence_id", "explanation", "what_to_review", "suggested_remediation")},
            "required": ["evidence_id", "explanation", "what_to_review", "suggested_remediation"],
        }},
        "uncertainty": {"type": "string"},
    }, "required": ["summary", "observations", "uncertainty"],
}
TEXT_FORMAT = {"type": "json_schema", "name": "evidence_review", "strict": True, "schema": SCHEMA}
REVIEW_INSTRUCTIONS = INSTRUCTIONS + (
    " Return JSON with summary, observations and uncertainty. Each observation must have "
    "evidence_id, explanation, what_to_review and suggested_remediation, all strings. "
    "Cover every supplied evidence_id exactly once, with no other identifiers. "
    "Do not invent observations. Explain practical review steps in plain language. "
    "Use the user's configured report language only if explicitly supplied; otherwise English. "
    "The application will show original limitations separately and your advice as unverified."
)


def validate_review(text, expected):
    if not isinstance(text, str) or len(text.encode("utf-8")) > 128 * 1024:
        raise ValidationError("AI review exceeds its response bound")
    value = document(text.encode("utf-8"))
    fields(value, {"summary", "observations", "uncertainty"})
    for key in ("summary", "uncertainty"):
        require_text(value[key], key)
        if len(value[key]) > 8000:
            raise ValidationError("AI review text exceeds its limit")
    rows = value["observations"]
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValidationError("AI review must address every supplied observation once")
    seen = set()
    for row in rows:
        fields(row, {"evidence_id", "explanation", "what_to_review", "suggested_remediation"})
        for key, content in row.items():
            require_text(content, key)
            if len(content) > 8000:
                raise ValidationError("AI review text exceeds its limit")
        identifier = row["evidence_id"]
        if identifier not in expected or identifier in seen:
            raise ValidationError("AI review contains an unknown or repeated evidence reference")
        seen.add(identifier)
    return value


def review_service(config, ledger, provider, evidence):
    expected = {row["evidence_id"] for row in evidence["findings"]}
    return BudgetedAI(
        config, ledger, provider, instructions=REVIEW_INSTRUCTIONS,
        response_validator=lambda text: validate_review(text, expected),
        extra_input_bytes=len(json.dumps({"text": {"format": TEXT_FORMAT}}).encode()),
        response_contract=json.dumps(TEXT_FORMAT, sort_keys=True),
    ), evidence


def review_result(config, ledger, client, report, *, dry_run=False,
                  packet_index=None, group_size=3):
    selected, index, total = select_packet(
        report, config.max_input_bytes, packet_index=packet_index, group_size=group_size)
    service, evidence = review_service(config, ledger, OpenAIResponses(
        client, text_format=TEXT_FORMAT), selected)
    result = service.explain(evidence, dry_run=dry_run)
    if "text" in result:
        result["interpretation"] = validate_review(
            result.pop("text"), {row["evidence_id"] for row in evidence["findings"]})
    result.update({
        "schema_version": 1, "mode": "advisory_interpretation",
        "packet_index": index, "packet_count": total,
        "packet_finding_count": len(evidence["findings"]),
        "total_finding_count": len(report["findings"]),
        "evidence_sha256": evidence_digest(json.loads(compact_evidence(
            evidence, config.max_input_bytes))),
        "not_checked": report["not_checked"],
        "notice": "AI advice is unverified interpretation of supplied observations. "
                  "Reference validation does not establish factual correctness. "
                  "Original tool findings and limitations remain authoritative. "
                  "No commands, code or model-proposed tools are executed.",
    })
    return result
