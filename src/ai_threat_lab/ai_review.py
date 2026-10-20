"""Grounded advisory interpretation. Model output is data, never a command plan."""

import copy
import json

from .ai_costs import INSTRUCTIONS, AIConfig, BudgetedAI, OpenAIResponses, compact_evidence, usd
from .contracts import fields
from .evidence import evidence_digest
from .finding_details import SUPPORTED_LANGUAGES, validate_report_language
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


def review_instructions(language: str = "en") -> str:
    validate_report_language(language)
    if language == "en":
        return REVIEW_INSTRUCTIONS
    name = SUPPORTED_LANGUAGES[language]
    return REVIEW_INSTRUCTIONS + (
        f" Write all prose fields (summary, explanation, what_to_review, "
        f"suggested_remediation, uncertainty) in {name} ({language}), while keeping "
        "every evidence_id exact and unchanged."
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


def review_service(config, ledger, provider, evidence, *, language: str = "en"):
    expected = {row["evidence_id"] for row in evidence["findings"]}
    return BudgetedAI(
        config, ledger, provider, instructions=review_instructions(language),
        response_validator=lambda text: validate_review(text, expected),
        extra_input_bytes=len(json.dumps({"text": {"format": TEXT_FORMAT}}).encode()),
        response_contract=json.dumps(TEXT_FORMAT, sort_keys=True),
    ), evidence


def review_result(config, ledger, client, report, *, dry_run=False,
                  packet_index=None, group_size=3, language: str = "en"):
    validate_report_language(language)
    selected, index, total = select_packet(
        report, config.max_input_bytes, packet_index=packet_index, group_size=group_size)
    service, evidence = review_service(
        config, ledger, OpenAIResponses(client, text_format=TEXT_FORMAT),
        selected, language=language,
    )
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
    if language != "en":
        result["report_language"] = language
    return result


def build_multilingual_ai_packet(
    report: dict,
    config: AIConfig | None = None,
    *,
    language: str = "en",
    packet_index: int | None = None,
    group_size: int = 3,
) -> dict:
    """Prepare a validated, language-scoped AI evidence packet without calling any API."""
    validate_report_language(language)
    if config is None:
        config = AIConfig(
            model="offline-contract-v1",
            input_usd_per_million="0.50",
            output_usd_per_million="1.50",
        )
    elif not isinstance(config, AIConfig):
        raise ValidationError("build_multilingual_ai_packet requires an AIConfig instance")
    snapshot = copy.deepcopy(report)
    selected, index, total = select_packet(
        snapshot, config.max_input_bytes, packet_index=packet_index, group_size=group_size
    )
    instructions = review_instructions(language)
    overhead = len(json.dumps({"text": {"format": TEXT_FORMAT}}).encode())
    prompt = compact_evidence(selected, config.max_input_bytes)
    parsed_prompt = json.loads(prompt)
    count = len(parsed_prompt["findings"])
    bound = len((instructions + prompt).encode("utf-8")) + overhead + 1024
    return {
        "schema_version": 1,
        "mode": "multilingual_ai_evidence_packet",
        "status": "prepared" if count else "skipped_no_findings",
        "report_language": language,
        "language_name": SUPPORTED_LANGUAGES[language],
        "network_called": False,
        "credentials_inspected": False,
        "ledger_written": False,
        "model": config.model,
        "packet_index": index,
        "packet_count": total,
        "finding_count": count,
        "total_finding_count": len(snapshot["findings"]),
        "evidence_sha256": evidence_digest(parsed_prompt),
        "input_bytes": len(prompt.encode("utf-8")),
        "input_token_planning_bound": bound if count else 0,
        "max_output_tokens": config.max_output_tokens if count else 0,
        "reserved_usd": usd(config.charge(bound, config.max_output_tokens)) if count else usd(0),
        "instructions": instructions,
        "text_format": TEXT_FORMAT,
        "tools": [],
        "tools_permitted": False,
        "input": parsed_prompt,
        "input_text": prompt,
        "authoritative_constraints": {
            "original_report_immutable": True,
            "ai_separated_from_technical_report": True,
            "cannot_invent_locations": True,
            "cannot_change_status": True,
            "cannot_execute_tools": True,
        },
        "notice": (
            "Prepared offline contract for future AI interpretation. "
            "Original technical findings and statuses remain immutable and authoritative."
        ),
    }


def attach_ai_interpretation(
    report: dict,
    raw_ai_response: str,
    *,
    expected_ids: set[str] | None = None,
    language: str = "en",
    preserve_on_error: bool = True,
) -> dict:
    """Validate raw AI JSON and return a composite view without mutating or corrupting `report`."""
    validate_report_language(language)
    technical = copy.deepcopy(report)
    by_id = {row["id"]: row for row in technical.get("findings", [])}
    required_ids = set(expected_ids) if expected_ids is not None else set(by_id)
    if not required_ids <= set(by_id):
        raise ValidationError("Expected evidence IDs must belong to the technical report")
    try:
        validated = validate_review(raw_ai_response, required_ids)
    except ValidationError as exc:
        if not preserve_on_error:
            raise
        return {
            "schema_version": 1,
            "technical_report": technical,
            "ai_advisory": {
                "status": "rejected_invalid_ai_output",
                "valid": False,
                "report_language": language,
                "error": str(exc),
                "observations": [],
            },
            "notice": (
                "AI response failed strict validation and was rejected. "
                "The local technical report remains intact and authoritative."
            ),
        }
    bound_observations = []
    for item in validated["observations"]:
        source = by_id[item["evidence_id"]]
        bound_observations.append(
            {
                "evidence_id": item["evidence_id"],
                "authoritative_check": source["check"],
                "authoritative_status": source["status"],
                "authoritative_target": source["target"],
                "authoritative_priority": source["triage_priority"],
                "explanation": item["explanation"],
                "what_to_review": item["what_to_review"],
                "suggested_remediation": item["suggested_remediation"],
            }
        )
    return {
        "schema_version": 1,
        "technical_report": technical,
        "ai_advisory": {
            "status": "validated_unverified_advisory",
            "valid": True,
            "report_language": language,
            "summary": validated["summary"],
            "uncertainty": validated["uncertainty"],
            "observations": bound_observations,
        },
        "notice": (
            "AI advisory is separated from the technical report. "
            "Locations, rule codes and confirmation statuses come strictly from the local scanner."
        ),
    }
