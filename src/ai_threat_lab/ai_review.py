"""Grounded advisory interpretation. Model output is data, never a command plan."""

import copy
import json

from .ai_costs import INSTRUCTIONS, AIConfig, BudgetedAI, OpenAIResponses, compact_evidence, usd
from .contracts import fields
from .evidence import evidence_digest, interpretation_evidence
from .finding_details import SUPPORTED_LANGUAGES, describe_finding, validate_report_language
from .models import ValidationError, require_text
from .review_packets import select_packet
from .scan_bundle import document

SUPPORTED_AI_PROVIDERS = ("openai", "gemini")

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "observations": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    key: {"type": "string"}
                    for key in (
                        "evidence_id",
                        "explanation",
                        "what_to_review",
                        "suggested_remediation",
                    )
                },
                "required": [
                    "evidence_id",
                    "explanation",
                    "what_to_review",
                    "suggested_remediation",
                ],
            },
        },
        "uncertainty": {"type": "string"},
    },
    "required": ["summary", "observations", "uncertainty"],
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


def validate_ai_provider(provider: str) -> str:
    if not isinstance(provider, str) or provider not in SUPPORTED_AI_PROVIDERS:
        allowed = ", ".join(SUPPORTED_AI_PROVIDERS)
        raise ValidationError(f"Unsupported AI provider; choose one of: {allowed}")
    return provider


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
    validate_report_language(language)
    expected = {row["evidence_id"] for row in evidence["findings"]}
    provider_id = getattr(provider, "PROVIDER_ID", "openai")
    return (
        BudgetedAI(
            config,
            ledger,
            provider,
            instructions=review_instructions(language),
            response_validator=lambda text: validate_review(text, expected),
            extra_input_bytes=len(json.dumps({"text": {"format": TEXT_FORMAT}}).encode()),
            response_contract=json.dumps(TEXT_FORMAT, sort_keys=True),
            provider_id=provider_id,
            language=language,
        ),
        evidence,
    )


def review_result(
    config,
    ledger,
    client,
    report,
    *,
    dry_run=False,
    packet_index=None,
    group_size=3,
    language: str = "en",
    provider: str = "openai",
    timeout: int = 30,
):
    validate_report_language(language)
    validate_ai_provider(provider)
    if provider == "gemini":
        from .gemini_adapter import gemini_review_result

        return gemini_review_result(
            config,
            ledger,
            client,
            report,
            dry_run=dry_run,
            packet_index=packet_index,
            group_size=group_size,
            language=language,
            timeout=timeout,
        )
    selected, index, total = select_packet(
        report, config.max_input_bytes, packet_index=packet_index, group_size=group_size
    )
    service, evidence = review_service(
        config,
        ledger,
        OpenAIResponses(client, text_format=TEXT_FORMAT),
        selected,
        language=language,
    )
    result = service.explain(evidence, dry_run=dry_run)
    if "text" in result:
        result["interpretation"] = validate_review(
            result.pop("text"), {row["evidence_id"] for row in evidence["findings"]}
        )
    result.update(
        {
            "schema_version": 1,
            "mode": "advisory_interpretation",
            "packet_index": index,
            "packet_count": total,
            "packet_finding_count": len(evidence["findings"]),
            "total_finding_count": len(report["findings"]),
            "evidence_sha256": evidence_digest(
                json.loads(compact_evidence(evidence, config.max_input_bytes))
            ),
            "not_checked": report["not_checked"],
            "notice": "AI advice is unverified interpretation of supplied observations. "
            "Reference validation does not establish factual correctness. "
            "Original tool findings and limitations remain authoritative. "
            "No commands, code or model-proposed tools are executed.",
        }
    )
    if language != "en":
        result["report_language"] = language
    return result


def build_multilingual_ai_packet(
    report: dict,
    config: AIConfig | None = None,
    *,
    language: str = "en",
    provider: str = "openai",
    packet_index: int | None = None,
    group_size: int = 3,
) -> dict:
    """Prepare a validated, language-scoped AI evidence packet without calling any API."""
    validate_report_language(language)
    validate_ai_provider(provider)
    if config is None:
        config = AIConfig(
            model="gemini-2.5-flash" if provider == "gemini" else "offline-contract-v1",
            input_usd_per_million="0.50",
            output_usd_per_million="1.50",
        )
    elif not isinstance(config, AIConfig):
        raise ValidationError("build_multilingual_ai_packet requires an AIConfig instance")
    snapshot = copy.deepcopy(report)
    raw_report_bytes = len(
        json.dumps(snapshot, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    )
    selected, index, total = select_packet(
        snapshot, config.max_input_bytes, packet_index=packet_index, group_size=group_size
    )
    instructions = review_instructions(language)
    if provider == "gemini":
        from .gemini_adapter import GEMINI_RESPONSE_SCHEMA, validate_gemini_model

        validate_gemini_model(config.model)
        contract_schema = {
            "responseMimeType": "application/json",
            "responseSchema": GEMINI_RESPONSE_SCHEMA,
        }
        overhead = len(json.dumps(contract_schema).encode("utf-8"))
        response_contract = json.dumps(GEMINI_RESPONSE_SCHEMA, sort_keys=True)
    else:
        contract_schema = TEXT_FORMAT
        overhead = len(json.dumps({"text": {"format": TEXT_FORMAT}}).encode("utf-8"))
        response_contract = json.dumps(TEXT_FORMAT, sort_keys=True)

    prompt = compact_evidence(selected, config.max_input_bytes)
    parsed_prompt = json.loads(prompt)
    count = len(parsed_prompt["findings"])
    input_bytes = len(prompt.encode("utf-8"))
    bound = len((instructions + prompt).encode("utf-8")) + overhead + 1024

    # Deduplicated rule context & grouped findings by rule code (never repeating rule descriptions)
    rule_context: dict[str, dict] = {}
    rule_groups: list[dict] = []
    groups_map: dict[str, dict] = {}
    for item in parsed_prompt["findings"]:
        rule = item["check"]
        if rule not in rule_context:
            detail = describe_finding(
                {
                    "check": rule,
                    "status": item["status"],
                    "evidence": item["evidence"],
                    "recommendation": item["recommendation"],
                },
                language=language,
            )
            rule_context[rule] = {
                "rule_code": rule,
                "title": detail.title,
                "threat_category": detail.threat_category,
                "triage_priority": detail.triage_priority,
                "recommendation": item["recommendation"],
            }
        group = groups_map.get(rule)
        if group is None:
            group = {
                "check": rule,
                "status": item["status"],
                "count": 0,
                "evidence_ids": [],
            }
            groups_map[rule] = group
            rule_groups.append(group)
        group["count"] += 1
        if "evidence_id" in item:
            group["evidence_ids"].append(item["evidence_id"])

    dummy_ai = BudgetedAI(
        config,
        None,  # type: ignore[arg-type]
        None,
        instructions=instructions,
        extra_input_bytes=overhead,
        response_contract=response_contract,
        provider_id=provider,
        language=language,
    )
    cache_key = dummy_ai.compute_cache_key(prompt)

    return {
        "schema_version": 1,
        "mode": "multilingual_ai_evidence_packet",
        "status": "prepared" if count else "skipped_no_findings",
        "provider": provider,
        "report_language": language,
        "language_name": SUPPORTED_LANGUAGES[language],
        "network_called": False,
        "credentials_inspected": False,
        "ledger_written": False,
        "model": config.model,
        "cache_key": cache_key,
        "packet_index": index,
        "packet_count": total,
        "finding_count": count,
        "total_finding_count": len(snapshot["findings"]),
        "evidence_sha256": evidence_digest(parsed_prompt),
        "input_bytes": input_bytes,
        "input_token_planning_bound": bound if count else 0,
        "max_output_tokens": config.max_output_tokens if count else 0,
        "reserved_usd": usd(config.charge(bound, config.max_output_tokens)) if count else usd(0),
        "instructions": instructions,
        "text_format": contract_schema,
        "tools": [],
        "tools_permitted": False,
        "input": parsed_prompt,
        "input_text": prompt,
        "rule_context": rule_context,
        "rule_groups": rule_groups,
        "optimization_stats": {
            "raw_report_bytes": raw_report_bytes,
            "minimized_input_bytes": input_bytes,
            "bytes_saved": max(0, raw_report_bytes - input_bytes),
            "reduction_ratio": round(max(0.0, 1.0 - (input_bytes / raw_report_bytes)), 4)
            if raw_report_bytes > 0
            else 0.0,
            "raw_limitation_count": len(snapshot.get("not_checked", [])),
            "deduplicated_limitation_count": len(parsed_prompt.get("not_checked", [])),
            "unique_rules_in_packet": len(rule_context),
            "findings_in_packet": count,
        },
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
    report_digest = (
        evidence_digest(interpretation_evidence(technical))
        if "assessments" in technical and "not_checked" in technical
        else evidence_digest(technical)
    )
    try:
        validated = validate_review(raw_ai_response, required_ids)
    except ValidationError as exc:
        if not preserve_on_error:
            raise
        return {
            "schema_version": 1,
            "report_evidence_sha256": report_digest,
            "technical_report": technical,
            "ai_advisory": {
                "status": "rejected_invalid_ai_output",
                "valid": False,
                "report_language": language,
                "report_evidence_sha256": report_digest,
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
        "report_evidence_sha256": report_digest,
        "technical_report": technical,
        "ai_advisory": {
            "status": "validated_unverified_advisory",
            "valid": True,
            "report_language": language,
            "report_evidence_sha256": report_digest,
            "summary": validated["summary"],
            "uncertainty": validated["uncertainty"],
            "observations": bound_observations,
        },
        "notice": (
            "AI advisory is separated from the technical report. "
            "Locations, rule codes and confirmation statuses come strictly from the local scanner."
        ),
    }
