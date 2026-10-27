"""Offline-verifiable Google Gemini API adapter (`generateContent`) with strict safety & cost gates.

Implements the Google Gemini REST `v1beta/models/{model}:generateContent` wire contract using:
- `GEMINI_API_KEY` passed only via the `x-goog-api-key` HTTP header (never in URLs or logs),
- explicit model validation (`AIConfig.model`),
- `systemInstruction` treating all evidence as untrusted data,
- `tools: []` and `toolConfig.functionCallingConfig.mode = "NONE"` disabling tool execution,
- `generationConfig` enforcing `maxOutputTokens`, `temperature: 0.0`,
  `responseMimeType: "application/json"`, and `responseSchema`,
- `CostLedger` + `BudgetedAI` pre-call reservation, daily budget/call limits, and no automatic
  paid retries after ambiguous transport or HTTP failures.
"""

from __future__ import annotations

import json
import os
import re

from .ai_costs import INSTRUCTIONS, AIConfig, BudgetedAI, compact_evidence, integer
from .ai_review import (
    attach_ai_interpretation,
    review_instructions,
    validate_review,
)
from .evidence import evidence_digest
from .finding_details import describe_finding, validate_report_language
from .models import ValidationError, require_text
from .providers import ProviderError
from .review_packets import select_packet

GEMINI_HOST = "generativelanguage.googleapis.com"
GEMINI_ENDPOINT_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

GEMINI_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "summary": {"type": "STRING"},
        "observations": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "evidence_id": {"type": "STRING"},
                    "explanation": {"type": "STRING"},
                    "what_to_review": {"type": "STRING"},
                    "suggested_remediation": {"type": "STRING"},
                },
                "required": [
                    "evidence_id",
                    "explanation",
                    "what_to_review",
                    "suggested_remediation",
                ],
            },
        },
        "uncertainty": {"type": "STRING"},
    },
    "required": ["summary", "observations", "uncertainty"],
}

_MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")
_KEY_QUERY_RE = re.compile(r"([?&]key=)[^&\s'\"]+", re.IGNORECASE)
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/-]+", re.IGNORECASE)
_X_GOOG_KEY_RE = re.compile(r"(x-goog-api-key[:=]\s*)[A-Za-z0-9._~+/-]+", re.IGNORECASE)
_REFUSAL_REASONS = frozenset(
    (
        "SAFETY",
        "RECITATION",
        "BLOCKLIST",
        "PROHIBITED_CONTENT",
        "SPII",
        "IMAGE_SAFETY",
        "REFUSAL",
    )
)


def validate_gemini_model(model: str) -> str:
    """Validate a Gemini model identifier and reject path traversal or query characters."""
    require_text(model, "Gemini model")
    normalized = model.removeprefix("models/")
    if ".." in normalized or not _MODEL_NAME_RE.fullmatch(normalized):
        raise ValidationError(
            "Invalid Gemini model name; use an explicit provider model identifier"
        )
    return normalized


def redact_api_key(message: str, token: str | None = None) -> str:
    """Mask any occurrence of a configured API key or Google AIza key pattern in error strings."""
    if not isinstance(message, str):
        return "REDACTED"
    cleaned = message
    if token and isinstance(token, str) and token.strip():
        cleaned = cleaned.replace(token, "[REDACTED_API_KEY]")
        cleaned = cleaned.replace(token.strip(), "[REDACTED_API_KEY]")
    cleaned = _GOOGLE_KEY_RE.sub("[REDACTED_API_KEY]", cleaned)
    cleaned = _KEY_QUERY_RE.sub(r"\1[REDACTED_API_KEY]", cleaned)
    cleaned = _BEARER_RE.sub(r"\1[REDACTED_API_KEY]", cleaned)
    cleaned = _X_GOOG_KEY_RE.sub(r"\1[REDACTED_API_KEY]", cleaned)
    return cleaned


class GeminiGenerateContent:
    """Fixed-endpoint Google Gemini `generateContent` adapter with no tools or auto-retries."""

    PROVIDER_ID = "gemini"

    def __init__(
        self,
        client,
        *,
        response_schema: dict | None = None,
        timeout: int = 30,
    ) -> None:
        integer(timeout, 1, 120, "Gemini request timeout")
        self.client = client
        self.response_schema = response_schema
        self.timeout = timeout

    def respond(
        self,
        model: str,
        instructions: str,
        prompt: str,
        max_output_tokens: int,
    ) -> tuple[str, int, int]:
        clean_model = validate_gemini_model(model)
        require_text(instructions, "Gemini system instructions")
        require_text(prompt, "Gemini prompt")
        integer(max_output_tokens, 16, 4096, "max_output_tokens")

        token = os.environ.get("GEMINI_API_KEY")
        if not token or not token.strip() or any(ord(c) < 32 or ord(c) == 127 for c in token):
            raise ProviderError("GEMINI_API_KEY is missing")

        generation_config: dict = {
            "maxOutputTokens": max_output_tokens,
            "temperature": 0.0,
            "candidateCount": 1,
        }
        if clean_model.startswith("gemini-2.5"):
            generation_config["thinkingConfig"] = {"thinkingBudget": 0}
        if self.response_schema is not None:
            generation_config["responseMimeType"] = "application/json"
            generation_config["responseSchema"] = self.response_schema

        payload = {
            "systemInstruction": {
                "parts": [{"text": instructions}],
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "tools": [],
            "toolConfig": {
                "functionCallingConfig": {
                    "mode": "NONE",
                }
            },
            "generationConfig": generation_config,
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        url = GEMINI_ENDPOINT_TEMPLATE.format(model=clean_model)
        try:
            response = self.client.request(
                url,
                method="POST",
                headers={
                    "x-goog-api-key": token,
                    "Content-Type": "application/json",
                },
                body=body,
            )
        except Exception as exc:
            safe_detail = redact_api_key(str(exc), token)
            raise ProviderError(
                f"Gemini transport error ({type(exc).__name__}): {safe_detail}"
            ) from None

        if getattr(response, "status", None) != 200:
            status = getattr(response, "status", "unknown")
            detail_msg = ""
            try:
                err_data = response.document()
                if isinstance(err_data, dict) and isinstance(err_data.get("error"), dict):
                    err = err_data["error"]
                    err_status = err.get("status")
                    err_message = err.get("message")
                    parts = []
                    if isinstance(err_status, str) and err_status:
                        parts.append(err_status)
                    if isinstance(err_message, str) and err_message:
                        parts.append(err_message)
                    if parts:
                        detail_msg = f": {' - '.join(parts)}"
            except Exception:
                pass
            safe_detail = redact_api_key(f"Gemini API returned HTTP {status}{detail_msg}", token)
            raise ProviderError(safe_detail)

        try:
            data = response.document()
        except Exception:
            raise ProviderError("Gemini API returned invalid JSON") from None

        if not isinstance(data, dict):
            raise ProviderError("Gemini API returned an invalid response")

        prompt_feedback = data.get("promptFeedback")
        if isinstance(prompt_feedback, dict) and prompt_feedback.get("blockReason"):
            raise ProviderError("Gemini model refused the request")

        candidates = data.get("candidates")
        if (
            not isinstance(candidates, list)
            or not candidates
            or not isinstance(candidates[0], dict)
        ):
            raise ProviderError("Gemini API returned an invalid response")

        candidate = candidates[0]
        finish_reason = candidate.get("finishReason")
        if finish_reason in _REFUSAL_REASONS:
            raise ProviderError(f"Gemini model refused the request ({finish_reason})")
        if finish_reason == "MAX_TOKENS":
            raise ProviderError(
                f"Gemini response is incomplete: reached maxOutputTokens ({max_output_tokens}); "
                "output was truncated"
            )
        if finish_reason != "STOP":
            raise ProviderError(f"Gemini response is incomplete (finishReason: {finish_reason})")

        content = candidate.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        if not isinstance(parts, list) or not parts:
            raise ProviderError("Gemini API returned an invalid response")

        text_parts: list[str] = []
        for part in parts:
            if not isinstance(part, dict):
                raise ProviderError("Gemini API returned an invalid response")
            if "functionCall" in part or "executableCode" in part:
                raise ProviderError("Gemini response attempted unauthorized tool execution")
            if "text" in part:
                if not isinstance(part["text"], str):
                    raise ProviderError("Gemini API returned an invalid response")
                text_parts.append(part["text"])

        text = "\n".join(text_parts)
        if not text.strip():
            raise ProviderError("Gemini API returned an invalid response")

        usage = data.get("usageMetadata")
        if not isinstance(usage, dict):
            raise ProviderError("Gemini API returned an invalid response")

        inputs = usage.get("promptTokenCount")
        outputs = usage.get("candidatesTokenCount", 0)
        thoughts = usage.get("thoughtsTokenCount", 0)
        cached = usage.get("cachedContentTokenCount", 0)
        if (
            type(inputs) is not int
            or inputs < 0
            or type(outputs) is not int
            or outputs < 0
            or type(thoughts) is not int
            or thoughts < 0
            or type(cached) is not int
            or cached < 0
        ):
            raise ProviderError("Gemini API returned an invalid response")

        billed_outputs = outputs + thoughts
        total_tokens = usage.get("totalTokenCount")
        if total_tokens is not None and (type(total_tokens) is not int or total_tokens < 0):
            raise ProviderError("Gemini API returned an invalid response")
        if type(total_tokens) is int and total_tokens > inputs + billed_outputs:
            billed_outputs = total_tokens - inputs

        return text, inputs, billed_outputs


def gemini_review_service(
    config: AIConfig,
    ledger,
    provider,
    evidence: dict,
    *,
    language: str = "en",
):
    """Construct a BudgetedAI service configured for structured Gemini evidence review."""
    validate_report_language(language)
    validate_gemini_model(config.model)
    expected = {row["evidence_id"] for row in evidence["findings"]}
    contract_json = json.dumps(GEMINI_RESPONSE_SCHEMA, sort_keys=True)
    return (
        BudgetedAI(
            config,
            ledger,
            provider,
            instructions=review_instructions(language),
            response_validator=lambda text: validate_review(text, expected),
            extra_input_bytes=len(
                json.dumps(
                    {
                        "responseMimeType": "application/json",
                        "responseSchema": GEMINI_RESPONSE_SCHEMA,
                    }
                ).encode("utf-8")
            ),
            response_contract=contract_json,
            provider_id="gemini",
            language=language,
        ),
        evidence,
    )


def gemini_review_result(
    config: AIConfig,
    ledger,
    client,
    report: dict,
    *,
    dry_run: bool = False,
    packet_index: int | None = None,
    group_size: int = 3,
    language: str = "en",
    timeout: int = 30,
    expected_evidence_sha256: str | None = None,
) -> dict:
    """Execute or dry-run a grounded Gemini advisory review for a selected evidence packet."""
    validate_report_language(language)
    validate_gemini_model(config.model)
    integer(timeout, 1, 120, "Gemini request timeout")
    selected, index, total = select_packet(
        report,
        config.max_input_bytes,
        packet_index=packet_index,
        group_size=group_size,
    )
    prepared_digest = evidence_digest(
        json.loads(compact_evidence(selected, config.max_input_bytes)))
    if expected_evidence_sha256 is not None and expected_evidence_sha256 != prepared_digest:
        raise ValidationError("Evidence changed after preview; no API request was sent")
    adapter = GeminiGenerateContent(
        client,
        response_schema=GEMINI_RESPONSE_SCHEMA,
        timeout=timeout,
    )
    service, evidence = gemini_review_service(
        config,
        ledger,
        adapter,
        selected,
        language=language,
    )
    result = service.explain(evidence, dry_run=dry_run)
    if "text" in result:
        result["interpretation"] = validate_review(
            result.pop("text"),
            {row["evidence_id"] for row in evidence["findings"]},
        )
    result.update(
        {
            "schema_version": 1,
            "mode": "advisory_interpretation",
            "provider": "gemini",
            "packet_index": index,
            "packet_count": total,
            "packet_finding_count": len(evidence["findings"]),
            "total_finding_count": len(report["findings"]),
            "evidence_sha256": evidence_digest(
                json.loads(compact_evidence(evidence, config.max_input_bytes))
            ),
            "not_checked": report["not_checked"],
            "notice": (
                "AI advice is unverified interpretation of supplied observations. "
                "Reference validation does not establish factual correctness. "
                "Original tool findings and limitations remain authoritative. "
                "No commands, code or model-proposed tools are executed."
            ),
        }
    )
    if language != "en":
        result["report_language"] = language
    return result


def gemini_explain_result(
    config: AIConfig,
    ledger,
    client,
    document: dict,
    *,
    dry_run: bool = False,
    language: str = "en",
    timeout: int = 30,
) -> dict:
    """Execute or dry-run a budgeted Gemini plain-text explanation."""
    validate_report_language(language)
    validate_gemini_model(config.model)
    integer(timeout, 1, 120, "Gemini request timeout")
    adapter = GeminiGenerateContent(client, response_schema=None, timeout=timeout)
    instructions = (
        INSTRUCTIONS
        if language == "en"
        else INSTRUCTIONS + " Write your explanation in Polish (pl)."
    )
    ai = BudgetedAI(
        config,
        ledger,
        adapter,
        instructions=instructions,
        provider_id="gemini",
        language=language,
    )
    result = ai.explain(document, dry_run=dry_run)
    result["provider"] = "gemini"
    if language != "en":
        result["report_language"] = language
    return result


def build_sample_validated_ai_response(
    report: dict,
    *,
    language: str = "en",
    packet_index: int | None = 1,
    group_size: int = 3,
    max_input_bytes: int = 12000,
) -> dict:
    """Build a deterministic, schema-validated sample AI response in 'en' or 'pl' for testing."""
    validate_report_language(language)
    pl = language == "pl"
    selected, index, total = select_packet(
        report,
        max_input_bytes,
        packet_index=packet_index,
        group_size=group_size,
    )
    by_id = {row["id"]: row for row in report.get("findings", [])}
    observations = []
    for item in selected["findings"]:
        eid = item["evidence_id"]
        raw_finding = by_id.get(eid, item)
        detail = describe_finding(
            raw_finding,
            target=raw_finding.get("target"),
            language=language,
        )
        loc = detail.file_path or raw_finding.get("target", "(aliased target)")
        if detail.line_number is not None:
            loc = f"{loc}:{detail.line_number}"
        if pl:
            observations.append(
                {
                    "evidence_id": eid,
                    "explanation": (
                        f"{detail.title}: {detail.mechanism} "
                        f"Potencjalny skutek: {detail.consequences}"
                    ),
                    "what_to_review": (
                        f"Sprawdź wskazane miejsce w kodzie/konfiguracji ({loc}) oraz przepływ "
                        f"danych wejściowych. Dowód skanera: {item['evidence']}."
                    ),
                    "suggested_remediation": (
                        f"{detail.recommendation} Weryfikacja: {detail.verification_steps}"
                    ),
                }
            )
        else:
            observations.append(
                {
                    "evidence_id": eid,
                    "explanation": (
                        f"{detail.title}: {detail.mechanism} "
                        f"Potential impact: {detail.consequences}"
                    ),
                    "what_to_review": (
                        f"Inspect the reported location ({loc}) and verify whether untrusted "
                        f"input reaches this operation. Scanner evidence: {item['evidence']}."
                    ),
                    "suggested_remediation": (
                        f"{detail.recommendation} Verification: {detail.verification_steps}"
                    ),
                }
            )

    summary = (
        f"Przegląd doradczy pakietu {index}/{total}: przeanalizowano {len(observations)} "
        "obserwacji ze skanera statycznego. Wszystkie wpisy mają charakter kandydatów "
        "wymagających ręcznej weryfikacji kontekstu."
        if pl
        else f"Advisory review of packet {index}/{total}: interpreted {len(observations)} "
        "static scanner observation(s). All items remain candidates requiring human "
        "context verification."
    )
    uncertainty = (
        "Analiza opiera się wyłącznie na statycznych obserwacjach offline. Model nie uruchamiał "
        "kodu, nie potwierdził osiągalności ścieżek w czasie wykonania i nie zastępuje pełnego "
        "audytu bezpieczeństwa. Obowiązują wszystkie ograniczenia z sekcji not_checked."
        if pl
        else "This interpretation is based solely on bounded offline static observations. "
        "No code was executed, runtime reachability was not proven, and all not_checked "
        "limitations from the technical report remain in force."
    )
    raw_payload = {
        "summary": summary,
        "observations": observations,
        "uncertainty": uncertainty,
    }
    raw_json = json.dumps(raw_payload, ensure_ascii=False)
    expected_ids = {row["evidence_id"] for row in selected["findings"]}
    validated = validate_review(raw_json, expected_ids)
    composite = attach_ai_interpretation(
        report,
        raw_json,
        expected_ids=expected_ids,
        language=language,
        preserve_on_error=False,
    )
    return {
        "language": language,
        "packet_index": index,
        "packet_count": total,
        "raw_response": raw_payload,
        "validated_review": validated,
        "composite_report": composite,
    }
