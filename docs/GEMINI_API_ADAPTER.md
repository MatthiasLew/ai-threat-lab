# Google Gemini API Adapter & Integration Contract (Stage 3)

This document specifies the architecture, wire contract, security controls, and offline verification framework for the Google Gemini API integration in AI Threat Lab.

## 1. Overview & Operational Model

AI Threat Lab features an offline-first architecture. Direct live network calls to commercial AI endpoints are disabled during local auditing and automated testing.

The Gemini adapter module (`src/ai_threat_lab/gemini_adapter.py`) implements a strictly bounded REST client targeting Google Gemini's `v1beta/models/{model}:generateContent` endpoint:
- **Default Model**: `gemini-2.5-flash`
- **Supported Models**: `gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-1.5-flash`, `gemini-1.5-pro`
- **Response Format**: Strictly enforced JSON schema via `responseSchema` and `responseMimeType: "application/json"`.
- **System Constraints**: Tools and function calling are unconditionally blocked (`tools: []`).

---

## 2. Security Controls & Defensive Design

### API Key Redaction in All Failure Modes
Under no circumstances is an API key printed to standard output, written into logs, or stored in exception traces.
All network errors, HTTP 4xx/5xx statuses, socket errors, and JSON decode failures pass through `redact_api_key()`:
- Matches query parameters (`?key=...`, `&key=...`).
- Matches bearer tokens and authorization headers.
- Masks the secret as `[REDACTED_API_KEY]` before bubble-up.

### Prompt Injection & Raw Code Isolation
- No arbitrary executable code is sent to the LLM.
- Analyzed source code files are parsed locally into structured AST findings and metadata.
- Packets are passed with explicit system instruction boundaries and strict JSON-only instructions.
- Sensitive strings and high-entropy credentials detected during local scanning are automatically redacted (`[REDACTED_SECRET]`) prior to forming AI payloads.

### Deterministic Cache Isolation
AI requests are protected by a cryptographic cache key calculated using SHA-256:
- Includes: `provider`, `model`, `schema_version`, `language`, `temperature`, `max_output_tokens`, and the exact `evidence_digest`.
- Guarantees cache key isolation between providers (`gemini` vs `openai`) and languages (`pl` vs `en`).
- Backward compatibility: Preserves existing cache entries for OpenAI English responses without cache invalidation.

---

## 3. Gemini REST Wire Specification

### Request Payload (`POST /v1beta/models/{model}:generateContent?key={API_KEY}`)

```json
{
  "contents": [
    {
      "role": "user",
      "parts": [
        {"text": "{\"task\": \"security_interpretation\", \"language\": \"pl\", ...}"}
      ]
    }
  ],
  "systemInstruction": {
    "parts": [
      {"text": "You are a senior application security reviewer. Provide accurate interpretations in JSON."}
    ]
  },
  "generationConfig": {
    "temperature": 0.1,
    "topP": 0.95,
    "maxOutputTokens": 2048,
    "responseMimeType": "application/json",
    "responseSchema": {
      "type": "object",
      "properties": {
        "summary": {"type": "string"},
        "risk_level": {"type": "string", "enum": ["none", "low", "medium", "high", "critical"]},
        "findings": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {"type": "string"},
              "title": {"type": "string"},
              "explanation": {"type": "string"},
              "recommendation": {"type": "string"}
            },
            "required": ["id", "title", "explanation", "recommendation"]
          }
        },
        "limitations": {"type": "array", "items": {"type": "string"}},
        "language": {"type": "string"}
      },
      "required": ["summary", "risk_level", "findings", "limitations", "language"]
    }
  }
}
```

---

## 4. Validated Reference Responses

### Reference Response (Polish: `pl`)

```json
{
  "summary": "Analiza wykryła 1 potencjalną podatność o niskim priorytecie: niezaszyfrowany transport HTTP.",
  "risk_level": "low",
  "findings": [
    {
      "id": "PY003-1",
      "title": "Niezabezpieczone połączenie HTTP",
      "explanation": "Wykryto użycie protokołu http:// w zapytaniach sieciowych lub konfiguracji, co umożliwia podsłuch lub modyfikację ruchu.",
      "recommendation": "Zastąp adresy http:// bezpiecznym protokołem https:// i zweryfikuj poprawność certyfikatów TLS."
    }
  ],
  "limitations": [
    "Analiza statyczna oparta na AST bez uwzględnienia dynamicznych przekierowań sieciowych."
  ],
  "language": "pl"
}
```

### Reference Response (English: `en`)

```json
{
  "summary": "Analysis identified 1 low-priority potential issue regarding unencrypted HTTP transport.",
  "risk_level": "low",
  "findings": [
    {
      "id": "PY003-1",
      "title": "Insecure HTTP Transport",
      "explanation": "Detected usage of http:// in network requests, making network traffic vulnerable to interception or modification.",
      "recommendation": "Replace http:// endpoints with https:// and enforce TLS certificate validation."
    }
  ],
  "limitations": [
    "Static AST analysis without evaluation of dynamic runtime redirection."
  ],
  "language": "en"
}
```

---

## 5. Offline Test Matrix & Coverage

The test suite in `tests/test_stage3_gemini_cache_and_perf.py` covers 20 explicit offline scenarios:

1. **Successful Generation**: Validates payload parsing and schema conformance.
2. **Missing API Key**: Raises error before issuing network call; validates key redaction.
3. **Invalid Model Rejection**: Rejects models outside the approved Gemini whitelist.
4. **HTTP 400 Bad Request**: Graceful error handling with query key masked in error message.
5. **HTTP 401 Unauthorized**: Key masked as `[REDACTED_API_KEY]`.
6. **HTTP 403 Forbidden**: Redacts API key and signals quota/permission limits.
7. **HTTP 429 Rate Limit**: Signals retry after backoff, tracks exhaustion.
8. **HTTP 500/503 Transient Server Error**: Properly categorizes upstream failures.
9. **JSON Decode Error**: Handles corrupt upstream bodies gracefully.
10. **Schema Invalidation**: Rejects payloads that do not match the expected structural envelope.
11. **Safety Block / Content Refusal**: Handles `finishReason: "SAFETY"` without crashing.
12. **Model Refusal**: Handles `finishReason: "RECITATION"` or empty candidate lists.
13. **Budget Exceeded (Foreground)**: Enforces hard token limits and budget checks.
14. **Budget Exceeded (Background)**: Rejects execution when run allocation is exhausted.
15. **Language Parity**: Validates structured output schema and generation for both `pl` and `en`.
16. **Dry Run / Offline Mocking**: Allows end-to-end rehearsal without live connections.
17. **Tool Disabling Verification**: Confirms `tools` and function declarations are omitted.
18. **Prompt Injection Boundary**: Checks that untrusted strings do not leak into top-level JSON structures.
19. **Cache Isolation**: Confirms distinct cache keys across providers and languages.
20. **Legacy Cache Backward Compatibility**: Confirms existing OpenAI cache hits remain valid.
