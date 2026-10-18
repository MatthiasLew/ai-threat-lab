"""Offline, source-free SARIF export for the bounded Python pattern reviewer."""

import json
from pathlib import Path
from urllib.parse import quote

from .code_review import CodeReviewResult
from .models import ValidationError

SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)


def render_sarif(result: CodeReviewResult, *, source_root: Path | None = None) -> str:
    """Use a basename by default, or a resolved path inside an explicitly supplied root.

    AST columns count UTF-8 bytes; SARIF regions deliberately use lines only.
    No source reread, snippet, absolute root, environment or invocation is exported.
    """
    path = Path(result.filename)
    if source_root is None:
        relative = path.name
    else:
        root = Path(source_root).resolve(strict=True)
        if not root.is_dir():
            raise ValidationError("SARIF source root must be a directory")
        try:
            relative = path.resolve(strict=True).relative_to(root).as_posix()
        except ValueError as exc:
            raise ValidationError("SARIF source must be inside the supplied root") from exc
    if not relative:
        raise ValidationError("SARIF requires a source filename")
    uri = quote(relative, safe="/")
    by_rule = {finding.rule_id: finding for finding in result.findings}
    rule_ids = sorted(by_rule)
    indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": by_rule[rule_id].title},
            "fullDescription": {"text": by_rule[rule_id].rationale},
            "help": {"text": by_rule[rule_id].recommendation},
            "defaultConfiguration": {"level": "warning"},
        }
        for rule_id in rule_ids
    ]
    results = [
        {
            "ruleId": finding.rule_id,
            "ruleIndex": indexes[finding.rule_id],
            "level": "warning",
            "message": {
                "text": f"{finding.title}. {finding.rationale} "
                f"Recommendation: {finding.recommendation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "index": 0},
                        "region": {"startLine": finding.line},
                    }
                }
            ],
            "properties": {
                "candidateOnly": True,
                "patternSeverity": finding.severity,
                "pythonUtf8ByteColumn": finding.column,
            },
        }
        for finding in result.findings
    ]
    payload = {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AI Threat Lab Python review", "rules": rules}},
                "columnKind": "unicodeCodePoints",
                "artifacts": [{"location": {"uri": uri}, "sourceLanguage": "python"}],
                "results": results,
                "properties": {
                    "engine": result.engine,
                    "candidateOnly": True,
                    "limitations": list(result.limitations),
                    "pathMode": "basename" if source_root is None else "root-relative",
                    "locationPrecision": "line-only",
                },
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
