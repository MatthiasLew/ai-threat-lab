"""Small offline Python AST reviewer; findings are candidates for human review."""

import ast
import io
import json
import tokenize
from dataclasses import asdict, dataclass
from pathlib import Path

from .models import ValidationError

MAX_SOURCE_BYTES = 256 * 1024
LIMITATIONS = (
    "Heuristic Python AST checks only; findings are candidates, not validated vulnerabilities.",
    "No data-flow, dependency, alias-rebinding or comprehensive scope analysis is performed.",
    "Only direct imports/simple import aliases and literal keyword arguments are recognized.",
    "A clean result does not establish that code is secure. Source is never executed or uploaded.",
)


@dataclass(frozen=True)
class CodeFinding:
    rule_id: str
    line: int
    column: int
    severity: str
    title: str
    rationale: str
    recommendation: str


@dataclass(frozen=True)
class CodeReviewResult:
    filename: str
    findings: tuple[CodeFinding, ...]
    limitations: tuple[str, ...] = LIMITATIONS
    engine: str = "python-ast-1.0"


def _qualified_name(node: ast.expr, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def review_source(source: str, filename: str = "<snippet>") -> CodeReviewResult:
    """Inspect source without importing it, evaluating expressions, or calling a provider."""
    if not isinstance(source, str):
        raise ValidationError("Python source must be text")
    try:
        if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise ValidationError(f"Python source exceeds the {MAX_SOURCE_BYTES}-byte limit")
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ValidationError):
            raise
        line = getattr(exc, "lineno", None)
        # Do not echo source text: a syntax error can contain secrets or private code.
        raise ValidationError(f"Cannot parse Python source (line {line or 'unknown'})") from exc
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _qualified_name(node.func, aliases)
        rule = None
        if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            rule = (
                "PY001",
                "High",
                "Dynamic code execution",
                "Untrusted input reaching eval/exec could execute arbitrary Python code.",
                "Avoid dynamic execution; parse a restricted data format "
                "or use explicit operations.",
            )
        elif name in (
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        ) and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            rule = (
                "PY002",
                "High",
                "Shell command interpretation enabled",
                "shell=True can interpret metacharacters if untrusted input reaches the command.",
                "Use an argument list with shell=False and validate allowed commands/arguments.",
            )
        elif name in ("pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"):
            rule = (
                "PY003",
                "High",
                "Potentially unsafe deserialization",
                "Loading a pickle from an untrusted source can execute code.",
                "Use a data-only format such as JSON for untrusted input; confirm provenance.",
            )
        elif name in {
            f"requests.{method}"
            for method in ("get", "post", "put", "patch", "delete", "head", "options", "request")
        } and any(
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        ):
            rule = (
                "PY004",
                "Medium",
                "TLS certificate verification disabled",
                "verify=False prevents normal server-certificate verification.",
                "Enable certificate verification and configure a trusted CA bundle when necessary.",
            )
        if rule:
            rule_id, severity, title, rationale, recommendation = rule
            findings.append(
                CodeFinding(
                    rule_id,
                    node.lineno,
                    node.col_offset + 1,
                    severity,
                    title,
                    rationale,
                    recommendation,
                )
            )
    return CodeReviewResult(filename, tuple(sorted(findings, key=lambda f: (f.line, f.column))))


def review_file(path: Path) -> CodeReviewResult:
    path = Path(path)
    if path.suffix.lower() != ".py":
        raise ValidationError("Code review currently accepts a single .py file")
    with path.open("rb") as source_file:
        raw = source_file.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValidationError(f"Python file exceeds the {MAX_SOURCE_BYTES}-byte limit")
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        source = raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError) as exc:
        raise ValidationError("Cannot decode Python source encoding") from exc
    return review_source(source, str(path))


def render_code_review(result: CodeReviewResult, format: str = "txt") -> str:
    if format == "json":
        return (
            json.dumps(
                {"schema_version": 1, "review": asdict(result)}, ensure_ascii=False, indent=2
            )
            + "\n"
        )
    if format != "txt":
        raise ValidationError("Report format must be txt or json")
    lines = [
        "AI THREAT LAB — OFFLINE PYTHON REVIEW",
        f"Engine: {result.engine}",
        f"File: {result.filename}",
        f"Candidate findings: {len(result.findings)}",
    ]
    for finding in result.findings:
        lines.extend(
            [
                "",
                f"{finding.rule_id} | {finding.severity} | "
                f"line {finding.line}, column {finding.column}: {finding.title}",
                finding.rationale,
                f"Recommendation: {finding.recommendation}",
            ]
        )
    lines.extend(["", "LIMITATIONS", *[f"- {item}" for item in result.limitations]])
    return "\n".join(lines) + "\n"
