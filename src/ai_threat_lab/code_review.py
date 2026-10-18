"""Small offline Python AST reviewer; findings are candidates for human review."""

import ast
import io
import json
import tokenize
from dataclasses import asdict, dataclass
from pathlib import Path

from .models import ValidationError
from .python_web_patterns import web_rule

MAX_SOURCE_BYTES = 256 * 1024
LIMITATIONS = (
    "Heuristic Python AST checks only; findings are candidates, not validated vulnerabilities.",
    "No data-flow, dependency, alias-rebinding or comprehensive scope analysis is performed.",
    "Direct imports/simple aliases, literal keywords and selected explicit API/loader names only.",
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
    engine: str = "python-ast-1.2"


def _qualified_name(node: ast.expr, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _unsafe_yaml(node, name, aliases):
    if name in ("yaml.unsafe_load", "yaml.unsafe_load_all"):
        return True
    if name not in ("yaml.load", "yaml.load_all"):
        return False
    loader = next((k.value for k in node.keywords if k.arg == "Loader"), None)
    if loader is None and len(node.args) >= 2:
        loader = node.args[1]
    return _qualified_name(loader, aliases) in (
        "yaml.Loader",
        "yaml.UnsafeLoader",
        "yaml.CLoader",
        "yaml.CUnsafeLoader",
    )


def _weak_digest(node, name):
    if any(
        k.arg == "usedforsecurity" and isinstance(k.value, ast.Constant) and k.value.value is False
        for k in node.keywords
    ):
        return False
    if name in ("hashlib.md5", "hashlib.sha1"):
        return True
    if name != "hashlib.new":
        return False
    algorithm = (
        node.args[0]
        if node.args
        else next((k.value for k in node.keywords if k.arg == "name"), None)
    )
    return (
        isinstance(algorithm, ast.Constant)
        and isinstance(algorithm.value, str)
        and (algorithm.value.lower() in ("md5", "sha1", "sha-1"))
    )


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
        elif name in ("os.system", "os.popen"):
            rule = (
                "PY005",
                "High",
                "Operating-system shell API",
                "The call invokes a shell; command injection depends on command provenance.",
                "Prefer subprocess argument lists with shell=False; review allowed operations "
                "and trace untrusted input before treating this as a vulnerability.",
            )
        elif name == "tempfile.mktemp":
            rule = (
                "PY006",
                "Medium",
                "Temporary filename without atomic file creation",
                "Separating a temporary name from file creation can permit a race.",
                "Use NamedTemporaryFile or mkstemp, manage cleanup and review platform semantics.",
            )
        elif name == "ssl._create_unverified_context":
            rule = (
                "PY007",
                "Medium",
                "Unverified TLS-context helper",
                "This helper defaults to an unverified context; overrides and later changes "
                "are not evaluated.",
                "Prefer create_default_context or PROTOCOL_TLS_CLIENT and review the effective "
                "certificate/hostname verification settings.",
            )
        elif _unsafe_yaml(node, name, aliases):
            rule = (
                "PY008",
                "High",
                "Explicit unsafe YAML loading API",
                "Unsafe constructors can instantiate objects when attacker-controlled YAML "
                "reaches this call; input trust is not established here.",
                "Prefer safe_load/safe_load_all or an explicitly restricted loader and validate "
                "the resulting data schema.",
            )
        elif _weak_digest(node, name):
            rule = (
                "PY009",
                "Medium",
                "MD5 or SHA-1 digest requires security-context review",
                "These digests have collision weaknesses; this check does not determine "
                "whether the use is cryptographic or an ordinary checksum.",
                "Use a suitable modern primitive for security-sensitive integrity. If the "
                "operation is explicitly non-security, document that intent; use an appropriate "
                "password KDF for passwords rather than a fast digest.",
            )
        if rule is None:
            rule = web_rule(node, name)
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


def render_code_review(
    result: CodeReviewResult, format: str = "txt", *, source_root: Path | None = None
) -> str:
    if source_root is not None and format != "sarif":
        raise ValidationError("Source root is only supported for SARIF export")
    if format == "sarif":
        from .sarif import render_sarif

        return render_sarif(result, source_root=source_root)
    if format == "json":
        return (
            json.dumps(
                {"schema_version": 1, "review": asdict(result)}, ensure_ascii=False, indent=2
            )
            + "\n"
        )
    if format != "txt":
        raise ValidationError("Report format must be txt, json or sarif")
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
