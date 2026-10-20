"""Target routing and honest capability results for local/optional remote adapters."""

import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from .code_review import read_python_source, review_source
from .models import ValidationError, require_text


@dataclass(frozen=True)
class AssessmentFinding:
    check: str
    status: str
    evidence: str
    recommendation: str

    def __post_init__(self) -> None:
        for label in ("check", "evidence", "recommendation"):
            require_text(getattr(self, label), label)
        if self.status not in ("candidate", "unverified", "confirmed"):
            raise ValidationError("Invalid assessment finding status")


@dataclass(frozen=True)
class AssessmentResult:
    target: str
    target_kind: str
    status: str
    findings: tuple[AssessmentFinding, ...]
    not_checked: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text(self.target, "target")
        require_text(self.target_kind, "target_kind")
        if self.status not in ("partial", "completed", "not_configured"):
            raise ValidationError("Invalid assessment result status")
        if not isinstance(self.findings, (list, tuple)) or not all(
            isinstance(f, AssessmentFinding) for f in self.findings
        ):
            raise ValidationError("findings must contain AssessmentFinding values")
        if not isinstance(self.not_checked, (list, tuple)):
            raise ValidationError("not_checked must be an array")
        for item in self.not_checked:
            require_text(item, "not_checked item")
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "not_checked", tuple(self.not_checked))


class TargetAdapter(Protocol):
    def assess(self, target: str) -> AssessmentResult:
        """Return evidence-backed results; unsupported checks must remain not_checked."""
        ...


def identify_target(target: str) -> str:
    require_text(target, "target")
    if target.startswith("mailbox:"):
        account = target.removeprefix("mailbox:")
        if not re.fullmatch(r"[^\s@<>:]+@[^\s@<>:]+\.[^\s@<>:]+", account):
            raise ValidationError("Use mailbox:user@example.com without credentials")
        return "mailbox_account"
    if target.startswith("mail-domain:"):
        domain = target.removeprefix("mail-domain:")
        labels = domain.split(".")
        if (
            len(domain) > 253
            or len(labels) < 2
            or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in labels
            )
        ):
            raise ValidationError("Use mail-domain:example.com")
        return "mail_domain"
    try:
        url = urlparse(target)
        _ = url.port  # Validate URL syntax even before a remote adapter is configured.
    except ValueError as exc:
        raise ValidationError("Invalid target URL") from exc
    if url.scheme in ("http", "https"):
        if not url.hostname or url.username or url.password:
            raise ValidationError("URL needs a host and must not contain embedded credentials")
        if url.hostname.lower() == "github.com":
            parts = [p for p in url.path.strip("/").split("/") if p]
            if len(parts) != 2 or url.query or url.fragment:
                raise ValidationError("Provide a GitHub repository root URL")
            return "github_repository"
        return "website"
    if "://" in target:
        raise ValidationError("Only HTTP(S) URLs or local paths are accepted")
    path = Path(target)
    if not path.exists():
        raise ValidationError("Local target does not exist; use a full URL for a website")
    if path.is_dir():
        return "local_project"
    if path.name.lower().endswith(".ssh.jsonl"):
        return "ssh_journal"
    if path.name.lower().endswith(".auth.jsonl"):
        return "authentication_log"
    if path.suffix.lower() == ".py":
        return "python_source"
    if path.suffix.lower() in (".html", ".htm"):
        return "html_document"
    if path.suffix.lower() == ".eml":
        return "mail_message"
    return "program_file"


def audit_message(path: Path) -> AssessmentResult:
    """Read one exported message. Authentication headers are observations, never trust proofs."""
    from .mail_review import inspect_message_content

    if path.is_symlink() or getattr(path, "is_junction", lambda: False)() or not path.is_file():
        raise ValidationError("Mail message must be a regular file, not a symlink/junction")
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValidationError("Mail message exceeds the 1 MiB limit")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (RecursionError, ValueError, IndexError):
        raise ValidationError(
            "Cannot parse mail message within supported structural limits"
        ) from None
    findings = []
    if message.defects:
        findings.append(
            AssessmentFinding(
                "message_format",
                "candidate",
                "The parser reported malformed message structure.",
                "Review the original message.",
            )
        )
    auth = "\n".join(str(value) for value in message.get_all("Authentication-Results", []))
    if re.search(r"\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|permerror|temperror)\b", auth, re.I):
        findings.append(
            AssessmentFinding(
                "reported_authentication_failure",
                "candidate",
                "An Authentication-Results header reports a failure; this header can be forged.",
                "Verify the trusted receiving server's authentication results and logs.",
            )
        )
    elif auth:
        findings.append(
            AssessmentFinding(
                "authentication_header",
                "unverified",
                "Authentication-Results is present; provenance and results are unverified.",
                "Use receiving-server evidence before treating the sender as authenticated.",
            )
        )
    reply_to = message.get("Reply-To")
    sender = message.get("From")
    if reply_to and sender and str(reply_to).casefold() != str(sender).casefold():
        findings.append(
            AssessmentFinding(
                "different_reply_to",
                "candidate",
                "Reply-To differs from From; legitimate mailing systems can also do this.",
                "Check the reply destination against a previously trusted contact.",
            )
        )
    content_findings, content_notices = inspect_message_content(message)
    findings.extend(content_findings)
    from .attachment_review import inspect_message_attachments

    try:
        attachment_findings, attachment_notices = inspect_message_attachments(message)
        findings.extend(attachment_findings)
    except (ValidationError, ValueError, RecursionError, IndexError):
        attachment_notices = (
            "Attachment structure review unavailable; message evidence retained.",
        )
    return AssessmentResult(
        str(path),
        "mail_message",
        "partial",
        tuple(findings),
        (
            "Mailbox MFA, forwarding rules, permissions and account access were not checked.",
            "SPF/DKIM/DMARC DNS and cryptographic signatures were not verified.",
            "Bounded text links, selected HTML forms, attachment metadata and decoded "
            "attachment structures were analyzed offline; no links were visited, "
            "attachment files extracted/executed or sender reputation queried.",
            "Header observations alone cannot establish phishing or authenticity.",
            "HTML/CSS rendering, redirects, URL decoding tricks, office/PDF active content "
            "and malware detection are outside these selected checks.",
        )
        + content_notices + attachment_notices,
    )


class AssessmentService:
    def __init__(self, adapters: dict[str, TargetAdapter] | None = None) -> None:
        self.adapters = dict(adapters or {})

    def assess(self, target: str) -> AssessmentResult:
        kind = identify_target(target)
        if kind in self.adapters:
            result = self.adapters[kind].assess(target)
            if (
                not isinstance(result, AssessmentResult)
                or result.target_kind != kind
                or result.target != target
            ):
                raise ValidationError("Assessment adapter returned an invalid result")
            return result
        if kind == "ssh_journal":
            from .ssh_journal_review import review_ssh_journal_file

            return review_ssh_journal_file(target)
        if kind == "authentication_log":
            from .auth_log_review import review_auth_log_file

            return review_auth_log_file(target)
        if kind == "html_document":
            from .html_review import review_html_file

            return review_html_file(target)
        if kind == "mail_message":
            return audit_message(Path(target))
        if kind in ("python_source", "local_project"):
            paths = [Path(target)]
            omitted = 0
            traversal_limited = False
            walk_errors = []
            if kind == "local_project":
                # Walk deterministically, do not follow directory symlinks or dependency folders.
                import os

                paths = []
                excluded = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
                visited = examined = 0
                for directory, dirs, filenames in os.walk(
                    target, followlinks=False, onerror=walk_errors.append
                ):
                    visited += 1
                    if visited > 1000:
                        traversal_limited = True
                        break
                    dirs[:] = sorted(
                        d
                        for d in dirs
                        if d not in excluded and not (Path(directory) / d).is_symlink()
                    )
                    for filename in sorted(filenames):
                        examined += 1
                        if examined > 10000:
                            traversal_limited = True
                            break
                        candidate = Path(directory) / filename
                        if candidate.suffix == ".py" and not candidate.is_symlink():
                            if len(paths) < 100:
                                paths.append(candidate)
                            else:
                                omitted += 1
                    if traversal_limited:
                        break
            from .python_flow import NOTICE as FLOW_NOTICE

            findings = []
            missing = [
                FLOW_NOTICE,
                "Only selected Python AST patterns were checked; no execution or full audit.",
            ]
            project_sources, unavailable_sources = [], []
            for path in paths:
                decoded = False
                origin = (
                    path.relative_to(Path(target)).as_posix()
                    if kind == "local_project"
                    else path.name
                )
                try:
                    source = read_python_source(path)
                    decoded = True
                    if kind == "local_project":
                        project_sources.append((origin, source))
                    result = review_source(source, str(path))
                except (ValidationError, OSError) as exc:
                    if kind == "local_project" and not decoded:
                        unavailable_sources.append(origin)
                    missing.append(f"Skipped {path}: {type(exc).__name__}")
                    continue
                missing.extend(
                    f"{path}: {notice}"
                    for notice in result.limitations
                    if notice.startswith("Flow coverage:") and notice != FLOW_NOTICE
                )
                findings.extend(
                    AssessmentFinding(
                        f.rule_id,
                        "candidate",
                        f"{path}:{f.line}:{f.column} — {f.title}"
                        + (f". {f.rationale}" if f.rule_id in ("PY013", "PY014") else ""),
                        f.recommendation,
                    )
                    for f in result.findings
                )
            if kind == "local_project":
                from .python_project_flow import project_flows

                extra, notices = project_flows(project_sources, unavailable=unavailable_sources)
                findings.extend(extra)
                missing.extend(notices)
            if traversal_limited:
                missing.append("Python traversal stopped at the 1000-directory/10000-entry limit.")
            for err in walk_errors:
                err_path = getattr(err, "filename", None) or target
                missing.append(f"Skipped directory {err_path}: {type(err).__name__}")
            if not paths:
                missing.append("No Python source files were found.")
            if omitted:
                missing.append(f"The 100-file limit excluded {omitted} additional Python files.")
            return AssessmentResult(target, kind, "partial", tuple(findings), tuple(missing))
        checks = {
            "mailbox_account": "Mailbox settings need a scoped, authenticated provider adapter.",
            "mail_domain": "SPF/DKIM/DMARC checks need a DNS/domain audit adapter.",
            "github_repository": "Repository retrieval and source review need an adapter.",
            "website": "Web checks need a scoped HTTP/TLS assessment adapter.",
            "program_file": "Binary inspection needs a format-specific adapter.",
        }
        return AssessmentResult(target, kind, "not_configured", (), (checks[kind],))
