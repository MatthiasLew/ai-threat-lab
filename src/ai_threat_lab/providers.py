"""Explicit dependency injection; configuration never imports code or stores credentials."""

from dataclasses import asdict, dataclass

from .assessment import AssessmentResult, AssessmentService
from .campaigns import DeliveryReceipt, DemoTransport, TemplateContentProvider, TrainingContent
from .models import ValidationError, require_text

TARGET_KINDS = frozenset(
    (
        "github_repository",
        "website",
        "python_source",
        "local_project",
        "mail_message",
        "mail_domain",
        "mailbox_account",
        "program_file",
        "html_document",
        "authentication_log",
        "ssh_journal",
    )
)


class ProviderError(RuntimeError):
    """Redacted integration failure; callers must not retry dispatch blindly."""

    def __init__(
        self,
        message: str = "",
        *,
        category: str | None = None,
        diagnosis=None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.diagnosis = diagnosis


@dataclass(frozen=True)
class ProviderConfig:
    content: str = "template"
    assessment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        require_text(self.content, "content provider")
        seen = set()
        for kind, name in self.assessment:
            if kind not in TARGET_KINDS or kind in seen:
                raise ValidationError("Unknown or duplicate assessment target kind")
            require_text(name, "assessment provider")
            seen.add(kind)
        object.__setattr__(self, "assessment", tuple(sorted(self.assessment)))


class GuardedContent:
    def __init__(self, provider) -> None:
        self.provider = provider

    def prepare(self, scenario, approved_facts, identity_reference) -> TrainingContent:
        try:
            result = self.provider.prepare(scenario, approved_facts, identity_reference)
            if not isinstance(result, TrainingContent):
                raise TypeError("Invalid content result")
            return result
        except Exception:
            raise ProviderError("Content provider failed; no dispatch was performed") from None


class GuardedTarget:
    def __init__(self, provider, kind: str) -> None:
        self.provider, self.kind = provider, kind

    def assess(self, target: str) -> AssessmentResult:
        try:
            result = self.provider.assess(target)
            if (
                not isinstance(result, AssessmentResult)
                or result.target != target
                or result.target_kind != self.kind
            ):
                raise TypeError("Invalid assessment result")
            return result
        except Exception:
            raise ProviderError(
                "Assessment provider failed; no security conclusion is available"
            ) from None


class GuardedTransport:
    def __init__(self, transport, channel: str) -> None:
        self.transport, self.channel = transport, channel

    def deliver(self, plan, recipient) -> DeliveryReceipt:
        try:
            result = self.transport.deliver(plan, recipient)
            if not isinstance(result, DeliveryReceipt) or result.recipient != recipient:
                raise TypeError("Invalid transport receipt")
            return result
        except Exception:
            raise ProviderError(
                "Transport outcome is unconfirmed; inspect the attempt before retrying"
            ) from None


class ProviderRegistry:
    """Only trusted application code can register adapters; JSON merely selects their names."""

    def __init__(self) -> None:
        self._content = {"template": TemplateContentProvider()}
        self._targets: dict[tuple[str, str], object] = {}
        self._transports = {
            (channel, "demo"): DemoTransport(channel) for channel in ("email", "voice", "video")
        }

    def register_content(self, name: str, provider) -> None:
        require_text(name, "provider name")
        if name in self._content or not callable(getattr(provider, "prepare", None)):
            raise ValidationError("Duplicate name or invalid content provider")
        self._content[name] = provider

    def register_target(self, kind: str, name: str, provider) -> None:
        require_text(name, "provider name")
        if (
            kind not in TARGET_KINDS
            or (kind, name) in self._targets
            or not callable(getattr(provider, "assess", None))
        ):
            raise ValidationError("Unknown kind, duplicate name or invalid target provider")
        self._targets[(kind, name)] = provider

    def register_transport(self, channel: str, name: str, transport) -> None:
        require_text(name, "transport name")
        if (
            channel not in ("email", "voice", "video")
            or (channel, name) in self._transports
            or getattr(transport, "channel", None) != channel
            or not callable(getattr(transport, "deliver", None))
        ):
            raise ValidationError("Invalid or duplicate training transport")
        self._transports[(channel, name)] = transport

    def transport(self, channel: str, name: str):
        transport = self._transports.get((channel, name))
        if transport is None:
            raise ProviderError("Selected transport is not installed")
        return GuardedTransport(transport, channel)

    def content(self, name: str):
        if name not in self._content:
            raise ProviderError("Selected content provider is not installed")
        return GuardedContent(self._content[name])

    def assessment_service(self, config: ProviderConfig) -> AssessmentService:
        adapters = {}
        for kind, name in config.assessment:
            provider = self._targets.get((kind, name))
            if provider is None:
                raise ProviderError("Selected assessment provider is not installed")
            adapters[kind] = GuardedTarget(provider, kind)
        return AssessmentService(adapters)

    def describe(self, config: ProviderConfig) -> dict:
        return {
            "available_content": sorted(self._content),
            "available_assessment": [
                {"kind": kind, "name": name} for kind, name in sorted(self._targets)
            ],
            "selected": asdict(config),
            "available_transports": [
                {"channel": channel, "name": name} for channel, name in sorted(self._transports)
            ],
            "live_transport": "not_bundled",
            "credentials": "Managed by concrete adapters; not accepted in config files",
        }

    def diagnose(self, config: ProviderConfig) -> dict:
        missing = []
        if config.content not in self._content:
            missing.append("content")
        for kind, name in config.assessment:
            if (kind, name) not in self._targets:
                missing.append(f"assessment:{kind}")
        return {
            "status": "ready_offline" if not missing else "missing_provider",
            "live_validation_status": "REQUIRES_LIVE_VALIDATION",
            "missing": missing,
            "network_checked": False,
            "notice": "REQUIRES_LIVE_VALIDATION: Registration is not proof of API credentials "
            "or provider availability.",
        }
