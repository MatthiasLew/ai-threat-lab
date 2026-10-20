"""AI Threat Lab public integration API."""

from ._version import __version__
from .ai_costs import AIConfig, CostLedger
from .ai_review import (
    SUPPORTED_AI_PROVIDERS,
    attach_ai_interpretation,
    build_multilingual_ai_packet,
    validate_ai_provider,
)
from .analyzer import ThreatAnalyzer
from .assessment import AssessmentService
from .campaigns import CampaignService
from .code_review import CodeReviewResult, review_file, review_source
from .finding_details import DetailedFinding, describe_finding, detailed_findings
from .gemini_adapter import (
    GEMINI_RESPONSE_SCHEMA,
    GeminiGenerateContent,
    build_sample_validated_ai_response,
    gemini_explain_result,
    gemini_review_result,
    gemini_review_service,
)
from .gui_api import (
    create_audit_options,
    export_audit_report,
    get_audit_history,
    get_audit_limitations,
    get_audit_results,
    get_audit_status,
    get_capabilities,
    list_analyzers,
    plan_audit,
    prepare_ai_packets,
    run_audit,
)
from .models import AnalysisRequest, AnalysisResult, TargetProfile, ValidationError
from .providers import ProviderConfig, ProviderError, ProviderRegistry
from .reports import export_report
from .scan_engine import ScanOptions, ScanService

__all__ = [
    "__version__",
    "AIConfig",
    "CostLedger",
    "ScanOptions",
    "ScanService",
    "DetailedFinding",
    "describe_finding",
    "detailed_findings",
    "SUPPORTED_AI_PROVIDERS",
    "validate_ai_provider",
    "GEMINI_RESPONSE_SCHEMA",
    "GeminiGenerateContent",
    "gemini_explain_result",
    "gemini_review_result",
    "gemini_review_service",
    "build_sample_validated_ai_response",
    "attach_ai_interpretation",
    "build_multilingual_ai_packet",
    "list_analyzers",
    "get_capabilities",
    "create_audit_options",
    "plan_audit",
    "run_audit",
    "get_audit_status",
    "get_audit_limitations",
    "get_audit_results",
    "export_audit_report",
    "get_audit_history",
    "prepare_ai_packets",
    "ThreatAnalyzer",
    "ProviderRegistry",
    "ProviderConfig",
    "ProviderError",
    "AssessmentService",
    "CampaignService",
    "CodeReviewResult",
    "review_file",
    "review_source",
    "AnalysisRequest",
    "AnalysisResult",
    "TargetProfile",
    "ValidationError",
    "export_report",
]
