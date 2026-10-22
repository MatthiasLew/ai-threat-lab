"""AI Threat Lab public integration API."""

from ._version import __version__
from .ai_costs import (
    ALL_FAILURE_CATEGORIES,
    AIConfig,
    CostLedger,
    FailureDiagnosis,
    classify_ai_failure,
)
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
from .code_snippet import CodeSnippet, extract_code_snippet
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
    export_audit_pdf,
    export_audit_report,
    get_audit_history,
    get_audit_limitations,
    get_audit_results,
    get_audit_status,
    get_capabilities,
    get_scan_profiles,
    list_analyzers,
    plan_audit,
    prepare_ai_packets,
    run_audit,
)
from .i18n import (
    get_active_language,
    get_default_reports_dir,
    load_language_preference,
    load_reports_directory_preference,
    save_language_preference,
    save_reports_directory_preference,
    set_active_language,
    t,
)
from .models import AnalysisRequest, AnalysisResult, TargetProfile, ValidationError
from .path_utils import (
    clean_user_path,
    generate_audit_subfolder_name,
    get_safe_target_display_name,
    get_unique_audit_directory,
)
from .pdf_report import generate_pdf_report
from .providers import ProviderConfig, ProviderError, ProviderRegistry
from .reports import export_report
from .scan_engine import SCAN_PROFILES, ScanOptions, ScanService, get_scan_profile

__all__ = [
    "__version__",
    "AIConfig",
    "CostLedger",
    "ALL_FAILURE_CATEGORIES",
    "FailureDiagnosis",
    "classify_ai_failure",
    "ScanOptions",
    "ScanService",
    "SCAN_PROFILES",
    "get_scan_profiles",
    "get_scan_profile",
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
    "export_audit_pdf",
    "export_audit_report",
    "get_audit_history",
    "generate_pdf_report",
    "clean_user_path",
    "generate_audit_subfolder_name",
    "get_safe_target_display_name",
    "get_unique_audit_directory",
    "get_default_reports_dir",
    "load_reports_directory_preference",
    "save_reports_directory_preference",
    "extract_code_snippet",
    "CodeSnippet",
    "get_active_language",
    "set_active_language",
    "load_language_preference",
    "save_language_preference",
    "t",
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
