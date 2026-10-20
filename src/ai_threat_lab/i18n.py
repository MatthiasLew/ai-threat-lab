"""Internationalization and localization engine for AI Threat Lab.

Provides centralized UI strings, language selection, preference persistence outside
source control, parameter interpolation, and deterministic fallback (pl -> en -> key).
Never translates domain models, internal JSON field names, rule IDs, or CLI arguments.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SUPPORTED_LANGUAGES: dict[str, str] = {
    "pl": "Polski",
    "en": "English",
}

DEFAULT_LANGUAGE = "en"
_ACTIVE_LANGUAGE: str | None = None

# Translations catalog: key -> {"pl": "...", "en": "..."}
STRINGS: dict[str, dict[str, str]] = {
    # Application & Branding
    "app_title": {
        "pl": "AI THREAT LAB",
        "en": "AI THREAT LAB",
    },
    "app_subtitle": {
        "pl": "Bezpieczne audyty offline, przejrzyste raporty i doradcze analizy AI",
        "en": "Safe offline audits, transparent reports, and advisory AI analysis",
    },
    "report_title": {
        "pl": "Raport Analizy Bezpieczeństwa",
        "en": "Security Analysis Report",
    },
    "disclaimer_title": {
        "pl": "Ważna informacja o zakresie analizy",
        "en": "Important Scope & Limitation Notice",
    },
    "disclaimer_text": {
        "pl": (
            "Niniejszy raport zawiera wyniki automatycznej, statycznej analizy bezpieczeństwa "
            "wykonanej w bezpiecznym trybie offline. Wszelkie wykryte problemy stanowią kandydatów "
            "do weryfikacji i wymagają sprawdzenia kontekstu przez programistę. Raport nie "
            "stanowi pełnego audytu bezpieczeństwa, testu penetracyjnego ani gwarancji braku "
            "innych podatności."
        ),
        "en": (
            "This report contains the findings of an automated, offline static security analysis. "
            "All identified items represent candidate observations that require human context "
            "verification. This report does not constitute a full penetration test, certification, "
            "or guarantee of the absence of other vulnerabilities."
        ),
    },
    # Language Selection
    "choose_language_title": {
        "pl": "Wybierz język / Choose language:",
        "en": "Choose language / Wybierz język:",
    },
    "select_option": {
        "pl": "Wybierz opcję",
        "en": "Select option",
    },
    "language_changed": {
        "pl": "Zmieniono język na: {language}",
        "en": "Language changed to: {language}",
    },
    # Main Menu
    "menu_start_audit": {
        "pl": "Rozpocznij nowy audyt",
        "en": "Start a new audit",
    },
    "menu_browse_history": {
        "pl": "Przeglądaj poprzednie raporty",
        "en": "Browse previous reports",
    },
    "menu_export_report": {
        "pl": "Eksportuj raport",
        "en": "Export report",
    },
    "menu_settings": {
        "pl": "Ustawienia",
        "en": "Settings",
    },
    "menu_help": {
        "pl": "Pomoc",
        "en": "Help",
    },
    "menu_exit": {
        "pl": "Wyjdź",
        "en": "Exit",
    },
    # Prompts & Inputs
    "prompt_target_path": {
        "pl": "Podaj ścieżkę do pliku, katalogu projektu lub repozytorium: ",
        "en": "Enter path to file, project directory, or repository: ",
    },
    "prompt_output_dir": {
        "pl": "Katalog na wyniki audytu [reports/{default_name}]: ",
        "en": "Output directory for audit results [reports/{default_name}]: ",
    },
    "prompt_confirm_scan": {
        "pl": "Czy rozpocząć analizę ze wskazanymi ustawieniami? [T/n]: ",
        "en": "Start analysis with the displayed settings? [Y/n]: ",
    },
    "prompt_ai_enrich": {
        "pl": "Czy chcesz utworzyć zrozumiałą interpretację AI za pomocą Google Gemini? [t/N]: ",
        "en": (
            "Would you like to generate an advisory AI interpretation with Google Gemini? [y/N]: "
        ),
    },
    "prompt_ai_confirm_cost": {
        "pl": (
            "Szacowany koszt: ~${cost_usd} USD ({tokens} tokenów). "
            "Czy zatwierdzasz wysłanie dowodów? [t/N]: "
        ),
        "en": (
            "Estimated cost: ~${cost_usd} USD ({tokens} tokens). "
            "Do you approve sending evidence? [y/N]: "
        ),
    },
    "prompt_back_to_menu": {
        "pl": "Naciśnij Enter, aby wrócić do menu...",
        "en": "Press Enter to return to menu...",
    },
    # Audit Flow & Progress
    "target_not_found": {
        "pl": "Błąd: Wskazana ścieżka '{target}' nie istnieje.",
        "en": "Error: Target path '{target}' does not exist.",
    },
    "planning_analysis": {
        "pl": "Przygotowywanie planu audytu dla: {target}...",
        "en": "Preparing audit plan for: {target}...",
    },
    "target_kind_label": {
        "pl": "Rozpoznany typ celu: {kind}",
        "en": "Recognized target type: {kind}",
    },
    "planned_analyzers": {
        "pl": "Dostępne analizatory lokalne:",
        "en": "Available local analyzers:",
    },
    "running_audit": {
        "pl": "Trwa analiza bezpieczeństwa offline...",
        "en": "Running offline security analysis...",
    },
    "audit_completed": {
        "pl": "ANALIZA ZAKOŃCZONA",
        "en": "ANALYSIS COMPLETED",
    },
    "audit_partial": {
        "pl": "ANALIZA CZĘŚCIOWA (niektóre elementy pominięto)",
        "en": "PARTIAL ANALYSIS (some components were skipped)",
    },
    "metric_project": {
        "pl": "Projekt: {project}",
        "en": "Project: {project}",
    },
    "metric_files_checked": {
        "pl": "Sprawdzone pliki: {count}",
        "en": "Files checked: {count}",
    },
    "metric_threats_found": {
        "pl": "Potencjalne zagrożenia: {count}",
        "en": "Potential threats: {count}",
    },
    "metric_skipped_items": {
        "pl": "Elementy pominięte: {count}",
        "en": "Items skipped: {count}",
    },
    "report_pdf_saved": {
        "pl": "Raport PDF:",
        "en": "PDF Report:",
    },
    "report_tech_saved": {
        "pl": "Raport techniczny:",
        "en": "Technical report:",
    },
    "no_findings_clean": {
        "pl": "W badanym zakresie nie wykryto znanych wzorców podatności.",
        "en": "No known vulnerability patterns detected within the inspected scope.",
    },
    # Risk Levels
    "priority_p1": {
        "pl": "Wysoki priorytet (P1)",
        "en": "High Priority (P1)",
    },
    "priority_p2": {
        "pl": "Średni priorytet (P2)",
        "en": "Medium Priority (P2)",
    },
    "priority_p3": {
        "pl": "Niski priorytet (P3)",
        "en": "Low Priority (P3)",
    },
    "priority_p4": {
        "pl": "Informacyjny (P4)",
        "en": "Informational (P4)",
    },
    "status_candidate": {
        "pl": "Kandydat do weryfikacji",
        "en": "Candidate for review",
    },
    "status_confirmed": {
        "pl": "Potwierdzone",
        "en": "Confirmed",
    },
    # Detailed Finding Sections
    "section_executive_summary": {
        "pl": "Podsumowanie dla kierownictwa i użytkownika",
        "en": "Executive & User Summary",
    },
    "section_results_overview": {
        "pl": "Przegląd wyników i metryki audytu",
        "en": "Results Overview & Audit Metrics",
    },
    "section_detailed_findings": {
        "pl": "Szczegółowe opisy wykrytych zagrożeń",
        "en": "Detailed Threat Descriptions",
    },
    "section_ai_interpretation": {
        "pl": "Doradcza interpretacja AI (Google Gemini)",
        "en": "Advisory AI Interpretation (Google Gemini)",
    },
    "section_limitations": {
        "pl": "Ograniczenia analizy i elementy nieobjęte badaniem",
        "en": "Analysis Limitations & Not Checked Scope",
    },
    "field_threat_number": {
        "pl": "Zagrożenie nr {index}",
        "en": "Threat #{index}",
    },
    "field_title": {
        "pl": "Nazwa",
        "en": "Title",
    },
    "field_risk_level": {
        "pl": "Poziom ryzyka",
        "en": "Risk Level",
    },
    "field_status": {
        "pl": "Status ustalenia",
        "en": "Finding Status",
    },
    "field_location": {
        "pl": "Lokalizacja",
        "en": "Location",
    },
    "field_what_detected": {
        "pl": "Co wykryto?",
        "en": "What was detected?",
    },
    "field_why_dangerous": {
        "pl": "Dlaczego może to być niebezpieczne?",
        "en": "Why is this potentially dangerous?",
    },
    "field_code_snippet": {
        "pl": "Fragment kodu źródłowego",
        "en": "Source Code Snippet",
    },
    "field_what_to_check": {
        "pl": "Co należy sprawdzić?",
        "en": "What should be checked?",
    },
    "field_how_to_fix": {
        "pl": "Jak naprawić problem?",
        "en": "How to fix this issue?",
    },
    "field_how_to_verify": {
        "pl": "Jak zweryfikować naprawę?",
        "en": "How to verify the fix?",
    },
    "field_limitations": {
        "pl": "Ograniczenia analizy",
        "en": "Analysis limitations",
    },
    "field_ai_observations": {
        "pl": "Obserwacje doradcze modelu AI",
        "en": "Model Advisory Observations",
    },
    "field_ai_uncertainty": {
        "pl": "Oświadczenie o niepewności modelu",
        "en": "Model Uncertainty Statement",
    },
    # Metadata & Footer
    "page_number": {
        "pl": "Strona {current} z {total}",
        "en": "Page {current} of {total}",
    },
    "date_generated": {
        "pl": "Data utworzenia: {date}",
        "en": "Generated on: {date}",
    },
    "audit_type_label": {
        "pl": "Typ audytu: Statyczny audyt bezpieczeństwa (offline)",
        "en": "Audit type: Static security audit (offline)",
    },
    "ai_status_offline": {
        "pl": "Tryb: W pełni lokalny (bez AI)",
        "en": "Mode: Fully offline (no AI)",
    },
    "ai_status_enriched": {
        "pl": "Tryb: Wzbogacony interpretacją Google Gemini",
        "en": "Mode: Enriched with Google Gemini interpretation",
    },
    "source_code_unavailable": {
        "pl": "Kod źródłowy niedostępny lokalnie lub brak dostępu do pliku.",
        "en": "Source code is not accessible locally or file permissions restricted.",
    },
    "source_code_diverged": {
        "pl": "Uwaga: Plik źródłowy uległ zmianie na dysku od momentu wykonania analizy.",
        "en": "Notice: Source file was modified on disk since the audit was performed.",
    },
    # Settings & Help
    "settings_title": {
        "pl": "USTAWIENIA",
        "en": "SETTINGS",
    },
    "settings_current_language": {
        "pl": "Bieżący język: {language} ({code})",
        "en": "Current language: {language} ({code})",
    },
    "settings_config_file": {
        "pl": "Plik konfiguracji użytkownika: {path}",
        "en": "User configuration file: {path}",
    },
    "settings_change_language": {
        "pl": "1. Zmień język",
        "en": "1. Change language",
    },
    "help_title": {
        "pl": "POMOC I INFORMACJE O PROGRAMIE",
        "en": "HELP & INFORMATION",
    },
    "help_text": {
        "pl": (
            "AI Threat Lab to zaawansowane narzędzie audytu bezpieczeństwa o architekturze "
            "offline-first.\n\n"
            "Główne zasady:\n"
            "1. Domyślnie program działa w 100% lokalnie — żaden kod ani sekrety nie są wysyłane.\n"
            "2. Wykrycia mają charakter kandydatów do weryfikacji i wymagają potwierdzenia "
            "przez człowieka.\n"
            "3. Opcjonalna interpretacja Gemini API wysyła wyłącznie zminimalizowane dowody,\n"
            "   nigdy surowe pliki ani całe repozytoria.\n"
            "4. Raporty PDF stanowią domyślny format dla ludzi; JSON i SARIF służą automatyzacji."
        ),
        "en": (
            "AI Threat Lab is an offline-first security audit and reporting platform.\n\n"
            "Core principles:\n"
            "1. By default, operations are 100% offline — no code or secrets leave your machine.\n"
            "2. Scanner findings represent candidate observations requiring human verification.\n"
            "3. Optional Gemini API interpretation sends only minimized scrubbed evidence,\n"
            "   never raw files or complete code repositories.\n"
            "4. PDF reports are the default format for human readers; JSON/SARIF serve automation."
        ),
    },
}

TRANSLATIONS = STRINGS


def get_user_config_dir() -> Path:
    """Return local user configuration directory outside source control."""
    custom = os.environ.get("AI_THREAT_LAB_CONFIG_DIR")
    if custom:
        return Path(custom)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "ai-threat-lab"
    return Path.home() / ".ai-threat-lab"


def get_user_config_file() -> Path:
    """Return configuration file path."""
    return get_user_config_dir() / "config.json"


def load_language_preference() -> str | None:
    """Load user language preference from configuration file or environment."""
    env_lang = os.environ.get("AI_THREAT_LAB_LANG")
    if env_lang and env_lang.lower() in SUPPORTED_LANGUAGES:
        return env_lang.lower()

    cfg_file = get_user_config_file()
    if cfg_file.is_file():
        try:
            data = json.loads(cfg_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                lang = data.get("language")
                if isinstance(lang, str) and lang.lower() in SUPPORTED_LANGUAGES:
                    return lang.lower()
        except Exception:
            pass
    return None


def save_language_preference(language: str) -> Path:
    """Persist language preference to local user configuration file."""
    lang = validate_language(language)
    cfg_dir = get_user_config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = cfg_dir / "config.json"

    data: dict[str, Any] = {}
    if cfg_file.is_file():
        try:
            data = json.loads(cfg_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {}

    data["language"] = lang
    cfg_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    set_active_language(lang)
    return cfg_file


def validate_language(language: str) -> str:
    """Validate and normalize supported language code."""
    if not isinstance(language, str) or language.lower() not in SUPPORTED_LANGUAGES:
        supported = ", ".join(sorted(SUPPORTED_LANGUAGES))
        from .models import ValidationError

        raise ValidationError(f"Unsupported language '{language}'; choose one of: {supported}")
    return language.lower()


def get_active_language() -> str:
    """Return currently active language code."""
    global _ACTIVE_LANGUAGE
    if _ACTIVE_LANGUAGE is not None:
        return _ACTIVE_LANGUAGE
    saved = load_language_preference()
    if saved is not None:
        _ACTIVE_LANGUAGE = saved
        return saved
    return DEFAULT_LANGUAGE


def set_active_language(language: str) -> None:
    """Set the active language in memory for the current session."""
    global _ACTIVE_LANGUAGE
    _ACTIVE_LANGUAGE = validate_language(language)


def t(key: str, lang: str | None = None, **kwargs: Any) -> str:
    """Retrieve translated string with parameter interpolation and deterministic fallback.

    Fallback sequence: target_lang -> en -> key itself.
    """
    target = lang.lower() if lang else get_active_language()
    entry = STRINGS.get(key)
    if entry is None:
        return key

    text = entry.get(target)
    if text is None and target != "en":
        text = entry.get("en")
    if text is None:
        return key

    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return text
    return text


def get_all_translation_keys() -> tuple[str, ...]:
    """Return all defined translation keys."""
    return tuple(sorted(STRINGS.keys()))
