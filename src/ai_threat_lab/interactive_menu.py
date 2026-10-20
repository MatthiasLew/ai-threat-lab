"""Interactive user-facing console menu and guided workflow for AI Threat Lab.

Provides a clean, human-friendly interface in Polish or English for:
- Language selection and persistent preference management
- Starting a new audit with plan preview, scan execution, and automatic PDF report generation
- Optional explicit consent workflow for Google Gemini advisory interpretation
- Browsing previous audit results
- Exporting reports to PDF, HTML, JSON, and SARIF
- Built-in guidance and settings
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from .contracts import write_document
from .gui_api import (
    export_audit_report,
    get_audit_results,
    plan_audit,
    prepare_ai_packets,
    run_audit,
)
from .i18n import (
    get_active_language,
    get_user_config_file,
    load_language_preference,
    save_language_preference,
    set_active_language,
    t,
)
from .pdf_report import generate_pdf_report


def prompt_user(prompt: str, *, default: str = "", input_fn: Callable[[str], str] = input) -> str:
    """Prompt user for input with an optional default value."""
    try:
        val = input_fn(prompt).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        raise


def run_language_selection(
    input_fn: Callable[[str], str] = input, print_fn: Callable[..., None] = print
) -> str:
    """Prompt user to select interface language and persist choice."""
    print_fn()
    print_fn(t("app_title"))
    print_fn(t("choose_language_title"))
    print_fn("1. Polski")
    print_fn("2. English")
    print_fn()

    while True:
        try:
            choice = prompt_user(f"{t('select_option')} [1/2]: ", input_fn=input_fn)
            if choice in ("1", "pl", "PL", "polski"):
                save_language_preference("pl")
                print_fn(t("language_changed", "pl", language="Polski"))
                return "pl"
            if choice in ("2", "en", "EN", "english"):
                save_language_preference("en")
                print_fn(t("language_changed", "en", language="English"))
                return "en"
            print_fn("Nieprawidłowy wybór. Wpisz 1 lub 2 / Invalid choice. Enter 1 or 2.")
        except (EOFError, KeyboardInterrupt):
            print_fn()
            return get_active_language()


def display_main_menu(language: str, print_fn: Callable[..., None] = print) -> None:
    """Render the main user menu in the selected language."""
    print_fn()
    print_fn("==================================================")
    print_fn(f"  {t('app_title', language)} — {t('app_subtitle', language)}")
    print_fn("==================================================")
    print_fn(f"1. {t('menu_start_audit', language)}")
    print_fn(f"2. {t('menu_browse_history', language)}")
    print_fn(f"3. {t('menu_export_report', language)}")
    print_fn(f"4. {t('menu_settings', language)}")
    print_fn(f"5. {t('menu_help', language)}")
    print_fn(f"0. {t('menu_exit', language)}")
    print_fn()


def run_new_audit_workflow(
    language: str,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
) -> None:
    """Guided workflow for inspecting a target, running audit, and producing PDF report."""
    pl = language == "pl"
    raw_target = prompt_user(t("prompt_target_path", language), input_fn=input_fn)
    if not raw_target:
        print_fn("Anulowano: Nie podano celu." if pl else "Cancelled: No target specified.")
        return

    target_path = Path(raw_target)
    if not target_path.exists():
        print_fn(t("target_not_found", language, target=raw_target))
        return

    # Plan audit
    print_fn()
    print_fn(t("planning_analysis", language, target=str(target_path)))
    plan = plan_audit(target_path)

    print_fn(t("target_kind_label", language, kind=plan.get("target_kind", "unknown")))
    print_fn(t("planned_analyzers", language))
    for an in plan.get("analyzers", []):
        desc = an.get("description", an.get("name"))
        print_fn(f"  • {an.get('name')}: {desc}")

    # Confirm scan
    confirm = prompt_user(
        t("prompt_confirm_scan", language), default="t" if pl else "y", input_fn=input_fn
    ).lower()
    if confirm not in ("t", "tak", "y", "yes"):
        print_fn("Anulowano audyt." if pl else "Audit cancelled.")
        return

    # Setup output directory
    safe_name = target_path.name or "audit-target"
    default_out = f"reports/{safe_name}"
    out_dir_str = prompt_user(
        t("prompt_output_dir", language, default_name=safe_name),
        default=default_out,
        input_fn=input_fn,
    )
    out_dir = Path(out_dir_str)

    # Execute audit
    print_fn()
    print_fn(t("running_audit", language))
    run_audit(target_path, out_dir, language=language)

    results = get_audit_results(out_dir)
    rep = results.get("report", {})
    findings = rep.get("findings", [])
    not_checked = rep.get("not_checked", [])

    # Generate default PDF report
    pdf_path = out_dir / "audit.pdf"
    pdf_bytes = generate_pdf_report(
        rep,
        language=language,
        source_root=target_path.parent if target_path.is_file() else target_path,
    )
    pdf_path.write_bytes(pdf_bytes)

    # Print clean human summary
    print_fn()
    print_fn("==================================================")
    print_fn(f"  {t('audit_completed', language)}")
    print_fn("==================================================")
    print_fn(t("metric_project", language, project=safe_name))
    print_fn(t("metric_threats_found", language, count=len(findings)))
    print_fn(t("metric_skipped_items", language, count=len(not_checked)))
    print_fn()
    print_fn(f"{t('report_pdf_saved', language)}  {pdf_path}")
    print_fn(f"{t('report_tech_saved', language)} {out_dir / 'report.json'}")
    print_fn()

    if len(findings) == 0:
        print_fn(t("no_findings_clean", language))
        return

    # Optional AI enrichment prompt
    ai_choice = prompt_user(t("prompt_ai_enrich", language), default="n", input_fn=input_fn).lower()
    if ai_choice in ("t", "tak", "y", "yes"):
        if not os.environ.get("GEMINI_API_KEY"):
            print_fn()
            print_fn(
                "Uwaga: Zmienna środowiskowa GEMINI_API_KEY nie jest ustawiona w bieżącej sesji.\n"
                'Ustaw ją przed wywołaniem API: $env:GEMINI_API_KEY="AIza..."\n'
                "Raport lokalny PDF i JSON pozostają kompletne i w pełni bezpieczne."
                if pl
                else (
                    "Notice: GEMINI_API_KEY environment variable is not set in this session.\n"
                    'Set it before invoking API: export GEMINI_API_KEY="AIza..."\n'
                    "Your local PDF and JSON reports remain complete and fully verified offline."
                )
            )
            return

        # Prepare AI packets preview
        preview = prepare_ai_packets(out_dir, language=language, provider="gemini")
        est_cost = preview.get("maximum_reserved_usd", "0.003")
        packets = preview.get("packets", [])
        total_tokens = sum(p.get("input_token_planning_bound", 0) for p in packets)

        print_fn()
        print_fn(
            f"Preflight AI: Przygotowano {len(packets)} pakiet(ów) dowodowych bez żadnych sekretów."
            if pl
            else f"AI Preflight: Prepared {len(packets)} secret-scrubbed evidence packet(s)."
        )
        ai_confirm = prompt_user(
            t("prompt_ai_confirm_cost", language, cost_usd=est_cost, tokens=total_tokens),
            default="n",
            input_fn=input_fn,
        ).lower()

        if ai_confirm in ("t", "tak", "y", "yes"):
            print_fn(
                "Generowanie interpretacji doradczej Gemini..."
                if pl
                else "Generating Gemini advisory review..."
            )
            try:
                from .ai_costs import AIConfig, CostLedger
                from .gemini_adapter import GEMINI_HOST, gemini_review_result
                from .http_client import PublicHTTPS

                cfg = AIConfig(
                    model="gemini-2.5-flash",
                    input_usd_per_million="0.30",
                    output_usd_per_million="2.50",
                    max_input_bytes=12000,
                    max_output_tokens=600,
                    daily_budget_usd="0.10",
                    max_calls_per_day=5,
                    cache_ttl_seconds=3600,
                    namespace="interactive-menu",
                )
                ledger = CostLedger(out_dir / "costs.sqlite")
                client = PublicHTTPS([GEMINI_HOST], timeout=30, max_requests=1)

                ai_res = gemini_review_result(
                    cfg,
                    ledger,
                    client,
                    rep,
                    packet_index=1,
                    language=language,
                    timeout=30,
                )

                # Save AI JSON
                ai_json_path = out_dir / "gemini-review.json"
                ai_json_path.write_text(write_document(ai_res), encoding="utf-8")

                # Regenerate PDF with AI interpretation attached
                enriched_pdf_bytes = generate_pdf_report(
                    rep,
                    ai_review=ai_res,
                    language=language,
                    source_root=target_path.parent if target_path.is_file() else target_path,
                )
                pdf_path.write_bytes(enriched_pdf_bytes)

                print_fn()
                print_fn(
                    "Raport PDF został pomyślnie wzbogacony o interpretację Gemini:"
                    if pl
                    else "PDF report successfully enriched with Gemini interpretation:"
                )
                print_fn(f"  {pdf_path}")
            except Exception as exc:
                print_fn()
                print_fn(
                    f"Błąd podczas wywołania API: {exc}" if pl else f"Error during API call: {exc}"
                )
                print_fn(
                    "Raport lokalny PDF bez AI został zachowany."
                    if pl
                    else "Local offline PDF report was preserved."
                )


def run_export_workflow(
    language: str,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
) -> None:
    """Guided export workflow for saved audit directories."""
    pl = language == "pl"
    raw_run = prompt_user(
        "Podaj ścieżkę do katalogu zapisanego audytu: "
        if pl
        else "Enter path to saved audit directory: ",
        input_fn=input_fn,
    )
    if not raw_run:
        return

    run_path = Path(raw_run)
    if not run_path.is_dir():
        print_fn("Błąd: Katalog nie istnieje." if pl else "Error: Directory does not exist.")
        return

    print_fn("Dostępne formaty:" if pl else "Available formats:")
    print_fn(
        "1. PDF (profesjonalny raport dla człowieka)"
        if pl
        else "1. PDF (professional human-facing report)"
    )
    print_fn("2. HTML (podgląd w przeglądarce)" if pl else "2. HTML (browser standalone preview)")
    print_fn("3. JSON (format techniczny)" if pl else "3. JSON (technical format)")
    print_fn(
        "4. SARIF (integracja z narzędziami deweloperskimi)"
        if pl
        else "4. SARIF (IDE & tooling integration)"
    )

    fmt_choice = prompt_user(
        "Wybierz format [1-4]: " if pl else "Select format [1-4]: ", default="1", input_fn=input_fn
    )
    fmt_map = {"1": "pdf", "2": "html", "3": "json", "4": "sarif"}
    fmt = fmt_map.get(fmt_choice, "pdf")

    default_out = f"export_{run_path.name}.{fmt}"
    out_file = prompt_user(
        f"Ścieżka do pliku wyjściowego [{default_out}]: "
        if pl
        else f"Output file path [{default_out}]: ",
        default=default_out,
        input_fn=input_fn,
    )

    try:
        export_audit_report(run_path, output=out_file, format=fmt, language=language)
        print_fn()
        print_fn(
            f"Pomyślnie wyeksportowano raport do: {out_file}"
            if pl
            else f"Successfully exported report to: {out_file}"
        )
    except Exception as exc:
        print_fn(f"Błąd eksportu: {exc}" if pl else f"Export error: {exc}")


def run_settings_workflow(
    language: str,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
) -> str:
    """Settings menu to view or change language preference."""
    print_fn()
    print_fn(f"=== {t('settings_title', language)} ===")
    print_fn(
        t(
            "settings_current_language",
            language,
            language="Polski" if language == "pl" else "English",
            code=language,
        )
    )
    print_fn(t("settings_config_file", language, path=str(get_user_config_file())))
    print_fn()
    print_fn(t("settings_change_language", language))
    print_fn(f"0. {t('menu_exit', language)}")

    choice = prompt_user(f"{t('select_option')} [0/1]: ", input_fn=input_fn)
    if choice == "1":
        new_lang = run_language_selection(input_fn=input_fn, print_fn=print_fn)
        return new_lang
    return language


def run_interactive_entrypoint(
    *,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
    registry=None,
) -> int:
    """Main interactive text menu entrypoint when launched without arguments."""
    saved_lang = load_language_preference()
    if saved_lang is None:
        lang = run_language_selection(input_fn=input_fn, print_fn=print_fn)
    else:
        lang = saved_lang
        set_active_language(lang)

    while True:
        try:
            display_main_menu(lang, print_fn=print_fn)
            choice = prompt_user(f"{t('select_option')} [0-5]: ", input_fn=input_fn)

            if choice in ("0", "exit", "quit", "q"):
                print_fn("Do widzenia!" if lang == "pl" else "Goodbye!")
                return 0
            if choice == "1":
                run_new_audit_workflow(lang, input_fn=input_fn, print_fn=print_fn)
                prompt_user(t("prompt_back_to_menu", lang), input_fn=input_fn)
            elif choice == "2":
                print_fn()
                print_fn(
                    "Wybierz opcję 3, aby wyeksportować i przeglądać zapisany audyt."
                    if lang == "pl"
                    else "Use option 3 to export and review a saved audit."
                )
                prompt_user(t("prompt_back_to_menu", lang), input_fn=input_fn)
            elif choice == "3":
                run_export_workflow(lang, input_fn=input_fn, print_fn=print_fn)
                prompt_user(t("prompt_back_to_menu", lang), input_fn=input_fn)
            elif choice == "4":
                lang = run_settings_workflow(lang, input_fn=input_fn, print_fn=print_fn)
            elif choice == "5":
                print_fn()
                print_fn(f"=== {t('help_title', lang)} ===")
                print_fn(t("help_text", lang))
                prompt_user(t("prompt_back_to_menu", lang), input_fn=input_fn)
            else:
                print_fn(
                    "Nieprawidłowy wybór. Wpisz liczbę od 0 do 5."
                    if lang == "pl"
                    else "Invalid option. Please enter a number between 0 and 5."
                )
        except KeyboardInterrupt:
            print_fn()
            print_fn("Anulowano." if lang == "pl" else "Cancelled.")
            return 130
        except EOFError:
            print_fn()
            return 0
