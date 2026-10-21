"""Interactive user-facing console menu and guided workflow for AI Threat Lab.

Provides a clean, human-friendly interface in Polish or English for:
- Language selection and persistent preference management
- Starting a new audit with plan preview, scan execution, and automatic PDF report generation
- Safe Windows path input handling (including paths pasted with quotes from Explorer)
- Robust pre-audit target and destination validation
- Optional explicit consent workflow for Google Gemini advisory interpretation
- Browsing previous audit results
- Exporting reports to PDF, HTML, JSON, and SARIF
- Built-in guidance and settings
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

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
    validate_language,
)
from .path_utils import clean_user_path, suggest_output_dir
from .pdf_report import generate_pdf_report
from .scan_engine import ScanOptions


def prompt_user(prompt: str, *, default: str = "", input_fn: Callable[[str], str] = input) -> str:
    """Prompt user for input with an optional default value."""
    try:
        val = input_fn(prompt).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        raise


def format_target_kind(kind: str, language: str) -> str:
    """Format technical target_kind into a friendly localized label."""
    pl = language == "pl"
    labels: dict[str, str] = {
        "local_project": "Katalog projektu lokalnego" if pl else "Local project directory",
        "python_source": "Plik źródłowy Python" if pl else "Python source file",
        "program_file": "Plik binarny / archiwum" if pl else "Binary file / archive",
        "mail_message": "Wiadomość e-mail (EML)" if pl else "Email message (EML)",
        "html_document": "Dokument HTML" if pl else "HTML document",
        "authentication_log": "Dziennik zdarzeń logowania" if pl else "Authentication log",
        "ssh_journal": "Dziennik OpenSSH" if pl else "OpenSSH journal",
        "github_repository": "Repozytorium GitHub" if pl else "GitHub repository",
        "website": "Strona WWW (HTTPS)" if pl else "Website (HTTPS)",
        "mail_domain": "Domena pocztowa" if pl else "Mail domain",
        "mailbox_account": "Konto pocztowe Gmail" if pl else "Gmail mailbox account",
    }
    return labels.get(kind, kind)


def describe_planned_scope(target_path: Path, plan: dict, language: str) -> list[str]:
    """Construct human-readable list of analyzers and planned scope items."""
    pl = language == "pl"
    tools = plan.get("tools") or plan.get("analyzers") or []
    target_kind = plan.get("target_kind", "")

    if not tools:
        return []

    if target_kind == "local_project":
        return [
            (
                "Analizator statyczny kodu Python (wykrywanie niebezpiecznych wywołań "
                "subprocess, shell=True, eval, pickle, podatności wstrzykiwania)"
                if pl
                else (
                    "Python static code analysis (detection of subprocess, shell=True, "
                    "eval, pickle, and command injection vulnerabilities)"
                )
            ),
            (
                (
                    "Skaner sekretów i poświadczeń (wykrywanie kluczy API, tokenów, "
                    "haseł i certyfikatów)"
                )
                if pl
                else (
                    "Secrets and credentials scanner (detection of API keys, tokens, "
                    "passwords, and certificates)"
                )
            ),
            (
                "Inwentaryzacja zależności i konfiguracji (analiza wymagań i manifestów projektu)"
                if pl
                else (
                    "Dependency and configuration inventory (analysis of project requirements "
                    "and manifests)"
                )
            ),
        ]

    tool_descriptions: dict[str, dict[str, str]] = {
        "python_review": {
            "pl": "Analiza statyczna składni i przepływu danych w kodzie Python",
            "en": "Static syntax and candidate data-flow analysis in Python source",
        },
        "binary_archive_review": {
            "pl": "Strukturalna analiza nagłówków PE/ELF oraz archiwów ZIP",
            "en": "Structural review of PE/ELF headers and ZIP archive metadata",
        },
        "saved_mail_review": {
            "pl": "Analiza nagłówków wiadomości EML, linków i formularzy",
            "en": "Review of saved EML headers, links, and forms",
        },
        "mail_attachment_structures": {
            "pl": "Analiza metadanych i struktury załączników pocztowych",
            "en": "Review of mail attachment structures and metadata",
        },
        "saved_html_review": {
            "pl": "Analiza formularzy i zasobów w zapisanych plikach HTML",
            "en": "Review of forms and embedded resources in saved HTML files",
        },
        "authentication_patterns": {
            "pl": "Analiza znormalizowanych wzorców zdarzeń logowania",
            "en": "Analysis of normalized saved login-event patterns",
        },
        "openssh_journal_review": {
            "pl": "Analiza wybranych zdarzeń dziennika OpenSSH",
            "en": "Review of selected saved single-host OpenSSH journal events",
        },
        "github_snapshot": {
            "pl": "Pobieranie i analiza migawki repozytorium GitHub oraz zależności",
            "en": "Pinned snapshot analysis of GitHub repository files and dependencies",
        },
        "passive_https": {
            "pl": "Pasywna analiza nagłówków i zawartości HTTPS pojedynczej strony",
            "en": "Passive analysis of HTTPS headers and single-page HTML",
        },
        "mail_dns": {
            "pl": "Weryfikacja rekordów SPF, DMARC i DKIM domeny pocztowej",
            "en": "Verification of mail domain SPF, DMARC, and DKIM DNS records",
        },
        "gmail_settings": {
            "pl": "Przegląd reguł przekazywania i filtrów konta pocztowego Gmail",
            "en": "Review of Gmail account forwarding and filter settings",
        },
        "dependency_inventory": {
            "pl": "Inwentaryzacja dokładnych wersji zależności w manifestach projektu",
            "en": "Inventory of exact dependency versions from manifest files",
        },
        "osv_advisories": {
            "pl": "Weryfikacja znanych podatności pakietów w bazie OSV",
            "en": "Verification of known package advisories via OSV database",
        },
        "verified_report_bundle": {
            "pl": "Generowanie zweryfikowanego pakietu raportu i integralności dowodowej",
            "en": "Generation of verified report bundle with evidentiary integrity",
        },
    }

    scope_items: list[str] = []
    for item in tools:
        tool_id = item.get("id") or item.get("name") or ""
        desc_entry = tool_descriptions.get(tool_id)
        if desc_entry:
            scope_items.append(desc_entry.get("pl" if pl else "en", tool_id))
        else:
            purpose = item.get("purpose") or item.get("description") or tool_id
            scope_items.append(purpose)

    return scope_items


def validate_target_path(
    raw: str | None, language: str = "en"
) -> tuple[bool, Path | None, str | None]:
    """Validate user input target path. Returns (is_valid, resolved_path, error_message)."""
    cleaned = clean_user_path(raw)
    if not cleaned:
        return False, None, t("error_target_empty", language)
    try:
        target_path = Path(cleaned)
    except Exception as exc:
        return False, None, t("error_path_syntax", language, error=str(exc))

    try:
        exists = target_path.exists()
    except OSError as exc:
        return False, None, t("error_path_access", language, error=str(exc))

    if not exists:
        return False, None, t("target_not_found", language, target=cleaned)

    return True, target_path, None


def validate_output_directory(
    raw: str | None,
    target_path: Path,
    language: str = "en",
) -> tuple[bool, Path | None, str | None]:
    """Validate user output directory. Returns (is_valid, resolved_path, error_message)."""
    cleaned = clean_user_path(raw)
    if not cleaned:
        return False, None, t("error_output_empty", language)

    try:
        out_path = Path(cleaned)
        # Attempt path resolution to detect malformed path syntax (e.g. WinError 123)
        resolved_out = out_path.resolve()
    except OSError as exc:
        return False, None, t("error_path_syntax", language, error=str(exc))
    except Exception as exc:
        return False, None, t("error_path_syntax", language, error=str(exc))

    try:
        resolved_target = target_path.resolve()
        if resolved_out == resolved_target:
            return False, None, t("error_output_same_as_target", language)
        if resolved_target.is_dir():
            try:
                resolved_out.relative_to(resolved_target)
                return False, None, t("error_output_inside_target", language)
            except ValueError:
                pass
    except Exception:
        pass

    try:
        if out_path.exists() or resolved_out.exists():
            return False, None, t("error_output_exists", language, path=cleaned)
    except OSError as exc:
        return False, None, t("error_path_access", language, error=str(exc))

    # Check parent writability
    try:
        parent = resolved_out.parent
        check_dir = parent
        while not check_dir.exists() and check_dir.parent != check_dir:
            check_dir = check_dir.parent
        if check_dir.exists() and not os.access(check_dir, os.W_OK):
            return False, None, t("error_output_parent_not_writable", language, dir=str(check_dir))
    except Exception:
        pass

    return True, out_path, None


def display_target_menu(language: str, print_fn: Callable[..., None] = print) -> None:
    """Render the structured 9-option target selection menu."""
    print_fn()
    print_fn("==================================================")
    print_fn(f"  {t('target_menu_title', language)}")
    print_fn("==================================================")
    print_fn(f"1. {t('target_opt_local_project', language)}")
    print_fn(f"2. {t('target_opt_single_file', language)}")
    print_fn(f"3. {t('target_opt_github_repo', language)}")
    print_fn(f"4. {t('target_opt_website_https', language)}")
    print_fn(f"5. {t('target_opt_mail_domain', language)}")
    print_fn(f"6. {t('target_opt_mail_message', language)}")
    print_fn(f"7. {t('target_opt_mailbox_gmail', language)}")
    print_fn(f"8. {t('target_opt_security_logs', language)}")
    print_fn(f"9. {t('target_opt_other_source', language)}")
    print_fn(f"0. {t('target_opt_back', language)}")
    print_fn()


def select_scan_profile(
    language: str,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
) -> int:
    """Prompt user to choose scan profile or custom file limit."""
    pl = language == "pl"
    print_fn()
    print_fn(f"--- {t('profile_menu_title', language)} ---")
    print_fn(t("profile_menu_desc", language))
    print_fn(f"  1. {t('profile_opt_fast', language)}")
    print_fn(f"  2. {t('profile_opt_standard', language)}")
    print_fn(f"  3. {t('profile_opt_extended', language)}")
    print_fn(f"  4. {t('profile_opt_custom', language)}")
    print_fn()

    choice = prompt_user(
        t("prompt_select_profile", language), default="2", input_fn=input_fn
    ).strip()
    if choice == "1":
        print_fn(t("profile_selected", language, name="Fast / Szybki" if pl else "Fast", limit=100))
        return 100
    elif choice == "3":
        print_fn(
            t(
                "profile_selected",
                language,
                name="Extended / Rozszerzony" if pl else "Extended",
                limit=5000,
            )
        )
        return 5000
    elif choice == "4":
        raw = prompt_user(
            t("prompt_custom_max_files", language), default="1000", input_fn=input_fn
        ).strip()
        try:
            val = int(raw)
            if 1 <= val <= 10000:
                print_fn(
                    t(
                        "profile_selected",
                        language,
                        name="Custom / Własny" if pl else "Custom",
                        limit=val,
                    )
                )
                return val
        except ValueError:
            pass
        print_fn(
            "Niepoprawna wartość. Użyto domyślnego limitu 1 000 plików."
            if pl
            else "Invalid value. Defaulting to 1,000 files."
        )
        return 1000
    else:
        print_fn(
            t(
                "profile_selected",
                language,
                name="Standard / Standardowy" if pl else "Standard",
                limit=1000,
            )
        )
        return 1000


def confirm_network_consent(
    host: str,
    purpose: str,
    language: str,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
) -> bool:
    """Explicit network consent disclosure gate before any remote query."""
    print_fn()
    print_fn("--------------------------------------------------")
    print_fn(f"  {t('network_consent_title', language)}")
    print_fn("--------------------------------------------------")
    print_fn(t("network_consent_details", language, host=host, purpose=purpose))
    print_fn()
    ans = prompt_user(
        t("prompt_network_consent", language),
        default="n",
        input_fn=input_fn,
    ).lower()
    if ans not in ("t", "tak", "y", "yes"):
        print_fn(t("network_consent_denied", language))
        return False
    return True


def run_language_selection(
    input_fn: Callable[[str], str] = input, print_fn: Callable[..., None] = print
) -> str:
    """Prompt user to select interface language and persist choice."""
    print_fn()
    print_fn("==================================================")
    print_fn("  AI THREAT LAB — WYBÓR JĘZYKA / LANGUAGE SELECTION")
    print_fn("==================================================")
    print_fn("1. Polski (Polish)")
    print_fn("2. English (Angielski)")
    print_fn()

    while True:
        try:
            choice = prompt_user("Wybierz język / Select language [1/2]: ", input_fn=input_fn)
            if choice in ("1", "pl", "PL", "polski", "Polish"):
                save_language_preference("pl")
                print_fn(t("language_changed", "pl", language="Polski"))
                return "pl"
            if choice in ("2", "en", "EN", "english", "English"):
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

    # Step 1: Target Type Selection / Direct Input
    display_target_menu(language, print_fn=print_fn)

    options: ScanOptions | None = None
    safe_name: str = "audit_target"

    while True:
        try:
            choice = prompt_user(t("target_menu_prompt", language), input_fn=input_fn)
            cleaned_choice = clean_user_path(choice)
            if not cleaned_choice or cleaned_choice.lower() in (
                "0",
                "q",
                "quit",
                "cancel",
                "anuluj",
            ):
                print_fn(t("audit_cancelled", language))
                return

            # Check if user entered a menu number 1-9
            if cleaned_choice == "1":
                # 1. Local project directory
                target_raw = prompt_user(t("prompt_target_path", language), input_fn=input_fn)
                c_target = clean_user_path(target_raw)
                valid, p_obj, err_msg = validate_target_path(c_target, language=language)
                if not valid or p_obj is None or not p_obj.is_dir():
                    print_fn(
                        err_msg
                        or (
                            "Wskazana ścieżka nie jest katalogiem."
                            if pl
                            else "Target path is not a directory."
                        )
                    )
                    continue
                max_f = select_scan_profile(language, input_fn=input_fn, print_fn=print_fn)
                options = ScanOptions(target=str(p_obj), max_files=max_f, network=False)
                safe_name = p_obj.name or "local_project"
                break

            elif cleaned_choice == "2":
                # 2. Single file
                target_raw = prompt_user(t("prompt_target_path", language), input_fn=input_fn)
                c_target = clean_user_path(target_raw)
                valid, p_obj, err_msg = validate_target_path(c_target, language=language)
                if not valid or p_obj is None or not p_obj.is_file():
                    print_fn(
                        err_msg
                        or (
                            "Wskazana ścieżka nie jest plikiem."
                            if pl
                            else "Target path is not a file."
                        )
                    )
                    continue
                options = ScanOptions(target=str(p_obj), max_files=10, network=False)
                safe_name = p_obj.stem or "single_file"
                break

            elif cleaned_choice == "3":
                # 3. GitHub repository
                repo_raw = prompt_user(t("prompt_prompt_github", language), input_fn=input_fn)
                c_repo = clean_user_path(repo_raw)
                if not c_repo or c_repo.lower() in ("0", "q", "quit", "cancel", "anuluj"):
                    print_fn(t("audit_cancelled", language))
                    return
                if not c_repo.startswith("http"):
                    c_repo = f"https://github.com/{c_repo.strip('/')}"
                host = "github.com"
                purpose = (
                    "Pobranie drzewa kodu i plików źródłowych przez GitHub API"
                    if pl
                    else "Fetch repository tree and source files via GitHub API"
                )
                if not confirm_network_consent(
                    host, purpose, language, input_fn=input_fn, print_fn=print_fn
                ):
                    return
                max_f = select_scan_profile(language, input_fn=input_fn, print_fn=print_fn)
                options = ScanOptions(
                    target=c_repo, network=True, allowed_hosts=(host,), max_files=max_f
                )
                safe_name = c_repo.rstrip("/").split("/")[-1] or "github_repo"
                break

            elif cleaned_choice == "4":
                # 4. HTTPS Website
                url_raw = prompt_user(t("prompt_prompt_website", language), input_fn=input_fn)
                c_url = clean_user_path(url_raw)
                if not c_url or c_url.lower() in ("0", "q", "quit", "cancel", "anuluj"):
                    print_fn(t("audit_cancelled", language))
                    return
                parsed = urlsplit(c_url)
                if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
                    print_fn(
                        "Błąd: Wymagany jest pełny adres HTTPS bez fragmentu (#)."
                        if pl
                        else "Error: HTTPS URL without fragments (#) is required."
                    )
                    continue
                host = parsed.hostname
                purpose = (
                    "Analiza nagłówków bezpieczeństwa HTTP i parametrów TLS"
                    if pl
                    else "Inspect HTTP security headers and TLS parameters"
                )
                if not confirm_network_consent(
                    host, purpose, language, input_fn=input_fn, print_fn=print_fn
                ):
                    return
                options = ScanOptions(
                    target=c_url, network=True, allowed_hosts=(host,), max_files=50
                )
                safe_name = host.replace(".", "_")
                break

            elif cleaned_choice == "5":
                # 5. Mail domain
                dom_raw = prompt_user(t("prompt_prompt_mail_domain", language), input_fn=input_fn)
                c_dom = clean_user_path(dom_raw).removeprefix("mail-domain:").lower()
                if not c_dom or c_dom.lower() in ("0", "q", "quit", "cancel", "anuluj"):
                    print_fn(t("audit_cancelled", language))
                    return
                dkim_raw = prompt_user(t("prompt_prompt_dkim", language), input_fn=input_fn).strip()
                dkim_sel = dkim_raw if dkim_raw else None
                purpose = (
                    "Weryfikacja rekordów SPF, DMARC i kluczy DKIM przez bezpieczny DNS-over-HTTPS"
                    if pl
                    else "Verify SPF, DMARC, and DKIM records via DNS-over-HTTPS"
                )
                if not confirm_network_consent(
                    c_dom, purpose, language, input_fn=input_fn, print_fn=print_fn
                ):
                    return
                options = ScanOptions(
                    target=f"mail-domain:{c_dom}",
                    network=True,
                    allowed_hosts=(c_dom,),
                    dkim_selector=dkim_sel,
                    max_files=50,
                )
                safe_name = f"mail_{c_dom.replace('.', '_')}"
                break

            elif cleaned_choice == "6":
                # 6. Saved email message (.eml)
                eml_raw = prompt_user(t("prompt_target_path", language), input_fn=input_fn)
                c_eml = clean_user_path(eml_raw)
                valid, p_obj, err_msg = validate_target_path(c_eml, language=language)
                if not valid or p_obj is None or not p_obj.is_file():
                    print_fn(
                        err_msg or ("Wskazany plik nie istnieje." if pl else "File does not exist.")
                    )
                    continue
                options = ScanOptions(target=str(p_obj), network=False)
                safe_name = p_obj.stem or "mail_message"
                break

            elif cleaned_choice == "7":
                # 7. Gmail account
                print_fn()
                print_fn(t("gmail_setup_guide", language))
                print_fn()
                gmail_raw = prompt_user(t("prompt_prompt_gmail", language), input_fn=input_fn)
                c_gmail = clean_user_path(gmail_raw).removeprefix("mailbox:")
                if not c_gmail or c_gmail.lower() in ("0", "q", "quit", "cancel", "anuluj"):
                    print_fn(t("audit_cancelled", language))
                    return
                if "@" not in c_gmail:
                    print_fn(
                        "Błąd: Podaj poprawny adres e-mail."
                        if pl
                        else "Error: Enter a valid email address."
                    )
                    continue
                host = "gmail.googleapis.com"
                purpose = (
                    "Odczyt reguł przekazywania i filtrów konta Gmail"
                    if pl
                    else "Read Gmail account forwarding and filter rules"
                )
                if not confirm_network_consent(
                    host, purpose, language, input_fn=input_fn, print_fn=print_fn
                ):
                    return
                options = ScanOptions(
                    target=f"mailbox:{c_gmail}", network=True, allowed_hosts=(host,)
                )
                safe_name = f"gmail_{c_gmail.split('@')[0]}"
                break

            elif cleaned_choice == "8":
                # 8. Security log
                log_raw = prompt_user(t("prompt_prompt_logs", language), input_fn=input_fn)
                c_log = clean_user_path(log_raw)
                valid, p_obj, err_msg = validate_target_path(c_log, language=language)
                if not valid or p_obj is None or not p_obj.is_file():
                    print_fn(
                        err_msg
                        or (
                            "Wskazany plik logu nie istnieje." if pl else "Log file does not exist."
                        )
                    )
                    continue
                options = ScanOptions(target=str(p_obj), network=False)
                safe_name = p_obj.stem or "security_log"
                break

            elif cleaned_choice == "9":
                # 9. Other source
                target_raw = prompt_user(t("prompt_target_path", language), input_fn=input_fn)
                c_target = clean_user_path(target_raw)
                valid, p_obj, err_msg = validate_target_path(c_target, language=language)
                if valid and p_obj is not None:
                    options = ScanOptions(target=str(p_obj), network=False)
                    safe_name = p_obj.name or "audit_target"
                else:
                    options = ScanOptions(target=c_target, network=False)
                    safe_name = "custom_audit"
                break

            else:
                # Direct target path/URL fallback for seamless UX and backwards compatibility
                valid, path_obj, error_msg = validate_target_path(cleaned_choice, language=language)
                if not valid or path_obj is None:
                    print_fn(error_msg or t("target_not_found", language, target=cleaned_choice))
                    continue
                options = ScanOptions(
                    target=str(path_obj), max_files=1000 if path_obj.is_dir() else 10, network=False
                )
                safe_name = path_obj.name or "audit_target"
                break

        except (EOFError, KeyboardInterrupt):
            print_fn()
            print_fn(t("audit_cancelled", language))
            return

    if options is None:
        return

    # Step 2: Plan Audit & Display Planned Scope
    print_fn()
    print_fn(t("planning_analysis", language, target=options.target))
    try:
        plan = plan_audit(
            options.target,
            network=options.network,
            allowed_hosts=options.allowed_hosts,
            max_files=options.max_files,
            dkim_selector=options.dkim_selector,
            language=language,
        )
    except Exception as exc:
        print_fn(f"Błąd planowania audytu: {exc}" if pl else f"Audit planning error: {exc}")
        return

    raw_kind = plan.get("target_kind", "unknown")
    kind_display = format_target_kind(raw_kind, language)
    print_fn(t("target_kind_label", language, kind=kind_display))
    print_fn()
    print_fn(t("planned_analyzers", language))

    t_path = (
        Path(options.target)
        if not options.target.startswith(("http", "mail-domain:", "mailbox:"))
        else Path(".")
    )
    scope_items = describe_planned_scope(t_path, plan, language)
    if scope_items:
        for item in scope_items:
            print_fn(f"  • {item}")
    else:
        print_fn(f"  {t('no_analyzers_found', language)}")

    print_fn()

    # Step 3: Confirm Scan Plan
    try:
        confirm = prompt_user(
            t("prompt_confirm_scan", language), default="t" if pl else "y", input_fn=input_fn
        ).lower()
        if confirm not in ("t", "tak", "y", "yes"):
            print_fn(t("audit_cancelled", language))
            return
    except (EOFError, KeyboardInterrupt):
        print_fn()
        print_fn(t("audit_cancelled", language))
        return

    # Step 4: Output Directory Selection
    suggested_dir = suggest_output_dir(safe_name)

    print_fn()
    print_fn("==================================================")
    print_fn(f"  {t('destination_screen_title', language)}")
    print_fn("==================================================")
    print_fn(t("destination_screen_desc", language))
    print_fn()

    out_dir: Path | None = None
    while True:
        try:
            raw_out = prompt_user(
                t("destination_screen_prompt", language, default=suggested_dir),
                default=suggested_dir,
                input_fn=input_fn,
            )
            cleaned_out = clean_user_path(raw_out)
            if not cleaned_out or cleaned_out.lower() in ("q", "quit", "cancel", "anuluj"):
                print_fn(t("audit_cancelled", language))
                return

            valid_out, out_obj, err_out = validate_output_directory(
                cleaned_out, t_path, language=language
            )
            if not valid_out or out_obj is None:
                print_fn()
                print_fn(err_out)
                print_fn()
                suggested_dir = suggest_output_dir(safe_name)
                continue

            confirm_dest = prompt_user(
                t("destination_confirm", language), default="t" if pl else "y", input_fn=input_fn
            ).lower()
            if confirm_dest not in ("t", "tak", "y", "yes"):
                print_fn(
                    "Podaj inną ścieżkę do katalogu wynikowego:"
                    if pl
                    else "Enter a different output directory path:"
                )
                continue

            out_dir = out_obj
            break
        except (EOFError, KeyboardInterrupt):
            print_fn()
            print_fn(t("audit_cancelled", language))
            return

    # Step 5: Execute Audit safely
    print_fn()
    print_fn(t("running_audit", language))
    try:
        run_audit(options, out_dir, language=language)
        results = get_audit_results(out_dir)
        rep = results.get("report", {})
        findings = rep.get("findings", [])
        not_checked = rep.get("not_checked", [])

        # Generate default PDF reports into exports/ and out_dir/
        exports_dir = out_dir / "exports"
        exports_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = exports_dir / f"audit_{language}.pdf"
        compat_pdf = out_dir / "audit.pdf"

        source_root = None
        if t_path.exists():
            source_root = t_path.parent if t_path.is_file() else t_path

        pdf_bytes = generate_pdf_report(
            rep,
            language=language,
            source_root=source_root,
            project_name=safe_name,
        )
        pdf_path.write_bytes(pdf_bytes)
        compat_pdf.write_bytes(pdf_bytes)
    except Exception as exc:
        print_fn()
        print_fn(t("error_audit_failed", language, error=str(exc)))
        return

    # Step 6: Print clean human summary
    print_fn()
    print_fn("==================================================")
    print_fn(f"  {t('audit_completed', language)}")
    print_fn("==================================================")
    print_fn(t("metric_project", language, project=safe_name))
    print_fn(t("metric_threats_found", language, count=len(findings)))
    print_fn(t("metric_skipped_items", language, count=len(not_checked)))
    print_fn()
    print_fn(f"{t('report_pdf_saved', language)}  {pdf_path} ({compat_pdf.name})")
    print_fn(f"{t('report_tech_saved', language)} {out_dir / 'report.json'}")
    print_fn()

    if len(findings) == 0:
        print_fn(t("no_findings_clean", language))
        return

    # Step 7: Optional AI enrichment prompt
    try:
        ai_choice = prompt_user(
            t("prompt_ai_enrich", language), default="n", input_fn=input_fn
        ).lower()
    except (EOFError, KeyboardInterrupt):
        return

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

        try:
            preview = prepare_ai_packets(out_dir, language=language, provider="gemini")
            est_cost = preview.get("maximum_reserved_usd", "0.003")
            packets = preview.get("packets", [])
            total_tokens = sum(p.get("input_token_planning_bound", 0) for p in packets)

            print_fn()
            print_fn(
                (
                    f"Preflight AI: Przygotowano {len(packets)} pakiet(ów) "
                    "dowodowych bez żadnych sekretów."
                )
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

                ai_json_path = out_dir / "gemini-review.json"
                ai_json_path.write_text(write_document(ai_res), encoding="utf-8")

                enriched_pdf_bytes = generate_pdf_report(
                    rep,
                    ai_review=ai_res,
                    language=language,
                    source_root=source_root,
                    project_name=safe_name,
                )
                pdf_path.write_bytes(enriched_pdf_bytes)
                compat_pdf.write_bytes(enriched_pdf_bytes)

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
    cleaned_run = clean_user_path(raw_run)
    if not cleaned_run or cleaned_run.lower() in ("q", "quit", "cancel", "anuluj"):
        return

    try:
        run_path = Path(cleaned_run)
        if not run_path.is_dir():
            print_fn("Błąd: Katalog nie istnieje." if pl else "Error: Directory does not exist.")
            return
    except Exception as exc:
        print_fn(f"Błąd ścieżki: {exc}" if pl else f"Path error: {exc}")
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
    out_file_raw = prompt_user(
        f"Ścieżka do pliku wyjściowego [{default_out}]: "
        if pl
        else f"Output file path [{default_out}]: ",
        default=default_out,
        input_fn=input_fn,
    )
    out_file = clean_user_path(out_file_raw)

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
    force_language_selection: bool = False,
    override_language: str | None = None,
) -> int:
    """Main interactive text menu entrypoint when launched without arguments or via menu."""
    if override_language:
        lang = validate_language(override_language)
        set_active_language(lang)
    elif force_language_selection:
        lang = run_language_selection(input_fn=input_fn, print_fn=print_fn)
    else:
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
