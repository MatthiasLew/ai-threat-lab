"""Professional security audit PDF report generator for human stakeholders.

Generates beautifully structured, printable A4 PDF audit reports with:
- Dedicated title page with metadata, accurate project name, and clear scope disclaimer
- Executive & user-friendly summary distinguishing zero findings from partial audits
- Clear distinction between confirmed findings, candidates, and limitations
- Categorized and human-readable limitation summaries with zero raw Python dicts
- Prominent file traversal limit warnings with clear remediation instructions
- Metrics overview cards (threats, audit status, traversal limits, scope bounds)
- Detailed threat descriptions with mechanism, consequences, fixes, and verification steps
- Highlighted source code snippets with context lines and visual target line markers
- Seamless optional integration of verified Google Gemini advisory interpretations
- Native Polish diacritics and typographic punctuation support (em-dash, en-dash, quotes, bullets)
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

from .code_snippet import extract_code_snippet
from .finding_details import detailed_findings, validate_report_language
from .i18n import t
from .models import ValidationError
from .pdf_writer import PDFDocument

# Color palette
COLOR_PRIMARY = (0.08, 0.16, 0.32)  # Dark Navy #142852
COLOR_SECONDARY = (0.22, 0.35, 0.55)  # Steel Blue #38598C
COLOR_TEXT_DARK = (0.12, 0.15, 0.20)  # Charcoal text #1F2633
COLOR_TEXT_MUTED = (0.40, 0.45, 0.52)  # Muted gray #667385
COLOR_BORDER = (0.85, 0.88, 0.92)  # Border gray #D9E0EB
COLOR_BG_CARD = (0.97, 0.98, 0.99)  # Card background #F7F9FC
COLOR_BG_ALT = (0.94, 0.96, 0.98)  # Alternate background #F0F4FA

NOTICE_TRANSLATIONS_PL: dict[str, str] = {
    "Only one HTTPS response was checked; redirects are not followed.": (
        "Zbadano wyłącznie pojedynczą odpowiedź HTTPS; "
        "przekierowania (redirects) nie były śledzone."
    ),
    (
        "Declared integrity values, CSS URLs, DOM mutations and "
        "browser URL normalization are unverified."
    ): (
        "Zadeklarowane wartości integrity, adresy URL w stylach CSS, "
        "dynamiczne mutacje DOM oraz normalizacja URL w przeglądarce nie były weryfikowane."
    ),
    (
        "Static HTML subset only; no rendering, JavaScript, requests, "
        "form submission, CSP/browser enforcement, authentication, "
        "CSRF, reachability or exploitability validation."
    ): (
        "Pasywna analiza statycznego podzbioru HTML; brak renderowania w przeglądarce, "
        "wykonywania JavaScriptu, wysyłania formularzy, weryfikacji uwierzytelniania, "
        "CSRF ani sprawdzania osiągalności podatności."
    ),
    "Adapter supplied only a header mapping; duplicate fields may be missing.": (
        "Adapter dostarczył uproszczone mapowanie nagłówków; "
        "zduplikowane pola mogły zostać pominięte."
    ),
    "Response is not unambiguously declared text/html; body unchecked.": (
        "Odpowiedź nie została jednoznacznie zadeklarowana jako text/html; "
        "treść nie była sprawdzana."
    ),
    "HTML body exceeded the size limit; body unchecked.": (
        "Rozmiar treści HTML przekroczył dopuszczalny limit (256 KiB); treść nie była sprawdzana."
    ),
    "HTML body read incomplete or failed; body unchecked.": (
        "Odczyt treści HTML był niekompletny lub nie powiódł się; treść nie była sprawdzana."
    ),
    "HTML finding limit reached; additional candidates omitted.": (
        "Osiągnięto limit wykryć HTML; dodatkowi kandydaci zostali pominięci."
    ),
    "Non-200 response body unchecked.": (
        "Odpowiedź ze statusem innym niż 200 OK; treść nie była sprawdzana."
    ),
    "Plaintext remainder unchecked as markup.": (
        "Pozostała część dokumentu w formacie plaintext pominięta jako znaczniki."
    ),
    "Template, foreign and noscript subtrees unchecked.": (
        "Poddrzewa znaczników template, foreign (SVG/MathML) oraz noscript nie były sprawdzane."
    ),
    "Duplicate attributes leave the affected element unchecked.": (
        "Zduplikowane atrybuty spowodowały pominięcie danego elementu."
    ),
    "Nested forms unchecked; HTML tree repair was not simulated.": (
        "Zagnieżdżone formularze pominięte; naprawa drzewa HTML nie była symulowana."
    ),
    "Explicit form-owner associations unchecked; form-dependent candidates omitted.": (
        "Jawne powiązania form-owner pominięte; "
        "kandydaci zależni od formularza nie byli sprawdzani."
    ),
    "Fieldset and submitter-override form effects unchecked.": (
        "Elementy fieldset oraz nadpisania submitter-override nie były sprawdzane."
    ),
    "Non-JavaScript script types unchecked.": (
        "Skrypty o typach innych niż JavaScript nie były sprawdzane."
    ),
    "Srcset and srcdoc contents unchecked.": (
        "Zawartość atrybutów srcset i srcdoc nie była sprawdzana."
    ),
    "Target collector failed; no security conclusion is available.": (
        "Kolektor celu uległ awarii; brak wniosków dotyczących bezpieczeństwa."
    ),
    (
        "Passive single main-page inspection; multi-page crawling, authentication, "
        "forms, and dynamic JS execution were not performed."
    ): (
        "Pasywna analiza pojedynczej strony głównej; indeksowanie wielostronicowe, "
        "formularze, uwierzytelnianie oraz dynamiczne wykonywanie kodu JavaScript "
        "nie były wykonywane."
    ),
}


# Severity Badge Colors (Background, Text, Border)
BADGE_COLORS: dict[
    str, tuple[tuple[float, float, float], tuple[float, float, float], tuple[float, float, float]]
] = {
    "P1": (
        (0.99, 0.91, 0.91),  # BG soft red #FDE8E8
        (0.61, 0.11, 0.11),  # Text red #9B1C1C
        (0.97, 0.71, 0.71),  # Border red #F8B4B4
    ),
    "P2": (
        (0.99, 0.94, 0.54),  # BG amber #FEF08A
        (0.47, 0.21, 0.06),  # Text amber #78350F
        (0.99, 0.88, 0.28),  # Border amber #FDE047
    ),
    "P3": (
        (0.88, 0.94, 0.99),  # BG blue #E1EFFE
        (0.12, 0.26, 0.62),  # Text blue #1E429F
        (0.64, 0.79, 0.99),  # Border blue #A4CAFE
    ),
    "P4": (
        (0.95, 0.96, 0.97),  # BG gray #F3F4F6
        (0.22, 0.27, 0.32),  # Text gray #374151
        (0.82, 0.85, 0.88),  # Border gray #D1D5DB
    ),
}


def extract_project_identity(
    report: dict[str, Any],
    project_name: str | None = None,
    manifest: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Extract display project name and full target path from report metadata.

    Preserves dots in domain names (e.g. archeolabrys.pl) without mangling into underscores.
    """
    from .path_utils import get_safe_target_display_name

    target_candidate = None
    if scope:
        target_candidate = scope.get("target")
    if not target_candidate and manifest:
        target_candidate = manifest.get("scope", {}).get("target")
    if not target_candidate:
        target_candidate = (
            report.get("target")
            or report.get("project_name")
            or report.get("scope", {}).get("target")
            or report.get("manifest", {}).get("scope", {}).get("target")
        )
    if not target_candidate:
        assessments = report.get("assessments", [])
        if (
            assessments
            and isinstance(assessments, (list, tuple))
            and isinstance(assessments[0], dict)
        ):
            target_candidate = assessments[0].get("target")
    if not target_candidate:
        limits = report.get("not_checked", [])
        if limits and isinstance(limits, (list, tuple)) and isinstance(limits[0], dict):
            target_candidate = limits[0].get("target")

    if not target_candidate and project_name:
        target_candidate = str(project_name)

    if target_candidate:
        target_str = str(target_candidate)
        # If target is an HTTP/HTTPS URL, preserve domain as display name
        display_name = get_safe_target_display_name(target_str)
        return display_name, target_str

    if project_name:
        p_str = str(project_name)
        display_name = get_safe_target_display_name(p_str)
        return display_name, p_str

    return "Projekt", "Nieznana lokalizacja"


def extract_scope_details(
    report: dict[str, Any],
    manifest: dict[str, Any] | None = None,
    scope_arg: dict[str, Any] | None = None,
    language: str = "en",
) -> dict[str, Any]:
    """Extract recognized technologies, files scanned, network state and profile limits."""
    pl = language == "pl"
    scope = scope_arg or report.get("scope") or report.get("manifest", {}).get("scope")
    if not scope and manifest:
        scope = manifest.get("scope", {})
    if not scope:
        scope = {}

    not_checked = report.get("not_checked", [])
    assessments = report.get("assessments", [])
    primary_assessment = (
        assessments[0]
        if (
            assessments
            and isinstance(assessments, (list, tuple))
            and isinstance(assessments[0], dict)
        )
        else {}
    )

    target = scope.get("target") or report.get("target") or primary_assessment.get("target") or ""
    target_kind = scope.get("target_kind") or primary_assessment.get("target_kind") or ""

    # Infer target kind from target string if still unknown
    if not target_kind:
        if str(target).startswith(("http://", "https://")):
            target_kind = "website"
        elif str(target).startswith("mail-domain:"):
            target_kind = "mail_domain"
        elif str(target).startswith("mailbox:"):
            target_kind = "mailbox_account"
        elif str(target).endswith(".eml"):
            target_kind = "eml_message"
        else:
            target_kind = "local_project"

    techs: list[str] = []
    files_inspected: str | None = None

    for item in not_checked:
        txt = ""
        if isinstance(item, dict):
            txt = item.get("notice") or item.get("message") or ""
        elif isinstance(item, str):
            txt = item
        if txt.startswith("Scope technologies:"):
            parts = txt.split(". ")
            tech_part = parts[0].removeprefix("Scope technologies:").strip()
            techs = [t.strip() for t in tech_part.split(",") if t.strip()]
            for p in parts[1:]:
                if "Files inspected:" in p:
                    files_inspected = p.removeprefix("Files inspected:").strip().rstrip(".")

    network_enabled = bool(scope.get("network", False))
    allowed_hosts = list(scope.get("allowed_hosts", []))

    if target_kind == "website":
        from urllib.parse import urlsplit

        host = urlsplit(str(target)).hostname or str(target)
        if not allowed_hosts:
            allowed_hosts = [host]
        network_enabled = True
        return {
            "technologies": ["HTML", "HTTPS", "TLS"],
            "files_inspected": "1 pobrana strona HTTPS (odpowiedź GET)"
            if pl
            else "1 fetched HTTPS web page (GET response)",
            "max_files": None,
            "network_enabled": True,
            "allowed_hosts": allowed_hosts,
            "target_kind": "website",
            "target": target,
        }

    if target_kind == "mail_domain":
        domain = str(target).removeprefix("mail-domain:")
        if not allowed_hosts:
            allowed_hosts = [domain]
        network_enabled = True
        return {
            "technologies": ["DNS", "SPF", "DKIM", "DMARC"],
            "files_inspected": "Publiczne rekordy DNS domeny"
            if pl
            else "Public domain DNS records",
            "max_files": None,
            "network_enabled": True,
            "allowed_hosts": allowed_hosts,
            "target_kind": "mail_domain",
            "target": target,
        }

    if target_kind == "eml_message":
        return {
            "technologies": ["Email (RFC 5322)", "MIME", "HTML"],
            "files_inspected": "1 plik wiadomości e-mail (.eml)"
            if pl
            else "1 email message file (.eml)",
            "max_files": 1,
            "network_enabled": False,
            "allowed_hosts": [],
            "target_kind": "eml_message",
            "target": target,
        }

    if target_kind == "mailbox_account":
        return {
            "technologies": ["Gmail API", "OAuth"],
            "files_inspected": "Reguły filtrów i przekazywania poczty"
            if pl
            else "Mailbox filters & forwarding rules",
            "max_files": None,
            "network_enabled": True,
            "allowed_hosts": ["gmail.googleapis.com"],
            "target_kind": "mailbox_account",
            "target": target,
        }

    max_files = scope.get("max_files", 100)
    return {
        "technologies": techs if techs else ["Python", "Config"],
        "files_inspected": files_inspected or f"<= {max_files}",
        "max_files": max_files,
        "network_enabled": network_enabled,
        "allowed_hosts": allowed_hosts,
        "target_kind": target_kind,
        "target": target,
    }


def parse_not_checked_items(not_checked: list[Any], language: str) -> list[dict[str, Any]]:
    """Convert raw not_checked entries into human-readable, categorized items.

    Guarantees no raw Python dictionary representations (`{'source': ...}`)
    ever appear in the output.
    """
    pl = language == "pl"
    raw_notices: list[str] = []

    for item in not_checked:
        if isinstance(item, dict):
            txt = (
                item.get("notice")
                or item.get("message")
                or item.get("reason")
                or item.get("description")
            )
            if not txt:
                target = item.get("target")
                source = item.get("source")
                txt = f"Zakres: {target}" if target else f"Moduł #{source}"
            raw_notices.append(str(txt))
        elif isinstance(item, str):
            raw_notices.append(item)
        else:
            raw_notices.append(str(item))

    website_notices: list[str] = []
    traversal_limits: list[str] = []
    oversized_files: list[str] = []
    excluded_dirs: list[str] = []
    access_errors: list[str] = []
    dependency_notices: list[str] = []
    data_flow_notices: list[str] = []
    scope_notices: list[str] = []
    other_notices: list[str] = []

    for notice in raw_notices:
        n_clean = notice.strip()
        if not n_clean:
            continue
        low = n_clean.lower()
        if low.startswith("scope technologies:"):
            continue
        if any(
            k in low
            for k in (
                "https response",
                "html subset",
                "integrity values",
                "header mapping",
                "unambiguously declared text/html",
                "html finding limit",
                "duplicate attributes",
            )
        ):
            website_notices.append(n_clean)
        elif "traversal stopped" in low or "file/directory limit" in low:
            traversal_limits.append(n_clean)
        elif low.startswith("skipped oversized file:"):
            filename = n_clean.split(":", 1)[1].strip()
            oversized_files.append(filename)
        elif "excluded" in low and ("director" in low or "katalog" in low):
            excluded_dirs.append(n_clean)
        elif "could not enumerate directory:" in low or "permission denied" in low:
            access_errors.append(n_clean)
        elif any(k in low for k in ("flow coverage", "data-flow", "candidate data-flow")):
            data_flow_notices.append(n_clean)
        elif any(k in low for k in ("osv", "manifest", "package sharing", "dependency", "zależno")):
            dependency_notices.append(n_clean)
        elif any(
            k in low
            for k in (
                "ast pattern",
                "selected source",
                "selected read-only",
                "complete coverage",
                "nie obejmuje",
            )
        ):
            scope_notices.append(n_clean)
        else:
            other_notices.append(n_clean)

    categories: list[dict[str, Any]] = []

    # 0. Website Inspection Methodology & Limitations
    if website_notices:
        unique_web = list(dict.fromkeys(website_notices))
        desc_web: list[str] = []
        for w in unique_web:
            translated = NOTICE_TRANSLATIONS_PL.get(w, w) if pl else w
            desc_web.append(translated)
        categories.append(
            {
                "title": (
                    "Metodyka i granice badania witryny WWW"
                    if pl
                    else "Website Inspection Methodology & Scope"
                ),
                "badge": "ZAKRES" if pl else "SCOPE",
                "is_warning": False,
                "description": " • " + "\n • ".join(desc_web),
                "count": len(website_notices),
            }
        )

    # 1. Traversal Limits (Critical warning)
    if traversal_limits:
        categories.append(
            {
                "title": (
                    "Osiągnięto limit przeglądania plików (Analiza niepełna)"
                    if pl
                    else "File Traversal Limit Reached (Incomplete Analysis)"
                ),
                "badge": "OSTRZEŻENIE" if pl else "WARNING",
                "is_warning": True,
                "description": (
                    "Skanowanie struktury projektu osiągnęło limit liczby plików lub katalogów. "
                    "Część plików i katalogów nie została sprawdzona. Aby poszerzyć badany zakres, "
                    "wybierz profil Standardowy (do 1 000 plików), Rozszerzony (do 5 000 plików) "
                    "lub uruchom analizę z parametrem --max-files."
                    if pl
                    else (
                        "Project tree traversal stopped at the file or directory limit. "
                        "Part of the project remains uninspected. To inspect more files, "
                        "select the Standard profile (up to 1,000 files), Extended profile "
                        "(up to 5,000 files), or re-run with --max-files."
                    )
                ),
                "count": len(traversal_limits),
            }
        )

    # 2. Excluded Directories
    if excluded_dirs:
        unique_exc = sorted(set(excluded_dirs))
        categories.append(
            {
                "title": (
                    "Wykluczone katalogi tymczasowe, środowiska i cache"
                    if pl
                    else "Excluded Temporary, Environment & Cache Directories"
                ),
                "badge": "INFORMACJA" if pl else "INFO",
                "is_warning": False,
                "description": (
                    "Automatycznie pominięto katalogi tymczasowe, środowiska wirtualne, buildy "
                    f"i cache: {'; '.join(unique_exc[:3])}"
                    + (f" (+{len(unique_exc) - 3} więcej)" if len(unique_exc) > 3 else "")
                    + "."
                    if pl
                    else (
                        "Temporary directories, virtual environments, builds, and caches were "
                        f"excluded: {'; '.join(unique_exc[:3])}"
                        + (f" (+{len(unique_exc) - 3} more)" if len(unique_exc) > 3 else "")
                        + "."
                    )
                ),
                "count": len(excluded_dirs),
            }
        )

    # 3. Oversized Files
    if oversized_files:
        sample = ", ".join(oversized_files[:5])
        more = f" (+{len(oversized_files) - 5} więcej)" if len(oversized_files) > 5 else ""
        categories.append(
            {
                "title": (
                    f"Pominięto zbyt duże pliki: {len(oversized_files)}"
                    if pl
                    else f"Skipped Oversized Files: {len(oversized_files)}"
                ),
                "badge": "INFORMACJA" if pl else "INFO",
                "is_warning": False,
                "description": (
                    f"Pominięto pliki przekraczające limit rozmiaru (256 KiB): {sample}{more}."
                    if pl
                    else f"Skipped files exceeding 256 KiB size limit: {sample}{more}."
                ),
                "count": len(oversized_files),
            }
        )

    # 4. Access / Permission Errors
    if access_errors:
        unique_errs = sorted(set(access_errors))
        categories.append(
            {
                "title": (
                    f"Błędy dostępu do katalogów: {len(access_errors)}"
                    if pl
                    else f"Directory Access Errors: {len(access_errors)}"
                ),
                "badge": "OSTRZEŻENIE" if pl else "WARNING",
                "is_warning": True,
                "description": "; ".join(unique_errs[:3])
                + (f" (+{len(unique_errs) - 3} więcej)" if len(unique_errs) > 3 else ""),
                "count": len(access_errors),
            }
        )

    # 5. Data Flow Notices (Grouped)
    if data_flow_notices:
        categories.append(
            {
                "title": (
                    "Ograniczenie analizy przepływu danych (Data Flow)"
                    if pl
                    else "Data Flow Coverage Limitations"
                ),
                "badge": "ZAKRES" if pl else "SCOPE",
                "is_warning": False,
                "description": (
                    f"Statyczna analiza przepływu danych została wykonana dla wyselekcjonowanych "
                    f"modułów ({len(data_flow_notices)} plików). Nie obejmuje pełnej "
                    "międzymodułowej osiągalności kodu ani wywołań w czasie wykonania (runtime)."
                    if pl
                    else (
                        f"Candidate data-flow checks were applied to selected modules "
                        f"({len(data_flow_notices)} files). Full whole-program "
                        "inter-procedural reachability and dynamic runtime "
                        "execution are not modeled."
                    )
                ),
                "count": len(data_flow_notices),
            }
        )

    # 6. Dependency Notices
    if dependency_notices:
        unique_dep = sorted(set(dependency_notices))
        desc_list: list[str] = []
        for d in unique_dep:
            if "No OSV query" in d:
                desc_list.append(
                    "Baza podatności OSV: Wyłączona w domyślnym trybie offline "
                    "(wymaga opcji --share-packages / zezwolenia sieciowego)"
                    if pl
                    else "OSV vulnerability database: Disabled in default offline mode "
                    "(requires --share-packages network consent)"
                )
            elif "Root-directory supported manifests" in d or "Root-only dependency" in d:
                desc_list.append(
                    (
                        "Inwentaryzacja zależności: Badano manifesty w katalogu "
                        "głównym (bez flagi rekurencyjnej)"
                    )
                    if pl
                    else (
                        "Dependency inventory: Inspected root-directory "
                        "manifests only (non-recursive)"
                    )
                )
            elif "Selected recursive supported manifests" in d:
                desc_list.append(
                    (
                        "Inwentaryzacja zależności: Dokładne wersje pakietów "
                        "z manifestów rekurencyjnych"
                    )
                    if pl
                    else "Dependency inventory: Exact package versions from recursive manifests"
                )
            else:
                desc_list.append(d)
        categories.append(
            {
                "title": (
                    "Inwentaryzacja zależności i baza OSV"
                    if pl
                    else "Dependency Inventory & OSV Advisories"
                ),
                "badge": "INFORMACJA" if pl else "INFO",
                "is_warning": False,
                "description": " • " + "\n • ".join(desc_list),
                "count": len(dependency_notices),
            }
        )

    # 7. General Static Scope Boundaries
    if scope_notices:
        unique_scope = sorted(set(scope_notices))
        desc_list_scope: list[str] = []
        for s in unique_scope:
            if "Only selected Python AST patterns" in s:
                desc_list_scope.append(
                    (
                        "Analizator kodu Python: Badano wybrane statyczne wzorce AST; "
                        "brak analizy wykonania w czasie rzeczywistym"
                    )
                    if pl
                    else (
                        "Python code analyzer: Checked selected static AST patterns; "
                        "no runtime reachability analysis"
                    )
                )
            elif "Selected source/config items only" in s:
                desc_list_scope.append(
                    (
                        "Zakres ogólny: Zbadano wybrane pliki źródłowe i konfiguracyjne; "
                        "pozostałe technologie wymagają dedykowanych narzędzi"
                    )
                    if pl
                    else (
                        "General scope: Checked selected source and config files; "
                        "other technologies require dedicated tools"
                    )
                )
            else:
                desc_list_scope.append(s)
        categories.append(
            {
                "title": (
                    "Granice i metodyka analizy statycznej"
                    if pl
                    else "Static Analysis Scope & Boundaries"
                ),
                "badge": "INFORMACJA" if pl else "INFO",
                "is_warning": False,
                "description": " • " + "\n • ".join(desc_list_scope),
                "count": len(scope_notices),
            }
        )

    # 8. Other unique notices (clean, no raw dicts!)
    if other_notices:
        unique_other = list(dict.fromkeys(other_notices))
        for item_txt in unique_other[:5]:
            translated_item = NOTICE_TRANSLATIONS_PL.get(item_txt, item_txt) if pl else item_txt
            categories.append(
                {
                    "title": (
                        "Pozostałe ograniczenia zakresu" if pl else "Other Scope Limitations"
                    ),
                    "badge": "INFORMACJA" if pl else "INFO",
                    "is_warning": False,
                    "description": translated_item,
                    "count": 1,
                }
            )

    return categories


def validate_ai_review_binding(report: dict, ai_review: dict) -> None:
    """Verify that an AI review strictly corresponds to the provided technical audit report."""
    if not isinstance(ai_review, dict):
        raise ValidationError("AI review must be a dictionary")
    interp = ai_review.get("interpretation")
    if not isinstance(interp, dict):
        raise ValidationError("AI review has no valid interpretation object")
    observations = interp.get("observations")
    if not isinstance(observations, list):
        raise ValidationError("AI review has no observations array")

    findings = report.get("findings", [])
    valid_ids = {
        f.get("evidence_id") or f.get("id") or f.get("finding_id")
        for f in findings
        if isinstance(f, dict) and (f.get("evidence_id") or f.get("id") or f.get("finding_id"))
    }

    obs_ids = {
        obs.get("evidence_id") or obs.get("finding_id") or obs.get("id")
        for obs in observations
        if isinstance(obs, dict)
        and (obs.get("evidence_id") or obs.get("finding_id") or obs.get("id"))
    }
    if not obs_ids:
        raise ValidationError("AI review observations contain no valid finding references")

    unknown = obs_ids - valid_ids
    if unknown:
        obs_list = sorted(unknown)
        raise ValidationError(
            f"AI review contains {len(unknown)} observation(s) not found "
            f"in technical report: {obs_list}"
        )


def generate_pdf_report(
    report: dict[str, Any],
    *,
    ai_review: dict[str, Any] | None = None,
    language: str = "en",
    lang: str | None = None,
    source_root: Path | str | None = None,
    project_name: str | None = None,
    manifest: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
) -> bytes:
    """Generate a complete, publication-grade security audit report PDF.

    Returns the raw PDF 1.4 binary data.
    """
    if lang is not None:
        language = lang
    validate_report_language(language)

    if ai_review is not None:
        validate_ai_review_binding(report, ai_review)

    doc = PDFDocument()
    pl = language == "pl"

    # Extract accurate project name and full target path
    display_project, target_path_str = extract_project_identity(
        report, project_name=project_name, manifest=manifest, scope=scope
    )
    scope_details = extract_scope_details(
        report, manifest=manifest, scope_arg=scope, language=language
    )
    target_kind = scope_details.get("target_kind", "local_project")

    findings = detailed_findings(report, language=language)
    not_checked = report.get("not_checked", [])
    status = str(report.get("status", "completed")).lower()
    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Assess traversal limit and completeness
    is_traversal_limited = any(
        "traversal stopped" in str(item).lower() or "file/directory limit" in str(item).lower()
        for item in not_checked
    )
    is_partial = (status == "partial") or is_traversal_limited

    # AI interpretation mapping
    ai_obs_map: dict[str, dict] = {}
    ai_summary = ""
    ai_uncertainty = ""
    ai_model = ""
    if ai_review is not None:
        interp = ai_review.get("interpretation", {})
        ai_summary = interp.get("summary", "")
        ai_uncertainty = interp.get("uncertainty", "")
        ai_model = ai_review.get("model", "Google Gemini")
        for obs in interp.get("observations", []):
            if isinstance(obs, dict) and obs.get("evidence_id"):
                ai_obs_map[obs["evidence_id"]] = obs

    # =========================================================================
    # 1. TITLE / COVER PAGE
    # =========================================================================
    # Top decorative primary accent bar
    doc.rect(doc.margin_x, doc.height - 50, doc.content_width, 6, fill=COLOR_PRIMARY)

    # Header branding
    doc.text(
        doc.margin_x,
        doc.height - 85,
        t("app_title", language),
        font="Helvetica-Bold",
        size=22,
        color=COLOR_PRIMARY,
    )
    doc.text(
        doc.margin_x,
        doc.height - 105,
        t("app_subtitle", language),
        font="Helvetica",
        size=10,
        color=COLOR_TEXT_MUTED,
    )

    # Document Title Card
    doc.rect(
        doc.margin_x,
        doc.height - 235,
        doc.content_width,
        115,
        fill=COLOR_BG_CARD,
        stroke=COLOR_BORDER,
    )
    doc.text(
        doc.margin_x + 16,
        doc.height - 145,
        t("report_title", language),
        font="Helvetica-Bold",
        size=17,
        color=COLOR_PRIMARY,
    )

    # Prominent Project Name Display
    project_title_label = f"PROJEKT: {display_project}" if pl else f"PROJECT: {display_project}"
    doc.text(
        doc.margin_x + 16,
        doc.height - 175,
        project_title_label,
        font="Helvetica-Bold",
        size=14,
        color=COLOR_SECONDARY,
    )

    # Target path location line
    path_label = f"Lokalizacja: {target_path_str}" if pl else f"Location: {target_path_str}"
    doc.text(
        doc.margin_x + 16,
        doc.height - 200,
        path_label,
        font="Courier",
        size=8.5,
        color=COLOR_TEXT_MUTED,
    )

    # Metadata Box
    meta_y = doc.height - 250
    doc.rect(
        doc.margin_x, meta_y - 125, doc.content_width, 125, fill=(1, 1, 1), stroke=COLOR_BORDER
    )

    status_label = "CZĘŚCIOWY (PARTIAL)" if is_partial else status.upper()
    if target_kind == "website":
        scope_label = (
            "Pasywna analiza strony WWW (HTTPS/HTML)"
            if pl
            else "Passive Website Analysis (HTTPS/HTML)"
        )
        net_label = (
            f"Wymagane — połączenie HTTPS ({scope_details['allowed_hosts'][0]})"
            if scope_details["allowed_hosts"]
            else "Wymagane — połączenie HTTPS"
        )
        if not pl:
            net_label = (
                f"Required — HTTPS connection ({scope_details['allowed_hosts'][0]})"
                if scope_details["allowed_hosts"]
                else "Required — HTTPS connection"
            )
    elif target_kind == "mail_domain":
        scope_label = (
            "Weryfikacja rekordów uwierzytelniania domeny pocztowej"
            if pl
            else "Mail Domain Authentication Records"
        )
        host_str = (
            scope_details["allowed_hosts"][0] if scope_details["allowed_hosts"] else display_project
        )
        net_label = (
            f"Zapytania DoH (DNS-over-HTTPS) dla {host_str}"
            if pl
            else f"DoH (DNS-over-HTTPS) for {host_str}"
        )
    elif target_kind == "eml_message":
        scope_label = (
            "Lokalna analiza struktury wiadomości e-mail (.eml)"
            if pl
            else "Local Email Message Structure (.eml)"
        )
        net_label = (
            "Pełna izolacja offline (brak połączeń)"
            if pl
            else "Full offline isolation (no network calls)"
        )
    else:
        scope_label = "Statyczna analiza offline" if pl else "Offline static analysis"
        net_label = (
            ("Zezwolono na hosty: " + ", ".join(scope_details["allowed_hosts"]))
            if scope_details["network_enabled"]
            else ("Pełna izolacja offline" if pl else "Full offline isolation")
        )

    meta_rows = [
        ("Projekt / Cel" if pl else "Project / Target", display_project),
        ("Adres celu" if pl else "Target Address", target_path_str),
        ("Data analizy" if pl else "Audit Date", date_str),
        ("Status przebiegu" if pl else "Audit Status", status_label),
        (
            "Interpretacja AI" if pl else "AI Interpretation",
            f"Google Gemini ({ai_model})"
            if ai_review
            else ("Brak — tryb w pełni lokalny" if pl else "None — fully offline mode"),
        ),
        (
            "Zakres analizy" if pl else "Analysis Scope",
            scope_label,
        ),
        (
            "Połączenie sieciowe" if pl else "Network Connection",
            net_label,
        ),
    ]

    curr_row_y = meta_y - 18
    for label, val in meta_rows:
        doc.text(
            doc.margin_x + 16,
            curr_row_y,
            f"{label}:",
            font="Helvetica-Bold",
            size=9,
            color=COLOR_SECONDARY,
        )
        doc.text(
            doc.margin_x + 160,
            curr_row_y,
            val,
            font="Helvetica",
            size=9,
            color=COLOR_TEXT_DARK,
        )
        curr_row_y -= 19

    # Scope Disclaimer Box
    disc_y = doc.height - 395
    doc.rect(
        doc.margin_x, disc_y - 95, doc.content_width, 95, fill=COLOR_BG_ALT, stroke=COLOR_BORDER
    )
    doc.text(
        doc.margin_x + 16,
        disc_y - 18,
        t("disclaimer_title", language),
        font="Helvetica-Bold",
        size=9.5,
        color=COLOR_PRIMARY,
    )
    doc.draw_text_block(
        doc.margin_x + 16,
        disc_y - 34,
        t("disclaimer_text", language),
        doc.content_width - 32,
        font="Helvetica",
        size=8.5,
        line_height=12.5,
        color=COLOR_TEXT_DARK,
    )

    # Executive Overview on Cover Page
    exec_y = doc.height - 515
    doc.text(
        doc.margin_x,
        exec_y,
        t("section_executive_summary", language),
        font="Helvetica-Bold",
        size=13,
        color=COLOR_PRIMARY,
    )
    doc.line(
        doc.margin_x,
        exec_y - 6,
        doc.margin_x + doc.content_width,
        exec_y - 6,
        stroke=COLOR_SECONDARY,
        line_width=1,
    )

    p1_count = sum(1 for f in findings if f.triage_priority == "P1")
    p2_count = sum(1 for f in findings if f.triage_priority == "P2")
    p3_count = sum(1 for f in findings if f.triage_priority == "P3")
    total_findings = len(findings)

    # Credible, unambiguous executive summary prose
    if total_findings == 0:
        if is_partial:
            if pl:
                partial_reason = (
                    "Osiągnięto limit przeglądania plików/katalogów — część struktury "
                    "projektu nie została zbadana. "
                    if is_traversal_limited
                    else (
                        "Niektóre analizatory nie zostały w pełni wykonane "
                        "lub nie posiadały konfiguracji. "
                    )
                )
                summary_prose = (
                    "W sprawdzonym zakresie plików nie wykryto znanych wzorców podatności. "
                    "UWAGA: Przeprowadzona analiza miała charakter CZĘŚCIOWY (status: PARTIAL). "
                    f"{partial_reason}"
                    "Zero wykryć dotyczy wyłącznie zbadanego fragmentu kodu i nie stanowi "
                    "gwarancji bezpieczeństwa całego projektu ani braku innych podatności."
                )
            else:
                partial_reason_en = (
                    "File traversal limits were reached — part of the project "
                    "tree remains uninspected. "
                    if is_traversal_limited
                    else "Some analysis modules were bounded or unconfigured. "
                )
                summary_prose = (
                    "No known vulnerability patterns were identified within the "
                    "inspected file scope. "
                    "NOTICE: This analysis was PARTIAL (status: PARTIAL). "
                    f"{partial_reason_en}"
                    "Zero findings applies strictly to the inspected subset of code and does not "
                    "guarantee the overall security of the project or absence of vulnerabilities."
                )
        else:
            if pl:
                summary_prose = (
                    "W zbadanym zakresie projektu nie wykryto znanych wzorców podatności objętych "
                    "aktywnymi regułami analizy statycznej offline. Należy pamiętać, że analiza "
                    "statyczna kodu nie obejmuje zachowań w czasie wykonania, logiki biznesowej "
                    "ani interakcji sieciowych."
                )
            else:
                summary_prose = (
                    "No known vulnerability patterns were detected within the inspected project "
                    "scope under active offline static rules. Note that static code analysis "
                    "does not inspect runtime reachability, business logic flaws, "
                    "or network interactions."
                )
    else:
        if pl:
            p1_advice = (
                "Zaleca się priorytetowe zbadanie problemów P1 przed wdrożeniem produkcyjnym."
                if p1_count > 0
                else "Zaleca się zapoznanie ze szczegółami obserwacji i zastosowanie rekomendacji."
            )
            summary_prose = (
                f"W projekcie wykryto łącznie {total_findings} potencjalnych problemów "
                f"bezpieczeństwa (P1: {p1_count}, P2: {p2_count}, P3: {p3_count}). "
                f"Wszystkie wykrycia mają charakter kandydatów wymagających weryfikacji. "
                f"{p1_advice}"
            )
        else:
            p1_advice = (
                "Immediate attention is recommended for P1 items prior to deployment."
                if p1_count > 0
                else "Review the detailed observations below and apply recommendations."
            )
            summary_prose = (
                f"The analysis identified a total of {total_findings} finding(s) "
                f"(P1: {p1_count}, P2: {p2_count}, P3: {p3_count}). All findings represent "
                f"candidate observations requiring human context verification. {p1_advice}"
            )

    doc.draw_text_block(
        doc.margin_x,
        exec_y - 20,
        summary_prose,
        doc.content_width,
        font="Helvetica",
        size=9,
        line_height=13.5,
        color=COLOR_TEXT_DARK,
    )

    # Metrics Summary Cards
    cards_y = exec_y - 105
    card_w = (doc.content_width - 24) / 4
    card_h = 55

    status_card_val = (
        ("CZĘŚCIOWY" if pl else "PARTIAL") if is_partial else ("KOMPLETNY" if pl else "COMPLETE")
    )
    status_card_col = (0.75, 0.40, 0.0) if is_partial else (0.1, 0.5, 0.1)

    traversal_card_val = (
        ("LIMIT" if pl else "LIMITED") if is_traversal_limited else ("W NORMIE" if pl else "OK")
    )
    traversal_card_col = (0.75, 0.15, 0.15) if is_traversal_limited else COLOR_TEXT_MUTED

    metrics = [
        (
            "POTENCJALNE ZAGROŻENIA" if pl else "TOTAL THREATS",
            str(total_findings),
            COLOR_PRIMARY if total_findings == 0 else (0.7, 0.1, 0.1),
        ),
        (
            "STATUS AUDYTU" if pl else "AUDIT STATUS",
            status_card_val,
            status_card_col,
        ),
        (
            ("METODA BADANIA" if pl else "METHOD")
            if target_kind == "website"
            else (
                ("REKORDY DNS" if pl else "DNS RECORDS")
                if target_kind == "mail_domain"
                else (
                    ("PLIK POCZTY" if pl else "MESSAGE FILE")
                    if target_kind == "eml_message"
                    else ("LIMIT PLIKÓW" if pl else "FILE LIMIT")
                )
            ),
            (
                "HTTPS"
                if target_kind == "website"
                else (
                    "DOH"
                    if target_kind == "mail_domain"
                    else (
                        ("1 PLIK" if pl else "1 FILE")
                        if target_kind == "eml_message"
                        else traversal_card_val
                    )
                )
            ),
            ((0.1, 0.4, 0.7) if target_kind in ("website", "mail_domain") else traversal_card_col),
        ),
        (
            "OGRANICZENIA ZAKRESU" if pl else "SCOPE BOUNDS",
            str(len(not_checked)),
            COLOR_TEXT_MUTED,
        ),
    ]

    for idx, (lbl, val, col) in enumerate(metrics):
        cx = doc.margin_x + idx * (card_w + 8)
        doc.rect(cx, cards_y - card_h, card_w, card_h, fill=COLOR_BG_CARD, stroke=COLOR_BORDER)
        doc.text(cx + 8, cards_y - 18, lbl, font="Helvetica-Bold", size=6.5, color=COLOR_TEXT_MUTED)
        doc.text(cx + 8, cards_y - 45, val, font="Helvetica-Bold", size=15, color=col)

    # =========================================================================
    # 2. AUDIT SCOPE & METHODOLOGY
    # =========================================================================
    doc.new_page()

    doc.text(
        doc.margin_x,
        doc.cursor_y,
        t("section_audit_scope", language),
        font="Helvetica-Bold",
        size=14,
        color=COLOR_PRIMARY,
    )
    doc.cursor_y -= 8
    doc.line(
        doc.margin_x,
        doc.cursor_y,
        doc.margin_x + doc.content_width,
        doc.cursor_y,
        stroke=COLOR_SECONDARY,
        line_width=1,
    )
    doc.cursor_y -= 16

    ai_mode_str = (
        (
            "Interpretacja doradcza AI (Google Gemini)"
            if pl
            else "AI Advisory Review (Google Gemini)"
        )
        if ai_review
        else (
            "Lokalna analiza deterministyczna offline"
            if pl
            else "Offline deterministic static rules"
        )
    )

    if target_kind == "website":
        s_rows = [
            ("Adres HTTPS" if pl else "HTTPS URL", target_path_str),
            ("Faktyczny host" if pl else "Target Host", display_project),
            (
                "Połączenie sieciowe" if pl else "Network Connection",
                f"Bezpieczne zapytanie HTTPS ({display_project}:443)"
                if pl
                else f"Secure HTTPS query ({display_project}:443)",
            ),
            (
                "Metoda badania" if pl else "Inspection Method",
                "Pasywna analiza nagłówków HTTP, parametrów TLS i struktury HTML"
                if pl
                else "Passive inspection of HTTP headers, TLS parameters, and HTML structure",
            ),
            (
                "Zakres zasobów" if pl else "Inspected Resources",
                "Pojedyncza strona główna (GET 200, bez przekierowań i bez uruchamiania JS)"
                if pl
                else "Single main page (GET 200, no redirects, no JavaScript execution)",
            ),
            ("Tryb analizy" if pl else "Analysis Mode", ai_mode_str),
        ]
    elif target_kind == "mail_domain":
        s_rows = [
            ("Badana domena" if pl else "Inspected Domain", display_project),
            (
                "Połączenie sieciowe" if pl else "Network Connection",
                f"Zapytania DoH (DNS-over-HTTPS) dla {display_project}"
                if pl
                else f"DoH (DNS-over-HTTPS) queries for {display_project}",
            ),
            (
                "Metoda badania" if pl else "Inspection Method",
                "Weryfikacja rekordów SPF, DMARC i kluczy DKIM w publicznym DNS"
                if pl
                else "Public DNS SPF, DMARC, and DKIM verification",
            ),
            (
                "Zakres rekordów" if pl else "Inspected Records",
                "Rekordy TXT dla SPF i DMARC, publikacja selektora DKIM"
                if pl
                else "TXT records for SPF/DMARC, DKIM selector publication",
            ),
            ("Tryb analizy" if pl else "Analysis Mode", ai_mode_str),
        ]
    elif target_kind == "eml_message":
        s_rows = [
            ("Plik wiadomości" if pl else "Message File", display_project),
            (
                "Połączenie sieciowe" if pl else "Network Connection",
                "Pełna izolacja offline (brak połączeń)"
                if pl
                else "Full offline isolation (no network calls)",
            ),
            (
                "Metoda badania" if pl else "Inspection Method",
                "Pasywna analiza nagłówków RFC 5322, struktury MIME i odnośników"
                if pl
                else "Passive inspection of RFC 5322 headers, MIME structure, and URLs",
            ),
            (
                "Zakres badania" if pl else "Inspected Scope",
                "Pojedynczy plik wiadomości e-mail (.eml)"
                if pl
                else "Single email message file (.eml)",
            ),
            ("Tryb analizy" if pl else "Analysis Mode", ai_mode_str),
        ]
    else:
        tech_str = ", ".join(scope_details["technologies"]) or (
            "Python, Pliki konfiguracji" if pl else "Python, Config files"
        )
        files_str = scope_details["files_inspected"]
        if scope_details.get("max_files"):
            files_str += f" (maks. limit: {scope_details['max_files']})"
        net_str = (
            ("Zezwolono na hosty: " + ", ".join(scope_details["allowed_hosts"]))
            if scope_details["network_enabled"]
            else (
                "Pełna izolacja offline (brak połączeń sieciowych)"
                if pl
                else "Full offline isolation (no network calls)"
            )
        )
        s_rows = [
            (t("field_tech_recognized", language), tech_str),
            (t("field_files_scanned", language), files_str),
            (t("field_network_policy", language), net_str),
            ("Tryb analizy" if pl else "Analysis Mode", ai_mode_str),
        ]

    scope_box_h = 20 + len(s_rows) * 16
    doc.rect(
        doc.margin_x,
        doc.cursor_y - scope_box_h,
        doc.content_width,
        scope_box_h,
        fill=COLOR_BG_CARD,
        stroke=COLOR_BORDER,
    )

    sy = doc.cursor_y - 15
    for slabel, sval in s_rows:
        doc.text(
            doc.margin_x + 12,
            sy,
            f"{slabel}:",
            font="Helvetica-Bold",
            size=8.5,
            color=COLOR_SECONDARY,
        )
        doc.text(
            doc.margin_x + 150,
            sy,
            sval,
            font="Helvetica",
            size=8.5,
            color=COLOR_TEXT_DARK,
        )
        sy -= 16

    doc.cursor_y -= scope_box_h + 20

    # =========================================================================
    # 3. DETAILED FINDINGS
    # =========================================================================
    doc.ensure_space(60)
    doc.text(
        doc.margin_x,
        doc.cursor_y,
        t("section_detailed_findings", language),
        font="Helvetica-Bold",
        size=14,
        color=COLOR_PRIMARY,
    )
    doc.cursor_y -= 8
    doc.line(
        doc.margin_x,
        doc.cursor_y,
        doc.margin_x + doc.content_width,
        doc.cursor_y,
        stroke=COLOR_SECONDARY,
        line_width=1,
    )
    doc.cursor_y -= 20

    if total_findings == 0:
        clean_notice = (
            (
                "W zbadanym zakresie plików nie wykryto żadnych znanych "
                "podatności ani kandydatów na zagrożenia."
            )
            if pl
            else (
                "No known vulnerabilities or candidate threats were "
                "detected in the inspected files."
            )
        )
        doc.text(
            doc.margin_x,
            doc.cursor_y,
            clean_notice,
            font="Helvetica-Oblique",
            size=9.5,
            color=COLOR_TEXT_MUTED,
        )
        doc.cursor_y -= 30
    else:
        for idx, finding in enumerate(findings, 1):
            badge_config = BADGE_COLORS.get(finding.triage_priority, BADGE_COLORS["P3"])

            doc.ensure_space(180)

            # Finding Header Line: "Threat #1: Title"
            header_title = f"{t('field_threat_number', language, index=idx)}: {finding.title}"
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                header_title,
                font="Helvetica-Bold",
                size=12,
                color=COLOR_PRIMARY,
            )

            # Priority Badge on right
            badge_label = t(f"priority_{finding.triage_priority.lower()}", language)
            doc.badge(
                doc.margin_x + doc.content_width - 120,
                doc.cursor_y + 1,
                badge_label,
                bg_color=badge_config[0],
                text_color=badge_config[1],
                border_color=badge_config[2],
                font_size=8,
            )

            doc.cursor_y -= 18

            # Sub-bar: Status and Location
            loc_label = finding.file_path or finding.target
            if finding.line_number is not None:
                loc_label += f":{finding.line_number}"
            status_text = (
                t("status_candidate", language)
                if finding.confirmation_status == "candidate"
                else t("status_confirmed", language)
            )

            sub_bar = (
                f"{t('field_status', language)}: {status_text}  |  "
                f"{t('field_location', language)}: {loc_label}"
            )
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                sub_bar,
                font="Helvetica",
                size=8.5,
                color=COLOR_TEXT_MUTED,
            )
            doc.cursor_y -= 14

            # Section: What was detected?
            doc.ensure_space(45)
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                t("field_what_detected", language),
                font="Helvetica-Bold",
                size=9,
                color=COLOR_SECONDARY,
            )
            doc.cursor_y -= 12
            h1 = doc.draw_text_block(
                doc.margin_x,
                doc.cursor_y,
                finding.what_was_detected,
                doc.content_width,
                font="Helvetica",
                size=8.5,
                line_height=12,
                color=COLOR_TEXT_DARK,
            )
            doc.cursor_y -= h1 + 8

            # Section: Why is it dangerous?
            doc.ensure_space(60)
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                t("field_why_dangerous", language),
                font="Helvetica-Bold",
                size=9,
                color=COLOR_SECONDARY,
            )
            doc.cursor_y -= 12
            mech_text = f"{finding.mechanism} {finding.consequences}"
            h2 = doc.draw_text_block(
                doc.margin_x,
                doc.cursor_y,
                mech_text,
                doc.content_width,
                font="Helvetica",
                size=8.5,
                line_height=12,
                color=COLOR_TEXT_DARK,
            )
            doc.cursor_y -= h2 + 8

            # Section: Source Code Snippet
            doc.ensure_space(80)
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                t("field_code_snippet", language),
                font="Helvetica-Bold",
                size=9,
                color=COLOR_SECONDARY,
            )
            doc.cursor_y -= 12

            snippet = extract_code_snippet(
                finding.file_path or finding.target,
                finding.line_number,
                context_lines=2,
                source_root=source_root,
            )

            if snippet and snippet.lines:
                box_lines = len(snippet.lines)
                box_h = (box_lines * 14.0) + 12.0
                doc.rect(
                    doc.margin_x,
                    doc.cursor_y - box_h + 10,
                    doc.content_width,
                    box_h,
                    fill=(0.97, 0.98, 0.99),
                    stroke=COLOR_BORDER,
                )

                code_y = doc.cursor_y - 2
                for sline in snippet.lines:
                    if sline.is_target:
                        doc.rect(
                            doc.margin_x + 1,
                            code_y - 9.5,
                            doc.content_width - 2,
                            13.5,
                            fill=(0.99, 0.95, 0.88),
                        )
                        marker = "> "
                        num_col = (0.7, 0.2, 0.1)
                        code_col = (0.6, 0.1, 0.1)
                    else:
                        marker = "  "
                        num_col = COLOR_TEXT_MUTED
                        code_col = COLOR_TEXT_DARK

                    line_prefix = f"{marker}{sline.line_number:4d} | "
                    doc.text(
                        doc.margin_x + 8,
                        code_y,
                        line_prefix,
                        font="Courier-Bold" if sline.is_target else "Courier",
                        size=8,
                        color=num_col,
                    )
                    doc.text(
                        doc.margin_x + 65,
                        code_y,
                        sline.text,
                        font="Courier-Bold" if sline.is_target else "Courier",
                        size=8,
                        color=code_col,
                    )
                    code_y -= 14.0

                doc.cursor_y -= box_h + 8
            elif target_kind == "website" and finding.line_number is not None:
                tag_preview = ""
                if "<script" in finding.evidence:
                    import re

                    m = re.search(r"(<script[^>]*>)", finding.evidence)
                    if m:
                        tag_preview = m.group(1) + "</script>"
                if not tag_preview:
                    tag_preview = (
                        f'<script src="..."></script> (linia {finding.line_number})'
                        if pl
                        else f'<script src="..."></script> (line {finding.line_number})'
                    )

                box_h = 42.0
                doc.rect(
                    doc.margin_x,
                    doc.cursor_y - box_h + 10,
                    doc.content_width,
                    box_h,
                    fill=(0.97, 0.98, 0.99),
                    stroke=COLOR_BORDER,
                )
                doc.rect(
                    doc.margin_x + 1,
                    doc.cursor_y - 12,
                    doc.content_width - 2,
                    15.0,
                    fill=(0.99, 0.95, 0.88),
                )
                doc.text(
                    doc.margin_x + 8,
                    doc.cursor_y - 1,
                    f"> {finding.line_number:4d} | ",
                    font="Courier-Bold",
                    size=8,
                    color=(0.7, 0.2, 0.1),
                )
                doc.text(
                    doc.margin_x + 65,
                    doc.cursor_y - 1,
                    tag_preview,
                    font="Courier-Bold",
                    size=8,
                    color=(0.6, 0.1, 0.1),
                )
                doc.text(
                    doc.margin_x + 8,
                    doc.cursor_y - 18,
                    (
                        "Źródło: Pobrana odpowiedź HTTPS (GET 200)  |  "
                        "Brak atrybutu integrity (Subresource Integrity)"
                    )
                    if pl
                    else (
                        "Source: Fetched HTTPS response (GET 200)  |  "
                        "Missing integrity attribute (Subresource Integrity)"
                    ),
                    font="Helvetica",
                    size=7.5,
                    color=COLOR_TEXT_MUTED,
                )
                doc.cursor_y -= box_h + 8
            else:
                notice = t("source_code_unavailable", language)
                doc.text(
                    doc.margin_x,
                    doc.cursor_y,
                    notice,
                    font="Helvetica-Oblique",
                    size=8,
                    color=COLOR_TEXT_MUTED,
                )
                doc.cursor_y -= 16

            # Section: What to check?
            doc.ensure_space(45)
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                t("field_what_to_check", language),
                font="Helvetica-Bold",
                size=9,
                color=COLOR_SECONDARY,
            )
            doc.cursor_y -= 12
            verify_msg = (
                "Sprawdź, czy dane wejściowe przekazywane do tej operacji mogą "
                "pochodzić z zewnętrznych źródeł i czy są rygorystycznie walidowane."
                if pl
                else (
                    "Verify whether input reaching this operation originates "
                    "from untrusted external sources and is strictly validated."
                )
            )
            h_check = doc.draw_text_block(
                doc.margin_x,
                doc.cursor_y,
                verify_msg,
                doc.content_width,
                font="Helvetica",
                size=8.5,
                line_height=12,
                color=COLOR_TEXT_DARK,
            )
            doc.cursor_y -= h_check + 8

            # Section: How to fix?
            doc.ensure_space(55)
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                t("field_how_to_fix", language),
                font="Helvetica-Bold",
                size=9,
                color=COLOR_SECONDARY,
            )
            doc.cursor_y -= 12
            h3 = doc.draw_text_block(
                doc.margin_x,
                doc.cursor_y,
                finding.recommendation,
                doc.content_width,
                font="Helvetica",
                size=8.5,
                line_height=12,
                color=COLOR_TEXT_DARK,
            )
            doc.cursor_y -= h3 + 8

            # Code example if provided
            if finding.code_example:
                doc.ensure_space(50)
                ex_lines = finding.code_example.splitlines()
                ex_h = len(ex_lines) * 12.0 + 8.0
                doc.rect(
                    doc.margin_x,
                    doc.cursor_y - ex_h + 8,
                    doc.content_width,
                    ex_h,
                    fill=(0.95, 0.97, 0.95),
                    stroke=(0.8, 0.88, 0.8),
                )
                ey = doc.cursor_y - 2
                for el in ex_lines:
                    doc.text(
                        doc.margin_x + 10, ey, el, font="Courier", size=7.5, color=(0.1, 0.4, 0.1)
                    )
                    ey -= 12.0
                doc.cursor_y -= ex_h + 8

            # Section: How to verify?
            doc.ensure_space(40)
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                t("field_how_to_verify", language),
                font="Helvetica-Bold",
                size=9,
                color=COLOR_SECONDARY,
            )
            doc.cursor_y -= 12
            h4 = doc.draw_text_block(
                doc.margin_x,
                doc.cursor_y,
                finding.verification_steps,
                doc.content_width,
                font="Helvetica",
                size=8.5,
                line_height=12,
                color=COLOR_TEXT_DARK,
            )
            doc.cursor_y -= h4 + 8

            # Section: Analysis Limitations
            doc.ensure_space(35)
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                t("field_limitations", language),
                font="Helvetica-Bold",
                size=8.5,
                color=COLOR_TEXT_MUTED,
            )
            doc.cursor_y -= 11
            h5 = doc.draw_text_block(
                doc.margin_x,
                doc.cursor_y,
                finding.analysis_limitations,
                doc.content_width,
                font="Helvetica-Oblique",
                size=8,
                line_height=11,
                color=COLOR_TEXT_MUTED,
            )
            doc.cursor_y -= h5 + 8

            # AI observation block if tied to this finding
            if finding.id in ai_obs_map:
                ai_finding_obs = ai_obs_map[finding.id]
                doc.ensure_space(60)
                doc.rect(
                    doc.margin_x,
                    doc.cursor_y - 50,
                    doc.content_width,
                    55,
                    fill=(0.95, 0.96, 0.99),
                    stroke=(0.7, 0.8, 0.95),
                )
                doc.text(
                    doc.margin_x + 8,
                    doc.cursor_y - 12,
                    "Interpretacja AI (Google Gemini):"
                    if pl
                    else "AI Interpretation (Google Gemini):",
                    font="Helvetica-Bold",
                    size=8.5,
                    color=COLOR_PRIMARY,
                )
                ai_note = ai_finding_obs.get("explanation", "")
                doc.draw_text_block(
                    doc.margin_x + 8,
                    doc.cursor_y - 25,
                    ai_note,
                    doc.content_width - 16,
                    font="Helvetica",
                    size=8,
                    line_height=11,
                    color=COLOR_TEXT_DARK,
                )
                doc.cursor_y -= 62

            # Divider line between findings
            doc.cursor_y -= 10
            doc.line(
                doc.margin_x,
                doc.cursor_y,
                doc.margin_x + doc.content_width,
                doc.cursor_y,
                stroke=COLOR_BORDER,
                line_width=0.75,
            )
            doc.cursor_y -= 18

    # =========================================================================
    # 3. AI INTERPRETATION SECTION (IF PRESENT)
    # =========================================================================
    if ai_review is not None and ai_summary:
        doc.ensure_space(140)
        doc.text(
            doc.margin_x,
            doc.cursor_y,
            t("section_ai_interpretation", language),
            font="Helvetica-Bold",
            size=13,
            color=COLOR_PRIMARY,
        )
        doc.cursor_y -= 8
        doc.line(
            doc.margin_x,
            doc.cursor_y,
            doc.margin_x + doc.content_width,
            doc.cursor_y,
            stroke=COLOR_SECONDARY,
            line_width=1,
        )
        doc.cursor_y -= 18

        # AI Summary card
        doc.text(
            doc.margin_x,
            doc.cursor_y,
            "Podsumowanie modelu:" if pl else "Model Advisory Summary:",
            font="Helvetica-Bold",
            size=9.5,
            color=COLOR_TEXT_DARK,
        )
        doc.cursor_y -= 12
        h_sum = doc.draw_text_block(
            doc.margin_x,
            doc.cursor_y,
            ai_summary,
            doc.content_width,
            font="Helvetica",
            size=9,
            line_height=13,
            color=COLOR_TEXT_DARK,
        )
        doc.cursor_y -= h_sum + 14

        if ai_uncertainty:
            doc.text(
                doc.margin_x,
                doc.cursor_y,
                t("field_ai_uncertainty", language),
                font="Helvetica-Bold",
                size=9,
                color=COLOR_TEXT_MUTED,
            )
            doc.cursor_y -= 12
            h_unc = doc.draw_text_block(
                doc.margin_x,
                doc.cursor_y,
                ai_uncertainty,
                doc.content_width,
                font="Helvetica-Oblique",
                size=8.5,
                line_height=12,
                color=COLOR_TEXT_MUTED,
            )
            doc.cursor_y -= h_unc + 14

    # =========================================================================
    # 4. LIMITATIONS & NOT CHECKED (CATEGORIZED & HUMAN-FACING)
    # =========================================================================
    if not_checked:
        doc.ensure_space(100)
        doc.text(
            doc.margin_x,
            doc.cursor_y,
            t("section_limitations", language),
            font="Helvetica-Bold",
            size=13,
            color=COLOR_PRIMARY,
        )
        doc.cursor_y -= 8
        doc.line(
            doc.margin_x,
            doc.cursor_y,
            doc.margin_x + doc.content_width,
            doc.cursor_y,
            stroke=COLOR_SECONDARY,
            line_width=1,
        )
        doc.cursor_y -= 16

        # Group and parse all raw items (never outputting raw Python dicts!)
        categories = parse_not_checked_items(not_checked, language)

        for cat in categories:
            doc.ensure_space(60)

            is_warn = cat.get("is_warning", False)
            title = cat.get("title", "")
            badge = cat.get("badge", "INFO")
            desc = cat.get("description", "")

            # Category Header
            doc.text(
                doc.margin_x + 8,
                doc.cursor_y,
                title,
                font="Helvetica-Bold",
                size=10,
                color=(0.7, 0.15, 0.15) if is_warn else COLOR_SECONDARY,
            )
            doc.badge(
                doc.margin_x + doc.content_width - 85,
                doc.cursor_y + 1,
                badge,
                bg_color=(0.99, 0.92, 0.92) if is_warn else COLOR_BG_ALT,
                text_color=(0.6, 0.1, 0.1) if is_warn else COLOR_SECONDARY,
                font_size=7.5,
            )
            doc.cursor_y -= 14

            # Category Body text (wrapped)
            h_cat = doc.draw_text_block(
                doc.margin_x + 12,
                doc.cursor_y,
                desc,
                doc.content_width - 24,
                font="Helvetica",
                size=8.5,
                line_height=12,
                color=COLOR_TEXT_DARK,
            )
            doc.cursor_y -= h_cat + 12

        # Technical JSON hint
        doc.ensure_space(30)
        json_hint = (
            f"Uwaga: Raport techniczny JSON (report.json) zawiera pełny rejestr wszystkich "
            f"{len(not_checked)} pojedynczych zdarzeń i technicznych ograniczeń modułów."
            if pl
            else (
                f"Note: The technical JSON report (report.json) contains the full record of all "
                f"{len(not_checked)} individual events and module limitations."
            )
        )
        doc.draw_text_block(
            doc.margin_x + 8,
            doc.cursor_y,
            json_hint,
            doc.content_width - 16,
            font="Helvetica-Oblique",
            size=8,
            line_height=11,
            color=COLOR_TEXT_MUTED,
        )
        doc.cursor_y -= 18

    # =========================================================================
    # 5. RUNNING HEADER & FOOTER CALLBACKS
    # =========================================================================
    # =========================================================================
    # 5. RECOMMENDED NEXT STEPS
    # =========================================================================
    doc.ensure_space(110)
    doc.text(
        doc.margin_x,
        doc.cursor_y,
        t("section_next_steps", language),
        font="Helvetica-Bold",
        size=13,
        color=COLOR_PRIMARY,
    )
    doc.cursor_y -= 8
    doc.line(
        doc.margin_x,
        doc.cursor_y,
        doc.margin_x + doc.content_width,
        doc.cursor_y,
        stroke=COLOR_SECONDARY,
        line_width=1,
    )
    doc.cursor_y -= 16

    next_steps: list[str] = []
    if target_kind == "website":
        if any(f.rule_code == "html_external_script_without_integrity" for f in findings):
            next_steps.append(
                (
                    "Konfiguracja Subresource Integrity (SRI) lub CSP: Dodaj "
                    "atrybuty integrity i crossorigin "
                    "do zewnętrznych bibliotek statycznych (np. CDN). "
                    "Dla dynamicznych skryptów analitycznych "
                    "wdroż restrykcyjną dyrektywę script-src "
                    "w nagłówku Content-Security-Policy (CSP)."
                )
                if pl
                else (
                    "Configure Subresource Integrity (SRI) or CSP: Add "
                    "integrity and crossorigin attributes "
                    "to static CDN libraries. For dynamic third-party scripts, "
                    "enforce strict script-src "
                    "directives within Content-Security-Policy (CSP) headers."
                )
            )
        next_steps.append(
            (
                "Weryfikacja nagłówków bezpieczeństwa HTTP: Upewnij się, "
                "że serwer produkcyjny zwraca "
                "rekomendowane nagłówki ochronne: HSTS, "
                "Content-Security-Policy, X-Frame-Options i X-Content-Type-Options."
            )
            if pl
            else (
                "Verify HTTP security headers: Ensure production "
                "servers deliver recommended defense headers: "
                "HSTS, Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options."
            )
        )
        next_steps.append(
            (
                "Cykliczne audyty integralności zasobów: Regularnie "
                "monitoruj zmiany w skryptach dostawców zewnętrznych "
                "oraz kontroluj domeny ładujące kod "
                "w przeglądarce użytkownika."
            )
            if pl
            else (
                "Periodic resource integrity reviews: Regularly audit "
                "external dependencies and maintain "
                "strict governance over domains executing code in user browsers."
            )
        )
    elif target_kind == "mail_domain":
        next_steps.append(
            (
                "Weryfikacja polityki DMARC: Wdróż rygorystyczną "
                "politykę 'p=reject' lub 'p=quarantine' "
                "oraz skonfiguruj raportowanie rua/ruf, "
                "aby zapobiec podszywaniu się pod domenę (spoofing)."
            )
            if pl
            else (
                "DMARC enforcement: Deploy strict 'p=reject' or "
                "'p=quarantine' policies and configure "
                "rua/ruf reporting to prevent domain spoofing."
            )
        )
        next_steps.append(
            (
                "Weryfikacja rekordów SPF i DKIM: Upewnij się, "
                "że wszystkie autoryzowane serwery wysyłające "
                "są uwzględnione w rekordzie SPF oraz że klucze DKIM podlegają regularnej rotacji."
            )
            if pl
            else (
                "Verify SPF and DKIM configuration: Ensure all "
                "authorized sending servers are declared "
                "in SPF and DKIM cryptographic keys undergo regular rotation."
            )
        )
    elif target_kind == "eml_message":
        next_steps.append(
            (
                "Weryfikacja autentyczności nadawcy na serwerze "
                "pocztowym: Wyniki lokalnej analizy sygnałów "
                "nie zastępują weryfikacji nagłówków "
                "Authentication-Results (SPF/DKIM/DMARC) przez MTA."
            )
            if pl
            else (
                "Verify sender authenticity at mail server: "
                "Local heuristic signal inspection does not substitute "
                "for authoritative Authentication-Results "
                "headers (SPF/DKIM/DMARC) verified by the MTA."
            )
        )
    else:
        if p1_count > 0:
            next_steps.append(
                (
                    "Priorytetowa mitygacja problemów P1: Zbadaj natychmiast "
                    "zidentyfikowane wywołania powłoki "
                    "lub niebezpieczne deserializacje i zastąp je bezpiecznymi API "
                    "(np. lista argumentów bez shell=True)."
                )
                if pl
                else (
                    "Priority P1 mitigation: Immediately review identified shell execution "
                    "and unsafe deserialization calls, replacing them with safe APIs "
                    "(e.g. argument sequences without shell=True)."
                )
            )
        elif total_findings > 0:
            next_steps.append(
                "Weryfikacja kontekstowa wykryć: Sprawdź "
                "zidentyfikowane fragmenty kodu i upewnij się, "
                "że dane wejściowe podlegają odpowiedniej walidacji przed przetworzeniem."
                if pl
                else (
                    "Contextual finding verification: Review identified code fragments "
                    "and verify input validation before processing."
                )
            )

        if is_traversal_limited:
            next_steps.append(
                (
                    "Rozszerzenie zakresu analizy: Uruchom ponowny audyt z profilem 'Rozszerzony' "
                    "(--profile extended) lub parametrem '--max-files 5000', "
                    "aby objąć pliki pominięte w wyniku limitu."
                )
                if pl
                else (
                    "Expand scan scope: Re-run audit with the 'Extended' profile "
                    "(--profile extended) or '--max-files 5000' to inspect files omitted "
                    "due to traversal limits."
                )
            )

        next_steps.append(
            (
                "Weryfikacja zależności z bazą OSV: Jeśli projekt korzysta z zewnętrznych "
                "bibliotek, uruchom audyt z flagami '--network' oraz '--share-packages', "
                "aby porównać wersje z publiczną bazą podatności."
            )
            if pl
            else (
                "OSV dependency lookup: If project uses external libraries, "
                "run audit with '--network' and '--share-packages' "
                "to check package versions against the public vulnerability database."
            )
        )

    next_steps.append(
        (
            "Cykliczne audyty i linia bazowa: Zapisz ten raport i wykorzystaj go "
            "jako bazę porównawczą (--baseline) przy kolejnych wydaniach oprogramowania, "
            "aby szybko wykrywać nowe zagrożenia."
        )
        if pl
        else (
            "Continuous audit & baseline: Retain this report and use it as a reference "
            "baseline (--baseline) in future releases to promptly detect regressions."
        )
    )

    for s_idx, step_txt in enumerate(next_steps, 1):
        doc.ensure_space(35)
        doc.text(
            doc.margin_x + 8,
            doc.cursor_y,
            f"{s_idx}.",
            font="Helvetica-Bold",
            size=9,
            color=COLOR_PRIMARY,
        )
        h_step = doc.draw_text_block(
            doc.margin_x + 24,
            doc.cursor_y,
            step_txt,
            doc.content_width - 32,
            font="Helvetica",
            size=8.5,
            line_height=12,
            color=COLOR_TEXT_DARK,
        )
        doc.cursor_y -= h_step + 10

    def header_callback(page_num: int, total_pages: int, c: PDFDocument) -> None:
        if page_num > 1:
            c.text(
                c.margin_x,
                c.height - 28,
                f"{t('app_title', language)} — {t('report_title', language)}: {display_project}",
                font="Helvetica",
                size=8,
                color=COLOR_TEXT_MUTED,
            )
            c.line(
                c.margin_x,
                c.height - 32,
                c.margin_x + c.content_width,
                c.height - 32,
                stroke=COLOR_BORDER,
                line_width=0.5,
            )

    def footer_callback(page_num: int, total_pages: int, c: PDFDocument) -> None:
        c.line(
            c.margin_x,
            38,
            c.margin_x + c.content_width,
            38,
            stroke=COLOR_BORDER,
            line_width=0.5,
        )
        ai_status_text = (
            t("ai_status_enriched", language) if ai_review else t("ai_status_offline", language)
        )
        footer_sub = f"{t('audit_type_label', language)}  |  {ai_status_text}"
        c.text(
            c.margin_x,
            24,
            footer_sub,
            font="Helvetica",
            size=7.5,
            color=COLOR_TEXT_MUTED,
        )
        page_str = t("page_number", language, current=page_num, total=total_pages)
        pw = c.content_width
        c.text(
            c.margin_x + pw - 65,
            24,
            page_str,
            font="Helvetica-Bold",
            size=8,
            color=COLOR_TEXT_MUTED,
        )

    return doc.render(header_fn=header_callback, footer_fn=footer_callback)
