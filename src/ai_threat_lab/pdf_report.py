"""Professional security audit PDF report generator for human stakeholders.

Generates beautifully structured, printable A4 PDF audit reports with:
- Dedicated title page with metadata, project name, and clear scope disclaimer
- Executive & user-friendly summary answering all key security questions in plain language
- Metrics overview cards (analyzers used, scanned files, risk priority breakdown)
- Detailed threat descriptions with mechanism, consequences, fixes, and verification steps
- Highlighted source code snippets with context lines and visual target line markers
- Seamless optional integration of verified Google Gemini advisory interpretations
- Complete multilingual support in Polish ('pl') and English ('en')
- Universal Polish diacritics rendering without downloading or bundling external fonts
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
        if isinstance(f, dict)
        and (f.get("evidence_id") or f.get("id") or f.get("finding_id"))
    }

    obs_ids = {
        obs.get("evidence_id") or obs.get("finding_id") or obs.get("id")
        for obs in observations
        if isinstance(obs, dict)
        and (obs.get("evidence_id") or obs.get("finding_id") or obs.get("id"))
    }
    if not obs_ids:
        raise ValidationError("AI review observations contain no valid finding references")

    # Ensure every observation refers to an actual finding in the report
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

    # Extract high-level metadata
    target_label = project_name or report.get("target") or "Inspected Project"
    if "/" in target_label or "\\" in target_label:
        display_project = Path(target_label).name or target_label
    else:
        display_project = target_label

    findings = detailed_findings(report, language=language)
    not_checked = report.get("not_checked", [])
    status = report.get("status", "completed")
    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

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
    # Top decorative bar
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

    # Document Main Title
    doc.text(
        doc.margin_x,
        doc.height - 150,
        t("report_title", language),
        font="Helvetica-Bold",
        size=20,
        color=COLOR_TEXT_DARK,
    )

    # Target Project Name Banner
    doc.rect(
        doc.margin_x,
        doc.height - 235,
        doc.content_width,
        65,
        fill=COLOR_BG_CARD,
        stroke=COLOR_BORDER,
    )
    doc.text(
        doc.margin_x + 16,
        doc.height - 188,
        t("metric_project", language, project=display_project),
        font="Helvetica-Bold",
        size=15,
        color=COLOR_PRIMARY,
    )
    doc.text(
        doc.margin_x + 16,
        doc.height - 212,
        f"{target_label}",
        font="Courier",
        size=9,
        color=COLOR_TEXT_MUTED,
    )

    # Metadata Box
    meta_y = doc.height - 255
    doc.rect(
        doc.margin_x, meta_y - 120, doc.content_width, 120, fill=(1, 1, 1), stroke=COLOR_BORDER
    )

    meta_rows = [
        ("Data analizy" if pl else "Audit Date", date_str),
        ("Język raportu" if pl else "Report Language", "Polski (pl)" if pl else "English (en)"),
        (
            "Zakres analizy" if pl else "Analysis Scope",
            "Lokalny audyt statyczny (offline)" if pl else "Local static audit (offline)",
        ),
        ("Status przebiegu" if pl else "Audit Status", status.upper()),
        (
            "Interpretacja AI" if pl else "AI Interpretation",
            f"Google Gemini ({ai_model})"
            if ai_review
            else ("Brak — tryb w pełni lokalny" if pl else "None — fully offline mode"),
        ),
    ]

    curr_row_y = meta_y - 22
    for label, val in meta_rows:
        doc.text(
            doc.margin_x + 16,
            curr_row_y,
            f"{label}:",
            font="Helvetica-Bold",
            size=9.5,
            color=COLOR_SECONDARY,
        )
        doc.text(
            doc.margin_x + 170, curr_row_y, val, font="Helvetica", size=9.5, color=COLOR_TEXT_DARK
        )
        curr_row_y -= 20

    # Prominent Scope Disclaimer Box
    disc_y = doc.height - 400
    doc.rect(
        doc.margin_x, disc_y - 100, doc.content_width, 100, fill=COLOR_BG_ALT, stroke=COLOR_BORDER
    )
    doc.text(
        doc.margin_x + 16,
        disc_y - 20,
        t("disclaimer_title", language),
        font="Helvetica-Bold",
        size=10,
        color=COLOR_PRIMARY,
    )
    doc.draw_text_block(
        doc.margin_x + 16,
        disc_y - 36,
        t("disclaimer_text", language),
        doc.content_width - 32,
        font="Helvetica",
        size=8.5,
        line_height=12.5,
        color=COLOR_TEXT_DARK,
    )

    # Executive Overview on Cover Page
    exec_y = doc.height - 530
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

    if total_findings == 0:
        if pl:
            summary_prose = (
                "W analizowanym projekcie nie wykryto żadnych znanych wzorców podatności "
                "w obsługiwanym zakresie reguł. Projekt przeszedł pomyślnie wszystkie "
                "aktywne reguły analizy statycznej offline. Należy jednak pamiętać, że "
                "analiza statyczna nie obejmuje zachowań w czasie wykonania ani sieci."
            )
        else:
            summary_prose = (
                "No known vulnerability patterns were identified in the inspected target "
                "within the active rule scope. The target passed all offline static checks. "
                "Note that static analysis does not cover runtime execution reachability."
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
        size=9.5,
        line_height=14,
        color=COLOR_TEXT_DARK,
    )

    # Metrics Summary Cards
    cards_y = exec_y - 100
    card_w = (doc.content_width - 24) / 4
    card_h = 55

    metrics = [
        ("POTENCJALNE ZAGROŻENIA" if pl else "TOTAL THREATS", str(total_findings), COLOR_PRIMARY),
        (
            "WYSOKI PRIORYTET (P1)" if pl else "HIGH PRIORITY (P1)",
            str(p1_count),
            (0.7, 0.1, 0.1) if p1_count else COLOR_TEXT_MUTED,
        ),
        (
            "ŚREDNI PRIORYTET (P2)" if pl else "MEDIUM (P2)",
            str(p2_count),
            (0.7, 0.4, 0.0) if p2_count else COLOR_TEXT_MUTED,
        ),
        ("POMINIĘTE ELEMENTY" if pl else "ITEMS SKIPPED", str(len(not_checked)), COLOR_TEXT_MUTED),
    ]

    for idx, (lbl, val, col) in enumerate(metrics):
        cx = doc.margin_x + idx * (card_w + 8)
        doc.rect(cx, cards_y - card_h, card_w, card_h, fill=COLOR_BG_CARD, stroke=COLOR_BORDER)
        doc.text(cx + 8, cards_y - 18, lbl, font="Helvetica-Bold", size=6.5, color=COLOR_TEXT_MUTED)
        doc.text(cx + 8, cards_y - 45, val, font="Helvetica-Bold", size=20, color=col)

    # =========================================================================
    # 2. DETAILED FINDINGS PAGES
    # =========================================================================
    doc.new_page()

    doc.text(
        doc.margin_x,
        doc.cursor_y,
        t("section_detailed_findings", language),
        font="Helvetica-Bold",
        size=15,
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
        doc.text(
            doc.margin_x,
            doc.cursor_y,
            t("no_findings_clean", language),
            font="Helvetica-Oblique",
            size=10,
            color=COLOR_TEXT_MUTED,
        )
        doc.cursor_y -= 30
    else:
        for idx, finding in enumerate(findings, 1):
            # Calculate height needed for this finding card
            badge_config = BADGE_COLORS.get(finding.triage_priority, BADGE_COLORS["P3"])

            # Check if we need page break before starting finding
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

            # Draw Priority Badge on right side
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

            # Section: Why is it dangerous? (Mechanism & Consequences)
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

            # Section: Source Code Snippet (with highlighted target line!)
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
                # Draw snippet box
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
                        # Highlight line background band
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
                "pochodzić z zewnątrz i czy są odpowiednio sanityzowane."
                if pl
                else (
                    "Verify whether input reaching this operation originates "
                    "from untrusted sources and is strictly validated."
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
    # 4. LIMITATIONS & NOT CHECKED
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

        for item in not_checked:
            doc.ensure_space(20)
            doc.text(
                doc.margin_x + 8,
                doc.cursor_y,
                f"• {item}",
                font="Helvetica",
                size=8.5,
                color=COLOR_TEXT_MUTED,
            )
            doc.cursor_y -= 14

    # =========================================================================
    # 5. RUNNING HEADER & FOOTER CALLBACKS
    # =========================================================================
    def header_callback(page_num: int, total_pages: int, c: PDFDocument) -> None:
        if page_num > 1:
            c.text(
                c.margin_x,
                c.height - 28,
                f"{t('app_title', language)} — {t('report_title', language)}",
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
            c.margin_x, 32, c.margin_x + c.content_width, 32, stroke=COLOR_BORDER, line_width=0.5
        )
        c.text(c.margin_x, 20, display_project, font="Helvetica", size=8, color=COLOR_TEXT_MUTED)
        page_str = t("page_number", language, current=page_num, total=total_pages)
        c.text(
            c.margin_x + c.content_width - 80,
            20,
            page_str,
            font="Helvetica",
            size=8,
            color=COLOR_TEXT_MUTED,
        )

    return doc.render(header_fn=header_callback, footer_fn=footer_callback)
