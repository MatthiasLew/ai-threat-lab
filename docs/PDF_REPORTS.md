# Professional PDF Audit Reports

AI Threat Lab generates publication-grade, self-contained PDF audit reports designed specifically for software engineers, security leads, and project stakeholders.

## 1. Design & Audience Goals

The PDF report format is the default human-readable deliverable answering seven core questions:
1. **What was inspected?** Target project, scan date, local execution hashes.
2. **Were potential threats identified?** Executive summary and severity totals (P1, P2, P3, P4).
3. **Where exactly are the issues located?** File path, relative target, and line numbers.
4. **What could happen if unaddressed?** Real-world mechanism and business/operational consequences.
5. **How to fix it?** Concrete, safe remediation guidance.
6. **How to verify the fix?** Step-by-step verification instructions.
7. **What could not be checked?** Explicit offline analysis boundaries and limitations (`not_checked`).

## 2. Zero External Dependencies & Pure Python PDF 1.4

Unlike heavy report engines requiring `reportlab`, `weasyprint`, or headless browser rendering engines, AI Threat Lab uses a dedicated standard-library PDF generator (`src/ai_threat_lab/pdf_writer.py`):
- Strict **PDF 1.4** compliance.
- Vector graphics primitives: filled/bordered rectangles, lines, badges, and text blocks.
- Bounded text wrapping and page break calculation with running headers and footers.
- Two-pass rendering for exact page numbering ("Strona X z Y" / "Page X of Y").
- File size typically **10–25 KB** per complete audit report.

## 3. High-Fidelity Unicode & Typography Support

Standard PDF Type-1 base fonts (such as Helvetica and Courier) do not provide Polish diacritics or typographical marks in their default WinAnsiEncoding table.

AI Threat Lab resolves this with zero font downloads and zero external dependencies:
1. **Custom Encoding Vector (`/Differences`)**: Maps all 18 Polish diacritics (`ą`, `ć`, `ę`, `ł`, `ń`, `ó`, `ś`, `ź`, `ż`, `Ą`, `Ć`, `Ę`, `Ł`, `Ń`, `Ó`, `Ś`, `Ź`, `Ż`), typographic dashes (em-dash `—`, en-dash `–`), typographic quotes (Polish `„` / `”`, English `“` / `”`, `‘` / `’`), bullets (`•`), ellipsis (`…`), and symbols (`€`, `™`) into standard Adobe Type-1 glyph indices.
2. **`/ToUnicode` CMap**: Embeds a complete reverse lookup mapping table so that text can be searched, copied, and selected in Adobe Acrobat, Chrome, Firefox, Safari, and macOS Preview with 100% fidelity.
3. **No Silent `?` Degradation**: Unmapped characters undergo NFKD transliteration and safe fallbacks, preventing corrupted question-mark artifacts in generated documents.
4. **Intelligent Text & Path Wrapping**: Long unbroken file paths, URLs, and exception messages are wrapped with character-level boundary splits, guaranteeing text never overflows page margins.

## 4. Report Structure & Credibility

Every generated report contains:

### Section 1: Title & Audit Overview
- Project title extracted directly from target directory or manifest (`extract_project_identity`), displaying real names (e.g. `Labrys`) instead of generic labels.
- Inspection date, target directory or repository path.
- Scope disclaimer emphasizing that scanner findings represent candidate observations requiring human verification.
- Overview KPI cards: Potential Threats, Audit Status (`KOMPLETNY` / `CZĘŚCIOWY`), File Limits (`W NORMIE` / `LIMIT`), and Scope Limitations.

### Section 2: Executive Summary & Credibility Rules
- Transparent reporting of audit boundaries: if the audit was `partial` or file limits were reached (e.g. 100 files / 1000 directories), the summary explicitly warns that 0 findings applies strictly to the inspected subset of files, never falsely claiming the entire project is free of vulnerabilities.
- P1 / P2 / P3 / P4 distribution badges when findings are present.

### Section 3: Detailed Technical Findings
For each candidate observation:
- **Header**: Threat index, finding title, and colored priority badge (Red for P1, Orange for P2, Blue for P3, Gray for P4).
- **Metadata**: Confirmation status (`Kandydat` / `Candidate`), location (`file:line`).
- **Mechanism & Consequences**: Technical explanation of how the pattern operates.
- **Code Snippet**: Source code context lines with line numbering, secret scrubbing (`[REDACTED_SECRET]`), and marker (`>`) on the affected line.
- **Remediation**: Concrete code recommendations.
- **Verification**: How to confirm the fix works.

### Section 4: Optional Google Gemini AI Advisory Section
When generated with AI enrichment (optional, opt-in with explicit cost approval):
- Clear distinction between deterministic offline findings and generative AI advice.
- Model name (`gemini-2.5-flash`), cost, and token usage notice.
- Advisory summary and per-observation impact analysis.

### Section 5: Scope & Limitations (`not_checked`)
- Categorized, human-readable grouping (`parse_not_checked_items`):
  - Traversal limits (with instructions on using `--max-files` to expand coverage)
  - Oversized files skipped (> 256 KiB)
  - Excluded directories (.ai, tmp, temp, .venv, node_modules, etc.)
  - Ecosystem limitations (e.g. OSV lockfile scanner unconfigured)
  - Parser limitations (e.g. syntax errors)
- Completely eliminates raw Python dictionary dumps (`{'source': ..., 'target': ...}`).

## 5. Generation Usage

### Command Line Interface

```bash
# Export a saved audit scan to PDF in Polish
ai-threat-lab report-export runs/scan-001 --format pdf --lang pl --output report.pdf

# Export with attached Gemini AI advisory review
ai-threat-lab report-export runs/scan-001 --format pdf --lang en --ai-review runs/ai-review.json --output report.pdf
```

### Python API (for Future GUI)

```python
from ai_threat_lab import export_audit_pdf, generate_pdf_report

# Direct export to PDF file
export_audit_pdf("runs/scan-001", "audit_report.pdf", language="pl")

# In-memory raw bytes generation
pdf_bytes = generate_pdf_report(report_dict, ai_review=ai_review_dict, language="en")
```
