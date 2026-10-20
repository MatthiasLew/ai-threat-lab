# Saved Office package review

`review-office` inspects selected declarations in a local ZIP-based Office package.
It needs no account or API and does not launch Office, execute macros, render the
file, follow a relationship target, or extract files to disk. Console option 18
provides the same workflow.

```bash
ai-threat-lab review-office saved.docm --output office.json
ai-threat-lab brief office.json
ai-threat-lab ai-prepare office.json --ai-config examples/ai-budget.json --structured --split
```

The original package can be removed before `brief` or `ai-prepare`: the saved report
contains the observations and limits. Review an AI preview before explicitly sharing
it through the existing interpretation workflow. No AI call happens during review.
Existing output files are never replaced. `--fail-on-findings` returns 1 when review
candidates exist; malformed or over-bound selected XML returns 2 while preserving
other observations in the saved report. A structural package error returns 2 without
a new report. Status 0 is not a safety verdict.

## What is inspected

The existing ZIP header pass checks bounded directory/local-header consistency and
records its own path/size candidates. A separate explicit XML pass reads only
`[Content_Types].xml` and selected `.rels` members in memory. It records:

- Content-type strings containing macroEnabled/VBA-project, ActiveX and OLE-object
  markers. These are declarations, not proof of an embedded implementation or execution.
- Explicit `TargetMode="External"` relationship counts and a separate count of type
  strings ending in `/hyperlink`. Relationships can be ordinary, expected document
  features; the tool does not claim they are malicious or automatically followed.
- Numbers of selected and fully reviewed XML parts, with explicit skipped-part gaps.

Counts from a malformed metadata part are discarded; successful parts and ZIP
observations remain. Reports contain indexed part references and aggregate counts,
not member names, relationship targets, document text or embedded binary bytes.
The ZIP header findings describe that pass only; they do not imply that the separate
XML pass avoided all decompression.

## Bounds and limitations

Input must be a regular file within 16 MiB. Existing ZIP bounds apply: at most
1,000 entries, bounded directory/names, and no split/ZIP64/prefixed layouts.
Duplicate or ambiguous member paths block XML processing. A content-type manifest
is required; the document's actual Office compatibility is not established.

At most 64 XML parts (manifest first, then relationship members in directory order)
are selected. Each is at most 128 KiB, with at most 1 MiB reserved across the pass;
malformed XML consumes that budget too. Only stored/deflate members with a declared
expansion ratio at most 100 are read. Encrypted members are not opened. UTF-8 XML,
without DTD/entity declarations and with at most 4,096 elements per part, is supported.
Unsupported parts remain explicit gaps. XML CRC/decompression failures do not erase
successful earlier evidence. The total-byte accounting is conservative and can
include failed reads; it is not a complete inventory of a document's expanded size.

This does not inspect document bodies, VBA code, OLE/ActiveX payloads, DDE fields,
PDFs, encrypted/legacy binary Office files, signatures, trust settings, nested
packages or runtime behavior. Macro absence is never proof of safety. Generic ZIP
and email attachment review retain their original metadata-only/no-decompression
contracts; use this separate command on an authorized saved Office package.

`scripts/check_office_offline.py` exercises installed CLI review, overwrite refusal,
source-independent summaries, an AI preview and partial malformed-XML output with
all sockets blocked. Unit tests cover byte/part/ratio bounds, duplicate paths,
malformed XML and CRC failures. Real document diversity remains an acceptance need.

References: [package relationship semantics](https://learn.microsoft.com/en-us/dotnet/api/system.io.packaging.package.createrelationship),
[VBA project parts](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.packaging.vbaprojectpart)
and [Office XML formats](https://support.microsoft.com/en-us/office/vba/open-xml-formats-and-file-name-extensions).
