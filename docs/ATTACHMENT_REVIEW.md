# Saved email attachment structures

`review-attachments` decodes selected attachment parts from an exported EML file
and applies the existing PE/ELF header and ZIP directory checks to the bytes in memory.
It also records size and SHA-256 for unsupported formats. This extends the email
metadata review; it does not establish that an attachment is safe or malicious.

```bash
ai-threat-lab review-attachments message.eml --output attachments.json
ai-threat-lab brief attachments.json
ai-threat-lab review-attachments message.eml --start 21 --max-entries 20 --output next.json
```

Console option 12 runs the first page. The combined report works with the existing
`brief`, `ai-prepare` and `ai-review` evidence workflow. API access is not needed for
decoding, checking or reporting. Source EML files need not remain available to read
the saved report.

## Selection and bounds

Ordinary `assess`, `audit`, `scan` and `inspect` of EML also run these checks,
reusing the parsed message and selecting the first 20 attachments. Their existing
1 MiB source limit remains. Individual attachment failures become explicit gaps
while message header/link evidence remains available. Dedicated `review-attachments`
allows the larger source limit below and subsequent pages. Engine 28 marks this
expanded ordinary scan coverage; older bundles stay readable without cross-engine deltas.

The regular source file is at most 8 MiB. Traversal examines at most 100 MIME parts,
to depth 8. Parts with attachment disposition or a filename are eligible, including
named inline resources. Encapsulated messages are not traversed. Multipart containers
are traversed without treating their text representation as an attachment.

Each invocation selects at most 20 attachments by their discovered one-based index.
An attachment is bounded to 2 MiB of encoded text and 1 MiB of decoded bytes;
the selected batch has a 4 MiB decoded-byte limit. Base64, quoted-printable, 7bit,
8bit and binary transfer encodings are supported. Ambiguous, malformed or oversized
encodings become explicit unavailable entries. Other selected results are retained.
MIME traversal limits and defects remain visible in the report.

Reports label attachment and MIME-part indexes. They omit source filenames, addresses,
subject, text and attachment payloads. Digests identify the exact decoded bytes and
can link identical attachments across reports; they are not anonymization.

## Interpretation

PE and ELF checks inspect selected structures and flags. ZIP checks read directory
and local-header metadata, including unsafe path candidates. ZIP members are never
decompressed or extracted. No attachment is written to disk, launched or loaded.
An unknown format receives inventory evidence and an explicit limitation.

This workflow does not verify message authenticity, signatures, malware, office/PDF
active content, nested archive payloads, encryption passwords or runtime behavior.
No findings is not a clean bill of health. A malformed binary structure remains
visible through `binary_structure_unavailable` and its limitations.

Exit status is 2 for invalid input or unavailable selected attachments, 1 when
`--fail-on-findings` is requested and observations exist, otherwise 0. Existing
output files are never replaced. Tests use synthetic EML and archives, including
socket-blocked installed-package acceptance and saved reports after source deletion.
