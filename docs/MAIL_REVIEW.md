# Exported email review — 0.14.0

For decoded attachment bytes and PE/ELF/ZIP structures, use the separate
[attachment review workflow](ATTACHMENT_REVIEW.md). The commands below retain their
existing message metadata, link and form scope.

Inspect one locally exported `.eml` message without opening its links, extracting or executing attachments, contacting the sender, reading a mailbox account or calling an AI model.

```bash
ai-threat-lab assess path/to/export.eml
ai-threat-lab audit path/to/export.eml --output mail-review.json
ai-threat-lab scan path/to/export.eml --output-dir scan-results/mail-01 --fail-on-findings
ai-threat-lab scan-check scan-results/mail-01
```

All results remain partial. The target must be a regular file, not a root symlink/junction. Existing report paths and bundle directories are not overwritten. The target path is retained in the report; message content, subject, address values, link destinations and attachment names are omitted from the new aggregate evidence. Protect the target filename/path when sharing reports.

## Selected candidates

| Check | Evidence | Context needed |
| --- | --- | --- |
| Authentication headers | Reported SPF/DKIM/DMARC failures across supplied Authentication-Results headers | Headers can be forged; receiving-server provenance and cryptographic checks absent |
| Reply routing | Reply-To differs from From | Mailing systems can legitimately use different routing/display names |
| `message_link_cleartext` | Selected HTTP link occurrences | HTTP is not itself phishing |
| `message_link_ip_address` | Selected IPv4/IPv6 literal hosts | Internal or administrative links can be legitimate |
| `message_link_credentials` | User information embedded in a selected URL | Review the actual destination independently |
| `message_link_display_mismatch` | An HTML anchor displays an HTTP(S) hostname different from its href host | Tracking/redirect services can be legitimate; ownership is not inferred |
| `message_link_active_scheme` | HTML href starts with javascript/data/vbscript | Content is never executed and client behavior is not simulated |
| `message_attachment_active_type` | Executable/script/macro-capable extension or selected executable MIME type on a declared attachment | Metadata is untrusted; this is not malware detection |
| `message_attachment_double_extension` | Document/image extension immediately before an active final extension | The file is not opened to verify its actual format |

New content findings are aggregated by check with occurrence/part counts, not by unique destination. Both alternatives of a multipart message can contribute observations; counts do not describe what a person viewed. Candidate status is preserved. Selected link/attachment candidates receive P2 triage order; simple HTTP/IP observations use default P3. This is review ordering, not severity/CVSS or a phishing verdict.

## Parsing and resource contract

The input read is capped at 1 MiB before standard-library MIME parsing. A structural recursion/parser failure produces a redacted input error. Parsed structure selection uses an iterative traversal capped at 100 MIME parts and depth 8 (root depth 0). Up to 20 inline `text/plain` or `text/html` parts and 256 KiB aggregate decoded text bytes are inspected. At most 200 selected link occurrences are considered, each at most 4096 characters. Stops, oversize/decoding/charset issues and detected MIME defects produce explicit `not_checked` notices.

These traversal limits apply after the standard-library parser constructs its representation; they are not a sandbox or a claim that the parser itself is depth limited. Attachment bodies, archives and embedded messages are not decoded by the content checker, materialized as files, opened in an external viewer or scanned for malware. No archive decompression occurs. Text transfer decoding uses Python's email package; unsupported/invalid charsets are skipped, not guessed.

Plain text uses bounded selection of explicit HTTP(S) URLs. HTML uses syntactic anchor hrefs and label text, including protocol-relative hrefs and HTML entities. It does not render HTML/CSS, resolve relative links, follow redirects, visit images/tracking pixels, inspect scripts, evaluate Unicode/domain reputation, normalize IDNs, compare registrable-domain ownership or recognize every URL obfuscation. Malformed or unrecognized links may be omitted; a clean report cannot rule out a dangerous message. The raw input's 1 MiB limit and decoded-text/part limits also constrain coverage.

The checker does not verify DKIM signatures, SPF/DMARC DNS policy, sender reputation, malware, attachment content, mailbox MFA, forwarding, permissions, delivery or user behavior. Use receiving-server evidence and an independently trusted contact/workflow for decisions. Do not infer susceptibility or training needs from these syntax-level observations alone.

## Offline demonstration and tests

`offline-demo --output-dir NEW_DIR` generates a fictional `.invalid` message with an RFC documentation IP and an inert attachment containing plain training bytes. Its separate report has five expected candidate checks and no outbound activity. Failing mail acceptance prevents publication of `demo-result.json`. The same checks run through service, audit, scan, real CLI-process and clean installed-wheel tests.

Primary parser references: [Python email parser](https://docs.python.org/3.12/library/email.parser.html) and [EmailMessage API](https://docs.python.org/3/library/email.message.html). See [testing](TESTING.md), [offline walkthrough](OFFLINE_ACCEPTANCE.md) and [remaining delivery work](DELIVERY_STATUS.md).

## HTML forms (0.27.0)

Selected HTML text parts now reuse [bounded HTML review](HTML_REVIEW.md). Absolute HTTP password form destinations can produce `message_html_password_form_get` and `message_html_password_form_http` candidates. No document URL is inferred, so relative destinations and origin/security context remain unchecked. Evidence uses MIME text-part indexes and HTML line numbers without values. Existing MIME budgets remain, with at most 200 HTML findings per message. Attachments remain metadata-only.
