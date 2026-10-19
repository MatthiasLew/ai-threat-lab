# Saved HTML and selected form review

Version 0.27.0 adds a bounded, offline authoring-pattern checker. It reads UTF-8 `.html`/`.htm` files without a browser, JavaScript, resource requests or form submission. Findings are candidates, never proof that data was submitted or a vulnerability exploited.

```bash
ai-threat-lab review-html saved-page.html --document-url https://example.com/login
ai-threat-lab review-html saved-page.html --format html --output page-review.html
ai-threat-lab review-html saved-page.html --fail-on-findings
ai-threat-lab scan saved-page.html --output-dir scans/page-01
```

`--document-url` declares context; it is never fetched. Without it, relative destinations, page security context and origin comparisons remain unchecked. Standalone audit/scan, project/GitHub collection and EML review do not infer this context. Reports are partial and include coverage gaps. `--fail-on-findings` returns 1 when candidates exist; invalid inputs/output conflicts return 2. Existing reports are never overwritten.

| Candidate | Selected evidence |
| --- | --- |
| `html_password_form_get` | Named, enabled password control in a selected form using GET |
| `html_password_form_http` | Selected password form has an HTTP destination |
| `html_password_form_cross_origin` | Destination origin differs from the declared document origin |
| `html_mixed_active_content` | Selected script, stylesheet or iframe points to HTTP from declared HTTPS context |
| `html_external_script_without_integrity` | Selected JavaScript source crosses the declared origin and lacks a nonempty integrity marker |

Evidence contains line numbers and fixed explanations, not source, field values, destinations or URL queries. The result target still identifies the supplied local file or website. Origin comparisons normalize host case, default ports and IP spelling. Empty form action uses the document URL; nonempty relative destinations use the first selected base href.

## Collection routes

Local/GitHub project review reuses selected collected HTML text, including uppercase extensions. GitHub blobs retain immutable-commit and digest checks. The explicit network website route inspects only its existing HTTP 200 response with one unambiguous `text/html` declaration, optional UTF-8 charset and absent/identity encoding; it makes no resource requests and does not decompress. Header results survive an unavailable body. Non-200 bodies are unchecked.

Selected EML HTML text parts reuse the form checker without a document origin. Their rule names have a `message_` prefix and evidence includes the MIME text-part index. Attachments are not opened, and external script/page-context rules require context unavailable in this route.

## Bounds and unresolved semantics

256 KiB input, 5,000 start elements, 100 forms, 100 attributes per element, 4,096-character URLs and 200 findings. Structural parser limits and unsupported self-closing containers suppress dependent candidates rather than returning an incomplete form interpretation. File inputs require regular files without links. EML additionally retains its existing MIME limits and a 200 HTML-finding message cap.

Nested/unclosed forms, duplicate attributes, explicit form owners, submitter overrides, fieldsets, table/select repair, foreign/template/noscript subtrees and selected unsupported encodings remain gaps. Raw-text/RCDATA-like elements do not create forms from their text; plaintext consumes the remainder. This is an HTMLParser-based subset, not a conforming browser tree builder. Malformed HTML, URL normalization, international hostnames, CSS/DOM mutations, redirects, CSP enforcement, SRI hash validity, authentication, CSRF and exploitability are not validated. A nonempty integrity marker is not a verified hash; an empty result is not a security certificate.

The synthetic demo checks five context-aware observations, a zero-observation negative control, two context-free scan observations and two EML observations. Installed-wheel checks repeat the CLI and verify generated bundles. Semantics are informed by the [HTML form specification](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html).
