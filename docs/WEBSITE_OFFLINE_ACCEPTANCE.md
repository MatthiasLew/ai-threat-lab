# Passive HTTPS collector offline completion — 0.36.0

This milestone accepts the existing single-response read-only website collector. It does not add crawling, authenticated application tests, payload submission, exploitation, browser execution or AI API setup. Real-target transport/configuration acceptance remains deferred.

| Contract | Required observable result |
| --- | --- |
| Input and scope | Full ASCII HTTPS URL, at most 4096 characters, default/explicit port 443, no credentials, fragments, control characters or backslashes. CLI network permission and exact approved target host are required before DNS. Percent-encode non-ASCII paths/queries and use an ASCII hostname. |
| Request policy | One GET to the supplied target; no redirect following, retries, resource requests, form submission or provider credentials. Existing public-DNS address pinning and TLS hostname checks remain in force. |
| Header observations | Preserve duplicate wire fields. Validate HTTP status, header field shapes, at most 100 fields, 16 KiB values and 64 KiB aggregate selected header bytes. Candidates remain bounded literal observations. |
| Independent body failure | A declared oversize body is skipped before an explicit body read. Unknown-sized bodies are read at most 256 KiB plus one detection byte. Oversize, read failure and incomplete declared length discard the entire body while retaining valid header findings and an explicit body gap. |
| Strict API behavior | Generic JSON/API clients retain strict defaults: oversized or incomplete bodies fail. `document()` rejects an incomplete response even if its retained bytes look like valid JSON. Partial-body collection is GET-only and opt-in. |
| HTML eligibility | Only a complete HTTP 200 response with unambiguous supported UTF-8 text/html/identity encoding reaches selected shared HTML checks. Unsupported encoding/type/structure stays an explicit gap; headers remain available. |
| Evidence | Candidate counts and line references omit cookie names/values, body text and exception details. Saved targets and report metadata can retain user-supplied URLs; query redaction is not promised. |
| Storage compatibility | Engine 23 identifies the revised collection scope. Prior supported bundles, including engine 22, remain readable. Cross-engine comparisons have no delta counts. |
| Installed acceptance | A clean wheel runs six native-HTTP-parser fixtures with blocked sockets: before/after, oversize, short read, read timeout and redirect. Verify saved bundles, retained headers, omitted incomplete HTML, one request, no credentials and three scope rejections. |

Run `python scripts/verify.py` for Ruff, full branch coverage tests, wheel/sdist build and isolated installed workflows. The release commit must also pass all six Linux/Windows Python 3.12–3.14 CI jobs. Boundary controls are in `tests/test_website_boundary.py`, with existing header/HTML/transport suites and `scripts/check_website_offline.py`.

The independent short-read regression uses the standard-library `http.client.HTTPResponse` over an in-memory socket. It reproduces a bounded read returning a valid-looking truncated JSON body without raising `IncompleteRead`; outstanding declared length must still cause rejection. The installed fixtures use that parser too, without a live server.

The collector has a per-socket timeout, not an absolute whole-command deadline. Comprehensive browser semantics, message framing/security verification, server deployment policy and real target behavior are outside this contract. See [usage and limits](WEBSITE_AUDIT.md), [saved headers](HTTP_HEADERS.md), [HTML checks](HTML_REVIEW.md) and [remaining work](DELIVERY_STATUS.md).
