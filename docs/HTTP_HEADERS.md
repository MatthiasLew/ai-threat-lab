# Saved and passive HTTP header review — 0.16.0

Review a caller-supplied HTTPS response capture entirely offline. The same bounded checker powers the existing opted-in one-response WebsiteAudit collector. Results are candidates for human review, not validated browser behavior or a complete web-application audit.

```bash
ai-threat-lab review-headers capture.json --output header-review.json
ai-threat-lab review-headers capture.json --format html --output header-review.html --fail-on-findings
# Merge a saved assessment with other existing audit results:
ai-threat-lab audit-report header-review.json source-review.json --format html --output combined.html
```

The command never resolves or fetches the declared URL, sends cookies, reads credentials, runs scripts or calls an AI model. It does not import HAR files, raw curl output or response bodies. Existing output files are not overwritten. JSON output is an assessment document; HTML uses the existing escaped remediation-report renderer.

## Input contract

Save a strict JSON object with exactly these fields:

```json
{
  "schema_version": 1,
  "url": "https://website.example.invalid/training",
  "status": 200,
  "headers": [
    ["Strict-Transport-Security", "max-age=31536000"],
    ["Content-Security-Policy", "script-src 'self'"],
    ["X-Content-Type-Options", "nosniff"],
    ["Referrer-Policy", "no-referrer"],
    ["Set-Cookie", "training=INERT; Secure; HttpOnly; SameSite=Lax"],
    ["Set-Cookie", "preferences=INERT; Secure; SameSite=Lax"]
  ]
}
```

Values here are fictional. Preserve each header occurrence as a separate name/value pair. Do not collapse repeated Set-Cookie fields into one string or split them on commas: Expires itself can contain a comma. The header names are case insensitive. Duplicate JSON object keys, unsupported fields, invalid types, control characters and non-finite numbers are rejected. The status must be an integer from 100 to 599 (booleans are not integers for this boundary).

The declared URL must use HTTPS and port 443/default, with a hostname and no embedded credentials, fragment or literal whitespace/control characters. Its origin, freshness and authenticity are not verified. The URL is omitted from the offline assessment; the capture file path remains as the target. A target filename/path can itself be sensitive.

The input must be a regular file, not a root symlink/junction. It is limited to 1 MiB JSON, 100 fields, 128 ASCII token characters per field name, 16 KiB UTF-8 bytes per value and 64 KiB total field-name/value bytes. Horizontal tabs are accepted in values; CR/LF and other controls are rejected. Invalid/oversized captures fail before output publication rather than being silently truncated.

## Selected observations

Only HTTP status 200 is assessed. Other statuses produce no security findings and an explicit unchecked notice; this is not an all-clear. The original presence checks remain HSTS, enforcing CSP, nosniff and Referrer-Policy. Selected first-field HSTS/max-age and nosniff checks remain literal observations. Repeated selected security fields receive a generic duplicate-header candidate; their full browser-specific processing is not simulated.

| Cookie check | Selected trigger |
| --- | --- |
| `cookie_missing_secure` | No Secure attribute |
| `cookie_missing_httponly` | No HttpOnly attribute |
| `cookie_missing_samesite` | No explicit SameSite attribute |
| `cookie_invalid_samesite` | An explicit SameSite value other than None/Lax/Strict |
| `cookie_none_without_secure` | SameSite=None without Secure |
| `cookie_prefix_constraints` | Selected case-sensitive Secure/Host prefix constraints are not met: Secure, or Host's Path=/ and no Domain |
| `cookie_unparsed` | Selected cookie name/value syntax cannot be interpreted; this entry is not further assessed |
| `cookie_ambiguous_attributes` | Duplicate or malformed attribute names; this entry is not further assessed |

Cookie findings aggregate the number of matching fields. One field can match several checks. Cookie purpose, expiry/deletion effects, server sessions and browser defaults are not inferred. Preferences may require JavaScript access; missing HttpOnly is not automatically a vulnerability. These checks do not test actual storage, delivery, cross-site requests or token theft. Other modern prefixes/attributes are not fully evaluated.

CSP checks observe `unsafe-eval`, unqualified `unsafe-inline` and a wildcard in a selected script source list, using script-src or its default-src fallback. Duplicate directives use the first occurrence and create a coverage notice. Syntactic nonce/hash presence suppresses the inline candidate; nonce entropy, hashes and actual scripts are not validated. A nonce/hash plus strict-dynamic suppresses the selected wildcard candidate. Split script-src-elem/attr directives skip the inline interpretation with a notice. These are deliberately partial checks.

Multiple enforcing CSP fields are inspected individually; policy intersection is not computed. A restrictive second policy can prevent behavior suggested by a permissive first one. Comma-combined policies are skipped with an explicit notice. Report-only policies are not treated as enforcing CSP. Meta policies, browser versions, rendering/execution and all CSP grammar/interaction rules remain unchecked. A clean result cannot establish that scripts are safely restricted.

## Reports, integration and exit codes

New finding evidence omits cookie names/values, policy values/nonces/hashes, unknown header values and response bodies. Offline reports also omit the declared capture URL. The original capture file can contain real secrets: redacted output does not sanitize that input. Protect both files appropriately. The passive online audit retains its requested target URL under the existing report contract, so review that URL before sharing it.

The built-in HTTPS transport now keeps all header pairs in `HttpResponse.header_items` and retains its legacy mapping. WebsiteAudit prefers the preserved pairs. A mapping-only adapter remains supported but receives an explicit notice that duplicate fields may be missing. No extra HTTP request, redirect, automatic retry, login or crawl is introduced. Exact network/host permission is still required for an online audit, and real-site integration validation remains separate from fixture tests.

The offline command is explicit; `scan`/`scan-batch` do not automatically classify arbitrary JSON as a header capture. `audit-report` accepts its JSON assessment. Scan engine 8 marks the changed online observation scope; older bundles remain readable, and cross-engine deltas are suppressed.

Exit 0 means the bounded review completed, including an empty or unchecked/non-200 result. Exit 1 means findings exist with `--fail-on-findings`. Exit 2 means invalid input/options, an existing destination or a file error; exit 130 means cancellation. Neither a zero exit nor an empty result is a security certification. Selected cookie-prefix/None and unsafe-eval observations receive P2 review ordering; other new patterns use default P3, without CVSS claims.

`offline-demo` produces a fictional two-cookie capture and six-observation JSON/HTML review, linked from its local index. The completion marker is withheld if this acceptance fails. No real website or cookie was used as release evidence.

Primary behavior references: [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie), [Mozilla cookie configuration guidance](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies), and [W3C CSP specification](https://www.w3.org/TR/CSP/). See [testing](TESTING.md), [live setup](LIVE_SETUP.md) and [delivery status](DELIVERY_STATUS.md).
