# Passive review with an explicitly supplied session

`review-site --session-file` can reuse an existing test-account session for the
same bounded header/HTML checks. It does not log in, automate a browser or submit forms.
The account and target must already be approved for the review.

Prepare a private JSON file outside shared source control, for example
`owned.session.json`, containing:

```json
{
  "schema_version": 1,
  "host": "owned.example",
  "path_prefix": "/app/",
  "expires_at": "REPLACE_WITH_UTC_TIMESTAMP_WITHIN_24_HOURS",
  "headers": {
    "Cookie": "REPLACE_WITH_APPROVED_TEST_SESSION"
  }
}
```

`Authorization` may be supplied instead of, or alongside, `Cookie`. These are the
only accepted header names. The expiry is an ISO timestamp with a UTC offset, such
as `+00:00` or `Z`, strictly in the future and no more than 24 hours away. The template
is intentionally unusable until configured. Treat the file as a credential; its header
values are not printed, copied into reports or sent to the interpretation API.

```bash
ai-threat-lab review-site https://owned.example/app/ --network --allow-host owned.example --path-prefix /app/ --session-file owned.session.json --private-path-map owned.paths.private.json --output session-report.json
ai-threat-lab brief session-report.json
```

Console option 14 collects these paths and requests explicit confirmation before
accessing the target. Both the configured host and path must exactly match the chosen
scope. Header values are static and are sent only to that host and directory path.
The client follows no redirects and does not update headers from response cookies.
The existing public-address/TLS checks, URL restrictions, page/depth and response limits
still apply. Expiry is checked before each request. HTTP 401/403 stops further session
requests and produces an explicit unavailable result. Other reviewed pages are retained.

## Private paths and shareable evidence

Session reports use `Session page 0001` aliases instead of URLs, because authenticated
paths can themselves contain private identifiers or reflected credentials. Findings
retain their selected check and line evidence; response body and header values are omitted.
Use the separate private path map to locate a reported page locally.

The path map is optional in the direct CLI and required by the guided session menu.
It is exclusively created before requests, with mode 0600 where supported. Existing
outputs and report/map aliases are rejected. A failure can leave an empty map file;
only a complete JSON document represents a completed map write.

Keep the map local: it can contain sensitive URLs. It is not a report and is rejected by
`brief`/AI evidence loading. `*.session.json` and `*.paths.private.json` are ignored by
this repository's Git configuration; this does not protect copies outside the repository.
Without a private map, use a single explicit page (`--max-depth 0`) when you need an
unambiguous local association with the supplied start URL.

## Limits

The session file is at most 16 KiB; each header is nonempty ASCII, at most 8,192
characters, without control characters. Duplicate JSON keys, unknown headers and
out-of-scope/expired configurations are rejected before collection.

The operator-supplied expiry is a local limit, not proof of the server's session lifetime.
A 200 response does not prove login success, identity or permissions. Static session
reuse does not implement MFA/OAuth/login flows, cookie renewal, role comparison,
authorization testing or application business-logic assessment.

GET requests can still change state in an application. Use a scoped test account and
a suitable target environment. Automated checks use synthetic headers with all sockets
blocked; actual login state and target behavior need controlled integration validation.
