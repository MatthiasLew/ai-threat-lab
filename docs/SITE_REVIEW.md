# Passive multi-page website review

`review-site` extends the one-response collector with explicit, bounded link navigation.
It needs no model or account. Existing `scan`/`inspect` keep their one-response contract.

```bash
ai-threat-lab review-site https://owned.example/app/ --network --allow-host owned.example --path-prefix /app/ --max-pages 10 --max-depth 2 --output site.json
ai-threat-lab brief site.json
```

The console offers the same operation under option 9. The start URL and every discovered
URL must use the exact HTTPS hostname, port 443 and approved path prefix. Prefixes end
with `/`. The default prefix is `/`, so set a narrower prefix when appropriate.
Collection is breadth-first, with at most 20 pages and depth 5; defaults are 10 and 2.
Every response is at most 256 KiB. Public-address DNS and TLS checks use the existing
transport. No API key is read. No target source code is executed.

Only eligible complete UTF-8 HTML anchor links are followed. Queries, credentials,
encoded/ambiguous URLs, other origins, downloads and documents with base elements
are excluded. Redirects, scripts, embedded resources, cookies and forms are never
followed or submitted. Duplicate URLs/fragments are deduplicated. Depth/page/parser
limits remain explicit. This is not a browser or authenticated application test.
Ordinary GET requests can have effects on incorrectly designed websites; explicitly
approve the exact host and path before collection.

Each response is checked once by the existing header/HTML analyzer. The combined report
preserves page targets, findings and limitations. A failed page produces an explicit
unavailable assessment while other pages remain present. Exit code 2 indicates a
collection/input/output failure; optional `--fail-on-findings` uses 1 for candidates.
An empty finding set is not a clean bill of health. Existing output files are rejected.

The JSON is accepted by `brief`, `ai-prepare` and `ai-review`. It is a bare combined
report with consistency validation, not an authenticated or signed scan bundle.
Report targets contain visited paths; inspect the preview before any external sharing.

Tests cover scope rejection before I/O, query/credential/foreign-link exclusion,
deduplication, traversal order, budgets, HTML contexts, partial failure, report
compatibility and an installed-package run with blocked sockets.
