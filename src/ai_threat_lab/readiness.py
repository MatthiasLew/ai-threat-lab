"""Static capability inventory. Does not probe accounts, credentials or remote services."""


def readiness():
    rows = (
        (
            "local_code",
            "partial",
            "not_required",
            "Selected Python AST rules and credential patterns; broader language analysis absent.",
        ),
        (
            "configuration",
            "partial",
            "not_required",
            "Literal Dockerfile/workflow and selected Kubernetes JSON fields; "
            "no cluster, admission or runtime assessment.",
        ),
        (
            "dependencies",
            "partial",
            "integration_validation_required",
            "Root/opt-in nested Python/npm/Cargo pins and Go checksum-record identities; "
            "OSV fixture-tested. "
            "Other ecosystems remain unchecked.",
        ),
        (
            "github",
            "fixture_tested",
            "integration_validation_required",
            "Pinned source/manifest collection; validate chosen public/private repository access.",
        ),
        (
            "website",
            "fixture_tested",
            "integration_validation_required",
            "One-response HSTS/CSP/cookie/header observations; browser/application tests absent.",
        ),
        (
            "http_headers",
            "partial",
            "not_required",
            "Offline duplicate-preserving response-header capture review with redacted evidence; "
            "origin, freshness and browser enforcement unverified.",
        ),
        (
            "exported_mail",
            "partial",
            "not_required",
            "Bounded EML header, link and attachment-metadata candidates; "
            "no link visits, payload execution, malware or authenticity validation.",
        ),
        (
            "mailbox",
            "fixture_tested",
            "integration_validation_required",
            "Selected Gmail settings and DNS checks; controlled OAuth/account validation pending.",
        ),
        (
            "binary",
            "static_headers_partial",
            "implementation_required",
            "Bounded PE/ELF headers; signature, disassembly and runtime analysis remain absent.",
        ),
        (
            "training",
            "local_rehearsal",
            "implementation_required",
            "Three approved text channels, inert exports and selected-outcome reports. "
            "Live dispatch and observed participant telemetry absent.",
        ),
        (
            "voice_video",
            "text_assets_only",
            "implementation_required",
            "Voice script and video storyboard only. No calls, speech or media generation.",
        ),
        (
            "password_attacks",
            "teaching_scenarios",
            "implementation_required",
            "Brute-force/credential-stuffing teaching scenarios; no login attempts.",
        ),
        (
            "ai_explanations",
            "fixture_tested",
            "integration_validation_required",
            "Budgeted Responses adapter and dry-run; selected model/prices/account unvalidated.",
        ),
        (
            "reports",
            "partial",
            "not_required",
            "Local JSON/HTML, Python SARIF, verified offline batches and scan history comparison; "
            "authenticated central history and GUI absent.",
        ),
        (
            "offline_demo",
            "implemented",
            "not_required",
            "Synthetic before/after scan and all training channels; no real-target evidence.",
        ),
    )
    return {
        "schema_version": 1,
        "mode": "static_capability_inventory",
        "network_called": False,
        "credentials_inspected": False,
        "complete_product": False,
        "api_key_alone_sufficient": False,
        "capabilities": [
            dict(zip(("id", "local_status", "external_status", "scope"), row, strict=True))
            for row in rows
        ],
        "notice": "Implementation inventory, not a live health check or security certification. "
        "External integrations are deferred; missing modules require engineering, not only keys.",
    }
