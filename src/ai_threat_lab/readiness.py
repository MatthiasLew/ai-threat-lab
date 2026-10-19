"""Static capability inventory. Does not probe accounts, credentials or remote services."""


def readiness():
    rows = (
        (
            "local_code",
            "partial",
            "not_required",
            "Selected Python AST rules, local Flask flows with branch joins/one-pass loops "
            "and credential patterns; "
            "bounded calls, selected SQLite connection contexts and root/src package links; "
            "literal importlib labels only; namespace/computed dynamic imports unhandled.",
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
            "offline_complete",
            "integration_validation_required",
            "Bounded pinned source/manifest collection, verified blobs and controlled metadata "
            "failures; installed synthetic wire accepted with blocked sockets. "
            "Real public/private repository and organization access remain unvalidated.",
        ),
        (
            "website",
            "fixture_tested",
            "integration_validation_required",
            "One-response headers and selected UTF-8 HTML authoring patterns; "
            "browser/application tests absent.",
        ),
        (
            "saved_html",
            "partial",
            "not_required",
            "Bounded UTF-8 saved HTML forms/resources; optional declared document URL; "
            "no browser rendering, submission or JavaScript execution.",
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
            "Bounded EML header, link, HTML form and attachment-metadata candidates; "
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
            "Bounded PE/ELF headers and ZIP directory/local-header metadata; "
            "signature, decompression, disassembly and runtime analysis remain absent.",
        ),
        (
            "authentication_logs",
            "partial",
            "not_required",
            "Bounded normalized UTC login-event capture review for failure/spray/distributed "
            "and post-failure success patterns, plus selected single-host OpenSSH journal JSONL; "
            "no login attempts, arbitrary native log conversion "
            "or compromise/defense validation.",
        ),
        (
            "training",
            "local_rehearsal",
            "implementation_required",
            "Three approved text channels, inert exports and selected-outcome reports. "
            "Live dispatch and observed participant telemetry absent.",
        ),
        (
            "signed_training_events",
            "local_journal",
            "implementation_required",
            "Approved plan/alias/key bindings, HMAC claims, transactional replay/conflict checks "
            "and cancellation; historical read-only receipts and combined local cancellation. "
            "Simulations/automation/adapter claims separate. "
            "Native provider webhook/delivery and participant identity/action verification absent.",
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
            "offline_complete",
            "integration_validation_required",
            "Offline cost contract complete: reservations, cache cleanup, unknown outcomes, "
            "reconciliation and output claims; selected model/prices/account remain unvalidated.",
        ),
        (
            "reports",
            "offline_complete",
            "not_required",
            "Local JSON/HTML, Python SARIF, verified single/batch runs, bounded history catalog "
            "and saved-report export/observation comparison; central history and GUI absent.",
        ),
        (
            "cli_installation",
            "offline_complete",
            "not_required",
            "Exact options, UTF-8 streams, process exit codes, local installation diagnostics; "
            "wheel built from sdist, fresh dependency-free installation and every command help. "
            "Linux/Windows Python 3.12-3.14 CI; other platforms unvalidated.",
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
