"""Static capability inventory. Does not probe accounts, credentials or remote services."""


def readiness():
    rows = (
        (
            "saved_site_session",
            "implemented",
            "integration_validation_required",
            "Explicit host/path-bound static Authorization/Cookie headers with a UTC expiry, "
            "access-denial stop and aliased evidence plus an optional private URL map. "
            "No automated login, cookie renewal, browser or business-logic validation.",
        ),
        (
            "stock_speech_asset",
            "implemented",
            "integration_validation_required",
            "Preview-bound Azure stock-voice synthesis of approved fictional scripts, "
            "configured per-request cost estimate, validated local WAV and durable "
            "duplicate/uncertain-outcome journal. No calling, cloning or distribution; "
            "resource, voice, audio quality and billed usage require live acceptance.",
        ),
        (
            "saved_mail_attachment_structures",
            "implemented",
            "not_required",
            "Bounded MIME decoding and in-memory PE/ELF/ZIP structure review with indexed "
            "evidence and explicit skipped parts. No extraction, payload execution, "
            "malware detection, signature trust or message authenticity verification.",
        ),
        (
            "fictional_smtp_delivery",
            "implemented",
            "integration_validation_required",
            "Exact preview-approved built-in fictional email template, authenticated verified "
            "TLS, persistent attempt/outcome journal, duplicate blocking and cancellation. "
            "SMTP account/delivery acceptance deferred; no observed participant telemetry.",
        ),
        (
            "saved_browser_capture",
            "implemented",
            "not_required",
            "HAR 1.2 selected response headers/HTML, including captured authenticated sessions. "
            "No request replay or credential export; malformed/missing bodies stay explicit. "
            "Not browser/session execution, authenticity or application-logic validation.",
        ),
        (
            "passive_site_navigation",
            "implemented",
            "integration_validation_required",
            "Explicit same-host/path HTTPS navigation, at most 20 pages and depth 5. "
            "Prepared header/HTML checks, bounded discovery and per-page failure evidence. "
            "Default requests have no session headers; queries, JavaScript, redirects, "
            "forms and active tests remain excluded.",
        ),
        (
            "console_workflow",
            "implemented",
            "not_required",
            "Guided console, deterministic prepared-tool planning, scoped inspection, "
            "saved source-independent summaries and local setup checks. GUI is separate.",
        ),
        (
            "grounded_ai_review",
            "implemented",
            "integration_validation_required",
            "Verified single/batch evidence input, exact previews, lossless bounded packets, "
            "explicit call selection and reference-validated advisory JSON. "
            "No generated attack code, model-executed tools or automatic paid retries. "
            "Real account/model/schema/prices and prose correctness need controlled validation.",
        ),
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
            "offline_complete",
            "integration_validation_required",
            "Root/opt-in nested Python/npm/Cargo/Composer/NuGet pins and Go checksum identities; "
            "OSV/cache typed failures, bounded rows and installed socket-blocked acceptance. "
            "Live OSV validation, other ecosystems and dependency graphs remain unchecked.",
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
            "offline_complete",
            "integration_validation_required",
            "One scoped HTTPS GET, bounded headers and complete eligible HTML; "
            "unavailable bodies preserve header evidence. Installed native-parser fixtures "
            "accepted with blocked sockets. Real targets and browser/application tests deferred.",
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
            "Bounded EML header, link, HTML form, attachment-metadata and decoded "
            "PE/ELF/ZIP structure observations; "
            "no link visits, payload execution, malware or authenticity validation.",
        ),
        (
            "mail_domain",
            "offline_complete",
            "integration_validation_required",
            "Bounded exact-owner SPF/DMARC and supplied-selector TXT observations; "
            "typed provider/alias/truncation failures and installed socket-blocked acceptance. "
            "Full policy, DNSSEC, delivery and real-domain validation remain deferred.",
        ),
        (
            "mailbox",
            "offline_complete",
            "integration_validation_required",
            "Bounded Gmail identity/forwarding/filter settings; typed metadata, token boundary and "
            "installed socket-blocked acceptance. OAuth/account and broader controls deferred.",
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
            "Separate fictional SMTP email delivery is available; observed participant "
            "telemetry and live voice/video dispatch remain absent.",
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
            "partial",
            "implementation_required",
            "Voice script, video storyboard and optional stock-speech WAV generation. "
            "No calls, live dialogue, video generation or media distribution.",
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
