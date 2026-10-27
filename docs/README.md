# Documentation

Start with [Quick start](QUICK_START.md), then [current capabilities and limits](DELIVERY_STATUS.md).
The console and report services are implemented; GUI remains another contributor's client.
Historical milestone documents are regression contracts, not a claim of full product coverage.

| Task | Guide |
| --- | --- |
| Install and run | [Installation](CLI_INSTALLATION.md), [quick start](QUICK_START.md) |
| Scan, verify and compare | [Scan workflow](SCAN_WORKFLOW.md), [local history](LOCAL_REPORT_HISTORY.md) |
| Console and evidence | [Console workflow](CONSOLE_WORKFLOW.md), [PDF reports](PDF_REPORTS.md) |
| Configure AI | [API acceptance](READY_FOR_API_TESTING.md), [costs](API_COSTS.md), [Gemini](GEMINI_API_ADAPTER.md) |
| Source and dependencies | [Python rules](CODE_REVIEW.md), [dependencies](DEPENDENCIES_AND_REPORTS.md), [SARIF import](SARIF_IMPORT.md) |
| Websites | [Passive HTTPS](WEBSITE_AUDIT.md), [navigation](SITE_REVIEW.md), [saved sessions](SAVED_SITE_SESSION.md), [HAR](HAR_REVIEW.md) |
| Email and files | [Gmail](GMAIL_AUDIT.md), [DNS](MAIL_DOMAIN_AUDIT.md), [attachments](ATTACHMENT_REVIEW.md), [Office](OFFICE_REVIEW.md), [reputation](FILE_REPUTATION.md) |
| Training | [Local exercises](TRAINING_LAB.md), [SMTP](SMTP_TRAINING.md), [speech](SPEECH_TRAINING.md), [avatars](STOCK_AVATAR.md), [calls](FICTIONAL_CALLS.md) |
| Develop and verify | [Architecture](ARCHITECTURE.md), [GUI API](GUI_API_HANDOFF.md), [tests](TESTING.md), [implementation workflow](IMPLEMENTATION_PLAN.md) |
| Evaluate quality | [Real-project protocol](REAL_PROJECT_VALIDATION.md), [performance protocol](PERFORMANCE_REPORT.md) |

Use `ai-threat-lab --version` for the installed version and `COMMAND --help` for the
exact argument contract. Keys belong outside source control. No account, live
provider acceptance or release publication follows from passing local tests.
