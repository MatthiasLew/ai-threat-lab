# Internationalization (i18n) & Localization Architecture

AI Threat Lab features a lightweight, zero-dependency internationalization system designed for deterministic CLI and PDF report generation in Polish (`pl`) and English (`en`).

## 1. Core Principles

- **Zero External Dependencies**: The localization engine is implemented using Python standard library primitives.
- **Offline First**: All dictionaries, labels, descriptions, and messages are packaged with the library. No remote translation services are required.
- **Fail-Safe Fallback**: If a key or parameter is missing, the system gracefully falls back to the key itself or the default language (`en`) without throwing unhandled exceptions.
- **Persistent User Preference**: Language settings are stored in local user configuration (`~/.ai-threat-lab/config.json`) outside source control.

## 2. Supported Languages

| Code | Language | Default Status |
|:---|:---|:---|
| `pl` | Polski (Polish) | Full support across CLI, interactive menu, and PDF reports |
| `en` | English | Default technical baseline across CLI, API, SARIF, and PDF |

## 3. Configuration & Preference Persistence

User preferences are managed in:
- Windows: `%USERPROFILE%\.ai-threat-lab\config.json`
- Linux / macOS: `~/.ai-threat-lab/config.json`
- Custom path override: `AI_THREAT_LAB_CONFIG_DIR` environment variable

Example `config.json`:
```json
{
  "language": "pl"
}
```

### Python API

```python
from ai_threat_lab import get_active_language, set_active_language, load_language_preference, save_language_preference, t

# Check current preference
lang = load_language_preference()  # e.g. "pl"

# Set runtime language
set_active_language("pl")

# Translate with parameter interpolation
message = t("found_issues_count", "pl", count=5)
# -> "Liczba wykrytych problemów: 5"
```

## 4. Translation Dictionary Structure

Translations are organized in `STRINGS` in `src/ai_threat_lab/i18n.py`:

```python
STRINGS = {
    "app_title": {
        "pl": "AI THREAT LAB",
        "en": "AI THREAT LAB",
    },
    "field_threat_number": {
        "pl": "Zagrożenie #{index}",
        "en": "Threat #{index}",
    },
    ...
}
```

## 5. Non-Interactive Environment Safety

When AI Threat Lab is invoked in automated CI/CD pipelines, background daemons, or piped stdin without a controlling terminal (`sys.stdin.isatty() == False`):
- The interactive menu is bypassed automatically.
- Commands adhere strictly to CLI arguments (`--lang pl`, `--format pdf`).
- If launched with no arguments in a non-tty environment, the process terminates immediately with exit code 2 and usage instructions, preventing hanging pipelines.
