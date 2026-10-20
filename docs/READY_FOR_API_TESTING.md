# Gotowość do kontrolowanych testów integracyjnych API (`READY_FOR_API_TESTING`)

Ten dokument opisuje granicę pomiędzy pełnym trybem lokalnym/offline a opcjonalnymi adapterami sieciowymi i AI w aplikacji **AI Threat Lab (`0.39.1`)**, a także procedurę bezpiecznego przejścia do pierwszych kontrolowanych testów z rzeczywistymi usługami zewnętrznymi.

> **Ważne:** Zaliczenie pełnego zestawu testów offline (mocki, deterministyczne fixture'y HTTP, zablokowane gniazda sieciowe) potwierdza poprawność lokalnej architektury, parserów, walidacji schematów, budżetowania oraz CLI. **Nie stanowi natomiast dowodu**, że zewnętrzne konto, uprawnienia OAuth, cennik dostawcy lub produkcyjny endpoint API działają w środowisku docelowym. Wszelkie właściwości wymagające weryfikacji z rzeczywistą usługą są jawnie oznaczane w diagnostyce jako `REQUIRES_LIVE_VALIDATION`.

---

## 1. Co działa całkowicie bez API i bez połączenia sieciowego (`offline`)

Bez kluczy API, kont zewnętrznych i dostępu do Internetu w pełni działają:

1. **Lokalna analiza bezpieczeństwa projektów i plików (`audit`, `scan`, `scan-batch`, `inspect`, `review-*`):**
   - Analiza kodu Python (`review-code`, `audit`, `scan`): reguły AST (`PY001`–`PY014`), przepływy danych Flask (`python_flow.py`), wiązanie wywołań w obrębie pliku i projektu (`python_call_binding.py`, `python_project_flow.py`, `python_module_index.py`), konteksty SQLite (`python_sqlite_context.py`) oraz wybrane wzorce webowe (`python_web_patterns.py`).
   - Analiza konfiguracji (`config_review.py`, `review-kubernetes`): pliki `Dockerfile`, workflow GitHub Actions (`.github/workflows/*.yml`) oraz manifesty JSON Kubernetes (`Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `ReplicaSet`, `ReplicationController`, `List`).
   - Inwentaryzacja zależności offline (`audit-deps` bez `--network`): `requirements.txt`, `pyproject.toml`, `poetry.lock`, `pdm.lock`, `uv.lock`, `Pipfile.lock`, `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `composer.lock`, `packages.lock.json` (w tym tryb `--recursive-dependencies` dla monorepo).
   - Analiza zapisanych odpowiedzi HTTP, HTML i HAR (`review-headers`, `review-html`, `review-har`).
   - Bezpieczna pasywna analiza plików binarnych, archiwów, dokumentów Office i wiadomości pocztowych (`binary_audit.py`, `archive_review.py`, `review-office`, `mail_review.py`, `review-attachments`, `review-sarif`): nagłówki PE/ELF, centralny katalog ZIP (wykrywanie path traversal, duplikatów, kolizji nazw, podejrzanych współczynników kompresji), deklaracje XML pakietów Office (makra VBA, ActiveX, OLE, zewnętrzne relacje), wiadomości `.eml` oraz załączniki MIME w pamięci — **bez wykonywania kodu i bez rozpakowywania na dysk**.
   - Analiza logów uwierzytelniania (`review-auth-log`, `review-ssh-journal`).
2. **Lokalne raportowanie, historia i porównania (`audit-report`, `scan-check`, `batch-check`, `history-list`, `report-export`, `scan-compare`, `brief`):**
   - Eksport raportów w formatach JSON, TXT, standalone HTML (z restrykcyjnym `Content-Security-Policy`) oraz SARIF 2.1.0.
   - Weryfikacja integralności pojedynczych przebiegów i batchy (`SHA-256` w `manifest.json` i `batch.json`).
   - Odtwarzanie i eksport raportów nawet po usunięciu oryginalnych badanych plików źródłowych.
3. **Lokalne szkolenia i symulacje zagrożeń (`analyze`, `interactive`, `campaign-*`, `training-*`, `exercise-export`, `offline-demo`):**
   - Modelowanie ryzyka dla scenariuszy `ai_phishing`, `voice_deepfake`, `video_deepfake`, `brute_force`, `credential_stuffing`, `insecure_generated_code`.
   - Pełny lokalny cykl zatwierdzania i symulacji kampanii (`campaign-example`, `campaign-prepare`, `campaign-approve`, `campaign-simulate`).
   - Lokalne ćwiczenia tekstowe w kanałach `email`, `voice`, `video` (`training-start`, `training-step`, `training-run`, `training-status`, `training-cancel`, `training-report`).
   - Podpisane lokalne zdarzenia szkoleniowe HMAC-SHA256 (`training-event-keygen`, `training-events-register`, `training-events-import`, `training-events-receipt`, `training-events-report`, `training-events-cancel`, `training-local-status`, `training-local-cancel`).
4. **Lokalne przygotowanie pakietów dowodowych i preflight AI (`plan`, `ai-prepare`, `setup-check`, `doctor`, `readiness`):**
   - Podział ustaleń na bezstratne pakiety dowodowe (`ai-prepare --structured --split`), podgląd dokładnego minimalizowanego payloadu JSON i szacowanego kosztu przed jakimkolwiek wywołaniem sieciowym.

---

## 2. Co wymaga klucza API lub jawnej zgody sieciowej (`live`)

| Obszar / Komenda | Wymagana zmienna środowiskowa | Wymagany plik konfiguracyjny | Wymagane flagi zgody w CLI |
| --- | --- | --- | --- |
| Wyjaśnienia i przegląd AI OpenAI (`ai-explain`, `ai-review`) | `OPENAI_API_KEY` | `--ai-config ai.json` | `--provider openai --send-evidence` (lub `--dry-run` bez klucza i bez sieci) |
| Wyjaśnienia i przegląd AI Google Gemini (`ai-explain`, `ai-review`) | `GEMINI_API_KEY` | `--ai-config ai.json` | `--provider gemini --send-evidence` (lub `--dry-run` bez klucza i bez sieci) |
| Pasywny audyt repozytorium GitHub (`audit`, `scan`) | Opcjonalnie `GITHUB_TOKEN` (dla prywatnych repozytoriów / wyższych limitów) | Brak | `--network --allow-host github.com` |
| Pasywny przegląd strony HTTPS (`audit`, `scan`, `review-site`) | Brak (lub `--session-file` z jawnym nagłówkiem sesji) | Opcjonalny plik sesji JSON | `--network --allow-host <dokładny-host>` |
| Audyt DNS domeny pocztowej (`audit`, `scan`) | Brak (używa Cloudflare DoH) | Brak | `--network --allow-host <domena>` |
| Pasywny audyt ustawień Gmail (`audit`, `scan`) | `GMAIL_ACCESS_TOKEN` | Brak | `--network --allow-host gmail.googleapis.com` |
| Zapytania o podatności OSV (`audit-deps`, `scan`) | Brak | Brak | `--network --share-packages` |
| Reputacja skrótu pliku VirusTotal (`file-reputation`) | `VT_API_KEY` | Brak | `--network --share-hash` |
| Dostarczenie fikcyjnego e-maila szkoleniowego SMTP (`smtp-send`) | `AI_THREAT_SMTP_PASSWORD` | `--smtp-config smtp.json` | `--allow-smtp-host <host> --send-mail` |
| Synteza głosu stockowego Azure (`speech-synthesize`) | `AI_THREAT_SPEECH_KEY` | `--speech-config speech.json` | `--allow-speech-host <host> --synthesize` |
| Wideo ze stockowym awatarem Azure (`avatar-submit`, `avatar-status`, `avatar-download`) | `AI_THREAT_AVATAR_KEY` | `--avatar-config avatar.json` | `--allow-avatar-host <host> --send-script` / `--network` |
| Fikcyjne połączenie szkoleniowe Twilio (`call-submit`, `call-status`, `call-stop`, `call-watch`) | `TWILIO_AUTH_TOKEN` | `--call-config call.json` | `--allow-call-host api.twilio.com --send-call` / `--network` |

---

## 3. Rozdzielenie trybów pracy: `offline`, `mock`, `dry-run` i `live`

- **`offline`**: Domyślny tryb wszystkich komend lokalnych. Żadne połączenie sieciowe nie jest nawiązywane, a zmienne środowiskowe z kluczami API nie są odczytywane.
- **`mock`**: Tryb wykorzystywany w testach jednostkowych, integracyjnych i akceptacyjnych (`pytest`, `scripts/check_ai_offline.py`, `scripts/check_installed_package.py`), w którym adaptery używają deterministycznych transportów testowych przy zablokowanych gniazdach systemowych (`socket`).
- **`dry-run`**: Tryb jawnego przeliczenia granic tokenów, minimalizacji dowodów i estymacji kosztu (`ai-explain --dry-run`, `ai-review --dry-run`) oraz podglądu payloadu (`ai-prepare`, `*-preview`). Nie wymaga klucza API i nie wysyła żądań HTTP. Jednoczesne podanie `--dry-run` i `--send-evidence` jest odrzucane z kodem wyjścia `2`.
- **`live`**: Tryb uruchamiany wyłącznie po jawnym podaniu flagi zgody (`--send-evidence`, `--network --allow-host ...`, `--send-mail`, `--synthesize`, `--send-script`, `--send-call`) oraz skonfigurowaniu poświadczeń poza repozytorium.

---

## 4. Konfiguracja środowiska przed testami API

1. **Przygotuj plik konfiguracji AI (`ai-config.json`) bez żadnych sekretów** (obecność pola z kluczem API w pliku JSON jest odrzucana):
   - Dla OpenAI (np. `gpt-4.1-mini`):
     ```json
     {
       "schema_version": 1,
       "model": "gpt-4.1-mini",
       "input_usd_per_million": "0.40",
       "output_usd_per_million": "1.60",
       "max_input_bytes": 12000,
       "max_output_tokens": 600,
       "daily_budget_usd": "0.05",
       "max_calls_per_day": 3,
       "cache_ttl_seconds": 3600,
       "namespace": "controlled-live-pilot"
     }
     ```
   - Dla Google Gemini (np. `gemini-2.5-flash`, `gemini-3.8-flash` lub `gemini-3.5-flash-lite`):
     ```json
     {
       "schema_version": 1,
       "model": "gemini-2.5-flash",
       "input_usd_per_million": "0.30",
       "output_usd_per_million": "2.50",
       "max_input_bytes": 12000,
       "max_output_tokens": 600,
       "daily_budget_usd": "0.05",
       "max_calls_per_day": 3,
       "cache_ttl_seconds": 3600,
       "namespace": "controlled-live-pilot"
     }
     ```
2. **Zweryfikuj lokalną konfigurację i instalację bez wykonywania płatnych wywołań:**
   ```bash
   ai-threat-lab doctor --installation
   ai-threat-lab setup-check --ai-config ai-config.json
   ai-threat-lab doctor
   ```
   - Komenda `setup-check` potwierdzi poprawność składni i granic (`status: "local_configuration_valid"`), pozostawiając `live_ready: false` oraz `live_validation_status: "REQUIRES_LIVE_VALIDATION"`, ponieważ weryfikacja konta, modelu i cennika wymaga testu live.

---

## 5. Jak uruchomić `dry-run` i sprawdzić dokładny payload oraz estymowany koszt

1. **Wykonaj lokalny skan na kontrolowanym celu:**
   ```bash
   ai-threat-lab scan path/to/local-project --output-dir runs/pilot-scan
   ```
2. **Sprawdź dokładny payload JSON i podział na pakiety dowodowe (`ai-prepare`):**
   ```bash
   ai-threat-lab ai-prepare runs/pilot-scan --ai-config ai-config.json --structured --split --output runs/packets-preview.json
   ```
   Plik `runs/packets-preview.json` zawiera:
   - dokładną treść `instructions` oraz zminimalizowane `input_text`, które zostaną wysłane do modelu,
   - skrót `evidence_sha256` dla każdego pakietu,
   - `input_token_planning_bound`, `max_output_tokens`, `reserved_usd` dla każdego pakietu oraz łączny `maximum_reserved_usd`.
3. **Wykonaj `dry-run` dla wybranego pakietu (`ai-review --dry-run`):**
   ```bash
   ai-threat-lab ai-review runs/pilot-scan --ai-config ai-config.json --ledger runs/costs.sqlite --packet-index 1 --dry-run
   ```
   Zwrócony JSON ma `"status": "estimate_only"` i `"network_called": false`. Baza `runs/costs.sqlite` nie jest tworzona podczas `ai-review --dry-run`.

---

## 6. Jak wykonać pierwszy kontrolowany test z małym budżetem

1. Ustaw klucz API wyłącznie w zmiennej środowiskowej bieżącej sesji terminala (nigdy w pliku konfiguracyjnym ani w repozytorium):
   - Dla OpenAI:
     - Linux / macOS: `export OPENAI_API_KEY="sk-..."`
     - Windows PowerShell: `$env:OPENAI_API_KEY = "sk-..."`
   - Dla Google Gemini (klucz przekazywany wyłącznie w nagłówku HTTP `x-goog-api-key`, nigdy w adresie URL `?key=`):
     - Linux / macOS: `export GEMINI_API_KEY="AIza..."`
     - Windows PowerShell: `$env:GEMINI_API_KEY = "AIza..."`
2. Upewnij się w `ai-config.json`, że `daily_budget_usd` (np. `"0.05"`) oraz `max_calls_per_day` (np. `1` lub `2`) są ustawione na minimalne wartości.
3. Wyślij **dokładnie jeden** wcześniej przejrzany pakiet dowodowy:
   - Z OpenAI:
     ```bash
     ai-threat-lab ai-review runs/pilot-scan --ai-config ai-config.json --ledger runs/costs.sqlite --provider openai --packet-index 1 --send-evidence --output runs/review-packet-1.json
     ```
   - Z Google Gemini:
     ```bash
     ai-threat-lab ai-review runs/pilot-scan --ai-config ai-config.json --ledger runs/costs.sqlite --provider gemini --packet-index 1 --send-evidence --output runs/review-packet-1.json
     ```
4. Zweryfikuj wygenerowany plik `runs/review-packet-1.json`:
   - `mode` musi wynosić `"advisory_interpretation"`,
   - każde `evidence_id` w `interpretation.observations` musi odpowiadać ustaleniom z pakietu,
   - oryginalne `not_checked` z raportu skanera są zachowane bez zmian.

---

## 7. Jak sprawdzić logi, cache i rozliczenia kosztów

1. **Sprawdź dziennik kosztów i rezerwacji (`api-costs`):**
   ```bash
   ai-threat-lab api-costs --ledger runs/costs.sqlite
   ```
   Raport zawiera dzienne podsumowanie:
   - `calls`, `cache_hits`, `stored_cache_responses`,
   - `recorded_usage_or_reconciled_usd` (zakończone lub ręcznie uzgodnione wywołania),
   - `reserved_unconfirmed_usd` oraz listę `unconfirmed` (wywołania o nieznanym wyniku, które zatrzymały rezerwację budżetu).
2. **Wyczyść pamięć podręczną odpowiedzi bez usuwania historii księgowej (`api-cache-prune`):**
   ```bash
   ai-threat-lab api-cache-prune --ledger runs/costs.sqlite
   # lub wszystkie wpisy:
   ai-threat-lab api-cache-prune --ledger runs/costs.sqlite --all
   ```

---

## 8. Jak bezpiecznie przerwać, odblokować lub wycofać operację

1. **Przerwanie w trakcie działania (`Ctrl+C`):**
   - Proces kończy pracę z kodem wyjścia `130` (`Cancelled.`).
   - Częściowo otwarte pliki wyjściowe (`--output`) są automatycznie usuwane, o ile należą do bieżącego deskryptora.
   - Jeżeli przerwanie nastąpiło po wysłaniu żądania do dostawcy (AI, SMTP, Speech, Avatar, Call), lokalna rezerwacja/próba pozostaje w stanie `"pending"` / `"unknown"`, aby **zablokować automatyczne ponowienie i podwójne naliczenie opłaty**.
2. **Uzgodnienie niepotwierdzonej rezerwacji AI (`api-reconcile`):**
   - Sprawdź w panelu bilingowym dostawcy faktyczny koszt dla `request_id` widocznego w `api-costs` w sekcji `unconfirmed`.
   - Rozlicz rezerwację rzeczywistą kwotą (lub `"0"`, jeżeli dostawca potwierdził brak opłaty):
     ```bash
     ai-threat-lab api-reconcile <request_id> --actual-usd 0 --ledger runs/costs.sqlite
     ```
3. **Zatrzymanie i anulowanie ćwiczeń oraz zadań zewnętrznych:**
   - Lokalne sesje i dzienniki zdarzeń: `training-cancel`, `training-events-cancel`, `training-local-cancel`.
   - Blokada kolejnych wysyłek w dziennikach adapterów: `smtp-cancel`, `speech-cancel`, `avatar-cancel`, `call-cancel`.
   - Zdalne zatrzymanie trwającego połączenia głosowego Twilio: `call-stop`.

---

## 9. Czego nadal nie wolno zakładać bez testów produkcyjnych (`REQUIRES_LIVE_VALIDATION`)

Nawet przy 100% przechodzących testach offline i poprawnej walidacji `setup-check` (`status: "local_configuration_valid"`), bez testów na rzeczywistych usługach **nie wolno zakładać**:

1. Że skonfigurowany klucz API lub token OAuth jest aktywny, niewygasły i posiada wymagane uprawnienia (np. uprawnienia organizacji GitHub, zakresy Gmail Workspace `gmail.settings.*`, dostęp do wybranego modelu OpenAI Responses).
2. Że wybrany model AI w koncie dostawcy obsługuje `json_schema` (`strict: true`) w endpointzie `/v1/responses`.
3. Że wpisane w `ai-config.json` stawki `input_usd_per_million` i `output_usd_per_million` zgadzają się z aktualnym cennikiem i fakturą dostawcy.
4. Że merytoryczna treść wygenerowanej porady AI jest wolna od błędów — walidator gwarantuje zgodność ze schematem i referencjami `evidence_id`, ale **porada AI zawsze pozostaje niezweryfikowaną interpretacją (`advisory_interpretation`)**.
5. Że zewnętrzne kanały komunikacji (SMTP, Azure Speech/Avatar, Twilio) dostarczą wiadomość/połączenie do odbiorcy końcowego bez sprawdzenia polityk antyspamowych, uprawnień regionalnych i jakości mediów na kontrolowanym koncie testowym.

### Reconciling Pending Request `6afea99f1ade4e36bc017ea6bc17b52c`

If a request was interrupted or held in pending status (such as `6afea99f1ade4e36bc017ea6bc17b52c` from pre-Stage 4 testing), run:

```powershell
py -m ai_threat_lab api-reconcile 6afea99f1ade4e36bc017ea6bc17b52c --actual-usd 0 --ledger runs/costs.sqlite
```

This clears the pending reservation, sets actual billed amount to $0.00 (since the request never reached Google due to the local client route check), and allows subsequent reviews to proceed immediately.

### Zarządzanie limitem czasu (`--timeout`) i diagnostyka `NETWORK_TIMEOUT`

Wszystkie komendy AI (`ai-review`, `ai-explain`) oraz klient `PublicHTTPS` obsługują zakres `--timeout` od 1 do 120 sekund (domyślnie 30s):

- **Wartości dozwolone**: od 1 do 120 sekund (np. `--timeout 30`, `--timeout 60`, `--timeout 90`, `--timeout 120`).
- **Walidacja lokalna**: Wartości poza zakresem (np. `--timeout 121` lub `--timeout 0`) są odrzucane natychmiast błędem `ValidationError` przed zainicjowaniem bazy `runs/costs.sqlite`, dzięki czemu nie tworzą żadnych niepotrzebnych rezerwacji.
- **Rzeczywiste zachowanie timeout**: Limit `--timeout` jest timeoutem na poziomie operacji gniazda TCP/TLS (połączenie z przypiętym adresem IP, handshake TLS, wysyłanie bajtów żądania, odczyt odpowiedzi), a nie sztywnym czasem całkowitej transakcji.
- **Postępowanie w przypadku timeoutu**: Gdy serwer Google nie odpowie w zadanym czasie, proces zgłasza błąd z kategorią `[NETWORK_TIMEOUT]`. Rezerwacja pozostaje w stanie niepotwierdzonym (`unconfirmed`), a użytkownik może ją bezpłatnie uzgodnić poleceniem:
  ```powershell
  py -m ai_threat_lab api-reconcile <REQUEST_ID> --actual-usd 0 --ledger runs/costs.sqlite
  ```
