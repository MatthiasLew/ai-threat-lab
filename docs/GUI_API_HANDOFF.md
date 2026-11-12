# GUI API Handoff (`ai_threat_lab.gui_api`)

Ten dokument stanowi specyfikację stabilnego kontraktu Python API dla przyszłego zespołu budującego interfejs graficzny (GUI) dla **AI Threat Lab**.

> **Zasada architektoniczna:** Warstwa GUI **nigdy nie parsuje tekstu wyjściowego CLI (`stdout`/`stderr`)**. Wszystkie operacje — od wykrycia dostępnych analizatorów, przez konfigurację i uruchomienie audytu, po pobranie ustrukturyzowanych ustaleń (`DetailedFinding`), eksport raportów i przygotowanie pakietów dowodowych dla AI — odbywają się przez wywołania funkcji Pythona zwracających słowniki/obiekty danych oraz rzucających typowane wyjątki.

---

## 1. Importowanie API

Wszystkie funkcje są eksportowane zarówno bezpośrednio z głównego pakietu `ai_threat_lab`, jak i z modułu `ai_threat_lab.gui_api`:

```python
from ai_threat_lab import (
    AIConfig,
    DetailedFinding,
    ScanOptions,
    ScanService,
    ValidationError,
    ProviderError,
    attach_ai_interpretation,
    build_multilingual_ai_packet,
    create_audit_options,
    describe_finding,
    detailed_findings,
    export_audit_report,
    get_audit_history,
    get_audit_results,
    get_audit_status,
    gemini_explain_result,
    gemini_review_result,
    gemini_review_service,
    get_audit_limitations,
    get_capabilities,
    list_analyzers,
    plan_audit,
    prepare_ai_packets,
    run_audit,
)
```

---

## 2. Typowane wyjątki i obsługa błędów

Warstwa GUI powinna przechwytywać następujące wyjątki:

| Wyjątek | Kiedy występuje | Zalecana reakcja GUI |
|---|---|---|
| `ValidationError` (`ai_threat_lab.ValidationError`) | Niepoprawna ścieżka celu, nieobsługiwany język raportu, naruszenie granic rozmiaru/limitów, uszkodzona paczka wyników lub odrzucona odpowiedź AI. | Wyświetl komunikat walidacji przy polu formularza bez zamykania okna. |
| `FileExistsError` | Docelowy katalog wyników (`output_dir`) lub plik eksportu już istnieje (ochrona `O_CREAT \| O_EXCL` przed nadpisaniem dowodów). | Poproś użytkownika o wybór nowego katalogu/pliku wyjściowego. |
| `ProviderError` (`ai_threat_lab.ProviderError`) | Błąd transportu lub usługi zewnętrznej podczas operacji z jawnym opt-in sieciowym. | Pokaż status błędu połączenia i zachowaj wyniki lokalne. |
| `OSError` / `PermissionError` | Brak uprawnień systemu plików do katalogu wyjściowego lub brak dostępu do głównego celu. | Wyświetl błąd dostępu do systemu plików. |

---

## 3. Katalog funkcji API

### 3.1 Pobranie listy analizatorów — `list_analyzers()`

```python
def list_analyzers() -> list[dict]: ...
```

Zwraca deterministyczną listę wszystkich analizatorów celów oraz analizatorów pomocniczych:

```python
[
    {
        "id": "local_inventory",
        "target_kind": "local_project",
        "purpose": "Selected configuration, Python, dependency and secret checks",
        "limitations": "Bounded static pass; no code execution, build or full repo reachability.",
        "requires_network_opt_in": False,
    },
    ...
]
```

### 3.2 Sprawdzenie możliwości i ograniczeń — `get_capabilities()` oraz `get_scan_profiles()`

```python
def get_capabilities() -> dict: ...
def get_scan_profiles() -> dict: ...
def get_scan_profile(name: str) -> dict: ...
```

- `get_capabilities` zwraca statyczny słownik gotowości (`readiness`), wspierane języki raportowania (`supported_languages`: `["en", "pl"]`) oraz formaty eksportu (`export_formats`: `["json", "html", "sarif", "pdf"]`). Nie wykonuje żadnych połączeń sieciowych ani nie odczytuje kluczy API.
- `get_scan_profiles` zwraca słownik predefiniowanych profili skanowania (`fast` - 100 plików, `standard` - 1 000 plików, `extended` - 5 000 plików, `custom` - limit własny do 10 000 plików).
- `get_scan_profile(name)` pobiera konfigurację wybranego profilu.

### 3.3 Konfiguracja audytu — `create_audit_options(...)` oraz `plan_audit(...)`

```python
def create_audit_options(
    target: str | Path = ".",
    *,
    network: bool = False,
    allowed_hosts: tuple[str, ...] | list[str] = (),
    max_files: int = 50,
    profile: str | None = None,
    dkim_selector: str | None = None,
    share_packages: bool = False,
    max_pages: int = 10,
    advisory_cache: Path | str | None = None,
    recursive_dependencies: bool = False,
    language: str = "en",
) -> ScanOptions: ...

def plan_audit(
    target: str | Path,
    *,
    network: bool = False,
    allowed_hosts: tuple[str, ...] | list[str] = (),
    max_files: int = 50,
    profile: str | None = None,
    recursive_dependencies: bool = False,
    share_packages: bool = False,
    dkim_selector: str | None = None,
    max_pages: int = 10,
    language: str = "en",
) -> dict: ...
```

- `create_audit_options` waliduje parametry wejściowe i zwraca niemutowalny obiekt `ScanOptions`. Obsługuje parametr `profile` (`"fast"`, `"standard"`, `"extended"`, `"custom"`) oraz limit `max_files` od 1 do 10 000 plików.
- Obsługuje 9 rodzajów celów:
  1. `local_project` — lokalny katalog projektu (Python, Go, Rust, Java, C/C++, JS/TS, konfiguracje)
  2. `python_source` / `program_file` — pojedynczy plik źródłowy, binarka ELF/PE lub archiwum ZIP
  3. `github_repository` — zdalne repozytorium GitHub (`https://github.com/owner/repo`; wymaga `--network` i zgody na `github.com`)
  4. `website` — serwis WWW HTTPS (nagłówki i TLS; wymaga `--network` i zgody na host docelowy)
  5. `mail_domain` — weryfikacja rekordów SPF, DMARC, DKIM przez DoH (wymaga `--network` i zgody na domenę)
  6. `mail_message` — plik wiadomości e-mail (`.eml`; analiza offline)
  7. `mailbox_account` — konto Gmail (`mailbox:user@gmail.com`; wymaga `--network`, zgody na `gmail.googleapis.com` i tokena OAuth2)
  8. `authentication_log` / `ssh_journal` — dzienniki zdarzeń logowania i SSH
  9. Inne źródła niestandardowe
- `plan_audit` rozpoznaje typ celu (`target_kind`) i zwraca `tools`,
  `data_disclosure`, `setup_requirements`, `permission_requirements`,
  `bounds` i `notice`, bez wykonywania skanu. Ograniczenia są w `tools[].limit`.

### 3.4 Uruchomienie audytu — `run_audit(...)`

```python
def run_audit(
    target_or_options: ScanOptions | str | Path,
    output_dir: Path | str,
    *,
    options: ScanOptions | None = None,
    language: str = "en",
    baseline: Path | str | None = None,
    service: ScanService | None = None,
    on_event: Callable[[ScanEvent], None] | None = None,
    control: ScanControl | None = None,
) -> dict: ...
```

Wykonuje wybrane kontrole w zatwierdzonym zakresie i zapisuje paczkę dowodową
(`assessment.json`, `report.json`, `report.html`, `modules.json`, `manifest.json`;
opcjonalnie pliki zależności i porównania) w nowym katalogu `output_dir`.
To częściowa analiza, nigdy deklaracja kompletnego audytu bezpieczeństwa.

Zwraca podsumowanie wykonania:
- `run_id`, `status` (`"partial"` lub `"partial_with_module_failures"`), `output_directory`
- `unique_findings`, `failed_modules`, `modules` (status i opis każdej części)
- `ai_calls` (0), `comparison` (podsumowanie lub `None`), `notice`
- `report_language` (`"en"` lub `"pl"`)

### 3.5 Sprawdzenie statusu zapisanego przebiegu — `get_audit_status(...)`

```python
def get_audit_status(run_dir: Path | str) -> dict: ...
```

Weryfikuje integralność paczki SHA-256 (`manifest.json`) i zwraca status przebiegu:
- `status` / `state`: `"partial"` lub `"partial_with_module_failures"`
- `integrity_verified`: `True`
- `unique_findings`, `triage_counts`, `failed_components`, `not_checked_count`, `comparison`

### 3.6 Pobranie wyników i szczegółowych ustaleń — `get_audit_results(...)`

```python
def get_audit_results(
    run_or_report: Path | str,
    *,
    language: str = "en",
) -> dict: ...
```

Zwraca kompletny słownik wyników gotowy do wyświetlenia w widokach tabelarycznych i kartach szczegółów w GUI:
- `report`: oryginalny, autorytatywny raport techniczny (`report.json`)
- `summary`: słownik podsumowania (`unique_findings`, `finding_count`, `triage_counts`, `status_counts`)
- `detailed_findings`: lista ustrukturyzowanych słowników (`DetailedFinding.to_dict()`), gdzie każdy element zawiera:
  - `id`: stabilny identyfikator ustalenia
  - `rule_code`: oryginalny kod reguły analizatora (np. `PY001` lub `possible_secret`)
  - `title`: czytelny tytuł w wybranym języku (`en` / `pl`)
  - `threat_category`: kategoria zagrożenia
  - `target`: badany cel
  - `file_path`: ścieżka pliku lub `None` (nigdy nie jest zgadywana)
  - `line_number`: numer linii (`int`) lub `None` (nigdy nie jest wymyślany)
  - `line_range`: zakres linii (np. `"15-16"`) lub `None`
  - `evidence`: dowód wykrycia
  - `what_was_detected`: odpowiedź na *Co wykryto?*
  - `mechanism`: odpowiedź na *Dlaczego jest to potencjalnie niebezpieczne?*
  - `consequences`: odpowiedź na *Do czego może doprowadzić?*
  - `recommendation`: odpowiedź na *Jak to naprawić?*
  - `code_example`: bezpieczny przykład kodu naprawczego lub `None`
  - `verification_steps`: odpowiedź na *Jak sprawdzić poprawkę?*
  - `analysis_limitations`: odpowiedź na *Czego analizator nie ustalił?*
  - `confirmation_status`: `"candidate"` lub `"unverified"` (heurystyki nigdy nie są oznaczane jako `"confirmed"`)
  - `triage_priority`: `"P1"`..`"P4"`
- `summary_text` / `brief_text`: tekstowe podsumowanie offline w wybranym języku
- `html_report` / `html`: pełny raport HTML z rygorystycznym `Content-Security-Policy` w wybranym języku
- `not_checked`: lista pominiętych kontroli i ograniczeń

### 3.7 Eksport raportów — `export_audit_report(...)`, `export_audit_pdf(...)`

```python
def export_audit_report(
    run_dir: Path | str,
    output: Path | str | None = None,
    *,
    format: str = "json",
    language: str = "en",
    ai_review: dict | None = None,
    ai_review_path: Path | str | None = None,
) -> str: ...

def export_audit_pdf(
    run_or_report: Path | str | dict,
    output: Path | str,
    *,
    language: str = "en",
    ai_review: dict | None = None,
) -> Path: ...
```

Eksportuje zweryfikowany przebieg do formatu `"json"`, `"html"` (w języku `"en"` lub `"pl"`), `"sarif"` (SARIF v2.1.0) lub profesjonalnego `"pdf"`. Generator PDF tworzy dokument PDF 1.4 z obsługą polskich znaków diakrytycznych, kartami wyników, wycinkami kodu źródłowego i opcjonalną interpretacją doradczą Gemini AI. Jeżeli podano `output`, zapisuje plik atomowo z flagą `O_CREAT | O_EXCL` poza katalogiem przebiegu.

### 3.8 Pobranie historii uruchomień — `get_audit_history(...)`

```python
def get_audit_history(history_root: Path | str) -> dict: ...
```

Przeszukuje katalog historii i zwraca zweryfikowane oraz uszkodzone przebiegi bez wykonywania zapytań sieciowych:
- `runs`: lista rekordów z polami `directory`, `verification` (`"verified"` / `"invalid"`), `kind`, `created_at`, `unique_findings`, `targets`
- `verified_runs`, `invalid_runs`, `ignored_files`, `ignored_directories`

### 3.9 Przygotowanie pakietów AI i walidacja odpowiedzi — `prepare_ai_packets(...)`, `build_multilingual_ai_packet(...)`, `attach_ai_interpretation(...)`

```python
def prepare_ai_packets(
    evidence_path: Path | str,
    config: AIConfig | None = None,
    *,
    language: str = "en",
    structured: bool = True,
    split: bool = True,
    packet_index: int | None = None,
    group_size: int = 3,
) -> dict: ...

def build_multilingual_ai_packet(
    report: dict,
    config: AIConfig | None = None,
    *,
    language: str = "en",
    packet_index: int | None = None,
    group_size: int = 3,
) -> dict: ...

def attach_ai_interpretation(
    report: dict,
    raw_ai_response: str,
    *,
    expected_ids: set[str] | None = None,
    language: str = "en",
    preserve_on_error: bool = True,
) -> dict: ...
```

Gwarancje kontraktu AI:
1. Model otrzymuje wyłącznie zminimalizowany pakiet dowodów (`input`).
2. Oryginalny raport techniczny pozostaje niemutowalny (`copy.deepcopy`).
3. Odpowiedź AI jest zapisana w osobnym polu `ai_advisory` obok `technical_report`.
4. Walidator odrzuca odpowiedzi z nieznanymi lub pominiętymi `evidence_id`, nadmiarowymi polami (np. próbą dopisania lokalizacji, zmiany statusu potwierdzenia lub wywołania narzędzi).
5. Przy `preserve_on_error=True` (domyślnie) błędna odpowiedź AI zwraca nienaruszony `technical_report` oraz `ai_advisory["status"] == "rejected_invalid_ai_output"`.

---

## 4. Przykład użycia w kodzie GUI (kontroler widoku)

```python
from pathlib import Path
from ai_threat_lab import (
    ValidationError,
    create_audit_options,
    get_audit_results,
    plan_audit,
    run_audit,
)

def execute_project_audit(project_path: Path, output_dir: Path, lang: str = "pl") -> dict:
    # 1. Podgląd planu przed uruchomieniem
    plan = plan_audit(project_path, language=lang)

    # 2. Konfiguracja i wykonanie audytu (w wątku roboczym GUI)
    options = create_audit_options(project_path, max_files=100, language=lang)
    run_audit(options, output_dir=output_dir, language=lang)

    # 3. Pobranie ustrukturyzowanych wyników i raportu HTML
    results = get_audit_results(output_dir, language=lang)
    return {
        "plan": plan,
        "summary": results["summary"],
        "findings": results["detailed_findings"],
        "not_checked": results["not_checked"],
        "html": results["html_report"],
    }
```

## 5. Postęp i anulowanie — rozszerzenie kompatybilne

`ScanEvent`, `ScanControl` i `ScanCancelled` są dostępne w `ai_threat_lab`
oraz `ai_threat_lab.gui_api`. Nowe parametry są opcjonalne i keyword-only;
istniejące wywołania `run_audit` i formaty raportów zachowują kontrakty.

`ScanEvent` jest niemutowalną dataclass z polami:

| Pole | Typ / znaczenie |
| --- | --- |
| `schema_version` | `int`, obecnie 1 |
| `operation_id` | `str`, identyfikator operacji zdarzeń; nie jest identyfikatorem zapisanego raportu |
| `sequence` | `int`, rosnący od 1 w jednej operacji |
| `event` | `str`, jedna z nazw poniżej |
| `module` | `str \| None`, target_assessment / dependency_inventory / dependency_advisories |
| `status` | `str \| None`, status modułu lub operacji, bez treści źródła i wyjątków |

Nazwy: `scan_started`, `module_started`, `module_completed`, `module_failed`,
`module_skipped`, `scan_publishing`, `scan_completed`, `scan_cancel_requested`,
`scan_cancelled`, `scan_interrupted`, `scan_failed`. `to_dict()` zwraca serializowalny
słownik. Nie ma fikcyjnych procentów ani liczby przeanalizowanych plików wyliczanej
z samego limitu. Moduł `partial` zakończył wykonywanie, ale nie zapewnia pełnego pokrycia.

Callback jest synchroniczny w wątku skanu. Powinien szybko przekazać zdarzenie do
kolejki. Zwykłe wyjątki callbacku są izolowane, aby awaria widoku nie unieważniała
raportu. Sam odbiorca odpowiada za rejestrowanie błędów swojej kolejki/widoku.
Brak callbacku nie zmienia raportu.

Przykład w czystym Pythonie, bez GUI:

```python
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue
from ai_threat_lab.gui_api import ScanCancelled, ScanControl, ScanEvent, run_audit

def audit_with_progress(target, output, cancel_requested=lambda: False):
    events: Queue[ScanEvent] = Queue()
    control = ScanControl()  # nowy obiekt dla każdego uruchomienia
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_audit, target, output,
                             on_event=events.put_nowait, control=control)
        while not future.done() or not events.empty():
            if cancel_requested():
                accepted = control.request_cancel()
                # False: publikacja już się rozpoczęła lub operacja zakończyła.
            try:
                event = events.get(timeout=0.1)
            except Empty:
                continue
            print(event.to_dict())  # konsument może zachować najnowszy stan
        try:
            return future.result()
        except ScanCancelled:
            return {"status": "cancelled", "bundle_committed": False}
```

`request_cancel() -> bool` jest thread-safe. Jeden token obsługuje jedną operację;
ponowne użycie powoduje `ValueError`. Akceptowane żądanie jest sprawdzane między
modułami i przed publikacją. Nie przerywa natychmiast zablokowanego kolektora;
nie jest twardym timeoutem. Ostatni checkpoint atomowo zamyka bramkę anulowania,
zanim zacznie się publikacja. Późniejsze żądanie zwraca `False`.

`ScanCancelled` gwarantuje brak opublikowanej nowej paczki. `KeyboardInterrupt`
przed publikacją zgłasza anulowanie; podczas publikacji zgłasza
`scan_interrupted`/`verification_required`. Wtedy sprawdź katalog przez
`get_audit_status` przed użyciem. Kill procesu lub zamknięcie terminala może nie
wygenerować zdarzenia końcowego. Brak poprawnego manifestu oznacza nieważną paczkę.
Wcześniejsze raporty pozostają nienaruszone.

`ScanService` nie przechowuje współdzielonego stanu postępu. Równoległe audyty
potrzebują oddzielnych tokenów i nowych katalogów; wstrzyknięte kolektory, zegary
oraz callbacki muszą samodzielnie zapewnić thread safety. Konsument powinien
przestrzegać kolejności `operation_id`/`sequence`, nie globalnej kolejności między
wątkami. `get_audit_status` odczytuje zapisany raport, nie działający Future.

## 6. Szczegóły, porównanie i walidacja bez GUI

Pojedyncze szczegóły są w `get_audit_results(run)["detailed_findings"]`, indeksowane
przez `id`; brak dopasowania jest brakiem obserwacji, nie potwierdzeniem poprawki.
Do porównania dwóch paczek pojedynczego skanu użyj istniejących publicznych usług:

```python
from pathlib import Path
from ai_threat_lab.scan_bundle import compare_bundles, read_bundle

delta = compare_bundles(read_bundle(Path("runs/before")),
                        read_bundle(Path("runs/after")))
if not delta["comparable"]:
    print(delta["reason"])  # zmiana zakresu/modułów lub błąd analizatora
```

Historia, szczegóły i eksport korzystają z tych samych zapisanych dowodów, nie
ponawiają skanu. Odczyt bare report ma słabszą proweniencję niż zweryfikowana paczka;
sprawdź `origin`. Integralność nie potwierdza autentyczności lub prawdziwości luk.
Przekazanie `source_root` do niskopoziomowego PDF jest osobną zgodą na odczyt
bieżącego kodu, oznaczanego jako niezweryfikowany względem skanu; eksport zapisanej
paczki przez fasadę nie potrzebuje ponownego otwierania źródeł. Redakcja wzorców
sekretów nie gwarantuje anonimizacji dowolnej treści.

Sieć, udostępnienie zależności i interpretacja AI mają osobne bramki zgody. Sam
callback, historia i eksport nie nadają dodatkowych uprawnień. Nigdy nie wykonuj
poleceń znalezionych w dowodach.

Testy kontraktu bez Qt i modeli:

```bash
python -m pytest -q tests/test_scan_lifecycle.py tests/test_audit_console.py tests/test_stage2_audit_and_gui_api.py
```
