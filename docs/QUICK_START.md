# AI Threat Lab — Szybki start (`QUICK_START.md`)

Praktyczny przewodnik dla programistów pokazujący, jak w kilka minut przeprowadzić lokalny audyt bezpieczeństwa projektu lub pliku bez konieczności konfigurowania kluczy API ani połączenia z siecią.

---

## 1. Instalacja

Wymagany jest **Python 3.12 lub nowszy** (obsługiwane wersje: `3.12`, `3.13`, `3.14`). Pakiet instaluje się bez zewnętrznych zależności uruchomieniowych:

```bash
python -m pip install -e .
```

Sprawdzenie poprawności instalacji i dostępnych możliwości offline:

```bash
ai-threat-lab readiness --format text
```

---

## 2. Audyt projektu lokalnego (jedna komenda)

Najprostszy sposób na wykonanie kompletnego audytu katalogu projektu wraz z wygenerowaniem zweryfikowanej paczki wyników i czytelnego raportu w języku polskim (`--language pl`) lub angielskim (`--language en`):

```bash
ai-threat-lab inspect ./my-project --output-dir results/my-project --language pl
```

Co robi to polecenie:
1. **Rozpoznaje typ celu** (`local_project`).
2. **Wyświetla dostępne i przygotowane analizatory** (analiza składni i przepływu danych Python AST, wykrywanie wzorców sekretów, kontrola `Dockerfile`, `.github/workflows/*.yml`, manifestów Kubernetes JSON oraz zależności `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.mod`, `go.sum`, `composer.lock`, `packages.lock.json`, `pom.xml`).
3. **Wykonuje kontrole statyczne offline** (bez uruchamiania badanego kodu i bez instalacji pakietów).
4. **Jawnie informuje o pominiętych kontrolach** (np. brak zapytań sieciowych OSV bez `--network`, pominięte pliki nieobsługiwane lub uszkodzone).
5. **Zapisuje zweryfikowaną paczkę wyników** w `results/my-project/` (`report.json`, `report.html`, `results.json`, `plan.json`, `manifest.json`).
6. **Wyświetla szczegółowe podsumowanie w terminalu** odpowiadające dla każdego ustalenia na 6 pytań inżynierskich (*Co wykryto?*, *Dlaczego jest to potencjalnie niebezpieczne?*, *Do czego może doprowadzić?*, *Jak to naprawić?*, *Jak sprawdzić poprawkę?*, *Czego analizator nie ustalił?*).

Jeżeli chcesz najpierw zobaczyć sam plan audytu bez uruchamiania analizatorów:

```bash
ai-threat-lab plan ./my-project --format text
```

---

## 3. Audyt pojedynczego pliku

Możesz przekazać do `inspect` pojedynczy plik źródłowy Pythona, dokument HTML, wiadomość `.eml`, archiwum `.zip`, plik wykonywalny PE/ELF lub dziennik logowania `.auth.jsonl` / `.ssh.jsonl`:

```bash
ai-threat-lab inspect ./src/app.py --output-dir results/app-audit --language pl
```

Do szybkiego przeglądu pojedynczego pliku Python bez tworzenia katalogu paczki możesz też użyć:

```bash
ai-threat-lab review-code ./src/app.py --format text
```

Lub wyeksportować wyniki bezpośrednio do formatu SARIF v2.1.0:

```bash
ai-threat-lab review-code ./src/app.py --format sarif --output results/app.sarif
```

---

## 4. Przegląd raportu i historii uruchomień

Po zakończeniu `inspect` w katalogu docelowym (`results/my-project/`) znajdują się:
- `report.html` — samodzielny raport HTML (z rygorystycznym `Content-Security-Policy`, bez zewnętrznych skryptów i czcionek) zawierający tabelę priorytetów oraz karty naprawcze (*Co wykryto?*, *Dlaczego jest to potencjalnie niebezpieczne?*, *Do czego może doprowadzić?*, *Jak to naprawić?*, *Jak sprawdzić poprawkę?*, *Czego analizator nie ustalił?*).
- `report.json` — ustrukturyzowany raport techniczny JSON.
- `manifest.json` — manifest skrótów SHA-256 chroniący spójność paczki.

Ponowne wyświetlenie czytelnego podsumowania w terminalu (po polsku lub angielsku):

```bash
ai-threat-lab brief results/my-project --language pl
```

Weryfikacja spójności kryptograficznej zapisanej paczki:

```bash
ai-threat-lab scan-check results/my-project
```

Eksport raportu HTML w wybranym języku lub przegląd historii wszystkich audytów w katalogu `results/`:

```bash
ai-threat-lab history results --format text
ai-threat-lab history-export results/my-project --format html --output results/raport-pl.html
```

---

## 5. Zrozumienie statusów ustaleń i priorytetów

AI Threat Lab rygorystycznie rozróżnia obserwacje statyczne od potwierdzonych podatności:

| Pole / Wartość | Znaczenie |
|---|---|
| `candidate` | **Kandydat do przeglądu** — statyczny analizator wykrył niebezpieczny wzorzec w kodzie, konfiguracji lub przepływie danych (np. `subprocess.run(..., shell=True)`, budowanie zapytania SQL przez f-string z wejścia HTTP, `permissions: write-all`). Wymaga weryfikacji kontekstu przez programistę. |
| `unverified` | **Obserwacja niezweryfikowana** — zapisany nagłówek, wpis w manifeście lub deklaracja, której autentyczności nie można potwierdzić wyłącznie na podstawie pliku lokalnego. |
| Brak fałszywego `confirmed` | Żaden heurystyczny ani statyczny analizator offline nie oznacza swoich wykryć jako potwierdzonej podatności (`confirmed`), dopóki człowiek nie zweryfikuje osiągalności w środowisku docelowym. |
| `P1` – `P4` | **Kolejność przeglądu (Triage Priority)** — porządkuje ustalenia od najbardziej ryzykownych wzorców wykonania kodu/wstrzyknięć (`P1`, `P2`) do zaleceń utwardzających konfigurację (`P3`, `P4`). |
| Lokalizacje (`file_path`, `line_number`) | Podawane wyłącznie wtedy, gdy wynikają bezpośrednio ze spasowanego pliku i linii. Program nigdy nie zgaduje ani nie wymyśla numerów linii. |

---

## 6. Znane ograniczenia wersji offline

1. **Brak wykonywania badanego kodu:** Analizatory parsują drzewo AST i pliki konfiguracyjne statycznie — badany kod ani kontenery nigdy nie są uruchamiane.
2. **Brak automatycznych połączeń sieciowych:** Domyślnie program działa w 100% offline. Odpytanie bazy podatności OSV dla zależności lub pobranie migawki zdalnego repozytorium wymaga jawnego przełącznika `--network` oraz listy dozwolonych hostów `--allow-host`.
3. **Ograniczony zasięg międzyplikowy:** Analiza przepływu danych w Pythonie śledzi wybrane źródła (np. Flask/WSGI/CGI/CLI) oraz ujścia (`eval`/`exec`, `subprocess`, `sqlite3`) w obrębie projektu do zdefiniowanych limitów liczby plików i rozmiaru, jawnie raportując pominięte pliki w sekcji `not_checked`.
4. **Przygotowanie danych dla AI bez wywoływania API:** Polecenie `ai-threat-lab ai-prepare results/my-project --ai-config ai.json --language pl` buduje zminimalizowany pakiet dowodów i wylicza rezerwację kosztu bez wysyłania danych przez sieć.
