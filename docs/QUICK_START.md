# Szybki start — konsola

Zainstaluj projekt według [instrukcji](CLI_INSTALLATION.md). Python 3.12 lub nowszy.

```bash
ai-threat-lab --version
ai-threat-lab menu --lang pl
ai-threat-lab doctor
```

Menu pozwala wybrać cel, limit plików i katalog wyników. Domyślnie analiza lokalna
nie wymaga klucza AI. Rozpoznanie rozszerzenia pliku nie oznacza pełnej analizy jego
języka. Wyniki to kandydaci i obserwacje z jawnymi ograniczeniami.

```bash
ai-threat-lab scan path/to/project --profile standard --output-dir results/run-01
ai-threat-lab scan-check results/run-01
ai-threat-lab brief results/run-01 --language pl
ai-threat-lab report-export results/run-01 --format pdf --lang pl --output audit.pdf
```

Używaj nowego katalogu skanu. Sprawdź błędy modułów i `not_checked`, także gdy nie
ma ustaleń. Zapisany PDF nie odczytuje automatycznie oryginalnych plików źródłowych.
Menu może dołączyć bieżący kontekst z wybranego projektu, wyraźnie oznaczony jako
niezweryfikowany względem skanu. Kontekst ustaleń o sekretach jest pomijany.

## Opcjonalne AI

Przygotuj prywatny plik konfiguracji na podstawie `examples/ai-budget.json`.
Wpisz wybrany model, sprawdzone ceny i własne limity; wartości przykładowe nie są
aktualnym cennikiem. Samo przygotowanie pakietów nie wymaga klucza.

```bash
ai-threat-lab ai-prepare results/run-01 --ai-config ai.json --provider gemini --language pl --structured --split --output preview.json
ai-threat-lab setup-check --ai-config ai.json
```

Przejrzyj dokładny pakiet przed udostępnieniem. Menu poprosi o konfigurację, wybór
pakietu i zgodę na koszt, używając wspólnego lokalnego dziennika między audytami.
Nie wszystkie ustalenia muszą zmieścić się w jednej interpretacji. Gemini i OpenAI
objaśniają dowody; nie uruchamiają ataków ani nie zastępują analizatorów.

[Akceptacja usług i klucze](READY_FOR_API_TESTING.md) · [Koszty](API_COSTS.md) ·
[Możliwości i brakujące obszary](DELIVERY_STATUS.md)
