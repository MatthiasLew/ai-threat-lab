"""Small bilingual terminal adapters over existing public audit services."""

from pathlib import Path

from .contracts import write_document
from .gui_api import get_audit_history, get_audit_results, get_capabilities
from .installation import installation_report
from .models import ValidationError
from .path_utils import clean_user_path
from .scan_bundle import compare_bundles, read_bundle
from .training_cli import terminal_text


def display_event(event, language, print_fn=print):
    pl = language == "pl"
    names = {
        "scan_started": ("Rozpoczęto audyt", "Audit started"),
        "module_started": ("Uruchomiono analizator", "Analyzer started"),
        "module_completed": ("Zakończono analizator", "Analyzer completed"),
        "module_failed": ("Błąd analizatora", "Analyzer failed"),
        "module_skipped": ("Pominięto analizator", "Analyzer skipped"),
        "scan_publishing": ("Zapisywanie raportu", "Publishing report"),
        "scan_completed": ("Zakończono audyt", "Audit completed"),
        "scan_cancel_requested": ("Żądanie anulowania", "Cancellation requested"),
        "scan_cancelled": ("Anulowano audyt", "Audit cancelled"),
        "scan_failed": ("Błąd audytu", "Audit failed"),
        "scan_interrupted": (
            "Przerwano zapis; sprawdź raport", "Publication interrupted; verify run",
        ),
    }
    label = names.get(event.event, (event.event, event.event))[0 if pl else 1]
    print_fn(f"[{event.sequence}] {label}" +
             (f": {event.module} ({event.status or 'running'})" if event.module else ""))


def browse_history(language, input_fn=input, print_fn=print):
    """Verify catalog first; never open invalid catalog entries as trusted results."""
    output = print_fn
    print_fn = lambda value: output(terminal_text(str(value)))  # noqa: E731
    pl = language == "pl"
    try:
        root = Path(clean_user_path(input_fn(
            "Katalog historii (0 = powrót): " if pl else "History directory (0 = back): "
        ).strip()))
        if str(root) == "0":
            return
        catalog = get_audit_history(root)
        rows = catalog["runs"]
        for index, row in enumerate(rows, 1):
            print_fn(f"{index}. {row['directory']} [{row['verification']}] "
                     f"{row.get('unique_findings', '?')}")
        print_fn(catalog["notice"])
        if not rows:
            print_fn("Brak audytów." if pl else "No saved audits.")
            return

        def select(prompt):
            value = int(input_fn(prompt))
            if not 1 <= value <= len(rows):
                raise ValidationError("Audit number outside catalog")
            row = rows[value - 1]
            if row["verification"] != "verified":
                raise ValidationError("Saved audit is invalid; cannot display trusted results")
            return root / row["directory"]

        while True:
            choice = input_fn(
                "1 Podsumowanie i szczegóły / 2 Porównaj / 0 Powrót: " if pl else
                "1 Summary and details / 2 Compare / 0 Back: "
            ).strip()
            if choice == "0":
                return
            try:
                if choice == "1":
                    selected = select("Numer audytu: " if pl else "Audit number: ")
                    result = get_audit_results(selected, language=language)
                    print_fn(result["summary_text"])
                    findings = result["detailed_findings"]
                    for index, finding in enumerate(findings, 1):
                        print_fn(f"{index}. [{finding['triage_priority']}] {finding['title']}")
                    while findings:
                        number = int(input_fn(
                            "Numer ustalenia (0 = powrót): " if pl else
                            "Finding number (0 = back): "
                        ))
                        if number == 0:
                            break
                        if not 1 <= number <= len(findings):
                            raise ValidationError("Finding number outside results")
                        print_fn(write_document(findings[number - 1]))
                elif choice == "2":
                    base = select("Poprzedni audyt: " if pl else "Previous audit: ")
                    head = select("Nowy audyt: " if pl else "Current audit: ")
                    print_fn(write_document(compare_bundles(read_bundle(base), read_bundle(head))))
                else:
                    raise ValidationError("Choose 0, 1 or 2")
            except (ValueError, ValidationError, OSError) as exc:
                print_fn(("Błąd: " if pl else "Error: ") + str(exc))
    except (ValueError, ValidationError, OSError) as exc:
        print_fn(("Błąd historii: " if pl else "History error: ") + str(exc))
    except EOFError:
        return


def display_diagnostics(language, print_fn=print):
    print_fn("Diagnostyka offline" if language == "pl" else "Offline diagnostics")
    print_fn(write_document({"installation": installation_report(),
                             "capabilities": get_capabilities()}))
