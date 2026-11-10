"""Reproducible synthetic engine/serialization timings and traced Python allocations.

Run from an installed development checkout. No network, models or target execution.
These deliberately small fixtures do not estimate real-world security effectiveness.
"""

import json
import tempfile
import tracemalloc
from pathlib import Path
from time import perf_counter

from ai_threat_lab.gui_api import export_audit_report, run_audit
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_engine import ScanOptions


def benchmark():
    rows = []
    with tempfile.TemporaryDirectory(prefix="threat engine benchmark ") as folder:
        base = Path(folder)
        for count in (1, 100):
            project = base / f"project-{count}"
            project.mkdir()
            for index in range(count):
                (project / f"sample_{index:03}.py").write_text(
                    "eval(user_input)\n" if index % 2 == 0 else
                    "import ast\nast.literal_eval(user_input)\n", encoding="utf-8",
                )
            for repeat in (1, 2):
                output = base / f"run-{count}-{repeat}"
                tracemalloc.start()
                start = perf_counter()
                result = run_audit(ScanOptions(str(project), max_files=100), output)
                elapsed = perf_counter() - start
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                start = perf_counter()
                bundle = read_bundle(output)
                verification = perf_counter() - start
                start = perf_counter()
                encoded = json.dumps(bundle["documents"]["report.json"],
                                     ensure_ascii=False, separators=(",", ":")).encode()
                serialization = perf_counter() - start
                start = perf_counter()
                export_audit_report(output, base / f"report-{count}-{repeat}.pdf", format="pdf")
                pdf = perf_counter() - start
                expected = (count + 1) // 2
                assert result["unique_findings"] == expected
                rows.append({
                    "files": count, "repeat": repeat, "candidates": expected,
                    "scan_seconds_with_tracemalloc": elapsed,
                    "python_traced_peak_bytes": peak,
                    "verify_seconds": verification, "serialize_seconds": serialization,
                    "report_json_bytes": len(encoded), "pdf_export_seconds": pdf,
                })
    return {
        "schema_version": 1, "fixture": "Alternating eval and literal_eval inert Python files",
        "measurements": rows,
        "notice": "Tracemalloc affects scan timing and excludes native/child allocations. "
        "This is not OS peak RSS, an OS memory ceiling, token counts or real-world recall. "
        "Repeat scans create new bundles; no scanner cache was introduced.",
    }


if __name__ == "__main__":
    print(json.dumps(benchmark(), indent=2))
