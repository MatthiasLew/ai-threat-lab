"""Reproducible synthetic engine/serialization timings and traced Python allocations.

Run from an installed development checkout. No network, models or target execution.
These deliberately small fixtures do not estimate real-world security effectiveness.
"""

import argparse
import json
import platform
import subprocess
import sys
import tempfile
import tracemalloc
from pathlib import Path
from time import perf_counter

from ai_threat_lab.agent_protocol import execute
from ai_threat_lab.gui_api import export_audit_report, run_audit
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_engine import ScanOptions


def peak_rss():
    if sys.platform == "linux":
        import resource

        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("faults", wintypes.DWORD),
                        ("peak_working_set", ctypes.c_size_t), ("other", ctypes.c_size_t * 7)]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        read = kernel.K32GetProcessMemoryInfo
        read.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD)
        counters = Counters()
        counters.size = ctypes.sizeof(counters)
        if read(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.size):
            return counters.peak_working_set
    return None


def mcp_summary(root, run):
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "benchmark", "version": "1"},
        }},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "security_summary", "arguments": {"run": run},
        }},
    ]
    started = perf_counter()
    response = subprocess.run(
        [sys.executable, "-m", "ai_threat_lab", "agent", "mcp", "serve", "--root", str(root)],
        input="".join(json.dumps(message) + "\n" for message in messages),
        text=True, encoding="utf-8", capture_output=True, check=True, timeout=75,
    )
    elapsed = perf_counter() - started
    replies = [json.loads(line) for line in response.stdout.splitlines()]
    assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
    assert replies[1]["id"] == 2
    return elapsed, replies[1]["result"]["structuredContent"]["status"]


def benchmark(*, extended=False):
    rows = []
    with tempfile.TemporaryDirectory(prefix="threat engine benchmark ") as folder:
        base = Path(folder)
        profiles = [("single", 1), ("flat", 100)]
        if extended:
            profiles += [("nested-lock-large", 1000)]
        for profile, count in profiles:
            project = base / f"project-{profile}"
            project.mkdir()
            for index in range(count):
                module = project / f"module_{index // 100}" if count == 1000 else project
                module.mkdir(exist_ok=True)
                source = ("eval(user_input)\n" if index % 2 == 0 else
                          "import ast\nast.literal_eval(user_input)\n")
                if count == 1000 and index == 999:
                    source += "# bounded large-file fixture\n" * 4000
                (module / f"sample_{index:03}.py").write_text(source, encoding="utf-8")
            if count == 1000:
                (project / "package-lock.json").write_text(
                    '{"lockfileVersion":3,"packages":{}}', encoding="utf-8",
                )
            for repeat in (1, 2):
                output = base / f"run-{count}-{repeat}"
                tracemalloc.start()
                start = perf_counter()
                result = run_audit(ScanOptions(str(project), max_files=max(100, count)), output)
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
                if count < 1000:
                    assert result["unique_findings"] == expected
                transport = {}
                if extended:
                    start = perf_counter()
                    response = execute(base, "summary", {"run": output.name})
                    transport = {"agent_worker_seconds": perf_counter() - start,
                                 "agent_worker_status": response["status"]}
                    elapsed_mcp, status_mcp = mcp_summary(base, output.name)
                    transport.update(mcp_roundtrip_seconds=elapsed_mcp, mcp_status=status_mcp)
                rows.append({
                    "profile": profile, "files": count, "repeat": repeat,
                    "candidates": result["unique_findings"], "expected_fixture_sites": expected,
                    "failed_modules": result["failed_modules"],
                    "scan_seconds_with_tracemalloc": elapsed,
                    "python_traced_peak_bytes": peak,
                    "verify_seconds": verification, "serialize_seconds": serialization,
                    "report_json_bytes": len(encoded), "pdf_export_seconds": pdf, **transport,
                })
    return {
        "schema_version": 1, "fixture": "Alternating eval and literal_eval inert Python files",
        "measurements": rows,
        "scanner_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "python": platform.python_version(), "system": platform.platform(),
        "process_peak_rss_bytes": peak_rss(),
        "rss_scope": "benchmark process lifetime, excluding workers",
        "notice": "Tracemalloc affects scan timing and excludes native/child allocations. "
        "This is not OS peak RSS, an OS memory ceiling, token counts or real-world recall. "
        "Repeat scans create new bundles; no scanner cache was introduced.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extended", action="store_true")
    print(json.dumps(benchmark(extended=parser.parse_args().extended), indent=2))
