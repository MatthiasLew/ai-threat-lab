"""Compare two local source trees using fresh processes and the same inert fixture."""

import argparse
import functools
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tracemalloc
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter


def measure(target, output, traced):
    from ai_threat_lab import report_io, scan_engine
    from ai_threat_lab.scan_bundle import read_bundle
    from ai_threat_lab.scan_cli import assessor

    times = dict(discovery=0.0, read=0.0, publication=0.0)

    def timed(function, phase):
        @functools.wraps(function)
        def call(*args, **kwargs):
            start = perf_counter()
            try:
                return function(*args, **kwargs)
            finally:
                times[phase] += perf_counter() - start
        return call

    def walk(function):
        def timed_walk(*args, **kwargs):
            iterator = iter(function(*args, **kwargs))
            advance = timed(next, "discovery")
            while True:
                try:
                    row = advance(iterator)
                except StopIteration:
                    return
                yield row
        return timed_walk

    os.walk = walk(os.walk)
    report_io.read_regular = timed(report_io.read_regular, "read")
    scan_engine.publish_bundle = timed(scan_engine.publish_bundle, "publication")
    if traced:
        tracemalloc.start()
    start = perf_counter()
    options = scan_engine.ScanOptions(str(target), max_files=1000)
    scan_engine.ScanService(assessor).run(options, output)
    elapsed = perf_counter() - start
    peak = tracemalloc.get_traced_memory()[1] if traced else None
    if traced:
        tracemalloc.stop()
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        counters = (ctypes.c_size_t * 10)()
        ctypes.cast(counters, ctypes.POINTER(wintypes.DWORD))[0] = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL("kernel32")
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        query = kernel.K32GetProcessMemoryInfo
        query.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD)
        success = query(kernel.GetCurrentProcess(), counters, ctypes.sizeof(counters))
        rss = counters[1] if success else None
    else:
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "linux":
            rss *= 1024
    assessment = read_bundle(output)["documents"]["assessment.json"]
    evidence = json.dumps(
        [assessment["findings"], assessment["not_checked"]], sort_keys=True,
    ).encode()
    return {
        "total": elapsed, **times, "analysis_and_other": elapsed - sum(times.values()),
        "python_peak_bytes": peak, "process_peak_rss_bytes": rss,
        "finding_count": len(assessment["findings"]),
        "assessment_sha256": hashlib.sha256(evidence).hexdigest(),
    }


def compare(trees):
    report = {"system": platform.platform(), "python": platform.python_version(), "modes": {}}
    report["revisions"] = {
        label: subprocess.check_output(
            ["git", "-C", str(tree), "rev-parse", "HEAD"], text=True,
        ).strip()
        for label, tree in trees.items()
    }
    with TemporaryDirectory(prefix="atl-m2-ab-") as temporary:
        root = Path(temporary)
        target = root / "fixture"
        for group in range(10):
            folder = target / f"group{group}"
            folder.mkdir(parents=True)
            for index in range(100):
                source = "eval(data)\n" if index % 2 == 0 else "pass\n"
                (folder / f"file{index:02}.py").write_text(source, encoding="utf-8")
        for mode in ("plain", "traced"):
            samples = {label: [] for label in trees}
            for iteration in range(4):
                order = list(trees) if iteration % 2 == 0 else list(reversed(trees))
                for label in order:
                    env = {**os.environ, "PYTHONPATH": str(trees[label] / "src")}
                    command = [
                        sys.executable, "-P", str(Path(__file__).resolve()), "--child",
                        str(target), str(root / f"{mode}-{label}-{iteration}"), mode,
                    ]
                    row = json.loads(subprocess.check_output(command, env=env, timeout=90))
                    if iteration:
                        samples[label].append(row)
            digests = {row["assessment_sha256"] for rows in samples.values() for row in rows}
            if len(digests) != 1:
                raise ValueError("Compared assessments differ")
            report["modes"][mode] = {}
            for label, rows in samples.items():
                report["modes"][mode][label] = {
                    "rows": rows,
                    "median": {
                        key: statistics.median(row[key] for row in rows)
                        for key, value in rows[0].items() if isinstance(value, (float, int))
                    },
                }
    return report


if __name__ == "__main__":
    if sys.argv[1:2] == ["--child"]:
        print(json.dumps(measure(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4] == "traced")))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("baseline", type=Path)
        parser.add_argument("candidate", type=Path)
        parser.add_argument("--intermediate", type=Path)
        args = parser.parse_args()
        trees = {"baseline": args.baseline.resolve()}
        if args.intermediate:
            trees["intermediate"] = args.intermediate.resolve()
        trees["candidate"] = args.candidate.resolve()
        print(json.dumps(compare(trees), indent=2))
