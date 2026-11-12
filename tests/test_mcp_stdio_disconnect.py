"""Check the synchronous server using actual OS pipes."""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from ai_threat_lab.scan_bundle import read_bundle

INITIALIZE = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {}},
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
SCAN = {
    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
    "params": {"name": "security_scan", "arguments": {"target": "fixture.py"}},
}


def verify_committed_scan(root):
    manifests = list((root / ".ai-threat-lab").rglob("manifest.json"))
    assert len(manifests) == 1
    read_bundle(manifests[0].parent)


@pytest.mark.parametrize("close_output", [False, True])
def test_stdio_exit_is_quiet_after_pipe_closure(tmp_path, close_output):
    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; from ai_threat_lab.agent_mcp import serve; "
            "raise SystemExit(serve(sys.argv[1]))",
            str(tmp_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        try:
            if close_output:
                process.stdout.close()
                request = {"jsonrpc": "2.0", "method": "ping", "id": 1}
                process.stdin.write(json.dumps(request).encode() + b"\n")
            process.stdin.close()
            result = process.wait(timeout=20)
            stderr = process.stderr.read()
            assert result == 0, stderr
            assert stderr == b""
        finally:
            if process.poll() is None:
                process.kill()


def test_scan_can_commit_after_stdio_client_disconnects(tmp_path):
    (tmp_path / "fixture.py").write_text("pass\n", encoding="utf-8")
    program = """
import sys
from ai_threat_lab import agent_protocol
from ai_threat_lab.agent_mcp import serve

start = agent_protocol.subprocess.Popen

def gate(command, **kwargs):
    child = start(command, **kwargs)
    print("worker-started", file=sys.stderr, flush=True)
    if sys.stdin.buffer.read(1) != b"":
        child.kill()
        child.wait()
        raise RuntimeError("expected client EOF")
    return child

agent_protocol.subprocess.Popen = gate
raise SystemExit(serve(sys.argv[1]))
"""
    messages = [INITIALIZE, INITIALIZED, SCAN]
    with subprocess.Popen(
        [sys.executable, "-c", program, str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process, ThreadPoolExecutor(max_workers=1) as reader:
        try:
            for message in messages:
                process.stdin.write(json.dumps(message).encode() + b"\n")
            process.stdin.flush()
            started = reader.submit(process.stderr.readline)
            assert started.result(timeout=20).rstrip(b"\r\n") == b"worker-started"
            process.stdout.close()
            process.stdin.close()
            assert process.wait(timeout=40) == 0
            assert process.stderr.read() == b""
        finally:
            if process.poll() is None:
                process.kill()

    verify_committed_scan(tmp_path)


def test_nonreading_client_can_block_response_after_worker_cleanup(tmp_path):
    (tmp_path / "fixture.py").write_text("pass\n", encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    program = """
import sys
from ai_threat_lab.agent_mcp import serve

class ObservedPipe:
    def write(self, data):
        if b'"id":2,' in data:
            print(len(data), file=sys.stderr, flush=True)
        return sys.stdout.buffer.write(data)

    def flush(self):
        sys.stdout.buffer.flush()

raise SystemExit(serve(sys.argv[1], output_stream=ObservedPipe()))
"""
    with subprocess.Popen(
        [sys.executable, "-c", program, str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "TEMP": str(scratch), "TMP": str(scratch), "TMPDIR": str(scratch)},
    ) as process, ThreadPoolExecutor(max_workers=1) as reader:
        try:
            request = b"".join(
                json.dumps(message, separators=(",", ":")).encode() + b"\n"
                for message in [INITIALIZE, INITIALIZED, SCAN, *(
                    {"jsonrpc": "2.0", "id": i, "method": "tools/list"} for i in range(3, 65)
                )]
            )
            process.stdin.write(request)
            process.stdin.close()
            size = int(reader.submit(process.stderr.readline).result(timeout=30))
            assert 0 < size < 4 * 32768
            verify_committed_scan(tmp_path)
            assert not list(scratch.iterdir())
            with pytest.raises(subprocess.TimeoutExpired):
                process.wait(timeout=0.5)
            process.kill()
            assert process.wait(timeout=10) != 0
            verify_committed_scan(tmp_path)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


@pytest.mark.skipif(sys.platform not in ("win32", "linux"), reason="Windows/Linux policy")
def test_abrupt_supervisor_exit_has_platform_specific_worker_lifetime(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    release = tmp_path / "release"
    completed = tmp_path / "completed"
    worker = """
import os
import sys
from pathlib import Path
from time import monotonic, sleep

sys.stdin.buffer.read()
Path(sys.argv[1], "owned").touch()
ready, release, completed = map(Path, sys.argv[2:])
ready.with_suffix(".pending").write_text(str(os.getpid()))
ready.with_suffix(".pending").replace(ready)
end = monotonic() + 12
while not release.exists() and monotonic() < end:
    sleep(0.02)
if release.exists():
    completed.touch()
"""
    supervisor = """
import sys
from ai_threat_lab import agent_protocol

start = agent_protocol.subprocess.Popen
def instrument(command, **kwargs):
    return start([command[0], "-c", sys.argv[1], command[-1], *sys.argv[2:]], **kwargs)
agent_protocol.subprocess.Popen = instrument
agent_protocol._run_worker(b"fixture")
"""
    ready = tmp_path / "ready"
    with subprocess.Popen(
        [sys.executable, "-c", supervisor, worker, str(ready), str(release), str(completed)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "TEMP": str(scratch), "TMP": str(scratch), "TMPDIR": str(scratch)},
    ) as process:
        try:
            wait_for_path(ready)
            leftover = list(scratch.glob("threat-agent-worker-*/owned"))
            assert len(leftover) == 1
            if sys.platform == "win32":
                assert_job_kills_worker(process, int(ready.read_text()))
            else:
                process.kill()
                process.wait(timeout=10)
                release.touch()
                wait_for_path(completed)
            assert leftover[0].is_file()
            assert not list(tmp_path.rglob("manifest.json"))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            release.touch()


def wait_for_path(path):
    from time import monotonic, sleep

    deadline = monotonic() + 10
    while not path.exists() and monotonic() < deadline:
        sleep(0.02)
    assert path.exists(), path


def assert_job_kills_worker(supervisor, pid):
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.OpenProcess(0x00100000, False, pid)
    assert handle
    try:
        assert kernel.WaitForSingleObject(handle, 0) == 258
        supervisor.kill()
        supervisor.wait(timeout=10)
        assert kernel.WaitForSingleObject(handle, 10000) == 0
    finally:
        kernel.CloseHandle(handle)
