"""Check the synchronous server using actual OS pipes."""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest


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
    messages = [
        {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {}},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "security_scan", "arguments": {"target": "fixture.py"}},
        },
    ]
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

    from ai_threat_lab.scan_bundle import read_bundle

    manifests = list((tmp_path / ".ai-threat-lab").rglob("manifest.json"))
    assert len(manifests) == 1
    read_bundle(manifests[0].parent)
