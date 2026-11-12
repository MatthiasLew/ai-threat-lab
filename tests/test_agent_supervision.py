"""Exercise real subprocess supervision using bounded, trusted test programs."""

import json
import sys
from pathlib import Path

import pytest

from ai_threat_lab import agent_protocol, agent_resources


@pytest.mark.parametrize(
    "mode", ["normal", "malformed", "bad_json", "oversized", "exit", "timeout"],
)
def test_supervisor_reaps_worker_and_cleans_scratch(tmp_path, monkeypatch, mode):
    original = agent_protocol.subprocess.Popen
    processes = []
    normal = json.dumps({
        "tool": "ai-threat-lab", "schema_version": "1.0", "operation": "doctor", "status": "ok",
    })
    responses = {
        "normal": f"print({normal!r})",
        "malformed": "print('{}')",
        "bad_json": "print('{')",
        "oversized": f"print('x' * {agent_protocol.MAX_RESPONSE + 1})",
        "exit": "raise SystemExit(4)",
        "timeout": "import time; time.sleep(30)",
    }

    def start(command, **kwargs):
        scratch = command[-1]
        program = (
            "import sys; from pathlib import Path; sys.stdin.buffer.read(); "
            "Path(sys.argv[1], 'owned-scratch').touch(); " + responses[mode]
        )
        process = original([sys.executable, "-c", program, scratch], **kwargs)
        processes.append((process, scratch))
        return process

    monkeypatch.setattr(agent_protocol.subprocess, "Popen", start)
    monkeypatch.setattr(agent_protocol, "TIMEOUT", 2 if mode == "timeout" else 15)
    result = agent_protocol.execute(tmp_path, "doctor", {})
    if mode == "normal":
        assert result["status"] == "ok"
    else:
        assert result["error"]["code"] == ("timeout" if mode == "timeout" else "worker_error")
    process, scratch = processes[0]
    assert process.poll() is not None
    assert not Path(scratch).exists()


@pytest.mark.skipif(sys.platform not in ("linux", "win32"), reason="Native memory policy")
def test_native_memory_ceiling(tmp_path, monkeypatch):
    original = agent_protocol.subprocess.Popen
    ceiling = 64 * 1024 * 1024
    monkeypatch.setattr(agent_resources, "MEMORY_BYTES", ceiling)
    reply = json.dumps({
        "tool": "ai-threat-lab", "schema_version": "1.0", "operation": "doctor", "status": "ok",
    })
    code = f"""
import sys
from ai_threat_lab import agent_resources
sys.stdin.buffer.read()
agent_resources.MEMORY_BYTES = {ceiling}
agent_resources.apply_worker_limits()
try:
    bytearray({ceiling + 1})
except MemoryError:
    print({reply!r})
else:
    raise SystemExit(3)
"""

    def start(_command, **kwargs):
        return original([sys.executable, "-P", "-c", code], **kwargs)

    monkeypatch.setattr(agent_protocol.subprocess, "Popen", start)
    assert agent_protocol.execute(tmp_path, "doctor", {})["status"] == "ok"
