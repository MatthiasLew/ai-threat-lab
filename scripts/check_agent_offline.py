"""Installed-wheel acceptance: real agent CLI, stable saved refs, MCP and EOF."""

import json
import subprocess


def check_agent(run, executable, work, env):
    target = work / "agent fixture"
    target.mkdir()
    (target / "sample.py").write_text("eval(input())\n", encoding="utf-8")

    def call(*args):
        return json.loads(run(executable, "agent", *args, "--root", work))

    result = call("scan", "--target", target.name)
    assert result["summary"]["findings"] == 1
    reference = call("findings", "--run", result["run"])["findings"][0]["id"]
    assert call("finding", "--run", result["run"], "--id", reference)["finding"]["id"] == reference
    assert call("summary", "--run", result["run"])["state_id"] == result["state_id"]
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "installed-acceptance", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "security_summary", "arguments": {"run": result["run"]}},
        },
    ]
    # The installed executable is absolute; test in a directory containing spaces.
    completed = subprocess.run(
        [str(executable), "agent", "mcp", "serve", "--root", str(work)],
        input="".join(json.dumps(m) + "\n" for m in messages),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=60,
        cwd=work,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    assert [r["id"] for r in responses] == [1, 2, 3]
    assert len(responses[1]["result"]["tools"]) == 9
    assert responses[2]["result"]["structuredContent"]["run_id"] == result["run_id"]
