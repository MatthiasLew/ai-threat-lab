"""Measure actual serialized evidence bytes; no model/tokenizer/network is required."""

import json
import tempfile
from pathlib import Path

from ai_threat_lab.agent_mcp import tool_list
from ai_threat_lab.agent_service import AgentService
from ai_threat_lab.gui_api import get_audit_results


def wire_size(value):
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")


def benchmark():
    with tempfile.TemporaryDirectory(prefix="agent-benchmark-") as folder:
        root = Path(folder)
        project = root / "project"
        project.mkdir()
        (project / "example.py").write_text("eval(input())\n" * 30, encoding="utf-8")
        service = AgentService(root)
        root = service.root
        scan = service.call("scan", {"target": "project"})
        run = scan["run"]
        full = get_audit_results(root / run)
        summary = service.call("summary", {"run": run})
        selected, references, notices = [summary], [], []
        for operation in ("findings", "limitations"):
            offset = 0
            while True:
                page = service.call(operation, {"run": run, "limit": 20, "offset": offset})
                selected.append(page)
                (references if operation == "findings" else notices).extend(page[operation])
                if not page["has_more"]:
                    break
                offset += 20
        selected.append(service.call("finding", {"run": run, "id": references[0]["id"]}))
        before = {
            (r["id"], r["check"], r["status"], r["triage_priority"])
            for r in full["report"]["findings"]
        }
        after = {(r["id"], r["rule_id"], r["confirmation"], r["priority"]) for r in references}
        original_notices = [
            r["notice"].replace(str(root), "[root]") for r in full["report"]["not_checked"]
        ]
        assert before == after
        assert original_notices == [r["notice"] for r in notices]
        assert not any(r["truncated"] for r in notices + references)
        assert summary["summary"]["findings"] == len(before)
        assert full["failed_components"] == summary["coverage"]["failed_modules"]
        sizes = {
            "raw_report_json": wire_size(full["report"]),
            "existing_api_full_results": wire_size(full),
            "agent_summary": wire_size(summary),
            "selective_all_references_one_detail": sum(map(wire_size, selected)),
            "mcp_discovery_once": wire_size({"tools": tool_list()}),
        }
        return {
            "schema_version": 1,
            "fixture": "30 inert eval AST candidates",
            "bytes": sizes,
            "decision_parity": {
                "all_references_rules_status_priorities": True,
                "all_limitations": True,
                "failure_counts": True,
            },
            "tokens": {"method": "not_measured", "reason": "No tokenizer dependency"},
            "notice": "Serialized UTF-8 payload bytes including newline. Summary alone does "
            "not contain all findings. Selective view includes every reference and limitation "
            "but only one expanded detail. MCP framing/discovery and request bytes are separate. "
            "Synthetic fixture results are not a universal savings claim.",
        }


if __name__ == "__main__":
    print(json.dumps(benchmark(), ensure_ascii=False, indent=2))
