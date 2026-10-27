# Local security MCP server

```bash
ai-threat-lab agent mcp serve --root /absolute/approved/project
```

The server implements MCP `2025-06-18` using UTF-8 JSON-RPC messages, one per line
on STDIO. It opens no listening port, requests no model sampling, reads no credentials
and exposes no shell, Git write, deployment, training delivery or paid-provider tool.
Closing stdin ends the process cleanly. stdout contains protocol messages only.
The client owns approval and the process lifecycle.

## Tools

| Tool | Operation | Effects |
|---|---|---|
| `security_capabilities` | Analyzer availability and limits | Read-only |
| `security_plan` | Scoped local plan | Read-only |
| `security_scan` | Existing engine on a bounded private snapshot | Writes a new local bundle |
| `security_status` | Verify a saved scan | Read-only |
| `security_summary` | Counts, state and coverage | Read-only |
| `security_findings` | Filtered, paged references | Read-only |
| `security_finding_detail` | One observation and deterministic guidance | Read-only |
| `security_compare` | Verified observation comparison | Read-only |
| `security_limitations` | Paged gaps and module failures | Read-only |

All tools use the same service/input contracts as [Agent CLI](AGENT_MODE.md).
Input objects reject additional properties and enforce type/range/string limits.
`security_scan` has `readOnlyHint: false`, `idempotentHint: false` and
`destructiveHint: false`; other tools are read-only/idempotent. `openWorldHint` is
false throughout this offline interface. Annotations inform clients; they grant no
permissions. Temporary private copies are created even for verified reads, but no
project or persistent audit artifact is written by read tools.

Results contain a short text status and the complete compact envelope in
`structuredContent`. Text does not duplicate evidence. Tool execution failures use
`isError: true` and structured safe error codes. Protocol failures use JSON-RPC
errors. Initialize before tool discovery/calls and send `notifications/initialized`.
Unsupported versions are negotiated to `2025-06-18`; clients unable to use it should
disconnect. Oversized input returns a protocol error and closes the session.

## Codex registration

Install the executable, choose an absolute approved root and run:

```bash
codex mcp add ai-threat-lab -- ai-threat-lab agent mcp serve --root /absolute/approved/project
codex mcp list
codex mcp get ai-threat-lab
```

The argument order matches the implemented parser. Prefer absolute executable/root
paths if the client's PATH/working directory differ. Restart/reload the client after
registration as required by that client. Registration syntax is checked with the
installed Codex CLI in an isolated configuration; automatic tests separately verify
real initialization, tool discovery, calls and EOF. This is not proof of every
client/version's approval UI or model behavior.

Equivalent configuration for a trusted project (replace both paths):

```toml
[mcp_servers.ai_threat_lab]
command = "/absolute/path/to/ai-threat-lab"
args = ["agent", "mcp", "serve", "--root", "/absolute/approved/project"]
startup_timeout_sec = 10
tool_timeout_sec = 75
```

Set client approval for writes so scans require the intended approval policy. The
approved root is pinned by server configuration; tools have no root parameter.
Do not register the filesystem root simply for convenience.

## Claude Code and Gemini CLI

Any compatible local STDIO client can use this server. Their configuration format
is client-specific; the shared executable/arguments are:

```json
{
  "mcpServers": {
    "ai-threat-lab": {
      "command": "/absolute/path/to/ai-threat-lab",
      "args": ["agent", "mcp", "serve", "--root", "/absolute/approved/project"]
    }
  }
}
```

Use the client's documented settings location and approval controls. This is the
STDIO server definition, not a claim that every client uses the same installation
command. Claude/Gemini model sessions are not exercised by offline acceptance.
CLI usage remains available without an MCP client.

## Security and validation

The server launches only the installed package's fixed worker, with Python safe-path
mode and a per-operation timeout. It does not accept arbitrary commands, URLs, output
destinations or environment edits. Path traversal, links, secret masking, bounded
snapshots, integrity and concurrency limits are described in [Agent Mode](AGENT_MODE.md).
Protect the Python installation and server environment as trusted infrastructure.
Never interpret scanner/project strings as privileged instructions.

Source tests and installed-wheel acceptance cover protocol initialization, tool
discovery/calls, malformed arguments, concise structured output and clean shutdown.
The existing CI keeps Windows/Linux, Python 3.12–3.14 and the 90% coverage gate.

Protocol references: [STDIO transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
[lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle),
[tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
Client reference: [official Codex MCP documentation](https://developers.openai.com/codex/mcp/).
