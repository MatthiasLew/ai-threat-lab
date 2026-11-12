# Proposed asynchronous MCP lifecycle

The current server negotiates MCP `2025-06-18` over STDIO. Keep the nine synchronous
tools available. Evaluate negotiated Tasks support in each client before enabling
asynchronous calls. The 2026-07-28 protocol moved Tasks to an extension and changed
initialization, so implementation requires a versioned compatibility design.
[Protocol release](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
[Tasks extension draft](https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks)

Proposed acceptance cases:

1. Starting a job returns an opaque identifier bound to the initiating authorized root.
2. The worker policy rejects excess work with a stable busy response.
3. Status transitions proceed from queued to running and then to one terminal state.
4. A cancellation acknowledgement precedes a confirmed terminal state. Publication
   that already began may complete and return a committed bundle.
5. Results are delivered only to the authorized client context. Reconnection requires
   explicit identity binding and a retention policy.
6. Terminal cleanup removes worker scratch while retaining committed reports.
7. Legacy status continues to verify committed reports and retains its existing schema.

Client feature probing and executable contract tests remain part of implementation.
