# Distributed fixture-lab protocol (version 1)

The coordinator stores state in memory and supports a single active execution per
agent. It is intended for controlled capability demonstrations. Authorization,
agent trust, mutual authentication, replay hardening, durable recovery, remote
execution policy, and production guarantees are deferred to S19–S23.

Include `create_distributed_router(Coordinator(...))` in a FastAPI application.
The existing application server includes this router and exposes its coordinator
as `app.state.coordinator`.

| HTTP | Path | Payload / result |
| --- | --- | --- |
| GET | `/api/v1/health` | Protocol version and explicit runtime semantics |
| POST | `/api/v1/agents/register` | `agent_id` (optional), `capabilities` (module paths) |
| GET | `/api/v1/agents` | Online/offline state and last heartbeat |
| POST | `/api/v1/agents/heartbeat` | `agent_id`, `leases: [{task_id, lease_id}]`; returns `renewed`, `lost`, `cancel` |
| POST | `/api/v1/tasks/submit` | `request: ExecutionRequest.to_dict()`, optional `priority` (1–4), `name` |
| POST | `/api/v1/tasks/request` | `agent_id`; returns `task` or null |
| POST | `/api/v1/tasks/result` | `task_id`, `agent_id`, `lease_id`, `result: ExecutionResult.to_dict()` |
| GET | `/api/v1/tasks` | All tasks with request, status, attempts, result, artifact metadata |
| GET | `/api/v1/tasks/{task_id}` | One task, or 404 |
| POST | `/api/v1/tasks/{task_id}/cancel` | Request cooperative cancellation |
| POST | `/api/v1/artifacts/upload` | `task_id`, `agent_id`, `lease_id`, `name`, `content_base64` |
| GET | `/api/v1/tasks/{task_id}/artifacts/{artifact_id}` | Artifact metadata and base64 content |
| POST | `/api/v1/findings/sync` | `agent_id`, `findings: [Finding.to_dict()]` |
| GET | `/api/v1/distributed/findings` | Findings received by this coordinator |

POST endpoints accept either the raw payload or an envelope with
`protocol_version: 1`, `type`, and `data`. Transport envelopes use message types
`register`, `heartbeat`, `task_submit`, `task_request`, `task_result`,
`artifact_upload`, and `findings_sync`. Unsupported versions return 422; missing
records return 404; stale leases and conflicting results return 409.

`/ws/agent` accepts the same envelopes plus an `id`, and echoes the `id` in its
response. `task_status` and `task_cancel` messages accept `task_id`. Agents poll;
there is no unsolicited WebSocket task or cancellation push. Both HTTP and
WebSocket agents use the same state machine. Header arguments are selected from
the installed `websockets.connect` signature, including modern versions that
require constructing the connection inside a running event loop.

## Running an agent

From a separate Python process with the same module installation:

```python
from purplesploit.core.framework import Framework
from purplesploit.distributed import Agent, AgentConfig, HTTPTransport, TransportConfig

framework = Framework(db_path="/tmp/purplesploit-lab-agent.db")
framework.discover_modules()
agent = Agent(
    HTTPTransport(TransportConfig(server_url="http://127.0.0.1:8000")),
    framework.execute_request,
    AgentConfig(agent_id="lab-agent", capabilities=list(framework.modules)),
)
try:
    agent.run()  # run_once() runs at most one task for a bounded demonstration
finally:
    agent.disconnect()
```

Use a stable `agent_id` across connection retries. Re-registering an agent returns
its active, unexpired lease when it next requests a task. Heartbeats renew the
specific task/lease pair. Expired leases return tasks to the queue, so a remote
process may still be executing an earlier attempt: delivery is at least once,
with no exactly-once claim. A result from the expired attempt is rejected. The
agent retains its unaccepted completion for inspection and stops its polling
loop after a lost lease. The process must recover that result or deliberately
discard it before claiming more work.

An accepted terminal result can be retried with the same lease and identical
payload; the result callback runs once in that coordinator process. This does
not make execution, artifacts, callbacks across failures, or finding delivery
exactly once. Artifact uploads can be repeated if a response is lost; all payloads
are buffered in memory. Agent filesystem artifact paths remain recorded in the
canonical result; separately transferred artifact IDs and metadata appear on the
task. Missing files cannot be transferred. I/O errors are recorded under
`result.raw_result.artifact_transfer_errors`.

Queued cancellation is immediate. Active cancellation appears as `cancelling`
until the agent returns a terminal result. The agent can cancel local background
`ExecutionHandle`s. Synchronous handlers must return before cancellation can be
acknowledged; a completed result can therefore win a cancellation race. If a
cancelled agent's lease expires, the coordinator exposes `cancel_unconfirmed`
and does not reassign that task. This is not proof that its remote process exited.

Coordinator result callbacks receive canonical `ExecutionResult` instances;
finding callbacks receive serialized canonical `Finding` records. They connect
remote observations and finding sync to the same application services as local
execution. Coordinator and agent process restarts do not preserve queue, lease,
artifact, or pending-result state.

The regression fixture `tests/unit/distributed/test_protocol.py` exercises a real
loopback HTTP and WebSocket agent, canonical execution/results/observations,
finding sync, artifact transfer, heartbeat, reconnect, result retry, stale leases,
and cooperative cancellation. Run it alongside the task and transport suites.
