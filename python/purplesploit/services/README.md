# Shared application services

`PurpleSploitServices(framework, storage_path=...)` owns the assessment,
workflow, canonical finding, graph, import, reporting, and job services used by
the `/api/v1` adapter. `create_app(services)` creates an injectable FastAPI app;
the existing server includes the same router with its existing framework.
The existing browser remains the single browser backend.

`GET /api/v1/capabilities` generates the module/operation capability manifest
from each installed module's `get_operation_manifest()`. Optional importers are
discovered from importable offline adapter functions. Unavailable modules are
marked unavailable with their initialization error. Executable handler objects
are omitted. `GET /api/v1/capabilities/reference` generates the matching Markdown
reference; `/api/v1/parity` returns the service/API inventory. These are runtime
views, so a plugin or module change does not require regenerating a checked-in
catalog.

Workflow, AutoEnum, and spray endpoints return HTTP 202 and a stable job ID.
Acceptance means a job was scheduled, not that its work succeeded. Poll
`GET /api/v1/jobs/{id}` for status, timestamps, progress, actual outcome, error,
and terminal result. `/jobs/{id}/result` returns 409 while work remains pending.
`/jobs/{id}/events?after=N` returns ordered snapshots after revision N.
`/jobs/{id}/stream?after=N` provides the same finite event replay as SSE;
reconnect with the last received revision to fetch subsequent events. It does
not hold a connection open or invent a second progress source.

`POST /jobs/{id}/pause`, `/resume`, and `/stop` operate cooperatively. `pausing`
and `stopping` mean a request is pending; `paused` means the runner reached a
safe checkpoint. The facade delegates execution through a framework proxy
that checks controls before each launch, with domain progress callbacks at
completed-step boundaries. Running external tools finish their current call;
the job API does not claim to pause or terminate an active subprocess. Resume
continues the same runner. A stopped workflow retains its completed step
checkpoints in a paused workflow; it can be submitted again to continue pending
work. Background execution handles are awaited before reporting completion.
Pending work returned without a handle is an error.

Jobs and their event journals are in process memory. A restarted process does
not recover their IDs: an absent ID returns 404/unknown, never success. A known
lost runner can be marked interrupted with outcome unknown. Assessment,
workflow, and finding records retain their existing persistence contracts.
There are no persisted authorization budgets in this layer.

JSON browser view models are available under `/views/{view}` for `topology`,
`identity-relationships`, `attack-paths`, `coverage`, `findings-retest`, and
`data-quality`. The latter includes evidence references, source checks, importer
results, and graph provenance. Coverage requires an `engagement_id`; findings
and data quality may optionally be scoped to an engagement. Graph observations
from direct executions, job executions, and offline imports feed the same graph.

Report data uses canonical findings. `POST /reports` generates a report under
the application's reports directory using the existing report generator;
optional renderer dependencies are required for their respective formats.
The facade does not implement authentication, CSRF, or a separate rate policy;
the hosting server retains its existing middleware.
