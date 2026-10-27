"""HTTP and WebSocket adapters for the fixture-lab distributed protocol."""

from fastapi import APIRouter, Body, HTTPException, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from purplesploit.distributed.coordinator import PROTOCOL_VERSION, ProtocolConflict


def create_distributed_router(coordinator, websocket_auth=None, message_auth=None):
    router = APIRouter(tags=["distributed lab protocol v1"])

    def dispatch(kind, envelope):
        try:
            if not isinstance(envelope, dict):
                raise ValueError("Distributed message must be an object")
            if envelope.get("protocol_version", PROTOCOL_VERSION) != PROTOCOL_VERSION:
                raise ValueError("Unsupported distributed protocol_version")
            if "type" in envelope and envelope["type"] != kind:
                raise ValueError("Envelope type does not match endpoint")
            if message_auth is not None and kind in {
                "register", "heartbeat", "task_request", "task_result",
                "findings_sync", "artifact_upload",
            }:
                message_auth.verify(envelope, kind)
            return coordinator.dispatch(kind, envelope.get("data", envelope))
        except ProtocolConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(401, str(exc)) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/api/v1/health")
    def health():
        return coordinator.health()

    # Keep these explicit so OpenAPI names and paths are stable.
    def endpoint(kind):
        def call(envelope: dict = Body(...)):
            return dispatch(kind, envelope)
        return call

    for path, kind in (("agents/register", "register"), ("agents/heartbeat", "heartbeat"),
                       ("tasks/submit", "task_submit"), ("tasks/request", "task_request"),
                       ("tasks/result", "task_result"), ("findings/sync", "findings_sync"),
                       ("artifacts/upload", "artifact_upload")):
        router.add_api_route("/api/v1/" + path, endpoint(kind), methods=["POST"], name="distributed_" + kind)

    @router.get("/api/v1/agents")
    def agents():
        return coordinator.agents()

    @router.get("/api/v1/tasks")
    def tasks():
        return coordinator.status()

    @router.get("/api/v1/tasks/{task_id}")
    def task(task_id: str):
        return dispatch("task_status", {"task_id": task_id})

    @router.post("/api/v1/tasks/{task_id}/cancel")
    def cancel(task_id: str):
        return dispatch("task_cancel", {"task_id": task_id})

    @router.get("/api/v1/tasks/{task_id}/artifacts/{artifact_id}")
    def artifact(task_id: str, artifact_id: str):
        try:
            return coordinator.artifact(task_id, artifact_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @router.get("/api/v1/distributed/findings")
    def findings():
        return coordinator.findings()

    @router.websocket("/ws/agent")
    async def websocket(websocket: WebSocket):
        if websocket_auth is not None:
            identity = await websocket_auth(websocket, kind="agent")
            if identity is None:
                return
        await websocket.accept()
        try:
            while True:
                envelope = await websocket.receive_json()
                try:
                    kind = envelope.get("type") if isinstance(envelope, dict) else None
                    result = await run_in_threadpool(dispatch, kind, envelope)
                    # Status responses are task objects, not success envelopes.
                    response = {"success": True, **(result if isinstance(result, dict) else {"tasks": result})}
                except HTTPException as exc:
                    response = {"success": False, "status_code": exc.status_code, "error": exc.detail}
                message_id = envelope.get("id") if isinstance(envelope, dict) else None
                await websocket.send_json({"id": message_id, "protocol_version": PROTOCOL_VERSION, **response})
        except WebSocketDisconnect:
            pass

    return router
