"""Fixture-lab lifecycle over the same HTTP/WebSocket protocol agents use."""

import asyncio
import base64
import socket
from threading import Event, Thread
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
import uvicorn

from purplesploit.core.execution import ExecutionOutcome, ExecutionRequest, ExecutionResult, Observation
from purplesploit.core.findings import Finding
from purplesploit.distributed.agent import Agent, AgentConfig, AgentStatus
from purplesploit.distributed.api import create_distributed_router
from purplesploit.distributed.coordinator import Coordinator, CoordinatorConfig, ProtocolConflict
from purplesploit.distributed.transport import HTTPTransport, TransportConfig, WebSocketTransport


def result_for(task, **values):
    return ExecutionResult(request_id=task["request"]["request_id"], module_path=task["request"]["module_path"],
                           outcome=ExecutionOutcome.SUCCESS, success=True, **values)


def lease_for(task, agent_id="fixture"):
    return {"task_id": task["id"], "agent_id": agent_id, "lease_id": task["lease_id"]}


def queued(coordinator):
    return coordinator.submit(ExecutionRequest(module_path="fixture/echo", options={"target": "lab"}))


@pytest.fixture
def coordinator():
    return Coordinator(CoordinatorConfig(lease_seconds=2))


@pytest.fixture
def client(coordinator):
    app = FastAPI()
    app.include_router(create_distributed_router(coordinator))
    with TestClient(app) as client:
        yield client


@pytest.fixture
def live_server(coordinator):
    app = FastAPI()
    app.include_router(create_distributed_router(coordinator))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    thread = Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    for _ in range(500):
        if server.started:
            break
        Event().wait(.01)
    assert server.started
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive()


def test_http_full_contract(client, coordinator):
    health = client.get("/api/v1/health").json()
    assert health["protocol_version"] == 1
    assert health["delivery"] == "at_least_once"
    assert health["security_hardened"] is False
    assert client.post("/api/v1/agents/register", json={"agent_id": "fixture"}).status_code == 200
    request = ExecutionRequest(module_path="fixture/echo")
    submitted = client.post("/api/v1/tasks/submit", json={"request": request.to_dict()}).json()
    task = client.post("/api/v1/tasks/request", json={"agent_id": "fixture"}).json()["task"]
    assert submitted["id"] == task["id"]
    assert task["request"] == request.to_dict()
    heartbeat = client.post("/api/v1/agents/heartbeat", json={"agent_id": "fixture", "leases": [
        {"task_id": task["id"], "lease_id": task["lease_id"]}]}).json()
    assert heartbeat["renewed"] == [task["id"]]
    observation = Observation(kind="host", target="lab", source_execution_id=request.request_id)
    response = client.post("/api/v1/tasks/result", json={**lease_for(task),
        "result": result_for(task, observations=[observation]).to_dict()})
    assert response.status_code == 200
    assert response.json()["task"]["result"]["observations"] == [observation.to_dict()]
    assert client.get(f"/api/v1/tasks/{task['id']}").json()["status"] == "completed"
    assert len(client.get("/api/v1/tasks").json()) == 1
    assert client.get("/api/v1/agents").json()[0]["status"] == "online"


def test_lease_expiry_reassignment_and_stale_result():
    now = [100.0]
    coordinator = Coordinator(CoordinatorConfig(lease_seconds=5), clock=lambda: now[0])
    coordinator.register("a")
    coordinator.register("b")
    queued(coordinator)
    first = coordinator.claim("a")["task"]
    now[0] += 6
    second = coordinator.claim("b")["task"]
    assert second["id"] == first["id"]
    assert second["attempt"] == 2
    assert second["lease_id"] != first["lease_id"]
    with pytest.raises(ProtocolConflict):
        coordinator.result(**lease_for(first, "a"), result=result_for(first))
    assert coordinator.heartbeat("a", [{"task_id": first["id"], "lease_id": first["lease_id"]}])["lost"] == [first["id"]]
    assert coordinator.result(**lease_for(second, "b"), result=result_for(second))["success"]


def test_reconnect_preserves_unexpired_lease(coordinator):
    coordinator.register("fixture")
    queued(coordinator)
    task = coordinator.claim("fixture")["task"]
    coordinator.register("fixture")
    same = coordinator.claim("fixture")["task"]
    assert same["lease_id"] == task["lease_id"]
    assert same["attempt"] == 1
    assert coordinator.agents()[0]["registrations"] == 2


def test_offline_agent_and_heartbeat_renewal():
    now = [100.0]
    coordinator = Coordinator(CoordinatorConfig(lease_seconds=5, heartbeat_timeout=6), clock=lambda: now[0])
    coordinator.register("fixture")
    queued(coordinator)
    task = coordinator.claim("fixture")["task"]
    now[0] += 4
    coordinator.heartbeat("fixture", [{"task_id": task["id"], "lease_id": task["lease_id"]}])
    now[0] += 2
    assert coordinator.status(task["id"])["status"] == "running"
    now[0] += 5
    assert coordinator.agents()[0]["status"] == "offline"
    assert coordinator.status(task["id"])["status"] == "queued"


def test_capabilities_priority_and_idle(coordinator):
    coordinator.register("fixture", ["fixture/echo"])
    other = coordinator.submit(ExecutionRequest(module_path="other"), priority=4)
    low = coordinator.submit(ExecutionRequest(module_path="fixture/echo"), priority=1)
    high = coordinator.submit(ExecutionRequest(module_path="fixture/echo"), priority=3)
    assert coordinator.claim("fixture")["task"]["id"] == high["id"]
    assert coordinator.status(other["id"])["status"] == "queued"
    assert coordinator.status(low["id"])["status"] == "queued"
    coordinator.register("empty", ["missing"])
    assert coordinator.claim("empty")["task"] is None


def test_cancel_queued_and_running(client, coordinator):
    pending = queued(coordinator)
    assert client.post(f"/api/v1/tasks/{pending['id']}/cancel").json()["status"] == "cancelled"
    coordinator.register("fixture")
    queued(coordinator)
    task = coordinator.claim("fixture")["task"]
    assert coordinator.cancel(task["id"])["status"] == "cancelling"
    assert coordinator.heartbeat("fixture", [{"task_id": task["id"], "lease_id": task["lease_id"]}])["cancel"] == [task["id"]]
    result = ExecutionResult(request_id=task["request"]["request_id"], module_path="fixture/echo",
                             outcome=ExecutionOutcome.CANCELLED, cancelled=True)
    assert coordinator.result(**lease_for(task), result=result)["task"]["status"] == "cancelled"


def test_disconnected_cancel_is_explicitly_unconfirmed():
    now = [100.0]
    coordinator = Coordinator(CoordinatorConfig(lease_seconds=5), clock=lambda: now[0])
    coordinator.register("fixture")
    queued(coordinator)
    task = coordinator.claim("fixture")["task"]
    coordinator.cancel(task["id"])
    now[0] += 6
    status = coordinator.status(task["id"])
    assert status["status"] == "cancel_unconfirmed"
    assert status["result"] is None
    assert coordinator.claim("fixture")["task"] is None


def test_duplicate_result_and_identity(coordinator):
    calls = []
    coordinator.on_result = calls.append
    coordinator.register("fixture")
    queued(coordinator)
    task = coordinator.claim("fixture")["task"]
    result = result_for(task)
    wrong = ExecutionResult(request_id="wrong", module_path="fixture/echo")
    with pytest.raises(ProtocolConflict):
        coordinator.result(**lease_for(task), result=wrong)
    assert not coordinator.result(**lease_for(task), result=result)["duplicate"]
    assert coordinator.result(**lease_for(task), result=result)["duplicate"]
    assert len(calls) == 1
    result.error = "changed"
    with pytest.raises(ProtocolConflict):
        coordinator.result(**lease_for(task), result=result)


def test_running_result_is_not_recorded_as_completed(coordinator):
    coordinator.register("fixture")
    queued(coordinator)
    task = coordinator.claim("fixture")["task"]
    result = ExecutionResult(request_id=task["request"]["request_id"], module_path="fixture/echo",
                             outcome=ExecutionOutcome.RUNNING)
    with pytest.raises(ValueError, match="terminal"):
        coordinator.result(**lease_for(task), result=result)
    assert coordinator.status(task["id"])["result"] is None


@pytest.mark.parametrize("path,payload,status", [
    ("tasks/request", {"agent_id": "missing"}, 404),
    ("agents/register", {"protocol_version": 999, "data": {}}, 422),
    ("agents/register", {"type": "task_result", "data": {}}, 422),
    ("tasks/submit", {"request": {"module_path": "fixture", "timeout_s": -1}}, 422),
])
def test_protocol_errors(client, path, payload, status):
    assert client.post("/api/v1/" + path, json=payload).status_code == status
    assert client.get("/api/v1/tasks/missing").status_code == 404


def test_artifact_transfer(client, coordinator):
    coordinator.register("fixture")
    queued(coordinator)
    task = coordinator.claim("fixture")["task"]
    content = base64.b64encode(b"fixture output\x00").decode("ascii")
    response = client.post("/api/v1/artifacts/upload", json={**lease_for(task), "name": "output.bin", "content_base64": content})
    assert response.status_code == 200
    artifact_id = response.json()["artifact_id"]
    received = client.get(f"/api/v1/tasks/{task['id']}/artifacts/{artifact_id}").json()
    assert base64.b64decode(received["content_base64"]) == b"fixture output\x00"
    assert received["size"] == 15
    assert "content_base64" not in coordinator.status(task["id"])["artifacts"][0]
    assert client.post("/api/v1/artifacts/upload", json={**lease_for(task), "name": "bad", "content_base64": "!"}).status_code == 422


def test_finding_sync(client, coordinator):
    received = []
    coordinator.on_findings = received.extend
    coordinator.register("fixture")
    finding = Finding(title="Fixture finding", target="lab")
    response = client.post("/api/v1/findings/sync", json={"agent_id": "fixture", "findings": [finding.to_dict()]})
    assert response.json()["finding_ids"] == [finding.id]
    assert received[0]["title"] == "Fixture finding"
    assert client.get("/api/v1/distributed/findings").json()[0]["id"] == finding.id


def test_websocket_envelope(client):
    with client.websocket_connect("/ws/agent") as ws:
        ws.send_json({"id": "register-1", "protocol_version": 1, "type": "register", "data": {"agent_id": "fixture"}})
        response = ws.receive_json()
        assert response["id"] == "register-1"
        assert response["agent_id"] == "fixture"
        ws.send_json({"id": "bad", "protocol_version": 2, "type": "register", "data": {}})
        response = ws.receive_json()
        assert response["success"] is False
        assert response["status_code"] == 422
        ws.send_json([])
        assert ws.receive_json()["status_code"] == 422


@pytest.mark.parametrize("transport_class", [HTTPTransport, WebSocketTransport])
def test_real_agent_task_and_findings(live_server, coordinator, tmp_path, transport_class):
    observations = []
    coordinator.on_result = lambda result: observations.extend(result.observations)
    task = queued(coordinator)
    artifact = tmp_path / "output.txt"
    artifact.write_text("fixture output")
    executed = []

    def execute(request):
        assert isinstance(request, ExecutionRequest)
        executed.append(request.request_id)
        return ExecutionResult(request_id=request.request_id, module_path=request.module_path,
            success=True, outcome=ExecutionOutcome.SUCCESS, artifacts=[str(artifact)],
            observations=[Observation(kind="host", target="lab", source_execution_id=request.request_id)])

    transport = transport_class(TransportConfig(server_url=live_server))
    agent = Agent(transport, execute, AgentConfig(agent_id="fixture", heartbeat_interval=.01))
    try:
        response = agent.run_once()
        assert response["success"], response
        assert executed == [task["request"]["request_id"]]
        final = coordinator.status(task["id"])
        assert final["status"] == "completed"
        assert final["artifacts"][0]["size"] == 14
        assert observations[0].target == "lab"
        assert agent.sync_findings([Finding(title="Remote fixture", target="lab")])["success"]
        assert coordinator.findings()[0]["title"] == "Remote fixture"
        agent.disconnect()
        assert agent.run_once()["task"] is None
        assert coordinator.agents()[0]["registrations"] == 2
    finally:
        agent.disconnect()


def test_installed_websocket_header_api(monkeypatch):
    captured = {}

    async def connect(uri, *, additional_headers=None, **kwargs):
        assert asyncio.get_running_loop()
        captured.update(uri=uri, headers=additional_headers)
        return AsyncMock()

    monkeypatch.setattr("purplesploit.distributed.transport.websockets.connect", connect)
    transport = WebSocketTransport(TransportConfig(server_url="http://fixture", api_key="lab-token"))
    try:
        assert transport.connect()
        assert captured == {"uri": "ws://fixture/ws/agent", "headers": {"Authorization": "Bearer lab-token"}}
    finally:
        transport.disconnect()


def test_legacy_websocket_header_api(monkeypatch):
    captured = {}

    async def connect(uri, *, extra_headers=None, **kwargs):
        captured["headers"] = extra_headers
        return AsyncMock()

    monkeypatch.setattr("purplesploit.distributed.transport.websockets.connect", connect)
    transport = WebSocketTransport(TransportConfig(server_url="http://fixture", api_key="lab-token"))
    try:
        assert transport.connect()
        assert captured["headers"] == {"Authorization": "Bearer lab-token"}
    finally:
        transport.disconnect()


def test_agent_cancel_background_handle(live_server, coordinator):
    task = queued(coordinator)

    class Handle:
        def __init__(self, result):
            self.result = result

        def cancel(self):
            self.result.cancelled = True
            self.result.outcome = ExecutionOutcome.CANCELLED

        def status(self):
            return self.result

    def execute(request):
        result = ExecutionResult(request_id=request.request_id, module_path=request.module_path,
                                 outcome=ExecutionOutcome.RUNNING)
        result._handle = Handle(result)
        coordinator.cancel(task["id"])
        return result

    agent = Agent(HTTPTransport(TransportConfig(server_url=live_server)), execute,
                  AgentConfig(agent_id="fixture", heartbeat_interval=.01))
    try:
        assert agent.run_once()["success"]
        assert coordinator.status(task["id"])["status"] == "cancelled"
        assert agent.status == AgentStatus.IDLE
    finally:
        agent.disconnect()


def test_agent_completion_replayed_after_lost_response(live_server, coordinator):
    task = queued(coordinator)
    calls = []

    def execute(request):
        calls.append(request.request_id)
        return result_for(task)

    transport = HTTPTransport(TransportConfig(server_url=live_server))
    original_send = transport.send
    first = [True]

    def send(kind, data):
        response = original_send(kind, data)
        if kind == "task_result" and first[0]:
            first[0] = False
            return {"success": False, "error": "Fixture response lost after coordinator accepted result"}
        return response

    transport.send = send
    agent = Agent(transport, execute, AgentConfig(agent_id="fixture"))
    try:
        assert not agent.run_once()["success"]
        assert agent.pending_result is not None
        response = agent.run_once()
        assert response["success"] and response["duplicate"]
        assert calls == [task["request"]["request_id"]]
        assert agent.pending_result is None
    finally:
        agent.disconnect()


def test_synchronous_completion_wins_cancel_race(live_server, coordinator):
    task = queued(coordinator)

    def execute(request):
        coordinator.cancel(task["id"])
        return result_for(task)

    agent = Agent(HTTPTransport(TransportConfig(server_url=live_server)), execute,
                  AgentConfig(agent_id="fixture", heartbeat_interval=.01))
    try:
        assert agent.run_once()["success"]
        final = coordinator.status(task["id"])
        assert final["status"] == "completed"
        assert final["cancel_requested"]
        assert not final["result"]["cancelled"]
    finally:
        agent.disconnect()


def test_expired_artifact_attempt_stops_agent(live_server, coordinator, tmp_path):
    task = queued(coordinator)
    artifact = tmp_path / "output.txt"
    artifact.write_text("fixture")

    def execute(request):
        # Expiry is forced only in this fixture to exercise the completion path.
        coordinator._tasks[task["id"]]["lease_expires_at"] = 0
        return result_for(task, artifacts=[str(artifact)])

    agent = Agent(HTTPTransport(TransportConfig(server_url=live_server)), execute,
                  AgentConfig(agent_id="fixture", heartbeat_interval=.01))
    try:
        response = agent.run_once()
        assert response["success"] is False
        assert response["status_code"] == 409
        assert agent.status == AgentStatus.LEASE_LOST
        assert agent.pending_result is not None
    finally:
        agent.disconnect()
