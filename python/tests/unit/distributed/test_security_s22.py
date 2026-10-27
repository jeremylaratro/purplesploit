"""S22 distributed mutual-message auth, scope, replay, and artifact integrity."""

import base64
from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from purplesploit.core.execution import ExecutionRequest
from purplesploit.distributed.api import create_distributed_router
from purplesploit.distributed.coordinator import Coordinator
from purplesploit.distributed.security import AgentMessageAuthenticator


def _envelope(auth, kind, data, *, message_id=None):
    value = {
        "protocol_version": 1,
        "id": message_id or str(uuid4()),
        "type": kind,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    value["signature"] = auth.signature("fixture-shared-secret", value)
    return value


def test_signed_agent_scope_replay_and_artifact_digest():
    auth = AgentMessageAuthenticator({
        "fixture": {"secret": "fixture-shared-secret", "capabilities": ["fixture/echo"]}
    })
    coordinator = Coordinator(authenticator=auth)
    app = FastAPI()
    app.include_router(create_distributed_router(coordinator, message_auth=auth))
    with TestClient(app) as client:
        registration = _envelope(
            auth, "register", {"agent_id": "fixture", "capabilities": ["fixture/echo"]}
        )
        assert client.post("/api/v1/agents/register", json=registration).status_code == 200
        assert client.post("/api/v1/agents/register", json=registration).status_code == 401

        coordinator.submit(ExecutionRequest(module_path="fixture/echo"))
        claim = client.post(
            "/api/v1/tasks/request",
            json=_envelope(auth, "task_request", {"agent_id": "fixture"}),
        ).json()["task"]
        content = b"verified evidence"
        upload = {
            "agent_id": "fixture",
            "task_id": claim["id"],
            "lease_id": claim["lease_id"],
            "name": "evidence.bin",
            "content_base64": base64.b64encode(content).decode(),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        response = client.post(
            "/api/v1/artifacts/upload", json=_envelope(auth, "artifact_upload", upload)
        )
        assert response.status_code == 200
        artifact = coordinator.artifact(claim["id"], response.json()["artifact_id"])
        assert artifact["sha256"] == hashlib.sha256(content).hexdigest()

        upload["sha256"] = "0" * 64
        assert client.post(
            "/api/v1/artifacts/upload", json=_envelope(auth, "artifact_upload", upload)
        ).status_code == 422


def test_unprovisioned_capability_and_unsigned_agent_are_rejected():
    auth = AgentMessageAuthenticator({
        "fixture": {"secret": "fixture-shared-secret", "capabilities": ["fixture/echo"]}
    })
    coordinator = Coordinator(authenticator=auth)
    app = FastAPI()
    app.include_router(create_distributed_router(coordinator, message_auth=auth))
    with TestClient(app) as client:
        excess = _envelope(
            auth, "register", {"agent_id": "fixture", "capabilities": ["other/module"]}
        )
        assert client.post("/api/v1/agents/register", json=excess).status_code == 401
        assert client.post(
            "/api/v1/agents/register", json={"agent_id": "fixture"}
        ).status_code == 401
        assert client.get("/api/v1/health").json()["security_hardened"] is True
