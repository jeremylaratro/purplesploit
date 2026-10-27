"""S22 application and WebSocket security regression tests."""

import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from purplesploit.core.framework import Framework
from purplesploit.services import PurpleSploitServices
from purplesploit.services.api import create_app
from purplesploit.services.security import (
    ApplicationSecurity,
    SecurityAuditLog,
    SecurityConfig,
    TokenAuthority,
)


@pytest.fixture
def secured(tmp_path):
    framework = Framework(
        db_path=str(tmp_path / "framework.db"),
        plugins_dir=tmp_path / "plugins",
        plugin_config_dir=tmp_path / "plugin-state",
    )
    framework.discover_modules()
    services = PurpleSploitServices(framework, tmp_path / "application")
    authority = TokenAuthority("initial-api-token-value")
    security = ApplicationSecurity(
        SecurityConfig(secure_cookies=False, rate_requests=50),
        authority,
        audit=SecurityAuditLog(tmp_path / "security.jsonl", services.redactor),
    )
    with TestClient(create_app(services, security)) as client:
        yield client, security, tmp_path / "security.jsonl"
    framework.cleanup()


def test_authentication_csrf_origin_headers_and_redacted_audit(secured):
    client, _, audit_path = secured
    assert client.get("/api/v1/modules").status_code == 401
    bearer = {"Authorization": "Bearer initial-api-token-value"}
    response = client.get("/api/v1/modules", headers=bearer)
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"

    session = client.post("/api/v1/auth/session", headers=bearer)
    assert session.status_code == 200
    csrf = session.json()["csrf_token"]
    rejected = client.post("/api/v1/workflows", json={"name": "blocked"})
    assert rejected.status_code == 403
    accepted = client.post(
        "/api/v1/workflows",
        json={"name": "allowed", "steps": []},
        headers={"x-csrf-token": csrf, "origin": "http://localhost"},
    )
    assert accepted.status_code == 201
    assert client.get(
        "/api/v1/modules", headers={**bearer, "origin": "https://evil.invalid"}
    ).status_code == 403

    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert any(item["event"] == "http_rejected" for item in records)
    assert "initial-api-token-value" not in audit_path.read_text()


def test_rotation_grace_and_websocket_header_only_authentication(secured):
    client, security, _ = secured
    bearer = {"Authorization": "Bearer initial-api-token-value"}
    rotated = client.post(
        "/api/v1/auth/rotate",
        headers=bearer,
        json={"new_token": "replacement-api-token-value"},
    )
    assert rotated.status_code == 200
    assert security.authority.authenticate_api_token("initial-api-token-value")
    assert security.authority.authenticate_api_token("replacement-api-token-value")

    agent = security.authority.issue_session("fixture-agent", 30, kind="agent")
    with client.websocket_connect(
        "/ws/agent", headers={"Authorization": f"Bearer {agent['token']}"}
    ):
        pass
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/agent?token=leaky"):
            pass
    assert exc.value.code == 1008


def test_rate_limit_is_fail_closed(tmp_path):
    framework = Framework(
        db_path=str(tmp_path / "framework.db"),
        plugins_dir=tmp_path / "plugins",
        plugin_config_dir=tmp_path / "state",
    )
    services = PurpleSploitServices(framework, tmp_path / "application")
    security = ApplicationSecurity(
        SecurityConfig(secure_cookies=False, rate_requests=1),
        TokenAuthority("initial-api-token-value"),
        audit=SecurityAuditLog(tmp_path / "audit.jsonl"),
    )
    headers = {"Authorization": "Bearer initial-api-token-value"}
    with TestClient(create_app(services, security)) as client:
        assert client.get("/api/v1/modules", headers=headers).status_code == 200
        assert client.get("/api/v1/modules", headers=headers).status_code == 429
    framework.cleanup()
