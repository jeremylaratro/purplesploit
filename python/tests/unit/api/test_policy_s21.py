from datetime import datetime, timedelta, timezone
import subprocess

from fastapi.testclient import TestClient

from purplesploit.core.framework import Framework
from purplesploit.core.policy import PolicyEngine
from purplesploit.services import PurpleSploitServices
from purplesploit.services.api import create_app


def authorization(engagement_id, *, approval=False):
    now = datetime.now(timezone.utc)
    value = {
        "engagement_id": engagement_id,
        "authorized_by": "client@example.test",
        "authorization_reference": "SOW-1",
        "starts_at": (now - timedelta(minutes=5)).isoformat(),
        "ends_at": (now + timedelta(hours=1)).isoformat(),
        "scope": {"include": ["192.0.2.0/24"], "exclude": ["192.0.2.99"]},
        "allowed_risks": ["passive", "low", "medium"],
        "require_lockout_discovery": True,
    }
    if approval:
        value["approvals"] = [{
            "id": "APR-SPRAY", "risks": ["high"],
            "approved_by": "lead@example.test",
            "expires_at": (now + timedelta(minutes=30)).isoformat(),
            "module_patterns": ["automation/credential-spray"],
            "target_patterns": ["192.0.2.*"],
        }]
    return value


def test_strict_api_plans_and_dispatches_share_policy(tmp_path, monkeypatch):
    framework = Framework(
        db_path=str(tmp_path / "framework.db"), plugins_dir=tmp_path / "plugins",
        plugin_config_dir=tmp_path / "plugin-state",
    )
    framework.discover_modules()
    services = PurpleSploitServices(
        framework, tmp_path / "application", policy=PolicyEngine()
    )
    calls = []
    monkeypatch.setattr(
        subprocess, "run",
        lambda argv, **kwargs: calls.append(argv) or subprocess.CompletedProcess(argv, 0, "[-] invalid", ""),
    )
    with TestClient(create_app(services)) as client:
        engagement = client.post(
            "/api/v1/assessments", json={"name": "Authorized"}
        ).json()
        request = {
            "module_path": "network/nxc_rdp", "operation_name": "test-auth",
            "options": {"RHOST": "192.0.2.10"}, "engagement_id": engagement["id"],
        }
        assert client.post("/api/v1/executions", json=request).status_code == 403
        configured = client.put(
            f"/api/v1/authorizations/{engagement['id']}",
            json=authorization(engagement["id"]),
        )
        assert configured.status_code == 200, configured.text
        plan = client.post("/api/v1/executions/plan", json=request).json()
        assert plan["allowed"] and plan["decision"] == "authorized"
        assert client.post("/api/v1/executions", json=request).status_code == 200
        assert len(calls) == 1
        request["options"]["RHOST"] = "192.0.2.99"
        rejected = client.post("/api/v1/executions", json=request)
        assert rejected.status_code == 403 and len(calls) == 1


def test_spray_requires_lockout_discovery_approval_and_cross_run_budget(tmp_path):
    framework = Framework(
        db_path=str(tmp_path / "framework.db"), plugins_dir=tmp_path / "plugins",
        plugin_config_dir=tmp_path / "plugin-state",
    )
    services = PurpleSploitServices(
        framework, tmp_path / "application", policy=PolicyEngine()
    )
    engagement = services.engagement_create(name="Spray")
    services.authorization_set(
        engagement["id"], authorization(engagement["id"], approval=True)
    )
    values = {
        "targets": ["192.0.2.10"], "users": ["alice"], "passwords": ["fixture"],
        "protocol": "rdp", "engagement_id": engagement["id"], "approval_id": "APR-SPRAY",
    }
    try:
        services.run_spray(**values)
    except PermissionError as exc:
        assert getattr(exc, "code") == "lockout_policy_required"
    else:
        raise AssertionError("Missing lockout discovery was not rejected")
    job = services.run_spray(**values, lockout_policy_discovered=True)
    assert services.jobs.wait(job["id"], 4)["status"] in {"completed", "error"}
    assert services.spray_budget.usage(engagement["id"])["principals"]["alice"] == 1
