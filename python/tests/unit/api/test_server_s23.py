"""S23 production entry-point, readiness, version, and support-bundle tests."""

import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from purplesploit import __version__
from purplesploit.services.server import build_application


def test_production_entrypoint_is_fail_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("PURPLESPLOIT_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="API_TOKEN"):
        build_application(data_dir=tmp_path)
    with pytest.raises(RuntimeError, match="16"):
        build_application(api_token="short", data_dir=tmp_path)


def test_readiness_authentication_strict_controls_and_support_bundle(tmp_path):
    app = build_application(
        api_token="production-fixture-token",
        data_dir=tmp_path,
        agent_records={},
    )
    headers = {"Authorization": "Bearer production-fixture-token"}
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        readiness = client.get("/readyz").json()
        assert readiness["policy_enforced"] is True
        assert readiness["agent_authentication"] is True
        assert client.get("/api/v1/modules").status_code == 401
        assert client.get("/api/v1/modules", headers=headers).status_code == 200
        response = client.post("/api/v1/support-bundles", headers=headers)
        assert response.status_code == 201
        bundle = response.json()
        assert bundle["redacted"]
        path = __import__("pathlib").Path(bundle["path"])
        assert path.stat().st_mode & 0o777 == 0o600
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            diagnostics = json.loads(archive.read("diagnostics.json"))
        assert names == {"diagnostics.json", "README.txt"}
        assert diagnostics["purplesploit_version"] == __version__ == "7.0.0"
        assert "targets" not in json.dumps(diagnostics).lower()

    assert app.state.services.framework.plugin_manager.strict_security is True
