"""Application/API parity using the real framework and external-process fakes."""

import json
import subprocess
from threading import Event

import pytest
from fastapi.testclient import TestClient

from purplesploit.core.framework import Framework
from purplesploit.services import PurpleSploitServices
from purplesploit.services.api import create_app


@pytest.fixture
def services(tmp_path):
    framework = Framework(
        db_path=str(tmp_path / "framework.db"),
        plugins_dir=tmp_path / "plugins",
        plugin_config_dir=tmp_path / "plugin-state",
    )
    framework.discover_modules()
    service = PurpleSploitServices(framework, tmp_path / "application")
    yield service
    framework.cleanup()


@pytest.fixture
def client(services):
    with TestClient(create_app(services)) as client:
        yield client


def test_manifest_runtime_operations_and_parity(services, client):
    response = client.get("/api/v1/capabilities")
    assert response.status_code == 200
    manifest = response.json()
    module = next(item for item in manifest["modules"] if item["path"] == "network/nxc_rdp")
    assert module["operations"] == services.operations("network/nxc_rdp")
    assert any(operation["id"] == "test-auth" for operation in module["operations"])
    assert all("handler" not in operation for operation in module["operations"])
    routes = {(method.upper(), path) for path, operations in client.app.openapi()["paths"].items()
              for method in operations}
    for item in manifest["parity"]:
        assert callable(getattr(services, item["service"]))
        assert (item["method"], item["path"]) in routes
    assert {(item["method"], item["path"]) for item in manifest["parity"]} == routes
    assert client.get("/api/v1/modules").json() == services.modules()
    assert client.get("/api/v1/operations", params={"module_path": "network/nxc_rdp"}).json() == module["operations"]
    assert "test-auth" in client.get("/api/v1/capabilities/reference").text
    assert client.get("/api/v1/operations", params={"module_path": "missing"}).status_code == 404


def test_execution_uses_real_framework_and_records_assessment(services, client, monkeypatch):
    calls = []

    def external(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "[+] authenticated", "")

    monkeypatch.setattr(subprocess, "run", external)
    engagement = client.post("/api/v1/assessments", json={"name": "API parity", "targets": ["192.0.2.7"]}).json()
    result = client.post("/api/v1/executions", json={"module_path": "network/nxc_rdp", "operation_name": "test-auth",
                                                   "options": {"RHOST": "192.0.2.7"}, "engagement_id": engagement["id"]}).json()
    assert result["success"] and result["outcome"] == "success" and calls
    assessment = client.get(f"/api/v1/assessments/{engagement['id']}").json()
    assert assessment["executions"][0]["request_id"] == result["request_id"]
    assert client.get("/api/v1/assessments").json() == services.engagement_list()


def test_workflow_job_pause_resume_and_result_polling(services, client, monkeypatch):
    entered, release = Event(), Event()
    calls = []

    def external(argv, **kwargs):
        calls.append(argv)
        if len(calls) == 1:
            entered.set()
            assert release.wait(4)
        return subprocess.CompletedProcess(argv, 0, "[+] authenticated", "")

    monkeypatch.setattr(subprocess, "run", external)
    workflow = client.post("/api/v1/workflows", json={"name": "real workflow", "steps": [
        {"id": f"step_{number}", "name": f"step {number}", "module": "network/nxc_rdp",
         "operation": "test-auth", "options": {"RHOST": "192.0.2.8"}} for number in (1, 2)]}).json()
    job = client.post(f"/api/v1/workflows/{workflow['id']}/run", json={}).json()
    assert entered.wait(4)
    assert client.get(f"/api/v1/jobs/{job['id']}/result").status_code == 409
    assert client.post(f"/api/v1/jobs/{job['id']}/pause").json()["status"] == "pausing"
    release.set()
    with services.jobs._condition:
        assert services.jobs._condition.wait_for(lambda: services.jobs.get(job["id"])["status"] == "paused", timeout=4)
    assert len(calls) == 1
    assert client.post(f"/api/v1/jobs/{job['id']}/resume").status_code == 200
    result = services.jobs.wait(job["id"], 4)
    assert result["status"] == "completed" and len(calls) == 2
    assert result["result"]["steps_completed"] == 2
    assert client.get(f"/api/v1/jobs/{job['id']}/result").json()["result"] == result["result"]
    events = client.get(f"/api/v1/jobs/{job['id']}/events").json()
    assert events == services.job_events(job["id"])
    stream = client.get(f"/api/v1/jobs/{job['id']}/stream").text
    assert "event: progress" in stream
    assert client.get("/api/v1/jobs/lost-on-restart").status_code == 404


def test_real_auto_enum_and_spray_job_outcomes(services, client, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, "[-] invalid credentials", ""))
    auto = client.post("/api/v1/auto-enum", json={"targets": [], "skip_discovery": True}).json()
    assert services.jobs.wait(auto["id"], 4)["status"] == "completed"
    spray = client.post("/api/v1/sprays", json={"targets": ["192.0.2.8"], "users": ["example"],
                                              "passwords": ["example"], "protocol": "rdp"}).json()
    spray_result = services.jobs.wait(spray["id"], 4)
    assert spray_result["status"] == "completed"
    assert spray_result["result"]["successful_attempts"] == 0
    assert spray_result["result"]["attempts"][0]["outcome"] == "invalid_credential"
    invalid = client.post("/api/v1/sprays", json={"targets": ["192.0.2.8"], "users": ["example"],
                                                "passwords": ["example"], "protocol": "ftp"}).json()
    assert services.jobs.wait(invalid["id"], 4)["status"] == "error"


def test_workflow_stop_retains_checkpoint_for_new_job(services, client, monkeypatch):
    entered, release = Event(), Event()
    calls = []

    def external(argv, **kwargs):
        calls.append(argv)
        if len(calls) == 1:
            entered.set()
            assert release.wait(4)
        return subprocess.CompletedProcess(argv, 0, "[+] authenticated", "")

    monkeypatch.setattr(subprocess, "run", external)
    workflow = services.workflow_create(name="stop checkpoint", steps=[
        {"id": f"step_{number}", "name": f"step {number}", "module": "network/nxc_rdp",
         "operation": "test-auth", "options": {"RHOST": "192.0.2.8"}} for number in (1, 2)])
    job = services.run_workflow(workflow["id"])
    assert entered.wait(4)
    assert client.post(f"/api/v1/jobs/{job['id']}/stop").json()["status"] == "stopping"
    release.set()
    assert services.jobs.wait(job["id"], 4)["status"] == "stopped"
    checkpoint = services.workflows.get_workflow(workflow["id"])
    assert checkpoint.status.value == "paused"
    assert checkpoint.steps[0].status.value == "success" and len(calls) == 1
    resumed = services.run_workflow(workflow["id"])
    result = services.jobs.wait(resumed["id"], 4)
    assert result["status"] == "completed" and len(calls) == 2


def test_findings_reports_assessment_views_and_import_registry(services, client):
    engagement = services.engagement_create(name="assessment")
    response = client.post("/api/v1/findings", json={"title": "Example finding", "description": "Evidence", "target": "192.0.2.8", "severity": "medium"})
    assert response.status_code == 201
    finding = response.json()
    assert client.get("/api/v1/findings").json() == services.finding_list()
    assert client.get("/api/v1/reports").json() == services.report_data()
    report = client.post("/api/v1/reports", json={"format": "json"})
    assert report.status_code == 201, report.text
    from pathlib import Path
    report_document = json.loads(Path(report.json()["path"]).read_text())
    assert finding["id"] in json.dumps(report_document)
    assert client.post(f"/api/v1/findings/{finding['id']}/status", json={"status": "confirmed"}).status_code == 200
    assert client.post(f"/api/v1/assessments/{engagement['id']}/actions/add_note", json={"text": "manual note"}).status_code == 200
    for view in ("topology", "identity-relationships", "attack-paths", "coverage", "findings-retest", "data-quality"):
        response = client.get(f"/api/v1/views/{view}", params={"engagement_id": engagement["id"]})
        assert response.status_code == 200, response.text
        assert response.json() == services.view_model(view, engagement["id"])
    registry = client.get("/api/v1/importers").json()
    assert any(item["id"] == "api_surface.import_openapi" for item in registry)
    imported = client.post("/api/v1/importers/api_surface.import_openapi", json={"document": {
        "openapi": "3.0.3", "info": {"title": "example", "version": "1"},
        "servers": [{"url": "https://example.test"}], "paths": {"/example": {"get": {"responses": {"200": {"description": "ok"}}}}}}})
    assert imported.status_code == 200, imported.text
    assert services.view_model("data-quality")["imports"]
    json.dumps(client.get("/api/v1/graph").json())


def test_integration_and_grounded_ai_service_routes(services, client):
    integrations = client.get("/api/v1/integrations")
    assert integrations.status_code == 200
    assert any(item["name"] == "slack" for item in integrations.json()["available"])
    configured = client.post(
        "/api/v1/integrations/lab/configure",
        json={"integration_type": "slack", "config": {"bot_token": "fixture"}},
    )
    assert configured.json()["success"]
    assert client.get("/api/v1/integrations/lab").json()["status"] == "disconnected"

    observation = {
        "kind": "service",
        "target": "192.0.2.8",
        "port": 80,
        "service": "http",
        "attributes": {},
    }
    analysis = client.post("/api/v1/ai/analyze", json={"observations": [observation]})
    assert analysis.status_code == 200, analysis.text
    recommendations = analysis.json()["analysis"]["recommendations"]
    assert recommendations
    assert all(item["module"] in services.framework.modules for item in recommendations)
    proposal = client.post("/api/v1/ai/workflows", json={"observations": [observation]})
    assert proposal.status_code == 201, proposal.text
    assert proposal.json()["draft"] and not proposal.json()["executed"]


def test_plugin_lifecycle_is_wired_through_shared_services(services, client):
    from pathlib import Path

    source = Path(__file__).parents[4] / "examples" / "plugins" / "hello-demo"
    installed = client.post(
        "/api/v1/plugins/install", json={"source": str(source)}
    )
    assert installed.status_code == 201, installed.text
    name = installed.json()["manifest"]["name"]
    assert client.get(f"/api/v1/plugins/{name}").status_code == 200
    assert any(item["manifest"]["name"] == name for item in client.get("/api/v1/plugins").json())
    assert client.post(f"/api/v1/plugins/{name}/disable").json()["success"]
    assert client.post(f"/api/v1/plugins/{name}/enable").json()["success"]
    assert client.post(f"/api/v1/plugins/{name}/uninstall").json()["success"]
    assert client.get(f"/api/v1/plugins/{name}").status_code == 404
