"""Versioned HTTP adapter. All business operations delegate to shared services."""

from functools import wraps
import json

from fastapi import APIRouter, Body, FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse, StreamingResponse

from purplesploit.core.jobs import TERMINAL
from purplesploit.distributed.api import create_distributed_router
from purplesploit.services.security import install_security_routes
from purplesploit.core.policy import PolicyViolation


def _errors(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (KeyError, FileNotFoundError) as exc:
            raise HTTPException(404, str(exc)) from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        except PolicyViolation as exc:
            raise HTTPException(403, detail=exc.to_dict()) from exc

    return call


def create_router(services):
    router = APIRouter(prefix="/api/v1", tags=["application services"])

    @router.get("/capabilities")
    def capabilities():
        return services.capability_manifest()

    @router.get("/capabilities/reference", response_class=PlainTextResponse)
    def reference():
        return services.capability_reference()

    @router.get("/parity")
    def parity():
        return services.parity_inventory()

    @router.get("/modules")
    def modules():
        return services.modules()

    @router.get("/operations")
    @_errors
    def operations(module_path: str):
        return services.operations(module_path)

    @router.post("/executions")
    @_errors
    def execute(values: dict = Body(...)):
        return services.execute(values)

    @router.post("/executions/plan")
    @_errors
    def execution_plan(values: dict = Body(...)):
        return services.execution_plan(values)

    @router.get("/workflow-templates")
    def workflow_templates():
        return services.workflow_templates()

    @router.get("/workflows")
    def workflows():
        return services.workflow_list()

    @router.post("/workflows", status_code=201)
    @_errors
    def workflow_create(values: dict = Body(...)):
        return services.workflow_create(**values)

    @router.get("/workflows/{workflow_id}")
    @_errors
    def workflow_get(workflow_id: str):
        return services.workflow_get(workflow_id)

    @router.post("/workflows/{workflow_id}/run", status_code=202)
    @_errors
    def workflow_run(workflow_id: str, values: dict = Body(default={})):
        return services.run_workflow(workflow_id, **values)

    @router.post("/auto-enum", status_code=202)
    @_errors
    def auto_enum(values: dict = Body(...)):
        return services.run_auto_enum(**values)

    @router.post("/sprays", status_code=202)
    @_errors
    def spray(values: dict = Body(...)):
        return services.run_spray(**values)

    @router.get("/assessments")
    def assessments():
        return services.engagement_list()

    @router.post("/assessments", status_code=201)
    @_errors
    def assessment_create(values: dict = Body(...)):
        return services.engagement_create(**values)

    @router.get("/assessments/{engagement_id}")
    @_errors
    def assessment_get(engagement_id: str):
        return services.engagement_get(engagement_id)

    @router.get("/assessments/{engagement_id}/coverage")
    @_errors
    def coverage(engagement_id: str):
        return services.view_model("coverage", engagement_id)

    @router.post("/assessments/{engagement_id}/actions/{action}")
    @_errors
    def assessment_action(engagement_id: str, action: str, values: dict = Body(...)):
        return services.assessment_action(engagement_id, action, values)

    @router.get("/methodologies")
    def methodologies():
        return services.methodologies()

    @router.get("/authorizations/{engagement_id}")
    @_errors
    def authorization_get(engagement_id: str):
        return services.authorization_get(engagement_id)

    @router.put("/authorizations/{engagement_id}")
    @_errors
    def authorization_set(engagement_id: str, values: dict = Body(...)):
        return services.authorization_set(engagement_id, values)

    @router.get("/findings")
    def findings():
        return services.finding_list()

    @router.post("/findings", status_code=201)
    @_errors
    def finding_create(values: dict = Body(...)):
        return services.finding_create(**values)

    @router.post("/findings/{finding_id}/status")
    @_errors
    def finding_transition(finding_id: str, values: dict = Body(...)):
        return services.finding_transition(finding_id, **values)

    @router.get("/reports")
    def reports():
        return services.report_data()

    @router.post("/reports", status_code=201)
    @_errors
    def report_generate(values: dict = Body(default={})):
        return services.report_generate(**values)

    @router.get("/graph")
    def graph():
        return services.graph_data()

    @router.get("/jobs")
    def jobs():
        return services.job_list()

    @router.get("/jobs/{job_id}")
    @_errors
    def job(job_id: str):
        return services.job_get(job_id)

    @router.get("/jobs/{job_id}/result")
    @_errors
    def job_result(job_id: str):
        value = services.job_get(job_id)
        if value["status"] not in TERMINAL:
            raise HTTPException(409, "Job has no terminal result yet")
        return {
            "status": value["status"],
            "outcome": value["outcome"],
            "result": value["result"],
            "error": value["error"],
        }

    @router.get("/jobs/{job_id}/events")
    @_errors
    def job_events(job_id: str, after: int = Query(default=0, ge=0)):
        return services.job_events(job_id, after)

    @router.get("/jobs/{job_id}/stream")
    @_errors
    def job_stream(job_id: str, after: int = Query(default=0, ge=0)):
        # Finite replay: clients reconnect with after=last event revision.
        events = services.job_events(job_id, after)
        return StreamingResponse(
            iter(
                f"id: {event['revision']}\nevent: progress\ndata: {json.dumps(event)}\n\n"
                for event in events
            ),
            media_type="text/event-stream",
        )

    @router.post("/jobs/{job_id}/{action}")
    @_errors
    def job_control(job_id: str, action: str):
        return services.job_control(job_id, action)

    @router.get("/importers")
    def importers():
        return services.importers()

    @router.post("/importers/{importer_id}")
    @_errors
    def import_data(importer_id: str, values: dict = Body(...)):
        return services.import_data(importer_id, **values)

    @router.get("/views/{view}")
    @_errors
    def view_model(view: str, engagement_id: str | None = None):
        return services.view_model(view, engagement_id)

    @router.get("/plugins")
    def plugins():
        return services.plugin_list()

    @router.post("/plugins/install", status_code=201)
    @_errors
    def plugin_install(values: dict = Body(...)):
        return services.plugin_install(**values)

    @router.get("/plugins/{name}")
    @_errors
    def plugin_get(name: str):
        return services.plugin_get(name)

    @router.post("/plugins/{name}/{action}")
    @_errors
    def plugin_action(name: str, action: str):
        return services.plugin_action(name, action)

    @router.get("/integrations")
    def integrations():
        return services.integration_list()

    @router.get("/integrations/deliveries")
    def integration_deliveries(finding_id: str | None = None):
        return services.integration_deliveries(finding_id)

    @router.get("/integrations/mappings")
    def integration_mappings():
        return services.integration_mappings()

    @router.post("/integrations/findings/{finding_id}/send")
    @_errors
    def integration_send_finding(finding_id: str, values: dict = Body(default={})):
        return services.integration_send_finding(finding_id, **values)

    @router.get("/integrations/{name}")
    def integration_status(name: str):
        return services.integration_status(name)

    @router.post("/integrations/{name}/configure")
    @_errors
    def integration_configure(name: str, values: dict = Body(...)):
        values = dict(values)
        integration_type = values.pop("integration_type", None)
        config = values.pop("config", values)
        if values and config is not values:
            raise ValueError("Unexpected integration configuration fields")
        return services.integration_configure(name, config, integration_type)

    @router.post("/integrations/{name}/{action}")
    @_errors
    def integration_action(name: str, action: str):
        return services.integration_action(name, action)

    @router.get("/ai/inventory")
    def ai_inventory():
        return services.ai_inventory()

    @router.post("/ai/analyze")
    @_errors
    def ai_analyze(values: dict = Body(default={})):
        return services.ai_analyze(**values)

    @router.post("/ai/workflows", status_code=201)
    @_errors
    def ai_workflow(values: dict = Body(default={})):
        return services.ai_propose_workflow(**values)

    @router.post("/support-bundles", status_code=201)
    @_errors
    def support_bundle():
        return services.support_bundle()

    return router


def create_app(services, security=None):
    """An injectable app factory for embedding and actual service/API tests."""
    app = FastAPI(title="PurpleSploit application services", version="1")
    app.state.services = services
    app.state.coordinator = services.coordinator
    app.state.security = security

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        verification = services.store.verify()
        if not verification["valid"]:
            raise HTTPException(503, "Canonical store verification failed")
        return {
            "status": "ready",
            "schema_version": verification["schema_version"],
            "policy_enforced": services.policy.enforce,
            "agent_authentication": services.coordinator.authenticator is not None,
        }

    app.include_router(create_router(services))
    app.include_router(
        create_distributed_router(
            services.coordinator,
            websocket_auth=security.authenticate_websocket if security else None,
            message_auth=services.coordinator.authenticator,
        )
    )
    if security is not None:
        app.middleware("http")(security.middleware)
        install_security_routes(app, security)
    return app
