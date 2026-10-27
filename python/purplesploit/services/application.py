"""Capability-first facade over the existing framework and domain contracts."""

from __future__ import annotations

from importlib import import_module
import inspect
from pathlib import Path
from threading import Lock, RLock
from uuid import uuid4

from purplesploit.core.assessment import (
    AssessmentProfile,
    AssessmentService,
    MethodologyCatalog,
    TestPlan,
)
from purplesploit.core.attack_graph import AttackGraph
from purplesploit.core.auto_enum import AutoEnumPipeline, EnumPhase, EnumScope
from purplesploit.core.credential_spray import CredentialSpray, SprayPattern
from purplesploit.core.execution import ExecutionRequest, Observation
from purplesploit.core.findings import Finding, Severity, FindingStatus
from purplesploit.core.jobs import JobManager, serializable
from purplesploit.core.evidence import EvidenceStore
from purplesploit.core.secrets import EncryptedFileSecretProvider, SecretRedactor
from purplesploit.core.store import (
    CanonicalAssessmentRepository,
    CanonicalFindingsManager,
    CanonicalStore,
)
from purplesploit.core.policy import (
    EngagementAuthorization,
    PolicyEngine,
    PolicyViolation,
    SprayBudgetLedger,
)
from purplesploit.core.workflow import WorkflowEngine, WorkflowStep
from purplesploit.core.support import create_support_bundle
from purplesploit.distributed.coordinator import Coordinator
from purplesploit.integrations import IntegrationService
from purplesploit.ai import AdvisoryService


class _JobFramework:
    """Delegate to one framework, checking controls around each execution."""

    def __init__(
        self,
        framework,
        context,
        on_execution=None,
        *,
        policy=None,
        engagement_id=None,
        targets=None,
    ):
        self._framework = framework
        self._context = context
        self._on_execution = on_execution
        self._policy = policy or PolicyEngine.disabled()
        self._engagement_id = engagement_id
        self._targets = list(targets or [])

    def __getattr__(self, name):
        return getattr(self._framework, name)

    def _execute(self, method, *args, **kwargs):
        self._context.checkpoint()
        request = None
        if args:
            request = (
                args[0]
                if isinstance(args[0], ExecutionRequest)
                else getattr(args[0], "execution_request", None)
            )
        if isinstance(request, ExecutionRequest):
            request.engagement_id = request.engagement_id or self._engagement_id
            request.targets = request.targets or list(self._targets)
        if isinstance(request, ExecutionRequest):
            with self._policy.permit(request):
                result = getattr(self._framework, method)(*args, **kwargs)
        else:
            result = getattr(self._framework, method)(*args, **kwargs)
        if self._on_execution:
            self._on_execution(result)
        return result

    def instantiate_module(self, *args, **kwargs):
        return self._framework.instantiate_module(*args, **kwargs)

    def execute_request(self, *args, **kwargs):
        return self._execute("execute_request", *args, **kwargs)

    def run_module(self, *args, **kwargs):
        return self._execute("run_module", *args, **kwargs)

    def run_operation(self, *args, **kwargs):
        return self._execute("run_operation", *args, **kwargs)


# Discovery stays read-only and tolerates optional import dependencies.
IMPORTER_MODULES = (
    "api_surface",
    "identity",
    "host_database",
    "cloud",
    "containers",
    "bloodhound",
    "aranum",
    "canonical",
    "attack_formats",
)


class PurpleSploitServices:
    """One service instance owns a framework, stores, graph, and in-process jobs.

    Long-running jobs use the same execution contract as direct module calls.
    Controls take effect between executions, never terminate an active tool.
    """

    def __init__(
        self,
        framework,
        storage_path=None,
        *,
        jobs=None,
        findings=None,
        graph=None,
        advisory_provider=None,
        advisory_policy=None,
        agent_authenticator=None,
        policy=None,
    ):
        self.framework = framework
        base = (
            Path(storage_path)
            if storage_path
            else Path(framework.database.db_path).parent / "application"
        )
        self.storage_path = base
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        base.chmod(0o700)
        self.store = CanonicalStore(base / "canonical.db")
        self.secrets = EncryptedFileSecretProvider(base / "secrets.vault")
        self.redactor = SecretRedactor(self.secrets)
        self.evidence = EvidenceStore(base / "evidence", self.store, self.secrets)
        self.policy = policy or PolicyEngine.disabled()
        self.spray_budget = SprayBudgetLedger(self.store)
        self.assessments = AssessmentService(CanonicalAssessmentRepository(self.store))
        for engagement in self.assessments.list_engagements():
            authorization = engagement.metadata.get("authorization")
            if authorization:
                self.policy.register(authorization)
        self.workflows = WorkflowEngine(framework, base / "workflows")
        self.findings = findings or CanonicalFindingsManager(
            self.store, framework, default_engagement_id="local-default"
        )
        self.graph = graph or getattr(framework, "attack_graph", None) or AttackGraph()
        self.jobs = jobs or JobManager()
        self._graph_lock = RLock()
        self._workflow_jobs = {}
        self._workflow_lock = Lock()
        self._imports = []
        self.integrations = IntegrationService(
            findings=self.findings,
            config_path=base / "integrations.json",
            secret_provider=self.secrets,
        )
        self.advisory = AdvisoryService(
            framework,
            provider=advisory_provider,
            workflows=self.workflows,
            policy=advisory_policy,
            redactor=self.redactor,
        )
        self.coordinator = Coordinator(
            on_result=self.ingest_remote_execution,
            on_findings=self.ingest_remote_findings,
            policy=self.policy,
            authenticator=agent_authenticator,
        )

    def modules(self):
        return [
            {
                key: getattr(module, key)
                for key in ("path", "name", "category", "description", "author")
            }
            for module in self.framework.list_modules()
        ]

    def operations(self, module_path):
        module = self.framework.instantiate_module(module_path)
        if module is None:
            raise KeyError(module_path)
        return [
            {key: serializable(value) for key, value in operation.items() if key != "handler"}
            for operation in module.get_operation_manifest()
        ]

    def execute(self, request):
        if isinstance(request, dict):
            request = ExecutionRequest.from_dict(request)
        if request.explain_only:
            return self.policy.explain(request)
        with self.policy.permit(request):
            result = self.framework.execute_request(request)
        self._ingest_execution(result)
        if request.engagement_id:
            self.assessments.record_execution(request.engagement_id, result)
            self.store.put_record(
                "execution",
                result.request_id,
                request.engagement_id,
                result.to_dict(),
                actor="execution",
            )
        return result.to_dict()

    def _ingest_execution(self, result):
        observations = (
            result.get("observations", [])
            if isinstance(result, dict)
            else getattr(result, "observations", [])
        )
        with self._graph_lock:
            self.graph.ingest_observations(
                [
                    Observation.from_dict(item) if isinstance(item, dict) else item
                    for item in observations
                ]
            )

    def capability_manifest(self):
        catalog = []
        for module in self.modules():
            try:
                module["operations"] = self.operations(module["path"])
                module["available"] = True
            except Exception as exc:
                module.update(available=False, operations=[], error=str(exc))
            catalog.append(module)
        return {
            "schema_version": 1,
            "modules": catalog,
            "importers": self.importers(),
            "job_semantics": {
                "storage": "in_process",
                "missing_id": "unknown",
                "control_boundary": "between_executions",
                "progress": "polling_and_event_journal",
            },
            "parity": self.parity_inventory(),
        }

    @staticmethod
    def parity_inventory():
        return [
            {"capability": capability, "service": method, "method": verb, "path": "/api/v1" + path}
            for capability, method, verb, path in (
                ("capabilities", "capability_manifest", "GET", "/capabilities"),
                ("capability_reference", "capability_reference", "GET", "/capabilities/reference"),
                ("parity", "parity_inventory", "GET", "/parity"),
                ("modules", "modules", "GET", "/modules"),
                ("operations", "operations", "GET", "/operations"),
                ("execution", "execute", "POST", "/executions"),
                ("workflows", "workflow_list", "GET", "/workflows"),
                ("workflow_create", "workflow_create", "POST", "/workflows"),
                ("workflow_templates", "workflow_templates", "GET", "/workflow-templates"),
                ("workflow_detail", "workflow_get", "GET", "/workflows/{workflow_id}"),
                ("workflow_run", "run_workflow", "POST", "/workflows/{workflow_id}/run"),
                ("auto_enum", "run_auto_enum", "POST", "/auto-enum"),
                ("spray", "run_spray", "POST", "/sprays"),
                ("assessments", "engagement_list", "GET", "/assessments"),
                ("assessment_create", "engagement_create", "POST", "/assessments"),
                ("assessment_detail", "engagement_get", "GET", "/assessments/{engagement_id}"),
                (
                    "assessment_actions",
                    "assessment_action",
                    "POST",
                    "/assessments/{engagement_id}/actions/{action}",
                ),
                (
                    "assessment_coverage",
                    "view_model",
                    "GET",
                    "/assessments/{engagement_id}/coverage",
                ),
                ("methodologies", "methodologies", "GET", "/methodologies"),
                ("findings", "finding_list", "GET", "/findings"),
                ("finding_create", "finding_create", "POST", "/findings"),
                ("finding_status", "finding_transition", "POST", "/findings/{finding_id}/status"),
                ("reports", "report_data", "GET", "/reports"),
                ("report_generation", "report_generate", "POST", "/reports"),
                ("graph", "graph_data", "GET", "/graph"),
                ("jobs", "job_list", "GET", "/jobs"),
                ("job_detail", "job_get", "GET", "/jobs/{job_id}"),
                ("job_result", "job_get", "GET", "/jobs/{job_id}/result"),
                ("job_control", "job_control", "POST", "/jobs/{job_id}/{action}"),
                ("job_events", "job_events", "GET", "/jobs/{job_id}/events"),
                ("job_stream", "job_events", "GET", "/jobs/{job_id}/stream"),
                ("importers", "importers", "GET", "/importers"),
                ("import", "import_data", "POST", "/importers/{importer_id}"),
                ("view_models", "view_model", "GET", "/views/{view}"),
                ("plugins", "plugin_list", "GET", "/plugins"),
                ("plugin_detail", "plugin_get", "GET", "/plugins/{name}"),
                ("plugin_install", "plugin_install", "POST", "/plugins/install"),
                ("plugin_action", "plugin_action", "POST", "/plugins/{name}/{action}"),
                ("distributed_health", "distributed_health", "GET", "/health"),
                ("agents", "agent_list", "GET", "/agents"),
                ("agent_register", "agent_register", "POST", "/agents/register"),
                ("agent_heartbeat", "agent_heartbeat", "POST", "/agents/heartbeat"),
                ("tasks", "task_list", "GET", "/tasks"),
                ("task_submit", "task_submit", "POST", "/tasks/submit"),
                ("task_request", "task_request", "POST", "/tasks/request"),
                ("task_result", "task_result", "POST", "/tasks/result"),
                ("task_detail", "task_status", "GET", "/tasks/{task_id}"),
                ("task_cancel", "task_cancel", "POST", "/tasks/{task_id}/cancel"),
                ("artifact_upload", "artifact_upload", "POST", "/artifacts/upload"),
                (
                    "artifact_download",
                    "artifact_get",
                    "GET",
                    "/tasks/{task_id}/artifacts/{artifact_id}",
                ),
                ("finding_sync", "remote_findings_sync", "POST", "/findings/sync"),
                ("distributed_findings", "remote_findings", "GET", "/distributed/findings"),
                ("integrations", "integration_list", "GET", "/integrations"),
                ("integration_detail", "integration_status", "GET", "/integrations/{name}"),
                (
                    "integration_configure",
                    "integration_configure",
                    "POST",
                    "/integrations/{name}/configure",
                ),
                (
                    "integration_action",
                    "integration_action",
                    "POST",
                    "/integrations/{name}/{action}",
                ),
                (
                    "finding_delivery",
                    "integration_send_finding",
                    "POST",
                    "/integrations/findings/{finding_id}/send",
                ),
                ("deliveries", "integration_deliveries", "GET", "/integrations/deliveries"),
                ("remote_mappings", "integration_mappings", "GET", "/integrations/mappings"),
                ("ai_inventory", "ai_inventory", "GET", "/ai/inventory"),
                ("ai_analysis", "ai_analyze", "POST", "/ai/analyze"),
                ("ai_workflow", "ai_propose_workflow", "POST", "/ai/workflows"),
                ("support_bundle", "support_bundle", "POST", "/support-bundles"),
                (
                    "authorization_get",
                    "authorization_get",
                    "GET",
                    "/authorizations/{engagement_id}",
                ),
                (
                    "authorization_set",
                    "authorization_set",
                    "PUT",
                    "/authorizations/{engagement_id}",
                ),
                ("execution_plan", "execution_plan", "POST", "/executions/plan"),
            )
        ]

    def capability_reference(self):
        manifest = self.capability_manifest()
        lines = [
            "# Runtime capability reference",
            "",
            "Generated from installed operation manifests.",
            "",
        ]
        for module in manifest["modules"]:
            lines.append(f"## {module['path']}")
            lines.extend(f"- {op['id']}: {op['description']}" for op in module["operations"])
            lines.append("")
        lines.extend(["## Service / API parity", ""])
        lines.extend(
            f"- `{item['service']}` → `{item['method']} {item['path']}`"
            for item in manifest["parity"]
        )
        return "\n".join(lines) + "\n"

    def workflow_list(self):
        return [workflow.to_dict() for workflow in self.workflows.list_workflows()]

    def workflow_templates(self):
        return self.workflows.list_templates()

    def workflow_get(self, workflow_id):
        workflow = self.workflows.get_workflow(workflow_id)
        if workflow is None:
            raise KeyError(workflow_id)
        return workflow.to_dict()

    def workflow_create(self, **values):
        steps = [WorkflowStep.from_dict(step) for step in values.pop("steps", [])]
        if values.get("from_template") and values["from_template"] not in {
            item["id"] for item in self.workflows.list_templates()
        }:
            raise ValueError("Unknown workflow template")
        workflow = self.workflows.create_workflow(**values)
        workflow.steps.extend(steps)
        self.workflows.save_workflow(workflow.id)
        return workflow.to_dict()

    def run_workflow(self, workflow_id, **values):
        if self.workflows.get_workflow(workflow_id) is None:
            raise KeyError(workflow_id)
        with self._workflow_lock:
            previous = self._workflow_jobs.get(workflow_id)
            if previous and self.jobs.get(previous)["status"] not in {
                "completed",
                "failed",
                "error",
                "stopped",
                "interrupted",
            }:
                raise ValueError("Workflow already has an active job")

            engagement_id = values.get("engagement_id")
            targets = values.get("targets") or ([values["target"]] if values.get("target") else [])

            def run(context):
                engine = WorkflowEngine(
                    _JobFramework(
                        self.framework,
                        context,
                        self._ingest_execution,
                        policy=self.policy,
                        engagement_id=engagement_id,
                        targets=targets,
                    ),
                    self.workflows.storage_path,
                )
                engine.on_step_complete = lambda workflow, step, result: context.checkpoint(
                    {
                        "workflow_id": workflow_id,
                        "step_id": step.id,
                        "step_status": step.status.value,
                    }
                )
                try:
                    return engine.run_workflow(workflow_id, **values)
                finally:
                    # A stopped job retains completed steps in a resumable domain
                    # checkpoint. It does not imply a completed workflow.
                    engine.pause_workflow(workflow_id)
                    self.workflows.workflows.pop(workflow_id, None)

            job = self.jobs.submit("workflow", run)
            self._workflow_jobs[workflow_id] = job["id"]
            return job

    def run_auto_enum(self, *, scope="normal", phases=None, **values):
        selected_scope = EnumScope(scope)
        selected_phases = [EnumPhase(phase) for phase in phases] if phases is not None else None
        timeout_s = float(values.pop("timeout_s", 600))
        run_dir = self.storage_path / "artifacts" / "auto-enum" / str(uuid4())
        engagement_id = values.get("engagement_id")
        targets = list(values.get("targets") or [])

        def run(context):
            pipeline = AutoEnumPipeline(
                _JobFramework(
                    self.framework,
                    context,
                    self._ingest_execution,
                    policy=self.policy,
                    engagement_id=engagement_id,
                    targets=targets,
                ),
                selected_scope,
                run_dir=run_dir,
                timeout_s=timeout_s,
            )
            pipeline.on_progress = lambda progress: context.checkpoint(serializable(progress))
            result = pipeline.run(phases=selected_phases, **values)
            return result

        return self.jobs.submit("auto_enum", run)

    def run_spray(self, *, pattern="breadth_first", **values):
        selected_pattern = SprayPattern(pattern)
        targets = list(values.get("targets") or [])
        engagement_id = values.pop("engagement_id", None)
        approval_id = values.pop("approval_id", None)
        if self.policy.enforce:
            contract = self.policy.get(engagement_id) if engagement_id else None
            if contract is None:
                raise PolicyViolation(
                    "missing_engagement", "Spray requires an authorized engagement"
                )
            if contract.require_lockout_discovery and not values.pop(
                "lockout_policy_discovered", False
            ):
                raise PolicyViolation(
                    "lockout_policy_required",
                    "Credential spray requires a recorded lockout policy",
                )
        else:
            values.pop("lockout_policy_discovered", None)
        spray_request = ExecutionRequest(
            module_path="automation/credential-spray",
            operation_name="credential-spray",
            engagement_id=engagement_id,
            targets=targets,
            action_risk="high",
            side_effects=["authentication attempts", "account lockout risk"],
            approval_id=approval_id,
        )
        self.policy.authorize(spray_request, reserve=False)
        reservations = []
        if self.policy.enforce:
            attempts = [
                (str(user), str(target))
                for target in targets
                for _password in values.get("passwords", [])
                for user in values.get("users", [])
            ]
            reservations = self.spray_budget.reserve(
                engagement_id=engagement_id,
                domain=str(values.get("domain") or ""),
                attempts=attempts,
            )

        def run(context):
            spray = CredentialSpray(
                _JobFramework(
                    self.framework,
                    context,
                    self._ingest_execution,
                    policy=self.policy,
                    engagement_id=engagement_id,
                    targets=targets,
                )
            )
            spray.on_progress = lambda completed, total: context.checkpoint(
                {"completed": completed, "total": total}
            )
            reservation_iter = iter(reservations)
            spray.on_attempt = lambda attempt: (
                self.spray_budget.record(next(reservation_iter), attempt.outcome.value)
                if reservations
                else None
            )
            result = spray.spray(pattern=selected_pattern, **values)
            return {
                **result.to_dict(),
                "attempts": [attempt.to_dict() for attempt in result.attempts],
            }

        return self.jobs.submit("spray", run)

    def engagement_list(self):
        return [item.to_dict() for item in self.assessments.list_engagements()]

    def engagement_create(self, **values):
        return self.assessments.create_engagement(**values).to_dict()

    def engagement_get(self, engagement_id):
        return self.assessments.get_engagement(engagement_id).to_dict()

    def authorization_set(self, engagement_id, values):
        if values.get("engagement_id", engagement_id) != engagement_id:
            raise ValueError("Authorization engagement_id does not match the route")
        values = {**values, "engagement_id": engagement_id}
        contract = EngagementAuthorization.from_dict(values)
        self.assessments.get_engagement(engagement_id)
        self.policy.register(contract)
        engagement = self.assessments.get_engagement(engagement_id)
        engagement.metadata["authorization"] = contract.to_dict()
        self.assessments.repository.update(engagement)
        return contract.to_dict()

    def authorization_get(self, engagement_id):
        return self.policy.get(engagement_id).to_dict()

    def execution_plan(self, request):
        return self.policy.explain(request)

    def assessment_action(self, engagement_id, action, values):
        allowed = {
            "update_engagement",
            "add_evidence",
            "attach_evidence",
            "add_note",
            "add_hypothesis",
            "update_hypothesis",
            "add_review",
            "update_review",
            "add_remediation",
            "update_remediation",
            "record_check",
            "add_retest",
            "create_baseline",
            "compare",
        }
        if action == "add_plan":
            return self.assessments.add_plan(engagement_id, TestPlan.from_dict(values)).to_dict()
        if action == "apply_profile":
            return self.assessments.apply_profile(
                engagement_id, AssessmentProfile.from_dict(values)
            ).to_dict()
        if action == "link_finding":
            finding = self.findings.get(values["finding_id"])
            if finding is None:
                raise KeyError(values["finding_id"])
            return self.assessments.link_finding(
                engagement_id,
                finding,
                case_ids=values.get("case_ids"),
                evidence_refs=values.get("evidence_refs"),
            ).to_dict()
        if action not in allowed:
            raise ValueError("Unknown assessment action")
        return serializable(getattr(self.assessments, action)(engagement_id, **values))

    def finding_list(self):
        return [finding.to_dict() for finding in self.findings.list_findings()]

    def finding_create(self, **values):
        engagement_id = values.pop("engagement_id", None) or "local-default"
        try:
            self.assessments.get_engagement(engagement_id)
        except FileNotFoundError:
            if engagement_id != "local-default":
                raise
            self.assessments.create_engagement(
                "Local compatibility engagement",
                engagement_id=engagement_id,
                metadata={"compatibility_default": True},
            )
        metadata = dict(values.pop("metadata", {}))
        metadata["engagement_id"] = engagement_id
        values["metadata"] = metadata
        if "severity" in values:
            values["severity"] = Severity(values["severity"])
        return self.findings.create(**values).to_dict()

    def finding_transition(self, finding_id, status, **values):
        result = self.findings.transition_status(finding_id, FindingStatus(status), **values)
        if not result:
            raise ValueError("Finding status transition was rejected")
        return self.findings.get(finding_id).to_dict()

    def report_data(self):
        return {"findings": self.finding_list(), "statistics": self.findings.get_statistics()}

    def report_generate(self, format="json"):
        from purplesploit.reporting.generator import ReportGenerator

        if format not in {"json", "markdown", "html", "pdf", "xlsx"}:
            raise ValueError("Unsupported report format")
        generator = ReportGenerator()
        generator.add_findings(self.findings.list_findings())
        destination = (
            self.storage_path
            / "reports"
            / f"report-{uuid4()}.{('md' if format == 'markdown' else format)}"
        )
        return {"path": generator.generate(format, str(destination)), "format": format}

    def graph_data(self):
        with self._graph_lock:
            return self.graph.to_dict()

    def job_list(self):
        return self.jobs.list()

    def job_get(self, job_id):
        return self.jobs.get(job_id)

    def job_control(self, job_id, action):
        return self.jobs.control(job_id, action)

    def job_events(self, job_id, after=0):
        return self.jobs.events(job_id, after)

    def plugin_list(self):
        return [plugin.to_dict() for plugin in self.framework.plugin_manager.list_installed()]

    def plugin_get(self, name):
        plugin = next(
            (item for item in self.framework.plugin_manager.list_installed() if item.name == name),
            None,
        )
        if plugin is None:
            raise KeyError(name)
        return plugin.to_dict()

    def plugin_install(self, source, force=False):
        return self.framework.plugin_manager.install_local(Path(source), force=force).to_dict()

    def plugin_action(self, name, action):
        manager = self.framework.plugin_manager
        if action == "enable":
            success = manager.enable(name)
        elif action == "disable":
            success = manager.disable(name)
        elif action == "uninstall":
            success = manager.uninstall(name)
        else:
            raise ValueError("Expected enable, disable, or uninstall")
        if not success:
            raise KeyError(name)
        return {"success": True, "name": name, "action": action}

    def importers(self):
        result = []
        for name in IMPORTER_MODULES:
            try:
                module = import_module(f"purplesploit.interop.{name}")
            except ImportError:
                continue
            for key, handler in inspect.getmembers(module, inspect.isfunction):
                if key.startswith("import_") and handler.__module__ == module.__name__:
                    result.append(
                        {
                            "id": f"{name}.{key}",
                            "name": key,
                            "parameters": list(inspect.signature(handler).parameters),
                        }
                    )
        return result

    def import_data(self, importer_id, document, **options):
        if importer_id not in {item["id"] for item in self.importers()}:
            raise KeyError(importer_id)
        module_name, handler_name = importer_id.split(".", 1)
        handler = getattr(import_module(f"purplesploit.interop.{module_name}"), handler_name)
        result = handler(document, **options)
        observations = getattr(result, "observations", [])
        with self._graph_lock:
            if observations:
                self.graph.ingest_observations(observations)
            if isinstance(result, AttackGraph):
                # Keep imported graph as the shared browser graph.
                self.graph = result
            elif isinstance(getattr(result, "graph", None), AttackGraph):
                # Graph-format adapters return a result envelope so they can
                # retain source payloads and mapping diagnostics.
                self.graph = result.graph
        value = serializable(result)
        self._imports.append({"importer": importer_id, "result": value})
        return value

    def view_model(self, view, engagement_id=None):
        if view == "topology":
            with self._graph_lock:
                return self.graph.to_cytoscape()
        if view == "identity-relationships":
            data = self.graph_data()
            kinds = {"user", "group", "credential", "identity", "role", "policy", "domain"}
            nodes = [node for node in data["nodes"] if node["type"] in kinds]
            ids = {node["id"] for node in nodes}
            edges = [
                edge for edge in data["edges"] if edge["source"] in ids or edge["target"] in ids
            ]
            related = ids | {edge[key] for edge in edges for key in ("source", "target")}
            return {
                "nodes": [node for node in data["nodes"] if node["id"] in related],
                "edges": edges,
            }
        if view == "attack-paths":
            with self._graph_lock:
                return {"paths": [path.to_dict() for path in self.graph.derive_attack_paths()]}
        if view == "coverage":
            return self.assessments.coverage(engagement_id)
        if view == "findings-retest":
            assessment = self.engagement_get(engagement_id) if engagement_id else {}
            return {
                "findings": self.finding_list(),
                "retests": assessment.get("retests", []),
                "remediations": assessment.get("remediations", []),
            }
        if view == "data-quality":
            assessment = self.engagement_get(engagement_id) if engagement_id else {}
            graph = self.graph_data()
            return {
                "evidence": assessment.get("evidence", []),
                "checks": assessment.get("checks", []),
                "imports": self._imports,
                "graph_statistics": graph["statistics"],
                "lineage": [
                    {
                        "node_id": node["id"],
                        "properties": node["properties"],
                        "metadata": node["metadata"],
                    }
                    for node in graph["nodes"]
                ],
            }
        raise KeyError(view)

    def methodologies(self):
        return MethodologyCatalog().list()

    def ingest_remote_execution(self, result):
        """Project an accepted remote result into the shared local views."""
        self._ingest_execution(result)
        if result.engagement_id:
            self.assessments.record_execution(result.engagement_id, result)

    def ingest_remote_findings(self, values):
        """Upsert coordinator-validated findings without changing their IDs."""
        findings = [Finding.from_dict(value) for value in values]
        for finding in findings:
            self.findings.findings[finding.id] = finding
        if findings:
            self.findings._save_findings()
        return [finding.id for finding in findings]

    def distributed_health(self):
        return self.coordinator.health()

    def agent_list(self):
        return self.coordinator.agents()

    def agent_register(self, **values):
        return self.coordinator.register(**values)

    def agent_heartbeat(self, **values):
        return self.coordinator.heartbeat(**values)

    def task_list(self):
        return self.coordinator.status()

    def task_submit(self, **values):
        return self.coordinator.submit(**values)

    def task_request(self, **values):
        return self.coordinator.claim(**values)

    def task_result(self, **values):
        return self.coordinator.result(**values)

    def task_status(self, task_id):
        return self.coordinator.status(task_id)

    def task_cancel(self, task_id):
        return self.coordinator.cancel(task_id)

    def artifact_upload(self, **values):
        return self.coordinator.put_artifact(**values)

    def artifact_get(self, task_id, artifact_id):
        return self.coordinator.artifact(task_id, artifact_id)

    def remote_findings_sync(self, **values):
        return self.coordinator.sync_findings(**values)

    def remote_findings(self):
        return self.coordinator.findings()

    def integration_list(self):
        return {
            "available": self.integrations.list_available(),
            "configured": self.integrations.list_configured(),
        }

    def integration_status(self, name=None):
        return self.integrations.status(name)

    def integration_configure(self, name, config, integration_type=None):
        return self.integrations.configure(name, config, integration_type)

    def integration_action(self, name, action):
        handlers = {
            "connect": self.integrations.connect,
            "disconnect": self.integrations.disconnect,
            "test": self.integrations.test_connection,
            "remove": self.integrations.remove,
        }
        if action not in handlers:
            raise ValueError("Expected connect, disconnect, test, or remove")
        return handlers[action](name)

    def integration_send_finding(self, finding_id, **values):
        return self.integrations.send_finding(finding_id, **values)

    def integration_deliveries(self, finding_id=None):
        return self.integrations.deliveries(finding_id)

    def integration_mappings(self):
        return self.integrations.mappings()

    def ai_inventory(self):
        return self.advisory.inventory()

    def ai_analyze(self, **values):
        return self.advisory.analyze(**values)

    def ai_propose_workflow(self, **values):
        return self.advisory.propose_workflow(**values)

    def support_bundle(self):
        directory = self.storage_path / "support"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return create_support_bundle(self, directory / f"support-{uuid4().hex}.zip")
