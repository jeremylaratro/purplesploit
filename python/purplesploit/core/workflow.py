"""
Workflow Engine for PurpleSploit

Module chaining and automated workflow execution with conditional logic,
parallel execution, and progress tracking.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum
import json
import copy
import ipaddress
import os
import tempfile
import time
import fcntl
from pathlib import Path
from urllib.parse import urlsplit


class StepStatus(Enum):
    """Workflow step status."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class WorkflowStatus(Enum):
    """Overall workflow status."""
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class WorkflowStep:
    """A single step in a workflow."""
    id: str
    name: str
    module: str
    operation: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    on_success: List[str] = field(default_factory=list)  # Step IDs to run on success
    on_failure: List[str] = field(default_factory=list)  # Step IDs to run on failure
    timeout: int = 600  # Seconds
    retry_count: int = 0
    status: StepStatus = StepStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    attempts: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "module": self.module,
            "operation": self.operation,
            "options": self.options,
            "conditions": self.conditions,
            "on_success": self.on_success,
            "on_failure": self.on_failure,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "status": self.status.value,
            "result": self.result,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "attempts": self.attempts,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorkflowStep":
        data = copy.deepcopy(data)
        if isinstance(data.get("status"), str):
            data["status"] = StepStatus(data["status"])
        for dt_field in ["started_at", "completed_at"]:
            if data.get(dt_field) and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])
        return cls(**data)


@dataclass
class Workflow:
    """A complete workflow definition."""
    id: str
    name: str
    description: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    status: WorkflowStatus = WorkflowStatus.CREATED
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def get_step(self, step_id: str) -> Optional[WorkflowStep]:
        """Get a step by ID."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def add_step(
        self,
        name: str,
        module: str,
        operation: Optional[str] = None,
        **kwargs
    ) -> WorkflowStep:
        """Add a step to the workflow."""
        step_id = f"step_{len(self.steps) + 1}"
        step = WorkflowStep(
            id=step_id,
            name=name,
            module=module,
            operation=operation,
            **kwargs
        )
        self.steps.append(step)
        return step

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
            "variables": self.variables,
            "status": self.status.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "current_step_id": self.current_step_id,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Workflow":
        data = copy.deepcopy(data)
        if isinstance(data.get("status"), str):
            data["status"] = WorkflowStatus(data["status"])
        if data.get("steps"):
            data["steps"] = [WorkflowStep.from_dict(s) for s in data["steps"]]
        for dt_field in ["created_at", "started_at", "completed_at"]:
            if data.get(dt_field) and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])
        return cls(**data)


# Pre-built workflow templates
WORKFLOW_TEMPLATES = {
    "full_network_assessment": {
        "name": "Full Network Assessment",
        "description": "Complete network enumeration: nmap → SMB enum → credential harvest",
        "tags": ["network", "assessment", "comprehensive"],
        "steps": [
            {
                "name": "Network Discovery",
                "module": "recon/nmap_fast",
                "options": {"BACKGROUND": "false"},
            },
            {
                "name": "Comprehensive Port Scan",
                "module": "recon/nmap_comprehensive",
                "options": {"BACKGROUND": "false"},
                "conditions": [{"type": "step_success", "step": "step_1"}],
            },
            {
                "name": "SMB Enumeration",
                "module": "smb/enumeration",
                "options": {},
                "conditions": [{"type": "service_found", "service": "smb"}],
            },
            {
                "name": "SMB Share Spider",
                "module": "network/nxc_smb",
                "operation": "Spider Configured (No Download)",
                "options": {},
                "conditions": [{"type": "step_success", "step": "step_3"}],
            },
            {
                "name": "Credential Dump",
                "module": "impacket/secretsdump",
                "options": {},
                "conditions": [{"type": "has_admin_creds"}],
            },
        ],
    },
    "web_application_test": {
        "name": "Web Application Test",
        "description": "Web app assessment: httpx → feroxbuster → nuclei → sqlmap",
        "tags": ["web", "assessment"],
        "steps": [
            {
                "name": "HTTP Probe",
                "module": "web/httpx",
                "options": {},
            },
            {
                "name": "Directory Discovery",
                "module": "web/feroxbuster",
                "options": {},
                "conditions": [{"type": "step_success", "step": "step_1"}],
            },
            {
                "name": "Recorded Form Import",
                "module": "web/forms",
                "operation": "Import Forms",
                "options": {"HTML_FILE": "$html_file"},
                "conditions": [
                    {"type": "step_success", "step": "step_1"},
                    {"type": "variable_set", "variable": "html_file"},
                ],
            },
            {
                "name": "Vulnerability Scan",
                "module": "recon/nuclei",
                "operation": "Critical/High Only",
                "options": {},
                "conditions": [{"type": "step_success", "step": "step_1"}],
            },
            {
                "name": "SQL Injection Testing",
                "module": "web/sqlmap",
                "options": {},
                "conditions": [{"type": "forms_found"}],
            },
        ],
    },
    "ad_assessment": {
        "name": "Active Directory Assessment",
        "description": "AD attack chain: LDAP enum → Kerberoast → AS-REP roast",
        "tags": ["active-directory", "assessment"],
        "steps": [
            {
                "name": "LDAP Enumeration",
                "module": "network/nxc_ldap",
                "operation": "Enumerate Users",
                "options": {},
            },
            {
                "name": "User Enumeration",
                "module": "ad/kerbrute",
                "operation": "User Enumeration",
                "options": {},
                "conditions": [{"type": "step_success", "step": "step_1"}],
            },
            {
                "name": "AS-REP Roasting",
                "module": "impacket/asreproast",
                "options": {},
                "conditions": [{"type": "has_user_list"}],
            },
            {
                "name": "Kerberoasting",
                "module": "impacket/kerberoast",
                "options": {},
                "conditions": [{"type": "has_valid_creds"}],
            },
        ],
    },
    "quick_recon": {
        "name": "Quick Reconnaissance",
        "description": "Fast initial recon: nmap fast → httpx → nuclei quick",
        "tags": ["recon", "quick"],
        "steps": [
            {
                "name": "Fast Port Scan",
                "module": "recon/nmap_fast",
                "options": {"BACKGROUND": "false"},
            },
            {
                "name": "HTTP Probe",
                "module": "web/httpx",
                "options": {},
                "conditions": [{"type": "service_found", "service": "http"}],
            },
            {
                "name": "Quick Vuln Scan",
                "module": "recon/nuclei",
                "operation": "Quick Scan",
                "options": {},
                "conditions": [{"type": "step_success", "step": "step_2"}],
            },
        ],
    },
    "osint_recon": {
        "name": "OSINT Reconnaissance",
        "description": "Passive recon: Shodan → crt.sh → DNSDumpster",
        "tags": ["osint", "passive", "recon"],
        "steps": [
            {
                "name": "Shodan Lookup",
                "module": "osint/shodan",
                "operation": "Host Lookup",
                "options": {},
            },
            {
                "name": "Certificate Transparency",
                "module": "osint/crtsh",
                "operation": "Subdomain Enumeration",
                "options": {},
            },
            {
                "name": "DNS Recon",
                "module": "osint/dnsdumpster",
                "operation": "Full DNS Recon",
                "options": {},
            },
        ],
    },
    "credential_harvest": {
        "name": "Credential Harvesting",
        "description": "Credential gathering: SMB spider → LDAP users → AS-REP → Kerberoast",
        "tags": ["credentials", "harvest"],
        "steps": [
            {
                "name": "SMB Share Spider",
                "module": "network/nxc_smb",
                "operation": "Spider Configured (No Download)",
                "options": {},
                "conditions": [{"type": "service_found", "service": "smb"}],
            },
            {
                "name": "LDAP User Enumeration",
                "module": "network/nxc_ldap",
                "operation": "Enumerate Users",
                "options": {},
                "conditions": [{"type": "has_valid_creds"}],
            },
            {
                "name": "AS-REP Roasting",
                "module": "impacket/asreproast",
                "options": {},
                "conditions": [{"type": "has_user_list"}],
            },
            {
                "name": "Kerberoasting",
                "module": "impacket/kerberoast",
                "options": {},
                "conditions": [{"type": "has_valid_creds"}],
            },
        ],
    },
}


class WorkflowEngine:
    """
    Executes and manages workflows.

    Features:
    - Step-by-step execution
    - Conditional branching
    - Variable passing between steps
    - Progress tracking
    - Pause/resume support
    """

    def __init__(self, framework=None, storage_path=None):
        self.framework = framework
        self.workflows: Dict[str, Workflow] = {}
        self.storage_path = Path(storage_path) if storage_path else Path.home() / ".purplesploit" / "workflows"
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Callbacks
        self.on_step_start: Optional[Callable] = None
        self.on_step_complete: Optional[Callable] = None
        self.on_workflow_complete: Optional[Callable] = None

    def create_workflow(
        self,
        name: str,
        description: str = "",
        from_template: Optional[str] = None,
    ) -> Workflow:
        """Create a new workflow."""
        import uuid
        workflow_id = str(uuid.uuid4())[:8]

        if from_template and from_template in WORKFLOW_TEMPLATES:
            template = copy.deepcopy(WORKFLOW_TEMPLATES[from_template])
            workflow = Workflow(
                id=workflow_id,
                name=template["name"],
                description=template["description"],
                tags=template.get("tags", []),
            )

            for i, step_config in enumerate(template["steps"], 1):
                step = WorkflowStep(id=f"step_{i}", **step_config)
                workflow.steps.append(step)
        else:
            workflow = Workflow(
                id=workflow_id,
                name=name,
                description=description,
            )

        self.workflows[workflow_id] = workflow
        self._save_workflow(workflow)
        return workflow

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get a workflow by ID."""
        return self.workflows.get(workflow_id) or self.load_workflow(workflow_id)

    def list_workflows(self) -> List[Workflow]:
        """List all workflows."""
        for path in sorted(self.storage_path.glob("*.json")):
            if path.stem not in self.workflows:
                try:
                    self.load_workflow(path.stem)
                except (ValueError, TypeError, OSError):
                    continue
        return list(self.workflows.values())

    def list_templates(self) -> List[Dict[str, Any]]:
        """List available workflow templates."""
        return [
            {
                "id": template_id,
                "name": template["name"],
                "description": template["description"],
                "tags": template.get("tags", []),
                "steps": len(template["steps"]),
            }
            for template_id, template in WORKFLOW_TEMPLATES.items()
        ]

    def run_workflow(
        self,
        workflow_id: str,
        variables: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Run under a process lock so recovery cannot mistake a live run for a crash."""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        # Recover an orphaned checkpoint before acquiring our own runner lock.
        workflow = self.get_workflow(workflow_id)
        if workflow is None:
            return {"success": False, "error": "Workflow not found"}
        lock_path = self._workflow_file(workflow_id).with_suffix(".lock")
        with open(lock_path, "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {"success": False, "error": "Workflow is already running"}
            try:
                return self._run_workflow(workflow_id, variables, dry_run)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _run_workflow(
        self,
        workflow_id: str,
        variables: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Run a workflow.

        Args:
            workflow_id: Workflow to run
            variables: Initial variables (target, credentials, etc.)
            dry_run: If True, just validate without executing

        Returns:
            Execution results
        """
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            return {"success": False, "error": "Workflow not found"}

        if workflow.status == WorkflowStatus.RUNNING:
            return {"success": False, "error": "Workflow is already running"}

        if variables:
            workflow.variables.update(variables)

        # Validate workflow
        validation = self._validate_workflow(workflow)
        if not validation["valid"]:
            return {"success": False, "error": validation["error"]}

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "steps": len(workflow.steps),
                "validation": validation,
            }

        # Start or continue execution. A resumed workflow retains its original
        # start time and terminal step states.
        workflow.status = WorkflowStatus.RUNNING
        if workflow.started_at is None:
            workflow.started_at = datetime.utcnow()
        workflow.completed_at = None
        workflow.current_step_id = None
        self._save_workflow(workflow)

        results = {
            "success": False,
            "workflow_id": workflow_id,
            "steps_completed": 0,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_pending": 0,
            "step_results": [],
            "status": workflow.status.value,
        }

        try:
            for step in workflow.steps:
                # A pause requested while a step is executing takes effect at
                # the next safe boundary, before another step starts.
                if workflow.status == WorkflowStatus.PAUSED:
                    workflow.current_step_id = None
                    break

                # Success, failure, and condition skips are persisted work.
                # Resume must continue from pending work rather than replay it.
                if step.status != StepStatus.PENDING:
                    continue

                workflow.current_step_id = step.id

                # Check conditions
                if not self._branch_selected(step, workflow) or not self._check_conditions(step, workflow):
                    step.status = StepStatus.SKIPPED
                    step.completed_at = datetime.utcnow()
                    workflow.current_step_id = None
                    self._save_workflow(workflow)
                    continue

                # Execute step
                step_result = self._execute_step(step, workflow)
                workflow.current_step_id = None
                self._save_workflow(workflow)

                # Check if we should continue after a failure. The result
                # summary is rebuilt from all persisted steps below.
                if not step_result["success"] and not step.on_failure:
                    break

            if workflow.status == WorkflowStatus.PAUSED:
                workflow.completed_at = None
            elif any(step.status == StepStatus.FAILED for step in workflow.steps):
                workflow.status = WorkflowStatus.FAILED
                workflow.completed_at = datetime.utcnow()
            elif any(
                step.status in {StepStatus.PENDING, StepStatus.RUNNING}
                for step in workflow.steps
            ):
                workflow.status = WorkflowStatus.FAILED
                workflow.completed_at = datetime.utcnow()
                results["error"] = "Workflow stopped with incomplete steps"
            else:
                workflow.status = WorkflowStatus.COMPLETED
                workflow.completed_at = datetime.utcnow()

        except Exception as e:
            workflow.status = WorkflowStatus.FAILED
            workflow.completed_at = datetime.utcnow()
            workflow.current_step_id = None
            results["error"] = str(e)

        self._update_result_summary(workflow, results)

        # A paused workflow is not complete; defer its completion callback
        # until it reaches a terminal state after resume.
        if (
            self.on_workflow_complete
            and workflow.status in {
                WorkflowStatus.COMPLETED,
                WorkflowStatus.FAILED,
            }
        ):
            self.on_workflow_complete(workflow, results)

        self._save_workflow(workflow)
        return results

    def pause_workflow(self, workflow_id: str) -> bool:
        """Pause a running workflow."""
        workflow = self.get_workflow(workflow_id)
        if workflow and workflow.status == WorkflowStatus.RUNNING:
            workflow.status = WorkflowStatus.PAUSED
            workflow.completed_at = None
            self._save_workflow(workflow)
            return True
        return False

    def resume_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Resume a paused workflow."""
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            return {"success": False, "error": "Workflow not found"}

        if workflow.status != WorkflowStatus.PAUSED:
            return {"success": False, "error": "Workflow is not paused"}
        if any(step.status == StepStatus.RUNNING for step in workflow.steps):
            return {"success": False, "error": "Workflow has an unresolved running step; reconcile its result before resuming"}

        # run_workflow preserves terminal steps and either continues pending
        # work or finalizes a workflow paused after its last step.
        return self.run_workflow(workflow_id)

    @staticmethod
    def _update_result_summary(
        workflow: Workflow,
        results: Dict[str, Any],
    ) -> None:
        """Rebuild an execution summary from the complete persisted workflow."""
        results["steps_completed"] = sum(
            step.status == StepStatus.SUCCESS for step in workflow.steps
        )
        results["steps_failed"] = sum(
            step.status == StepStatus.FAILED for step in workflow.steps
        )
        results["steps_skipped"] = sum(
            step.status == StepStatus.SKIPPED for step in workflow.steps
        )
        results["steps_pending"] = sum(
            step.status in {StepStatus.PENDING, StepStatus.RUNNING}
            for step in workflow.steps
        )
        results["status"] = workflow.status.value
        results["success"] = workflow.status == WorkflowStatus.COMPLETED

        step_results = []
        for step in workflow.steps:
            if step.status == StepStatus.SUCCESS:
                step_results.append({
                    "step_id": step.id,
                    "step_name": step.name,
                    "module": step.module,
                    "success": True,
                    "status": step.status.value,
                    "result": step.result,
                })
            elif step.status == StepStatus.FAILED:
                step_results.append({
                    "step_id": step.id,
                    "step_name": step.name,
                    "module": step.module,
                    "success": False,
                    "status": step.status.value,
                    "result": step.result,
                    "error": step.error or "Unknown error",
                })
            elif step.status == StepStatus.SKIPPED:
                step_results.append({
                    "step_id": step.id,
                    "status": step.status.value,
                    "reason": "Conditions not met",
                })
        results["step_results"] = step_results

        if workflow.status == WorkflowStatus.FAILED and "error" not in results:
            failed_step = next(
                (
                    step for step in workflow.steps
                    if step.status == StepStatus.FAILED
                ),
                None,
            )
            results["error"] = (
                failed_step.error
                if failed_step and failed_step.error
                else "One or more workflow steps failed"
            )

    def _validate_workflow(self, workflow: Workflow) -> Dict[str, Any]:
        """Validate a workflow before execution."""
        if not workflow.steps:
            return {"valid": False, "error": "Workflow has no steps"}

        positions = {step.id: index for index, step in enumerate(workflow.steps)}
        if len(positions) != len(workflow.steps):
            return {"valid": False, "error": "Duplicate workflow step IDs"}
        for step in workflow.steps:
            if step.timeout <= 0 or step.retry_count < 0:
                return {"valid": False, "error": "Timeout must be positive and retry_count nonnegative"}
            for destination in step.on_success + step.on_failure:
                if destination not in positions or positions[destination] <= positions[step.id]:
                    return {"valid": False, "error": f"Branch must reference a later step: {destination}"}
            background = step.options.get("BACKGROUND", False)
            if str(background).lower() in {"true", "1", "yes"}:
                return {"valid": False, "error": "Background execution is unsupported in deterministic workflows"}

        # Completed and skipped steps are immutable on resume, so only pending
        # work must still satisfy execution prerequisites.
        pending_steps = [
            step for step in workflow.steps
            if step.status == StepStatus.PENDING
        ]

        if pending_steps and self.framework is None:
            return {"valid": False, "error": "No framework available"}

        # Check required variables
        required_vars = set()
        for step in pending_steps:
            guarded_variables = {
                condition.get("variable")
                for condition in step.conditions
                if condition.get("type") == "variable_set"
            }
            for opt_name, opt_value in step.options.items():
                if isinstance(opt_value, str) and opt_value.startswith("$"):
                    variable = opt_value[1:]
                    if variable not in guarded_variables:
                        required_vars.add(variable)

        missing_vars = required_vars - set(workflow.variables.keys())
        if missing_vars:
            return {
                "valid": False,
                "error": f"Missing variables: {', '.join(missing_vars)}",
            }

        # Inspection creates a detached instance and never activates a module.
        for step in pending_steps:
            try:
                metadata = self.framework.get_module(step.module)
            except Exception as exc:
                return {
                    "valid": False,
                    "error": f"Unable to inspect module {step.module}: {exc}",
                }
            if metadata is None:
                return {
                    "valid": False,
                    "error": f"Module not found: {step.module}",
                }

            if step.operation:
                try:
                    instantiate = getattr(type(self.framework), "instantiate_module", None)
                    if callable(instantiate):
                        module_instance = self.framework.instantiate_module(step.module)
                    else:
                        module_instance = metadata.instance(self.framework)
                except Exception as exc:
                    return {
                        "valid": False,
                        "error": f"Unable to load module {step.module}: {exc}",
                    }
                if module_instance is None:
                    return {
                        "valid": False,
                        "error": f"Unable to load module: {step.module}",
                    }

                operation = self._find_operation(module_instance, step.operation)
                if operation is None:
                    return {
                        "valid": False,
                        "error": (
                            f"Operation not found for {step.module}: "
                            f"{step.operation}"
                        ),
                    }
                if operation.get("interactive") is True or operation.get("background") is True:
                    return {"valid": False, "error": f"Operation requires interactive or background execution: {step.operation}"}

        supported_conditions = {
            "step_success",
            "step_failed",
            "service_found",
            "has_valid_creds",
            "has_admin_creds",
            "has_user_list",
            "forms_found",
            "variable_set",
            "variable_equals",
        }
        for step in pending_steps:
            for condition in step.conditions:
                condition_type = condition.get("type")
                if condition_type not in supported_conditions:
                    return {
                        "valid": False,
                        "error": f"Unsupported condition type: {condition_type!r}",
                    }

        return {"valid": True}

    @staticmethod
    def _branch_selected(step: WorkflowStep, workflow: Workflow) -> bool:
        """Branch destinations execute only after a matching incoming outcome.

        Non-destinations retain ordinary sequential execution. Multiple incoming
        branches are alternatives; conditions on the destination remain ANDed.
        Forward edges make the sequence deterministic and resumable.
        """
        incoming = [source for source in workflow.steps if step.id in source.on_success + source.on_failure]
        return not incoming or any(
            (source.status == StepStatus.SUCCESS and step.id in source.on_success)
            or (source.status == StepStatus.FAILED and step.id in source.on_failure)
            for source in incoming
        )

    def _check_conditions(self, step: WorkflowStep, workflow: Workflow) -> bool:
        """Check if step conditions are met."""
        if not step.conditions:
            return True

        for condition in step.conditions:
            cond_type = condition.get("type")

            if cond_type == "step_success":
                target_step = workflow.get_step(condition.get("step"))
                if not target_step or target_step.status != StepStatus.SUCCESS:
                    return False

            elif cond_type == "step_failed":
                target_step = workflow.get_step(condition.get("step"))
                if not target_step or target_step.status != StepStatus.FAILED:
                    return False

            elif cond_type == "service_found":
                # Check if service was discovered
                service = condition.get("service")
                if not self._service_exists(service, workflow):
                    return False

            elif cond_type == "has_valid_creds":
                if not self._scoped_values(workflow.variables.get("credentials", []), workflow):
                    return False

            elif cond_type == "has_admin_creds":
                creds = self._scoped_values(workflow.variables.get("credentials", []), workflow)
                if not any(c.get("is_admin") for c in creds if isinstance(c, dict)):
                    return False

            elif cond_type == "has_user_list":
                if not self._scoped_values(workflow.variables.get("user_list", []), workflow):
                    return False

            elif cond_type == "forms_found":
                if not self._scoped_values(workflow.variables.get("forms", []), workflow):
                    return False

            elif cond_type == "variable_set":
                var_name = condition.get("variable")
                if var_name not in workflow.variables:
                    return False

            elif cond_type == "variable_equals":
                var_name = condition.get("variable")
                expected = condition.get("value")
                if workflow.variables.get(var_name) != expected:
                    return False

            else:
                # Conditions control whether active assessment steps execute.
                # Unknown condition types must never be treated as permission
                # to continue.
                return False

        return True

    def _service_exists(self, service: str, workflow: Workflow) -> bool:
        """Check if a service was discovered."""
        if not isinstance(service, str) or not service:
            return False

        # Check workflow variables
        services = self._scoped_values(workflow.variables.get("services", []), workflow)
        for svc in services:
            if isinstance(svc, dict):
                if service.lower() in svc.get("service", "").lower():
                    return True
            elif isinstance(svc, str):
                if service.lower() in svc.lower():
                    return True

        # Check framework database
        target = workflow.variables.get("target")
        if self.framework and target:
            try:
                session_services = self.framework.session.services.services
                if isinstance(session_services, dict):
                    for host, names in session_services.items():
                        if self._target_matches({"target": host}, target) and any(service.lower() in name.lower() for name in names):
                            return True
                # CIDR workflows may include several hosts; filter every row
                # explicitly instead of trusting an unscoped database match.
                db_services = self.framework.database.get_services()
                for svc in db_services:
                    if not self._target_matches(svc, target, allow_unscoped=False):
                        continue
                    if isinstance(svc, dict):
                        service_name = svc.get("service", "")
                    else:
                        service_name = getattr(svc, "service", "")
                    if service.lower() in str(service_name).lower():
                        return True
            except Exception:
                pass

        return False

    @staticmethod
    def _target_matches(value, target, allow_unscoped=True):
        if not isinstance(value, dict):
            return allow_unscoped
        source = value.get("target") or value.get("host") or value.get("ip") or value.get("url")
        if not source:
            return allow_unscoped
        if not target:
            return False

        def host(text):
            text = str(text)
            return (urlsplit(text).hostname if "://" in text else text).rstrip(".").lower()

        source, target = host(source), host(target)
        try:
            return ipaddress.ip_address(source) in ipaddress.ip_network(target, strict=False)
        except ValueError:
            return source == target

    def _scoped_values(self, values, workflow):
        return [value for value in values if self._target_matches(value, workflow.variables.get("target"))]

    def _execute_step(
        self,
        step: WorkflowStep,
        workflow: Workflow,
    ) -> Dict[str, Any]:
        """Retry completed failed attempts, checkpointing before each launch.

        Process deadlines are passed to the execution adapter. Python handlers
        cannot be forcibly stopped; an elapsed deadline is reported after they
        return. Unknown background completion never triggers a retry.
        """
        result = {}
        for _ in range(step.retry_count + 1):
            step.attempts += 1
            step.status = StepStatus.RUNNING
            step.error = None
            step.completed_at = None
            step.started_at = datetime.utcnow()
            self._save_workflow(workflow)
            started = time.monotonic()
            result = self._execute_attempt(step, workflow)
            if time.monotonic() - started > step.timeout and step.status == StepStatus.SUCCESS:
                step.status = StepStatus.FAILED
                step.error = f"Step exceeded timeout of {step.timeout} seconds"
                step.result = {**(step.result or {}), "success": False, "outcome": "timed_out", "timed_out": True, "error": step.error}
                result.update(success=False, error=step.error, result=step.result)
            if step.status == StepStatus.SUCCESS:
                self._extract_workflow_data(step.result or {}, workflow)
            self._save_workflow(workflow)
            if self.on_step_complete and step.status != StepStatus.RUNNING:
                self.on_step_complete(workflow, step, result)
            if step.status != StepStatus.FAILED or workflow.status == WorkflowStatus.PAUSED:
                break
        return result

    def _execute_attempt(
        self,
        step: WorkflowStep,
        workflow: Workflow,
    ) -> Dict[str, Any]:
        """Execute a single workflow step."""
        step.status = StepStatus.RUNNING
        step.started_at = datetime.utcnow()

        # Callback
        if self.on_step_start:
            self.on_step_start(workflow, step)

        result = {
            "step_id": step.id,
            "step_name": step.name,
            "module": step.module,
            "success": False,
        }

        try:
            if not self.framework:
                result["error"] = "No framework available"
                step.status = StepStatus.FAILED
                step.error = result["error"]
                return result

            # Inspect/configure a detached instance. The execution request
            # creates its own instance, so a workflow must not replace the
            # operator's currently selected interactive module.
            instantiate = getattr(type(self.framework), "instantiate_module", None)
            if callable(instantiate):
                module_instance = self.framework.instantiate_module(step.module)
            else:
                # Compatibility for lightweight framework doubles and older
                # embedders that do not expose the detached-instance seam.
                module_instance = self.framework.use_module(step.module)
            if not module_instance:
                result["error"] = f"Module not found: {step.module}"
                step.status = StepStatus.FAILED
                step.error = result["error"]
                raise RuntimeError(result["error"])

            # Set options (with variable substitution)
            resolved_options = self._resolve_variables(step.options, workflow.variables)
            for opt_name, opt_value in resolved_options.items():
                if not module_instance.set_option(opt_name, opt_value):
                    raise ValueError(
                        f"Unknown option for {step.module}: {opt_name}"
                    )

            # Set target from workflow variables
            if workflow.variables.get("target"):
                target = workflow.variables["target"]
                if "RHOST" in module_instance.options and "RHOST" not in resolved_options:
                    module_instance.set_option("RHOST", target)
                if "TARGET" in module_instance.options and "TARGET" not in resolved_options:
                    module_instance.set_option("TARGET", target)
                if "URL" in module_instance.options and "URL" not in resolved_options and "://" in str(target):
                    module_instance.set_option("URL", target)

            # Bind data produced by earlier steps before the request snapshot is
            # made.  Remote and local executors then receive the same explicit,
            # deterministic values instead of depending on mutable session state.
            bound_options = self._bind_workflow_context(
                module_instance, step, workflow, set(resolved_options)
            )
            module_instance.options_locked.update(
                set(resolved_options)
                | bound_options
                | {
                    key
                    for key in ("RHOST", "TARGET", "URL")
                    if key in module_instance.options
                }
            )
            # Fill any remaining unset options from the operator's selected
            # session context. Explicit and workflow-bound values stay locked.
            module_instance.auto_set_from_context()

            # Execute through Framework so workflow runs get the same option
            # validation, result recording, redaction, and audit behavior as
            # interactive module execution.
            from purplesploit.core.execution import ExecutionRequest
            request = ExecutionRequest(
                module_path=step.module,
                operation_name=step.operation,
                options={key: module_instance.get_option(key) for key in module_instance.options},
                options_locked=set(module_instance.options_locked),
                timeout_s=step.timeout,
                background=False,
                stdin="none",
            )
            module_instance.execution_request = request
            execute_request = getattr(type(self.framework), "execute_request", None)
            if callable(execute_request):
                execution = self.framework.execute_request(request)
                module_result = dict(execution.raw_result)
                module_result.update(success=execution.success, outcome=execution.outcome.value,
                                     timed_out=execution.timed_out, error=execution.error,
                                     observations=[item.to_dict() for item in execution.observations])
            elif step.operation:
                operation = self._find_operation(module_instance, step.operation)
                if operation is None:
                    raise ValueError(
                        f"Operation not found for {step.module}: {step.operation}"
                    )
                module_result = self.framework.run_operation(
                    module_instance,
                    operation,
                )
            else:
                module_result = self.framework.run_module(module_instance)

            if not isinstance(module_result, dict):
                module_result = {
                    "success": False,
                    "error": "Framework returned an invalid module result",
                }

            # Process result
            step.result = module_result
            result["result"] = module_result

            if module_result.get("background") or module_result.get("outcome") == "running" or module_result.get("job_id") and not module_result.get("finished_at"):
                step.status = StepStatus.RUNNING
                step.error = "Background completion is unknown; workflow paused for reconciliation"
                workflow.status = WorkflowStatus.PAUSED
                result["error"] = step.error
                return result

            if module_result.get("success"):
                step.status = StepStatus.SUCCESS
                result["success"] = True
            else:
                step.status = StepStatus.FAILED
                step.error = module_result.get("error", "Unknown error")
                result["error"] = step.error

        except Exception as e:
            step.status = StepStatus.FAILED
            step.error = str(e)
            result["error"] = str(e)

        step.completed_at = datetime.utcnow()

        return result

    def _bind_workflow_context(
        self,
        module_instance: Any,
        step: WorkflowStep,
        workflow: Workflow,
        explicit_options: set[str],
    ) -> set[str]:
        """Bind scoped credentials, identities, and domains into one step.

        Workflow observations are the durable hand-off between modules. Values
        supplied directly on the step always win, followed by scoped workflow
        observations and finally the interactive session context.
        """
        explicit = {name.upper() for name in explicit_options}
        bound: set[str] = set()

        def set_if_empty(option: str, value: Any) -> None:
            if (
                option in module_instance.options
                and option not in explicit
                and value not in (None, "")
                and module_instance.get_option(option) in (None, "")
            ):
                module_instance.set_option(option, value)
                bound.add(option)

        credentials = self._scoped_values(
            workflow.variables.get("credentials", []), workflow
        )
        if any(
            condition.get("type") == "has_admin_creds"
            for condition in step.conditions
        ):
            credentials = [
                credential
                for credential in credentials
                if isinstance(credential, dict) and credential.get("is_admin")
            ]
        credential = next(
            (value for value in credentials if isinstance(value, dict)), None
        )
        if credential:
            mappings = {
                "USERNAME": ("username", "user", "name"),
                "PASSWORD": ("password", "secret"),
                "HASH": ("hash", "ntlm", "nthash"),
                "DOMAIN": ("domain", "realm"),
                "DCIP": ("dcip", "dc_ip"),
                "DC_IP": ("dc_ip", "dcip"),
                "DNS": ("dns",),
            }
            for option, keys in mappings.items():
                set_if_empty(
                    option,
                    next(
                        (credential.get(key) for key in keys if credential.get(key) not in (None, "")),
                        None,
                    ),
                )

        users = self._scoped_values(workflow.variables.get("user_list", []), workflow)
        usernames = []
        domains = []
        for value in users:
            if isinstance(value, dict):
                username = value.get("username") or value.get("user") or value.get("name")
                domain = value.get("domain") or value.get("realm")
            else:
                username, domain = value, None
            if username and str(username) not in usernames:
                usernames.append(str(username))
            if domain and str(domain) not in domains:
                domains.append(str(domain))
        if usernames:
            set_if_empty("USERNAME", usernames[0])
            for option in ("USERLIST", "USERFILE"):
                if option not in module_instance.options or option in explicit:
                    continue
                step_name = "".join(
                    character if character.isalnum() or character in "-_" else "_"
                    for character in step.id
                )
                artifact_dir = self.storage_path / "artifacts" / workflow.id / step_name
                artifact_dir.mkdir(parents=True, exist_ok=True)
                user_file = artifact_dir / "users.txt"
                user_file.write_text("".join(f"{username}\n" for username in usernames), encoding="utf-8")
                set_if_empty(option, str(user_file))
        if domains:
            set_if_empty("DOMAIN", domains[0])

        return bound

    @staticmethod
    def _find_operation(
        module_instance: Any,
        operation_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Return an exact named operation from a live module instance."""
        finder = getattr(type(module_instance.framework), "find_operation", None)
        if callable(finder):
            return module_instance.framework.find_operation(module_instance, operation_name)
        if not module_instance.has_operations():
            return None

        for operation in module_instance.get_operations():
            if operation.get("name") == operation_name:
                return operation
        return None

    def _resolve_variables(
        self,
        options: Dict[str, Any],
        variables: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Resolve variable references in options."""
        resolved = {}
        for key, value in options.items():
            if isinstance(value, str) and value.startswith("$"):
                var_name = value[1:]
                resolved[key] = variables.get(var_name, value)
            else:
                resolved[key] = value
        return resolved

    def _extract_workflow_data(
        self,
        result: Dict[str, Any],
        workflow: Workflow,
    ) -> None:
        """Extract relevant data from step result to workflow variables."""
        typed_destinations = set()
        for observation in result.get("observations", []):
            kind = observation.get("kind")
            destination = {"service": "services", "credential": "credentials", "form": "forms", "user": "user_list", "finding": "findings"}.get(kind)
            if destination:
                typed_destinations.add(destination)
                value = {**observation.get("attributes", {}), **observation}
                if value not in workflow.variables.setdefault(destination, []):
                    workflow.variables[destination].append(value)
        # Extract credentials
        if result.get("credentials") and "credentials" not in typed_destinations:
            if "credentials" not in workflow.variables:
                workflow.variables["credentials"] = []
            workflow.variables["credentials"].extend(result["credentials"])

        # Extract users
        if (result.get("users") or result.get("user_list")) and "user_list" not in typed_destinations:
            users = result.get("users") or result.get("user_list", [])
            if "user_list" not in workflow.variables:
                workflow.variables["user_list"] = []
            workflow.variables["user_list"].extend(users)

        # Extract services
        if result.get("services") and "services" not in typed_destinations:
            if "services" not in workflow.variables:
                workflow.variables["services"] = []
            workflow.variables["services"].extend(result["services"])

        # Extract findings
        if result.get("findings") and "findings" not in typed_destinations:
            if "findings" not in workflow.variables:
                workflow.variables["findings"] = []
            workflow.variables["findings"].extend(result["findings"])

        # Preserve discovered web forms for the built-in forms_found
        # condition used by web assessment workflows.
        if result.get("forms") and "forms" not in typed_destinations:
            if "forms" not in workflow.variables:
                workflow.variables["forms"] = []
            workflow.variables["forms"].extend(result["forms"])

    def _save_workflow(self, workflow: Workflow) -> None:
        """Atomically checkpoint a workflow, including before external work."""
        workflow_file = self._workflow_file(workflow.id)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=self.storage_path, prefix=".workflow-", delete=False) as handle:
                temporary = handle.name
                json.dump(workflow.to_dict(), handle, indent=2, default=str)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, workflow_file)
            directory = os.open(self.storage_path, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def _workflow_file(self, workflow_id: str) -> Path:
        if not workflow_id or Path(workflow_id).name != workflow_id or workflow_id in {".", ".."}:
            raise ValueError("Invalid workflow ID")
        return self.storage_path / f"{workflow_id}.json"

    def save_workflow(self, workflow_id: str) -> bool:
        """Persist edits made to a workflow definition or its variables."""
        workflow = self.workflows.get(workflow_id)
        if workflow is None:
            return False
        self._save_workflow(workflow)
        return True

    def load_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Load a workflow from storage."""
        workflow_file = self._workflow_file(workflow_id)
        if workflow_file.exists():
            with open(workflow_file, 'r') as f:
                data = json.load(f)
                workflow = Workflow.from_dict(data)
                if workflow.id != workflow_id:
                    raise ValueError("Stored workflow ID does not match filename")
                if (workflow.status == WorkflowStatus.RUNNING or any(step.status == StepStatus.RUNNING for step in workflow.steps)) and not self._has_active_runner(workflow_id):
                    workflow.status = WorkflowStatus.PAUSED
                    workflow.current_step_id = None
                    workflow.completed_at = None
                    for step in workflow.steps:
                        if step.status == StepStatus.RUNNING:
                            step.status = StepStatus.FAILED
                            step.error = "Execution interrupted; external outcome unknown, not automatically replayed"
                            step.result = {"success": False, "outcome": "unknown", "error": step.error}
                            step.completed_at = datetime.utcnow()
                    self._save_workflow(workflow)
                self.workflows[workflow_id] = workflow
                return workflow
        return None

    def _has_active_runner(self, workflow_id: str) -> bool:
        with open(self._workflow_file(workflow_id).with_suffix(".lock"), "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(lock, fcntl.LOCK_UN)
        return False

    def export_workflow(self, workflow_id: str, output_path: str) -> bool:
        """Export a workflow to a file."""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False

        with open(output_path, 'w') as f:
            json.dump(workflow.to_dict(), f, indent=2, default=str)
        return True

    def import_workflow(self, input_path: str) -> Optional[Workflow]:
        """Import a workflow from a file."""
        with open(input_path, 'r') as f:
            data = json.load(f)
            workflow = Workflow.from_dict(data)
            self.workflows[workflow.id] = workflow
            self._save_workflow(workflow)
            return workflow
