"""
Workflow Engine for PurpleSploit

Module chaining and automated workflow execution with conditional logic,
parallel execution, and progress tracking.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Set
from datetime import datetime
from enum import Enum
import json
from pathlib import Path
import time


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
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorkflowStep":
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
                "options": {},
            },
            {
                "name": "Comprehensive Port Scan",
                "module": "recon/nmap_comprehensive",
                "options": {},
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
                "operation": "spider",
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
                "options": {},
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
        "description": "Credential gathering: SMB spider → Kerberoast → AS-REP",
        "tags": ["credentials", "harvest"],
        "steps": [
            {
                "name": "SMB Share Spider",
                "module": "network/nxc_smb",
                "operation": "spider",
                "options": {},
                "conditions": [{"type": "service_found", "service": "smb"}],
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

    def __init__(self, framework=None):
        self.framework = framework
        self.workflows: Dict[str, Workflow] = {}
        self.storage_path = Path.home() / ".purplesploit" / "workflows"
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
            template = WORKFLOW_TEMPLATES[from_template]
            workflow = Workflow(
                id=workflow_id,
                name=template["name"],
                description=template["description"],
                tags=template.get("tags", []),
            )

            for i, step_config in enumerate(template["steps"], 1):
                step = WorkflowStep(
                    id=f"step_{i}",
                    name=step_config["name"],
                    module=step_config["module"],
                    operation=step_config.get("operation"),
                    options=step_config.get("options", {}),
                    conditions=step_config.get("conditions", []),
                )
                workflow.steps.append(step)
        else:
            workflow = Workflow(
                id=workflow_id,
                name=name,
                description=description,
            )

        self.workflows[workflow_id] = workflow
        return workflow

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get a workflow by ID."""
        return self.workflows.get(workflow_id)

    def list_workflows(self) -> List[Workflow]:
        """List all workflows."""
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
        """
        Run a workflow.

        Args:
            workflow_id: Workflow to run
            variables: Initial variables (target, credentials, etc.)
            dry_run: If True, just validate without executing

        Returns:
            Execution results
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return {"success": False, "error": "Workflow not found"}

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

        # Start execution
        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.utcnow()

        results = {
            "success": True,
            "workflow_id": workflow_id,
            "steps_completed": 0,
            "steps_failed": 0,
            "steps_skipped": 0,
            "step_results": [],
        }

        try:
            for step in workflow.steps:
                workflow.current_step_id = step.id

                # Check conditions
                if not self._check_conditions(step, workflow):
                    step.status = StepStatus.SKIPPED
                    results["steps_skipped"] += 1
                    results["step_results"].append({
                        "step_id": step.id,
                        "status": "skipped",
                        "reason": "Conditions not met",
                    })
                    continue

                # Execute step
                step_result = self._execute_step(step, workflow)
                results["step_results"].append(step_result)

                if step_result["success"]:
                    results["steps_completed"] += 1
                else:
                    results["steps_failed"] += 1

                    # Check if we should continue
                    if not step.on_failure:
                        break

            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.utcnow()

        except Exception as e:
            workflow.status = WorkflowStatus.FAILED
            results["success"] = False
            results["error"] = str(e)

        # Callback
        if self.on_workflow_complete:
            self.on_workflow_complete(workflow, results)

        self._save_workflow(workflow)
        return results

    def pause_workflow(self, workflow_id: str) -> bool:
        """Pause a running workflow."""
        workflow = self.workflows.get(workflow_id)
        if workflow and workflow.status == WorkflowStatus.RUNNING:
            workflow.status = WorkflowStatus.PAUSED
            self._save_workflow(workflow)
            return True
        return False

    def resume_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Resume a paused workflow."""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return {"success": False, "error": "Workflow not found"}

        if workflow.status != WorkflowStatus.PAUSED:
            return {"success": False, "error": "Workflow is not paused"}

        # Find where we left off
        start_step = None
        for step in workflow.steps:
            if step.status == StepStatus.PENDING:
                start_step = step
                break

        if not start_step:
            return {"success": False, "error": "No pending steps to resume"}

        # Continue execution from the current step
        return self.run_workflow(workflow_id)

    def _validate_workflow(self, workflow: Workflow) -> Dict[str, Any]:
        """Validate a workflow before execution."""
        if not workflow.steps:
            return {"valid": False, "error": "Workflow has no steps"}

        # Check required variables
        required_vars = set()
        for step in workflow.steps:
            for opt_name, opt_value in step.options.items():
                if isinstance(opt_value, str) and opt_value.startswith("$"):
                    required_vars.add(opt_value[1:])

        missing_vars = required_vars - set(workflow.variables.keys())
        if missing_vars:
            return {
                "valid": False,
                "error": f"Missing variables: {', '.join(missing_vars)}",
            }

        # Check module existence
        for step in workflow.steps:
            if self.framework:
                # Module validation could go here
                pass

        return {"valid": True}

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
                if not workflow.variables.get("credentials"):
                    return False

            elif cond_type == "has_admin_creds":
                creds = workflow.variables.get("credentials", [])
                if not any(c.get("is_admin") for c in creds if isinstance(c, dict)):
                    return False

            elif cond_type == "has_user_list":
                if not workflow.variables.get("user_list"):
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

        return True

    def _service_exists(self, service: str, workflow: Workflow) -> bool:
        """Check if a service was discovered."""
        # Check workflow variables
        services = workflow.variables.get("services", [])
        for svc in services:
            if isinstance(svc, dict):
                if service.lower() in svc.get("service", "").lower():
                    return True
            elif isinstance(svc, str):
                if service.lower() in svc.lower():
                    return True

        # Check framework database
        if self.framework:
            try:
                db_services = self.framework.database.get_all_services()
                for svc in db_services:
                    if service.lower() in svc.service.lower():
                        return True
            except Exception:
                pass

        return False

    def _execute_step(
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

            # Get module
            module_instance = self.framework.get_module(step.module)
            if not module_instance:
                result["error"] = f"Module not found: {step.module}"
                step.status = StepStatus.FAILED
                step.error = result["error"]
                return result

            # Set options (with variable substitution)
            resolved_options = self._resolve_variables(step.options, workflow.variables)
            for opt_name, opt_value in resolved_options.items():
                module_instance.set_option(opt_name, opt_value)

            # Set target from workflow variables
            if workflow.variables.get("target"):
                target = workflow.variables["target"]
                if "RHOST" in module_instance.options:
                    module_instance.set_option("RHOST", target)
                if "TARGET" in module_instance.options:
                    module_instance.set_option("TARGET", target)
                if "URL" in module_instance.options and "://" in str(target):
                    module_instance.set_option("URL", target)

            # Execute
            if step.operation and hasattr(module_instance, f"op_{step.operation.lower().replace(' ', '_')}"):
                handler = getattr(module_instance, f"op_{step.operation.lower().replace(' ', '_')}")
                module_result = handler()
            elif step.operation and module_instance.has_operations():
                ops = module_instance.get_operations()
                for op in ops:
                    if op.get("name") == step.operation:
                        handler = op.get("handler")
                        if callable(handler):
                            module_result = handler()
                        elif isinstance(handler, str) and hasattr(module_instance, handler):
                            module_result = getattr(module_instance, handler)()
                        break
                else:
                    module_result = module_instance.run()
            else:
                module_result = module_instance.run()

            # Process result
            step.result = module_result
            result["result"] = module_result

            if module_result.get("success"):
                step.status = StepStatus.SUCCESS
                result["success"] = True

                # Extract and store relevant data
                self._extract_workflow_data(module_result, workflow)
            else:
                step.status = StepStatus.FAILED
                step.error = module_result.get("error", "Unknown error")
                result["error"] = step.error

        except Exception as e:
            step.status = StepStatus.FAILED
            step.error = str(e)
            result["error"] = str(e)

        step.completed_at = datetime.utcnow()

        # Callback
        if self.on_step_complete:
            self.on_step_complete(workflow, step, result)

        return result

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
        # Extract credentials
        if result.get("credentials"):
            if "credentials" not in workflow.variables:
                workflow.variables["credentials"] = []
            workflow.variables["credentials"].extend(result["credentials"])

        # Extract users
        if result.get("users") or result.get("user_list"):
            users = result.get("users") or result.get("user_list", [])
            if "user_list" not in workflow.variables:
                workflow.variables["user_list"] = []
            workflow.variables["user_list"].extend(users)

        # Extract services
        if result.get("services"):
            if "services" not in workflow.variables:
                workflow.variables["services"] = []
            workflow.variables["services"].extend(result["services"])

        # Extract findings
        if result.get("findings"):
            if "findings" not in workflow.variables:
                workflow.variables["findings"] = []
            workflow.variables["findings"].extend(result["findings"])

    def _save_workflow(self, workflow: Workflow) -> None:
        """Save workflow to storage."""
        workflow_file = self.storage_path / f"{workflow.id}.json"
        with open(workflow_file, 'w') as f:
            json.dump(workflow.to_dict(), f, indent=2, default=str)

    def load_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Load a workflow from storage."""
        workflow_file = self.storage_path / f"{workflow_id}.json"
        if workflow_file.exists():
            with open(workflow_file, 'r') as f:
                data = json.load(f)
                workflow = Workflow.from_dict(data)
                self.workflows[workflow_id] = workflow
                return workflow
        return None

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
            return workflow
