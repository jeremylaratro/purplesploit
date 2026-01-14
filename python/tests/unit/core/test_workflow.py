"""
Unit tests for purplesploit.core.workflow module.

Tests cover:
- StepStatus and WorkflowStatus enums
- WorkflowStep dataclass
- Workflow dataclass
- WorkflowEngine operations
- Workflow templates
- Conditional execution
- Variable resolution
- Pause/resume functionality
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch

from purplesploit.core.workflow import (
    StepStatus,
    WorkflowStatus,
    WorkflowStep,
    Workflow,
    WorkflowEngine,
    WORKFLOW_TEMPLATES,
)


# =============================================================================
# StepStatus Enum Tests
# =============================================================================

class TestStepStatus:
    """Tests for StepStatus enum."""

    def test_status_values(self):
        """Test all step status values exist."""
        assert StepStatus.PENDING.value == "pending"
        assert StepStatus.RUNNING.value == "running"
        assert StepStatus.SUCCESS.value == "success"
        assert StepStatus.FAILED.value == "failed"
        assert StepStatus.SKIPPED.value == "skipped"


# =============================================================================
# WorkflowStatus Enum Tests
# =============================================================================

class TestWorkflowStatus:
    """Tests for WorkflowStatus enum."""

    def test_status_values(self):
        """Test all workflow status values exist."""
        assert WorkflowStatus.CREATED.value == "created"
        assert WorkflowStatus.RUNNING.value == "running"
        assert WorkflowStatus.PAUSED.value == "paused"
        assert WorkflowStatus.COMPLETED.value == "completed"
        assert WorkflowStatus.FAILED.value == "failed"
        assert WorkflowStatus.CANCELLED.value == "cancelled"


# =============================================================================
# WorkflowStep Tests
# =============================================================================

class TestWorkflowStep:
    """Tests for WorkflowStep dataclass."""

    def test_step_creation(self):
        """Test basic step creation."""
        step = WorkflowStep(
            id="step_1",
            name="Network Scan",
            module="recon/nmap",
        )

        assert step.id == "step_1"
        assert step.name == "Network Scan"
        assert step.module == "recon/nmap"
        assert step.status == StepStatus.PENDING
        assert step.timeout == 600

    def test_step_with_operation(self):
        """Test step with specific operation."""
        step = WorkflowStep(
            id="step_1",
            name="Fast Scan",
            module="recon/nmap",
            operation="Fast Scan",
            options={"ports": "1-1000"},
        )

        assert step.operation == "Fast Scan"
        assert step.options["ports"] == "1-1000"

    def test_step_with_conditions(self):
        """Test step with conditions."""
        step = WorkflowStep(
            id="step_2",
            name="SMB Enum",
            module="smb/enumeration",
            conditions=[
                {"type": "step_success", "step": "step_1"},
                {"type": "service_found", "service": "smb"},
            ],
        )

        assert len(step.conditions) == 2
        assert step.conditions[0]["type"] == "step_success"

    def test_step_with_branching(self):
        """Test step with success/failure branching."""
        step = WorkflowStep(
            id="step_1",
            name="Auth Test",
            module="auth/test",
            on_success=["step_2", "step_3"],
            on_failure=["step_4"],
        )

        assert "step_2" in step.on_success
        assert "step_4" in step.on_failure

    def test_step_to_dict(self):
        """Test step serialization."""
        step = WorkflowStep(
            id="step_1",
            name="Test Step",
            module="test/module",
            operation="Test Op",
            options={"key": "value"},
            timeout=300,
        )
        step.status = StepStatus.SUCCESS
        step.started_at = datetime.now()
        step.completed_at = datetime.now()

        data = step.to_dict()

        assert data["id"] == "step_1"
        assert data["name"] == "Test Step"
        assert data["status"] == "success"
        assert data["timeout"] == 300
        assert "started_at" in data
        assert "completed_at" in data

    def test_step_from_dict(self):
        """Test step deserialization."""
        data = {
            "id": "step_1",
            "name": "Deserialized Step",
            "module": "test/module",
            "operation": "Op",
            "options": {"opt": "val"},
            "conditions": [],
            "on_success": [],
            "on_failure": [],
            "timeout": 120,
            "retry_count": 2,
            "status": "success",
            "result": {"data": "test"},
            "started_at": "2024-01-15T10:00:00",
            "completed_at": "2024-01-15T10:05:00",
            "error": None,
        }

        step = WorkflowStep.from_dict(data)

        assert step.id == "step_1"
        assert step.status == StepStatus.SUCCESS
        assert step.retry_count == 2
        assert isinstance(step.started_at, datetime)


# =============================================================================
# Workflow Tests
# =============================================================================

class TestWorkflow:
    """Tests for Workflow dataclass."""

    def test_workflow_creation(self):
        """Test basic workflow creation."""
        workflow = Workflow(
            id="wf_1",
            name="Test Workflow",
            description="A test workflow",
        )

        assert workflow.id == "wf_1"
        assert workflow.name == "Test Workflow"
        assert workflow.status == WorkflowStatus.CREATED
        assert workflow.steps == []

    def test_add_step(self):
        """Test adding steps to workflow."""
        workflow = Workflow(
            id="wf_1",
            name="Test",
        )

        step = workflow.add_step(
            name="Scan",
            module="recon/nmap",
            operation="Fast Scan",
        )

        assert len(workflow.steps) == 1
        assert step.id == "step_1"
        assert step.name == "Scan"

    def test_add_multiple_steps(self):
        """Test adding multiple steps."""
        workflow = Workflow(id="wf_1", name="Test")

        workflow.add_step(name="Step 1", module="module1")
        workflow.add_step(name="Step 2", module="module2")
        workflow.add_step(name="Step 3", module="module3")

        assert len(workflow.steps) == 3
        assert workflow.steps[0].id == "step_1"
        assert workflow.steps[1].id == "step_2"
        assert workflow.steps[2].id == "step_3"

    def test_get_step(self):
        """Test getting a step by ID."""
        workflow = Workflow(id="wf_1", name="Test")
        workflow.add_step(name="Target Step", module="test")

        step = workflow.get_step("step_1")

        assert step is not None
        assert step.name == "Target Step"

    def test_get_step_nonexistent(self):
        """Test getting non-existent step returns None."""
        workflow = Workflow(id="wf_1", name="Test")

        assert workflow.get_step("nonexistent") is None

    def test_workflow_to_dict(self):
        """Test workflow serialization."""
        workflow = Workflow(
            id="wf_1",
            name="Serialized Workflow",
            description="Test desc",
            tags=["test", "unit"],
        )
        workflow.add_step(name="Step", module="mod")
        workflow.variables = {"target": "192.168.1.1"}

        data = workflow.to_dict()

        assert data["id"] == "wf_1"
        assert data["name"] == "Serialized Workflow"
        assert len(data["steps"]) == 1
        assert data["variables"]["target"] == "192.168.1.1"
        assert "test" in data["tags"]

    def test_workflow_from_dict(self):
        """Test workflow deserialization."""
        data = {
            "id": "wf_1",
            "name": "Imported Workflow",
            "description": "Imported",
            "steps": [
                {
                    "id": "step_1",
                    "name": "Step 1",
                    "module": "mod",
                    "operation": None,
                    "options": {},
                    "conditions": [],
                    "on_success": [],
                    "on_failure": [],
                    "timeout": 600,
                    "retry_count": 0,
                    "status": "pending",
                    "result": None,
                    "started_at": None,
                    "completed_at": None,
                    "error": None,
                }
            ],
            "variables": {"var": "value"},
            "status": "completed",
            "created_at": "2024-01-15T10:00:00",
            "started_at": "2024-01-15T10:01:00",
            "completed_at": "2024-01-15T10:10:00",
            "current_step_id": None,
            "tags": ["imported"],
        }

        workflow = Workflow.from_dict(data)

        assert workflow.id == "wf_1"
        assert workflow.status == WorkflowStatus.COMPLETED
        assert len(workflow.steps) == 1
        assert isinstance(workflow.created_at, datetime)


# =============================================================================
# WorkflowEngine Tests
# =============================================================================

class TestWorkflowEngine:
    """Tests for WorkflowEngine class."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create a WorkflowEngine with mock framework."""
        mock_framework = MagicMock()
        mock_framework.session = MagicMock()
        mock_framework.database = MagicMock()
        mock_framework.database.get_all_services.return_value = []

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)

        return engine

    @pytest.fixture
    def engine_no_framework(self, tmp_path):
        """Create a WorkflowEngine without framework."""
        engine = WorkflowEngine(framework=None)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_initial_state(self, engine):
        """Test initial state of WorkflowEngine."""
        assert engine.workflows == {}
        assert engine.storage_path.exists()

    def test_create_workflow(self, engine):
        """Test creating a new workflow."""
        workflow = engine.create_workflow(
            name="Test Workflow",
            description="Test description",
        )

        assert workflow is not None
        assert workflow.name == "Test Workflow"
        assert workflow.id in engine.workflows

    def test_create_workflow_from_template(self, engine):
        """Test creating workflow from template."""
        workflow = engine.create_workflow(
            name="",
            from_template="quick_recon",
        )

        assert workflow.name == "Quick Reconnaissance"
        assert len(workflow.steps) > 0
        assert "recon" in workflow.tags

    def test_create_workflow_invalid_template(self, engine):
        """Test creating workflow with invalid template."""
        workflow = engine.create_workflow(
            name="Fallback",
            from_template="nonexistent_template",
        )

        assert workflow.name == "Fallback"
        assert len(workflow.steps) == 0

    def test_get_workflow(self, engine):
        """Test getting a workflow by ID."""
        created = engine.create_workflow(name="Test")

        found = engine.get_workflow(created.id)

        assert found is not None
        assert found.id == created.id

    def test_get_workflow_nonexistent(self, engine):
        """Test getting non-existent workflow returns None."""
        assert engine.get_workflow("nonexistent") is None

    def test_list_workflows(self, engine):
        """Test listing all workflows."""
        engine.create_workflow(name="Workflow 1")
        engine.create_workflow(name="Workflow 2")

        workflows = engine.list_workflows()

        assert len(workflows) == 2

    def test_list_templates(self, engine):
        """Test listing available templates."""
        templates = engine.list_templates()

        assert len(templates) > 0
        assert any(t["id"] == "quick_recon" for t in templates)
        assert any(t["id"] == "full_network_assessment" for t in templates)

    def test_run_workflow_no_steps(self, engine):
        """Test running workflow with no steps fails."""
        workflow = engine.create_workflow(name="Empty")

        result = engine.run_workflow(workflow.id)

        assert result["success"] is False
        assert "no steps" in result["error"].lower()

    def test_run_workflow_dry_run(self, engine):
        """Test dry run mode."""
        workflow = engine.create_workflow(name="Test")
        workflow.add_step(name="Step", module="test")

        result = engine.run_workflow(workflow.id, dry_run=True)

        assert result["success"] is True
        assert result["dry_run"] is True
        assert result["steps"] == 1

    def test_run_workflow_with_variables(self, engine):
        """Test running workflow with initial variables."""
        workflow = engine.create_workflow(name="Test")
        workflow.add_step(
            name="Step",
            module="test",
            options={"target": "$target"},
        )

        result = engine.run_workflow(
            workflow.id,
            variables={"target": "192.168.1.1"},
            dry_run=True,
        )

        assert result["success"] is True
        assert workflow.variables["target"] == "192.168.1.1"

    def test_run_workflow_missing_variables(self, engine):
        """Test running workflow with missing required variables."""
        workflow = engine.create_workflow(name="Test")
        workflow.add_step(
            name="Step",
            module="test",
            options={"target": "$required_var"},
        )

        result = engine.run_workflow(workflow.id)

        assert result["success"] is False
        assert "missing variables" in result["error"].lower()

    def test_run_workflow_nonexistent(self, engine):
        """Test running non-existent workflow fails."""
        result = engine.run_workflow("nonexistent")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_pause_workflow(self, engine):
        """Test pausing a running workflow."""
        workflow = engine.create_workflow(name="Test")
        workflow.status = WorkflowStatus.RUNNING

        result = engine.pause_workflow(workflow.id)

        assert result is True
        assert workflow.status == WorkflowStatus.PAUSED

    def test_pause_workflow_not_running(self, engine):
        """Test pausing non-running workflow fails."""
        workflow = engine.create_workflow(name="Test")

        result = engine.pause_workflow(workflow.id)

        assert result is False

    def test_resume_workflow_nonexistent(self, engine):
        """Test resuming non-existent workflow fails."""
        result = engine.resume_workflow("nonexistent")

        assert result["success"] is False

    def test_resume_workflow_not_paused(self, engine):
        """Test resuming non-paused workflow fails."""
        workflow = engine.create_workflow(name="Test")

        result = engine.resume_workflow(workflow.id)

        assert result["success"] is False
        assert "not paused" in result["error"].lower()

    def test_export_workflow(self, engine, tmp_path):
        """Test exporting workflow to file."""
        workflow = engine.create_workflow(name="Export Test")
        workflow.add_step(name="Step", module="test")

        output_path = str(tmp_path / "exported.json")
        result = engine.export_workflow(workflow.id, output_path)

        assert result is True
        assert Path(output_path).exists()

        with open(output_path) as f:
            data = json.load(f)
            assert data["name"] == "Export Test"

    def test_export_workflow_nonexistent(self, engine, tmp_path):
        """Test exporting non-existent workflow fails."""
        result = engine.export_workflow("nonexistent", str(tmp_path / "out.json"))
        assert result is False

    def test_import_workflow(self, engine, tmp_path):
        """Test importing workflow from file."""
        data = {
            "id": "imported_wf",
            "name": "Imported Workflow",
            "description": "Imported",
            "steps": [],
            "variables": {},
            "status": "created",
            "created_at": "2024-01-15T10:00:00",
            "started_at": None,
            "completed_at": None,
            "current_step_id": None,
            "tags": [],
        }

        input_path = str(tmp_path / "import.json")
        with open(input_path, 'w') as f:
            json.dump(data, f)

        workflow = engine.import_workflow(input_path)

        assert workflow is not None
        assert workflow.id == "imported_wf"
        assert workflow.id in engine.workflows

    def test_save_and_load_workflow(self, engine, tmp_path):
        """Test workflow persistence."""
        workflow = engine.create_workflow(name="Persistent")
        workflow.add_step(name="Step", module="test")
        engine._save_workflow(workflow)

        # Create new engine and load
        new_engine = WorkflowEngine(framework=engine.framework)
        new_engine.storage_path = engine.storage_path

        loaded = new_engine.load_workflow(workflow.id)

        assert loaded is not None
        assert loaded.name == "Persistent"
        assert len(loaded.steps) == 1


# =============================================================================
# Condition Checking Tests
# =============================================================================

class TestConditionChecking:
    """Tests for workflow condition checking."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine with mock framework."""
        mock_framework = MagicMock()
        mock_framework.database = MagicMock()
        mock_framework.database.get_all_services.return_value = []

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_no_conditions_returns_true(self, engine):
        """Test step with no conditions passes."""
        workflow = Workflow(id="wf", name="Test")
        step = WorkflowStep(id="step_1", name="Step", module="test")

        result = engine._check_conditions(step, workflow)

        assert result is True

    def test_step_success_condition(self, engine):
        """Test step_success condition."""
        workflow = Workflow(id="wf", name="Test")
        step1 = WorkflowStep(id="step_1", name="Step 1", module="test")
        step1.status = StepStatus.SUCCESS
        workflow.steps.append(step1)

        step2 = WorkflowStep(
            id="step_2",
            name="Step 2",
            module="test",
            conditions=[{"type": "step_success", "step": "step_1"}],
        )

        result = engine._check_conditions(step2, workflow)

        assert result is True

    def test_step_success_condition_fails(self, engine):
        """Test step_success condition fails when step not successful."""
        workflow = Workflow(id="wf", name="Test")
        step1 = WorkflowStep(id="step_1", name="Step 1", module="test")
        step1.status = StepStatus.FAILED
        workflow.steps.append(step1)

        step2 = WorkflowStep(
            id="step_2",
            name="Step 2",
            module="test",
            conditions=[{"type": "step_success", "step": "step_1"}],
        )

        result = engine._check_conditions(step2, workflow)

        assert result is False

    def test_step_failed_condition(self, engine):
        """Test step_failed condition."""
        workflow = Workflow(id="wf", name="Test")
        step1 = WorkflowStep(id="step_1", name="Step 1", module="test")
        step1.status = StepStatus.FAILED
        workflow.steps.append(step1)

        step2 = WorkflowStep(
            id="step_2",
            name="Fallback",
            module="test",
            conditions=[{"type": "step_failed", "step": "step_1"}],
        )

        result = engine._check_conditions(step2, workflow)

        assert result is True

    def test_has_valid_creds_condition(self, engine):
        """Test has_valid_creds condition."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["credentials"] = [{"username": "admin"}]

        step = WorkflowStep(
            id="step_1",
            name="Auth Step",
            module="test",
            conditions=[{"type": "has_valid_creds"}],
        )

        result = engine._check_conditions(step, workflow)

        assert result is True

    def test_has_valid_creds_condition_fails(self, engine):
        """Test has_valid_creds condition fails when no creds."""
        workflow = Workflow(id="wf", name="Test")

        step = WorkflowStep(
            id="step_1",
            name="Auth Step",
            module="test",
            conditions=[{"type": "has_valid_creds"}],
        )

        result = engine._check_conditions(step, workflow)

        assert result is False

    def test_has_admin_creds_condition(self, engine):
        """Test has_admin_creds condition."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["credentials"] = [
            {"username": "admin", "is_admin": True}
        ]

        step = WorkflowStep(
            id="step_1",
            name="Admin Step",
            module="test",
            conditions=[{"type": "has_admin_creds"}],
        )

        result = engine._check_conditions(step, workflow)

        assert result is True

    def test_has_admin_creds_condition_fails(self, engine):
        """Test has_admin_creds condition fails with non-admin creds."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["credentials"] = [
            {"username": "user", "is_admin": False}
        ]

        step = WorkflowStep(
            id="step_1",
            name="Admin Step",
            module="test",
            conditions=[{"type": "has_admin_creds"}],
        )

        result = engine._check_conditions(step, workflow)

        assert result is False

    def test_has_user_list_condition(self, engine):
        """Test has_user_list condition."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["user_list"] = ["admin", "user1", "user2"]

        step = WorkflowStep(
            id="step_1",
            name="User Enum",
            module="test",
            conditions=[{"type": "has_user_list"}],
        )

        result = engine._check_conditions(step, workflow)

        assert result is True

    def test_variable_set_condition(self, engine):
        """Test variable_set condition."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["custom_var"] = "some_value"

        step = WorkflowStep(
            id="step_1",
            name="Step",
            module="test",
            conditions=[{"type": "variable_set", "variable": "custom_var"}],
        )

        result = engine._check_conditions(step, workflow)

        assert result is True

    def test_variable_equals_condition(self, engine):
        """Test variable_equals condition."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["scan_type"] = "aggressive"

        step = WorkflowStep(
            id="step_1",
            name="Step",
            module="test",
            conditions=[{
                "type": "variable_equals",
                "variable": "scan_type",
                "value": "aggressive",
            }],
        )

        result = engine._check_conditions(step, workflow)

        assert result is True

    def test_variable_equals_condition_fails(self, engine):
        """Test variable_equals condition fails on mismatch."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["scan_type"] = "quick"

        step = WorkflowStep(
            id="step_1",
            name="Step",
            module="test",
            conditions=[{
                "type": "variable_equals",
                "variable": "scan_type",
                "value": "aggressive",
            }],
        )

        result = engine._check_conditions(step, workflow)

        assert result is False

    def test_service_found_condition_from_variables(self, engine):
        """Test service_found condition using workflow variables."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["services"] = [
            {"service": "smb", "port": 445},
            {"service": "http", "port": 80},
        ]

        step = WorkflowStep(
            id="step_1",
            name="SMB Step",
            module="test",
            conditions=[{"type": "service_found", "service": "smb"}],
        )

        result = engine._check_conditions(step, workflow)

        assert result is True

    def test_service_found_condition_string_list(self, engine):
        """Test service_found with string list in variables."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["services"] = ["smb", "http", "ssh"]

        step = WorkflowStep(
            id="step_1",
            name="SSH Step",
            module="test",
            conditions=[{"type": "service_found", "service": "ssh"}],
        )

        result = engine._check_conditions(step, workflow)

        assert result is True

    def test_multiple_conditions_all_must_pass(self, engine):
        """Test all conditions must pass for step to execute."""
        workflow = Workflow(id="wf", name="Test")
        step1 = WorkflowStep(id="step_1", name="Step 1", module="test")
        step1.status = StepStatus.SUCCESS
        workflow.steps.append(step1)
        workflow.variables["credentials"] = [{"username": "admin"}]

        step2 = WorkflowStep(
            id="step_2",
            name="Step 2",
            module="test",
            conditions=[
                {"type": "step_success", "step": "step_1"},
                {"type": "has_valid_creds"},
            ],
        )

        result = engine._check_conditions(step2, workflow)

        assert result is True

    def test_multiple_conditions_one_fails(self, engine):
        """Test step skipped if any condition fails."""
        workflow = Workflow(id="wf", name="Test")
        step1 = WorkflowStep(id="step_1", name="Step 1", module="test")
        step1.status = StepStatus.SUCCESS
        workflow.steps.append(step1)
        # No credentials set

        step2 = WorkflowStep(
            id="step_2",
            name="Step 2",
            module="test",
            conditions=[
                {"type": "step_success", "step": "step_1"},
                {"type": "has_valid_creds"},
            ],
        )

        result = engine._check_conditions(step2, workflow)

        assert result is False


# =============================================================================
# Variable Resolution Tests
# =============================================================================

class TestVariableResolution:
    """Tests for variable resolution in workflow options."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine for testing."""
        engine = WorkflowEngine(framework=None)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_resolve_simple_variable(self, engine):
        """Test resolving a simple variable."""
        options = {"target": "$host"}
        variables = {"host": "192.168.1.1"}

        resolved = engine._resolve_variables(options, variables)

        assert resolved["target"] == "192.168.1.1"

    def test_resolve_multiple_variables(self, engine):
        """Test resolving multiple variables."""
        options = {
            "target": "$host",
            "username": "$user",
            "password": "$pass",
        }
        variables = {
            "host": "10.0.0.1",
            "user": "admin",
            "pass": "secret",
        }

        resolved = engine._resolve_variables(options, variables)

        assert resolved["target"] == "10.0.0.1"
        assert resolved["username"] == "admin"
        assert resolved["password"] == "secret"

    def test_preserve_non_variable_values(self, engine):
        """Test non-variable values are preserved."""
        options = {
            "target": "$host",
            "port": 443,
            "timeout": 30,
        }
        variables = {"host": "example.com"}

        resolved = engine._resolve_variables(options, variables)

        assert resolved["target"] == "example.com"
        assert resolved["port"] == 443
        assert resolved["timeout"] == 30

    def test_unresolved_variable_kept(self, engine):
        """Test unresolved variables are kept as-is."""
        options = {"target": "$undefined_var"}
        variables = {}

        resolved = engine._resolve_variables(options, variables)

        assert resolved["target"] == "$undefined_var"


# =============================================================================
# Workflow Templates Tests
# =============================================================================

class TestWorkflowTemplates:
    """Tests for built-in workflow templates."""

    def test_templates_exist(self):
        """Test expected templates are defined."""
        assert "full_network_assessment" in WORKFLOW_TEMPLATES
        assert "web_application_test" in WORKFLOW_TEMPLATES
        assert "ad_assessment" in WORKFLOW_TEMPLATES
        assert "quick_recon" in WORKFLOW_TEMPLATES
        assert "osint_recon" in WORKFLOW_TEMPLATES
        assert "credential_harvest" in WORKFLOW_TEMPLATES

    def test_template_structure(self):
        """Test templates have required fields."""
        for template_id, template in WORKFLOW_TEMPLATES.items():
            assert "name" in template, f"{template_id} missing name"
            assert "description" in template, f"{template_id} missing description"
            assert "steps" in template, f"{template_id} missing steps"
            assert len(template["steps"]) > 0, f"{template_id} has no steps"

    def test_template_steps_structure(self):
        """Test template steps have required fields."""
        for template_id, template in WORKFLOW_TEMPLATES.items():
            for i, step in enumerate(template["steps"]):
                assert "name" in step, f"{template_id} step {i} missing name"
                assert "module" in step, f"{template_id} step {i} missing module"

    def test_quick_recon_template(self):
        """Test quick_recon template specifics."""
        template = WORKFLOW_TEMPLATES["quick_recon"]

        assert template["name"] == "Quick Reconnaissance"
        assert len(template["steps"]) >= 2
        assert any(step["module"].startswith("recon/") for step in template["steps"])

    def test_full_network_assessment_template(self):
        """Test full_network_assessment template specifics."""
        template = WORKFLOW_TEMPLATES["full_network_assessment"]

        assert "Full Network" in template["name"]
        assert "network" in template.get("tags", [])
        # Should have multiple steps for comprehensive assessment
        assert len(template["steps"]) >= 3


# =============================================================================
# Data Extraction Tests
# =============================================================================

class TestDataExtraction:
    """Tests for extracting data from step results."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine for testing."""
        engine = WorkflowEngine(framework=None)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_extract_credentials(self, engine):
        """Test extracting credentials from results."""
        workflow = Workflow(id="wf", name="Test")
        result = {
            "credentials": [
                {"username": "admin", "password": "pass123"},
                {"username": "user", "password": "user456"},
            ]
        }

        engine._extract_workflow_data(result, workflow)

        assert "credentials" in workflow.variables
        assert len(workflow.variables["credentials"]) == 2

    def test_extract_users(self, engine):
        """Test extracting user list from results."""
        workflow = Workflow(id="wf", name="Test")
        result = {
            "users": ["admin", "guest", "service_account"]
        }

        engine._extract_workflow_data(result, workflow)

        assert "user_list" in workflow.variables
        assert len(workflow.variables["user_list"]) == 3

    def test_extract_services(self, engine):
        """Test extracting services from results."""
        workflow = Workflow(id="wf", name="Test")
        result = {
            "services": [
                {"service": "ssh", "port": 22},
                {"service": "http", "port": 80},
            ]
        }

        engine._extract_workflow_data(result, workflow)

        assert "services" in workflow.variables
        assert len(workflow.variables["services"]) == 2

    def test_extract_findings(self, engine):
        """Test extracting findings from results."""
        workflow = Workflow(id="wf", name="Test")
        result = {
            "findings": [
                {"title": "SQL Injection", "severity": "high"},
            ]
        }

        engine._extract_workflow_data(result, workflow)

        assert "findings" in workflow.variables
        assert len(workflow.variables["findings"]) == 1

    def test_append_to_existing_data(self, engine):
        """Test new data is appended to existing variables."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["credentials"] = [{"username": "existing"}]

        result = {
            "credentials": [{"username": "new"}]
        }

        engine._extract_workflow_data(result, workflow)

        assert len(workflow.variables["credentials"]) == 2


# =============================================================================
# Callback Tests
# =============================================================================

class TestCallbacks:
    """Tests for workflow engine callbacks."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine for testing."""
        engine = WorkflowEngine(framework=None)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_step_start_callback(self, engine):
        """Test on_step_start callback is invoked."""
        callback_data = []

        def on_start(workflow, step):
            callback_data.append({"workflow": workflow.id, "step": step.id})

        engine.on_step_start = on_start

        # Would need to actually run a step to test this fully
        # This is a placeholder for the callback mechanism test

    def test_step_complete_callback(self, engine):
        """Test on_step_complete callback is invoked."""
        callback_data = []

        def on_complete(workflow, step, result):
            callback_data.append({
                "workflow": workflow.id,
                "step": step.id,
                "success": result.get("success"),
            })

        engine.on_step_complete = on_complete

        # Would need to actually run a step to test this fully

    def test_workflow_complete_callback(self, engine):
        """Test on_workflow_complete callback is invoked."""
        callback_data = []

        def on_complete(workflow, results):
            callback_data.append({
                "workflow": workflow.id,
                "steps_completed": results.get("steps_completed"),
            })

        engine.on_workflow_complete = on_complete

        # Would need to actually run a workflow to test this fully
