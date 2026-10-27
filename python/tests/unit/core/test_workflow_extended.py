"""
Extended tests for purplesploit.core.workflow module.

Comprehensive test coverage for:
- Full workflow execution with real step processing
- Conditional branching with complex scenarios
- Pause/resume functionality
- Template instantiation
- Step execution with module operations
- Service discovery from database
"""

import pytest
import json
from datetime import datetime
from unittest.mock import MagicMock

from purplesploit.core.framework import Framework
from purplesploit.core.module import BaseModule, ModuleMetadata
from purplesploit.core.workflow import (
    StepStatus,
    WorkflowStatus,
    WorkflowStep,
    Workflow,
    WorkflowEngine,
    WORKFLOW_TEMPLATES,
)


class ContractWorkflowModule(BaseModule):
    """Small real module whose execution stops at an injected fake boundary."""

    @property
    def name(self):
        return "Workflow Contract Module"

    @property
    def description(self):
        return "Exercises the real Framework workflow contracts"

    @property
    def author(self):
        return "Tests"

    @property
    def category(self):
        return "test"

    def get_operations(self):
        return [
            {
                "name": "Probe",
                "description": "Execute through a fake process boundary",
                "handler": "op_probe",
            }
        ]

    def op_probe(self):
        return self.framework.workflow_test_boundary(
            "probe",
            self.get_option("RHOST"),
        )

    def run(self):
        return self.framework.workflow_test_boundary(
            "default",
            self.get_option("RHOST"),
        )


def configure_framework_contract(mock_framework, mock_module, services=None):
    """Configure a mock with the same metadata/instance contracts as Framework."""
    metadata = ModuleMetadata(path="test/module", name="Test", category="test",
                              description="Test", author="Tests",
                              instance=lambda framework: mock_module)
    mock_framework.database = MagicMock()
    mock_framework.database.get_services = MagicMock(return_value=services or [])
    mock_framework.get_module = MagicMock(return_value=metadata)
    mock_framework.use_module = MagicMock(return_value=mock_module)
    mock_framework.run_module = MagicMock(side_effect=lambda module: module.run())

    def run_operation(module, operation):
        handler = operation.get("handler")
        if isinstance(handler, str):
            handler = getattr(module, handler)
        return handler()

    mock_framework.run_operation = MagicMock(side_effect=run_operation)
    return mock_framework


class TestRealFrameworkContract:
    """Regression coverage for the metadata/instance bug found in workflows."""

    @pytest.fixture
    def engine(self, tmp_path):
        framework = Framework(db_path=":memory:")
        framework.workflow_test_boundary = MagicMock(
            return_value={"success": True, "output": "fake process complete"}
        )
        framework.modules["test/contract"] = ModuleMetadata(
            path="test/contract",
            name="Workflow Contract Module",
            category="test",
            description="Exercises the real Framework workflow contracts",
            author="Tests",
            instance=ContractWorkflowModule,
        )

        engine = WorkflowEngine(framework=framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        yield engine
        framework.database.close()

    def test_selected_operation_uses_live_instance_and_framework_pipeline(self, engine):
        workflow = engine.create_workflow(name="Real contract")
        workflow.add_step(
            name="Probe target",
            module="test/contract",
            operation="Probe",
        )

        result = engine.run_workflow(
            workflow.id,
            variables={"target": "192.0.2.10"},
        )

        assert result["success"] is True
        assert result["steps_completed"] == 1
        assert workflow.status is WorkflowStatus.COMPLETED
        assert isinstance(engine.framework.get_module("test/contract"), ModuleMetadata)
        assert engine.framework.session.current_module is None
        engine.framework.workflow_test_boundary.assert_called_once_with(
            "probe",
            "192.0.2.10",
        )

    def test_unknown_operation_is_rejected_before_boundary_execution(self, engine):
        workflow = engine.create_workflow(name="Invalid operation")
        workflow.add_step(
            name="Bad selection",
            module="test/contract",
            operation="Missing Operation",
        )

        result = engine.run_workflow(workflow.id)

        assert result["success"] is False
        assert "operation not found" in result["error"].lower()
        engine.framework.workflow_test_boundary.assert_not_called()

    def test_builtin_template_operation_names_match_module_catalogs(self):
        from purplesploit.modules.ad.kerbrute import KerbruteModule
        from purplesploit.modules.network.nxc_ldap import NXCLDAPModule
        from purplesploit.modules.network.nxc_smb import NXCSMBModule
        from purplesploit.modules.osint.crtsh import CrtshModule
        from purplesploit.modules.osint.dnsdumpster import DNSDumpsterModule
        from purplesploit.modules.osint.shodan import ShodanModule
        from purplesploit.modules.recon.nuclei import NucleiModule
        from purplesploit.modules.web.forms import HTMLFormsModule

        framework = Framework(db_path=":memory:")
        try:
            operation_modules = {
                "ad/kerbrute": KerbruteModule,
                "network/nxc_ldap": NXCLDAPModule,
                "network/nxc_smb": NXCSMBModule,
                "osint/crtsh": CrtshModule,
                "osint/dnsdumpster": DNSDumpsterModule,
                "osint/shodan": ShodanModule,
                "recon/nuclei": NucleiModule,
                "web/forms": HTMLFormsModule,
            }

            for template_name, template in WORKFLOW_TEMPLATES.items():
                for step in template["steps"]:
                    operation_name = step.get("operation")
                    if not operation_name:
                        continue
                    module_class = operation_modules[step["module"]]
                    module = module_class(framework)
                    available = {
                        operation["name"] for operation in module.get_operations()
                    }
                    assert operation_name in available, (
                        f"{template_name}/{step['name']}: {operation_name}"
                    )
        finally:
            framework.database.close()


# =============================================================================
# Full Workflow Execution Tests
# =============================================================================

class TestFullWorkflowExecution:
    """Tests for complete workflow execution."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine with comprehensive mock framework."""
        mock_framework = MagicMock()
        mock_framework.session = MagicMock()

        # Mock module
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {
            'RHOST': {},
            'TARGET': {},
            'URL': {},
        }
        mock_module.has_operations = MagicMock(return_value=False)
        mock_module.run = MagicMock(return_value={'success': True, 'output': 'Complete'})

        configure_framework_contract(mock_framework, mock_module)

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)

        return engine

    def test_execute_simple_workflow(self, engine):
        """Test executing a simple workflow with one step."""
        workflow = engine.create_workflow(name="Simple Test")
        workflow.add_step(name="Scan", module="recon/nmap")
        workflow.variables = {"target": "192.168.1.1"}

        # Setup module return value
        engine.framework.use_module().run.return_value = {
            'success': True,
            'output': 'Scan complete',
            'services': [{'service': 'ssh', 'port': 22}],
        }

        result = engine.run_workflow(workflow.id, variables={"target": "192.168.1.1"})

        assert result["success"] is True
        assert result["steps_completed"] == 1
        assert result["steps_failed"] == 0

    def test_execute_multi_step_workflow(self, engine):
        """Test executing workflow with multiple steps."""
        workflow = engine.create_workflow(name="Multi-Step Test")
        workflow.add_step(name="Step 1", module="module1")
        workflow.add_step(name="Step 2", module="module2")
        workflow.add_step(name="Step 3", module="module3")

        engine.framework.use_module().run.return_value = {'success': True}

        result = engine.run_workflow(workflow.id)

        assert result["steps_completed"] == 3

    def test_execute_workflow_with_failed_step(self, engine):
        """Test workflow handles step failure."""
        workflow = engine.create_workflow(name="Failure Test")
        workflow.add_step(name="Succeed", module="module1")
        workflow.add_step(name="Fail", module="module2")
        workflow.add_step(name="Never Runs", module="module3")

        call_count = 0

        def run_side_effect():
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return {'success': False, 'error': 'Module failed'}
            return {'success': True}

        engine.framework.use_module().run = MagicMock(side_effect=run_side_effect)

        result = engine.run_workflow(workflow.id)

        assert result["steps_completed"] == 1
        assert result["steps_failed"] == 1
        assert result["success"] is False
        assert result["error"] == "Module failed"
        assert workflow.status == WorkflowStatus.FAILED
        # Step 3 should not run due to failure

    def test_execute_workflow_tracks_status(self, engine):
        """Test workflow status is updated during execution."""
        workflow = engine.create_workflow(name="Status Test")
        workflow.add_step(name="Step", module="test")

        engine.framework.use_module().run.return_value = {'success': True}

        engine.run_workflow(workflow.id)

        assert workflow.status == WorkflowStatus.COMPLETED
        assert workflow.started_at is not None
        assert workflow.completed_at is not None

    def test_execute_workflow_updates_step_status(self, engine):
        """Test step status is updated correctly."""
        workflow = engine.create_workflow(name="Step Status Test")
        step = workflow.add_step(name="Test Step", module="test")

        engine.framework.use_module().run.return_value = {'success': True}

        engine.run_workflow(workflow.id)

        assert step.status == StepStatus.SUCCESS
        assert step.started_at is not None
        assert step.completed_at is not None

    def test_execute_workflow_stores_step_result(self, engine):
        """Test step result is stored."""
        workflow = engine.create_workflow(name="Result Test")
        step = workflow.add_step(name="Test Step", module="test")

        expected_result = {'success': True, 'data': {'key': 'value'}}
        engine.framework.use_module().run.return_value = expected_result

        engine.run_workflow(workflow.id)

        assert step.result == expected_result


# =============================================================================
# Conditional Branching Tests
# =============================================================================

class TestConditionalBranching:
    """Tests for complex conditional branching scenarios."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine for conditional testing."""
        mock_framework = MagicMock()
        mock_module = MagicMock(
            set_option=MagicMock(return_value=True),
            options={'RHOST': {}},
            has_operations=MagicMock(return_value=False),
            run=MagicMock(return_value={'success': True}),
        )
        configure_framework_contract(mock_framework, mock_module)

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_step_skipped_when_condition_not_met(self, engine):
        """Test step is skipped when conditions aren't met."""
        workflow = engine.create_workflow(name="Condition Test")
        step1 = workflow.add_step(name="First", module="module1")
        step1.status = StepStatus.FAILED  # Simulate failed step

        step2 = workflow.add_step(
            name="Conditional",
            module="module2",
            conditions=[{"type": "step_success", "step": "step_1"}]
        )

        # Check conditions directly
        result = engine._check_conditions(step2, workflow)

        assert result is False

    def test_step_runs_when_condition_met(self, engine):
        """Test step runs when conditions are met."""
        workflow = engine.create_workflow(name="Condition Test")
        step1 = workflow.add_step(name="First", module="module1")
        step1.status = StepStatus.SUCCESS

        step2 = workflow.add_step(
            name="Conditional",
            module="module2",
            conditions=[{"type": "step_success", "step": "step_1"}]
        )

        result = engine._check_conditions(step2, workflow)

        assert result is True

    def test_complex_condition_chain(self, engine):
        """Test complex condition chain."""
        workflow = Workflow(id="wf", name="Complex Chain")

        # Create chain of steps
        step1 = WorkflowStep(id="step_1", name="Step 1", module="m1")
        step1.status = StepStatus.SUCCESS
        workflow.steps.append(step1)

        step2 = WorkflowStep(id="step_2", name="Step 2", module="m2")
        step2.status = StepStatus.SUCCESS
        workflow.steps.append(step2)

        # Step 3 requires both step 1 and 2 to succeed
        step3 = WorkflowStep(
            id="step_3",
            name="Step 3",
            module="m3",
            conditions=[
                {"type": "step_success", "step": "step_1"},
                {"type": "step_success", "step": "step_2"},
            ]
        )

        result = engine._check_conditions(step3, workflow)
        assert result is True

        # Now fail step 2
        step2.status = StepStatus.FAILED
        result = engine._check_conditions(step3, workflow)
        assert result is False

    def test_service_found_condition_with_database(self, engine):
        """Test service_found condition checks database."""
        workflow = Workflow(id="wf", name="Service Check")
        workflow.variables["target"] = "192.0.2.10"

        # Mock database services
        mock_service = MagicMock()
        mock_service.service = "smb"
        engine.framework.database.get_services.return_value = [
            {"service": mock_service.service, "target": "192.0.2.10"}
        ]

        step = WorkflowStep(
            id="step_1",
            name="SMB Step",
            module="smb_module",
            conditions=[{"type": "service_found", "service": "smb"}]
        )

        result = engine._check_conditions(step, workflow)
        assert result is True

    def test_forms_found_condition(self, engine):
        """Test custom forms_found condition type."""
        workflow = Workflow(id="wf", name="Forms Test")
        step = WorkflowStep(
            id="step_1",
            name="Form Step",
            module="sqlmap",
            conditions=[{"type": "forms_found"}]
        )

        assert engine._check_conditions(step, workflow) is False

        workflow.variables["forms"] = [{"action": "/login"}]
        assert engine._check_conditions(step, workflow) is True

    def test_conditional_execution_in_workflow(self, engine):
        """Test conditional execution during full workflow run."""
        workflow = engine.create_workflow(name="Full Conditional")
        workflow.add_step(name="Discovery", module="nmap")
        workflow.add_step(
            name="SMB Enum",
            module="smb",
            conditions=[{"type": "step_success", "step": "step_1"}]
        )

        # Make first step succeed
        engine.framework.use_module().run.return_value = {'success': True}

        result = engine.run_workflow(workflow.id)

        # Both steps should run
        assert result["steps_completed"] == 2
        assert result["steps_skipped"] == 0

    def test_conditional_skip_in_workflow(self, engine):
        """Test steps are skipped in workflow when conditions fail."""
        workflow = engine.create_workflow(name="Skip Test")
        workflow.add_step(name="Discovery", module="nmap")
        workflow.add_step(
            name="SMB Enum",
            module="smb",
            conditions=[{"type": "step_success", "step": "step_1"}]
        )

        # Make first step fail
        engine.framework.use_module().run.return_value = {
            'success': False,
            'error': 'Scan failed'
        }

        result = engine.run_workflow(workflow.id)

        # First step fails, so workflow stops (no on_failure handler)
        assert result["steps_failed"] >= 1


# =============================================================================
# Pause/Resume Tests
# =============================================================================

class TestPauseResume:
    """Tests for pause/resume functionality."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine for pause/resume testing."""
        mock_framework = MagicMock()
        mock_module = MagicMock(
            set_option=MagicMock(return_value=True),
            options={'RHOST': {}},
            has_operations=MagicMock(return_value=False),
            run=MagicMock(return_value={'success': True}),
        )
        configure_framework_contract(mock_framework, mock_module)

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_pause_running_workflow(self, engine):
        """Test pausing a running workflow."""
        workflow = engine.create_workflow(name="Pause Test")
        workflow.add_step(name="Step", module="test")
        workflow.status = WorkflowStatus.RUNNING

        result = engine.pause_workflow(workflow.id)

        assert result is True
        assert workflow.status == WorkflowStatus.PAUSED

    def test_pause_saves_workflow(self, engine):
        """Test pause saves workflow state."""
        workflow = engine.create_workflow(name="Save Test")
        workflow.add_step(name="Step", module="test")
        workflow.status = WorkflowStatus.RUNNING
        workflow.completed_at = datetime.utcnow()

        engine.pause_workflow(workflow.id)

        # Verify file was saved
        workflow_file = engine.storage_path / f"{workflow.id}.json"
        assert workflow_file.exists()
        with workflow_file.open() as workflow_handle:
            persisted = json.load(workflow_handle)
        assert persisted["status"] == "paused"
        assert persisted["completed_at"] is None

    def test_resume_preserves_terminal_steps_and_summarizes_full_workflow(
        self,
        engine,
    ):
        """Resume executes only pending work and reports persisted outcomes."""
        workflow = engine.create_workflow(name="Resume Test")
        step1 = workflow.add_step(name="Step 1", module="test1")
        step1.status = StepStatus.SUCCESS
        step1.result = {"success": True, "output": "already complete"}
        step1.started_at = datetime(2024, 1, 1, 12, 0, 0)
        step1.completed_at = datetime(2024, 1, 1, 12, 1, 0)

        step2 = workflow.add_step(name="Step 2", module="test2")
        step2.status = StepStatus.SKIPPED
        step2.completed_at = datetime(2024, 1, 1, 12, 2, 0)

        step3 = workflow.add_step(
            name="Step 3",
            module="test3",
            on_failure=["step_4"],
        )
        step3.status = StepStatus.FAILED
        step3.error = "persisted failure"
        step3.result = {"success": False, "error": "persisted failure"}
        step3.started_at = datetime(2024, 1, 1, 12, 3, 0)
        step3.completed_at = datetime(2024, 1, 1, 12, 4, 0)

        step4 = workflow.add_step(name="Step 4", module="test4")

        workflow.status = WorkflowStatus.PAUSED
        workflow.started_at = datetime(2024, 1, 1, 12, 0, 0)
        original_started_at = workflow.started_at

        result = engine.resume_workflow(workflow.id)

        assert engine.framework.run_module.call_count == 1
        assert engine.framework.use_module.call_count == 1
        assert step1.status == StepStatus.SUCCESS
        assert step2.status == StepStatus.SKIPPED
        assert step3.status == StepStatus.FAILED
        assert step4.status == StepStatus.SUCCESS
        assert workflow.started_at == original_started_at
        assert workflow.status == WorkflowStatus.FAILED
        assert workflow.completed_at is not None
        assert result == {
            "success": False,
            "workflow_id": workflow.id,
            "steps_completed": 2,
            "steps_failed": 1,
            "steps_skipped": 1,
            "steps_pending": 0,
            "step_results": result["step_results"],
            "status": "failed",
            "error": "persisted failure",
        }
        assert [item["step_id"] for item in result["step_results"]] == [
            "step_1",
            "step_2",
            "step_3",
            "step_4",
        ]

        reloaded_engine = WorkflowEngine(framework=engine.framework)
        reloaded_engine.storage_path = engine.storage_path
        reloaded = reloaded_engine.load_workflow(workflow.id)
        assert reloaded is not None
        assert reloaded.status == WorkflowStatus.FAILED
        assert reloaded.started_at == original_started_at
        assert reloaded.completed_at == workflow.completed_at
        assert [step.status for step in reloaded.steps] == [
            StepStatus.SUCCESS,
            StepStatus.SKIPPED,
            StepStatus.FAILED,
            StepStatus.SUCCESS,
        ]

    def test_resume_no_pending_steps_finalizes_without_reexecution(self, engine):
        """A last-step pause can be finalized without replaying any step."""
        workflow = engine.create_workflow(name="No Pending Test")
        step1 = workflow.add_step(name="Step 1", module="test1")
        step1.status = StepStatus.SUCCESS
        step1.result = {"success": True}
        step1.completed_at = datetime(2024, 1, 1, 12, 1, 0)
        step2 = workflow.add_step(name="Step 2", module="test2")
        step2.status = StepStatus.SKIPPED
        step2.completed_at = datetime(2024, 1, 1, 12, 2, 0)

        workflow.status = WorkflowStatus.PAUSED
        workflow.started_at = datetime(2024, 1, 1, 12, 0, 0)

        result = engine.resume_workflow(workflow.id)

        assert result["success"] is True
        assert result["status"] == "completed"
        assert result["steps_completed"] == 1
        assert result["steps_skipped"] == 1
        assert result["steps_pending"] == 0
        assert workflow.status == WorkflowStatus.COMPLETED
        assert workflow.completed_at is not None
        engine.framework.get_module.assert_not_called()
        engine.framework.use_module.assert_not_called()
        engine.framework.run_module.assert_not_called()

    def test_run_stops_between_steps_when_pause_is_requested(self, engine):
        """A pause during step completion is persisted before the next step."""
        workflow = engine.create_workflow(name="Concurrent Pause Test")
        workflow.add_step(name="Step 1", module="test1")
        workflow.add_step(name="Step 2", module="test2")
        workflow.add_step(name="Step 3", module="test3")
        workflow_complete = MagicMock()
        engine.on_workflow_complete = workflow_complete

        def pause_after_first_step(completed_workflow, step, _result):
            if step.id == "step_1":
                assert engine.pause_workflow(completed_workflow.id) is True

        engine.on_step_complete = pause_after_first_step

        paused_result = engine.run_workflow(workflow.id)

        assert paused_result["success"] is False
        assert paused_result["status"] == "paused"
        assert paused_result["steps_completed"] == 1
        assert paused_result["steps_pending"] == 2
        assert workflow.status == WorkflowStatus.PAUSED
        assert workflow.completed_at is None
        assert workflow.current_step_id is None
        assert engine.framework.run_module.call_count == 1
        workflow_complete.assert_not_called()

        workflow_file = engine.storage_path / f"{workflow.id}.json"
        with workflow_file.open() as workflow_handle:
            persisted = json.load(workflow_handle)
        assert persisted["status"] == "paused"
        assert persisted["completed_at"] is None
        assert [step["status"] for step in persisted["steps"]] == [
            "success",
            "pending",
            "pending",
        ]

        original_started_at = workflow.started_at
        engine.on_step_complete = None
        resumed_result = engine.resume_workflow(workflow.id)

        assert resumed_result["success"] is True
        assert resumed_result["status"] == "completed"
        assert resumed_result["steps_completed"] == 3
        assert resumed_result["steps_pending"] == 0
        assert workflow.started_at == original_started_at
        assert workflow.completed_at is not None
        assert engine.framework.run_module.call_count == 3
        workflow_complete.assert_called_once_with(workflow, resumed_result)

    def test_pause_nonexistent_workflow(self, engine):
        """Test pausing non-existent workflow."""
        result = engine.pause_workflow("nonexistent")
        assert result is False

    def test_pause_completed_workflow(self, engine):
        """Test can't pause completed workflow."""
        workflow = engine.create_workflow(name="Completed Test")
        workflow.status = WorkflowStatus.COMPLETED

        result = engine.pause_workflow(workflow.id)

        assert result is False

    def test_pause_created_workflow(self, engine):
        """Test can't pause workflow that hasn't started."""
        workflow = engine.create_workflow(name="Not Started")
        # Status is CREATED by default

        result = engine.pause_workflow(workflow.id)

        assert result is False


# =============================================================================
# Template Instantiation Tests
# =============================================================================

class TestTemplateInstantiation:
    """Tests for workflow template instantiation."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine for template testing."""
        engine = WorkflowEngine(framework=None)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_create_from_template_copies_all_fields(self, engine):
        """Test template creates workflow with all fields."""
        workflow = engine.create_workflow(name="", from_template="full_network_assessment")

        template = WORKFLOW_TEMPLATES["full_network_assessment"]

        assert workflow.name == template["name"]
        assert workflow.description == template["description"]
        assert workflow.tags == template.get("tags", [])
        assert len(workflow.steps) == len(template["steps"])

    def test_create_from_template_preserves_step_structure(self, engine):
        """Test template steps have correct structure."""
        workflow = engine.create_workflow(name="", from_template="web_application_test")

        template = WORKFLOW_TEMPLATES["web_application_test"]

        for i, step in enumerate(workflow.steps):
            template_step = template["steps"][i]
            assert step.name == template_step["name"]
            assert step.module == template_step["module"]
            assert step.operation == template_step.get("operation")
            assert step.conditions == template_step.get("conditions", [])

    def test_web_template_imports_recorded_forms_when_supplied(self, engine):
        template = WORKFLOW_TEMPLATES["web_application_test"]
        form_step = next(step for step in template["steps"] if step["module"] == "web/forms")
        assert form_step["operation"] == "Import Forms"
        assert form_step["options"] == {"HTML_FILE": "$html_file"}
        assert {condition["type"] for condition in form_step["conditions"]} == {
            "step_success",
            "variable_set",
        }

    def test_create_from_each_template(self, engine):
        """Test each template can be instantiated."""
        for template_id in WORKFLOW_TEMPLATES.keys():
            workflow = engine.create_workflow(name="", from_template=template_id)

            assert workflow is not None
            assert len(workflow.steps) > 0
            assert workflow.id in engine.workflows

    def test_template_step_ids_are_correct(self, engine):
        """Test template steps have sequential IDs."""
        workflow = engine.create_workflow(name="", from_template="ad_assessment")

        for i, step in enumerate(workflow.steps, 1):
            assert step.id == f"step_{i}"

    def test_template_conditions_reference_valid_steps(self, engine):
        """Test template conditions reference valid step IDs."""
        for template_id, template in WORKFLOW_TEMPLATES.items():
            step_ids = [f"step_{i+1}" for i in range(len(template["steps"]))]

            for step_config in template["steps"]:
                for condition in step_config.get("conditions", []):
                    if condition.get("type") == "step_success":
                        ref_step = condition.get("step")
                        assert ref_step in step_ids, \
                            f"Template {template_id} references invalid step: {ref_step}"

    def test_osint_recon_template(self, engine):
        """Test OSINT recon template specifics."""
        workflow = engine.create_workflow(name="", from_template="osint_recon")

        assert "osint" in workflow.tags
        assert "passive" in workflow.tags

        modules = [step.module for step in workflow.steps]
        assert any("shodan" in m for m in modules)
        assert any("crtsh" in m for m in modules)

    def test_credential_harvest_template(self, engine):
        """Test credential harvest template specifics."""
        workflow = engine.create_workflow(name="", from_template="credential_harvest")

        assert "credentials" in workflow.tags

        # Should have credential-related conditions
        has_cred_condition = False
        for step in workflow.steps:
            for cond in step.conditions:
                if cond.get("type") in ["has_valid_creds", "has_user_list"]:
                    has_cred_condition = True
                    break

        assert has_cred_condition


# =============================================================================
# Step Execution with Module Operations Tests
# =============================================================================

class TestStepExecutionWithOperations:
    """Tests for step execution with module operations."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine with operation-capable modules."""
        mock_framework = MagicMock()

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}, 'TARGET': {}, 'URL': {}}
        mock_module.has_operations = MagicMock(return_value=True)
        mock_module.get_operations = MagicMock(return_value=[
            {'name': 'Quick Scan', 'handler': 'op_quick_scan'},
            {'name': 'Full Scan', 'handler': 'op_full_scan'},
        ])
        mock_module.op_quick_scan = MagicMock(return_value={'success': True})
        mock_module.op_full_scan = MagicMock(return_value={'success': True})
        mock_module.run = MagicMock(return_value={'success': True})

        configure_framework_contract(mock_framework, mock_module)

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_execute_step_with_operation_by_name(self, engine):
        """Test executing step that specifies an operation."""
        workflow = engine.create_workflow(name="Operation Test")
        workflow.add_step(
            name="Scan",
            module="recon/nmap",
            operation="Quick Scan"
        )

        result = engine.run_workflow(workflow.id)

        assert result["success"] is True
        engine.framework.run_operation.assert_called_once()

    def test_execute_step_with_operation_handler(self, engine):
        """Test operation handler is called for matching operation."""
        workflow = Workflow(id="wf", name="Handler Test")
        step = WorkflowStep(
            id="step_1",
            name="Test",
            module="test",
            operation="Quick Scan"
        )
        workflow.steps.append(step)

        mock_module = engine.framework.use_module()

        # Setup operation handler
        mock_handler = MagicMock(return_value={'success': True, 'data': 'result'})
        mock_module.has_operations = MagicMock(return_value=True)
        mock_module.get_operations.return_value = [
            {'name': 'Quick Scan', 'handler': mock_handler}
        ]

        engine.workflows[workflow.id] = workflow
        result = engine._execute_step(step, workflow)

        assert result["success"] is True
        mock_handler.assert_called_once()

    def test_execute_step_with_string_handler(self, engine):
        """Test operation with string handler name."""
        workflow = Workflow(id="wf", name="String Handler Test")
        step = WorkflowStep(
            id="step_1",
            name="Test",
            module="test",
            operation="Quick Scan"
        )
        workflow.steps.append(step)

        mock_module = engine.framework.use_module()
        mock_module.op_quick_scan = MagicMock(return_value={'success': True})
        mock_module.get_operations.return_value = [
            {'name': 'Quick Scan', 'handler': 'op_quick_scan'}
        ]

        engine.workflows[workflow.id] = workflow
        engine._execute_step(step, workflow)

        mock_module.op_quick_scan.assert_called_once()

    def test_execute_step_rejects_unknown_operation(self, engine):
        """An unknown selected operation must not fall back to module.run()."""
        workflow = Workflow(id="wf", name="Fallback Test")
        step = WorkflowStep(
            id="step_1",
            name="Test",
            module="test",
            operation="Nonexistent Operation"
        )
        workflow.steps.append(step)

        mock_module = engine.framework.use_module()
        mock_module.has_operations = MagicMock(return_value=True)
        mock_module.get_operations.return_value = []  # No matching operations
        mock_module.run = MagicMock(return_value={'success': True})

        engine.workflows[workflow.id] = workflow
        result = engine._execute_step(step, workflow)

        assert result["success"] is False
        assert "operation not found" in result["error"].lower()
        mock_module.run.assert_not_called()


# =============================================================================
# Module Target Setting Tests
# =============================================================================

class TestModuleTargetSetting:
    """Tests for setting targets on modules during execution."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine with mock framework."""
        mock_framework = MagicMock()

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {
            'RHOST': {},
            'TARGET': {},
            'URL': {},
        }
        mock_module.has_operations = MagicMock(return_value=False)
        mock_module.run = MagicMock(return_value={'success': True})

        configure_framework_contract(mock_framework, mock_module)

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_target_set_on_rhost(self, engine):
        """Test target is set on RHOST option."""
        workflow = engine.create_workflow(name="Target Test")
        workflow.add_step(name="Scan", module="nmap")
        workflow.variables["target"] = "192.168.1.1"

        engine.run_workflow(workflow.id)

        engine.framework.use_module().set_option.assert_any_call('RHOST', '192.168.1.1')

    def test_target_set_on_target_option(self, engine):
        """Test target is set on TARGET option."""
        workflow = engine.create_workflow(name="Target Test")
        workflow.add_step(name="Scan", module="nmap")
        workflow.variables["target"] = "192.168.1.1"

        engine.run_workflow(workflow.id)

        engine.framework.use_module().set_option.assert_any_call('TARGET', '192.168.1.1')

    def test_url_target_set_on_url_option(self, engine):
        """Test URL target is set on URL option."""
        workflow = engine.create_workflow(name="URL Test")
        workflow.add_step(name="Web Scan", module="httpx")
        workflow.variables["target"] = "https://example.com"

        engine.run_workflow(workflow.id)

        engine.framework.use_module().set_option.assert_any_call('URL', 'https://example.com')


# =============================================================================
# Workflow Validation Tests
# =============================================================================

class TestWorkflowValidation:
    """Tests for workflow validation."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine for validation testing."""
        engine = WorkflowEngine(framework=MagicMock())
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_validate_empty_workflow(self, engine):
        """Test validation fails for empty workflow."""
        workflow = Workflow(id="wf", name="Empty")

        result = engine._validate_workflow(workflow)

        assert result["valid"] is False
        assert "no steps" in result["error"].lower()

    def test_validate_workflow_with_steps(self, engine):
        """Test validation passes for workflow with steps."""
        workflow = Workflow(id="wf", name="Valid")
        workflow.steps.append(WorkflowStep(id="step_1", name="Step", module="test"))

        result = engine._validate_workflow(workflow)

        assert result["valid"] is True

    def test_validate_rejects_missing_module(self, engine):
        workflow = Workflow(id="wf", name="Missing module")
        workflow.steps.append(
            WorkflowStep(
                id="step_1",
                name="Missing",
                module="missing/module",
            )
        )
        engine.framework.get_module.return_value = None

        result = engine._validate_workflow(workflow)

        assert result["valid"] is False
        assert "module not found" in result["error"].lower()

    def test_validate_rejects_unknown_condition(self, engine):
        workflow = Workflow(id="wf", name="Unknown condition")
        workflow.steps.append(
            WorkflowStep(
                id="step_1",
                name="Conditional",
                module="test",
                conditions=[{"type": "not_implemented"}],
            )
        )

        result = engine._validate_workflow(workflow)

        assert result["valid"] is False
        assert "unsupported condition" in result["error"].lower()

    def test_validate_missing_variable(self, engine):
        """Test validation detects missing variables."""
        workflow = Workflow(id="wf", name="Missing Var")
        step = WorkflowStep(
            id="step_1",
            name="Step",
            module="test",
            options={"target": "$required_var"}
        )
        workflow.steps.append(step)

        result = engine._validate_workflow(workflow)

        assert result["valid"] is False
        assert "missing variables" in result["error"].lower()
        assert "required_var" in result["error"]

    def test_validate_provided_variable(self, engine):
        """Test validation passes when variable is provided."""
        workflow = Workflow(id="wf", name="Provided Var")
        step = WorkflowStep(
            id="step_1",
            name="Step",
            module="test",
            options={"target": "$my_var"}
        )
        workflow.steps.append(step)
        workflow.variables["my_var"] = "some_value"

        result = engine._validate_workflow(workflow)

        assert result["valid"] is True


# =============================================================================
# Service Exists Check Tests
# =============================================================================

class TestServiceExistsCheck:
    """Tests for service existence checking."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine with mock database."""
        mock_framework = MagicMock()
        mock_framework.database = MagicMock()

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_service_exists_from_variables_dict(self, engine):
        """Test service found in workflow variables as dict."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["services"] = [
            {"service": "smb", "port": 445},
            {"service": "ssh", "port": 22},
        ]

        assert engine._service_exists("smb", workflow) is True
        assert engine._service_exists("ssh", workflow) is True
        assert engine._service_exists("rdp", workflow) is False

    def test_service_exists_from_variables_string(self, engine):
        """Test service found in workflow variables as string list."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["services"] = ["smb", "ssh", "http"]

        assert engine._service_exists("smb", workflow) is True
        assert engine._service_exists("HTTP", workflow) is True  # Case insensitive
        assert engine._service_exists("rdp", workflow) is False

    def test_service_exists_from_database(self, engine):
        """Test service found in database."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["target"] = "192.0.2.10"

        mock_service = MagicMock()
        mock_service.service = "microsoft-ds"  # SMB service name
        engine.framework.database.get_services.return_value = [
            {"service": mock_service.service, "target": "192.0.2.10"}
        ]

        assert engine._service_exists("microsoft", workflow) is True

    def test_service_exists_partial_match(self, engine):
        """Test partial service name matching."""
        workflow = Workflow(id="wf", name="Test")
        workflow.variables["services"] = [
            {"service": "microsoft-ds", "port": 445},
        ]

        assert engine._service_exists("microsoft", workflow) is True


# =============================================================================
# Callback Integration Tests
# =============================================================================

class TestCallbackIntegration:
    """Tests for callback integration during workflow execution."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine with mock framework."""
        mock_framework = MagicMock()
        mock_module = MagicMock(
            set_option=MagicMock(return_value=True),
            options={'RHOST': {}},
            has_operations=MagicMock(return_value=False),
            run=MagicMock(return_value={'success': True}),
        )
        configure_framework_contract(mock_framework, mock_module)

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_on_step_start_called(self, engine):
        """Test on_step_start callback is called."""
        callback = MagicMock()
        engine.on_step_start = callback

        workflow = engine.create_workflow(name="Callback Test")
        workflow.add_step(name="Step", module="test")

        engine.run_workflow(workflow.id)

        callback.assert_called_once()

    def test_on_step_complete_called(self, engine):
        """Test on_step_complete callback is called."""
        callback = MagicMock()
        engine.on_step_complete = callback

        workflow = engine.create_workflow(name="Callback Test")
        workflow.add_step(name="Step", module="test")

        engine.run_workflow(workflow.id)

        callback.assert_called_once()

    def test_on_workflow_complete_called(self, engine):
        """Test on_workflow_complete callback is called."""
        callback = MagicMock()
        engine.on_workflow_complete = callback

        workflow = engine.create_workflow(name="Callback Test")
        workflow.add_step(name="Step", module="test")

        engine.run_workflow(workflow.id)

        callback.assert_called_once()

    def test_callback_receives_correct_data(self, engine):
        """Test callbacks receive correct data."""
        step_start_data = []
        step_complete_data = []
        workflow_complete_data = []

        def on_step_start(wf, step):
            step_start_data.append({'workflow': wf.id, 'step': step.id})

        def on_step_complete(wf, step, result):
            step_complete_data.append({
                'workflow': wf.id,
                'step': step.id,
                'success': result.get('success')
            })

        def on_workflow_complete(wf, results):
            workflow_complete_data.append({
                'workflow': wf.id,
                'steps_completed': results.get('steps_completed')
            })

        engine.on_step_start = on_step_start
        engine.on_step_complete = on_step_complete
        engine.on_workflow_complete = on_workflow_complete

        workflow = engine.create_workflow(name="Data Test")
        workflow.add_step(name="Step", module="test")

        engine.run_workflow(workflow.id)

        assert len(step_start_data) == 1
        assert step_start_data[0]['step'] == 'step_1'

        assert len(step_complete_data) == 1
        assert step_complete_data[0]['success'] is True

        assert len(workflow_complete_data) == 1
        assert workflow_complete_data[0]['steps_completed'] == 1


# =============================================================================
# Workflow Persistence Tests
# =============================================================================

class TestWorkflowPersistence:
    """Tests for workflow persistence (save/load/export/import)."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine for persistence testing."""
        engine = WorkflowEngine(framework=None)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_save_workflow_creates_file(self, engine):
        """Test saving workflow creates JSON file."""
        workflow = engine.create_workflow(name="Save Test")
        workflow.add_step(name="Step", module="test")

        engine._save_workflow(workflow)

        workflow_file = engine.storage_path / f"{workflow.id}.json"
        assert workflow_file.exists()

    def test_save_workflow_valid_json(self, engine):
        """Test saved workflow is valid JSON."""
        workflow = engine.create_workflow(name="JSON Test")
        workflow.add_step(name="Step", module="test")
        workflow.variables["key"] = "value"

        engine._save_workflow(workflow)

        workflow_file = engine.storage_path / f"{workflow.id}.json"
        with open(workflow_file) as f:
            data = json.load(f)

        assert data["name"] == "JSON Test"
        assert len(data["steps"]) == 1

    def test_load_workflow_from_storage(self, engine):
        """Test loading workflow from storage."""
        # Create and save
        workflow = engine.create_workflow(name="Load Test")
        workflow.add_step(name="Step", module="test")
        engine._save_workflow(workflow)

        # Remove from memory
        del engine.workflows[workflow.id]

        # Load
        loaded = engine.load_workflow(workflow.id)

        assert loaded is not None
        assert loaded.name == "Load Test"
        assert len(loaded.steps) == 1

    def test_load_nonexistent_workflow(self, engine):
        """Test loading non-existent workflow returns None."""
        result = engine.load_workflow("nonexistent")
        assert result is None

    def test_export_import_roundtrip(self, engine, tmp_path):
        """Test export and import preserves workflow data."""
        # Create original
        original = engine.create_workflow(name="Roundtrip Test")
        original.add_step(name="Step 1", module="m1")
        original.add_step(name="Step 2", module="m2")
        original.variables["target"] = "192.168.1.1"
        original.tags = ["test", "roundtrip"]

        # Export
        export_path = str(tmp_path / "exported.json")
        engine.export_workflow(original.id, export_path)

        # Import
        imported = engine.import_workflow(export_path)

        assert imported.name == original.name
        assert len(imported.steps) == len(original.steps)
        assert imported.variables == original.variables
        assert imported.tags == original.tags


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling during workflow execution."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine with mock framework."""
        mock_framework = MagicMock()
        mock_module = MagicMock(
            set_option=MagicMock(return_value=True),
            options={"RHOST": {}},
            has_operations=MagicMock(return_value=False),
            run=MagicMock(return_value={"success": True}),
        )
        configure_framework_contract(mock_framework, mock_module)

        engine = WorkflowEngine(framework=mock_framework)
        engine.storage_path = tmp_path / "workflows"
        engine.storage_path.mkdir(parents=True, exist_ok=True)
        return engine

    def test_step_execution_exception_handling(self, engine):
        """Test step execution handles exceptions."""
        workflow = engine.create_workflow(name="Exception Test")
        step = workflow.add_step(name="Fail", module="test")

        engine.framework.use_module = MagicMock(side_effect=Exception("Module error"))

        result = engine._execute_step(step, workflow)

        assert result["success"] is False
        assert "Module error" in result["error"]
        assert step.status == StepStatus.FAILED

    def test_workflow_handles_step_exception(self, engine):
        """Test workflow continues or stops appropriately on exception."""
        workflow = engine.create_workflow(name="Exception Workflow")
        workflow.add_step(name="Fail", module="test")

        engine.framework.get_module = MagicMock(side_effect=Exception("Crash"))

        result = engine.run_workflow(workflow.id)

        assert result["success"] is False
        assert "crash" in result["error"].lower()

    def test_module_not_found_handling(self, engine):
        """Test handling when module is not found."""
        workflow = Workflow(id="wf", name="No Module")
        step = WorkflowStep(id="step_1", name="Missing", module="nonexistent/module")
        workflow.steps.append(step)

        engine.framework.use_module = MagicMock(return_value=None)

        engine.workflows[workflow.id] = workflow
        result = engine._execute_step(step, workflow)

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_no_framework_handling(self, engine):
        """Test handling when no framework is available."""
        engine.framework = None

        workflow = Workflow(id="wf", name="No Framework")
        step = WorkflowStep(id="step_1", name="Step", module="test")
        workflow.steps.append(step)

        engine.workflows[workflow.id] = workflow
        result = engine._execute_step(step, workflow)

        assert result["success"] is False
        assert "no framework" in result["error"].lower()
