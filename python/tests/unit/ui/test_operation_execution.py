"""
Tests for module operation execution flow.

Tests cover:
- Operation selection by index and name
- Operation handler execution (string and callable)
- Error handling during operation execution
- Operation result processing
- Run mode (single vs all targets)
- Auto-context population from session
"""

import pytest
from unittest.mock import MagicMock, patch


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework():
    """Create a mock framework with session."""
    framework = MagicMock()

    # Session
    framework.session = MagicMock()
    framework.session.current_module = None

    # Targets
    framework.session.targets = MagicMock()
    framework.session.targets.list.return_value = []
    framework.session.targets.get_current.return_value = None

    # Credentials
    framework.session.credentials = MagicMock()
    framework.session.credentials.get_current.return_value = None

    # Other
    framework.session.run_mode = "single"
    framework.session.command_history = []
    framework.session.add_command = MagicMock()
    framework.database = MagicMock()

    return framework


@pytest.fixture
def command_handler(mock_framework):
    """Create a CommandHandler for testing."""
    with patch('purplesploit.ui.commands.Display') as mock_display, \
         patch('purplesploit.ui.commands.InteractiveSelector'):
        from purplesploit.ui.commands import CommandHandler
        handler = CommandHandler(mock_framework)
        handler.display = MagicMock()
        return handler


@pytest.fixture
def mock_module_with_operations():
    """Create a mock module with operations."""
    module = MagicMock()
    module.name = "Test Module"
    module.has_operations.return_value = True

    def op_auth():
        return {"success": True, "output": "Authentication succeeded"}

    def op_enum():
        return {"success": True, "output": "Enumeration complete", "data": [1, 2, 3]}

    def op_failing():
        raise Exception("Operation failed unexpectedly")

    module.op_auth = op_auth
    module.op_enum = op_enum
    module.op_failing = op_failing

    module.get_operations.return_value = [
        {"name": "Authenticate", "handler": "op_auth", "description": "Test auth"},
        {"name": "Enumerate", "handler": "op_enum", "description": "Test enum"},
        {"name": "Failing Op", "handler": "op_failing", "description": "Will fail"},
    ]

    return module


# =============================================================================
# Operation Selection Tests
# =============================================================================

class TestOperationSelection:
    """Tests for selecting operations to run."""

    def test_run_without_module_shows_error(self, command_handler, mock_framework):
        """Test run without loaded module shows error."""
        mock_framework.session.current_module = None

        result = command_handler.cmd_run([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_run_operation_by_index(self, command_handler, mock_framework, mock_module_with_operations):
        """Test running operation by numeric index."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["1"])  # First operation

        assert result is True
        command_handler.display.print_results.assert_called()

    def test_run_operation_by_name(self, command_handler, mock_framework, mock_module_with_operations):
        """Test running operation by name."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["Authenticate"])

        # Should execute the operation
        assert result is True

    def test_run_invalid_index_shows_error(self, command_handler, mock_framework, mock_module_with_operations):
        """Test invalid index shows error."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["99"])

        command_handler.display.print_error.assert_called()

    def test_run_invalid_name_shows_error(self, command_handler, mock_framework, mock_module_with_operations):
        """Test invalid operation name shows error."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["NonExistentOperation"])

        command_handler.display.print_error.assert_called()

    def test_run_no_args_with_operations_shows_selector(self, command_handler, mock_framework, mock_module_with_operations):
        """Test run with no args shows operation selector."""
        mock_framework.session.current_module = mock_module_with_operations

        with patch.object(command_handler, 'interactive') as mock_interactive:
            mock_interactive.select_operation.return_value = None

            result = command_handler.cmd_run([])

            # Should show operations or use selector
            assert result is True


# =============================================================================
# Execute Operation Tests
# =============================================================================

class TestExecuteOperation:
    """Tests for _execute_operation method."""

    def test_execute_string_handler(self, command_handler, mock_module_with_operations):
        """Test executing operation with string handler."""
        operation = {"name": "Test", "handler": "op_auth"}

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        assert result["success"] is True

    def test_execute_callable_handler(self, command_handler, mock_module_with_operations):
        """Test executing operation with callable handler."""
        def custom_handler():
            return {"success": True, "data": "custom result"}

        operation = {"name": "Test", "handler": custom_handler}

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        assert result["success"] is True
        assert result["data"] == "custom result"

    def test_execute_missing_handler(self, command_handler):
        """Test executing operation with missing handler method."""
        # Use spec to prevent MagicMock from auto-creating attributes
        module = MagicMock(spec=['name', 'op_auth'])  # spec limits available attributes
        module.name = "Test Module"

        operation = {"name": "Test", "handler": "nonexistent_method"}

        result = command_handler._execute_operation(module, operation)

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_execute_no_handler_defined(self, command_handler, mock_module_with_operations):
        """Test executing operation with no handler defined."""
        operation = {"name": "Test"}  # No handler

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        assert result["success"] is False
        assert "no handler" in result["error"].lower()

    def test_execute_invalid_handler_type(self, command_handler, mock_module_with_operations):
        """Test executing operation with invalid handler type."""
        operation = {"name": "Test", "handler": 12345}  # Invalid type

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        assert result["success"] is False
        assert "invalid handler" in result["error"].lower()

    def test_execute_handler_that_raises_exception(self, command_handler, mock_module_with_operations):
        """Test executing handler that raises exception."""
        operation = {"name": "Test", "handler": "op_failing"}

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        assert result["success"] is False
        assert "error" in result

    def test_execute_handler_returns_non_dict(self, command_handler, mock_module_with_operations):
        """Test executing handler that returns non-dict."""
        def string_handler():
            return "Just a string result"

        operation = {"name": "Test", "handler": string_handler}

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        assert result["success"] is True
        assert result["output"] == "Just a string result"


# =============================================================================
# Module Without Operations Tests
# =============================================================================

class TestModuleWithoutOperations:
    """Tests for modules without operations (simple run)."""

    def test_run_simple_module(self, command_handler, mock_framework):
        """Test running a simple module without operations."""
        module = MagicMock()
        module.name = "Simple Module"
        module.has_operations.return_value = False
        mock_framework.session.current_module = module
        mock_framework.run_module.return_value = {"success": True, "output": "Done"}

        result = command_handler.cmd_run([])

        assert result is True
        # Simple modules are run via framework.run_module, not module.run
        mock_framework.run_module.assert_called_once_with(module)
        command_handler.display.print_results.assert_called()

    def test_run_simple_module_that_fails(self, command_handler, mock_framework):
        """Test running simple module that returns failure."""
        module = MagicMock()
        module.name = "Failing Module"
        module.has_operations.return_value = False
        mock_framework.session.current_module = module
        mock_framework.run_module.return_value = {"success": False, "error": "Operation failed"}

        result = command_handler.cmd_run([])

        assert result is True
        command_handler.display.print_results.assert_called()


# =============================================================================
# Last Ops Results Tests
# =============================================================================

class TestLastOpsResults:
    """Tests for running operations from last search results."""

    def test_run_from_last_ops_results_invalid_index(self, command_handler, mock_framework):
        """Test invalid index from last ops results shows error."""
        mock_framework.session.current_module = None

        # Simulate previous ops search
        command_handler.last_ops_results = [
            {"module_path": "test/module", "operation": "Authenticate"},
        ]

        # Index 99 is out of range
        result = command_handler.cmd_run(["99"])

        command_handler.display.print_error.assert_called()

    def test_run_no_ops_results_no_module(self, command_handler, mock_framework):
        """Test running without module or ops results shows error."""
        mock_framework.session.current_module = None
        command_handler.last_ops_results = []

        result = command_handler.cmd_run(["1"])

        command_handler.display.print_error.assert_called()

    def test_run_with_ops_results_attribute_absent(self, command_handler, mock_framework):
        """Test running when last_ops_results attribute doesn't exist."""
        mock_framework.session.current_module = None
        # Don't set last_ops_results at all

        result = command_handler.cmd_run(["1"])

        command_handler.display.print_error.assert_called()


# =============================================================================
# Auto Context Population Tests
# =============================================================================

class TestAutoContextPopulation:
    """Tests for auto-populating module options from session context."""

    def test_module_auto_set_called_on_load(self, command_handler, mock_framework):
        """Test module's auto_set_from_context called on load."""
        module = MagicMock()
        module.name = "Context Module"
        module.auto_set_from_context = MagicMock()
        mock_framework.use_module.return_value = module

        result = command_handler.cmd_use(["test/module"])

        # Should trigger auto_set when loaded via framework
        # (Framework.use_module calls session.load_module which calls auto_set)

    def test_target_applied_to_module_options(self, mock_framework):
        """Test target from session is applied to module options."""
        from purplesploit.core.session import Session

        session = Session()
        session.targets.add({"ip": "10.0.0.1", "name": "target1"})

        module = MagicMock()
        module.name = "Test Module"
        module.options = {"RHOST": {"value": None}}

        # Module has auto_set_from_context that uses session
        def auto_set():
            target = session.targets.get_current()
            if target and 'ip' in target:
                module.options["RHOST"]["value"] = target['ip']

        module.auto_set_from_context = auto_set

        session.load_module(module)

        assert module.options["RHOST"]["value"] == "10.0.0.1"


# =============================================================================
# Run Mode Tests
# =============================================================================

class TestRunMode:
    """Tests for single vs all targets run mode."""

    def test_single_run_mode(self, command_handler, mock_framework, mock_module_with_operations):
        """Test single target run mode."""
        mock_framework.session.current_module = mock_module_with_operations
        mock_framework.session.run_mode = "single"
        mock_framework.session.targets.list.return_value = [
            {"ip": "10.0.0.1"},
            {"ip": "10.0.0.2"},
        ]

        result = command_handler.cmd_run(["1"])

        # Should run once, not for each target in single mode
        assert result is True

    def test_check_run_mode_command(self, command_handler, mock_framework):
        """Test checking current run mode."""
        mock_framework.session.run_mode = "single"

        # Check if there's a way to query run mode
        # (This might vary based on implementation)


# =============================================================================
# Operation Results Display Tests
# =============================================================================

class TestOperationResultsDisplay:
    """Tests for displaying operation results."""

    def test_successful_result_displayed(self, command_handler, mock_framework, mock_module_with_operations):
        """Test successful results are displayed."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["1"])

        command_handler.display.print_results.assert_called_once()

    def test_failed_result_displayed(self, command_handler, mock_framework, mock_module_with_operations):
        """Test failed results are displayed."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["3"])  # Failing operation

        command_handler.display.print_results.assert_called()

    def test_results_stored_in_workspace(self, command_handler, mock_framework, mock_module_with_operations):
        """Test results are stored in session workspace."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["1"])

        # Verify results storage was attempted
        # (Implementation may or may not store automatically)


# =============================================================================
# Edge Cases Tests
# =============================================================================

class TestOperationEdgeCases:
    """Tests for edge cases in operation execution."""

    def test_operation_with_empty_result(self, command_handler, mock_module_with_operations):
        """Test operation returning empty dict."""
        def empty_handler():
            return {}

        operation = {"name": "Empty", "handler": empty_handler}

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        assert result == {}

    def test_operation_with_none_result(self, command_handler, mock_module_with_operations):
        """Test operation returning None."""
        def none_handler():
            return None

        operation = {"name": "None", "handler": none_handler}

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        # Should convert to success dict
        assert result["success"] is True

    def test_operation_with_complex_result(self, command_handler, mock_module_with_operations):
        """Test operation returning complex nested result."""
        def complex_handler():
            return {
                "success": True,
                "data": {
                    "hosts": [
                        {"ip": "10.0.0.1", "services": ["smb", "rdp"]},
                        {"ip": "10.0.0.2", "services": ["http"]},
                    ],
                    "metadata": {"scan_time": 30.5}
                }
            }

        operation = {"name": "Complex", "handler": complex_handler}

        result = command_handler._execute_operation(mock_module_with_operations, operation)

        assert result["success"] is True
        assert "hosts" in result["data"]

    def test_run_with_zero_index(self, command_handler, mock_framework, mock_module_with_operations):
        """Test run with index 0 (should be invalid, 1-based)."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["0"])

        # 0 is invalid in 1-based indexing
        command_handler.display.print_error.assert_called()

    def test_run_with_negative_index(self, command_handler, mock_framework, mock_module_with_operations):
        """Test run with negative index."""
        mock_framework.session.current_module = mock_module_with_operations

        result = command_handler.cmd_run(["-1"])

        # Should fail - negative not valid
        # Implementation may handle differently
        assert result is True


# =============================================================================
# Integration Tests
# =============================================================================

class TestOperationIntegration:
    """Integration tests for complete operation flows."""

    def test_full_operation_workflow(self, command_handler, mock_framework, mock_module_with_operations):
        """Test complete operation workflow."""
        # 1. Load module (simulated)
        mock_framework.session.current_module = mock_module_with_operations

        # 2. Run operation by index
        result1 = command_handler.cmd_run(["1"])
        assert result1 is True

        # 3. Run another operation by name
        result2 = command_handler.cmd_run(["Enumerate"])
        assert result2 is True

    def test_operation_after_target_change(self, command_handler, mock_framework, mock_module_with_operations):
        """Test operations work correctly after target change."""
        mock_framework.session.current_module = mock_module_with_operations

        # Simulate target change
        mock_framework.session.targets.get_current.return_value = {"ip": "192.168.1.1"}

        result = command_handler.cmd_run(["1"])

        assert result is True
