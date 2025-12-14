"""
Tests for module operations/submenu system.

Tests operation discovery, filtering, execution, and handler resolution.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any, List

from purplesploit.core.module import BaseModule, ExternalToolModule


# =============================================================================
# Test Fixtures
# =============================================================================

class MockOperationsModule(BaseModule):
    """Module with operations for testing."""

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "Test Operations Module"

    @property
    def description(self) -> str:
        return "Module for testing operations"

    @property
    def author(self) -> str:
        return "Test"

    @property
    def category(self) -> str:
        return "test"

    def get_operations(self) -> List[Dict[str, Any]]:
        return [
            {"name": "Auth Test", "description": "Test authentication", "handler": "op_auth_test", "subcategory": "authentication"},
            {"name": "Enum Users", "description": "Enumerate users", "handler": "op_enum_users", "subcategory": "enumeration"},
            {"name": "Enum Groups", "description": "Enumerate groups", "handler": "op_enum_groups", "subcategory": "enumeration"},
            {"name": "Exec Command", "description": "Execute command", "handler": self.op_exec_cmd, "subcategory": "execution"},
            {"name": "Simple Op", "description": "No subcategory operation", "handler": "op_simple"},
        ]

    def op_auth_test(self) -> Dict[str, Any]:
        return {"success": True, "output": "Authentication test passed"}

    def op_enum_users(self) -> Dict[str, Any]:
        return {"success": True, "output": ["user1", "user2", "user3"]}

    def op_enum_groups(self) -> Dict[str, Any]:
        return {"success": True, "output": ["admins", "users", "guests"]}

    def op_exec_cmd(self) -> Dict[str, Any]:
        return {"success": True, "output": "Command executed"}

    def op_simple(self) -> Dict[str, Any]:
        return {"success": True, "output": "Simple operation done"}

    def run(self) -> Dict[str, Any]:
        return {"success": True, "output": "Default run"}


class MockEmptyOperationsModule(BaseModule):
    """Module without operations for testing."""

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "Empty Operations Module"

    @property
    def description(self) -> str:
        return "Module without operations"

    @property
    def author(self) -> str:
        return "Test"

    @property
    def category(self) -> str:
        return "test"

    def run(self) -> Dict[str, Any]:
        return {"success": True}


@pytest.fixture
def mock_framework():
    """Create mock framework for testing."""
    framework = Mock()
    framework.session = Mock()
    framework.session.current_module = None
    framework.session.targets = Mock()
    framework.session.targets.get_current.return_value = None
    framework.session.credentials = Mock()
    framework.session.credentials.get_current.return_value = None
    framework.workspace = Mock()
    framework.workspace.logs_dir = "/tmp/test_logs"
    framework.database = Mock()
    # Return empty dict for module defaults to avoid iteration error
    framework.database.get_module_defaults.return_value = {}
    return framework


@pytest.fixture
def ops_module(mock_framework):
    """Create module with operations for testing."""
    return MockOperationsModule(mock_framework)


@pytest.fixture
def empty_module(mock_framework):
    """Create module without operations for testing."""
    return MockEmptyOperationsModule(mock_framework)


# =============================================================================
# Operation Discovery Tests
# =============================================================================

class TestOperationDiscovery:
    """Tests for operation discovery and listing."""

    def test_get_operations_returns_list(self, ops_module):
        """Test get_operations returns a list."""
        operations = ops_module.get_operations()
        assert isinstance(operations, list)

    def test_get_operations_returns_correct_count(self, ops_module):
        """Test correct number of operations returned."""
        operations = ops_module.get_operations()
        assert len(operations) == 5

    def test_operations_have_required_keys(self, ops_module):
        """Test each operation has required keys."""
        operations = ops_module.get_operations()
        for op in operations:
            assert "name" in op
            assert "description" in op
            assert "handler" in op

    def test_has_operations_true(self, ops_module):
        """Test has_operations returns True when operations exist."""
        assert ops_module.has_operations() is True

    def test_has_operations_false(self, empty_module):
        """Test has_operations returns False when no operations."""
        assert empty_module.has_operations() is False

    def test_get_operations_empty_module(self, empty_module):
        """Test get_operations returns empty list for module without operations."""
        operations = empty_module.get_operations()
        assert operations == []

    def test_operations_with_callable_handler(self, ops_module):
        """Test operations can have callable handlers."""
        operations = ops_module.get_operations()
        exec_op = [op for op in operations if op["name"] == "Exec Command"][0]
        assert callable(exec_op["handler"])

    def test_operations_with_string_handler(self, ops_module):
        """Test operations can have string handlers."""
        operations = ops_module.get_operations()
        auth_op = [op for op in operations if op["name"] == "Auth Test"][0]
        assert isinstance(auth_op["handler"], str)
        assert auth_op["handler"] == "op_auth_test"


# =============================================================================
# Subcategory Tests
# =============================================================================

class TestSubcategories:
    """Tests for subcategory filtering."""

    def test_get_subcategories_returns_list(self, ops_module):
        """Test get_subcategories returns a list."""
        subcategories = ops_module.get_subcategories()
        assert isinstance(subcategories, list)

    def test_get_subcategories_correct_values(self, ops_module):
        """Test correct subcategories are returned."""
        subcategories = ops_module.get_subcategories()
        assert "authentication" in subcategories
        assert "enumeration" in subcategories
        assert "execution" in subcategories

    def test_get_subcategories_sorted(self, ops_module):
        """Test subcategories are returned sorted."""
        subcategories = ops_module.get_subcategories()
        assert subcategories == sorted(subcategories)

    def test_get_subcategories_unique(self, ops_module):
        """Test subcategories are unique."""
        subcategories = ops_module.get_subcategories()
        assert len(subcategories) == len(set(subcategories))

    def test_get_subcategories_empty_module(self, empty_module):
        """Test get_subcategories returns empty for module without operations."""
        subcategories = empty_module.get_subcategories()
        assert subcategories == []

    def test_get_operations_by_subcategory_filter(self, ops_module):
        """Test filtering operations by subcategory."""
        enum_ops = ops_module.get_operations_by_subcategory("enumeration")
        assert len(enum_ops) == 2
        assert all(op["subcategory"] == "enumeration" for op in enum_ops)

    def test_get_operations_by_subcategory_case_insensitive(self, ops_module):
        """Test subcategory filtering is case-insensitive."""
        enum_ops_lower = ops_module.get_operations_by_subcategory("enumeration")
        enum_ops_upper = ops_module.get_operations_by_subcategory("ENUMERATION")
        enum_ops_mixed = ops_module.get_operations_by_subcategory("Enumeration")

        assert len(enum_ops_lower) == len(enum_ops_upper) == len(enum_ops_mixed)

    def test_get_operations_by_subcategory_none_returns_all(self, ops_module):
        """Test None subcategory returns all operations."""
        all_ops = ops_module.get_operations_by_subcategory(None)
        assert len(all_ops) == 5

    def test_get_operations_by_subcategory_nonexistent(self, ops_module):
        """Test filtering by nonexistent subcategory returns empty."""
        nonexistent_ops = ops_module.get_operations_by_subcategory("nonexistent")
        assert nonexistent_ops == []


# =============================================================================
# Operation Execution Tests
# =============================================================================

class TestOperationExecution:
    """Tests for operation handler execution."""

    def test_execute_string_handler(self, ops_module):
        """Test executing operation with string handler."""
        handler = "op_auth_test"
        method = getattr(ops_module, handler, None)
        assert method is not None

        result = method()
        assert result["success"] is True
        assert "output" in result

    def test_execute_callable_handler(self, ops_module):
        """Test executing operation with callable handler."""
        operations = ops_module.get_operations()
        exec_op = [op for op in operations if op["name"] == "Exec Command"][0]

        result = exec_op["handler"]()
        assert result["success"] is True
        assert result["output"] == "Command executed"

    def test_all_string_handlers_exist(self, ops_module):
        """Test all string handlers have corresponding methods."""
        operations = ops_module.get_operations()

        for op in operations:
            handler = op["handler"]
            if isinstance(handler, str):
                method = getattr(ops_module, handler, None)
                assert method is not None, f"Handler method '{handler}' not found"
                assert callable(method), f"Handler '{handler}' is not callable"

    def test_handler_returns_dict(self, ops_module):
        """Test handlers return dictionary results."""
        operations = ops_module.get_operations()

        for op in operations:
            handler = op["handler"]
            if isinstance(handler, str):
                method = getattr(ops_module, handler)
                result = method()
            else:
                result = handler()

            assert isinstance(result, dict)

    def test_handler_result_has_success(self, ops_module):
        """Test handler results have success key."""
        operations = ops_module.get_operations()

        for op in operations:
            handler = op["handler"]
            if isinstance(handler, str):
                method = getattr(ops_module, handler)
                result = method()
            else:
                result = handler()

            assert "success" in result


# =============================================================================
# Integration with CommandHandler Tests
# =============================================================================

class TestCommandHandlerIntegration:
    """Tests for command handler operation execution logic."""

    def test_execute_operation_string_handler(self, ops_module):
        """Test _execute_operation style logic with string handler."""
        operation = {"name": "Auth Test", "handler": "op_auth_test"}

        handler = operation["handler"]
        if isinstance(handler, str):
            method = getattr(ops_module, handler, None)
            result = method()
        else:
            result = handler()

        assert result["success"] is True

    def test_execute_operation_callable_handler(self, ops_module):
        """Test _execute_operation style logic with callable handler."""
        operation = {"name": "Exec Command", "handler": ops_module.op_exec_cmd}

        handler = operation["handler"]
        if isinstance(handler, str):
            method = getattr(ops_module, handler, None)
            result = method()
        else:
            result = handler()

        assert result["success"] is True

    def test_execute_operation_missing_handler(self, ops_module):
        """Test handling of missing handler method."""
        operation = {"name": "Bad Op", "handler": "nonexistent_method"}

        handler = operation["handler"]
        if isinstance(handler, str):
            method = getattr(ops_module, handler, None)
            if method is None:
                result = {"success": False, "error": f"Handler method not found: {handler}"}
            else:
                result = method()
        else:
            result = handler()

        assert result["success"] is False
        assert "not found" in result["error"]

    def test_find_operation_by_number(self, ops_module):
        """Test finding operation by index number."""
        operations = ops_module.get_operations()
        op_index = 1  # 1-based index

        if 0 <= op_index - 1 < len(operations):
            operation = operations[op_index - 1]
        else:
            operation = None

        assert operation is not None
        assert operation["name"] == "Auth Test"

    def test_find_operation_by_name(self, ops_module):
        """Test finding operation by name."""
        operations = ops_module.get_operations()
        op_name = "enum users"  # lowercase search

        operation = None
        for op in operations:
            if op["name"].lower() == op_name.lower():
                operation = op
                break

        assert operation is not None
        assert operation["name"] == "Enum Users"

    def test_find_operation_by_partial_name(self, ops_module):
        """Test finding operation by partial name match."""
        operations = ops_module.get_operations()
        search_term = "enum"

        matching = [op for op in operations if search_term.lower() in op["name"].lower()]

        assert len(matching) == 2
        assert all("Enum" in op["name"] for op in matching)


# =============================================================================
# Edge Cases
# =============================================================================

class TestOperationEdgeCases:
    """Edge case tests for operations."""

    def test_operation_with_no_subcategory(self, ops_module):
        """Test operation without subcategory is handled."""
        operations = ops_module.get_operations()
        simple_op = [op for op in operations if op["name"] == "Simple Op"][0]

        # Should not have subcategory key or have empty value
        subcategory = simple_op.get("subcategory", "")
        assert subcategory is None or subcategory == ""

    def test_operation_description_not_empty(self, ops_module):
        """Test all operations have non-empty descriptions."""
        operations = ops_module.get_operations()

        for op in operations:
            assert op["description"], f"Operation '{op['name']}' has empty description"

    def test_operation_names_unique(self, ops_module):
        """Test operation names are unique."""
        operations = ops_module.get_operations()
        names = [op["name"] for op in operations]

        assert len(names) == len(set(names)), "Duplicate operation names found"

    def test_handler_exception_handling(self, ops_module):
        """Test exception handling in handler execution."""
        # Create a mock handler that raises an exception
        def bad_handler():
            raise ValueError("Test error")

        operation = {"name": "Bad Handler", "handler": bad_handler}

        try:
            result = operation["handler"]()
        except Exception as e:
            result = {"success": False, "error": str(e)}

        assert result["success"] is False
        assert "Test error" in result["error"]


# =============================================================================
# ExternalToolModule Operations Tests
# =============================================================================

class MockExternalToolOpsModule(ExternalToolModule):
    """External tool module with operations for testing."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "test_tool"

    @property
    def name(self) -> str:
        return "External Tool Ops Module"

    @property
    def description(self) -> str:
        return "External tool module with operations"

    @property
    def author(self) -> str:
        return "Test"

    @property
    def category(self) -> str:
        return "test"

    def get_operations(self) -> List[Dict[str, Any]]:
        return [
            {"name": "Scan Basic", "description": "Basic scan", "handler": "op_scan_basic", "subcategory": "scanning"},
            {"name": "Scan Full", "description": "Full scan", "handler": "op_scan_full", "subcategory": "scanning"},
        ]

    def op_scan_basic(self) -> Dict[str, Any]:
        return {"success": True, "output": "Basic scan complete"}

    def op_scan_full(self) -> Dict[str, Any]:
        return {"success": True, "output": "Full scan complete"}


class TestExternalToolModuleOperations:
    """Tests for ExternalToolModule operations."""

    @pytest.fixture
    def ext_module(self, mock_framework):
        """Create external tool module with operations."""
        return MockExternalToolOpsModule(mock_framework)

    def test_external_module_has_operations(self, ext_module):
        """Test external tool module can have operations."""
        assert ext_module.has_operations() is True

    def test_external_module_operations_list(self, ext_module):
        """Test external tool module returns operations list."""
        operations = ext_module.get_operations()
        assert len(operations) == 2

    def test_external_module_operation_handlers(self, ext_module):
        """Test external tool module operation handlers work."""
        result = ext_module.op_scan_basic()
        assert result["success"] is True

    def test_external_module_subcategories(self, ext_module):
        """Test external tool module subcategories."""
        subcategories = ext_module.get_subcategories()
        assert "scanning" in subcategories
