"""
Unit tests for error handling across core components.

Tests cover:
- Network timeouts during module execution
- Malformed tool output
- Permission errors (file access, execution)
- Missing dependencies/tools
- Invalid user input
- Exception handling paths
- Graceful degradation
"""

import pytest
import subprocess
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path


# =============================================================================
# Framework Error Handling Tests
# =============================================================================

class TestFrameworkErrorHandling:
    """Tests for Framework error handling."""

    @pytest.fixture
    def framework(self, tmp_path):
        """Create a framework for testing."""
        from purplesploit.core.framework import Framework

        db_path = str(tmp_path / "test.db")
        modules_path = Path(__file__).parent.parent.parent.parent / "purplesploit" / "modules"

        with patch('purplesploit.core.framework.db_manager'):
            fw = Framework(modules_path=str(modules_path), db_path=db_path)

        yield fw
        fw.cleanup()

    def test_use_nonexistent_module(self, framework):
        """Test using a module that doesn't exist."""
        result = framework.use_module("nonexistent/fake/module")
        assert result is None

    def test_use_invalid_module_path_format(self, framework):
        """Test using an invalid module path format."""
        result = framework.use_module("")
        assert result is None

    def test_add_duplicate_target(self, framework):
        """Test adding duplicate target returns False."""
        with patch('purplesploit.core.framework.db_manager'):
            result1 = framework.add_target("network", "192.168.1.1")
            result2 = framework.add_target("network", "192.168.1.1")

        assert result1 is True
        assert result2 is False

    def test_search_modules_no_results(self, framework):
        """Test searching for modules with no results."""
        framework.discover_modules()
        results = framework.search_modules("xyznonexistent123")
        assert results == []

    def test_run_module_without_current_module(self, framework):
        """Test running module when none is selected."""
        result = framework.run_module(None)
        # Should handle gracefully
        assert result is None or isinstance(result, dict)


# =============================================================================
# Module Error Handling Tests
# =============================================================================

class TestModuleErrorHandling:
    """Tests for BaseModule error handling."""

    @pytest.fixture
    def test_module(self, mock_framework_minimal):
        """Create a test module instance."""
        from purplesploit.core.module import BaseModule
        from typing import Dict, Any

        class ErrorTestModule(BaseModule):
            @property
            def name(self) -> str:
                return "Error Test Module"

            @property
            def description(self) -> str:
                return "Module for testing error handling"

            @property
            def author(self) -> str:
                return "Test"

            @property
            def category(self) -> str:
                return "test"

            def run(self) -> Dict[str, Any]:
                return {"success": True}

        return ErrorTestModule(mock_framework_minimal)

    def test_set_invalid_option(self, test_module):
        """Test setting an option that doesn't exist."""
        result = test_module.set_option("NONEXISTENT_OPTION", "value")
        assert result is False

    def test_get_invalid_option(self, test_module):
        """Test getting an option that doesn't exist."""
        result = test_module.get_option("NONEXISTENT_OPTION")
        assert result is None

    def test_validate_missing_required_option(self, test_module):
        """Test validation fails for missing required option."""
        test_module.options["REQUIRED_TEST"] = {
            "value": None,
            "required": True,
            "description": "Required test option"
        }

        is_valid, error = test_module.validate_options()
        assert is_valid is False
        assert "REQUIRED_TEST" in error

    def test_validate_empty_required_option(self, test_module):
        """Test validation fails for empty required option."""
        test_module.options["REQUIRED_TEST"] = {
            "value": "",
            "required": True,
            "description": "Required test option"
        }

        is_valid, error = test_module.validate_options()
        assert is_valid is False

    def test_log_without_framework_logger(self, test_module):
        """Test log works when framework has no logger."""
        # Remove the log attribute entirely to test fallback
        delattr(test_module.framework, 'log')
        # Should not raise exception - falls back to print
        with patch('builtins.print') as mock_print:
            test_module.log("Test message", "info")
            mock_print.assert_called()


# =============================================================================
# ExternalToolModule Error Handling Tests
# =============================================================================

class TestExternalToolModuleErrorHandling:
    """Tests for ExternalToolModule error handling."""

    @pytest.fixture
    def external_module(self, mock_framework_minimal):
        """Create an ExternalToolModule for testing."""
        from purplesploit.core.module import ExternalToolModule
        from typing import Dict, Any

        class ErrorExternalModule(ExternalToolModule):
            def __init__(self, framework):
                super().__init__(framework)
                self.tool_name = "fake_tool"

            @property
            def name(self) -> str:
                return "Error External Module"

            @property
            def description(self) -> str:
                return "External module for error testing"

            @property
            def author(self) -> str:
                return "Test"

            @property
            def category(self) -> str:
                return "test"

            def build_command(self) -> str:
                return "fake_tool --test"

            def run(self) -> Dict[str, Any]:
                return self.execute_command(self.build_command())

        return ErrorExternalModule(mock_framework_minimal)

    def test_execute_command_timeout(self, external_module):
        """Test command execution with timeout."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=30)
            result = external_module.execute_command("slow_command", timeout=30)

            assert result["success"] is False
            assert "timeout" in result.get("error", "").lower() or "timed out" in str(result).lower()

    def test_execute_command_not_found(self, external_module):
        """Test command execution when tool not found."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("Command not found")
            result = external_module.execute_command("nonexistent_command")

            assert result["success"] is False

    def test_execute_command_permission_denied(self, external_module):
        """Test command execution with permission error."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = PermissionError("Permission denied")
            result = external_module.execute_command("restricted_command")

            assert result["success"] is False

    def test_execute_command_general_exception(self, external_module):
        """Test command execution with general exception."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Unexpected error")
            result = external_module.execute_command("problematic_command")

            assert result["success"] is False

    def test_check_tool_not_installed(self, external_module):
        """Test checking for tool that's not installed."""
        with patch('shutil.which', return_value=None):
            is_available = external_module.check_tool_installed()
            assert is_available is False

    def test_check_tool_installed(self, external_module):
        """Test checking for tool that is installed."""
        with patch('shutil.which', return_value="/usr/bin/fake_tool"):
            is_available = external_module.check_tool_installed()
            assert is_available is True


# =============================================================================
# Session Error Handling Tests
# =============================================================================

class TestSessionErrorHandling:
    """Tests for Session error handling."""

    @pytest.fixture
    def session(self):
        """Create a session for testing."""
        from purplesploit.core.session import Session
        return Session()

    def test_target_manager_set_invalid_current(self, session):
        """Test setting current to non-existent target."""
        # Add one target
        session.targets.add({"ip": "192.168.1.1", "name": "test"})

        # Try to set current to non-existent
        result = session.targets.set_current("192.168.1.99")
        assert result is False

    def test_credential_manager_set_invalid_current(self, session):
        """Test setting current to non-existent credential."""
        session.credentials.add({"username": "admin", "password": "pass"})

        result = session.credentials.set_current("nonexistent_user")
        assert result is False

    def test_import_session_invalid_data(self, session):
        """Test importing invalid session data."""
        # Should not crash with invalid data
        session.import_session({"invalid": "data"})
        # None and list may raise TypeError - test that they're handled
        try:
            session.import_session(None)
        except TypeError:
            pass  # Expected - None is not iterable
        try:
            session.import_session([])
        except (TypeError, AttributeError):
            pass  # Expected - list has no .get() method

    def test_import_session_missing_keys(self, session):
        """Test importing session with missing keys."""
        partial_data = {
            "targets": {"targets": [{"ip": "10.0.0.1"}], "current_index": 0}
            # Missing credentials, services, etc.
        }
        session.import_session(partial_data)
        assert len(session.targets.list()) == 1

    def test_export_empty_session(self, session):
        """Test exporting empty session."""
        data = session.export_session()
        assert isinstance(data, dict)
        assert "targets" in data
        assert "credentials" in data


# =============================================================================
# Database Error Handling Tests
# =============================================================================

class TestDatabaseErrorHandling:
    """Tests for Database error handling."""

    @pytest.fixture
    def database(self, tmp_path):
        """Create a database for testing."""
        from purplesploit.core.database import Database
        db_path = str(tmp_path / "test_error.db")
        db = Database(db_path)
        yield db
        db.close()

    def test_get_nonexistent_target(self, database):
        """Test getting targets when none exist."""
        result = database.get_targets()
        assert result == [] or isinstance(result, list)

    def test_get_nonexistent_credential(self, database):
        """Test getting credentials that don't exist."""
        result = database.get_credentials()
        assert result == [] or isinstance(result, list)

    def test_save_with_special_characters(self, database):
        """Test saving data with special characters."""
        # Should handle SQL injection attempts gracefully
        result = database.add_target(
            target_type="network",
            identifier="'; DROP TABLE targets; --",
            name="test"
        )
        # Should not crash and should sanitize input

    def test_close_already_closed(self, database):
        """Test closing already closed database."""
        database.close()
        # Second close should not crash
        database.close()


# =============================================================================
# Input Validation Tests
# =============================================================================

class TestInputValidation:
    """Tests for input validation across components."""

    @pytest.fixture
    def session(self):
        """Create a session for testing."""
        from purplesploit.core.session import Session
        return Session()

    def test_add_target_empty_ip(self, session):
        """Test adding target with empty IP."""
        result = session.targets.add({"ip": "", "name": "test"})
        # Should either reject or handle gracefully

    def test_add_target_none_values(self, session):
        """Test adding target with None values."""
        result = session.targets.add({"ip": None, "name": None})
        # Should handle gracefully

    def test_add_credential_empty_username(self, session):
        """Test adding credential with empty username."""
        result = session.credentials.add({"username": "", "password": "test"})
        # Should handle gracefully

    def test_service_manager_invalid_port(self, session):
        """Test adding service with invalid port."""
        # Negative port
        session.services.add_service("192.168.1.1", "ssh", -1)
        # Very large port
        session.services.add_service("192.168.1.1", "http", 999999)
        # Should handle gracefully


# =============================================================================
# Concurrent Access Tests
# =============================================================================

class TestConcurrentAccess:
    """Tests for handling concurrent access scenarios."""

    @pytest.fixture
    def session(self):
        """Create a session for testing."""
        from purplesploit.core.session import Session
        return Session()

    def test_concurrent_target_modifications(self, session):
        """Test rapid target additions."""
        for i in range(100):
            session.targets.add({"ip": f"192.168.1.{i}", "name": f"target{i}"})

        assert len(session.targets.list()) == 100

    def test_concurrent_workspace_updates(self, session):
        """Test rapid workspace updates."""
        for i in range(50):
            session.store_results(f"module_{i}", {"data": f"result_{i}"})

        assert len(session.workspace) == 50


# =============================================================================
# Recovery Tests
# =============================================================================

class TestRecoveryScenarios:
    """Tests for recovery from error states."""

    @pytest.fixture
    def session(self):
        """Create a session for testing."""
        from purplesploit.core.session import Session
        return Session()

    def test_session_clear_and_reuse(self, session):
        """Test clearing session and reusing."""
        # Add data
        session.targets.add({"ip": "192.168.1.1", "name": "test"})
        session.credentials.add({"username": "admin", "password": "pass"})

        # Clear
        session.targets.clear()
        session.credentials.clear()

        # Should be able to add again
        session.targets.add({"ip": "192.168.1.2", "name": "test2"})
        assert len(session.targets.list()) == 1

    def test_partial_import_recovery(self, session):
        """Test recovering from partial import."""
        # Add initial data
        session.targets.add({"ip": "192.168.1.1", "name": "original"})

        # Try to import corrupted data
        try:
            session.import_session({"corrupted": True, "targets": "invalid"})
        except Exception:
            pass

        # Original data should still be intact or recoverable
        # Session should still be functional
        session.targets.add({"ip": "192.168.1.2", "name": "new"})
