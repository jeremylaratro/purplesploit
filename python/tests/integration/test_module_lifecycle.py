"""
Integration tests for module lifecycle in PurpleSploit.

Tests the complete flow from loading a module through execution,
including context propagation and result storage.
"""

import pytest
from unittest.mock import MagicMock, patch
from purplesploit.core.session import Session
from purplesploit.core.database import Database
from purplesploit.core.module import BaseModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def integration_framework(tmp_path):
    """Create a framework with real session and database for integration tests."""
    framework = MagicMock()
    framework.session = Session()
    framework.database = Database(str(tmp_path / "test.db"))
    framework.log = MagicMock()

    def add_target(target_type, identifier, name=None):
        if target_type == "network":
            return framework.session.targets.add({
                "ip": identifier,
                "name": name or identifier,
                "type": target_type
            })
        else:
            return framework.session.targets.add({
                "url": identifier,
                "name": name or identifier,
                "type": target_type
            })

    framework.add_target = add_target
    yield framework
    framework.database.close()


@pytest.fixture
def test_module_class():
    """Create a concrete test module class."""
    class IntegrationTestModule(BaseModule):
        @property
        def name(self):
            return "Integration Test Module"

        @property
        def description(self):
            return "Module for integration testing"

        @property
        def author(self):
            return "Test"

        @property
        def category(self):
            return "test"

        @property
        def required_options(self):
            return ["RHOST"]

        def _init_options(self):
            self.options = {
                "RHOST": {"value": None, "required": True, "description": "Target", "default": None},
                "RPORT": {"value": 80, "required": False, "description": "Port", "default": 80},
                "USERNAME": {"value": None, "required": False, "description": "User", "default": None},
                "PASSWORD": {"value": None, "required": False, "description": "Pass", "default": None},
            }

        def run(self):
            rhost = self.get_option("RHOST")
            rport = self.get_option("RPORT")
            return {
                "success": True,
                "target": rhost,
                "port": rport,
                "message": f"Scanned {rhost}:{rport}"
            }

    return IntegrationTestModule


# =============================================================================
# Module Lifecycle Tests
# =============================================================================

@pytest.mark.integration
class TestModuleLifecycle:
    """Tests for the complete module lifecycle."""

    def test_load_set_validate_run(self, integration_framework, test_module_class):
        """Test complete module lifecycle: load -> set options -> validate -> run."""
        # Create and load module
        module = test_module_class(integration_framework)
        integration_framework.session.load_module(module)

        assert integration_framework.session.current_module is module

        # Set options
        module.set_option("RHOST", "192.168.1.100")
        module.set_option("RPORT", 443)

        # Validate
        is_valid, error = module.validate_options()
        assert is_valid is True

        # Run
        result = module.run()
        assert result["success"] is True
        assert result["target"] == "192.168.1.100"
        assert result["port"] == 443

    def test_validation_prevents_run(self, integration_framework, test_module_class):
        """Test that validation errors prevent execution."""
        module = test_module_class(integration_framework)

        # Don't set required option
        is_valid, error = module.validate_options()

        assert is_valid is False
        assert "RHOST" in error

    def test_module_switch_preserves_context(self, integration_framework, test_module_class):
        """Test that context persists when switching modules."""
        # Add target and credential to context
        integration_framework.session.targets.add({
            "ip": "192.168.1.100",
            "name": "target1"
        })
        integration_framework.session.credentials.add({
            "username": "admin",
            "password": "secret"
        })

        # Load first module
        module1 = test_module_class(integration_framework)
        integration_framework.session.load_module(module1)

        # Context should be auto-set
        assert module1.get_option("RHOST") == "192.168.1.100"
        assert module1.get_option("USERNAME") == "admin"

        # Load second module
        module2 = test_module_class(integration_framework)
        integration_framework.session.load_module(module2)

        # Context should still be available
        assert module2.get_option("RHOST") == "192.168.1.100"
        assert module2.get_option("USERNAME") == "admin"

        # First module should be in history
        assert len(integration_framework.session.module_history) == 1

    def test_results_stored_in_workspace(self, integration_framework, test_module_class):
        """Test that module results are stored in workspace."""
        module = test_module_class(integration_framework)
        module.set_option("RHOST", "192.168.1.100")

        result = module.run()

        # Store results
        integration_framework.session.store_results("test_module", result)

        # Retrieve results
        stored = integration_framework.session.get_results("test_module")
        assert len(stored) == 1
        assert stored[0]["results"]["success"] is True


# =============================================================================
# Context Propagation Tests
# =============================================================================

@pytest.mark.integration
class TestContextPropagation:
    """Tests for context propagation between session and modules."""

    def test_target_auto_populates_rhost(self, integration_framework, test_module_class):
        """Test target context auto-populates RHOST option."""
        integration_framework.session.targets.add({
            "ip": "10.0.0.1",
            "name": "test-target"
        })

        module = test_module_class(integration_framework)
        integration_framework.session.load_module(module)

        assert module.get_option("RHOST") == "10.0.0.1"

    def test_credential_auto_populates_auth(self, integration_framework, test_module_class):
        """Test credential context auto-populates auth options."""
        integration_framework.session.credentials.add({
            "username": "testuser",
            "password": "testpass",
            "domain": "TESTDOMAIN"
        })

        module = test_module_class(integration_framework)
        integration_framework.session.load_module(module)

        assert module.get_option("USERNAME") == "testuser"
        assert module.get_option("PASSWORD") == "testpass"

    def test_user_set_option_not_overwritten(self, integration_framework, test_module_class):
        """Test user-set options are not overwritten by context."""
        integration_framework.session.targets.add({
            "ip": "192.168.1.1",
            "name": "context-target"
        })

        module = test_module_class(integration_framework)
        module.set_option("RHOST", "10.0.0.99")  # User sets different value

        integration_framework.session.load_module(module)

        # Should keep user's value
        assert module.get_option("RHOST") == "10.0.0.99"

    def test_multiple_targets_uses_current(self, integration_framework, test_module_class):
        """Test that multiple targets use the current one."""
        integration_framework.session.targets.add({"ip": "192.168.1.1", "name": "target1"})
        integration_framework.session.targets.add({"ip": "192.168.1.2", "name": "target2"})
        integration_framework.session.targets.add({"ip": "192.168.1.3", "name": "target3"})

        # Set current to second target
        integration_framework.session.targets.set_current("1")

        module = test_module_class(integration_framework)
        integration_framework.session.load_module(module)

        assert module.get_option("RHOST") == "192.168.1.2"


# =============================================================================
# Database Integration Tests
# =============================================================================

@pytest.mark.integration
class TestDatabaseIntegration:
    """Tests for database integration in module operations."""

    def test_module_execution_recorded(self, integration_framework, test_module_class):
        """Test module execution is recorded in database."""
        module = test_module_class(integration_framework)
        module.set_option("RHOST", "192.168.1.100")

        result = module.run()

        # Record execution
        integration_framework.database.add_module_execution(
            module_name=module.name,
            module_path="test/integration",
            options=module.show_options(),
            results=result,
            success=result["success"]
        )

        # Verify recording
        history = integration_framework.database.get_module_history()
        assert len(history) == 1
        assert history[0]["module_name"] == "Integration Test Module"

    def test_discovered_targets_added_to_db(self, integration_framework):
        """Test discovered targets are added to database."""
        # Simulate discovery
        integration_framework.database.add_target(
            target_type="network",
            identifier="192.168.1.100",
            name="discovered-host"
        )

        # Verify in database
        targets = integration_framework.database.get_targets()
        assert len(targets) == 1
        assert targets[0]["identifier"] == "192.168.1.100"

    def test_services_recorded_in_db(self, integration_framework):
        """Test discovered services are recorded in database."""
        # Simulate service discovery
        integration_framework.database.add_service(
            target="192.168.1.100",
            service="ssh",
            port=22,
            version="OpenSSH 8.0"
        )

        # Verify in database
        services = integration_framework.database.get_services(target="192.168.1.100")
        assert len(services) == 1
        assert services[0]["service"] == "ssh"


# =============================================================================
# Session State Tests
# =============================================================================

@pytest.mark.integration
class TestSessionState:
    """Tests for session state management."""

    def test_session_export_import_roundtrip(self, integration_framework, test_module_class):
        """Test session can be exported and imported."""
        # Set up session state
        integration_framework.session.targets.add({"ip": "192.168.1.1", "name": "target1"})
        integration_framework.session.credentials.add({"username": "admin", "password": "pass"})
        integration_framework.session.services.add_service("192.168.1.1", "ssh", 22)

        # Export
        exported = integration_framework.session.export_session()

        # Create new session and import
        new_session = Session()
        new_session.import_session(exported)

        # Verify state
        assert len(new_session.targets.list()) == 1
        assert len(new_session.credentials.list()) == 1
        assert new_session.services.has_service("192.168.1.1", "ssh")

    def test_command_history_tracked(self, integration_framework):
        """Test command history is tracked."""
        integration_framework.session.add_command("use nmap")
        integration_framework.session.add_command("set RHOST 192.168.1.100")
        integration_framework.session.add_command("run")

        assert len(integration_framework.session.command_history) == 3
        assert integration_framework.session.command_history[0]["command"] == "use nmap"

    def test_workspace_stores_multiple_runs(self, integration_framework, test_module_class):
        """Test workspace stores results from multiple runs."""
        module = test_module_class(integration_framework)
        module.set_option("RHOST", "192.168.1.100")

        # Run multiple times
        for i in range(3):
            result = module.run()
            integration_framework.session.store_results("test_module", result)

        # Should have 3 results
        results = integration_framework.session.get_results("test_module")
        assert len(results) == 3


# =============================================================================
# Error Handling Tests
# =============================================================================

@pytest.mark.integration
class TestErrorHandling:
    """Tests for error handling in integrated operations."""

    def test_invalid_option_logged(self, integration_framework, test_module_class):
        """Test setting invalid option is logged."""
        module = test_module_class(integration_framework)

        result = module.set_option("INVALID_OPTION", "value")

        assert result is False
        integration_framework.log.assert_called()

    def test_cleanup_called_on_error(self, integration_framework):
        """Test cleanup is called even when module errors."""
        class ErrorModule(BaseModule):
            cleanup_called = False

            @property
            def name(self):
                return "Error Module"

            @property
            def description(self):
                return "Test"

            @property
            def author(self):
                return "Test"

            @property
            def category(self):
                return "test"

            def run(self):
                raise Exception("Test error")

            def cleanup(self):
                ErrorModule.cleanup_called = True

        module = ErrorModule(integration_framework)

        try:
            module.run()
        except Exception:
            module.cleanup()

        assert ErrorModule.cleanup_called is True
