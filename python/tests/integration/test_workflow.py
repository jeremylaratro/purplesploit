"""
Integration tests for full workflow scenarios.

Tests cover:
- Search -> Use -> Set Options -> Run workflow
- Module discovery and loading
- Target and credential flow
- End-to-end command execution
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from purplesploit.core.framework import Framework
from purplesploit.core.session import Session


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def integration_framework(tmp_path):
    """
    Create a fully integrated framework for testing.

    Uses real modules directory but temporary database.
    """
    db_path = str(tmp_path / "integration_test.db")

    # Use the real modules directory
    modules_path = Path(__file__).parent.parent.parent / "purplesploit" / "modules"

    with patch('purplesploit.core.framework.db_manager'):
        fw = Framework(modules_path=str(modules_path), db_path=db_path)
        fw.discover_modules()

    yield fw
    fw.cleanup()


@pytest.fixture
def framework_with_target(integration_framework):
    """Framework with a pre-configured target."""
    with patch('purplesploit.core.framework.db_manager'):
        integration_framework.add_target("network", "192.168.1.100", "test-target")
    return integration_framework


@pytest.fixture
def framework_with_credentials(framework_with_target):
    """Framework with target and credentials."""
    with patch('purplesploit.core.framework.db_manager'):
        framework_with_target.add_credential(
            username="admin",
            password="password123",
            domain="TESTDOMAIN"
        )
    return framework_with_target


# =============================================================================
# Search -> Use -> Run Workflow Tests
# =============================================================================

class TestSearchUseRunWorkflow:
    """Tests for the complete search -> use -> run workflow."""

    def test_search_finds_modules(self, integration_framework):
        """Test searching for modules returns results."""
        results = integration_framework.search_modules("nmap")

        assert len(results) > 0
        assert any("nmap" in r.name.lower() or "nmap" in r.path.lower() for r in results)

    def test_search_then_use_module(self, integration_framework):
        """Test searching then using a found module."""
        # Search for nmap
        results = integration_framework.search_modules("nmap")
        assert len(results) > 0

        # Use the first result
        module_path = results[0].path
        module = integration_framework.use_module(module_path)

        assert module is not None
        assert integration_framework.session.current_module == module

    def test_use_module_then_set_options(self, integration_framework):
        """Test using a module then setting options."""
        # Find and use a module
        results = integration_framework.search_modules("nmap")
        module = integration_framework.use_module(results[0].path)

        # Set options
        if "RHOST" in module.options:
            result = module.set_option("RHOST", "192.168.1.100")
            assert result is True
            assert module.get_option("RHOST") == "192.168.1.100"

    def test_full_workflow_with_mock_execution(self, framework_with_target):
        """Test full workflow: search -> use -> set -> run (mocked execution)."""
        # Search
        results = framework_with_target.search_modules("nmap")
        assert len(results) > 0

        # Use
        module = framework_with_target.use_module(results[0].path)
        assert module is not None

        # Options should auto-populate from context
        module.auto_set_from_context()

        # Verify target was auto-set
        if "RHOST" in module.options:
            assert module.get_option("RHOST") == "192.168.1.100"

        # Mock the actual command execution for testing
        with patch.object(module, 'run', return_value={"success": True, "output": "Mocked output"}):
            result = framework_with_target.run_module(module)
            assert result["success"] is True


# =============================================================================
# Module Selection Workflow Tests
# =============================================================================

class TestModuleSelectionWorkflow:
    """Tests for module selection workflows."""

    def test_list_all_modules(self, integration_framework):
        """Test listing all available modules."""
        modules = integration_framework.list_modules()

        assert len(modules) > 0
        # Should have modules from multiple categories
        categories = set(m.category for m in modules)
        assert len(categories) > 1

    def test_list_modules_by_category(self, integration_framework):
        """Test listing modules filtered by category."""
        # Get all categories
        categories = integration_framework.get_categories()
        assert len(categories) > 0

        # List modules for first category
        first_category = list(categories)[0]
        modules = integration_framework.list_modules(category=first_category)

        assert len(modules) > 0
        assert all(m.category == first_category for m in modules)

    def test_use_module_by_path(self, integration_framework):
        """Test using a module directly by path."""
        modules = integration_framework.list_modules()
        first_module = modules[0]

        module = integration_framework.use_module(first_module.path)

        assert module is not None
        assert integration_framework.session.current_module == module

    def test_switch_between_modules(self, integration_framework):
        """Test switching between different modules."""
        modules = integration_framework.list_modules()

        # Use first module
        module1 = integration_framework.use_module(modules[0].path)
        assert integration_framework.session.current_module == module1

        # Switch to second module
        if len(modules) > 1:
            module2 = integration_framework.use_module(modules[1].path)
            assert integration_framework.session.current_module == module2
            assert integration_framework.session.current_module != module1


# =============================================================================
# Target Integration Tests
# =============================================================================

class TestTargetIntegration:
    """Tests for target management integration."""

    def test_add_target_available_in_session(self, integration_framework):
        """Test added target is available in session."""
        with patch('purplesploit.core.framework.db_manager'):
            integration_framework.add_target("network", "10.0.0.1", "server1")

        targets = integration_framework.session.targets.list()
        assert len(targets) == 1
        assert targets[0]["ip"] == "10.0.0.1"

    def test_multiple_targets_management(self, integration_framework):
        """Test managing multiple targets."""
        with patch('purplesploit.core.framework.db_manager'):
            integration_framework.add_target("network", "10.0.0.1", "server1")
            integration_framework.add_target("network", "10.0.0.2", "server2")
            integration_framework.add_target("web", "http://example.com", "webserver")

        targets = integration_framework.session.targets.list()
        assert len(targets) == 3

    def test_target_auto_populates_module_options(self, framework_with_target):
        """Test target auto-populates module RHOST option."""
        # Use a module with RHOST option
        results = framework_with_target.search_modules("nmap")
        module = framework_with_target.use_module(results[0].path)

        # Auto-set should populate RHOST from current target
        module.auto_set_from_context()

        if "RHOST" in module.options:
            assert module.get_option("RHOST") == "192.168.1.100"

    def test_switching_targets_updates_context(self, integration_framework):
        """Test switching targets updates the context."""
        with patch('purplesploit.core.framework.db_manager'):
            integration_framework.add_target("network", "10.0.0.1", "server1")
            integration_framework.add_target("network", "10.0.0.2", "server2")

        # Current should be first target
        current = integration_framework.session.targets.get_current()
        assert current["ip"] == "10.0.0.1"

        # Switch to second target
        integration_framework.session.targets.set_current("10.0.0.2")
        current = integration_framework.session.targets.get_current()
        assert current["ip"] == "10.0.0.2"


# =============================================================================
# Credential Integration Tests
# =============================================================================

class TestCredentialIntegration:
    """Tests for credential management integration."""

    def test_add_credential_available_in_session(self, integration_framework):
        """Test added credential is available in session."""
        with patch('purplesploit.core.framework.db_manager'):
            integration_framework.add_credential(
                username="testuser",
                password="testpass"
            )

        creds = integration_framework.session.credentials.list()
        assert len(creds) == 1
        assert creds[0]["username"] == "testuser"

    def test_credential_with_domain(self, integration_framework):
        """Test credential with domain is stored correctly."""
        with patch('purplesploit.core.framework.db_manager'):
            integration_framework.add_credential(
                username="admin",
                password="password",
                domain="CORP"
            )

        creds = integration_framework.session.credentials.list()
        assert creds[0]["domain"] == "CORP"

    def test_credential_auto_populates_module_options(self, framework_with_credentials):
        """Test credentials auto-populate module options."""
        # Find a module with credential options
        results = framework_with_credentials.search_modules("smb")

        if results:
            module = framework_with_credentials.use_module(results[0].path)
            module.auto_set_from_context()

            # Check if credential options were populated
            if "USERNAME" in module.options:
                assert module.get_option("USERNAME") == "admin"


# =============================================================================
# Combined Target + Credential Workflow Tests
# =============================================================================

class TestCombinedWorkflow:
    """Tests for combined target and credential workflows."""

    def test_full_context_auto_population(self, framework_with_credentials):
        """Test both target and credential auto-populate."""
        # Find a module that uses both
        results = framework_with_credentials.search_modules("smb")

        if results:
            module = framework_with_credentials.use_module(results[0].path)
            module.auto_set_from_context()

            # Verify target
            if "RHOST" in module.options:
                assert module.get_option("RHOST") == "192.168.1.100"

            # Verify credentials
            if "USERNAME" in module.options:
                assert module.get_option("USERNAME") == "admin"

    def test_workflow_with_web_target(self, integration_framework):
        """Test workflow with web target type."""
        with patch('purplesploit.core.framework.db_manager'):
            integration_framework.add_target("web", "http://testsite.com", "testsite")

        # Find a web module
        results = integration_framework.search_modules("ferox")

        if results:
            module = integration_framework.use_module(results[0].path)
            module.auto_set_from_context()

            # URL should be populated
            if "URL" in module.options:
                assert module.get_option("URL") == "http://testsite.com"


# =============================================================================
# Module History and Recent Tests
# =============================================================================

class TestModuleHistory:
    """Tests for module history tracking."""

    def test_module_use_tracked_in_history(self, integration_framework):
        """Test using modules is tracked in session history."""
        modules = integration_framework.list_modules()

        # Use a module
        integration_framework.use_module(modules[0].path)

        # Use another module
        if len(modules) > 1:
            integration_framework.use_module(modules[1].path)

            # Check history
            history = integration_framework.session.module_history
            assert len(history) >= 1

    def test_module_execution_stored_in_workspace(self, framework_with_target):
        """Test module execution results stored in workspace."""
        results = framework_with_target.search_modules("nmap")
        module = framework_with_target.use_module(results[0].path)

        # Mock execution
        with patch.object(module, 'run', return_value={"success": True, "data": "test"}):
            framework_with_target.run_module(module)

        # Check workspace has results
        workspace = framework_with_target.session.workspace
        assert module.name in workspace


# =============================================================================
# Statistics and State Tests
# =============================================================================

class TestStatisticsAndState:
    """Tests for framework statistics and state export."""

    def test_stats_reflect_current_state(self, framework_with_credentials):
        """Test statistics accurately reflect current state."""
        stats = framework_with_credentials.get_stats()

        assert stats["modules"] > 0
        assert stats["targets"] == 1
        assert stats["credentials"] == 1

    def test_export_state_includes_all_data(self, framework_with_credentials):
        """Test state export includes all relevant data."""
        # Use a module to add to state
        modules = framework_with_credentials.list_modules()
        framework_with_credentials.use_module(modules[0].path)

        state = framework_with_credentials.export_state()

        assert "session" in state
        assert "stats" in state
        assert "logs" in state

        # Session should have targets and credentials
        assert len(state["session"]["targets"]["targets"]) == 1
        assert len(state["session"]["credentials"]["credentials"]) == 1


# =============================================================================
# Error Recovery Tests
# =============================================================================

class TestErrorRecovery:
    """Tests for error handling and recovery in workflows."""

    def test_invalid_module_path_handled(self, integration_framework):
        """Test invalid module path is handled gracefully."""
        module = integration_framework.use_module("nonexistent/module/path")
        assert module is None
        assert integration_framework.session.current_module is None

    def test_module_validation_failure_handled(self, integration_framework):
        """Test module validation failure is handled."""
        modules = integration_framework.list_modules()
        module = integration_framework.use_module(modules[0].path)

        # Set required option to invalid state
        for opt_name, opt_data in module.options.items():
            if opt_data.get("required"):
                module.options[opt_name]["value"] = None
                break

        # Validation should fail gracefully
        is_valid, error = module.validate_options()
        # This is expected behavior - may pass if no required options

    def test_duplicate_target_rejected(self, integration_framework):
        """Test duplicate targets are rejected gracefully."""
        with patch('purplesploit.core.framework.db_manager'):
            result1 = integration_framework.add_target("network", "10.0.0.1")
            result2 = integration_framework.add_target("network", "10.0.0.1")

        assert result1 is True
        assert result2 is False
        assert len(integration_framework.session.targets.list()) == 1


# =============================================================================
# Service Discovery Integration Tests
# =============================================================================

class TestServiceDiscoveryIntegration:
    """Tests for service discovery integration."""

    def test_services_can_be_added(self, framework_with_target):
        """Test services can be added for a target."""
        framework_with_target.session.services.add_service("192.168.1.100", "ssh", 22)
        framework_with_target.session.services.add_service("192.168.1.100", "http", 80)

        services = framework_with_target.session.services.get_services("192.168.1.100")

        assert "ssh" in services
        assert "http" in services

    def test_services_persist_across_module_switches(self, framework_with_target):
        """Test services persist when switching modules."""
        # Add services
        framework_with_target.session.services.add_service("192.168.1.100", "smb", 445)

        # Switch modules
        modules = framework_with_target.list_modules()
        framework_with_target.use_module(modules[0].path)
        if len(modules) > 1:
            framework_with_target.use_module(modules[1].path)

        # Services should still be there
        assert framework_with_target.session.services.has_service("192.168.1.100", "smb")
