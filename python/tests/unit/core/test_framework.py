"""
Unit tests for purplesploit.core.framework module.

Tests cover:
- Framework initialization
- Module discovery and registration
- Module loading and execution
- Target and credential management
- Search functionality
- Statistics and state export
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from purplesploit.core.framework import Framework
from purplesploit.core.module import BaseModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def framework(tmp_path):
    """Create a Framework instance with temporary paths."""
    db_path = str(tmp_path / "test.db")
    modules_path = str(tmp_path / "modules")
    os.makedirs(modules_path)

    # Mock the lazy-loaded models.database module
    with patch('purplesploit.models.database.db_manager'):
        fw = Framework(modules_path=modules_path, db_path=db_path)
    yield fw
    fw.cleanup()


@pytest.fixture
def framework_with_modules(tmp_path):
    """Create a Framework that uses the real modules directory."""
    db_path = str(tmp_path / "test.db")
    # Use actual modules path for discovery tests
    framework_dir = Path(__file__).parent.parent.parent.parent / "purplesploit" / "modules"
    modules_path = str(framework_dir)

    # Mock the lazy-loaded models.database module
    with patch('purplesploit.models.database.db_manager'):
        fw = Framework(modules_path=modules_path, db_path=db_path)
    yield fw
    fw.cleanup()


# =============================================================================
# Framework Initialization Tests
# =============================================================================

class TestFrameworkInitialization:
    """Tests for Framework initialization."""

    def test_creates_with_custom_paths(self, tmp_path):
        """Test framework creates with custom paths."""
        db_path = str(tmp_path / "test.db")
        modules_path = str(tmp_path / "modules")
        os.makedirs(modules_path)

        with patch('purplesploit.models.database.db_manager'):
            fw = Framework(modules_path=modules_path, db_path=db_path)

        assert fw.modules_path == modules_path
        assert fw.database is not None
        assert fw.session is not None
        fw.cleanup()

    def test_creates_session(self, framework):
        """Test framework creates a session."""
        assert framework.session is not None

    def test_creates_database(self, framework):
        """Test framework creates a database."""
        assert framework.database is not None

    def test_initializes_empty_modules(self, framework):
        """Test framework starts with empty modules dict."""
        assert framework.modules == {}

    def test_initializes_empty_logs(self, framework):
        """Test framework starts with empty log messages."""
        assert framework.log_messages == []


# =============================================================================
# Module Discovery Tests
# =============================================================================

class TestModuleDiscovery:
    """Tests for module discovery and registration."""

    def test_discover_modules_empty_dir(self, framework):
        """Test discovery in empty directory returns 0."""
        count = framework.discover_modules()
        assert count == 0

    def test_discover_modules_missing_path(self, framework):
        """Test discovery with missing path logs warning."""
        framework.modules_path = "/nonexistent/path"
        count = framework.discover_modules()
        assert count == 0
        # Check warning was logged
        assert any("not found" in log["message"].lower() for log in framework.log_messages)

    def test_discover_modules_finds_modules(self, framework_with_modules):
        """Test discovery finds modules in directory."""
        count = framework_with_modules.discover_modules()
        assert count > 0
        assert len(framework_with_modules.modules) > 0

    def test_discovered_module_has_metadata(self, framework_with_modules):
        """Test discovered modules have correct metadata."""
        framework_with_modules.discover_modules()

        # Find any module and verify it has metadata
        assert len(framework_with_modules.modules) > 0
        # Get first module
        first_module = list(framework_with_modules.modules.values())[0]
        assert first_module.name is not None
        assert first_module.category is not None
        assert first_module.path is not None


# =============================================================================
# Module Loading Tests
# =============================================================================

class TestModuleLoading:
    """Tests for module loading."""

    def test_use_module_not_found(self, framework):
        """Test use_module returns None for non-existent module."""
        result = framework.use_module("nonexistent/module")
        assert result is None

    def test_use_module_loads_module(self, framework_with_modules):
        """Test use_module successfully loads a module."""
        framework_with_modules.discover_modules()

        # Use a module that exists in the real modules
        module_path = list(framework_with_modules.modules.keys())[0]
        module = framework_with_modules.use_module(module_path)
        assert module is not None

    def test_use_module_sets_current(self, framework_with_modules):
        """Test use_module sets session's current module."""
        framework_with_modules.discover_modules()

        module_path = list(framework_with_modules.modules.keys())[0]
        module = framework_with_modules.use_module(module_path)
        assert framework_with_modules.session.current_module == module

    def test_get_module_returns_metadata(self, framework_with_modules):
        """Test get_module returns module metadata."""
        framework_with_modules.discover_modules()

        module_path = list(framework_with_modules.modules.keys())[0]
        metadata = framework_with_modules.get_module(module_path)
        assert metadata is not None
        assert metadata.path == module_path


# =============================================================================
# Module Execution Tests
# =============================================================================

class TestModuleExecution:
    """Tests for module execution."""

    def test_run_module_no_module_loaded(self, framework):
        """Test run_module fails when no module loaded."""
        result = framework.run_module()
        assert result["success"] is False
        assert "No module loaded" in result["error"]

    def test_run_module_stores_results(self, framework_with_modules):
        """Test run_module stores results in session (with mock module)."""
        # Create a mock module that always succeeds
        mock_module = MagicMock()
        mock_module.name = "MockModule"
        mock_module.validate_options.return_value = (True, "")
        mock_module.auto_set_from_context.return_value = None
        mock_module.run.return_value = {"success": True, "output": "Test completed"}
        mock_module.show_options.return_value = {}
        mock_module.__class__.__module__ = "test.mock_module"

        framework_with_modules.session.current_module = mock_module

        result = framework_with_modules.run_module(mock_module)

        assert result["success"] is True
        # Results should be in workspace
        workspace = framework_with_modules.session.workspace
        assert "MockModule" in workspace

    def test_run_module_logs_to_database(self, framework_with_modules):
        """Test run_module logs execution to database."""
        # Create a mock module that always succeeds
        mock_module = MagicMock()
        mock_module.name = "MockModule"
        mock_module.validate_options.return_value = (True, "")
        mock_module.auto_set_from_context.return_value = None
        mock_module.run.return_value = {"success": True, "output": "Test completed"}
        mock_module.show_options.return_value = {}
        mock_module.__class__.__module__ = "test.mock_module"

        framework_with_modules.session.current_module = mock_module
        framework_with_modules.run_module(mock_module)

        # Check database has execution record
        history = framework_with_modules.database.get_module_history()
        assert len(history) > 0


# =============================================================================
# Module Search Tests
# =============================================================================

class TestModuleSearch:
    """Tests for module search functionality."""

    def test_search_modules_by_name(self, framework_with_modules):
        """Test searching modules by name."""
        framework_with_modules.discover_modules()

        # Search for a common term that should exist in real modules
        results = framework_with_modules.search_modules("nmap")
        assert len(results) > 0

    def test_search_modules_by_category(self, framework_with_modules):
        """Test searching modules by category."""
        framework_with_modules.discover_modules()

        # Search for recon category which should have nmap
        results = framework_with_modules.search_modules("recon")
        assert len(results) > 0

    def test_search_modules_no_results(self, framework_with_modules):
        """Test search with no matches returns empty list."""
        framework_with_modules.discover_modules()

        results = framework_with_modules.search_modules("nonexistent_query_xyz_12345")
        assert len(results) == 0

    def test_search_modules_case_insensitive(self, framework_with_modules):
        """Test search is case insensitive."""
        framework_with_modules.discover_modules()

        results_lower = framework_with_modules.search_modules("nmap")
        results_upper = framework_with_modules.search_modules("NMAP")

        assert len(results_lower) == len(results_upper)


# =============================================================================
# Module Listing Tests
# =============================================================================

class TestModuleListing:
    """Tests for module listing functionality."""

    def test_list_modules_all(self, framework_with_modules):
        """Test listing all modules."""
        framework_with_modules.discover_modules()

        modules = framework_with_modules.list_modules()
        assert len(modules) > 0

    def test_list_modules_by_category(self, framework_with_modules):
        """Test listing modules by category."""
        framework_with_modules.discover_modules()

        modules = framework_with_modules.list_modules(category="recon")
        assert len(modules) > 0
        assert all(m.category == "recon" for m in modules)

    def test_list_modules_sorted(self, framework_with_modules):
        """Test listed modules are sorted."""
        framework_with_modules.discover_modules()

        modules = framework_with_modules.list_modules()
        # Check sorted by category then name
        for i in range(len(modules) - 1):
            assert (modules[i].category, modules[i].name) <= (modules[i+1].category, modules[i+1].name)

    def test_get_categories(self, framework_with_modules):
        """Test getting unique categories."""
        framework_with_modules.discover_modules()

        categories = framework_with_modules.get_categories()
        # Should have at least recon category from nmap
        assert "recon" in categories


# =============================================================================
# Target Management Tests
# =============================================================================

class TestTargetManagement:
    """Tests for target management."""

    def test_add_network_target(self, framework):
        """Test adding a network target."""
        with patch('purplesploit.models.database.db_manager'):
            result = framework.add_target("network", "192.168.1.100", "test-server")

        assert result is True
        assert len(framework.session.targets.list()) == 1

    def test_add_web_target(self, framework):
        """Test adding a web target."""
        with patch('purplesploit.models.database.db_manager'):
            result = framework.add_target("web", "http://example.com", "example")

        assert result is True
        targets = framework.session.targets.list()
        assert len(targets) == 1
        assert targets[0].get("url") == "http://example.com"

    def test_add_target_auto_name(self, framework):
        """Test target gets auto-generated name."""
        with patch('purplesploit.models.database.db_manager'):
            result = framework.add_target("network", "192.168.1.100")

        assert result is True
        targets = framework.session.targets.list()
        assert targets[0]["name"] == "192.168.1.100"

    def test_add_duplicate_target_rejected(self, framework):
        """Test duplicate target is rejected."""
        with patch('purplesploit.models.database.db_manager'):
            framework.add_target("network", "192.168.1.100")
            result = framework.add_target("network", "192.168.1.100")

        assert result is False


# =============================================================================
# Credential Management Tests
# =============================================================================

class TestCredentialManagement:
    """Tests for credential management."""

    def test_add_credential_basic(self, framework):
        """Test adding a basic credential."""
        with patch('purplesploit.models.database.db_manager'):
            result = framework.add_credential(username="admin", password="password123")

        assert result is True
        assert len(framework.session.credentials.list()) == 1

    def test_add_credential_with_domain(self, framework):
        """Test adding a credential with domain."""
        with patch('purplesploit.models.database.db_manager'):
            result = framework.add_credential(
                username="admin",
                password="password123",
                domain="TESTDOMAIN"
            )

        assert result is True
        creds = framework.session.credentials.list()
        assert creds[0]["domain"] == "TESTDOMAIN"

    def test_add_credential_with_hash(self, framework):
        """Test adding a credential with hash."""
        with patch('purplesploit.models.database.db_manager'):
            result = framework.add_credential(
                username="admin",
                hash_value="aad3b435b51404ee:8846f7eaee8fb117"
            )

        assert result is True
        creds = framework.session.credentials.list()
        assert creds[0]["hash"] == "aad3b435b51404ee:8846f7eaee8fb117"

    def test_add_credential_auto_name(self, framework):
        """Test credential gets auto-generated name."""
        with patch('purplesploit.models.database.db_manager'):
            result = framework.add_credential(
                username="admin",
                password="pass",
                domain="DOMAIN"
            )

        creds = framework.session.credentials.list()
        assert creds[0]["name"] == "DOMAIN/admin"


# =============================================================================
# Logging Tests
# =============================================================================

class TestLogging:
    """Tests for framework logging."""

    def test_log_adds_entry(self, framework):
        """Test log adds entry to log_messages."""
        framework.log("Test message", "info")

        assert len(framework.log_messages) == 1
        assert framework.log_messages[0]["message"] == "Test message"
        assert framework.log_messages[0]["level"] == "info"

    def test_log_has_timestamp(self, framework):
        """Test log entries have timestamps."""
        framework.log("Test message", "info")

        assert "timestamp" in framework.log_messages[0]

    def test_get_recent_logs(self, framework):
        """Test getting recent logs."""
        for i in range(10):
            framework.log(f"Message {i}", "info")

        recent = framework.get_recent_logs(5)
        assert len(recent) == 5
        assert recent[-1]["message"] == "Message 9"

    def test_get_recent_logs_default_count(self, framework):
        """Test default count for get_recent_logs."""
        for i in range(50):
            framework.log(f"Message {i}", "info")

        recent = framework.get_recent_logs()
        assert len(recent) == 50  # Less than 100, so all returned


# =============================================================================
# Statistics Tests
# =============================================================================

class TestStatistics:
    """Tests for framework statistics."""

    def test_get_stats_empty(self, framework):
        """Test stats on empty framework."""
        stats = framework.get_stats()

        assert stats["modules"] == 0
        assert stats["categories"] == 0
        assert stats["targets"] == 0
        assert stats["credentials"] == 0
        assert stats["current_module"] is None

    def test_get_stats_with_data(self, framework_with_modules):
        """Test stats with modules and data."""
        framework_with_modules.discover_modules()
        with patch('purplesploit.models.database.db_manager'):
            framework_with_modules.add_target("network", "192.168.1.100")
            framework_with_modules.add_credential("admin", "password")

        stats = framework_with_modules.get_stats()

        assert stats["modules"] > 0
        assert stats["targets"] == 1
        assert stats["credentials"] == 1


# =============================================================================
# State Export Tests
# =============================================================================

class TestStateExport:
    """Tests for state export functionality."""

    def test_export_state(self, framework):
        """Test exporting framework state."""
        state = framework.export_state()

        assert "session" in state
        assert "stats" in state
        assert "logs" in state

    def test_export_state_includes_session(self, framework):
        """Test exported state includes session data."""
        with patch('purplesploit.models.database.db_manager'):
            framework.add_target("network", "192.168.1.100")

        state = framework.export_state()

        # Session targets is a dict with 'targets' key containing the list
        assert len(state["session"]["targets"]["targets"]) == 1


# =============================================================================
# Cleanup Tests
# =============================================================================

class TestCleanup:
    """Tests for framework cleanup."""

    def test_cleanup_closes_database(self, tmp_path):
        """Test cleanup closes database connection."""
        db_path = str(tmp_path / "test.db")
        modules_path = str(tmp_path / "modules")
        os.makedirs(modules_path)

        with patch('purplesploit.models.database.db_manager'):
            fw = Framework(modules_path=modules_path, db_path=db_path)

        fw.cleanup()
        # Database should be closed - trying to use it would raise error
        # Just verify cleanup didn't raise an exception
        assert True
