"""
Integration tests for data persistence.

Tests cover:
- Session export and import
- Target/credential persistence across sessions
- Database storage and retrieval
- State recovery after restart
"""

import pytest
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

from purplesploit.core.framework import Framework
from purplesploit.core.session import (
    Session,
    TargetManager,
    CredentialManager,
    ServiceManager,
    WordlistManager
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary database path."""
    return str(tmp_path / "test_persist.db")


@pytest.fixture
def temp_session_file(tmp_path):
    """Provide a temporary session file path."""
    return str(tmp_path / "session.json")


@pytest.fixture
def persistence_framework(tmp_path):
    """Create a framework for persistence testing."""
    db_path = str(tmp_path / "persist_test.db")
    modules_path = Path(__file__).parent.parent.parent / "purplesploit" / "modules"

    with patch('purplesploit.core.framework.db_manager'):
        fw = Framework(modules_path=str(modules_path), db_path=db_path)
        fw.discover_modules()

    yield fw
    fw.cleanup()


@pytest.fixture
def populated_session():
    """Create a session with various data for testing."""
    session = Session()

    # Add targets
    session.targets.add({"ip": "192.168.1.1", "name": "server1", "type": "network"})
    session.targets.add({"ip": "192.168.1.2", "name": "server2", "type": "network"})
    session.targets.add({"url": "http://example.com", "name": "webserver", "type": "web"})

    # Add credentials
    session.credentials.add({"username": "admin", "password": "pass123", "domain": "CORP"})
    session.credentials.add({"username": "user", "password": "userpass"})

    # Add services
    session.services.add_service("192.168.1.1", "ssh", 22)
    session.services.add_service("192.168.1.1", "http", 80)
    session.services.add_service("192.168.1.2", "smb", 445)

    # Add some workspace data
    session.workspace["test_module"] = [
        {"results": {"success": True}, "timestamp": datetime.now().isoformat()}
    ]

    # Add command history
    session.add_command("use nmap")
    session.add_command("set RHOST 192.168.1.1")
    session.add_command("run")

    return session


# =============================================================================
# Session Export/Import Tests
# =============================================================================

class TestSessionExportImport:
    """Tests for session export and import."""

    def test_export_session_returns_dict(self, populated_session):
        """Test session export returns a dictionary."""
        data = populated_session.export_session()

        assert isinstance(data, dict)
        assert "targets" in data
        assert "credentials" in data
        assert "services" in data
        assert "workspace" in data

    def test_export_preserves_targets(self, populated_session):
        """Test export preserves all targets."""
        data = populated_session.export_session()

        assert len(data["targets"]["targets"]) == 3

    def test_export_preserves_credentials(self, populated_session):
        """Test export preserves all credentials."""
        data = populated_session.export_session()

        assert len(data["credentials"]["credentials"]) == 2

    def test_export_preserves_services(self, populated_session):
        """Test export preserves all services."""
        data = populated_session.export_session()

        assert "services" in data["services"]
        assert "192.168.1.1" in data["services"]["services"]

    def test_import_restores_targets(self, populated_session):
        """Test import restores targets correctly."""
        data = populated_session.export_session()

        new_session = Session()
        new_session.import_session(data)

        assert len(new_session.targets.list()) == 3
        assert new_session.targets.list()[0]["ip"] == "192.168.1.1"

    def test_import_restores_credentials(self, populated_session):
        """Test import restores credentials correctly."""
        data = populated_session.export_session()

        new_session = Session()
        new_session.import_session(data)

        assert len(new_session.credentials.list()) == 2
        assert new_session.credentials.list()[0]["username"] == "admin"

    def test_import_restores_services(self, populated_session):
        """Test import restores services correctly."""
        data = populated_session.export_session()

        new_session = Session()
        new_session.import_session(data)

        assert new_session.services.has_service("192.168.1.1", "ssh")
        assert new_session.services.has_service("192.168.1.2", "smb")

    def test_import_restores_current_selection(self, populated_session):
        """Test import restores current target/credential selection."""
        # Set specific selections
        populated_session.targets.set_current("192.168.1.2")
        populated_session.credentials.set_current("user")

        data = populated_session.export_session()

        new_session = Session()
        new_session.import_session(data)

        assert new_session.targets.get_current()["ip"] == "192.168.1.2"
        assert new_session.credentials.get_current()["username"] == "user"


# =============================================================================
# File Persistence Tests
# =============================================================================

class TestFilePersistence:
    """Tests for persisting session to file."""

    def test_save_session_to_file(self, populated_session, temp_session_file):
        """Test saving session to JSON file."""
        data = populated_session.export_session()

        with open(temp_session_file, 'w') as f:
            json.dump(data, f)

        assert os.path.exists(temp_session_file)

        # Verify file content
        with open(temp_session_file, 'r') as f:
            loaded = json.load(f)

        assert "targets" in loaded
        assert "credentials" in loaded

    def test_load_session_from_file(self, populated_session, temp_session_file):
        """Test loading session from JSON file."""
        # Save
        data = populated_session.export_session()
        with open(temp_session_file, 'w') as f:
            json.dump(data, f)

        # Load
        with open(temp_session_file, 'r') as f:
            loaded_data = json.load(f)

        new_session = Session()
        new_session.import_session(loaded_data)

        assert len(new_session.targets.list()) == 3
        assert len(new_session.credentials.list()) == 2

    def test_session_roundtrip_preserves_data(self, populated_session, temp_session_file):
        """Test complete save/load roundtrip preserves all data."""
        original_targets = len(populated_session.targets.list())
        original_creds = len(populated_session.credentials.list())

        # Save
        data = populated_session.export_session()
        with open(temp_session_file, 'w') as f:
            json.dump(data, f)

        # Load into new session
        with open(temp_session_file, 'r') as f:
            loaded_data = json.load(f)

        new_session = Session()
        new_session.import_session(loaded_data)

        assert len(new_session.targets.list()) == original_targets
        assert len(new_session.credentials.list()) == original_creds


# =============================================================================
# Manager Export/Import Tests
# =============================================================================

class TestManagerPersistence:
    """Tests for individual manager persistence."""

    def test_target_manager_export_import(self):
        """Test TargetManager export and import."""
        manager = TargetManager()
        manager.add({"ip": "10.0.0.1", "name": "test1"})
        manager.add({"ip": "10.0.0.2", "name": "test2"})
        manager.set_current("10.0.0.2")

        data = manager.export()

        new_manager = TargetManager()
        new_manager.import_data(data)

        assert len(new_manager.targets) == 2
        assert new_manager.current_index == 1

    def test_credential_manager_export_import(self):
        """Test CredentialManager export and import."""
        manager = CredentialManager()
        manager.add({"username": "admin", "password": "pass", "domain": "CORP"})
        manager.add({"username": "user", "password": "userpass"})

        data = manager.export()

        new_manager = CredentialManager()
        new_manager.import_data(data)

        assert len(new_manager.credentials) == 2
        assert new_manager.credentials[0]["domain"] == "CORP"

    def test_service_manager_export_import(self):
        """Test ServiceManager export and import."""
        manager = ServiceManager()
        manager.add_service("10.0.0.1", "ssh", 22)
        manager.add_service("10.0.0.1", "http", 80)
        manager.add_service("10.0.0.2", "smb", 445)

        data = manager.export()

        new_manager = ServiceManager()
        new_manager.import_data(data)

        assert new_manager.has_service("10.0.0.1", "ssh")
        assert new_manager.has_service("10.0.0.1", "http")
        assert new_manager.has_service("10.0.0.2", "smb")

    def test_wordlist_manager_export_import(self, tmp_path):
        """Test WordlistManager export and import."""
        # Create a test wordlist file
        wordlist_file = tmp_path / "test.txt"
        wordlist_file.write_text("admin\nuser\ntest\n")

        manager = WordlistManager()
        manager.add("web_dir", str(wordlist_file), "test_wordlist")
        manager.set_current("web_dir", "test_wordlist")

        data = manager.export()

        new_manager = WordlistManager()
        new_manager.import_data(data)

        assert len(new_manager.wordlists["web_dir"]) == 1
        assert new_manager.current_selections.get("web_dir") == 0


# =============================================================================
# Database Persistence Tests
# =============================================================================

class TestDatabasePersistence:
    """Tests for database persistence."""

    def test_module_execution_persisted(self, persistence_framework):
        """Test module execution is logged to database."""
        modules = persistence_framework.list_modules()
        module = persistence_framework.use_module(modules[0].path)

        # Mock execution and validation to bypass required options check
        with patch.object(module, 'run', return_value={"success": True}):
            with patch.object(module, 'validate_options', return_value=(True, None)):
                persistence_framework.run_module(module)

        # Check database
        history = persistence_framework.database.get_module_history()
        assert len(history) > 0

    def test_target_persisted_to_database(self, persistence_framework):
        """Test targets are persisted to database."""
        with patch('purplesploit.core.framework.db_manager'):
            persistence_framework.add_target("network", "192.168.1.50", "db-server")

        # Verify in database
        targets = persistence_framework.database.get_targets()
        assert any(t.get('ip') == '192.168.1.50' or t.get('identifier') == '192.168.1.50' for t in targets)

    def test_credential_persisted_to_database(self, persistence_framework):
        """Test credentials are persisted to database."""
        with patch('purplesploit.core.framework.db_manager'):
            persistence_framework.add_credential(username="dbuser", password="dbpass")

        # Verify in database
        creds = persistence_framework.database.get_credentials()
        assert any(c.get('username') == 'dbuser' for c in creds)


# =============================================================================
# State Recovery Tests
# =============================================================================

class TestStateRecovery:
    """Tests for state recovery after simulated restart."""

    def test_framework_state_export_import(self, persistence_framework):
        """Test framework state can be exported and restored."""
        # Add some state
        with patch('purplesploit.core.framework.db_manager'):
            persistence_framework.add_target("network", "10.0.0.1")
            persistence_framework.add_credential(username="admin", password="pass")

        # Export state
        state = persistence_framework.export_state()

        # Verify state contains data
        assert state["stats"]["targets"] == 1
        assert state["stats"]["credentials"] == 1

    def test_session_recovery_after_clear(self, populated_session):
        """Test session can be recovered after clearing."""
        # Export before clear
        saved_data = populated_session.export_session()

        # Clear session
        populated_session.targets.clear()
        populated_session.credentials.clear()

        assert len(populated_session.targets.list()) == 0
        assert len(populated_session.credentials.list()) == 0

        # Restore
        populated_session.import_session(saved_data)

        assert len(populated_session.targets.list()) == 3
        assert len(populated_session.credentials.list()) == 2


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================

class TestPersistenceEdgeCases:
    """Tests for edge cases in persistence."""

    def test_import_empty_data(self):
        """Test importing empty data doesn't crash."""
        session = Session()

        # Empty import data
        session.import_session({})

        # Should still work
        assert len(session.targets.list()) == 0

    def test_import_partial_data(self):
        """Test importing partial data works."""
        session = Session()

        # Only targets, no credentials
        partial_data = {
            "targets": {
                "targets": [{"ip": "10.0.0.1", "name": "test"}],
                "current_index": 0
            }
        }

        session.import_session(partial_data)

        assert len(session.targets.list()) == 1

    def test_import_invalid_current_index(self):
        """Test importing with invalid current_index is handled."""
        session = Session()

        data = {
            "targets": {
                "targets": [{"ip": "10.0.0.1", "name": "test"}],
                "current_index": 999  # Invalid index
            }
        }

        # Should not crash
        session.import_session(data)

    def test_export_with_special_characters(self):
        """Test export handles special characters in data."""
        session = Session()
        session.targets.add({
            "ip": "10.0.0.1",
            "name": "server with spaces & symbols!@#$%"
        })
        session.credentials.add({
            "username": "admin",
            "password": "p@ss'word\"test"
        })

        data = session.export_session()

        # Should be JSON serializable
        json_str = json.dumps(data)
        restored = json.loads(json_str)

        assert restored["credentials"]["credentials"][0]["password"] == "p@ss'word\"test"


# =============================================================================
# Workspace Persistence Tests
# =============================================================================

class TestWorkspacePersistence:
    """Tests for workspace/results persistence."""

    def test_workspace_export(self, populated_session):
        """Test workspace results are exported."""
        data = populated_session.export_session()

        assert "workspace" in data
        assert "test_module" in data["workspace"]

    def test_workspace_import(self, populated_session):
        """Test workspace results are imported."""
        data = populated_session.export_session()

        new_session = Session()
        new_session.import_session(data)

        assert "test_module" in new_session.workspace
        assert len(new_session.workspace["test_module"]) == 1

    def test_multiple_module_results_persist(self):
        """Test multiple module results persist correctly."""
        session = Session()

        session.store_results("module1", {"data": "result1"})
        session.store_results("module1", {"data": "result2"})
        session.store_results("module2", {"data": "result3"})

        data = session.export_session()

        new_session = Session()
        new_session.import_session(data)

        assert len(new_session.workspace["module1"]) == 2
        assert len(new_session.workspace["module2"]) == 1
