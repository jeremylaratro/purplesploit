"""
Unit tests for purplesploit.core.session module.

Tests cover:
- Session class operations
- TargetManager CRUD operations
- CredentialManager CRUD operations
- ServiceManager operations
- WordlistManager operations
- Session export/import
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch
from purplesploit.core.session import (
    Session,
    TargetManager,
    CredentialManager,
    ServiceManager,
    WordlistManager,
)


# =============================================================================
# TargetManager Tests
# =============================================================================

class TestTargetManager:
    """Tests for the TargetManager class."""

    def test_initial_state(self, target_manager):
        """Test initial state of TargetManager."""
        assert target_manager.targets == []
        assert target_manager.current_index == 0

    def test_add_target(self, target_manager, sample_target):
        """Test adding a target."""
        result = target_manager.add(sample_target)

        assert result is True
        assert len(target_manager.targets) == 1
        assert target_manager.targets[0]["ip"] == sample_target["ip"]
        assert "added_at" in target_manager.targets[0]

    def test_add_duplicate_ip_rejected(self, target_manager, sample_target):
        """Test duplicate targets are rejected."""
        target_manager.add(sample_target)
        result = target_manager.add(sample_target)

        assert result is False
        assert len(target_manager.targets) == 1

    def test_add_first_target_sets_current(self, target_manager, sample_target):
        """Test first target becomes current."""
        target_manager.add(sample_target)

        assert target_manager.current_index == 0
        assert target_manager.get_current()["ip"] == sample_target["ip"]

    def test_remove_by_ip(self, target_manager, sample_target):
        """Test removing a target by IP."""
        target_manager.add(sample_target)
        result = target_manager.remove(sample_target["ip"])

        assert result is True
        assert len(target_manager.targets) == 0

    def test_remove_by_name(self, target_manager, sample_target):
        """Test removing a target by name."""
        target_manager.add(sample_target)
        result = target_manager.remove(sample_target["name"])

        assert result is True
        assert len(target_manager.targets) == 0

    def test_remove_nonexistent(self, target_manager):
        """Test removing non-existent target returns False."""
        result = target_manager.remove("nonexistent")
        assert result is False

    def test_remove_by_index(self, target_manager, sample_target):
        """Test removing a target by index."""
        target_manager.add(sample_target)
        result = target_manager.remove_by_index(0)

        assert result is True
        assert len(target_manager.targets) == 0

    def test_remove_by_index_invalid(self, target_manager):
        """Test removing with invalid index returns False."""
        result = target_manager.remove_by_index(999)
        assert result is False

    def test_remove_range(self, target_manager):
        """Test removing a range of targets."""
        for i in range(5):
            target_manager.add({"ip": f"192.168.1.{i}", "name": f"target{i}"})

        count = target_manager.remove_range(1, 3)

        assert count == 3
        assert len(target_manager.targets) == 2
        assert target_manager.targets[0]["ip"] == "192.168.1.0"
        assert target_manager.targets[1]["ip"] == "192.168.1.4"

    def test_remove_range_invalid(self, target_manager):
        """Test remove_range with invalid range returns 0."""
        target_manager.add({"ip": "192.168.1.1", "name": "test"})

        count = target_manager.remove_range(5, 10)
        assert count == 0

    def test_clear(self, target_manager):
        """Test clearing all targets."""
        for i in range(3):
            target_manager.add({"ip": f"192.168.1.{i}", "name": f"target{i}"})

        count = target_manager.clear()

        assert count == 3
        assert len(target_manager.targets) == 0
        assert target_manager.current_index == 0

    def test_modify(self, target_manager, sample_target):
        """Test modifying a target's attributes."""
        target_manager.add(sample_target)
        result = target_manager.modify(0, name="new-name", ip="10.0.0.1")

        assert result is True
        assert target_manager.targets[0]["name"] == "new-name"
        assert target_manager.targets[0]["ip"] == "10.0.0.1"

    def test_modify_invalid_index(self, target_manager):
        """Test modify with invalid index returns False."""
        result = target_manager.modify(999, name="test")
        assert result is False

    def test_list(self, target_manager):
        """Test listing all targets."""
        for i in range(3):
            target_manager.add({"ip": f"192.168.1.{i}", "name": f"target{i}"})

        targets = target_manager.list()

        assert len(targets) == 3
        assert targets is target_manager.targets

    def test_get_current_empty(self, target_manager):
        """Test get_current returns None when empty."""
        assert target_manager.get_current() is None

    def test_set_current_by_index(self, target_manager):
        """Test setting current target by index."""
        for i in range(3):
            target_manager.add({"ip": f"192.168.1.{i}", "name": f"target{i}"})

        result = target_manager.set_current("2")

        assert result is True
        assert target_manager.current_index == 2

    def test_set_current_by_ip(self, target_manager):
        """Test setting current target by IP."""
        for i in range(3):
            target_manager.add({"ip": f"192.168.1.{i}", "name": f"target{i}"})

        result = target_manager.set_current("192.168.1.1")

        assert result is True
        assert target_manager.current_index == 1

    def test_set_current_nonexistent(self, target_manager):
        """Test set_current with non-existent identifier returns False."""
        target_manager.add({"ip": "192.168.1.1", "name": "test"})
        result = target_manager.set_current("nonexistent")

        assert result is False

    def test_export(self, target_manager, sample_target):
        """Test exporting target data."""
        target_manager.add(sample_target)
        data = target_manager.export()

        assert "targets" in data
        assert "current_index" in data
        assert len(data["targets"]) == 1

    def test_import_data(self, target_manager, sample_target):
        """Test importing target data."""
        sample_target["added_at"] = datetime.now().isoformat()
        data = {
            "targets": [sample_target],
            "current_index": 0
        }

        target_manager.import_data(data)

        assert len(target_manager.targets) == 1
        assert target_manager.targets[0]["ip"] == sample_target["ip"]

    def test_current_index_adjusts_on_remove(self, target_manager):
        """Test current_index adjusts when current target is removed."""
        for i in range(3):
            target_manager.add({"ip": f"192.168.1.{i}", "name": f"target{i}"})

        target_manager.set_current("2")  # Set to last target
        target_manager.remove_by_index(2)  # Remove last target

        # Current index should adjust to valid range
        assert target_manager.current_index <= len(target_manager.targets) - 1


# =============================================================================
# CredentialManager Tests
# =============================================================================

class TestCredentialManager:
    """Tests for the CredentialManager class."""

    def test_initial_state(self, credential_manager):
        """Test initial state of CredentialManager."""
        assert credential_manager.credentials == []
        assert credential_manager.current_index == 0

    def test_add_credential(self, credential_manager, sample_credential):
        """Test adding a credential."""
        result = credential_manager.add(sample_credential)

        assert result is True
        assert len(credential_manager.credentials) == 1
        assert credential_manager.credentials[0]["username"] == sample_credential["username"]

    def test_add_duplicate_rejected(self, credential_manager, sample_credential):
        """Test duplicate credentials (same username+domain) are rejected."""
        credential_manager.add(sample_credential)
        result = credential_manager.add(sample_credential)

        assert result is False
        assert len(credential_manager.credentials) == 1

    def test_remove_by_username(self, credential_manager, sample_credential):
        """Test removing a credential by username."""
        credential_manager.add(sample_credential)
        result = credential_manager.remove(sample_credential["username"])

        assert result is True
        assert len(credential_manager.credentials) == 0

    def test_remove_by_index(self, credential_manager, sample_credential):
        """Test removing a credential by index."""
        credential_manager.add(sample_credential)
        result = credential_manager.remove_by_index(0)

        assert result is True
        assert len(credential_manager.credentials) == 0

    def test_remove_range(self, credential_manager):
        """Test removing a range of credentials."""
        for i in range(5):
            credential_manager.add({"username": f"user{i}", "password": "pass"})

        count = credential_manager.remove_range(1, 3)

        assert count == 3
        assert len(credential_manager.credentials) == 2

    def test_clear(self, credential_manager, sample_credential):
        """Test clearing all credentials."""
        credential_manager.add(sample_credential)
        count = credential_manager.clear()

        assert count == 1
        assert len(credential_manager.credentials) == 0

    def test_modify(self, credential_manager, sample_credential):
        """Test modifying a credential's attributes."""
        credential_manager.add(sample_credential)
        result = credential_manager.modify(0, password="newpass", domain="NEWDOMAIN")

        assert result is True
        assert credential_manager.credentials[0]["password"] == "newpass"
        assert credential_manager.credentials[0]["domain"] == "NEWDOMAIN"

    def test_get_current(self, credential_manager, sample_credential):
        """Test getting current credential."""
        credential_manager.add(sample_credential)

        current = credential_manager.get_current()

        assert current is not None
        assert current["username"] == sample_credential["username"]

    def test_set_current_by_username(self, credential_manager):
        """Test setting current credential by username."""
        for i in range(3):
            credential_manager.add({"username": f"user{i}", "password": "pass"})

        result = credential_manager.set_current("user2")

        assert result is True
        assert credential_manager.current_index == 2

    def test_export_import(self, credential_manager, sample_credential):
        """Test export and import roundtrip."""
        sample_credential["added_at"] = datetime.now().isoformat()
        credential_manager.add(sample_credential)
        data = credential_manager.export()

        new_manager = CredentialManager()
        new_manager.import_data(data)

        assert len(new_manager.credentials) == 1
        assert new_manager.credentials[0]["username"] == sample_credential["username"]


# =============================================================================
# ServiceManager Tests
# =============================================================================

class TestServiceManager:
    """Tests for the ServiceManager class."""

    def test_initial_state(self, service_manager):
        """Test initial state of ServiceManager."""
        assert service_manager.services == {}

    def test_add_service(self, service_manager):
        """Test adding a service."""
        service_manager.add_service("192.168.1.1", "ssh", 22)

        assert "192.168.1.1" in service_manager.services
        assert "ssh" in service_manager.services["192.168.1.1"]
        assert 22 in service_manager.services["192.168.1.1"]["ssh"]

    def test_add_service_multiple_ports(self, service_manager):
        """Test adding multiple ports for same service."""
        service_manager.add_service("192.168.1.1", "http", 80)
        service_manager.add_service("192.168.1.1", "http", 8080)

        services = service_manager.services["192.168.1.1"]["http"]
        assert 80 in services
        assert 8080 in services

    def test_add_service_no_duplicates(self, service_manager):
        """Test duplicate port not added twice."""
        service_manager.add_service("192.168.1.1", "ssh", 22)
        service_manager.add_service("192.168.1.1", "ssh", 22)

        assert len(service_manager.services["192.168.1.1"]["ssh"]) == 1

    def test_get_services_for_target(self, service_manager):
        """Test getting services for a specific target."""
        service_manager.add_service("192.168.1.1", "ssh", 22)
        service_manager.add_service("192.168.1.1", "http", 80)
        service_manager.add_service("192.168.1.2", "smb", 445)

        services = service_manager.get_services("192.168.1.1")

        assert "ssh" in services
        assert "http" in services
        assert "smb" not in services

    def test_get_services_nonexistent(self, service_manager):
        """Test getting services for non-existent target."""
        services = service_manager.get_services("nonexistent")
        assert services == {}

    def test_has_service(self, service_manager):
        """Test checking if target has service."""
        service_manager.add_service("192.168.1.1", "ssh", 22)

        assert service_manager.has_service("192.168.1.1", "ssh") is True
        assert service_manager.has_service("192.168.1.1", "http") is False
        assert service_manager.has_service("192.168.1.2", "ssh") is False

    def test_clear(self, service_manager):
        """Test clearing all services."""
        service_manager.add_service("192.168.1.1", "ssh", 22)
        service_manager.add_service("192.168.1.2", "http", 80)

        count = service_manager.clear()

        assert count == 2
        assert service_manager.services == {}

    def test_export_import(self, service_manager):
        """Test export and import roundtrip."""
        service_manager.add_service("192.168.1.1", "ssh", 22)
        data = service_manager.export()

        new_manager = ServiceManager()
        new_manager.import_data(data)

        assert new_manager.has_service("192.168.1.1", "ssh")


# =============================================================================
# WordlistManager Tests
# =============================================================================

class TestWordlistManager:
    """Tests for the WordlistManager class."""

    def test_initial_state(self, wordlist_manager):
        """Test initial state with default categories."""
        categories = wordlist_manager.get_categories()

        assert "web_dir" in categories
        assert "password" in categories
        assert "username" in categories
        assert "subdomain" in categories

    def test_add_wordlist(self, wordlist_manager, temp_wordlist):
        """Test adding a wordlist."""
        result = wordlist_manager.add("web_dir", temp_wordlist, "test_wordlist")

        assert result is True
        wordlists = wordlist_manager.list("web_dir")
        assert len(wordlists["web_dir"]) == 1
        assert wordlists["web_dir"][0]["name"] == "test_wordlist"

    def test_add_wordlist_invalid_category(self, wordlist_manager, temp_wordlist):
        """Test adding to invalid category returns False."""
        result = wordlist_manager.add("invalid_category", temp_wordlist)
        assert result is False

    def test_add_wordlist_nonexistent_file(self, wordlist_manager):
        """Test adding non-existent file returns False."""
        result = wordlist_manager.add("web_dir", "/nonexistent/file.txt")
        assert result is False

    def test_add_duplicate_rejected(self, wordlist_manager, temp_wordlist):
        """Test duplicate wordlist paths are rejected."""
        wordlist_manager.add("web_dir", temp_wordlist)
        result = wordlist_manager.add("web_dir", temp_wordlist)

        assert result is False
        assert len(wordlist_manager.wordlists["web_dir"]) == 1

    def test_remove_wordlist(self, wordlist_manager, temp_wordlist):
        """Test removing a wordlist."""
        wordlist_manager.add("web_dir", temp_wordlist, "test")
        result = wordlist_manager.remove("web_dir", "test")

        assert result is True
        assert len(wordlist_manager.wordlists["web_dir"]) == 0

    def test_remove_by_path(self, wordlist_manager, temp_wordlist):
        """Test removing a wordlist by path."""
        wordlist_manager.add("web_dir", temp_wordlist)
        result = wordlist_manager.remove("web_dir", temp_wordlist)

        assert result is True

    def test_list_all_categories(self, wordlist_manager, temp_wordlist):
        """Test listing all wordlists."""
        wordlist_manager.add("web_dir", temp_wordlist)
        all_wordlists = wordlist_manager.list()

        assert "web_dir" in all_wordlists
        assert "password" in all_wordlists

    def test_list_single_category(self, wordlist_manager, temp_wordlist):
        """Test listing wordlists for single category."""
        wordlist_manager.add("web_dir", temp_wordlist)
        wordlists = wordlist_manager.list("web_dir")

        assert "web_dir" in wordlists
        assert len(wordlists) == 1

    def test_get_current_none(self, wordlist_manager):
        """Test get_current returns None when nothing selected."""
        assert wordlist_manager.get_current("web_dir") is None

    def test_set_current_by_index(self, wordlist_manager, temp_wordlist):
        """Test setting current wordlist by index."""
        wordlist_manager.add("web_dir", temp_wordlist, "test")
        result = wordlist_manager.set_current("web_dir", "0")

        assert result is True
        assert wordlist_manager.get_current("web_dir")["name"] == "test"

    def test_set_current_by_name(self, wordlist_manager, temp_wordlist):
        """Test setting current wordlist by name."""
        wordlist_manager.add("web_dir", temp_wordlist, "test_name")
        result = wordlist_manager.set_current("web_dir", "test_name")

        assert result is True

    def test_export_import(self, wordlist_manager, temp_wordlist):
        """Test export and import roundtrip."""
        wordlist_manager.add("web_dir", temp_wordlist, "test")
        wordlist_manager.set_current("web_dir", "0")
        data = wordlist_manager.export()

        new_manager = WordlistManager()
        new_manager.import_data(data)

        assert len(new_manager.wordlists["web_dir"]) == 1
        assert new_manager.current_selections["web_dir"] == 0


# =============================================================================
# Session Tests
# =============================================================================

class TestSession:
    """Tests for the Session class."""

    def test_initial_state(self, clean_session):
        """Test initial state of Session."""
        assert clean_session.current_module is None
        assert clean_session.module_history == []
        assert clean_session.workspace == {}
        assert clean_session.command_history == []
        assert clean_session.run_mode == "single"

    def test_load_module(self, clean_session):
        """Test loading a module."""
        mock_module = MagicMock()
        mock_module.name = "TestModule"

        clean_session.load_module(mock_module)

        assert clean_session.current_module is mock_module
        mock_module.auto_set_from_context.assert_called_once()

    def test_load_module_records_previous(self, clean_session):
        """Test loading new module records previous in history."""
        module1 = MagicMock()
        module1.name = "Module1"
        module2 = MagicMock()
        module2.name = "Module2"

        clean_session.load_module(module1)
        clean_session.load_module(module2)

        assert len(clean_session.module_history) == 1
        assert clean_session.module_history[0]["module"] == "Module1"

    def test_unload_module(self, clean_session):
        """Test unloading a module."""
        mock_module = MagicMock()
        mock_module.name = "TestModule"
        clean_session.load_module(mock_module)

        clean_session.unload_module()

        assert clean_session.current_module is None
        assert len(clean_session.module_history) == 1

    def test_store_results(self, clean_session):
        """Test storing module results."""
        results = {"success": True, "data": "test"}

        clean_session.store_results("test_module", results)

        stored = clean_session.get_results("test_module")
        assert len(stored) == 1
        assert stored[0]["results"] == results

    def test_store_results_multiple(self, clean_session):
        """Test storing multiple results for same module."""
        clean_session.store_results("test_module", {"run": 1})
        clean_session.store_results("test_module", {"run": 2})

        stored = clean_session.get_results("test_module")
        assert len(stored) == 2

    def test_get_results_empty(self, clean_session):
        """Test getting results for module with no results."""
        results = clean_session.get_results("nonexistent")
        assert results == []

    def test_add_command(self, clean_session):
        """Test adding command to history."""
        clean_session.add_command("use nmap")

        assert len(clean_session.command_history) == 1
        assert clean_session.command_history[0]["command"] == "use nmap"

    def test_get_current_target(self, clean_session, sample_target):
        """Test getting current target through session."""
        clean_session.targets.add(sample_target)

        target = clean_session.get_current_target()

        assert target["ip"] == sample_target["ip"]

    def test_get_current_credential(self, clean_session, sample_credential):
        """Test getting current credential through session."""
        clean_session.credentials.add(sample_credential)

        cred = clean_session.get_current_credential()

        assert cred["username"] == sample_credential["username"]

    def test_export_session(self, clean_session, sample_target, sample_credential):
        """Test exporting full session state."""
        clean_session.targets.add(sample_target)
        clean_session.credentials.add(sample_credential)
        clean_session.run_mode = "all"

        data = clean_session.export_session()

        assert "targets" in data
        assert "credentials" in data
        assert "workspace" in data
        assert data["run_mode"] == "all"

    def test_import_session(self, clean_session):
        """Test importing session state."""
        data = {
            "targets": {"targets": [{"ip": "10.0.0.1", "name": "test"}], "current_index": 0},
            "credentials": {"credentials": [{"username": "admin"}], "current_index": 0},
            "workspace": {"module1": [{"results": "test"}]},
            "run_mode": "all"
        }

        clean_session.import_session(data)

        assert len(clean_session.targets.list()) == 1
        assert len(clean_session.credentials.list()) == 1
        assert "module1" in clean_session.workspace
        assert clean_session.run_mode == "all"


# =============================================================================
# Edge Cases
# =============================================================================

class TestSessionEdgeCases:
    """Tests for edge cases in session management."""

    def test_target_url_vs_ip(self, target_manager):
        """Test targets can have URL or IP."""
        target_manager.add({"ip": "192.168.1.1", "name": "network"})
        target_manager.add({"url": "http://example.com", "name": "web"})

        assert len(target_manager.targets) == 2

    def test_credential_with_hash(self, credential_manager, sample_credential_with_hash):
        """Test credentials with hash instead of password."""
        result = credential_manager.add(sample_credential_with_hash)

        assert result is True
        cred = credential_manager.get_current()
        assert cred["hash"] is not None
        assert cred["hash_type"] == "NTLM"

    def test_service_manager_multiple_targets(self, service_manager):
        """Test services across multiple targets."""
        service_manager.add_service("192.168.1.1", "ssh", 22)
        service_manager.add_service("192.168.1.2", "ssh", 22)
        service_manager.add_service("192.168.1.1", "http", 80)

        assert len(service_manager.services) == 2
        assert service_manager.has_service("192.168.1.1", "ssh")
        assert service_manager.has_service("192.168.1.2", "ssh")
        assert service_manager.has_service("192.168.1.1", "http")
        assert not service_manager.has_service("192.168.1.2", "http")

    def test_session_managers_are_independent(self, clean_session):
        """Test that session managers are separate instances."""
        session2 = Session()

        clean_session.targets.add({"ip": "192.168.1.1", "name": "test"})

        # session2 should not have the target
        assert len(session2.targets.list()) == 0
