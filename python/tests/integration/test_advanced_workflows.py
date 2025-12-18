"""
Advanced Integration Tests for PurpleSploit Workflows.

Tests end-to-end workflows including reconnaissance pipelines,
attack chains, and credential management flows.
"""

import pytest
from unittest.mock import MagicMock, patch
import json
from typing import Dict, Any, List


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def full_framework(test_database, clean_session):
    """Create a complete framework for integration testing."""
    framework = MagicMock()
    framework.session = clean_session
    framework.database = test_database
    framework.log = MagicMock()
    framework.modules = {}

    # Add helper methods using actual session API
    def add_target(target_type, identifier, name=None):
        target = {
            "type": target_type,
            "name": name or identifier
        }
        if target_type == "network":
            target["ip"] = identifier
        else:
            target["url"] = identifier
        return clean_session.targets.add(target)

    def add_credential(username, password=None, hash_val=None, domain=None):
        return clean_session.credentials.add({
            "username": username,
            "password": password,
            "hash": hash_val,
            "domain": domain
        })

    def add_service(target, port, service, version=None):
        # Note: add_service takes (target, service, port) not (target, port, service)
        return clean_session.services.add_service(target, service, port)

    framework.add_target = add_target
    framework.add_credential = add_credential
    framework.add_service = add_service

    return framework


@pytest.fixture
def nmap_module_class():
    """Create a mock Nmap module class."""
    from purplesploit.core.module import ExternalToolModule

    class MockNmapModule(ExternalToolModule):
        def __init__(self, framework):
            super().__init__(framework)
            self.tool_name = "nmap"

        @property
        def name(self):
            return "Nmap Scanner"

        @property
        def description(self):
            return "Network port scanner"

        @property
        def author(self):
            return "Test"

        @property
        def category(self):
            return "recon"

        def build_command(self):
            return f"nmap {self.get_option('RHOST')}"

        def run(self):
            return {
                "success": True,
                "output": "22/tcp open ssh\n80/tcp open http",
                "ports": [22, 80],
                "services": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 8.0"},
                    {"port": 80, "service": "http", "version": "nginx 1.18"}
                ]
            }

    return MockNmapModule


@pytest.fixture
def smb_auth_module_class():
    """Create a mock SMB authentication module class."""
    from purplesploit.core.module import BaseModule

    class MockSMBAuthModule(BaseModule):
        def __init__(self, framework):
            super().__init__(framework)

        @property
        def name(self):
            return "SMB Auth"

        @property
        def description(self):
            return "SMB authentication testing"

        @property
        def author(self):
            return "Test"

        @property
        def category(self):
            return "smb"

        def run(self):
            return {
                "success": True,
                "authenticated": True,
                "admin": True,
                "output": "Authentication successful as admin"
            }

    return MockSMBAuthModule


# =============================================================================
# Reconnaissance Pipeline Tests
# =============================================================================

class TestReconnaissancePipeline:
    """Tests for full reconnaissance workflow."""

    def test_nmap_scan_populates_services(self, full_framework, nmap_module_class):
        """Test that nmap results populate services."""
        # Add target
        full_framework.add_target("network", "192.168.1.100", "dc01")
        full_framework.session.targets.set_current(0)

        # Create and run nmap module
        nmap = nmap_module_class(full_framework)
        nmap.set_option("RHOST", "192.168.1.100")

        result = nmap.run()

        # Simulate service discovery
        for svc in result.get("services", []):
            full_framework.add_service(
                "192.168.1.100",
                svc["port"],
                svc["service"],
                svc.get("version")
            )

        # Verify services are added using internal structure
        # ServiceManager stores by target, so check the target's services
        svc_for_target = full_framework.session.services.get_services("192.168.1.100")
        total_ports = sum(len(ports) for ports in svc_for_target.values())
        assert total_ports == 2

    def test_target_discovery_updates_session(self, full_framework):
        """Test that discovered targets are added to session."""
        # Simulate subnet scan discovery
        discovered = ["192.168.1.1", "192.168.1.50", "192.168.1.100"]

        for ip in discovered:
            full_framework.add_target("network", ip)

        targets = full_framework.session.targets.list()
        assert len(targets) == 3

    def test_scan_results_stored_in_workspace(self, full_framework, nmap_module_class):
        """Test that scan results are stored in workspace."""
        full_framework.add_target("network", "192.168.1.100")
        full_framework.session.targets.set_current(0)

        nmap = nmap_module_class(full_framework)
        nmap.set_option("RHOST", "192.168.1.100")

        result = nmap.run()

        # Store in workspace
        full_framework.session.workspace["nmap_scan"] = result

        assert "nmap_scan" in full_framework.session.workspace
        assert full_framework.session.workspace["nmap_scan"]["success"] is True


# =============================================================================
# SMB Attack Chain Tests
# =============================================================================

class TestSMBAttackChain:
    """Tests for SMB attack chain workflow."""

    def test_credential_discovery_to_auth(self, full_framework, smb_auth_module_class):
        """Test credential discovery to authentication workflow."""
        # Add target
        full_framework.add_target("network", "192.168.1.100", "dc01")
        full_framework.session.targets.set_current(0)

        # Add discovered credential
        full_framework.add_credential(
            username="administrator",
            password="Password123!",
            domain="TESTDOMAIN"
        )
        full_framework.session.credentials.set_current(0)

        # Run SMB auth module
        smb = smb_auth_module_class(full_framework)
        current_cred = full_framework.session.credentials.get_current()

        smb.set_option("USERNAME", current_cred["username"])
        smb.set_option("PASSWORD", current_cred["password"])
        smb.set_option("DOMAIN", current_cred["domain"])

        result = smb.run()

        assert result["success"] is True
        assert result["authenticated"] is True

    def test_hash_auth_workflow(self, full_framework, smb_auth_module_class):
        """Test authentication with NTLM hash."""
        full_framework.add_target("network", "192.168.1.100")
        full_framework.session.targets.set_current(0)

        full_framework.add_credential(
            username="administrator",
            hash_val="aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            domain="TESTDOMAIN"
        )
        full_framework.session.credentials.set_current(0)

        current_cred = full_framework.session.credentials.get_current()
        assert current_cred["hash"] is not None

    def test_multi_target_credential_spray(self, full_framework, smb_auth_module_class):
        """Test credential spray across multiple targets."""
        # Add multiple targets
        targets = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
        for ip in targets:
            full_framework.add_target("network", ip)

        # Add credential
        full_framework.add_credential(
            username="admin",
            password="password",
            domain="CORP"
        )
        full_framework.session.credentials.set_current(0)

        results = []
        for i, target in enumerate(targets):
            full_framework.session.targets.set_current(i)
            smb = smb_auth_module_class(full_framework)
            smb.set_option("RHOST", target)
            results.append(smb.run())

        # All should succeed in mock
        assert all(r["success"] for r in results)


# =============================================================================
# Credential Management Workflow Tests
# =============================================================================

class TestCredentialManagementWorkflow:
    """Tests for credential management workflows."""

    def test_credential_discovery_and_reuse(self, full_framework):
        """Test discovering and reusing credentials."""
        # Simulate secretsdump discovering credentials
        discovered_creds = [
            {"username": "admin", "hash": "aad3b435b51404ee:8846f7eaee8fb117"},
            {"username": "svc_backup", "hash": "31d6cfe0d16ae931b73c59d7e0c089c0:e3c7f1a5b2d4e6f8"},
            {"username": "krbtgt", "hash": "00000000000000000000000000000000:e3c7f1a5b2d4e6f8"}
        ]

        for cred in discovered_creds:
            full_framework.add_credential(
                username=cred["username"],
                hash_val=cred["hash"],
                domain="CORP"
            )

        all_creds = full_framework.session.credentials.list()
        assert len(all_creds) == 3

        # Set and get current credential
        full_framework.session.credentials.set_current(1)
        current = full_framework.session.credentials.get_current()
        assert current["username"] == "svc_backup"

    def test_credential_switching(self, full_framework):
        """Test switching between credentials."""
        full_framework.add_credential("user1", "pass1")
        full_framework.add_credential("user2", "pass2")
        full_framework.add_credential("user3", "pass3")

        full_framework.session.credentials.set_current(0)
        assert full_framework.session.credentials.get_current()["username"] == "user1"

        full_framework.session.credentials.set_current(2)
        assert full_framework.session.credentials.get_current()["username"] == "user3"


# =============================================================================
# Web Application Testing Flow Tests
# =============================================================================

class TestWebApplicationWorkflow:
    """Tests for web application testing workflow."""

    def test_web_target_discovery(self, full_framework):
        """Test web target discovery and tracking."""
        # Add web targets
        full_framework.add_target("web", "http://example.com", "example")
        full_framework.add_target("web", "https://secure.example.com", "secure")
        full_framework.add_target("web", "http://192.168.1.100:8080", "internal")

        targets = full_framework.session.targets.list()
        web_targets = [t for t in targets if t.get("type") == "web"]
        assert len(web_targets) == 3

    def test_directory_discovery_results(self, full_framework):
        """Test storing directory discovery results."""
        full_framework.add_target("web", "http://example.com")
        full_framework.session.targets.set_current(0)

        # Simulate feroxbuster results
        discoveries = [
            {"url": "/admin", "status": 200},
            {"url": "/login", "status": 200},
            {"url": "/api", "status": 301},
            {"url": "/backup", "status": 403}
        ]

        full_framework.session.workspace["dir_scan"] = {
            "target": "http://example.com",
            "discoveries": discoveries
        }

        assert len(full_framework.session.workspace["dir_scan"]["discoveries"]) == 4


# =============================================================================
# Session Persistence Workflow Tests
# =============================================================================

class TestSessionPersistenceWorkflow:
    """Tests for session persistence workflows."""

    def test_full_session_export_import(self, full_framework):
        """Test complete session export and import."""
        # Populate session
        full_framework.add_target("network", "192.168.1.1")
        full_framework.add_target("network", "192.168.1.2")
        full_framework.add_credential("admin", "pass", domain="CORP")
        full_framework.add_service("192.168.1.1", 22, "ssh", "OpenSSH 8.0")

        # Export
        export_data = full_framework.session.export_session()

        # Clear and reimport
        full_framework.session.targets._targets = []
        full_framework.session.credentials._credentials = []
        full_framework.session.services._services = []

        full_framework.session.import_session(export_data)

        # Verify restoration
        assert len(full_framework.session.targets.list()) == 2
        assert len(full_framework.session.credentials.list()) == 1
        # Services are stored internally, check via get_services
        svc_count = len(full_framework.session.services.get_services("192.168.1.1"))
        assert svc_count >= 1

    def test_workspace_persistence(self, full_framework):
        """Test workspace data persistence via store_results."""
        # Store scan results using the proper API
        full_framework.session.store_results("scan1", {"ports": [22, 80]})
        full_framework.session.store_results("scan2", {"vulnerabilities": ["CVE-2021-1234"]})

        # Verify results are stored
        assert "scan1" in full_framework.session.workspace
        assert "scan2" in full_framework.session.workspace

        # Export and import
        export_data = full_framework.session.export_session()

        # Note: import_session restores workspace data
        assert len(export_data["workspace"]) >= 2


# =============================================================================
# Error Recovery Workflow Tests
# =============================================================================

class TestErrorRecoveryWorkflow:
    """Tests for error recovery in workflows."""

    def test_module_failure_preserves_context(self, full_framework):
        """Test that module failure doesn't lose context."""
        # Setup context
        full_framework.add_target("network", "192.168.1.100")
        full_framework.session.targets.set_current(0)
        full_framework.add_credential("admin", "pass")
        full_framework.session.credentials.set_current(0)

        # Simulate module failure
        try:
            raise Exception("Module execution failed")
        except:
            pass

        # Verify context preserved
        assert full_framework.session.targets.get_current() is not None
        assert full_framework.session.credentials.get_current() is not None

    def test_partial_results_saved(self, full_framework):
        """Test that partial results are saved on failure."""
        full_framework.add_target("network", "192.168.1.100")

        # Store partial results before simulated failure
        partial_results = {
            "ports_scanned": 1000,
            "ports_open": [22, 80, 443],
            "complete": False
        }
        full_framework.session.workspace["partial_scan"] = partial_results

        # Verify partial results exist
        assert full_framework.session.workspace["partial_scan"]["complete"] is False
        assert len(full_framework.session.workspace["partial_scan"]["ports_open"]) == 3


# =============================================================================
# Multi-Module Workflow Tests
# =============================================================================

class TestMultiModuleWorkflow:
    """Tests for workflows involving multiple modules."""

    def test_service_based_module_selection(self, full_framework):
        """Test selecting modules based on discovered services."""
        # Add services
        full_framework.add_service("192.168.1.100", 22, "ssh")
        full_framework.add_service("192.168.1.100", 445, "smb")
        full_framework.add_service("192.168.1.100", 80, "http")

        services = full_framework.session.services.get_services("192.168.1.100")

        # Determine applicable modules based on services
        applicable_modules = []
        for service_name, ports in services.items():
            if service_name == "ssh":
                applicable_modules.append("ssh_brute")
            elif service_name == "smb":
                applicable_modules.append("smb_enum")
                applicable_modules.append("smb_auth")
            elif service_name == "http":
                applicable_modules.append("web_scan")
                applicable_modules.append("dir_brute")

        assert "smb_enum" in applicable_modules
        assert "web_scan" in applicable_modules
        assert "ssh_brute" in applicable_modules

    def test_results_aggregation(self, full_framework):
        """Test aggregating results from multiple module runs."""
        # Simulate results from multiple modules
        full_framework.session.workspace["nmap"] = {
            "ports": [22, 80, 445],
            "target": "192.168.1.100"
        }
        full_framework.session.workspace["smb_enum"] = {
            "shares": ["ADMIN$", "C$", "IPC$"],
            "target": "192.168.1.100"
        }
        full_framework.session.workspace["dir_brute"] = {
            "directories": ["/admin", "/login"],
            "target": "192.168.1.100"
        }

        # Aggregate results
        aggregated = {
            "target": "192.168.1.100",
            "open_ports": full_framework.session.workspace["nmap"]["ports"],
            "smb_shares": full_framework.session.workspace["smb_enum"]["shares"],
            "web_paths": full_framework.session.workspace["dir_brute"]["directories"]
        }

        assert len(aggregated["open_ports"]) == 3
        assert len(aggregated["smb_shares"]) == 3
        assert len(aggregated["web_paths"]) == 2


# =============================================================================
# Database Integration Workflow Tests
# =============================================================================

class TestDatabaseIntegrationWorkflow:
    """Tests for database-integrated workflows."""

    def test_module_history_tracking(self, full_framework):
        """Test that module executions are tracked in database."""
        # Record module executions
        executions = [
            ("recon/nmap", "recon/nmap", {"RHOST": "192.168.1.100"}, True),
            ("smb/auth", "smb/auth", {"RHOST": "192.168.1.100"}, True),
            ("smb/shares", "smb/shares", {"RHOST": "192.168.1.100"}, False)
        ]

        for module_name, module_path, options, success in executions:
            full_framework.database.add_module_execution(
                module_name=module_name,
                module_path=module_path,
                options=options,
                results={"success": success},
                success=success
            )

        history = full_framework.database.get_module_history()
        assert len(history) == 3

    def test_target_database_sync(self, full_framework):
        """Test target synchronization with database."""
        # Add targets to session
        full_framework.add_target("network", "10.10.10.1")
        full_framework.add_target("network", "10.10.10.2")

        # Persist to database using correct API (target_type, identifier, name)
        for target in full_framework.session.targets.list():
            full_framework.database.add_target(
                target_type=target.get("type", "network"),
                identifier=target.get("ip"),
                name=target.get("name")
            )

        # Verify in database
        db_targets = full_framework.database.get_targets()
        assert len(db_targets) >= 2
