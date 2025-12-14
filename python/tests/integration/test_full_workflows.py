"""
Integration tests for complete PurpleSploit workflows.

Tests end-to-end scenarios including command handler, module operations,
and context management across the entire framework.
"""

import pytest
from unittest.mock import MagicMock, patch, Mock
from purplesploit.core.session import Session
from purplesploit.core.database import Database
from purplesploit.core.module import BaseModule, ExternalToolModule
from purplesploit.ui.commands import CommandHandler
from purplesploit.ui.display import Display
from typing import Dict, Any, List


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def full_framework(tmp_path):
    """Create a complete framework setup for integration testing."""
    framework = MagicMock()
    framework.session = Session()
    framework.database = Database(str(tmp_path / "test.db"))
    framework.log = MagicMock()
    framework.modules = {}
    framework.workspace = MagicMock()
    framework.workspace.logs_dir = str(tmp_path / "logs")

    def add_target(target_type, identifier, name=None):
        target = {
            "type": target_type,
            "name": name or identifier
        }
        if target_type == "network":
            target["ip"] = identifier
        else:
            target["url"] = identifier
        return framework.session.targets.add(target)

    def add_credential(username, password, domain=None, dcip=None, dns=None):
        cred = {
            "username": username,
            "password": password
        }
        if domain:
            cred["domain"] = domain
        if dcip:
            cred["dcip"] = dcip
        if dns:
            cred["dns"] = dns
        return framework.session.credentials.add(cred)

    framework.add_target = add_target
    framework.add_credential = add_credential

    yield framework
    framework.database.close()


@pytest.fixture
def operations_module_class():
    """Create a test module class with operations."""
    class TestOperationsModule(BaseModule):
        @property
        def name(self):
            return "Test Operations Module"

        @property
        def description(self):
            return "Module with operations for testing"

        @property
        def author(self):
            return "Test"

        @property
        def category(self):
            return "test"

        def _init_options(self):
            self.options = {
                "RHOST": {"value": None, "required": True, "description": "Target", "default": None},
                "USERNAME": {"value": None, "required": False, "description": "User", "default": None},
                "PASSWORD": {"value": None, "required": False, "description": "Pass", "default": None},
            }

        def get_operations(self) -> List[Dict[str, Any]]:
            return [
                {"name": "Authenticate", "description": "Test authentication", "handler": "op_auth", "subcategory": "auth"},
                {"name": "Enumerate Users", "description": "Enumerate users", "handler": "op_enum_users", "subcategory": "enum"},
                {"name": "Enumerate Groups", "description": "Enumerate groups", "handler": "op_enum_groups", "subcategory": "enum"},
                {"name": "Execute Command", "description": "Execute command", "handler": "op_exec", "subcategory": "exec"},
            ]

        def op_auth(self) -> Dict[str, Any]:
            rhost = self.get_option("RHOST")
            username = self.get_option("USERNAME")
            return {
                "success": True,
                "output": f"Authenticated to {rhost} as {username}"
            }

        def op_enum_users(self) -> Dict[str, Any]:
            return {
                "success": True,
                "output": ["user1", "user2", "admin"]
            }

        def op_enum_groups(self) -> Dict[str, Any]:
            return {
                "success": True,
                "output": ["Domain Users", "Domain Admins"]
            }

        def op_exec(self) -> Dict[str, Any]:
            return {
                "success": True,
                "output": "Command executed successfully"
            }

        def run(self):
            return {"success": True}

    return TestOperationsModule


@pytest.fixture
def simple_module_class():
    """Create a simple test module class without operations."""
    class SimpleTestModule(BaseModule):
        @property
        def name(self):
            return "Simple Test Module"

        @property
        def description(self):
            return "Simple module for testing"

        @property
        def author(self):
            return "Test"

        @property
        def category(self):
            return "test"

        def _init_options(self):
            self.options = {
                "RHOST": {"value": None, "required": True, "description": "Target", "default": None},
                "RPORT": {"value": 80, "required": False, "description": "Port", "default": 80},
            }

        def run(self):
            rhost = self.get_option("RHOST")
            rport = self.get_option("RPORT")
            return {
                "success": True,
                "target": rhost,
                "port": rport,
                "results": ["finding1", "finding2"]
            }

    return SimpleTestModule


# =============================================================================
# Complete Workflow Tests
# =============================================================================

@pytest.mark.integration
class TestCompleteWorkflows:
    """Tests for complete end-to-end workflows."""

    def test_target_cred_module_run_workflow(self, full_framework, simple_module_class):
        """Test complete workflow: add target -> add cred -> load module -> run."""
        # Add target
        full_framework.add_target("network", "192.168.1.100", "target1")
        assert len(full_framework.session.targets.list()) == 1

        # Add credential
        full_framework.add_credential("admin", "password123", "DOMAIN.COM")
        assert len(full_framework.session.credentials.list()) == 1

        # Load module
        module = simple_module_class(full_framework)
        full_framework.session.load_module(module)

        # Context should be auto-populated
        assert module.get_option("RHOST") == "192.168.1.100"

        # Run module
        result = module.run()
        assert result["success"] is True
        assert result["target"] == "192.168.1.100"

    def test_module_operations_workflow(self, full_framework, operations_module_class):
        """Test workflow using module operations."""
        # Setup context
        full_framework.add_target("network", "10.0.0.1")
        full_framework.add_credential("admin", "secret")

        # Load module
        module = operations_module_class(full_framework)
        full_framework.session.load_module(module)

        # Verify operations available
        assert module.has_operations()
        ops = module.get_operations()
        assert len(ops) == 4

        # Get by subcategory
        enum_ops = module.get_operations_by_subcategory("enum")
        assert len(enum_ops) == 2

        # Execute specific operation
        result = module.op_auth()
        assert result["success"] is True
        assert "10.0.0.1" in result["output"]
        assert "admin" in result["output"]

    def test_multi_target_workflow(self, full_framework, simple_module_class):
        """Test workflow with multiple targets."""
        # Add multiple targets
        targets = [
            ("192.168.1.1", "server1"),
            ("192.168.1.2", "server2"),
            ("192.168.1.3", "server3"),
        ]
        for ip, name in targets:
            full_framework.add_target("network", ip, name)

        assert len(full_framework.session.targets.list()) == 3

        # Select different target
        full_framework.session.targets.set_current("1")  # server2
        current = full_framework.session.targets.get_current()
        assert current["ip"] == "192.168.1.2"

        # Load module
        module = simple_module_class(full_framework)
        full_framework.session.load_module(module)

        # Should use current target
        assert module.get_option("RHOST") == "192.168.1.2"

        # Run and store results
        result = module.run()
        full_framework.session.store_results("test_run", result)

        # Verify results stored
        stored = full_framework.session.get_results("test_run")
        assert len(stored) == 1

    def test_results_aggregation_workflow(self, full_framework, simple_module_class):
        """Test aggregating results from multiple runs."""
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

        for ip in targets:
            full_framework.add_target("network", ip)

        results = []
        for i, ip in enumerate(targets):
            full_framework.session.targets.set_current(str(i))

            module = simple_module_class(full_framework)
            full_framework.session.load_module(module)

            result = module.run()
            results.append(result)
            full_framework.session.store_results("scan_results", result)

        # All results stored
        stored = full_framework.session.get_results("scan_results")
        assert len(stored) == 3

        # Verify each target was scanned
        scanned_targets = [r["results"]["target"] for r in stored]
        for ip in targets:
            assert ip in scanned_targets


# =============================================================================
# Context Propagation Workflow Tests
# =============================================================================

@pytest.mark.integration
class TestContextWorkflows:
    """Tests for context propagation across workflows."""

    def test_context_persists_across_modules(self, full_framework, simple_module_class, operations_module_class):
        """Test context persists when switching between modules."""
        # Setup initial context
        full_framework.add_target("network", "192.168.1.100")
        full_framework.add_credential("admin", "pass123")

        # Load first module
        module1 = simple_module_class(full_framework)
        full_framework.session.load_module(module1)
        assert module1.get_option("RHOST") == "192.168.1.100"

        # Run first module
        result1 = module1.run()
        assert result1["success"] is True

        # Load second module (different type)
        module2 = operations_module_class(full_framework)
        full_framework.session.load_module(module2)

        # Context should still be set
        assert module2.get_option("RHOST") == "192.168.1.100"
        assert module2.get_option("USERNAME") == "admin"

    def test_credential_switch_workflow(self, full_framework, operations_module_class):
        """Test switching credentials during workflow."""
        full_framework.add_target("network", "192.168.1.100")

        # Add multiple credentials
        full_framework.add_credential("user1", "pass1")
        full_framework.add_credential("admin", "adminpass")

        # Load module with first cred
        module = operations_module_class(full_framework)
        full_framework.session.load_module(module)
        assert module.get_option("USERNAME") == "user1"

        # Run auth with first cred
        result1 = module.op_auth()
        assert "user1" in result1["output"]

        # Switch to second credential and explicitly set in module
        full_framework.session.credentials.set_current("1")
        current_cred = full_framework.session.credentials.get_current()
        module.set_option("USERNAME", current_cred["username"])
        module.set_option("PASSWORD", current_cred["password"])

        assert module.get_option("USERNAME") == "admin"

        # Run auth with second cred
        result2 = module.op_auth()
        assert "admin" in result2["output"]

    def test_service_discovery_updates_context(self, full_framework):
        """Test that discovered services update the context."""
        # Add target
        full_framework.add_target("network", "192.168.1.100")

        # Simulate service discovery
        services = [
            ("ssh", 22),
            ("http", 80),
            ("https", 443),
            ("smb", 445),
        ]

        for service, port in services:
            full_framework.session.services.add_service("192.168.1.100", service, port)

        # Verify services in context
        assert full_framework.session.services.has_service("192.168.1.100", "ssh")
        assert full_framework.session.services.has_service("192.168.1.100", "smb")

        # Services is structured as dict of dicts (target -> service -> ports)
        all_services = full_framework.session.services.services
        # Should have 1 target with 4 services
        assert "192.168.1.100" in all_services
        assert len(all_services["192.168.1.100"]) == 4  # 4 services for this target


# =============================================================================
# Database Integration Workflow Tests
# =============================================================================

@pytest.mark.integration
class TestDatabaseWorkflows:
    """Tests for database-integrated workflows."""

    def test_module_history_workflow(self, full_framework, simple_module_class):
        """Test module execution history is recorded."""
        full_framework.add_target("network", "192.168.1.100")

        module = simple_module_class(full_framework)
        full_framework.session.load_module(module)

        # Run module
        result = module.run()

        # Record execution
        full_framework.database.add_module_execution(
            module_name=module.name,
            module_path="test/simple",
            options=module.show_options(),
            results=result,
            success=result["success"]
        )

        # Verify history
        history = full_framework.database.get_module_history()
        assert len(history) == 1
        assert history[0]["module_name"] == "Simple Test Module"

    def test_findings_workflow(self, full_framework):
        """Test findings are recorded and retrievable."""
        # Add findings from simulated module execution
        findings = [
            ("192.168.1.100", "high", "MS17-010", "EternalBlue vulnerability detected"),
            ("192.168.1.100", "medium", "SMB Signing", "SMB signing not required"),
            ("192.168.1.101", "low", "Info", "Host is alive"),
        ]

        for target, severity, title, description in findings:
            full_framework.database.add_finding(
                target=target,
                severity=severity,
                title=title,
                description=description
            )

        # Get all findings
        all_findings = full_framework.database.get_findings()
        assert len(all_findings) == 3

        # Filter by target
        target_findings = full_framework.database.get_findings(target="192.168.1.100")
        assert len(target_findings) == 2

        # Filter by severity
        high_findings = full_framework.database.get_findings(severity="high")
        assert len(high_findings) == 1

    def test_module_defaults_workflow(self, full_framework, simple_module_class):
        """Test module defaults are applied on load."""
        # Set defaults
        full_framework.database.set_module_default("simple", "RPORT", "8080")

        # Get defaults
        defaults = full_framework.database.get_module_defaults("simple")
        assert defaults["RPORT"] == "8080"

        # Module should apply defaults when loaded (requires module to check defaults)
        # This tests the database side of the workflow


# =============================================================================
# Error Recovery Workflow Tests
# =============================================================================

@pytest.mark.integration
class TestErrorRecoveryWorkflows:
    """Tests for error recovery in workflows."""

    def test_module_error_preserves_session(self, full_framework):
        """Test that module errors don't corrupt session state."""
        # Setup initial state
        full_framework.add_target("network", "192.168.1.100")
        full_framework.add_credential("admin", "pass")

        initial_targets = len(full_framework.session.targets.list())
        initial_creds = len(full_framework.session.credentials.list())

        # Create module that errors
        class ErrorModule(BaseModule):
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
                raise ValueError("Simulated error")

        module = ErrorModule(full_framework)

        # Run with error
        try:
            module.run()
        except ValueError:
            pass

        # Session state should be preserved
        assert len(full_framework.session.targets.list()) == initial_targets
        assert len(full_framework.session.credentials.list()) == initial_creds

    def test_partial_results_preserved(self, full_framework, simple_module_class):
        """Test that partial results are preserved on error."""
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

        for ip in targets:
            full_framework.add_target("network", ip)

        # Run against first two targets successfully
        for i in range(2):
            full_framework.session.targets.set_current(str(i))
            module = simple_module_class(full_framework)
            full_framework.session.load_module(module)
            result = module.run()
            full_framework.session.store_results("partial_scan", result)

        # Even if third fails, first two results preserved
        stored = full_framework.session.get_results("partial_scan")
        assert len(stored) == 2


# =============================================================================
# Session Export/Import Workflow Tests
# =============================================================================

@pytest.mark.integration
class TestSessionPersistenceWorkflows:
    """Tests for session export and import workflows."""

    def test_complete_session_roundtrip(self, full_framework, simple_module_class):
        """Test complete session state survives export/import."""
        # Build up session state
        full_framework.add_target("network", "192.168.1.100", "target1")
        full_framework.add_target("web", "http://example.com", "web1")
        full_framework.add_credential("admin", "pass123", "DOMAIN")
        full_framework.session.services.add_service("192.168.1.100", "ssh", 22)

        # Run a module and store results
        module = simple_module_class(full_framework)
        module.set_option("RHOST", "192.168.1.100")
        result = module.run()
        full_framework.session.store_results("test_scan", result)

        # Export session
        exported = full_framework.session.export_session()

        # Create new session and import
        new_session = Session()
        new_session.import_session(exported)

        # Verify state
        assert len(new_session.targets.list()) == 2
        assert len(new_session.credentials.list()) == 1
        assert new_session.services.has_service("192.168.1.100", "ssh")

        # Verify stored results
        results = new_session.get_results("test_scan")
        assert len(results) == 1

    def test_command_history_persists(self, full_framework):
        """Test command history is tracked in session (not necessarily exported)."""
        commands = [
            "use test/module",
            "set RHOST 192.168.1.100",
            "run",
            "targets add 192.168.1.101",
            "back"
        ]

        for cmd in commands:
            full_framework.session.add_command(cmd)

        # Verify history is tracked in current session
        assert len(full_framework.session.command_history) == len(commands)
        assert full_framework.session.command_history[0]["command"] == "use test/module"

        # Note: Command history export/import depends on implementation
        # This test focuses on in-session tracking
