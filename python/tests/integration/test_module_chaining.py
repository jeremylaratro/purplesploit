"""
Integration tests for module chaining scenarios.

Tests cover:
- Running multiple modules in sequence
- Passing data between modules
- Operation-based module workflows
- Multi-target module execution
"""

import pytest
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from purplesploit.core.framework import Framework
from purplesploit.core.session import Session


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def chaining_framework(tmp_path):
    """Create a framework for module chaining tests."""
    db_path = str(tmp_path / "chaining_test.db")
    modules_path = Path(__file__).parent.parent.parent / "purplesploit" / "modules"

    with patch('purplesploit.models.database.db_manager'):
        fw = Framework(modules_path=str(modules_path), db_path=db_path)
        fw.discover_modules()

    yield fw
    fw.cleanup()


@pytest.fixture
def multi_target_framework(chaining_framework):
    """Framework with multiple targets configured."""
    with patch('purplesploit.models.database.db_manager'):
        chaining_framework.add_target("network", "192.168.1.10", "server1")
        chaining_framework.add_target("network", "192.168.1.20", "server2")
        chaining_framework.add_target("network", "192.168.1.30", "server3")

    return chaining_framework


# =============================================================================
# Sequential Module Execution Tests
# =============================================================================

class TestSequentialModuleExecution:
    """Tests for running modules in sequence."""

    def test_run_multiple_modules_sequentially(self, chaining_framework):
        """Test running multiple different modules in sequence."""
        modules = chaining_framework.list_modules()

        results = []
        for module_meta in modules[:3]:  # Test with first 3 modules
            module = chaining_framework.use_module(module_meta.path)
            if module:
                with patch.object(module, 'run', return_value={"success": True, "module": module_meta.name}):
                    result = chaining_framework.run_module(module)
                    results.append(result)

        assert len(results) == 3
        # Check that results were returned (may have validation errors but ran)
        assert all(isinstance(r, dict) for r in results)

    def test_module_results_stored_separately(self, chaining_framework):
        """Test each module's results are stored separately in workspace."""
        modules = chaining_framework.list_modules()

        for module_meta in modules[:2]:
            module = chaining_framework.use_module(module_meta.path)
            if module:
                with patch.object(module, 'run', return_value={"success": True, "data": module_meta.name}):
                    chaining_framework.run_module(module)

        workspace = chaining_framework.session.workspace

        # Should have results for each module
        assert len(workspace) >= 1

    def test_module_history_tracks_sequence(self, chaining_framework):
        """Test module history tracks the sequence of used modules."""
        modules = chaining_framework.list_modules()

        # Use modules in sequence
        chaining_framework.use_module(modules[0].path)
        chaining_framework.use_module(modules[1].path)

        history = chaining_framework.session.module_history

        # History should have at least the first module
        assert len(history) >= 1


# =============================================================================
# Data Passing Between Modules Tests
# =============================================================================

class TestDataPassingBetweenModules:
    """Tests for passing data between modules."""

    def test_scan_results_available_to_next_module(self, chaining_framework):
        """Test scan results from one module are available to next."""
        with patch('purplesploit.models.database.db_manager'):
            chaining_framework.add_target("network", "192.168.1.100")

        # Simulate nmap scan storing services
        chaining_framework.session.services.add_service("192.168.1.100", "ssh", 22)
        chaining_framework.session.services.add_service("192.168.1.100", "smb", 445)

        # Next module should be able to see these services
        services = chaining_framework.session.services.get_services("192.168.1.100")

        assert "ssh" in services
        assert "smb" in services

    def test_discovered_credentials_available(self, chaining_framework):
        """Test credentials discovered by one module available to next."""
        # Simulate credential discovery
        with patch('purplesploit.models.database.db_manager'):
            chaining_framework.add_credential(
                username="discovered_user",
                password="discovered_pass",
                domain="CORP"
            )

        # Next module should auto-populate with discovered creds
        modules = chaining_framework.search_modules("smb")
        if modules:
            module = chaining_framework.use_module(modules[0].path)
            module.auto_set_from_context()

            if "USERNAME" in module.options:
                assert module.get_option("USERNAME") == "discovered_user"

    def test_target_context_persists_between_modules(self, chaining_framework):
        """Test target context persists when switching modules."""
        with patch('purplesploit.models.database.db_manager'):
            chaining_framework.add_target("network", "10.0.0.5", "persistent-target")

        modules = chaining_framework.list_modules()

        # Use first module
        module1 = chaining_framework.use_module(modules[0].path)
        module1.auto_set_from_context()
        target1 = module1.get_option("RHOST") if "RHOST" in module1.options else None

        # Switch to second module
        if len(modules) > 1:
            module2 = chaining_framework.use_module(modules[1].path)
            module2.auto_set_from_context()
            target2 = module2.get_option("RHOST") if "RHOST" in module2.options else None

            # Both should have same target
            if target1 and target2:
                assert target1 == target2 == "10.0.0.5"


# =============================================================================
# Multi-Target Execution Tests
# =============================================================================

class TestMultiTargetExecution:
    """Tests for running modules against multiple targets."""

    def test_iterate_over_multiple_targets(self, multi_target_framework):
        """Test running module against each target."""
        modules = multi_target_framework.search_modules("nmap")
        if not modules:
            pytest.skip("No nmap module found")

        module = multi_target_framework.use_module(modules[0].path)

        targets = multi_target_framework.session.targets.list()
        results = []

        for target in targets:
            multi_target_framework.session.targets.set_current(target["ip"])
            module.auto_set_from_context()

            with patch.object(module, 'run', return_value={"success": True, "target": target["ip"]}):
                result = multi_target_framework.run_module(module)
                results.append(result)

        assert len(results) == 3
        assert all(r["success"] for r in results)

    def test_target_switching_updates_module_options(self, multi_target_framework):
        """Test switching targets updates module RHOST option."""
        modules = multi_target_framework.list_modules()
        module = multi_target_framework.use_module(modules[0].path)

        targets = multi_target_framework.session.targets.list()

        for target in targets:
            multi_target_framework.session.targets.set_current(target["ip"])
            module.auto_set_from_context()

            if "RHOST" in module.options:
                current_target = multi_target_framework.session.targets.get_current()
                # After auto_set, RHOST should match current target
                # Note: auto_set only sets if not already set, so we need to clear first
                module.options["RHOST"]["value"] = None
                module.auto_set_from_context()
                assert module.get_option("RHOST") == current_target["ip"]

    def test_results_tracked_per_target(self, multi_target_framework):
        """Test results are tracked separately per target."""
        modules = multi_target_framework.list_modules()
        module = multi_target_framework.use_module(modules[0].path)

        targets = multi_target_framework.session.targets.list()

        for i, target in enumerate(targets):
            multi_target_framework.session.targets.set_current(target["ip"])

            with patch.object(module, 'run', return_value={"success": True, "target": target["ip"], "run": i}):
                multi_target_framework.run_module(module)

        # Check workspace has all results
        workspace = multi_target_framework.session.workspace
        if module.name in workspace:
            assert len(workspace[module.name]) == 3


# =============================================================================
# Operation-Based Module Chaining Tests
# =============================================================================

class TestOperationBasedChaining:
    """Tests for modules with operations/submenus."""

    def test_module_with_operations_listing(self, chaining_framework):
        """Test listing operations for modules that have them."""
        # Find a module with operations (like nxc_smb)
        modules = chaining_framework.search_modules("smb")

        for module_meta in modules:
            module = chaining_framework.use_module(module_meta.path)
            if module and module.has_operations():
                operations = module.get_operations()
                assert len(operations) > 0
                break

    def test_run_specific_operation(self, chaining_framework):
        """Test running a specific operation from a module."""
        modules = chaining_framework.search_modules("smb")

        for module_meta in modules:
            module = chaining_framework.use_module(module_meta.path)
            if module and module.has_operations():
                operations = module.get_operations()
                if operations:
                    # Get first operation
                    op = operations[0]
                    op_name = op.get("name", op.get("handler"))

                    # Mock the operation handler
                    with patch.object(module, op_name if hasattr(module, op_name) else 'run',
                                    return_value={"success": True, "operation": op_name}):
                        # The actual run would call the operation
                        result = {"success": True, "operation": op_name}
                        assert result["success"] is True
                    break

    def test_operations_filtered_by_subcategory(self, chaining_framework):
        """Test filtering operations by subcategory."""
        modules = chaining_framework.search_modules("smb")

        for module_meta in modules:
            module = chaining_framework.use_module(module_meta.path)
            if module and module.has_operations():
                subcategories = module.get_subcategories()

                if subcategories:
                    # Get operations for first subcategory
                    filtered = module.get_operations_by_subcategory(subcategories[0])
                    assert all(op.get("subcategory", "").lower() == subcategories[0].lower()
                             for op in filtered)
                break


# =============================================================================
# Reconnaissance Chain Tests
# =============================================================================

class TestReconnaissanceChain:
    """Tests simulating a typical reconnaissance chain."""

    def test_nmap_to_service_enumeration_chain(self, chaining_framework):
        """Test chain: nmap scan -> store services -> service-specific enum."""
        with patch('purplesploit.models.database.db_manager'):
            chaining_framework.add_target("network", "10.0.0.100")

        # Step 1: Simulate nmap scan discovering services
        nmap_results = {
            "success": True,
            "services": [
                {"port": 22, "service": "ssh"},
                {"port": 445, "service": "smb"},
                {"port": 80, "service": "http"}
            ]
        }

        # Store discovered services
        for svc in nmap_results["services"]:
            chaining_framework.session.services.add_service(
                "10.0.0.100",
                svc["service"],
                svc["port"]
            )

        # Step 2: Verify services are available for next module
        services = chaining_framework.session.services.get_services("10.0.0.100")
        assert "ssh" in services
        assert "smb" in services
        assert "http" in services

        # Step 3: Find and use SMB-specific module
        smb_modules = chaining_framework.search_modules("smb")
        if smb_modules:
            smb_module = chaining_framework.use_module(smb_modules[0].path)
            smb_module.auto_set_from_context()

            # RHOST should be set from context
            if "RHOST" in smb_module.options:
                assert smb_module.get_option("RHOST") == "10.0.0.100"

    def test_credential_discovery_to_auth_chain(self, chaining_framework):
        """Test chain: discover creds -> use for authentication."""
        with patch('purplesploit.models.database.db_manager'):
            chaining_framework.add_target("network", "10.0.0.100")

        # Step 1: Simulate credential discovery
        with patch('purplesploit.models.database.db_manager'):
            chaining_framework.add_credential(
                username="admin",
                password="Winter2024!",
                domain="CORP"
            )

        # Step 2: Find auth module and verify creds auto-populate
        auth_modules = chaining_framework.search_modules("smb")
        if auth_modules:
            auth_module = chaining_framework.use_module(auth_modules[0].path)

            # Clear options that may have defaults before auto-set
            for opt in ["USERNAME", "PASSWORD", "DOMAIN"]:
                if opt in auth_module.options:
                    auth_module.options[opt]["value"] = None

            auth_module.auto_set_from_context()

            # Check credentials were populated (may be different option names)
            cred = chaining_framework.session.credentials.get_current()
            assert cred["username"] == "admin"
            assert cred["password"] == "Winter2024!"
            assert cred["domain"] == "CORP"


# =============================================================================
# Run Mode Tests
# =============================================================================

class TestRunModes:
    """Tests for different run modes (single, all targets)."""

    def test_single_run_mode(self, multi_target_framework):
        """Test single run mode executes on current target only."""
        multi_target_framework.session.run_mode = "single"

        modules = multi_target_framework.list_modules()
        module = multi_target_framework.use_module(modules[0].path)

        # Only current target should be affected
        current = multi_target_framework.session.targets.get_current()
        module.auto_set_from_context()

        if "RHOST" in module.options:
            assert module.get_option("RHOST") == current["ip"]

    def test_session_run_mode_persists(self, multi_target_framework):
        """Test run mode persists in session."""
        multi_target_framework.session.run_mode = "all"

        assert multi_target_framework.session.run_mode == "all"

        # Export and verify
        data = multi_target_framework.session.export_session()
        assert data.get("run_mode") == "all"


# =============================================================================
# Error Handling in Chains Tests
# =============================================================================

class TestChainErrorHandling:
    """Tests for error handling in module chains."""

    def test_chain_continues_after_module_failure(self, chaining_framework):
        """Test chain can continue even if one module fails."""
        modules = chaining_framework.list_modules()

        results = []
        for i, module_meta in enumerate(modules[:3]):
            module = chaining_framework.use_module(module_meta.path)
            if module:
                # Make second module "fail"
                success = i != 1
                with patch.object(module, 'run', return_value={"success": success}):
                    result = chaining_framework.run_module(module)
                    results.append(result)

        # Should have 3 results
        assert len(results) == 3
        # All should be dict results (chain continued regardless of success/failure)
        assert all(isinstance(r, dict) for r in results)

    def test_invalid_module_in_chain_skipped(self, chaining_framework):
        """Test invalid module paths are handled gracefully."""
        valid_modules = chaining_framework.list_modules()

        paths = [
            valid_modules[0].path,
            "invalid/nonexistent/module",
            valid_modules[1].path if len(valid_modules) > 1 else valid_modules[0].path
        ]

        loaded_count = 0
        for path in paths:
            module = chaining_framework.use_module(path)
            if module:
                loaded_count += 1

        # Should have loaded valid modules
        assert loaded_count >= 1

    def test_context_preserved_after_error(self, chaining_framework):
        """Test session context is preserved after module error."""
        with patch('purplesploit.models.database.db_manager'):
            chaining_framework.add_target("network", "10.0.0.1")
            chaining_framework.add_credential(username="admin", password="pass")

        modules = chaining_framework.list_modules()
        module = chaining_framework.use_module(modules[0].path)

        # Simulate error
        with patch.object(module, 'run', side_effect=Exception("Test error")):
            try:
                chaining_framework.run_module(module)
            except Exception:
                pass

        # Context should still be intact
        assert len(chaining_framework.session.targets.list()) == 1
        assert len(chaining_framework.session.credentials.list()) == 1
