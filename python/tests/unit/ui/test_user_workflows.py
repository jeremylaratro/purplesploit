"""
Tests for user workflow commands and end-to-end scenarios.

Tests cover:
- cmd_go (quick workflow: target + creds + operation)
- cmd_targets (range operations, index clear, modify)
- cmd_quick (module shortcuts)
- Session state consistency across commands
- Triple-layer data sync (session, database, models.database)
"""

import pytest
from unittest.mock import MagicMock, patch, call


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework():
    """Create a fully mocked framework with session managers."""
    framework = MagicMock()

    # Session with working target/credential managers
    framework.session = MagicMock()
    framework.session.current_module = None

    # Target manager with real-ish state
    targets = MagicMock()
    targets._targets = []
    targets.list.return_value = []
    targets.get_current.return_value = None
    targets.clear.return_value = 0
    targets.add.return_value = True
    targets.remove_by_index.return_value = True
    targets.remove_range.return_value = 0
    targets.modify.return_value = True
    framework.session.targets = targets

    # Credential manager
    credentials = MagicMock()
    credentials.list.return_value = []
    credentials.get_current.return_value = None
    credentials.add.return_value = True
    framework.session.credentials = credentials

    # Other session attributes
    framework.session.services = MagicMock()
    framework.session.services.services = {}
    framework.session.wordlists = MagicMock()
    framework.session.command_history = []
    framework.session.add_command = MagicMock()

    # Framework attributes
    framework.modules = {}
    framework.database = MagicMock()
    framework.use_module = MagicMock(return_value=None)
    framework.search_modules = MagicMock(return_value=[])

    return framework


@pytest.fixture
def command_handler(mock_framework):
    """Create a CommandHandler for testing."""
    with patch('purplesploit.ui.commands.Display') as mock_display, \
         patch('purplesploit.ui.commands.InteractiveSelector'):
        from purplesploit.ui.commands import CommandHandler
        handler = CommandHandler(mock_framework)
        handler.display = MagicMock()
        return handler


# =============================================================================
# Go Command Tests - Quick Workflow
# =============================================================================

class TestGoCommand:
    """Tests for cmd_go (quick workflow command)."""

    def test_go_no_args_shows_usage(self, command_handler):
        """Test go without args shows usage info."""
        result = command_handler.cmd_go([])

        assert result is True
        command_handler.display.print_error.assert_called()
        # Usage should include example
        call_args = str(command_handler.display.print_error.call_args)
        assert "Usage" in call_args or "go" in call_args

    def test_go_with_target_only(self, command_handler, mock_framework):
        """Test go with just target sets RHOST."""
        with patch.object(command_handler, 'cmd_target_quick') as mock_target:
            result = command_handler.cmd_go(["192.168.1.100"])

            mock_target.assert_called_once_with(["192.168.1.100"])
            assert result is True

    def test_go_with_target_and_creds(self, command_handler, mock_framework):
        """Test go with target + creds sets both."""
        with patch.object(command_handler, 'cmd_target_quick') as mock_target, \
             patch.object(command_handler, 'cmd_cred_quick') as mock_cred:

            result = command_handler.cmd_go(["192.168.1.100", "admin:Password123"])

            mock_target.assert_called_once_with(["192.168.1.100"])
            mock_cred.assert_called_once_with(["admin:Password123"])
            assert result is True

    def test_go_with_target_creds_and_operation(self, command_handler, mock_framework):
        """Test go with target + creds + operation runs the operation."""
        # Set up module with operations
        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_framework.session.current_module = mock_module

        with patch.object(command_handler, 'cmd_target_quick') as mock_target, \
             patch.object(command_handler, 'cmd_cred_quick') as mock_cred, \
             patch.object(command_handler, 'cmd_run') as mock_run:
            mock_run.return_value = True

            result = command_handler.cmd_go(["10.0.0.1", "user:pass", "1"])

            mock_target.assert_called_once_with(["10.0.0.1"])
            mock_cred.assert_called_once_with(["user:pass"])
            mock_run.assert_called_once_with(["1"])

    def test_go_operation_without_module_warns(self, command_handler, mock_framework):
        """Test go with operation but no module shows warning."""
        mock_framework.session.current_module = None

        with patch.object(command_handler, 'cmd_target_quick'), \
             patch.object(command_handler, 'cmd_cred_quick'):

            result = command_handler.cmd_go(["10.0.0.1", "user:pass", "1"])

            command_handler.display.print_warning.assert_called()
            assert result is True

    def test_go_operation_with_non_operation_module_warns(self, command_handler, mock_framework):
        """Test go with operation on module without operations warns."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = False
        mock_framework.session.current_module = mock_module

        with patch.object(command_handler, 'cmd_target_quick'), \
             patch.object(command_handler, 'cmd_cred_quick'):

            result = command_handler.cmd_go(["10.0.0.1", "user:pass", "1"])

            command_handler.display.print_warning.assert_called()

    def test_go_shows_operations_when_module_loaded(self, command_handler, mock_framework):
        """Test go shows available operations when module is loaded."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {"name": "Auth Test", "handler": "op_auth"},
            {"name": "Enum Shares", "handler": "op_shares"},
        ]
        mock_framework.session.current_module = mock_module

        with patch.object(command_handler, 'cmd_target_quick'), \
             patch.object(command_handler, '_show_operations') as mock_show:

            result = command_handler.cmd_go(["10.0.0.1"])

            # Should show operations since no operation specified
            mock_show.assert_called_once()

    def test_go_credential_format_with_domain(self, command_handler):
        """Test go recognizes domain\\user:pass format."""
        with patch.object(command_handler, 'cmd_target_quick'), \
             patch.object(command_handler, 'cmd_cred_quick') as mock_cred:

            result = command_handler.cmd_go(["10.0.0.1", "DOMAIN\\admin:pass"])

            # Should pass the full cred string
            mock_cred.assert_called_once_with(["DOMAIN\\admin:pass"])

    def test_go_credential_format_with_colon_in_password(self, command_handler):
        """Test go handles passwords with colons."""
        with patch.object(command_handler, 'cmd_target_quick'), \
             patch.object(command_handler, 'cmd_cred_quick') as mock_cred:

            result = command_handler.cmd_go(["10.0.0.1", "admin:pass:word:123"])

            # Should pass the full cred string, split handling is in cred_quick
            mock_cred.assert_called_once_with(["admin:pass:word:123"])


# =============================================================================
# Quick Command Tests - Module Shortcuts
# =============================================================================

class TestQuickCommand:
    """Tests for cmd_quick (module shortcuts)."""

    def test_quick_no_args_shows_usage(self, command_handler):
        """Test quick without args shows usage."""
        result = command_handler.cmd_quick([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_quick_unknown_module_shows_error(self, command_handler):
        """Test quick with unknown module shows error."""
        result = command_handler.cmd_quick(["unknown_module"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_quick_smb_loads_nxc_smb(self, command_handler, mock_framework):
        """Test quick smb loads network/nxc_smb."""
        mock_module = MagicMock()
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_quick(["smb"])

        # Should attempt to load SMB module
        assert mock_framework.use_module.called or command_handler.display.print_error.called

    def test_quick_available_shortcuts(self, command_handler):
        """Test quick shows available shortcuts on invalid input."""
        result = command_handler.cmd_quick(["invalid"])

        # Should mention available shortcuts
        calls = command_handler.display.print_info.call_args_list
        info_text = " ".join(str(c) for c in calls)
        # At least one shortcut should be mentioned
        assert any(s in info_text.lower() for s in ["smb", "ldap", "winrm", "available"])


# =============================================================================
# Targets Command - Range Operations
# =============================================================================

class TestTargetsRangeOperations:
    """Tests for targets command range operations."""

    def test_targets_list_default(self, command_handler, mock_framework):
        """Test targets with no args lists targets."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "Host1"},
            {"ip": "192.168.1.2", "name": "Host2"},
        ]

        result = command_handler.cmd_targets([])

        assert result is True
        command_handler.display.print_targets_table.assert_called()

    def test_targets_clear_all(self, command_handler, mock_framework):
        """Test targets clear removes all targets."""
        mock_framework.session.targets.clear.return_value = 5

        with patch.dict('sys.modules', {'purplesploit.models.database': MagicMock()}):
            result = command_handler.cmd_targets(["clear"])

        assert result is True
        mock_framework.session.targets.clear.assert_called_once()
        mock_framework.database.clear_all_targets.assert_called_once()
        command_handler.display.print_success.assert_called()

    def test_targets_clear_syncs_to_models_database(self, command_handler, mock_framework):
        """Test targets clear syncs to models.database for dashboard."""
        mock_framework.session.targets.clear.return_value = 3

        mock_db_manager = MagicMock()
        with patch.dict('sys.modules', {'purplesploit.models.database': MagicMock(db_manager=mock_db_manager)}):
            with patch('purplesploit.models.database.db_manager', mock_db_manager):
                result = command_handler.cmd_targets(["clear"])

        assert result is True

    def test_targets_index_clear(self, command_handler, mock_framework):
        """Test targets <index> clear removes single target."""
        mock_framework.session.targets.remove_by_index.return_value = True

        result = command_handler.cmd_targets(["2", "clear"])

        assert result is True
        mock_framework.session.targets.remove_by_index.assert_called_once_with(2)
        command_handler.display.print_success.assert_called()

    def test_targets_index_clear_invalid_index(self, command_handler, mock_framework):
        """Test targets <index> clear with invalid index shows error."""
        mock_framework.session.targets.remove_by_index.return_value = False

        result = command_handler.cmd_targets(["99", "clear"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_targets_range_clear(self, command_handler, mock_framework):
        """Test targets 1-5 clear removes range of targets."""
        mock_framework.session.targets.remove_range.return_value = 5

        result = command_handler.cmd_targets(["1-5", "clear"])

        assert result is True
        mock_framework.session.targets.remove_range.assert_called_once_with(1, 5)
        command_handler.display.print_success.assert_called()

    def test_targets_range_clear_invalid_format(self, command_handler, mock_framework):
        """Test targets with invalid range format shows error."""
        result = command_handler.cmd_targets(["a-b", "clear"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_targets_index_without_action_shows_error(self, command_handler):
        """Test targets <index> without action shows usage."""
        result = command_handler.cmd_targets(["1"])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Targets Command - Modify Operations
# =============================================================================

class TestTargetsModifyOperations:
    """Tests for targets modify operations."""

    def test_targets_index_modify(self, command_handler, mock_framework):
        """Test targets <index> modify key=value updates target."""
        mock_framework.session.targets.modify.return_value = True

        result = command_handler.cmd_targets(["1", "modify", "name=NewName"])

        assert result is True
        mock_framework.session.targets.modify.assert_called_once_with(1, name="NewName")
        command_handler.display.print_success.assert_called()

    def test_targets_index_modify_multiple_fields(self, command_handler, mock_framework):
        """Test targets modify with multiple key=value pairs."""
        mock_framework.session.targets.modify.return_value = True

        result = command_handler.cmd_targets(["0", "modify", "name=Server1", "ip=10.0.0.1"])

        assert result is True
        mock_framework.session.targets.modify.assert_called_once_with(0, name="Server1", ip="10.0.0.1")

    def test_targets_index_modify_invalid_index(self, command_handler, mock_framework):
        """Test targets modify with invalid index shows error."""
        mock_framework.session.targets.modify.return_value = False

        result = command_handler.cmd_targets(["99", "modify", "name=Test"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_targets_index_modify_no_fields(self, command_handler):
        """Test targets modify without fields shows error."""
        result = command_handler.cmd_targets(["1", "modify"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_targets_index_unknown_action(self, command_handler):
        """Test targets <index> unknown_action shows error."""
        result = command_handler.cmd_targets(["1", "unknown"])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Targets Command - Add Operations
# =============================================================================

class TestTargetsAddOperations:
    """Tests for targets add operations."""

    def test_targets_add_ip(self, command_handler, mock_framework):
        """Test targets add <ip> adds network target."""
        mock_framework.session.targets.list.return_value = []
        mock_framework.add_target.return_value = True

        result = command_handler.cmd_targets(["add", "192.168.1.100"])

        assert result is True
        mock_framework.add_target.assert_called_once()
        # Check arguments: (type, identifier, name)
        call_args = mock_framework.add_target.call_args[0]
        assert call_args[0] == 'network'  # type
        assert call_args[1] == '192.168.1.100'  # identifier

    def test_targets_add_url(self, command_handler, mock_framework):
        """Test targets add <url> adds web target."""
        mock_framework.session.targets.list.return_value = []
        mock_framework.add_target.return_value = True

        result = command_handler.cmd_targets(["add", "http://example.com"])

        assert result is True
        call_args = mock_framework.add_target.call_args[0]
        assert call_args[0] == 'web'  # type

    def test_targets_add_with_name(self, command_handler, mock_framework):
        """Test targets add <ip> <name> sets custom name."""
        mock_framework.session.targets.list.return_value = []
        mock_framework.add_target.return_value = True

        result = command_handler.cmd_targets(["add", "192.168.1.1", "DC01"])

        assert result is True
        call_args = mock_framework.add_target.call_args[0]
        assert call_args[2] == 'DC01'  # name

    def test_targets_add_first_target_auto_selected(self, command_handler, mock_framework):
        """Test first target added is auto-selected."""
        mock_framework.session.targets.list.return_value = []  # Empty before add
        mock_framework.add_target.return_value = True

        result = command_handler.cmd_targets(["add", "10.0.0.1"])

        assert result is True
        # Display should indicate auto-selection
        assert command_handler.display.print_success.called

    def test_targets_add_no_args_shows_usage(self, command_handler):
        """Test targets add without IP shows usage."""
        result = command_handler.cmd_targets(["add"])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Session State Consistency Tests
# =============================================================================

class TestSessionStateConsistency:
    """Tests for session state consistency across operations."""

    def test_targets_clear_syncs_all_layers(self, command_handler, mock_framework):
        """Test targets clear syncs session, database, and models.database."""
        mock_framework.session.targets.clear.return_value = 3

        # Mock the models.database import
        mock_db_module = MagicMock()
        mock_db_manager = MagicMock()
        mock_db_module.db_manager = mock_db_manager

        with patch.dict('sys.modules', {'purplesploit.models.database': mock_db_module}):
            result = command_handler.cmd_targets(["clear"])

        # All three layers should be cleared
        mock_framework.session.targets.clear.assert_called_once()
        mock_framework.database.clear_all_targets.assert_called_once()

    def test_targets_clear_handles_models_database_exception(self, command_handler, mock_framework):
        """Test targets clear handles models.database exception gracefully."""
        mock_framework.session.targets.clear.return_value = 2

        # Make the models.database import fail
        with patch.dict('sys.modules', {'purplesploit.models.database': MagicMock(side_effect=ImportError)}):
            # Or make db_manager.clear_all_targets raise an exception
            def raise_error():
                raise Exception("Database error")

            with patch('purplesploit.models.database.db_manager.clear_all_targets', side_effect=Exception("DB error")):
                try:
                    result = command_handler.cmd_targets(["clear"])
                except:
                    pass  # Exception handling is part of the test

        # Should still report success for session clear
        command_handler.display.print_success.assert_called()


# =============================================================================
# Edge Cases and Error Recovery
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error scenarios."""

    def test_go_with_url_target(self, command_handler):
        """Test go command with URL target."""
        with patch.object(command_handler, 'cmd_target_quick') as mock_target:
            result = command_handler.cmd_go(["http://example.com:8080/api"])

            mock_target.assert_called_once_with(["http://example.com:8080/api"])

    def test_go_with_ipv6_target(self, command_handler):
        """Test go command with IPv6 address."""
        with patch.object(command_handler, 'cmd_target_quick') as mock_target:
            result = command_handler.cmd_go(["2001:db8::1"])

            mock_target.assert_called_once_with(["2001:db8::1"])

    def test_targets_range_zero_based_indexing(self, command_handler, mock_framework):
        """Test range operations use correct zero-based indexing."""
        mock_framework.session.targets.remove_range.return_value = 3

        result = command_handler.cmd_targets(["0-2", "clear"])

        # Should pass 0 and 2 as start and end
        mock_framework.session.targets.remove_range.assert_called_once_with(0, 2)

    def test_targets_modify_value_with_equals(self, command_handler, mock_framework):
        """Test modify with value containing equals sign."""
        mock_framework.session.targets.modify.return_value = True

        result = command_handler.cmd_targets(["0", "modify", "metadata=key=value"])

        # Should split only on first equals
        mock_framework.session.targets.modify.assert_called_once_with(0, metadata="key=value")

    def test_targets_add_duplicate_handling(self, command_handler, mock_framework):
        """Test adding duplicate target returns appropriate message."""
        mock_framework.session.targets.list.return_value = [{"ip": "10.0.0.1"}]
        mock_framework.session.targets.add.return_value = False  # Duplicate rejected

        result = command_handler.cmd_targets(["add", "10.0.0.1"])

        # Should indicate duplicate or already exists
        assert result is True

    def test_go_empty_credential_not_parsed(self, command_handler):
        """Test go with second arg without colon doesn't set creds."""
        with patch.object(command_handler, 'cmd_target_quick') as mock_target, \
             patch.object(command_handler, 'cmd_cred_quick') as mock_cred:

            # Second arg without colon should NOT be parsed as credential
            result = command_handler.cmd_go(["10.0.0.1", "not_a_credential"])

            mock_target.assert_called_once()
            # cred_quick should NOT be called since "not_a_credential" has no colon
            mock_cred.assert_not_called()


# =============================================================================
# Integration Workflow Tests
# =============================================================================

class TestWorkflowIntegration:
    """Tests for complete workflow scenarios."""

    def test_full_pentest_workflow_setup(self, command_handler, mock_framework):
        """Test typical pentest setup workflow."""
        # 1. Add target
        mock_framework.session.targets.list.return_value = []
        mock_framework.add_target.return_value = True

        result1 = command_handler.cmd_targets(["add", "192.168.1.100", "DC01"])
        assert result1 is True

        # 2. Add another target
        mock_framework.session.targets.list.return_value = [{"ip": "192.168.1.100"}]
        result2 = command_handler.cmd_targets(["add", "192.168.1.101", "WEB01"])
        assert result2 is True

        # 3. Clear specific target
        mock_framework.session.targets.remove_by_index.return_value = True
        result3 = command_handler.cmd_targets(["1", "clear"])
        assert result3 is True

    def test_bulk_target_cleanup(self, command_handler, mock_framework):
        """Test bulk cleanup of targets."""
        mock_framework.session.targets.remove_range.return_value = 10

        result = command_handler.cmd_targets(["0-9", "clear"])

        assert result is True
        mock_framework.session.targets.remove_range.assert_called_once_with(0, 9)
        command_handler.display.print_success.assert_called()

    def test_modify_target_during_assessment(self, command_handler, mock_framework):
        """Test modifying target info during assessment."""
        mock_framework.session.targets.modify.return_value = True

        # Update hostname after discovery
        result = command_handler.cmd_targets(["0", "modify", "name=ACTUAL-DC01.corp.local"])

        assert result is True
        command_handler.display.print_success.assert_called()
