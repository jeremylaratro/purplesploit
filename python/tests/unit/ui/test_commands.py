"""
Unit tests for purplesploit.ui.commands module.

Tests cover:
- CommandHandler initialization
- Command execution flow
- Core commands (help, search, use, back, info, options, show, set, run)
- Target and credential management commands
- Error handling
"""

import pytest
from unittest.mock import MagicMock, patch
from purplesploit.ui.commands import CommandHandler


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework():
    """Create a mock framework for command handler testing."""
    framework = MagicMock()
    framework.session = MagicMock()
    framework.session.current_module = None
    framework.session.targets = MagicMock()
    framework.session.targets.list.return_value = []
    framework.session.targets.get_current.return_value = None
    framework.session.credentials = MagicMock()
    framework.session.credentials.list.return_value = []
    framework.session.credentials.get_current.return_value = None
    framework.session.services = MagicMock()
    framework.session.services.services = {}
    framework.session.wordlists = MagicMock()
    framework.session.command_history = []
    framework.session.add_command = MagicMock()
    framework.modules = {}
    framework.database = MagicMock()
    return framework


@pytest.fixture
def command_handler(mock_framework):
    """Create a CommandHandler instance for testing."""
    with patch('purplesploit.ui.commands.Display') as mock_display, \
         patch('purplesploit.ui.commands.InteractiveSelector') as mock_interactive:
        handler = CommandHandler(mock_framework)
        # Make display methods accessible for assertions
        handler.display = MagicMock()
    return handler


# =============================================================================
# Initialization Tests
# =============================================================================

class TestCommandHandlerInit:
    """Tests for CommandHandler initialization."""

    def test_registers_commands(self, command_handler):
        """Test command handler registers all commands."""
        assert "help" in command_handler.commands
        assert "search" in command_handler.commands
        assert "use" in command_handler.commands
        assert "back" in command_handler.commands
        assert "info" in command_handler.commands
        assert "options" in command_handler.commands
        assert "set" in command_handler.commands
        assert "run" in command_handler.commands
        assert "exit" in command_handler.commands

    def test_has_service_shortcuts(self, command_handler):
        """Test service shortcuts are registered."""
        assert "smb" in command_handler.service_shortcuts
        assert "nmap" in command_handler.service_shortcuts
        assert "wfuzz" in command_handler.service_shortcuts

    def test_initializes_search_results(self, command_handler):
        """Test last search results is initialized."""
        assert command_handler.last_search_results == []


# =============================================================================
# Execute Tests
# =============================================================================

class TestCommandExecution:
    """Tests for command execution."""

    def test_execute_empty_command(self, command_handler):
        """Test executing empty command returns True."""
        result = command_handler.execute("")
        assert result is True

    def test_execute_whitespace_command(self, command_handler):
        """Test executing whitespace-only command returns True."""
        result = command_handler.execute("   ")
        assert result is True

    def test_execute_adds_to_history(self, command_handler, mock_framework):
        """Test executing command adds to history."""
        command_handler.execute("help")
        mock_framework.session.add_command.assert_called_once_with("help")

    def test_execute_unknown_command(self, command_handler):
        """Test executing unknown command shows error."""
        result = command_handler.execute("unknown_command_xyz")
        assert result is True
        command_handler.display.print_error.assert_called()

    def test_execute_exit_returns_false(self, command_handler):
        """Test exit command returns False."""
        result = command_handler.execute("exit")
        assert result is False

    def test_execute_quit_returns_false(self, command_handler):
        """Test quit command returns False."""
        result = command_handler.execute("quit")
        assert result is False


# =============================================================================
# Help Command Tests
# =============================================================================

class TestHelpCommand:
    """Tests for help command."""

    def test_help_command(self, command_handler):
        """Test help command runs successfully."""
        result = command_handler.cmd_help([])
        assert result is True


# =============================================================================
# Search Command Tests
# =============================================================================

class TestSearchCommand:
    """Tests for search command."""

    def test_search_no_args(self, command_handler):
        """Test search without arguments shows error."""
        result = command_handler.cmd_search([])
        assert result is True
        command_handler.display.print_error.assert_called()

    def test_search_with_query(self, command_handler, mock_framework):
        """Test search with query calls framework search."""
        mock_framework.search_modules.return_value = []

        result = command_handler.cmd_search(["nmap"])

        assert result is True
        mock_framework.search_modules.assert_called_once_with("nmap")

    def test_search_stores_results(self, command_handler, mock_framework):
        """Test search stores results for number selection."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        mock_framework.search_modules.return_value = [mock_module, mock_module]

        command_handler.cmd_search(["test"])

        assert command_handler.last_search_results == [mock_module, mock_module]

    def test_search_auto_loads_single_result(self, command_handler, mock_framework):
        """Test search auto-loads when only one result."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        mock_framework.search_modules.return_value = [mock_module]
        mock_framework.use_module.return_value = MagicMock()

        result = command_handler.cmd_search(["nmap"])

        # Should attempt to load the module
        mock_framework.use_module.assert_called_once_with("recon/nmap")


# =============================================================================
# Use Command Tests
# =============================================================================

class TestUseCommand:
    """Tests for use command."""

    def test_use_no_args(self, command_handler):
        """Test use without arguments shows error."""
        result = command_handler.cmd_use([])
        assert result is True
        command_handler.display.print_error.assert_called()

    def test_use_with_path(self, command_handler, mock_framework):
        """Test use with module path."""
        mock_module = MagicMock()
        mock_module.name = "Test Module"
        mock_module.has_operations.return_value = False
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_use(["recon/nmap"])

        assert result is True
        mock_framework.use_module.assert_called_once_with("recon/nmap")
        command_handler.display.print_success.assert_called()

    def test_use_with_number(self, command_handler, mock_framework):
        """Test use with number from search results."""
        mock_metadata = MagicMock()
        mock_metadata.path = "recon/nmap"
        command_handler.last_search_results = [mock_metadata]

        mock_module = MagicMock()
        mock_module.name = "Nmap"
        mock_module.has_operations.return_value = False
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_use(["1"])

        assert result is True
        mock_framework.use_module.assert_called_once_with("recon/nmap")

    def test_use_invalid_number(self, command_handler):
        """Test use with invalid number shows error."""
        command_handler.last_search_results = [MagicMock()]

        result = command_handler.cmd_use(["99"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_use_service_shortcut(self, command_handler, mock_framework):
        """Test use with service shortcut."""
        mock_module = MagicMock()
        mock_module.name = "NXC SMB"
        mock_module.has_operations.return_value = False
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_use(["smb"])

        assert result is True
        mock_framework.use_module.assert_called_once_with("network/nxc_smb")

    def test_use_module_not_found(self, command_handler, mock_framework):
        """Test use when module not found."""
        mock_framework.use_module.return_value = None

        result = command_handler.cmd_use(["nonexistent/module"])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Back Command Tests
# =============================================================================

class TestBackCommand:
    """Tests for back command."""

    def test_back_no_module(self, command_handler, mock_framework):
        """Test back when no module loaded."""
        mock_framework.session.current_module = None

        result = command_handler.cmd_back([])

        assert result is True
        command_handler.display.print_warning.assert_called()

    def test_back_with_module(self, command_handler, mock_framework):
        """Test back unloads module."""
        mock_module = MagicMock()
        mock_module.name = "Test Module"
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_back([])

        assert result is True
        mock_framework.session.unload_module.assert_called_once()
        command_handler.display.print_success.assert_called()


# =============================================================================
# Info Command Tests
# =============================================================================

class TestInfoCommand:
    """Tests for info command."""

    def test_info_no_module(self, command_handler, mock_framework):
        """Test info when no module loaded."""
        mock_framework.session.current_module = None

        result = command_handler.cmd_info([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_info_with_module(self, command_handler, mock_framework):
        """Test info with module loaded."""
        mock_module = MagicMock()
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_info([])

        assert result is True
        command_handler.display.print_module_info.assert_called_once_with(mock_module)


# =============================================================================
# Options Command Tests
# =============================================================================

class TestOptionsCommand:
    """Tests for options command."""

    def test_options_no_module(self, command_handler, mock_framework):
        """Test options when no module loaded."""
        mock_framework.session.current_module = None

        result = command_handler.cmd_options([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_options_with_module(self, command_handler, mock_framework):
        """Test options with module loaded."""
        mock_module = MagicMock()
        mock_module.show_options.return_value = {"RHOST": {"value": None}}
        mock_module.get_default_command.return_value = None
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_options([])

        assert result is True
        command_handler.display.print_options_table.assert_called()


# =============================================================================
# Set Command Tests
# =============================================================================

class TestSetCommand:
    """Tests for set command."""

    def test_set_no_module(self, command_handler, mock_framework):
        """Test set when no module loaded."""
        mock_framework.session.current_module = None

        result = command_handler.cmd_set(["RHOST", "192.168.1.1"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_set_no_args(self, command_handler, mock_framework):
        """Test set without arguments shows error."""
        mock_framework.session.current_module = MagicMock()

        result = command_handler.cmd_set([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_set_option(self, command_handler, mock_framework):
        """Test setting an option."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_set(["RHOST", "192.168.1.1"])

        assert result is True
        mock_module.set_option.assert_called_once_with("RHOST", "192.168.1.1")
        command_handler.display.print_success.assert_called()

    def test_set_option_with_spaces(self, command_handler, mock_framework):
        """Test setting option with value containing spaces."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_set(["SCRIPT", "vuln", "and", "safe"])

        assert result is True
        mock_module.set_option.assert_called_once_with("SCRIPT", "vuln and safe")


# =============================================================================
# Show Command Tests
# =============================================================================

class TestShowCommand:
    """Tests for show command."""

    def test_show_no_args(self, command_handler):
        """Test show without arguments shows error."""
        result = command_handler.cmd_show([])
        assert result is True
        command_handler.display.print_error.assert_called()

    def test_show_modules(self, command_handler, mock_framework):
        """Test show modules."""
        mock_framework.list_modules.return_value = []

        result = command_handler.cmd_show(["modules"])

        assert result is True
        mock_framework.list_modules.assert_called_once()

    def test_show_targets(self, command_handler, mock_framework):
        """Test show targets."""
        mock_framework.session.targets.list.return_value = []

        result = command_handler.cmd_show(["targets"])

        assert result is True
        command_handler.display.print_targets_table.assert_called()

    def test_show_creds(self, command_handler, mock_framework):
        """Test show credentials."""
        mock_framework.session.credentials.list.return_value = []

        result = command_handler.cmd_show(["creds"])

        assert result is True
        command_handler.display.print_credentials_table.assert_called()

    def test_show_invalid(self, command_handler):
        """Test show with invalid option."""
        result = command_handler.cmd_show(["invalid"])
        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Run Command Tests
# =============================================================================

class TestRunCommand:
    """Tests for run command."""

    def test_run_no_module(self, command_handler, mock_framework):
        """Test run when no module loaded."""
        mock_framework.session.current_module = None

        result = command_handler.cmd_run([])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Target Command Tests
# =============================================================================

class TestTargetCommands:
    """Tests for target-related commands."""

    def test_targets_list(self, command_handler, mock_framework):
        """Test targets list command."""
        mock_framework.session.targets.list.return_value = []

        result = command_handler.cmd_targets(["list"])

        assert result is True
        mock_framework.session.targets.list.assert_called()

    def test_targets_add(self, command_handler, mock_framework):
        """Test targets add command."""
        with patch.object(command_handler, 'interactive') as mock_interactive:
            mock_interactive.get_input.side_effect = ["192.168.1.1", "test-server"]
            mock_framework.add_target.return_value = True

            result = command_handler.cmd_targets(["add"])

            assert result is True

    def test_target_quick(self, command_handler, mock_framework):
        """Test quick target command."""
        mock_framework.add_target.return_value = True

        result = command_handler.cmd_target_quick(["192.168.1.100"])

        assert result is True
        mock_framework.add_target.assert_called()

    def test_target_quick_no_ip(self, command_handler):
        """Test quick target without IP shows usage info."""
        result = command_handler.cmd_target_quick([])
        assert result is True
        # Shows usage info when no args
        command_handler.display.print_info.assert_called()


# =============================================================================
# Credential Command Tests
# =============================================================================

class TestCredentialCommands:
    """Tests for credential-related commands."""

    def test_creds_list(self, command_handler, mock_framework):
        """Test creds list command."""
        mock_framework.session.credentials.list.return_value = []

        result = command_handler.cmd_creds(["list"])

        assert result is True
        mock_framework.session.credentials.list.assert_called()

    def test_cred_quick(self, command_handler, mock_framework):
        """Test quick credential command."""
        mock_framework.add_credential.return_value = True

        result = command_handler.cmd_cred_quick(["admin:password123"])

        assert result is True
        mock_framework.add_credential.assert_called()

    def test_cred_quick_no_args(self, command_handler):
        """Test quick credential without args shows usage info."""
        result = command_handler.cmd_cred_quick([])
        assert result is True
        # Shows usage info when no args
        command_handler.display.print_info.assert_called()


# =============================================================================
# Utility Command Tests
# =============================================================================

class TestUtilityCommands:
    """Tests for utility commands."""

    def test_clear_command(self, command_handler):
        """Test clear command."""
        result = command_handler.cmd_clear([])
        assert result is True

    def test_history_command(self, command_handler, mock_framework):
        """Test history command."""
        # Command history entries are dicts with 'command' key
        mock_framework.session.command_history = [
            {"command": "help", "timestamp": "2025-01-01"},
            {"command": "search nmap", "timestamp": "2025-01-01"}
        ]

        result = command_handler.cmd_history([])

        assert result is True

    def test_stats_command(self, command_handler, mock_framework):
        """Test stats command."""
        mock_framework.get_stats.return_value = {
            "modules": 10,
            "categories": 3,
            "targets": 5,
            "credentials": 2,
            "current_module": None,
            "session_age": 3600
        }

        result = command_handler.cmd_stats([])

        assert result is True

    def test_exit_command(self, command_handler):
        """Test exit command returns False."""
        result = command_handler.cmd_exit([])
        assert result is False


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_execute_with_quoted_args(self, command_handler, mock_framework):
        """Test executing command with quoted arguments."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        result = command_handler.execute('set SCRIPT "vuln and safe"')

        assert result is True
        # Should handle quoted argument properly
        mock_module.set_option.assert_called()

    def test_execute_handles_shlex_error(self, command_handler):
        """Test execute handles malformed quotes gracefully."""
        result = command_handler.execute('set SCRIPT "unclosed quote')

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_command_case_insensitive(self, command_handler, mock_framework):
        """Test commands are case insensitive."""
        mock_framework.session.current_module = None

        result1 = command_handler.execute("HELP")
        result2 = command_handler.execute("Help")
        result3 = command_handler.execute("help")

        assert result1 is True
        assert result2 is True
        assert result3 is True
