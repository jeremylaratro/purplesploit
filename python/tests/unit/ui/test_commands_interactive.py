"""
Unit tests for interactive features in purplesploit.ui.commands.

Tests cover:
- Module selection and quick commands
- Auto-population from context
- Operation selection and go command
- Argument parsing edge cases
- Interactive selector integration
"""

import pytest
from unittest.mock import MagicMock, patch, call
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
    framework.session.workspace = "default"
    framework.modules = {}
    framework.database = MagicMock()
    return framework


@pytest.fixture
def command_handler(mock_framework):
    """Create a CommandHandler instance for testing."""
    with patch('purplesploit.ui.commands.Display') as mock_display, \
         patch('purplesploit.ui.commands.InteractiveSelector') as mock_interactive:
        handler = CommandHandler(mock_framework)
        handler.display = MagicMock()
        handler.interactive = MagicMock()
    return handler


# =============================================================================
# Module Selection Tests
# =============================================================================

class TestModuleSelection:
    """Tests for module selection commands."""

    def test_module_select_with_modules(self, command_handler, mock_framework):
        """Test module select with available modules."""
        mock_metadata1 = MagicMock()
        mock_metadata1.path = "recon/nmap"
        mock_metadata1.name = "Nmap Scanner"
        mock_metadata2 = MagicMock()
        mock_metadata2.path = "network/nxc_smb"
        mock_metadata2.name = "SMB"

        mock_framework.list_modules.return_value = [mock_metadata1, mock_metadata2]
        # Implementation uses select_module, not select_from_list
        command_handler.interactive.select_module.return_value = mock_metadata1

        mock_module = MagicMock()
        mock_module.name = "Nmap Scanner"
        mock_module.has_operations.return_value = False
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_module(["select"])

        assert result is True
        command_handler.interactive.select_module.assert_called_once()
        mock_framework.use_module.assert_called_once_with("recon/nmap")

    def test_module_select_cancelled(self, command_handler, mock_framework):
        """Test module select when user cancels."""
        mock_metadata = MagicMock()
        mock_framework.list_modules.return_value = [mock_metadata]
        command_handler.interactive.select_module.return_value = None

        result = command_handler.cmd_module(["select"])

        assert result is True
        mock_framework.use_module.assert_not_called()

    def test_module_list(self, command_handler, mock_framework):
        """Test module list command - falls back to select behavior."""
        mock_framework.list_modules.return_value = []

        # 'list' is not a valid subcommand - shows error
        result = command_handler.cmd_module(["list"])

        assert result is True
        # Implementation doesn't have 'list' subcommand - prints usage error
        command_handler.display.print_error.assert_called()

    def test_module_categories(self, command_handler, mock_framework):
        """Test module categories command."""
        mock_framework.modules = {
            "recon/nmap": MagicMock(),
            "network/nxc_smb": MagicMock(),
            "web/feroxbuster": MagicMock()
        }

        result = command_handler.cmd_module(["categories"])

        assert result is True


# =============================================================================
# Quick Command Tests
# =============================================================================

class TestQuickCommand:
    """Tests for quick module loading command."""

    def test_quick_no_args(self, command_handler):
        """Test quick without arguments shows usage."""
        result = command_handler.cmd_quick([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_quick_smb_basic(self, command_handler, mock_framework):
        """Test quick smb command."""
        mock_module = MagicMock()
        mock_module.name = "SMB"
        mock_module.has_operations.return_value = False
        mock_module.get_option.return_value = None
        mock_module.auto_set_from_context = MagicMock()
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_quick(["smb"])

        assert result is True
        mock_framework.use_module.assert_called_once_with("network/nxc_smb")
        mock_module.auto_set_from_context.assert_called_once()

    def test_quick_with_operation_filter(self, command_handler, mock_framework):
        """Test quick command with operation filter."""
        mock_module = MagicMock()
        mock_module.name = "SMB"
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {"name": "Authentication", "description": "Test auth"},
            {"name": "Shares Enum", "description": "List shares"}
        ]
        mock_module.get_option.return_value = None
        mock_module.auto_set_from_context = MagicMock()
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_quick(["smb", "auth"])

        assert result is True
        mock_module.get_operations.assert_called()

    def test_quick_unknown_module(self, command_handler, mock_framework):
        """Test quick with unknown module type."""
        result = command_handler.cmd_quick(["unknown"])

        assert result is True
        command_handler.display.print_error.assert_called()

    @pytest.mark.parametrize("module_type,expected_path", [
        ("smb", "network/nxc_smb"),
        ("ldap", "network/nxc_ldap"),
        ("winrm", "network/nxc_winrm"),
        ("ferox", "web/feroxbuster"),
        ("sqlmap", "web/sqlmap"),
    ])
    def test_quick_module_mapping(self, command_handler, mock_framework, module_type, expected_path):
        """Test quick command module type mapping."""
        mock_module = MagicMock()
        mock_module.name = "Module"
        mock_module.has_operations.return_value = False
        mock_module.get_option.return_value = None
        mock_module.auto_set_from_context = MagicMock()
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_quick([module_type])

        assert result is True
        mock_framework.use_module.assert_called_once_with(expected_path)


# =============================================================================
# Go Command Tests
# =============================================================================

class TestGoCommand:
    """Tests for the go super-quick command."""

    def test_go_no_args(self, command_handler, mock_framework):
        """Test go without arguments shows usage."""
        result = command_handler.cmd_go([])

        assert result is True
        command_handler.display.print_info.assert_called()

    def test_go_with_module(self, command_handler, mock_framework):
        """Test go command sets target and shows operations."""
        mock_module = MagicMock()
        mock_module.name = "SMB"
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {"name": "Auth", "description": "Test"}
        ]
        mock_framework.session.current_module = mock_module

        # go command takes a target, not a module
        result = command_handler.cmd_go(["192.168.1.1"])

        assert result is True
        # Should show operations since module is loaded
        mock_module.get_operations.assert_called()

    def test_go_no_target(self, command_handler, mock_framework):
        """Test go when no target in context."""
        mock_framework.session.current_module = None
        mock_framework.session.targets.get_current.return_value = None

        result = command_handler.cmd_go([])

        assert result is True


# =============================================================================
# Argument Parsing Tests
# =============================================================================

class TestArgumentParsing:
    """Tests for complex argument parsing scenarios."""

    def test_set_with_equals_in_value(self, command_handler, mock_framework):
        """Test set command with equals sign in value."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        result = command_handler.execute('set PAYLOAD "param=value"')

        assert result is True
        mock_module.set_option.assert_called()

    def test_command_with_special_chars(self, command_handler, mock_framework):
        """Test command with special characters in arguments."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        result = command_handler.execute('set URL "http://test.com?param=1&foo=bar"')

        assert result is True

    def test_command_with_escaped_quotes(self, command_handler, mock_framework):
        """Test command with escaped quotes."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        # This should handle escaped quotes properly
        result = command_handler.execute('set SCRIPT "test \\"nested\\" quotes"')

        assert result is True

    def test_empty_quoted_value(self, command_handler, mock_framework):
        """Test setting empty quoted value."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        result = command_handler.execute('set OPTION ""')

        assert result is True

    def test_multiple_spaces_in_value(self, command_handler, mock_framework):
        """Test value with multiple spaces."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_set(["SCRIPT", "vuln", "and", "safe", "scripts"])

        assert result is True
        mock_module.set_option.assert_called_once_with("SCRIPT", "vuln and safe scripts")


# =============================================================================
# Interactive Selector Tests
# =============================================================================

class TestInteractiveSelector:
    """Tests for interactive selector integration."""

    def test_target_add_interactive(self, command_handler, mock_framework):
        """Test target add with arguments (not interactive)."""
        mock_framework.add_target.return_value = True
        mock_framework.session.targets.list.return_value = []

        # targets add requires arguments: <ip|url> [name]
        result = command_handler.cmd_targets(["add", "192.168.1.50", "test-host"])

        assert result is True
        mock_framework.add_target.assert_called_once_with("network", "192.168.1.50", "test-host")

    def test_target_add_interactive_cancelled(self, command_handler, mock_framework):
        """Test interactive target add when cancelled."""
        command_handler.interactive.get_input.return_value = None

        result = command_handler.cmd_targets(["add"])

        assert result is True
        mock_framework.add_target.assert_not_called()

    def test_creds_add_interactive(self, command_handler, mock_framework):
        """Test credential add with arguments (not interactive)."""
        mock_framework.add_credential.return_value = True

        # creds add requires arguments: <username>:<password> [domain]
        result = command_handler.cmd_creds(["add", "testuser:testpass", "domain.local"])

        assert result is True
        mock_framework.add_credential.assert_called_once_with("testuser", "testpass", "domain.local")

    def test_creds_select_interactive(self, command_handler, mock_framework):
        """Test interactive credential selection."""
        mock_cred = {"id": "1", "username": "admin", "password": "pass"}
        mock_framework.session.credentials.list.return_value = [mock_cred]
        # Implementation uses select_credential, not select_from_list
        command_handler.interactive.select_credential.return_value = mock_cred

        result = command_handler.cmd_creds(["select"])

        assert result is True
        command_handler.interactive.select_credential.assert_called_once()

    def test_target_select_interactive(self, command_handler, mock_framework):
        """Test interactive target selection."""
        mock_target = {"id": "1", "ip": "192.168.1.1", "name": "host1"}
        mock_framework.session.targets.list.return_value = [mock_target]
        # Implementation uses select_target, not select_from_list
        command_handler.interactive.select_target.return_value = mock_target

        result = command_handler.cmd_targets(["select"])

        assert result is True
        command_handler.interactive.select_target.assert_called_once()


# =============================================================================
# Context Persistence Tests
# =============================================================================

class TestContextPersistence:
    """Tests for context state persistence."""

    def test_search_results_persistence(self, command_handler, mock_framework):
        """Test search results are stored for number selection."""
        mock_module1 = MagicMock()
        mock_module1.path = "recon/nmap"
        mock_module2 = MagicMock()
        mock_module2.path = "recon/dnsenum"

        mock_framework.search_modules.return_value = [mock_module1, mock_module2]

        command_handler.cmd_search(["recon"])

        assert len(command_handler.last_search_results) == 2
        assert command_handler.last_search_results[0].path == "recon/nmap"

    def test_use_number_after_search(self, command_handler, mock_framework):
        """Test using number to load module after search."""
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

    def test_search_clears_old_results(self, command_handler, mock_framework):
        """Test new search clears old results."""
        # First search
        mock_module1 = MagicMock()
        mock_module1.path = "recon/nmap"
        mock_framework.search_modules.return_value = [mock_module1]
        command_handler.cmd_search(["nmap"])

        assert len(command_handler.last_search_results) == 1

        # Second search
        mock_module2 = MagicMock()
        mock_module2.path = "web/feroxbuster"
        mock_framework.search_modules.return_value = [mock_module2]
        command_handler.cmd_search(["ferox"])

        assert len(command_handler.last_search_results) == 1
        assert command_handler.last_search_results[0].path == "web/feroxbuster"

    def test_operation_index_persistence(self, command_handler):
        """Test operation index is tracked."""
        command_handler.current_operation_index = 2

        assert command_handler.current_operation_index == 2

    def test_webserver_process_tracking(self, command_handler):
        """Test webserver process is tracked."""
        mock_process = MagicMock()
        command_handler.webserver_process = mock_process

        assert command_handler.webserver_process == mock_process


# =============================================================================
# Error Handling in Interactive Mode Tests
# =============================================================================

class TestInteractiveErrorHandling:
    """Tests for error handling in interactive operations."""

    def test_target_add_invalid_ip(self, command_handler, mock_framework):
        """Test adding target with invalid IP."""
        command_handler.interactive.get_input.side_effect = [
            "invalid_ip",
            "hostname"
        ]
        mock_framework.add_target.return_value = False

        result = command_handler.cmd_targets(["add"])

        assert result is True

    def test_use_number_without_search(self, command_handler):
        """Test using number when no search was performed."""
        command_handler.last_search_results = []

        result = command_handler.cmd_use(["1"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_use_number_out_of_range(self, command_handler, mock_framework):
        """Test using number that exceeds search results."""
        mock_metadata = MagicMock()
        command_handler.last_search_results = [mock_metadata]

        result = command_handler.cmd_use(["5"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_module_select_with_load_failure(self, command_handler, mock_framework):
        """Test module select when module fails to load."""
        mock_metadata = MagicMock()
        mock_metadata.path = "recon/nmap"
        mock_framework.list_modules.return_value = [mock_metadata]
        command_handler.interactive.select_from_list.return_value = mock_metadata
        mock_framework.use_module.return_value = None

        result = command_handler.cmd_module(["select"])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Service Shortcuts Tests
# =============================================================================

class TestServiceShortcuts:
    """Tests for service name shortcuts."""

    @pytest.mark.parametrize("shortcut,expected_path", [
        ("smb", "network/nxc_smb"),
        ("ldap", "network/nxc_ldap"),
        ("winrm", "network/nxc_winrm"),
        ("mssql", "network/nxc_mssql"),
        ("rdp", "network/nxc_rdp"),
        ("ssh", "network/nxc_ssh"),
        ("nmap", "recon/nmap"),
        ("feroxbuster", "web/feroxbuster"),
        ("ferox", "web/feroxbuster"),
        ("sqlmap", "web/sqlmap"),
        ("wfuzz", "web/wfuzz"),
        ("httpx", "web/httpx"),
    ])
    def test_service_shortcut_mapping(self, command_handler, mock_framework, shortcut, expected_path):
        """Test all service shortcut mappings."""
        mock_module = MagicMock()
        mock_module.name = "Module"
        mock_module.has_operations.return_value = False
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_use([shortcut])

        assert result is True
        mock_framework.use_module.assert_called_once_with(expected_path)

    def test_use_shortcut_module_not_found(self, command_handler, mock_framework):
        """Test service shortcut when module doesn't exist."""
        mock_framework.use_module.return_value = None

        result = command_handler.cmd_use(["smb"])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Ops Command Tests
# =============================================================================

class TestOpsCommand:
    """Tests for operations command."""

    def test_ops_with_module_having_operations(self, command_handler, mock_framework):
        """Test ops command when module has operations."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {"name": "Basic Scan", "description": "Run basic scan"}
        ]
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_ops([])

        assert result is True
        mock_module.get_operations.assert_called()

    def test_ops_with_module_no_operations(self, command_handler, mock_framework):
        """Test ops when module doesn't have operations."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = False
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_ops([])

        assert result is True
        command_handler.display.print_info.assert_called()


# =============================================================================
# Show Ops Command Tests
# =============================================================================

class TestShowOpsCommand:
    """Tests for show operations command."""

    def test_show_ops_no_module(self, command_handler, mock_framework):
        """Test show ops when no module loaded."""
        mock_framework.session.current_module = None

        result = command_handler.cmd_show_ops([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_show_ops_with_operations(self, command_handler, mock_framework):
        """Test show ops with module having operations."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {"name": "Scan", "description": "Basic scan"}
        ]
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_show_ops([])

        assert result is True

    def test_show_ops_without_operations(self, command_handler, mock_framework):
        """Test show ops with module not having operations."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = False
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_show_ops([])

        assert result is True
        command_handler.display.print_info.assert_called()
