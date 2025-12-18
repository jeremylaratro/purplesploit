"""
Tests for the ModuleCommandsMixin class.

Tests the module-related commands for search, loading, and execution.
"""

import pytest
from unittest.mock import MagicMock, patch


class MockModuleHandler:
    """Mock handler class combining base and module mixins for testing."""

    def __init__(self):
        # Simulate base mixin
        self.commands = {}
        self.aliases = {}
        self.last_search_results = []
        self.last_ops_results = []

        # Mock framework
        self.framework = MagicMock()
        self.framework.session = MagicMock()
        self.framework.session.current_module = None

        # Mock display
        self.display = MagicMock()

        # Mock interactive selector
        self.interactive = MagicMock()

        # Service shortcuts
        self.service_shortcuts = {
            'smb': 'network/nxc_smb',
            'ssh': 'network/nxc_ssh',
            'rdp': 'network/nxc_rdp'
        }

    def register_command(self, name, handler, aliases=None):
        """Mock register_command from base mixin."""
        self.commands[name] = handler
        if aliases:
            for alias in aliases:
                self.aliases[alias] = name

    def _show_operations(self, operations):
        """Mock method to display operations."""
        pass

    def _execute_operation(self, module, operation):
        """Mock method to execute operation."""
        return {'success': True}

    def _show_modules_tree(self, modules):
        """Mock method to display modules as a tree."""
        pass


@pytest.fixture
def module_handler():
    """Create a mock module handler for testing."""
    from purplesploit.ui.command_mixins.module_commands import ModuleCommandsMixin

    # Create combined class
    class TestHandler(MockModuleHandler, ModuleCommandsMixin):
        def __init__(self):
            MockModuleHandler.__init__(self)
            self._init_module_commands()

    return TestHandler()


class TestModuleCommandsInit:
    """Tests for ModuleCommandsMixin initialization."""

    def test_registers_search_command(self, module_handler):
        """Test that search command is registered."""
        assert "search" in module_handler.commands

    def test_registers_module_command(self, module_handler):
        """Test that module command is registered."""
        assert "module" in module_handler.commands

    def test_registers_use_command(self, module_handler):
        """Test that use command is registered."""
        assert "use" in module_handler.commands

    def test_registers_back_command(self, module_handler):
        """Test that back command is registered."""
        assert "back" in module_handler.commands

    def test_registers_info_command(self, module_handler):
        """Test that info command is registered."""
        assert "info" in module_handler.commands

    def test_registers_options_command(self, module_handler):
        """Test that options command is registered."""
        assert "options" in module_handler.commands

    def test_registers_set_command(self, module_handler):
        """Test that set command is registered."""
        assert "set" in module_handler.commands

    def test_registers_run_command(self, module_handler):
        """Test that run command is registered."""
        assert "run" in module_handler.commands

    def test_run_has_exploit_alias(self, module_handler):
        """Test that run has exploit alias."""
        assert "exploit" in module_handler.aliases
        assert module_handler.aliases["exploit"] == "run"

    def test_registers_ops_command(self, module_handler):
        """Test that ops command is registered."""
        assert "ops" in module_handler.commands

    def test_registers_operations_command(self, module_handler):
        """Test that operations command is registered."""
        assert "operations" in module_handler.commands


class TestSearchCommand:
    """Tests for cmd_search method."""

    def test_search_no_query_shows_error(self, module_handler):
        """Test search without query shows error."""
        result = module_handler.cmd_search([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_search_with_query(self, module_handler):
        """Test search with query."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        module_handler.framework.search_modules.return_value = [mock_module]

        result = module_handler.cmd_search(["nmap"])
        assert result is True
        module_handler.framework.search_modules.assert_called_with("nmap")

    def test_search_stores_results(self, module_handler):
        """Test that search results are stored."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        mock_module2 = MagicMock()
        mock_module2.path = "recon/nmap_fast"
        module_handler.framework.search_modules.return_value = [mock_module, mock_module2]

        module_handler.cmd_search(["nmap"])
        assert len(module_handler.last_search_results) == 2

    def test_search_auto_loads_single_result(self, module_handler):
        """Test that single result is auto-loaded."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        module_handler.framework.search_modules.return_value = [mock_module]
        module_handler.framework.use_module.return_value = MagicMock(name="Nmap")

        result = module_handler.cmd_search(["nmap"])
        assert result is True
        module_handler.framework.use_module.assert_called_with("recon/nmap")

    def test_search_no_results(self, module_handler):
        """Test search with no results."""
        module_handler.framework.search_modules.return_value = []

        result = module_handler.cmd_search(["nonexistent"])
        assert result is True
        module_handler.display.print_warning.assert_called()

    def test_search_select_no_results(self, module_handler):
        """Test search select with no previous results."""
        module_handler.last_search_results = []

        result = module_handler.cmd_search(["select"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_search_select_with_results(self, module_handler):
        """Test search select with previous results."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        module_handler.last_search_results = [mock_module]
        module_handler.interactive.select_module.return_value = mock_module
        module_handler.framework.use_module.return_value = MagicMock(name="Nmap")

        result = module_handler.cmd_search(["select"])
        assert result is True
        module_handler.interactive.select_module.assert_called()


class TestUseCommand:
    """Tests for cmd_use method."""

    def test_use_no_args_shows_error(self, module_handler):
        """Test use without args shows error."""
        result = module_handler.cmd_use([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_use_with_path(self, module_handler):
        """Test use with module path."""
        mock_module = MagicMock()
        mock_module.name = "Nmap"
        mock_module.has_operations.return_value = False
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_use(["recon/nmap"])
        assert result is True
        module_handler.framework.use_module.assert_called_with("recon/nmap")
        module_handler.display.print_success.assert_called()

    def test_use_with_number_from_search(self, module_handler):
        """Test use with number from search results."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        mock_module.name = "Nmap"
        mock_module.has_operations.return_value = False
        module_handler.last_search_results = [mock_module]
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_use(["1"])
        assert result is True
        module_handler.framework.use_module.assert_called_with("recon/nmap")

    def test_use_with_invalid_number(self, module_handler):
        """Test use with invalid number."""
        module_handler.last_search_results = []

        result = module_handler.cmd_use(["99"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_use_module_not_found(self, module_handler):
        """Test use with non-existent module."""
        module_handler.framework.use_module.return_value = None

        result = module_handler.cmd_use(["nonexistent/module"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_use_module_with_operations(self, module_handler):
        """Test use with module that has operations."""
        mock_module = MagicMock()
        mock_module.name = "NXC SMB"
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'List Shares', 'description': 'List SMB shares'}
        ]
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_use(["network/nxc_smb"])
        assert result is True
        module_handler.display.print_info.assert_called()


class TestBackCommand:
    """Tests for cmd_back method."""

    def test_back_no_module(self, module_handler):
        """Test back when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_back([])
        assert result is True
        module_handler.display.print_warning.assert_called()

    def test_back_with_module(self, module_handler):
        """Test back with module loaded."""
        mock_module = MagicMock()
        mock_module.name = "Nmap"
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_back([])
        assert result is True
        # The actual code calls session.unload_module() and prints success
        module_handler.framework.session.unload_module.assert_called_once()
        module_handler.display.print_success.assert_called()


class TestInfoCommand:
    """Tests for cmd_info method."""

    def test_info_no_module(self, module_handler):
        """Test info when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_info([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_info_with_module(self, module_handler):
        """Test info with module loaded."""
        mock_module = MagicMock()
        mock_module.name = "Nmap"
        mock_module.description = "Network scanner"
        mock_module.author = "PurpleSploit"
        mock_module.category = "recon"
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_info([])
        assert result is True
        module_handler.display.print_module_info.assert_called_with(mock_module)


class TestOptionsCommand:
    """Tests for cmd_options method."""

    def test_options_no_module(self, module_handler):
        """Test options when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_options([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_options_with_module(self, module_handler):
        """Test options with module loaded."""
        mock_module = MagicMock()
        mock_module.options = {
            'RHOST': {'value': None, 'required': True, 'description': 'Target'}
        }
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_options([])
        assert result is True
        module_handler.display.print_options_table.assert_called()


class TestSetCommand:
    """Tests for cmd_set method."""

    def test_set_no_module(self, module_handler):
        """Test set when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_set(["RHOST", "192.168.1.1"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_set_no_args(self, module_handler):
        """Test set without arguments."""
        mock_module = MagicMock()
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_set([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_set_option(self, module_handler):
        """Test setting an option."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_set(["RHOST", "192.168.1.1"])
        assert result is True
        mock_module.set_option.assert_called_with("RHOST", "192.168.1.1")

    def test_set_option_with_spaces(self, module_handler):
        """Test setting option with value containing spaces."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_set(["DATA", "user=admin", "pass=test"])
        assert result is True
        # Value should be joined with spaces
        mock_module.set_option.assert_called_with("DATA", "user=admin pass=test")


class TestUnsetCommand:
    """Tests for cmd_unset method."""

    def test_unset_no_module(self, module_handler):
        """Test unset when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_unset(["RHOST"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_unset_option(self, module_handler):
        """Test unsetting an option."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_unset(["RHOST"])
        assert result is True
        mock_module.set_option.assert_called_with("RHOST", None)


class TestRunCommand:
    """Tests for cmd_run method."""

    def test_run_no_module(self, module_handler):
        """Test run when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_run([])
        assert result is True
        module_handler.display.print_error.assert_called()


class TestCheckCommand:
    """Tests for cmd_check method."""

    def test_check_no_module(self, module_handler):
        """Test check when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_check([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_check_with_module(self, module_handler):
        """Test check with module loaded."""
        mock_module = MagicMock()
        # The actual code calls module.validate() which returns (is_valid, errors)
        mock_module.validate.return_value = (True, [])
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_check([])
        assert result is True
        mock_module.validate.assert_called_once()


class TestModuleCommand:
    """Tests for cmd_module method."""

    def test_module_select_no_modules(self, module_handler):
        """Test module select with no modules available."""
        module_handler.framework.list_modules.return_value = []

        result = module_handler.cmd_module(["select"])
        assert result is True
        module_handler.display.print_warning.assert_called()

    def test_module_select_cancelled(self, module_handler):
        """Test module select when cancelled."""
        mock_module = MagicMock()
        module_handler.framework.list_modules.return_value = [mock_module]
        module_handler.interactive.select_module.return_value = None

        result = module_handler.cmd_module(["select"])
        assert result is True
        module_handler.display.print_warning.assert_called()

    def test_module_select_with_selection(self, module_handler):
        """Test module select with valid selection."""
        mock_metadata = MagicMock()
        mock_metadata.path = "recon/nmap"
        mock_module = MagicMock()
        mock_module.name = "Nmap"
        mock_module.has_operations.return_value = False

        module_handler.framework.list_modules.return_value = [mock_metadata]
        module_handler.interactive.select_module.return_value = mock_metadata
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_module(["select"])
        assert result is True
        module_handler.display.print_success.assert_called()


class TestShowCommand:
    """Tests for cmd_show method."""

    def test_show_no_args_shows_error(self, module_handler):
        """Test show without args shows error."""
        result = module_handler.cmd_show([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_show_modules(self, module_handler):
        """Test show modules."""
        mock_module = MagicMock()
        module_handler.framework.list_modules.return_value = [mock_module]

        result = module_handler.cmd_show(["modules"])
        assert result is True

    def test_show_targets(self, module_handler):
        """Test show targets."""
        module_handler.framework.session.targets.list.return_value = []

        result = module_handler.cmd_show(["targets"])
        assert result is True
        module_handler.display.print_targets_table.assert_called()

    def test_show_creds(self, module_handler):
        """Test show creds."""
        module_handler.framework.session.credentials.list.return_value = []

        result = module_handler.cmd_show(["creds"])
        assert result is True
        module_handler.display.print_credentials_table.assert_called()


class TestOpsCommand:
    """Tests for cmd_ops global operation search."""

    def test_ops_no_query_shows_error(self, module_handler):
        """Test ops without query shows error."""
        result = module_handler.cmd_ops([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_ops_select_no_modules(self, module_handler):
        """Test ops select with no modules having operations."""
        # Return empty list for list_modules
        module_handler.framework.list_modules.return_value = []

        result = module_handler.cmd_ops(["select"])
        assert result is True
        # When no operations found, it prints a warning
        module_handler.display.print_warning.assert_called()


class TestRecentCommand:
    """Tests for cmd_recent method."""

    def test_recent_no_history(self, module_handler):
        """Test recent with no history."""
        # The actual code calls framework.get_recent_modules()
        module_handler.framework.get_recent_modules.return_value = []

        result = module_handler.cmd_recent([])
        assert result is True
        module_handler.display.print_warning.assert_called()

    def test_recent_with_history(self, module_handler):
        """Test recent with history."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        mock_module.name = "Nmap"
        module_handler.framework.get_recent_modules.return_value = [mock_module]

        result = module_handler.cmd_recent([])
        assert result is True

    def test_recent_select_no_history(self, module_handler):
        """Test recent select with no history."""
        module_handler.framework.get_recent_modules.return_value = []

        result = module_handler.cmd_recent(["select"])
        assert result is True
        module_handler.display.print_warning.assert_called()

    def test_recent_select_with_selection(self, module_handler):
        """Test recent select with valid selection."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        module_handler.framework.get_recent_modules.return_value = [mock_module]
        module_handler.interactive.select_from_list.return_value = "recon/nmap"
        module_handler.framework.use_module.return_value = MagicMock()

        result = module_handler.cmd_recent(["select"])
        assert result is True


class TestSearchExtended:
    """Extended tests for cmd_search method."""

    def test_search_auto_loads_single_result(self, module_handler):
        """Test that single search result auto-loads."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        mock_module.name = "Nmap"
        mock_module.has_operations.return_value = False
        module_handler.framework.search_modules.return_value = [mock_module]
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_search(["nmap"])
        assert result is True
        module_handler.framework.use_module.assert_called_with("recon/nmap")

    def test_search_multiple_results_no_auto_load(self, module_handler):
        """Test that multiple search results don't auto-load."""
        mock_module1 = MagicMock()
        mock_module1.path = "recon/nmap"
        mock_module2 = MagicMock()
        mock_module2.path = "recon/nmap_fast"
        module_handler.framework.search_modules.return_value = [mock_module1, mock_module2]

        result = module_handler.cmd_search(["nmap"])
        assert result is True
        module_handler.framework.use_module.assert_not_called()
        module_handler.display.print_modules_table.assert_called()

    def test_search_select_no_results(self, module_handler):
        """Test search select with no previous results."""
        module_handler.last_search_results = []

        result = module_handler.cmd_search(["select"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_search_select_with_results(self, module_handler):
        """Test search select with previous results."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        module_handler.last_search_results = [mock_module]
        module_handler.interactive.select_module.return_value = mock_module
        module_handler.framework.use_module.return_value = MagicMock()

        result = module_handler.cmd_search(["select"])
        assert result is True

    def test_search_select_cancelled(self, module_handler):
        """Test search select when cancelled."""
        mock_module = MagicMock()
        module_handler.last_search_results = [mock_module]
        module_handler.interactive.select_module.return_value = None

        result = module_handler.cmd_search(["select"])
        assert result is True
        module_handler.display.print_warning.assert_called()


class TestUseExtended:
    """Extended tests for cmd_use method."""

    def test_use_with_service_shortcut(self, module_handler):
        """Test use with service shortcut."""
        mock_module = MagicMock()
        mock_module.name = "NXC SMB"
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [{'name': 'test', 'description': 'test op'}]
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_use(["smb"])
        assert result is True
        module_handler.framework.use_module.assert_called_with("network/nxc_smb")

    def test_use_with_number_from_search(self, module_handler):
        """Test use with number from search results."""
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        mock_module.name = "Nmap"
        mock_module.has_operations.return_value = False
        module_handler.last_search_results = [mock_module]
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_use(["1"])
        assert result is True
        module_handler.framework.use_module.assert_called_with("recon/nmap")

    def test_use_with_invalid_number(self, module_handler):
        """Test use with invalid number."""
        mock_module = MagicMock()
        module_handler.last_search_results = [mock_module]

        result = module_handler.cmd_use(["999"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_use_with_number_no_results(self, module_handler):
        """Test use with number but no search results."""
        module_handler.last_search_results = []
        module_handler.last_ops_results = []

        result = module_handler.cmd_use(["1"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_use_module_load_failed(self, module_handler):
        """Test use when module load fails."""
        module_handler.framework.use_module.return_value = None

        result = module_handler.cmd_use(["nonexistent/module"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_use_with_filter(self, module_handler):
        """Test use with filter like 'use smb auth'."""
        mock_module = MagicMock()
        mock_module.path = "network/nxc_smb"
        mock_module.name = "NXC SMB"
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'smb_auth', 'description': 'auth test', 'subcategory': 'auth'}
        ]
        mock_module.get_subcategories.return_value = ['auth', 'shares']
        mock_module.get_operations_by_subcategory.return_value = [
            {'name': 'smb_auth', 'description': 'auth test', 'subcategory': 'auth'}
        ]

        module_handler.framework.list_modules.return_value = [mock_module]
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_use(["smb", "auth"])
        assert result is True
        module_handler.framework.use_module.assert_called()


class TestSetExtended:
    """Extended tests for cmd_set method."""

    def test_set_with_value_containing_spaces(self, module_handler):
        """Test setting option with value containing spaces."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_set(["DATA", "user=admin", "pass=test"])
        assert result is True
        mock_module.set_option.assert_called_with("DATA", "user=admin pass=test")

    def test_set_option_failed(self, module_handler):
        """Test set when option setting fails."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = False
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_set(["INVALID", "value"])
        assert result is True
        module_handler.display.print_error.assert_called()


class TestUnsetCommand:
    """Tests for cmd_unset method."""

    def test_unset_no_module(self, module_handler):
        """Test unset when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_unset(["RHOST"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_unset_no_args(self, module_handler):
        """Test unset without arguments."""
        mock_module = MagicMock()
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_unset([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_unset_success(self, module_handler):
        """Test unset option successfully."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_unset(["RHOST"])
        assert result is True
        mock_module.set_option.assert_called_with("RHOST", None)
        module_handler.display.print_success.assert_called()

    def test_unset_failed(self, module_handler):
        """Test unset when option clear fails."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = False
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_unset(["INVALID"])
        assert result is True
        module_handler.display.print_error.assert_called()


class TestRunExtended:
    """Extended tests for cmd_run method."""

    def test_run_no_module_with_ops_results(self, module_handler):
        """Test run with number and ops results but no module."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [{'name': 'test_op'}]

        module_handler.framework.session.current_module = None
        module_handler.last_ops_results = [
            {'module': 'TestModule', 'module_path': 'test/module', 'operation': 'test_op'}
        ]
        module_handler.framework.use_module.return_value = mock_module

        result = module_handler.cmd_run(["1"])
        assert result is True

    def test_run_invalid_ops_number(self, module_handler):
        """Test run with invalid ops number."""
        module_handler.framework.session.current_module = None
        module_handler.last_ops_results = [{'module': 'Test'}]

        result = module_handler.cmd_run(["999"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_run_module_with_operations_by_number(self, module_handler):
        """Test run operation by number."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'op1', 'description': 'test'}
        ]
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_run(["1"])
        assert result is True

    def test_run_module_with_operations_invalid_number(self, module_handler):
        """Test run operation with invalid number."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'op1', 'description': 'test'}
        ]
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_run(["999"])
        assert result is True
        module_handler.display.print_error.assert_called()


class TestOpsExtended:
    """Extended tests for cmd_ops method."""

    def test_ops_search_with_results(self, module_handler):
        """Test ops search with matching results."""
        mock_module_info = MagicMock()
        mock_module_info.path = "test/module"
        mock_module_info.name = "TestModule"

        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'auth_test', 'description': 'Authentication test'}
        ]

        module_handler.framework.list_modules.return_value = [mock_module_info]
        module_handler.framework.load_module.return_value = mock_module

        result = module_handler.cmd_ops(["auth"])
        assert result is True

    def test_ops_search_no_results(self, module_handler):
        """Test ops search with no matching results."""
        mock_module_info = MagicMock()
        mock_module_info.path = "test/module"

        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'something_else', 'description': 'Other operation'}
        ]

        module_handler.framework.list_modules.return_value = [mock_module_info]
        module_handler.framework.load_module.return_value = mock_module

        result = module_handler.cmd_ops(["nonexistent_query_xyz"])
        assert result is True
        module_handler.display.print_warning.assert_called()


class TestShowOpsCommand:
    """Tests for cmd_show_ops method."""

    def test_show_ops_no_module(self, module_handler):
        """Test show ops when no module loaded."""
        module_handler.framework.session.current_module = None

        result = module_handler.cmd_show_ops([])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_show_ops_module_no_operations(self, module_handler):
        """Test show ops when module has no operations."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = False
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_show_ops([])
        assert result is True
        module_handler.display.print_warning.assert_called()

    def test_show_ops_with_operations(self, module_handler):
        """Test show ops when module has operations."""
        mock_module = MagicMock()
        mock_module.name = "TestModule"
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'op1', 'description': 'test'}
        ]
        mock_module.get_subcategories.return_value = []
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_show_ops([])
        assert result is True

    def test_show_ops_with_filter(self, module_handler):
        """Test show ops with subcategory filter."""
        mock_module = MagicMock()
        mock_module.name = "TestModule"
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'auth_op', 'description': 'auth test', 'subcategory': 'auth'}
        ]
        mock_module.get_subcategories.return_value = ['auth']
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_show_ops(["auth"])
        assert result is True


class TestModuleCommandExtended:
    """Extended tests for cmd_module method."""

    def test_module_invalid_subcommand(self, module_handler):
        """Test module with invalid subcommand."""
        result = module_handler.cmd_module(["invalid"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_module_select_load_fails(self, module_handler):
        """Test module select when load fails."""
        mock_metadata = MagicMock()
        mock_metadata.path = "test/module"

        module_handler.framework.list_modules.return_value = [mock_metadata]
        module_handler.interactive.select_module.return_value = mock_metadata
        module_handler.framework.use_module.return_value = None

        result = module_handler.cmd_module(["select"])
        assert result is True
        module_handler.display.print_error.assert_called()

    def test_module_select_with_operations_then_select_op(self, module_handler):
        """Test module select with operation selection."""
        mock_metadata = MagicMock()
        mock_metadata.path = "test/module"

        mock_module = MagicMock()
        mock_module.name = "TestModule"
        mock_module.has_operations.return_value = True
        mock_module.get_operations.return_value = [
            {'name': 'test_op', 'description': 'test operation'}
        ]

        module_handler.framework.list_modules.return_value = [mock_metadata]
        module_handler.interactive.select_module.return_value = mock_metadata
        module_handler.framework.use_module.return_value = mock_module
        module_handler.interactive.select_operation.return_value = {'name': 'test_op'}

        result = module_handler.cmd_module(["select"])
        assert result is True
        module_handler.display.print_results.assert_called()


class TestOptionsExtended:
    """Extended tests for cmd_options method."""

    def test_options_shows_default_command(self, module_handler):
        """Test that options shows default command if available."""
        mock_module = MagicMock()
        mock_module.show_options.return_value = {'RHOST': {}}
        mock_module.get_default_command.return_value = "nmap -sV {RHOST}"
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_options([])
        assert result is True
        module_handler.display.print_options_table.assert_called()
        module_handler.display.console.print.assert_called()


class TestCheckExtended:
    """Extended tests for cmd_check method."""

    def test_check_valid_module(self, module_handler):
        """Test check with valid module."""
        mock_module = MagicMock()
        mock_module.validate.return_value = (True, [])
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_check([])
        assert result is True
        module_handler.display.print_success.assert_called()

    def test_check_invalid_module(self, module_handler):
        """Test check with invalid module."""
        mock_module = MagicMock()
        mock_module.validate.return_value = (False, ["Missing RHOST", "Missing TARGET"])
        module_handler.framework.session.current_module = mock_module

        result = module_handler.cmd_check([])
        assert result is True
        module_handler.display.print_error.assert_called()
