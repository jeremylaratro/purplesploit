"""
Tests for the ContextCommandsMixin class.

Tests the context management commands for targets, credentials, services, and wordlists.
"""

import pytest
from unittest.mock import MagicMock, patch


class MockContextHandler:
    """Mock handler class combining base and context mixins for testing."""

    def __init__(self):
        # Simulate base mixin
        self.commands = {}
        self.aliases = {}
        self.last_search_results = []
        self.last_ops_results = []

        # Mock framework
        self.framework = MagicMock()
        self.framework.session = MagicMock()
        self.framework.session.targets = MagicMock()
        self.framework.session.credentials = MagicMock()
        self.framework.session.services = MagicMock()
        self.framework.session.wordlists = MagicMock()
        self.framework.session.current_module = None
        self.framework.database = MagicMock()

        # Mock display
        self.display = MagicMock()

        # Mock interactive selector
        self.interactive = MagicMock()

    def register_command(self, name, handler, aliases=None):
        """Mock register_command from base mixin."""
        self.commands[name] = handler
        if aliases:
            for alias in aliases:
                self.aliases[alias] = name

    def _auto_set_target_in_module(self, target):
        """Mock method."""
        pass


@pytest.fixture
def context_handler():
    """Create a mock context handler for testing."""
    from purplesploit.ui.command_mixins.context_commands import ContextCommandsMixin

    # Create combined class
    class TestHandler(MockContextHandler, ContextCommandsMixin):
        def __init__(self):
            MockContextHandler.__init__(self)
            self._init_context_commands()

    return TestHandler()


class TestContextCommandsInit:
    """Tests for ContextCommandsMixin initialization."""

    def test_registers_targets_command(self, context_handler):
        """Test that targets command is registered."""
        assert "targets" in context_handler.commands

    def test_registers_creds_command(self, context_handler):
        """Test that creds command is registered."""
        assert "creds" in context_handler.commands

    def test_registers_services_command(self, context_handler):
        """Test that services command is registered."""
        assert "services" in context_handler.commands

    def test_registers_wordlists_command(self, context_handler):
        """Test that wordlists command is registered."""
        assert "wordlists" in context_handler.commands

    def test_registers_target_quick_command(self, context_handler):
        """Test that target quick command is registered."""
        assert "target" in context_handler.commands

    def test_registers_cred_quick_command(self, context_handler):
        """Test that cred quick command is registered."""
        assert "cred" in context_handler.commands

    def test_registers_go_command(self, context_handler):
        """Test that go command is registered."""
        assert "go" in context_handler.commands


class TestTargetsCommand:
    """Tests for cmd_targets method."""

    def test_targets_list_default(self, context_handler):
        """Test targets command with no args lists targets."""
        context_handler.framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1', 'name': 'target1'}
        ]

        result = context_handler.cmd_targets([])
        assert result is True
        context_handler.display.print_targets_table.assert_called_once()

    def test_targets_list_explicit(self, context_handler):
        """Test targets list subcommand."""
        context_handler.framework.session.targets.list.return_value = []

        result = context_handler.cmd_targets(["list"])
        assert result is True
        context_handler.display.print_targets_table.assert_called_once()

    def test_targets_clear(self, context_handler):
        """Test targets clear subcommand."""
        context_handler.framework.session.targets.clear.return_value = 5

        result = context_handler.cmd_targets(["clear"])
        assert result is True
        context_handler.framework.session.targets.clear.assert_called_once()
        context_handler.display.print_success.assert_called()

    def test_targets_add_with_ip(self, context_handler):
        """Test targets add with IP address."""
        context_handler.framework.session.targets.list.return_value = []
        context_handler.framework.add_target.return_value = True

        result = context_handler.cmd_targets(["add", "192.168.1.1"])
        assert result is True
        context_handler.framework.add_target.assert_called_with("network", "192.168.1.1", None)

    def test_targets_add_with_url(self, context_handler):
        """Test targets add with URL."""
        context_handler.framework.session.targets.list.return_value = []
        context_handler.framework.add_target.return_value = True

        result = context_handler.cmd_targets(["add", "http://example.com"])
        assert result is True
        context_handler.framework.add_target.assert_called_with("web", "http://example.com", None)

    def test_targets_add_with_name(self, context_handler):
        """Test targets add with custom name."""
        context_handler.framework.session.targets.list.return_value = []
        context_handler.framework.add_target.return_value = True

        result = context_handler.cmd_targets(["add", "192.168.1.1", "myserver"])
        assert result is True
        context_handler.framework.add_target.assert_called_with("network", "192.168.1.1", "myserver")

    def test_targets_add_missing_identifier(self, context_handler):
        """Test targets add without identifier shows error."""
        result = context_handler.cmd_targets(["add"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_targets_set(self, context_handler):
        """Test targets set subcommand."""
        context_handler.framework.session.targets.set_current.return_value = True
        context_handler.framework.session.targets.get_current.return_value = {'ip': '192.168.1.1'}

        result = context_handler.cmd_targets(["set", "192.168.1.1"])
        assert result is True
        context_handler.framework.session.targets.set_current.assert_called_with("192.168.1.1")

    def test_targets_remove(self, context_handler):
        """Test targets remove subcommand."""
        context_handler.framework.session.targets.remove.return_value = True

        result = context_handler.cmd_targets(["remove", "192.168.1.1"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_targets_unknown_subcommand(self, context_handler):
        """Test targets with unknown subcommand shows error."""
        result = context_handler.cmd_targets(["invalid"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestTargetsIndexOperations:
    """Tests for target index operations."""

    def test_targets_index_clear(self, context_handler):
        """Test clearing target by index."""
        context_handler.framework.session.targets.remove_by_index.return_value = True

        result = context_handler.cmd_targets(["1", "clear"])
        assert result is True
        context_handler.framework.session.targets.remove_by_index.assert_called_with(1)

    def test_targets_range_clear(self, context_handler):
        """Test clearing targets by range."""
        context_handler.framework.session.targets.remove_range.return_value = 3

        result = context_handler.cmd_targets(["1-3", "clear"])
        assert result is True
        context_handler.framework.session.targets.remove_range.assert_called_with(1, 3)

    def test_targets_index_modify(self, context_handler):
        """Test modifying target by index."""
        context_handler.framework.session.targets.modify.return_value = True

        result = context_handler.cmd_targets(["1", "modify", "ip=10.0.0.1"])
        assert result is True
        context_handler.framework.session.targets.modify.assert_called_with(1, ip="10.0.0.1")

    def test_targets_index_modify_multiple(self, context_handler):
        """Test modifying multiple fields by index."""
        context_handler.framework.session.targets.modify.return_value = True

        result = context_handler.cmd_targets(["1", "modify", "ip=10.0.0.1", "name=newname"])
        assert result is True
        context_handler.framework.session.targets.modify.assert_called_with(1, ip="10.0.0.1", name="newname")

    def test_targets_index_missing_action(self, context_handler):
        """Test target index without action shows error."""
        result = context_handler.cmd_targets(["1"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestTargetsSelect:
    """Tests for targets select functionality."""

    def test_targets_select_with_selection(self, context_handler):
        """Test interactive target selection."""
        targets = [
            {'ip': '192.168.1.1', 'name': 'target1'},
            {'ip': '192.168.1.2', 'name': 'target2'}
        ]
        context_handler.framework.session.targets.list.return_value = targets
        context_handler.interactive.select_target.return_value = targets[1]

        result = context_handler.cmd_targets(["select"])
        assert result is True
        context_handler.interactive.select_target.assert_called_with(targets)
        context_handler.display.print_success.assert_called()

    def test_targets_select_no_targets(self, context_handler):
        """Test targets select with no targets available."""
        context_handler.framework.session.targets.list.return_value = []

        result = context_handler.cmd_targets(["select"])
        assert result is True
        context_handler.display.print_warning.assert_called()

    def test_targets_select_cancelled(self, context_handler):
        """Test targets select when cancelled."""
        context_handler.framework.session.targets.list.return_value = [{'ip': '192.168.1.1'}]
        context_handler.interactive.select_target.return_value = None

        result = context_handler.cmd_targets(["select"])
        assert result is True
        context_handler.display.print_warning.assert_called()


class TestCredsCommand:
    """Tests for cmd_creds method."""

    def test_creds_list_default(self, context_handler):
        """Test creds command with no args lists credentials."""
        context_handler.framework.session.credentials.list.return_value = [
            {'username': 'admin', 'password': 'secret'}
        ]

        result = context_handler.cmd_creds([])
        assert result is True
        context_handler.display.print_credentials_table.assert_called_once()

    def test_creds_clear(self, context_handler):
        """Test creds clear subcommand."""
        context_handler.framework.session.credentials.clear.return_value = 3

        result = context_handler.cmd_creds(["clear"])
        assert result is True
        context_handler.framework.session.credentials.clear.assert_called_once()


class TestTargetQuickCommand:
    """Tests for cmd_target_quick method."""

    def test_target_quick_with_ip(self, context_handler):
        """Test quick target add with IP."""
        context_handler.framework.session.targets.list.return_value = []
        context_handler.framework.add_target.return_value = True
        context_handler.framework.session.targets.get_current.return_value = {'ip': '192.168.1.1'}

        result = context_handler.cmd_target_quick(["192.168.1.1"])
        assert result is True
        context_handler.framework.add_target.assert_called()

    def test_target_quick_no_ip(self, context_handler):
        """Test quick target without IP shows error."""
        result = context_handler.cmd_target_quick([])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestCredQuickCommand:
    """Tests for cmd_cred_quick method."""

    def test_cred_quick_user_pass(self, context_handler):
        """Test quick cred add with user:pass format."""
        context_handler.framework.session.credentials.list.return_value = []
        context_handler.framework.add_credential.return_value = True

        result = context_handler.cmd_cred_quick(["admin:password123"])
        assert result is True
        context_handler.framework.add_credential.assert_called()

    def test_cred_quick_no_args(self, context_handler):
        """Test quick cred without args shows error."""
        result = context_handler.cmd_cred_quick([])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestServicesCommand:
    """Tests for cmd_services method."""

    def test_services_list_default(self, context_handler):
        """Test services command lists detected services."""
        context_handler.framework.session.services.get_services.return_value = {
            '192.168.1.1': {'ssh': [22], 'http': [80]}
        }

        result = context_handler.cmd_services([])
        assert result is True
        context_handler.display.print_services_table.assert_called()

    def test_services_clear(self, context_handler):
        """Test services clear subcommand."""
        context_handler.framework.session.services.clear.return_value = None

        result = context_handler.cmd_services(["clear"])
        assert result is True
        context_handler.framework.session.services.clear.assert_called_once()


class TestWordlistsCommand:
    """Tests for cmd_wordlists method."""

    def test_wordlists_list_default(self, context_handler):
        """Test wordlists command lists wordlists."""
        context_handler.framework.session.wordlists.list_all.return_value = {
            'directory': [{'name': 'common', 'path': '/path/common.txt'}]
        }

        result = context_handler.cmd_wordlists([])
        assert result is True
        # Should call some display method


class TestGoCommand:
    """Tests for cmd_go all-in-one workflow command."""

    def test_go_with_target_and_cred(self, context_handler):
        """Test go command with target and credential."""
        context_handler.framework.session.targets.get_current.return_value = {'ip': '192.168.1.1'}
        context_handler.framework.session.credentials.get_current.return_value = {'username': 'admin'}

        result = context_handler.cmd_go(["192.168.1.1", "admin:password"])
        assert result is True

    def test_go_no_args(self, context_handler):
        """Test go command without args shows usage."""
        result = context_handler.cmd_go([])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_go_one_arg_shows_error(self, context_handler):
        """Test go command with only one arg shows error."""
        result = context_handler.cmd_go(["192.168.1.1"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestTargetsAddAutoSelect:
    """Tests for targets add auto-selection behavior."""

    def test_targets_add_auto_selects_first(self, context_handler):
        """Test that adding first target auto-selects it."""
        # Empty list initially, then has target after add
        context_handler.framework.session.targets.list.return_value = []
        context_handler.framework.add_target.return_value = True
        context_handler.framework.session.targets.get_current.return_value = {'ip': '192.168.1.1'}

        result = context_handler.cmd_targets(["add", "192.168.1.1"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_targets_add_already_exists(self, context_handler):
        """Test adding duplicate target shows warning."""
        context_handler.framework.session.targets.list.return_value = [{'ip': '192.168.1.1'}]
        context_handler.framework.add_target.return_value = False

        result = context_handler.cmd_targets(["add", "192.168.1.1"])
        assert result is True
        context_handler.display.print_warning.assert_called()


class TestTargetsSetNotFound:
    """Tests for targets set when target not found."""

    def test_targets_set_not_found(self, context_handler):
        """Test targets set with non-existent target."""
        context_handler.framework.session.targets.set_current.return_value = False

        result = context_handler.cmd_targets(["set", "nonexistent"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_targets_set_missing_identifier(self, context_handler):
        """Test targets set without identifier shows error."""
        result = context_handler.cmd_targets(["set"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestTargetsRemoveNotFound:
    """Tests for targets remove when target not found."""

    def test_targets_remove_not_found(self, context_handler):
        """Test targets remove with non-existent target."""
        context_handler.framework.session.targets.remove.return_value = False

        result = context_handler.cmd_targets(["remove", "nonexistent"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_targets_remove_missing_identifier(self, context_handler):
        """Test targets remove without identifier shows error."""
        result = context_handler.cmd_targets(["remove"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestTargetsIndexOperationsExtended:
    """Extended tests for target index operations."""

    def test_targets_index_clear_not_found(self, context_handler):
        """Test clearing target by invalid index."""
        context_handler.framework.session.targets.remove_by_index.return_value = False

        result = context_handler.cmd_targets(["999", "clear"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_targets_range_clear_invalid_format(self, context_handler):
        """Test clearing targets with invalid range format."""
        result = context_handler.cmd_targets(["abc-xyz", "clear"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_targets_index_unknown_action(self, context_handler):
        """Test target index with unknown action."""
        result = context_handler.cmd_targets(["1", "unknown"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_targets_index_modify_missing_options(self, context_handler):
        """Test targets index modify without options shows error."""
        result = context_handler.cmd_targets(["1", "modify"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_targets_index_modify_no_equals(self, context_handler):
        """Test targets index modify with invalid format (no equals sign)."""
        result = context_handler.cmd_targets(["1", "modify", "invalid"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_targets_index_modify_not_found(self, context_handler):
        """Test targets index modify with non-existent index."""
        context_handler.framework.session.targets.modify.return_value = False

        result = context_handler.cmd_targets(["999", "modify", "ip=10.0.0.1"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestCredsExtended:
    """Extended tests for credentials commands."""

    def test_creds_list_explicit(self, context_handler):
        """Test creds list subcommand."""
        context_handler.framework.session.credentials.list.return_value = []

        result = context_handler.cmd_creds(["list"])
        assert result is True
        context_handler.display.print_credentials_table.assert_called_once()

    def test_creds_add_user_pass(self, context_handler):
        """Test creds add with user:pass format."""
        context_handler.framework.add_credential.return_value = True

        result = context_handler.cmd_creds(["add", "admin:password123"])
        assert result is True
        context_handler.framework.add_credential.assert_called()
        context_handler.display.print_success.assert_called()

    def test_creds_add_user_only(self, context_handler):
        """Test creds add with username only."""
        context_handler.framework.add_credential.return_value = True

        result = context_handler.cmd_creds(["add", "admin"])
        assert result is True
        context_handler.framework.add_credential.assert_called()

    def test_creds_add_with_domain(self, context_handler):
        """Test creds add with domain."""
        context_handler.framework.add_credential.return_value = True

        result = context_handler.cmd_creds(["add", "admin:password", "CORP"])
        assert result is True
        context_handler.framework.add_credential.assert_called()

    def test_creds_add_already_exists(self, context_handler):
        """Test creds add with duplicate credential."""
        context_handler.framework.add_credential.return_value = False

        result = context_handler.cmd_creds(["add", "admin:password"])
        assert result is True
        context_handler.display.print_warning.assert_called()

    def test_creds_add_missing_args(self, context_handler):
        """Test creds add without arguments shows error."""
        result = context_handler.cmd_creds(["add"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_set_success(self, context_handler):
        """Test creds set subcommand."""
        context_handler.framework.session.credentials.set_current.return_value = True
        context_handler.framework.session.credentials.get_current.return_value = {'username': 'admin'}

        result = context_handler.cmd_creds(["set", "admin"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_creds_set_not_found(self, context_handler):
        """Test creds set with non-existent credential."""
        context_handler.framework.session.credentials.set_current.return_value = False

        result = context_handler.cmd_creds(["set", "nonexistent"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_set_missing_identifier(self, context_handler):
        """Test creds set without identifier shows error."""
        result = context_handler.cmd_creds(["set"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_remove_success(self, context_handler):
        """Test creds remove subcommand."""
        context_handler.framework.session.credentials.remove.return_value = True

        result = context_handler.cmd_creds(["remove", "admin"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_creds_remove_not_found(self, context_handler):
        """Test creds remove with non-existent credential."""
        context_handler.framework.session.credentials.remove.return_value = False

        result = context_handler.cmd_creds(["remove", "nonexistent"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_remove_missing_identifier(self, context_handler):
        """Test creds remove without identifier shows error."""
        result = context_handler.cmd_creds(["remove"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_unknown_subcommand(self, context_handler):
        """Test creds with unknown subcommand."""
        result = context_handler.cmd_creds(["invalid"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestCredsIndexOperations:
    """Tests for credential index operations."""

    def test_creds_index_clear(self, context_handler):
        """Test clearing credential by index."""
        context_handler.framework.session.credentials.remove_by_index.return_value = True

        result = context_handler.cmd_creds(["1", "clear"])
        assert result is True
        context_handler.framework.session.credentials.remove_by_index.assert_called_with(1)
        context_handler.display.print_success.assert_called()

    def test_creds_index_clear_not_found(self, context_handler):
        """Test clearing credential by invalid index."""
        context_handler.framework.session.credentials.remove_by_index.return_value = False

        result = context_handler.cmd_creds(["999", "clear"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_range_clear(self, context_handler):
        """Test clearing credentials by range."""
        context_handler.framework.session.credentials.remove_range.return_value = 3

        result = context_handler.cmd_creds(["1-3", "clear"])
        assert result is True
        context_handler.framework.session.credentials.remove_range.assert_called_with(1, 3)
        context_handler.display.print_success.assert_called()

    def test_creds_range_clear_invalid_format(self, context_handler):
        """Test clearing credentials with invalid range format."""
        result = context_handler.cmd_creds(["abc-xyz", "clear"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_index_modify(self, context_handler):
        """Test modifying credential by index."""
        context_handler.framework.session.credentials.modify.return_value = True

        result = context_handler.cmd_creds(["1", "modify", "password=newpass"])
        assert result is True
        context_handler.framework.session.credentials.modify.assert_called_with(1, password="newpass")
        context_handler.display.print_success.assert_called()

    def test_creds_index_modify_multiple(self, context_handler):
        """Test modifying multiple credential fields by index."""
        context_handler.framework.session.credentials.modify.return_value = True

        result = context_handler.cmd_creds(["1", "modify", "username=newuser", "domain=CORP"])
        assert result is True
        context_handler.framework.session.credentials.modify.assert_called_with(1, username="newuser", domain="CORP")

    def test_creds_index_modify_not_found(self, context_handler):
        """Test modifying credential with invalid index."""
        context_handler.framework.session.credentials.modify.return_value = False

        result = context_handler.cmd_creds(["999", "modify", "password=newpass"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_index_modify_missing_options(self, context_handler):
        """Test credential index modify without options."""
        result = context_handler.cmd_creds(["1", "modify"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_index_modify_no_equals(self, context_handler):
        """Test credential index modify with invalid format."""
        result = context_handler.cmd_creds(["1", "modify", "invalid"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_index_unknown_action(self, context_handler):
        """Test credential index with unknown action."""
        result = context_handler.cmd_creds(["1", "unknown"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_creds_index_missing_action(self, context_handler):
        """Test credential index without action shows error."""
        result = context_handler.cmd_creds(["1"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestCredsSelect:
    """Tests for credentials select functionality."""

    def test_creds_select_with_selection(self, context_handler):
        """Test interactive credential selection."""
        creds = [
            {'username': 'admin', 'password': 'secret'},
            {'username': 'user', 'password': 'pass'}
        ]
        context_handler.framework.session.credentials.list.return_value = creds
        context_handler.interactive.select_credential.return_value = creds[0]

        result = context_handler.cmd_creds(["select"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_creds_select_cancelled(self, context_handler):
        """Test credentials select when cancelled."""
        context_handler.framework.session.credentials.list.return_value = [{'username': 'admin'}]
        context_handler.interactive.select_credential.return_value = None

        result = context_handler.cmd_creds(["select"])
        assert result is True
        context_handler.display.print_warning.assert_called()

    def test_creds_select_add_new(self, context_handler):
        """Test credentials select with add new option."""
        context_handler.framework.session.credentials.list.return_value = []
        context_handler.interactive.select_credential.return_value = "ADD_NEW"

        # Mock input for the interactive add
        with patch('builtins.input', side_effect=['admin', 'password', '', '', '']):
            context_handler.framework.add_credential.return_value = True
            result = context_handler.cmd_creds(["select"])
            assert result is True


class TestServicesExtended:
    """Extended tests for services commands."""

    def test_services_select_with_selection(self, context_handler):
        """Test interactive service selection."""
        services = {'192.168.1.1': [{'port': 22, 'name': 'ssh', 'target': '192.168.1.1'}]}
        context_handler.framework.session.services.services = services
        selected = {'port': 22, 'name': 'ssh', 'target': '192.168.1.1'}
        context_handler.interactive.select_service.return_value = selected
        context_handler.framework.session.targets.set_current.return_value = True

        result = context_handler.cmd_services(["select"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_services_select_no_services(self, context_handler):
        """Test services select with no services available."""
        context_handler.framework.session.services.services = {}

        result = context_handler.cmd_services(["select"])
        assert result is True
        context_handler.display.print_warning.assert_called()

    def test_services_select_cancelled(self, context_handler):
        """Test services select when cancelled."""
        context_handler.framework.session.services.services = {'192.168.1.1': [{'port': 22}]}
        context_handler.interactive.select_service.return_value = None

        result = context_handler.cmd_services(["select"])
        assert result is True
        context_handler.display.print_warning.assert_called()


class TestWordlistsExtended:
    """Extended tests for wordlists commands."""

    def test_wordlists_add_success(self, context_handler):
        """Test wordlists add subcommand."""
        context_handler.framework.session.wordlists.add.return_value = True

        result = context_handler.cmd_wordlists(["add", "web_dir", "/path/to/wordlist.txt"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_wordlists_add_with_name(self, context_handler):
        """Test wordlists add with custom name."""
        context_handler.framework.session.wordlists.add.return_value = True

        result = context_handler.cmd_wordlists(["add", "web_dir", "/path/to/wordlist.txt", "custom"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_wordlists_add_failure(self, context_handler):
        """Test wordlists add failure."""
        context_handler.framework.session.wordlists.add.return_value = False

        result = context_handler.cmd_wordlists(["add", "web_dir", "/invalid/path"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_wordlists_add_missing_args(self, context_handler):
        """Test wordlists add without required args."""
        result = context_handler.cmd_wordlists(["add", "web_dir"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_wordlists_remove_success(self, context_handler):
        """Test wordlists remove subcommand."""
        context_handler.framework.session.wordlists.remove.return_value = True

        result = context_handler.cmd_wordlists(["remove", "web_dir", "common"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_wordlists_remove_not_found(self, context_handler):
        """Test wordlists remove with non-existent wordlist."""
        context_handler.framework.session.wordlists.remove.return_value = False

        result = context_handler.cmd_wordlists(["remove", "web_dir", "nonexistent"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_wordlists_remove_missing_args(self, context_handler):
        """Test wordlists remove without required args."""
        result = context_handler.cmd_wordlists(["remove", "web_dir"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_wordlists_set_success(self, context_handler):
        """Test wordlists set subcommand."""
        context_handler.framework.session.wordlists.set_current.return_value = True
        context_handler.framework.session.wordlists.get_current.return_value = {'name': 'common'}

        result = context_handler.cmd_wordlists(["set", "web_dir", "common"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_wordlists_set_not_found(self, context_handler):
        """Test wordlists set with non-existent wordlist."""
        context_handler.framework.session.wordlists.set_current.return_value = False

        result = context_handler.cmd_wordlists(["set", "web_dir", "nonexistent"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_wordlists_set_missing_args(self, context_handler):
        """Test wordlists set without required args."""
        result = context_handler.cmd_wordlists(["set", "web_dir"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_wordlists_select_success(self, context_handler):
        """Test wordlists select subcommand."""
        wordlists = [{'name': 'common', 'path': '/path/common.txt'}]
        context_handler.framework.session.wordlists.list.return_value = {'web_dir': wordlists}
        context_handler.framework.session.wordlists.current_selections = {}
        context_handler.interactive.select_wordlist.return_value = wordlists[0]

        result = context_handler.cmd_wordlists(["select", "web_dir"])
        assert result is True
        context_handler.display.print_success.assert_called()

    def test_wordlists_select_no_wordlists(self, context_handler):
        """Test wordlists select with no wordlists in category."""
        context_handler.framework.session.wordlists.list.return_value = {'web_dir': []}

        result = context_handler.cmd_wordlists(["select", "web_dir"])
        assert result is True
        context_handler.display.print_warning.assert_called()

    def test_wordlists_select_cancelled(self, context_handler):
        """Test wordlists select when cancelled."""
        wordlists = [{'name': 'common'}]
        context_handler.framework.session.wordlists.list.return_value = {'web_dir': wordlists}
        context_handler.interactive.select_wordlist.return_value = None

        result = context_handler.cmd_wordlists(["select", "web_dir"])
        assert result is True
        context_handler.display.print_warning.assert_called()

    def test_wordlists_select_missing_category(self, context_handler):
        """Test wordlists select without category."""
        result = context_handler.cmd_wordlists(["select"])
        assert result is True
        context_handler.display.print_error.assert_called()

    def test_wordlists_unknown_subcommand(self, context_handler):
        """Test wordlists with unknown subcommand."""
        result = context_handler.cmd_wordlists(["invalid"])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestTargetQuickExtended:
    """Extended tests for quick target command."""

    def test_target_quick_with_url(self, context_handler):
        """Test quick target add with URL."""
        context_handler.framework.session.targets.get_current.return_value = {'url': 'http://example.com'}

        result = context_handler.cmd_target_quick(["http://example.com"])
        assert result is True
        context_handler.framework.add_target.assert_called()
        context_handler.display.print_success.assert_called()


class TestCredQuickExtended:
    """Extended tests for quick credential command."""

    def test_cred_quick_with_domain(self, context_handler):
        """Test quick cred add with domain."""
        context_handler.framework.session.credentials.get_current.return_value = {'username': 'admin'}

        result = context_handler.cmd_cred_quick(["admin:password", "CORP"])
        assert result is True
        context_handler.framework.add_credential.assert_called()

    def test_cred_quick_username_only(self, context_handler):
        """Test quick cred add with username only."""
        context_handler.framework.session.credentials.get_current.return_value = {'username': 'admin'}

        result = context_handler.cmd_cred_quick(["admin"])
        assert result is True
        context_handler.framework.add_credential.assert_called()


class TestAnalysisCommand:
    """Tests for cmd_analysis method."""

    def test_analysis_no_results(self, context_handler):
        """Test analysis with no web results."""
        context_handler.framework.database.get_scan_results.return_value = []

        result = context_handler.cmd_analysis([])
        assert result is True
        context_handler.display.print_warning.assert_called()

    def test_analysis_with_results(self, context_handler):
        """Test analysis with web results."""
        context_handler.framework.database.get_scan_results.return_value = [
            {
                'target': 'http://example.com',
                'scan_name': 'feroxbuster',
                'timestamp': '2024-01-01 10:00:00',
                'status': 'completed',
                'log_file': '/path/to/log',
                'data': {'urls_found': ['url1', 'url2']}
            }
        ]

        result = context_handler.cmd_analysis([])
        assert result is True
        context_handler.display.console.print.assert_called()


class TestQuickCommand:
    """Tests for cmd_quick method."""

    def test_quick_no_args_shows_usage(self, context_handler):
        """Test quick command without args shows usage."""
        result = context_handler.cmd_quick([])
        assert result is True
        context_handler.display.print_error.assert_called()


class TestAutoSetTargetInModule:
    """Tests for _auto_set_target_in_module method."""

    def test_auto_set_target_no_module(self):
        """Test auto-set when no module loaded."""
        from purplesploit.ui.command_mixins.context_commands import ContextCommandsMixin

        # Create a minimal handler that allows testing the real _auto_set_target_in_module
        class MinimalHandler(ContextCommandsMixin):
            def __init__(self):
                self.framework = MagicMock()
                self.framework.session = MagicMock()
                self.framework.session.current_module = None
                self.display = MagicMock()

        handler = MinimalHandler()
        target = {'ip': '192.168.1.1'}

        # Should not raise
        handler._auto_set_target_in_module(target)

    def test_auto_set_target_with_rhost(self):
        """Test auto-set RHOST option."""
        from purplesploit.ui.command_mixins.context_commands import ContextCommandsMixin

        class MinimalHandler(ContextCommandsMixin):
            def __init__(self):
                self.framework = MagicMock()
                self.framework.session = MagicMock()
                mock_module = MagicMock()
                mock_module.options = {'RHOST': {}}
                self.framework.session.current_module = mock_module
                self.display = MagicMock()

        handler = MinimalHandler()
        target = {'ip': '192.168.1.1'}

        handler._auto_set_target_in_module(target)
        handler.framework.session.current_module.set_option.assert_called_with("RHOST", '192.168.1.1')

    def test_auto_set_target_with_url(self):
        """Test auto-set URL option."""
        from purplesploit.ui.command_mixins.context_commands import ContextCommandsMixin

        class MinimalHandler(ContextCommandsMixin):
            def __init__(self):
                self.framework = MagicMock()
                self.framework.session = MagicMock()
                mock_module = MagicMock()
                mock_module.options = {'URL': {}}
                self.framework.session.current_module = mock_module
                self.display = MagicMock()

        handler = MinimalHandler()
        target = {'url': 'http://example.com'}

        handler._auto_set_target_in_module(target)
        handler.framework.session.current_module.set_option.assert_called_with("URL", 'http://example.com')

    def test_auto_set_target_with_target_option(self):
        """Test auto-set TARGET option."""
        from purplesploit.ui.command_mixins.context_commands import ContextCommandsMixin

        class MinimalHandler(ContextCommandsMixin):
            def __init__(self):
                self.framework = MagicMock()
                self.framework.session = MagicMock()
                mock_module = MagicMock()
                mock_module.options = {'TARGET': {}}
                self.framework.session.current_module = mock_module
                self.display = MagicMock()

        handler = MinimalHandler()
        target = {'ip': '192.168.1.1'}

        handler._auto_set_target_in_module(target)
        handler.framework.session.current_module.set_option.assert_called_with("TARGET", '192.168.1.1')
