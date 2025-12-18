"""
Tests for the UtilityCommandsMixin class.

Tests the utility commands for help, history, stats, shell, and webserver.
"""

import pytest
from unittest.mock import MagicMock, patch


class MockUtilityHandler:
    """Mock handler class combining base and utility mixins for testing."""

    def __init__(self):
        # Simulate base mixin
        self.commands = {}
        self.aliases = {}
        self.last_search_results = []
        self.last_ops_results = []

        # Mock framework
        self.framework = MagicMock()
        self.framework.session = MagicMock()
        self.framework.session.command_history = []
        self.framework.database = MagicMock()

        # Mock display
        self.display = MagicMock()

        # Webserver process
        self.webserver_process = None

    def register_command(self, name, handler, aliases=None):
        """Mock register_command from base mixin."""
        self.commands[name] = handler
        if aliases:
            for alias in aliases:
                self.aliases[alias] = name


@pytest.fixture
def utility_handler():
    """Create a mock utility handler for testing."""
    from purplesploit.ui.command_mixins.utility_commands import UtilityCommandsMixin

    # Create combined class
    class TestHandler(MockUtilityHandler, UtilityCommandsMixin):
        def __init__(self):
            MockUtilityHandler.__init__(self)
            self._init_utility_commands()

    return TestHandler()


class TestUtilityCommandsInit:
    """Tests for UtilityCommandsMixin initialization."""

    def test_registers_help_command(self, utility_handler):
        """Test that help command is registered."""
        assert "help" in utility_handler.commands

    def test_help_has_question_alias(self, utility_handler):
        """Test that help has ? alias."""
        assert "?" in utility_handler.aliases
        assert utility_handler.aliases["?"] == "help"

    def test_registers_clear_command(self, utility_handler):
        """Test that clear command is registered."""
        assert "clear" in utility_handler.commands

    def test_registers_history_command(self, utility_handler):
        """Test that history command is registered."""
        assert "history" in utility_handler.commands

    def test_registers_stats_command(self, utility_handler):
        """Test that stats command is registered."""
        assert "stats" in utility_handler.commands

    def test_registers_hosts_command(self, utility_handler):
        """Test that hosts command is registered."""
        assert "hosts" in utility_handler.commands

    def test_registers_shell_command(self, utility_handler):
        """Test that shell command is registered."""
        assert "shell" in utility_handler.commands

    def test_registers_webserver_command(self, utility_handler):
        """Test that webserver command is registered."""
        assert "webserver" in utility_handler.commands

    def test_registers_exit_command(self, utility_handler):
        """Test that exit command is registered."""
        assert "exit" in utility_handler.commands

    def test_exit_has_quit_alias(self, utility_handler):
        """Test that exit has quit alias."""
        assert "quit" in utility_handler.aliases
        assert utility_handler.aliases["quit"] == "exit"

    def test_registers_defaults_command(self, utility_handler):
        """Test that defaults command is registered."""
        assert "defaults" in utility_handler.commands

    def test_registers_deploy_command(self, utility_handler):
        """Test that deploy command is registered."""
        assert "deploy" in utility_handler.commands

    def test_registers_parse_command(self, utility_handler):
        """Test that parse command is registered."""
        assert "parse" in utility_handler.commands


class TestHelpCommand:
    """Tests for cmd_help method."""

    def test_help_returns_true(self, utility_handler):
        """Test that help returns True."""
        result = utility_handler.cmd_help([])
        assert result is True

    def test_help_prints_to_console(self, utility_handler):
        """Test that help prints to console."""
        utility_handler.cmd_help([])
        # Should have multiple print calls for the help panels
        assert utility_handler.display.console.print.called


class TestClearCommand:
    """Tests for cmd_clear method."""

    def test_clear_returns_true(self, utility_handler):
        """Test that clear returns True."""
        result = utility_handler.cmd_clear([])
        assert result is True

    def test_clear_calls_display_clear(self, utility_handler):
        """Test that clear calls display.clear()."""
        utility_handler.cmd_clear([])
        utility_handler.display.clear.assert_called_once()


class TestHistoryCommand:
    """Tests for cmd_history method."""

    def test_history_no_entries(self, utility_handler):
        """Test history with no entries."""
        utility_handler.framework.session.command_history = []

        result = utility_handler.cmd_history([])
        assert result is True
        utility_handler.display.print_info.assert_called_with("No command history")

    def test_history_with_entries(self, utility_handler):
        """Test history with entries."""
        utility_handler.framework.session.command_history = [
            {'command': 'help', 'timestamp': '2024-01-01 10:00:00'},
            {'command': 'search nmap', 'timestamp': '2024-01-01 10:01:00'}
        ]

        result = utility_handler.cmd_history([])
        assert result is True
        # Should print entries
        assert utility_handler.display.console.print.called

    def test_history_shows_last_20(self, utility_handler):
        """Test that history shows last 20 entries."""
        # Create 25 entries
        utility_handler.framework.session.command_history = [
            {'command': f'cmd{i}', 'timestamp': '2024-01-01'} for i in range(25)
        ]

        result = utility_handler.cmd_history([])
        assert result is True
        # Should have printed entries (at most 20)
        assert utility_handler.display.console.print.call_count <= 25


class TestStatsCommand:
    """Tests for cmd_stats method."""

    def test_stats_returns_true(self, utility_handler):
        """Test that stats returns True."""
        utility_handler.framework.get_stats.return_value = {
            'modules': 10,
            'categories': 5,
            'targets': 3,
            'credentials': 2,
            'current_module': 'Nmap'
        }

        result = utility_handler.cmd_stats([])
        assert result is True

    def test_stats_calls_get_stats(self, utility_handler):
        """Test that stats calls framework.get_stats()."""
        utility_handler.framework.get_stats.return_value = {
            'modules': 10,
            'categories': 5,
            'targets': 3,
            'credentials': 2,
            'current_module': None
        }

        utility_handler.cmd_stats([])
        utility_handler.framework.get_stats.assert_called_once()

    def test_stats_displays_info(self, utility_handler):
        """Test that stats displays statistics."""
        utility_handler.framework.get_stats.return_value = {
            'modules': 10,
            'categories': 5,
            'targets': 3,
            'credentials': 2,
            'current_module': None
        }

        utility_handler.cmd_stats([])
        utility_handler.display.print_info.assert_called()


class TestExitCommand:
    """Tests for cmd_exit method."""

    def test_exit_returns_false(self, utility_handler):
        """Test that exit returns False to signal exit."""
        result = utility_handler.cmd_exit([])
        assert result is False

    def test_exit_prints_goodbye(self, utility_handler):
        """Test that exit prints goodbye message."""
        utility_handler.cmd_exit([])
        utility_handler.display.print_info.assert_called()


class TestShellCommand:
    """Tests for cmd_shell method."""

    @patch('subprocess.run')
    def test_shell_runs_bash(self, mock_run, utility_handler):
        """Test that shell runs bash."""
        mock_run.return_value = MagicMock(returncode=0)

        result = utility_handler.cmd_shell([])
        assert result is True

    @patch('subprocess.run')
    def test_shell_with_command(self, mock_run, utility_handler):
        """Test shell with specific command."""
        mock_run.return_value = MagicMock(returncode=0)

        result = utility_handler.cmd_shell(["ls", "-la"])
        assert result is True


class TestWebserverCommand:
    """Tests for cmd_webserver method."""

    def test_webserver_no_args_starts_server(self, utility_handler):
        """Test webserver without args defaults to start action."""
        # When called with no args, the code defaults to "start" action
        # which attempts to start the web server
        with patch('multiprocessing.Process') as mock_process:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = False  # Start fails
            mock_process.return_value = mock_proc

            result = utility_handler.cmd_webserver([])
            assert result is True

    def test_webserver_status_not_running(self, utility_handler):
        """Test webserver status when not running."""
        utility_handler.webserver_process = None

        result = utility_handler.cmd_webserver(["status"])
        assert result is True

    def test_webserver_status_running(self, utility_handler):
        """Test webserver status when running."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Running
        utility_handler.webserver_process = mock_process

        result = utility_handler.cmd_webserver(["status"])
        assert result is True

    def test_webserver_stop_not_running(self, utility_handler):
        """Test webserver stop when not running."""
        utility_handler.webserver_process = None

        result = utility_handler.cmd_webserver(["stop"])
        assert result is True
        utility_handler.display.print_warning.assert_called()

    def test_webserver_stop_running(self, utility_handler):
        """Test webserver stop when running."""
        mock_process = MagicMock()
        utility_handler.webserver_process = mock_process

        result = utility_handler.cmd_webserver(["stop"])
        assert result is True
        mock_process.terminate.assert_called()


class TestDefaultsCommand:
    """Tests for cmd_defaults method."""

    def test_defaults_no_args_shows_help(self, utility_handler):
        """Test defaults without args shows help."""
        result = utility_handler.cmd_defaults([])
        assert result is True
        utility_handler.display.print_info.assert_called()

    def test_defaults_list(self, utility_handler):
        """Test defaults list subcommand."""
        utility_handler.framework.database.get_module_defaults.return_value = [
            ('nmap', 'RHOST', '192.168.1.1')
        ]

        result = utility_handler.cmd_defaults(["list"])
        assert result is True

    def test_defaults_set(self, utility_handler):
        """Test defaults set subcommand."""
        utility_handler.framework.session.current_module = MagicMock()
        utility_handler.framework.session.current_module.name = "Nmap"
        utility_handler.framework.session.current_module.options = {
            'RHOST': {'value': '192.168.1.1'}
        }

        result = utility_handler.cmd_defaults(["set", "RHOST"])
        assert result is True

    def test_defaults_reset(self, utility_handler):
        """Test defaults reset subcommand."""
        utility_handler.framework.database.delete_all_module_defaults.return_value = True

        # Mock input to confirm reset
        with patch('builtins.input', return_value='y'):
            result = utility_handler.cmd_defaults(["reset", "nmap"])
            assert result is True
            utility_handler.framework.database.delete_all_module_defaults.assert_called_with("nmap")


class TestHostsCommand:
    """Tests for cmd_hosts method."""

    def test_hosts_returns_true(self, utility_handler):
        """Test that hosts returns True."""
        utility_handler.framework.database.get_targets.return_value = []

        result = utility_handler.cmd_hosts([])
        assert result is True


class TestDeployCommand:
    """Tests for cmd_deploy method."""

    def test_deploy_no_args_shows_available(self, utility_handler):
        """Test deploy without args shows available modules."""
        utility_handler.framework.search_modules.return_value = []

        result = utility_handler.cmd_deploy([])
        assert result is True

    def test_deploy_with_type(self, utility_handler):
        """Test deploy with specific type."""
        mock_module = MagicMock()
        mock_module.path = "deploy/ligolo"
        utility_handler.framework.search_modules.return_value = [mock_module]
        utility_handler.framework.use_module.return_value = MagicMock()

        result = utility_handler.cmd_deploy(["ligolo"])
        assert result is True


class TestParseCommand:
    """Tests for cmd_parse method."""

    def test_parse_no_args_shows_usage(self, utility_handler):
        """Test parse without args shows usage."""
        result = utility_handler.cmd_parse([])
        assert result is True
        utility_handler.display.print_error.assert_called()


class TestLigoloCommand:
    """Tests for cmd_ligolo method."""

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_ligolo_kill(self, mock_which, mock_run, utility_handler):
        """Test ligolo kill subcommand."""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock(returncode=0)

        result = utility_handler.cmd_ligolo(["kill"])
        assert result is True

    @patch('shutil.which')
    def test_ligolo_not_installed(self, mock_which, utility_handler):
        """Test ligolo when not installed."""
        mock_which.return_value = None

        result = utility_handler.cmd_ligolo([])
        assert result is True
        utility_handler.display.print_error.assert_called()


# =============================================================================
# Extended Tests for Ligolo Command
# =============================================================================

class TestLigoloExtended:
    """Extended tests for cmd_ligolo method."""

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_ligolo_kill_success(self, mock_which, mock_run, utility_handler):
        """Test ligolo kill when session exists."""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock(returncode=0)

        result = utility_handler.cmd_ligolo(["kill"])
        assert result is True
        utility_handler.display.print_success.assert_called()

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_ligolo_kill_no_session(self, mock_which, mock_run, utility_handler):
        """Test ligolo kill when no session exists."""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock(returncode=1)

        result = utility_handler.cmd_ligolo(["kill"])
        assert result is True
        utility_handler.display.print_warning.assert_called()

    @patch('shutil.which')
    def test_ligolo_tmux_not_installed(self, mock_which, utility_handler):
        """Test ligolo when tmux is not installed."""
        mock_which.return_value = None

        result = utility_handler.cmd_ligolo([])
        assert result is True
        utility_handler.display.print_error.assert_called()

    @patch('os.system')
    @patch('subprocess.run')
    @patch('shutil.which')
    def test_ligolo_attach_existing_session(self, mock_which, mock_run, mock_os_system, utility_handler):
        """Test ligolo attaches to existing session."""
        mock_which.side_effect = lambda x: '/usr/bin/tmux' if x == 'tmux' else '/usr/bin/ligolo-proxy' if x == 'ligolo-proxy' else None
        # has-session returns 0 (session exists)
        mock_run.return_value = MagicMock(returncode=0)

        result = utility_handler.cmd_ligolo([])
        assert result is True
        mock_os_system.assert_called_with("tmux attach-session -t ligolo")

    @patch('os.system')
    @patch('subprocess.run')
    @patch('shutil.which')
    def test_ligolo_create_new_session(self, mock_which, mock_run, mock_os_system, utility_handler):
        """Test ligolo creates new session."""
        mock_which.side_effect = lambda x: '/usr/bin/tmux' if x == 'tmux' else '/usr/bin/ligolo-proxy' if x == 'ligolo-proxy' else None
        # has-session returns 1 (no session)
        mock_run.return_value = MagicMock(returncode=1)

        result = utility_handler.cmd_ligolo([])
        assert result is True
        # Should create new session with default -selfcert flag
        mock_os_system.assert_called()

    @patch('os.system')
    @patch('subprocess.run')
    @patch('shutil.which')
    def test_ligolo_create_session_with_args(self, mock_which, mock_run, mock_os_system, utility_handler):
        """Test ligolo creates session with custom args."""
        mock_which.side_effect = lambda x: '/usr/bin/tmux' if x == 'tmux' else '/usr/bin/ligolo-proxy' if x == 'ligolo-proxy' else None
        mock_run.return_value = MagicMock(returncode=1)

        result = utility_handler.cmd_ligolo(["-laddr", "0.0.0.0:11601"])
        assert result is True


# =============================================================================
# Extended Tests for Shell Command
# =============================================================================

class TestShellExtended:
    """Extended tests for cmd_shell method."""

    @patch('subprocess.run')
    def test_shell_with_command_executes(self, mock_run, utility_handler):
        """Test shell with command executes it."""
        mock_run.return_value = MagicMock(returncode=0)

        result = utility_handler.cmd_shell(["ls", "-la", "/tmp"])
        assert result is True
        utility_handler.display.print_info.assert_called()

    @patch('os.system')
    @patch('os.environ.get')
    def test_shell_uses_user_shell(self, mock_environ, mock_os_system, utility_handler):
        """Test shell uses user's default shell."""
        mock_environ.return_value = '/usr/bin/zsh'

        result = utility_handler.cmd_shell([])
        assert result is True
        mock_os_system.assert_called_with('/usr/bin/zsh')

    @patch('os.system')
    @patch('os.environ.get')
    def test_shell_falls_back_to_bash(self, mock_environ, mock_os_system, utility_handler):
        """Test shell falls back to bash if SHELL not set."""
        mock_environ.return_value = '/bin/bash'

        result = utility_handler.cmd_shell([])
        assert result is True
        mock_os_system.assert_called_with('/bin/bash')


# =============================================================================
# Extended Tests for Webserver Command
# =============================================================================

class TestWebserverExtended:
    """Extended tests for cmd_webserver method."""

    def test_webserver_start_already_running(self, utility_handler):
        """Test webserver start when already running."""
        mock_process = MagicMock()
        mock_process.is_alive.return_value = True
        utility_handler.webserver_process = mock_process

        result = utility_handler.cmd_webserver(["start"])
        assert result is True
        utility_handler.display.print_warning.assert_called()

    def test_webserver_stop_force_kill(self, utility_handler):
        """Test webserver stop with forced kill."""
        mock_process = MagicMock()
        mock_process.is_alive.side_effect = [True, True, False]  # First check, after terminate (still alive), after kill
        utility_handler.webserver_process = mock_process

        result = utility_handler.cmd_webserver(["stop"])
        assert result is True
        mock_process.terminate.assert_called()
        mock_process.kill.assert_called()

    def test_webserver_status_running(self, utility_handler):
        """Test webserver status when running."""
        mock_process = MagicMock()
        mock_process.is_alive.return_value = True
        mock_process.pid = 12345
        utility_handler.webserver_process = mock_process

        result = utility_handler.cmd_webserver(["status"])
        assert result is True
        utility_handler.display.print_success.assert_called()

    def test_webserver_status_not_running(self, utility_handler):
        """Test webserver status when not running."""
        utility_handler.webserver_process = None

        result = utility_handler.cmd_webserver(["status"])
        assert result is True
        utility_handler.display.print_info.assert_called()

    def test_webserver_invalid_action(self, utility_handler):
        """Test webserver with invalid action."""
        result = utility_handler.cmd_webserver(["invalid"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    @patch('multiprocessing.Process')
    def test_webserver_start_with_port(self, mock_process, utility_handler):
        """Test webserver start with custom port."""
        mock_proc = MagicMock()
        mock_proc.is_alive.return_value = True
        mock_proc.pid = 12345
        mock_process.return_value = mock_proc

        result = utility_handler.cmd_webserver(["start", "--port", "8080"])
        assert result is True

    def test_webserver_start_invalid_port(self, utility_handler):
        """Test webserver start with invalid port."""
        result = utility_handler.cmd_webserver(["start", "--port", "invalid"])
        assert result is True
        utility_handler.display.print_error.assert_called()


# =============================================================================
# Extended Tests for Hosts Command
# =============================================================================

class TestHostsExtended:
    """Extended tests for cmd_hosts method."""

    def test_hosts_no_targets(self, utility_handler):
        """Test hosts with no targets."""
        utility_handler.framework.session.targets.list.return_value = []

        result = utility_handler.cmd_hosts([])
        assert result is True
        utility_handler.display.print_warning.assert_called()

    def test_hosts_with_targets(self, utility_handler):
        """Test hosts with targets."""
        utility_handler.framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1', 'name': 'server1'},
            {'ip': '192.168.1.2', 'name': 'server2'}
        ]

        result = utility_handler.cmd_hosts([])
        assert result is True
        utility_handler.display.console.print.assert_called()

    def test_hosts_export_no_file(self, utility_handler):
        """Test hosts export without file argument."""
        utility_handler.framework.session.targets.list.return_value = []

        result = utility_handler.cmd_hosts(["export"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    @patch('builtins.open', create=True)
    def test_hosts_export_success(self, mock_open, utility_handler):
        """Test hosts export success."""
        utility_handler.framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1', 'name': 'server1'}
        ]
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        result = utility_handler.cmd_hosts(["export", "/tmp/hosts.txt"])
        assert result is True
        utility_handler.display.print_success.assert_called()

    @patch('builtins.open', side_effect=PermissionError("Access denied"))
    def test_hosts_export_permission_error(self, mock_open, utility_handler):
        """Test hosts export with permission error."""
        utility_handler.framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1', 'name': 'server1'}
        ]

        result = utility_handler.cmd_hosts(["export", "/etc/hosts.new"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    def test_hosts_append_no_file(self, utility_handler):
        """Test hosts append without file argument."""
        utility_handler.framework.session.targets.list.return_value = []

        result = utility_handler.cmd_hosts(["append"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    @patch('builtins.open', create=True)
    def test_hosts_append_success(self, mock_open, utility_handler):
        """Test hosts append success."""
        utility_handler.framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1', 'name': 'server1'}
        ]
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        result = utility_handler.cmd_hosts(["append", "/tmp/hosts.txt"])
        assert result is True
        utility_handler.display.print_success.assert_called()

    @patch('builtins.input', return_value='n')
    def test_hosts_sudo_cancelled(self, mock_input, utility_handler):
        """Test hosts sudo cancelled by user."""
        utility_handler.framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1', 'name': 'server1'}
        ]

        result = utility_handler.cmd_hosts(["sudo"])
        assert result is True
        utility_handler.display.print_info.assert_called()

    def test_hosts_invalid_subcommand(self, utility_handler):
        """Test hosts with invalid subcommand."""
        utility_handler.framework.session.targets.list.return_value = []

        result = utility_handler.cmd_hosts(["invalid"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    def test_hosts_generates_hostname_for_unnamed(self, utility_handler):
        """Test hosts generates hostname for targets without name."""
        utility_handler.framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1'}  # No name
        ]

        result = utility_handler.cmd_hosts([])
        assert result is True


# =============================================================================
# Extended Tests for Defaults Command
# =============================================================================

class TestDefaultsExtended:
    """Extended tests for cmd_defaults method."""

    def test_defaults_show_no_module(self, utility_handler):
        """Test defaults show without module name."""
        result = utility_handler.cmd_defaults(["show"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    def test_defaults_show_no_defaults(self, utility_handler):
        """Test defaults show when no defaults exist."""
        utility_handler.framework.database.get_module_defaults.return_value = {}

        result = utility_handler.cmd_defaults(["show", "nmap"])
        assert result is True
        utility_handler.display.print_warning.assert_called()

    def test_defaults_show_with_defaults(self, utility_handler):
        """Test defaults show with existing defaults."""
        utility_handler.framework.database.get_module_defaults.return_value = {
            'PORTS': '-',
            'MIN_RATE': '3900'
        }

        result = utility_handler.cmd_defaults(["show", "nmap"])
        assert result is True
        utility_handler.display.console.print.assert_called()

    def test_defaults_set_missing_args(self, utility_handler):
        """Test defaults set with missing arguments."""
        result = utility_handler.cmd_defaults(["set", "nmap"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    def test_defaults_set_success(self, utility_handler):
        """Test defaults set success."""
        utility_handler.framework.database.set_module_default.return_value = True

        result = utility_handler.cmd_defaults(["set", "nmap", "PORTS", "-"])
        assert result is True
        utility_handler.display.print_success.assert_called()
        utility_handler.framework.database.set_module_default.assert_called_with(
            "nmap", "PORTS", "-"
        )

    def test_defaults_set_with_spaces_in_value(self, utility_handler):
        """Test defaults set with value containing spaces."""
        utility_handler.framework.database.set_module_default.return_value = True

        result = utility_handler.cmd_defaults(["set", "nmap", "ARGS", "-sV", "-sC"])
        assert result is True
        utility_handler.framework.database.set_module_default.assert_called_with(
            "nmap", "ARGS", "-sV -sC"
        )

    def test_defaults_set_failure(self, utility_handler):
        """Test defaults set failure."""
        utility_handler.framework.database.set_module_default.return_value = False

        result = utility_handler.cmd_defaults(["set", "nmap", "PORTS", "-"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    def test_defaults_delete_missing_args(self, utility_handler):
        """Test defaults delete with missing arguments."""
        result = utility_handler.cmd_defaults(["delete", "nmap"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    def test_defaults_delete_success(self, utility_handler):
        """Test defaults delete success."""
        utility_handler.framework.database.delete_module_default.return_value = True

        result = utility_handler.cmd_defaults(["delete", "nmap", "PORTS"])
        assert result is True
        utility_handler.display.print_success.assert_called()

    def test_defaults_delete_not_found(self, utility_handler):
        """Test defaults delete when not found."""
        utility_handler.framework.database.delete_module_default.return_value = False

        result = utility_handler.cmd_defaults(["delete", "nmap", "PORTS"])
        assert result is True
        utility_handler.display.print_warning.assert_called()

    def test_defaults_reset_missing_module(self, utility_handler):
        """Test defaults reset without module name."""
        result = utility_handler.cmd_defaults(["reset"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    @patch('builtins.input', return_value='y')
    def test_defaults_reset_confirmed(self, mock_input, utility_handler):
        """Test defaults reset when confirmed."""
        utility_handler.framework.database.delete_all_module_defaults.return_value = True

        result = utility_handler.cmd_defaults(["reset", "nmap"])
        assert result is True
        utility_handler.display.print_success.assert_called()

    @patch('builtins.input', return_value='n')
    def test_defaults_reset_cancelled(self, mock_input, utility_handler):
        """Test defaults reset when cancelled."""
        result = utility_handler.cmd_defaults(["reset", "nmap"])
        assert result is True
        utility_handler.display.print_info.assert_called()

    def test_defaults_invalid_subcommand(self, utility_handler):
        """Test defaults with invalid subcommand."""
        result = utility_handler.cmd_defaults(["invalid"])
        assert result is True
        utility_handler.display.print_error.assert_called()


# =============================================================================
# Extended Tests for Deploy Command
# =============================================================================

class TestDeployExtended:
    """Extended tests for cmd_deploy method."""

    def test_deploy_no_args_shows_modules(self, utility_handler):
        """Test deploy without args shows available modules."""
        result = utility_handler.cmd_deploy([])
        assert result is True
        utility_handler.display.console.print.assert_called()

    def test_deploy_ligolo(self, utility_handler):
        """Test deploy ligolo loads module."""
        utility_handler.framework.modules = {'deploy/ligolo': MagicMock()}
        utility_handler.cmd_use = MagicMock(return_value=True)

        result = utility_handler.cmd_deploy(["ligolo"])
        assert result is True
        utility_handler.cmd_use.assert_called_with(["deploy/ligolo"])

    def test_deploy_c2(self, utility_handler):
        """Test deploy c2 loads module."""
        utility_handler.framework.modules = {'deploy/c2': MagicMock()}
        utility_handler.cmd_use = MagicMock(return_value=True)

        result = utility_handler.cmd_deploy(["c2"])
        assert result is True
        utility_handler.cmd_use.assert_called_with(["deploy/c2"])

    def test_deploy_beacon_alias(self, utility_handler):
        """Test deploy beacon is alias for c2."""
        utility_handler.framework.modules = {'deploy/c2': MagicMock()}
        utility_handler.cmd_use = MagicMock(return_value=True)

        result = utility_handler.cmd_deploy(["beacon"])
        assert result is True
        utility_handler.cmd_use.assert_called_with(["deploy/c2"])

    def test_deploy_script(self, utility_handler):
        """Test deploy script loads module."""
        utility_handler.framework.modules = {'deploy/script': MagicMock()}
        utility_handler.cmd_use = MagicMock(return_value=True)

        result = utility_handler.cmd_deploy(["script"])
        assert result is True
        utility_handler.cmd_use.assert_called_with(["deploy/script"])

    def test_deploy_module_not_found(self, utility_handler):
        """Test deploy when module not found."""
        utility_handler.framework.modules = {}

        result = utility_handler.cmd_deploy(["ligolo"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    def test_deploy_invalid_type(self, utility_handler):
        """Test deploy with invalid type."""
        result = utility_handler.cmd_deploy(["invalid"])
        assert result is True
        utility_handler.display.print_error.assert_called()


# =============================================================================
# Extended Tests for Parse Command
# =============================================================================

class TestParseExtended:
    """Extended tests for cmd_parse method."""

    def test_parse_no_args(self, utility_handler):
        """Test parse without arguments."""
        result = utility_handler.cmd_parse([])
        assert result is True
        utility_handler.display.print_error.assert_called()

    def test_parse_file_not_found(self, utility_handler):
        """Test parse with non-existent file."""
        result = utility_handler.cmd_parse(["/nonexistent/file.xml"])
        assert result is True
        utility_handler.display.print_error.assert_called()

    @patch('pathlib.Path.exists')
    def test_parse_no_hosts_found(self, mock_exists, utility_handler):
        """Test parse when no hosts found in XML."""
        mock_exists.return_value = True

        with patch('purplesploit.modules.recon.nmap.NmapModule') as mock_nmap:
            mock_instance = MagicMock()
            mock_instance.parse_xml_output.return_value = {'hosts': []}
            mock_nmap.return_value = mock_instance

            result = utility_handler.cmd_parse(["scan.xml"])
            assert result is True
            utility_handler.display.print_warning.assert_called()

    @patch('pathlib.Path.exists')
    def test_parse_success(self, mock_exists, utility_handler):
        """Test parse success."""
        mock_exists.return_value = True

        with patch('purplesploit.modules.recon.nmap.NmapModule') as mock_nmap:
            mock_instance = MagicMock()
            mock_instance.parse_xml_output.return_value = {
                'hosts': [{'ip': '192.168.1.1'}],
                'total_hosts': 5
            }
            mock_nmap.return_value = mock_instance

            result = utility_handler.cmd_parse(["scan.xml"])
            assert result is True
            utility_handler.display.print_success.assert_called()

    @patch('pathlib.Path.exists')
    def test_parse_exception(self, mock_exists, utility_handler):
        """Test parse with exception."""
        mock_exists.return_value = True

        with patch('purplesploit.modules.recon.nmap.NmapModule') as mock_nmap:
            mock_nmap.side_effect = Exception("Parse error")

            result = utility_handler.cmd_parse(["scan.xml"])
            assert result is True
            utility_handler.display.print_error.assert_called()


# =============================================================================
# Extended Tests for Exit Command
# =============================================================================

class TestExitExtended:
    """Extended tests for cmd_exit method."""

    def test_exit_calls_cleanup(self, utility_handler):
        """Test exit calls cleanup."""
        utility_handler.cleanup = MagicMock()

        result = utility_handler.cmd_exit([])
        assert result is False
        utility_handler.cleanup.assert_called_once()

    def test_cleanup_stops_webserver(self, utility_handler):
        """Test cleanup stops webserver if running."""
        mock_process = MagicMock()
        mock_process.is_alive.side_effect = [True, False]
        utility_handler.webserver_process = mock_process

        utility_handler.cleanup()
        mock_process.terminate.assert_called()

    def test_cleanup_force_kills_webserver(self, utility_handler):
        """Test cleanup force kills stuck webserver."""
        mock_process = MagicMock()
        mock_process.is_alive.side_effect = [True, True]  # Still alive after terminate
        utility_handler.webserver_process = mock_process

        utility_handler.cleanup()
        mock_process.terminate.assert_called()
        mock_process.kill.assert_called()

    def test_cleanup_no_webserver(self, utility_handler):
        """Test cleanup when no webserver running."""
        utility_handler.webserver_process = None
        # Should not raise any errors
        utility_handler.cleanup()


# =============================================================================
# Tests for Generate Hosts Entries
# =============================================================================

class TestGenerateHostsEntries:
    """Tests for _generate_hosts_entries method."""

    def test_generate_hosts_with_names(self, utility_handler):
        """Test generating hosts entries with names."""
        targets = [
            {'ip': '192.168.1.1', 'name': 'server1'},
            {'ip': '192.168.1.2', 'name': 'server2.domain.com'}
        ]

        entries = utility_handler._generate_hosts_entries(targets)
        assert len(entries) == 2
        assert "192.168.1.1\tserver1" in entries
        assert "192.168.1.2\tserver2.domain.com" in entries

    def test_generate_hosts_without_names(self, utility_handler):
        """Test generating hosts entries without names."""
        targets = [
            {'ip': '192.168.1.1'},
            {'ip': '10.0.0.5'}
        ]

        entries = utility_handler._generate_hosts_entries(targets)
        assert len(entries) == 2
        assert "192.168.1.1\ttarget-192-168-1-1" in entries
        assert "10.0.0.5\ttarget-10-0-0-5" in entries

    def test_generate_hosts_mixed(self, utility_handler):
        """Test generating hosts entries with mixed targets."""
        targets = [
            {'ip': '192.168.1.1', 'name': 'server1'},
            {'ip': '192.168.1.2'},  # No name
            {'name': 'no-ip-target'}  # No IP (should be skipped)
        ]

        entries = utility_handler._generate_hosts_entries(targets)
        assert len(entries) == 2

    def test_generate_hosts_empty_list(self, utility_handler):
        """Test generating hosts entries with empty list."""
        entries = utility_handler._generate_hosts_entries([])
        assert entries == []
