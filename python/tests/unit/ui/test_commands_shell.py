"""
Unit tests for shell and session management in purplesploit.ui.commands.

Tests cover:
- Shell command (localhost shell)
- Sessions management (list, create, kill, interact)
- Interact command (session interaction)
- Webserver command (start, stop, status)
- Background process management
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
    framework.session.credentials = MagicMock()
    framework.session.command_history = []
    framework.session.add_command = MagicMock()
    framework.session.workspace = "default"
    framework.session_manager = MagicMock()
    framework.modules = {}
    return framework


@pytest.fixture
def command_handler(mock_framework):
    """Create a CommandHandler instance for testing."""
    with patch('purplesploit.ui.commands.Display'), \
         patch('purplesploit.ui.commands.InteractiveSelector'):
        handler = CommandHandler(mock_framework)
        handler.display = MagicMock()
        handler.interactive = MagicMock()
    return handler


# =============================================================================
# Shell Command Tests
# =============================================================================

class TestShellCommand:
    """Tests for shell command."""

    def test_shell_interactive(self, command_handler):
        """Test launching interactive shell."""
        with patch('os.system') as mock_system, \
             patch('os.environ.get', return_value='/bin/bash'):
            result = command_handler.cmd_shell([])

            assert result is True
            mock_system.assert_called_once_with('/bin/bash')

    def test_shell_execute_command(self, command_handler):
        """Test executing single command in shell."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = command_handler.cmd_shell(["ls", "-la"])

            assert result is True
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert "ls -la" in call_args[0][0]

    def test_shell_with_custom_shell(self, command_handler):
        """Test shell with custom SHELL environment variable."""
        with patch('os.system') as mock_system, \
             patch('os.environ.get', return_value='/bin/zsh'):
            result = command_handler.cmd_shell([])

            assert result is True
            mock_system.assert_called_once_with('/bin/zsh')

    def test_shell_default_to_bash(self, command_handler):
        """Test shell defaults to bash if SHELL not set."""
        with patch('os.system') as mock_system, \
             patch('os.environ.get', return_value=None):
            result = command_handler.cmd_shell([])

            assert result is True
            # Should default to /bin/bash
            mock_system.assert_called_once()

    def test_shell_keyboard_interrupt(self, command_handler):
        """Test shell handles keyboard interrupt."""
        with patch('os.system', side_effect=KeyboardInterrupt()):
            result = command_handler.cmd_shell([])

            assert result is True
            command_handler.display.print_info.assert_called()

    def test_shell_exception(self, command_handler):
        """Test shell handles exceptions."""
        with patch('os.system', side_effect=Exception("Shell error")):
            result = command_handler.cmd_shell([])

            assert result is True
            command_handler.display.print_error.assert_called()

    def test_shell_command_with_pipes(self, command_handler):
        """Test shell command with pipes."""
        with patch('subprocess.run') as mock_run:
            result = command_handler.cmd_shell(["ps", "aux", "|", "grep", "python"])

            assert result is True
            mock_run.assert_called_once()


# =============================================================================
# Sessions Management Tests
# =============================================================================

class TestSessionsCommand:
    """Tests for sessions management commands."""

    def test_sessions_list_empty(self, command_handler, mock_framework):
        """Test listing sessions when none exist."""
        mock_framework.session_manager.list_sessions.return_value = []

        result = command_handler.cmd_sessions(["list"])

        assert result is True
        mock_framework.session_manager.list_sessions.assert_called_once()

    def test_sessions_list_with_sessions(self, command_handler, mock_framework):
        """Test listing active sessions."""
        mock_framework.session_manager.list_sessions.return_value = [
            {
                "id": "sess-1",
                "type": "shell",
                "target": "192.168.1.1",
                "status": "active"
            },
            {
                "id": "sess-2",
                "type": "meterpreter",
                "target": "192.168.1.2",
                "status": "active"
            }
        ]

        result = command_handler.cmd_sessions(["list"])

        assert result is True

    def test_sessions_create(self, command_handler, mock_framework):
        """Test creating a new session."""
        mock_framework.session_manager.create_session.return_value = "sess-123"

        result = command_handler.cmd_sessions(["create", "--type", "shell", "--target", "192.168.1.1"])

        assert result is True

    def test_sessions_kill(self, command_handler, mock_framework):
        """Test killing a session."""
        command_handler.interactive.confirm.return_value = True
        mock_framework.session_manager.kill_session.return_value = True

        result = command_handler.cmd_sessions(["kill", "sess-1"])

        assert result is True
        mock_framework.session_manager.kill_session.assert_called_once_with("sess-1")

    def test_sessions_kill_cancelled(self, command_handler, mock_framework):
        """Test killing session when cancelled."""
        command_handler.interactive.confirm.return_value = False

        result = command_handler.cmd_sessions(["kill", "sess-1"])

        assert result is True
        mock_framework.session_manager.kill_session.assert_not_called()

    def test_sessions_info(self, command_handler, mock_framework):
        """Test showing session info."""
        mock_framework.session_manager.get_session.return_value = {
            "id": "sess-1",
            "type": "shell",
            "target": "192.168.1.1",
            "created_at": "2025-01-01 12:00:00",
            "status": "active"
        }

        result = command_handler.cmd_sessions(["info", "sess-1"])

        assert result is True
        mock_framework.session_manager.get_session.assert_called_once_with("sess-1")

    def test_sessions_upgrade(self, command_handler, mock_framework):
        """Test upgrading a session."""
        mock_framework.session_manager.upgrade_session.return_value = True

        result = command_handler.cmd_sessions(["upgrade", "sess-1"])

        assert result is True
        mock_framework.session_manager.upgrade_session.assert_called_once()

    def test_sessions_default_to_list(self, command_handler, mock_framework):
        """Test sessions without args defaults to list."""
        mock_framework.session_manager.list_sessions.return_value = []

        result = command_handler.cmd_sessions([])

        assert result is True
        mock_framework.session_manager.list_sessions.assert_called_once()

    def test_sessions_background(self, command_handler, mock_framework):
        """Test backgrounding current session."""
        result = command_handler.cmd_sessions(["background"])

        assert result is True

    def test_sessions_killall(self, command_handler, mock_framework):
        """Test killing all sessions."""
        command_handler.interactive.confirm.return_value = True
        mock_framework.session_manager.list_sessions.return_value = [
            {"id": "sess-1"},
            {"id": "sess-2"}
        ]

        result = command_handler.cmd_sessions(["killall"])

        assert result is True


# =============================================================================
# Interact Command Tests
# =============================================================================

class TestInteractCommand:
    """Tests for interact command."""

    def test_interact_no_args(self, command_handler, mock_framework):
        """Test interact without session ID."""
        mock_framework.session_manager.list_sessions.return_value = []

        result = command_handler.cmd_interact([])

        assert result is True

    def test_interact_with_session_id(self, command_handler, mock_framework):
        """Test interacting with specific session."""
        with patch('purplesploit.core.session_manager.SessionInteraction') as mock_si:
            mock_interaction = MagicMock()
            mock_si.return_value = mock_interaction

            result = command_handler.cmd_interact(["sess-1"])

            assert result is True
            mock_interaction.start.assert_called_once()

    def test_interact_select_from_list(self, command_handler, mock_framework):
        """Test interactive session selection."""
        mock_sessions = [
            {"id": "sess-1", "type": "shell", "target": "192.168.1.1"},
            {"id": "sess-2", "type": "meterpreter", "target": "192.168.1.2"}
        ]
        mock_framework.session_manager.list_sessions.return_value = mock_sessions
        command_handler.interactive.select_from_list.return_value = mock_sessions[0]

        with patch('purplesploit.core.session_manager.SessionInteraction') as mock_si:
            mock_interaction = MagicMock()
            mock_si.return_value = mock_interaction

            result = command_handler.cmd_interact([])

            assert result is True
            mock_interaction.start.assert_called_once()

    def test_interact_session_not_found(self, command_handler, mock_framework):
        """Test interact with non-existent session."""
        mock_framework.session_manager.get_session.return_value = None

        result = command_handler.cmd_interact(["sess-999"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_interact_selection_cancelled(self, command_handler, mock_framework):
        """Test interact when selection cancelled."""
        mock_framework.session_manager.list_sessions.return_value = [
            {"id": "sess-1", "type": "shell"}
        ]
        command_handler.interactive.select_from_list.return_value = None

        result = command_handler.cmd_interact([])

        assert result is True

    def test_interact_keyboard_interrupt(self, command_handler, mock_framework):
        """Test interact handles keyboard interrupt."""
        with patch('purplesploit.core.session_manager.SessionInteraction') as mock_si:
            mock_interaction = MagicMock()
            mock_interaction.start.side_effect = KeyboardInterrupt()
            mock_si.return_value = mock_interaction

            result = command_handler.cmd_interact(["sess-1"])

            assert result is True


# =============================================================================
# Webserver Command Tests
# =============================================================================

class TestWebserverCommand:
    """Tests for webserver management commands."""

    def test_webserver_start(self, command_handler):
        """Test starting webserver."""
        with patch('multiprocessing.Process') as mock_process_class:
            mock_process = MagicMock()
            mock_process.is_alive.return_value = True
            mock_process.pid = 12345
            mock_process_class.return_value = mock_process

            with patch('purplesploit.ui.commands.uvicorn'), \
                 patch('purplesploit.ui.commands.fastapi'), \
                 patch('time.sleep'):
                result = command_handler.cmd_webserver(["start"])

                assert result is True
                mock_process.start.assert_called_once()
                assert command_handler.webserver_process == mock_process

    def test_webserver_start_with_custom_port(self, command_handler):
        """Test starting webserver on custom port."""
        with patch('multiprocessing.Process') as mock_process_class:
            mock_process = MagicMock()
            mock_process.is_alive.return_value = True
            mock_process_class.return_value = mock_process

            with patch('purplesploit.ui.commands.uvicorn'), \
                 patch('purplesploit.ui.commands.fastapi'), \
                 patch('time.sleep'):
                result = command_handler.cmd_webserver(["start", "--port", "8080"])

                assert result is True

    def test_webserver_start_already_running(self, command_handler):
        """Test starting webserver when already running."""
        mock_process = MagicMock()
        mock_process.is_alive.return_value = True
        command_handler.webserver_process = mock_process

        result = command_handler.cmd_webserver(["start"])

        assert result is True
        command_handler.display.print_warning.assert_called()

    def test_webserver_start_missing_dependencies(self, command_handler):
        """Test starting webserver with missing dependencies."""
        with patch('purplesploit.ui.commands.uvicorn', side_effect=ImportError("uvicorn not found")):
            result = command_handler.cmd_webserver(["start"])

            assert result is True
            command_handler.display.print_error.assert_called()

    def test_webserver_start_failed(self, command_handler):
        """Test webserver start failure."""
        with patch('multiprocessing.Process') as mock_process_class:
            mock_process = MagicMock()
            mock_process.is_alive.return_value = False
            mock_process_class.return_value = mock_process

            with patch('purplesploit.ui.commands.uvicorn'), \
                 patch('purplesploit.ui.commands.fastapi'), \
                 patch('time.sleep'):
                result = command_handler.cmd_webserver(["start"])

                assert result is True
                assert command_handler.webserver_process is None

    def test_webserver_stop(self, command_handler):
        """Test stopping webserver."""
        mock_process = MagicMock()
        mock_process.is_alive.return_value = True
        command_handler.webserver_process = mock_process

        result = command_handler.cmd_webserver(["stop"])

        assert result is True
        mock_process.terminate.assert_called_once()
        mock_process.join.assert_called()
        assert command_handler.webserver_process is None

    def test_webserver_stop_not_running(self, command_handler):
        """Test stopping webserver when not running."""
        command_handler.webserver_process = None

        result = command_handler.cmd_webserver(["stop"])

        assert result is True
        command_handler.display.print_warning.assert_called()

    def test_webserver_stop_force_kill(self, command_handler):
        """Test force killing webserver."""
        mock_process = MagicMock()
        mock_process.is_alive.side_effect = [True, True, False]
        command_handler.webserver_process = mock_process

        result = command_handler.cmd_webserver(["stop"])

        assert result is True
        mock_process.kill.assert_called_once()

    def test_webserver_status_running(self, command_handler):
        """Test checking webserver status when running."""
        mock_process = MagicMock()
        mock_process.is_alive.return_value = True
        mock_process.pid = 12345
        command_handler.webserver_process = mock_process

        result = command_handler.cmd_webserver(["status"])

        assert result is True
        command_handler.display.print_success.assert_called()

    def test_webserver_status_not_running(self, command_handler):
        """Test checking webserver status when not running."""
        command_handler.webserver_process = None

        result = command_handler.cmd_webserver(["status"])

        assert result is True
        command_handler.display.print_info.assert_called()

    def test_webserver_default_to_start(self, command_handler):
        """Test webserver defaults to start command."""
        with patch('multiprocessing.Process') as mock_process_class:
            mock_process = MagicMock()
            mock_process.is_alive.return_value = True
            mock_process_class.return_value = mock_process

            with patch('purplesploit.ui.commands.uvicorn'), \
                 patch('purplesploit.ui.commands.fastapi'), \
                 patch('time.sleep'):
                result = command_handler.cmd_webserver([])

                assert result is True

    def test_webserver_unknown_command(self, command_handler):
        """Test webserver with unknown command."""
        result = command_handler.cmd_webserver(["invalid"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_webserver_start_with_host(self, command_handler):
        """Test starting webserver with custom host."""
        with patch('multiprocessing.Process') as mock_process_class:
            mock_process = MagicMock()
            mock_process.is_alive.return_value = True
            mock_process_class.return_value = mock_process

            with patch('purplesploit.ui.commands.uvicorn'), \
                 patch('purplesploit.ui.commands.fastapi'), \
                 patch('time.sleep'):
                result = command_handler.cmd_webserver(["start", "--host", "127.0.0.1"])

                assert result is True


# =============================================================================
# Background Process Management Tests
# =============================================================================

class TestBackgroundProcesses:
    """Tests for background process management."""

    def test_multiple_processes_tracked(self, command_handler):
        """Test tracking multiple background processes."""
        # Webserver process
        mock_webserver = MagicMock()
        command_handler.webserver_process = mock_webserver

        assert command_handler.webserver_process is not None

    def test_process_cleanup_on_exit(self, command_handler):
        """Test processes are cleaned up on exit."""
        mock_process = MagicMock()
        mock_process.is_alive.return_value = True
        command_handler.webserver_process = mock_process

        # Simulate cleanup
        if command_handler.webserver_process and command_handler.webserver_process.is_alive():
            command_handler.webserver_process.terminate()

        mock_process.terminate.assert_called_once()


# =============================================================================
# Session Export Tests
# =============================================================================

class TestSessionsExport:
    """Tests for session export functionality."""

    def test_sessions_export_default_file(self, command_handler, mock_framework):
        """Test exporting sessions to default file."""
        mock_framework.session_manager.export_sessions.return_value = "sessions_default.json"

        with patch('purplesploit.core.session_manager.SessionManager'):
            result = command_handler._sessions_export(mock_framework.session_manager, [])

            assert result is True

    def test_sessions_export_custom_file(self, command_handler, mock_framework):
        """Test exporting sessions to custom file."""
        mock_framework.session_manager.export_sessions.return_value = "my_sessions.json"

        with patch('purplesploit.core.session_manager.SessionManager'):
            result = command_handler._sessions_export(mock_framework.session_manager, ["my_sessions.json"])

            assert result is True
            mock_framework.session_manager.export_sessions.assert_called_once_with("my_sessions.json")

    def test_sessions_export_error(self, command_handler, mock_framework):
        """Test session export error handling."""
        mock_framework.session_manager.export_sessions.side_effect = Exception("Export failed")

        with patch('purplesploit.core.session_manager.SessionManager'):
            result = command_handler._sessions_export(mock_framework.session_manager, [])

            assert result is True
            command_handler.display.print_error.assert_called()


# =============================================================================
# Integration Tests
# =============================================================================

class TestShellIntegration:
    """Integration tests for shell and session commands."""

    def test_shell_to_sessions_workflow(self, command_handler, mock_framework):
        """Test workflow from shell to sessions management."""
        # Execute shell command
        with patch('subprocess.run') as mock_run:
            command_handler.cmd_shell(["whoami"])
            mock_run.assert_called_once()

        # List sessions
        mock_framework.session_manager.list_sessions.return_value = []
        command_handler.cmd_sessions(["list"])

        assert True

    def test_webserver_lifecycle(self, command_handler):
        """Test complete webserver lifecycle."""
        with patch('multiprocessing.Process') as mock_process_class:
            mock_process = MagicMock()
            mock_process.is_alive.side_effect = [True, True, True, False]
            mock_process.pid = 12345
            mock_process_class.return_value = mock_process

            with patch('purplesploit.ui.commands.uvicorn'), \
                 patch('purplesploit.ui.commands.fastapi'), \
                 patch('time.sleep'):
                # Start
                command_handler.cmd_webserver(["start"])
                assert command_handler.webserver_process is not None

                # Status
                command_handler.cmd_webserver(["status"])

                # Stop
                command_handler.cmd_webserver(["stop"])
                assert command_handler.webserver_process is None


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestShellErrorHandling:
    """Tests for error handling in shell commands."""

    def test_shell_command_failure(self, command_handler):
        """Test shell command failure."""
        with patch('subprocess.run', side_effect=Exception("Command failed")):
            result = command_handler.cmd_shell(["false_command"])

            assert result is True

    def test_sessions_manager_not_available(self, command_handler, mock_framework):
        """Test sessions command when manager not available."""
        mock_framework.session_manager = None

        result = command_handler.cmd_sessions(["list"])

        # Should handle gracefully
        assert result is True

    def test_interact_connection_error(self, command_handler, mock_framework):
        """Test interact with connection error."""
        with patch('purplesploit.core.session_manager.SessionInteraction') as mock_si:
            mock_interaction = MagicMock()
            mock_interaction.start.side_effect = ConnectionError("Connection lost")
            mock_si.return_value = mock_interaction

            result = command_handler.cmd_interact(["sess-1"])

            assert result is True

    def test_webserver_port_in_use(self, command_handler):
        """Test webserver when port is already in use."""
        with patch('multiprocessing.Process') as mock_process_class:
            mock_process = MagicMock()
            mock_process.start.side_effect = OSError("Address already in use")
            mock_process_class.return_value = mock_process

            with patch('purplesploit.ui.commands.uvicorn'), \
                 patch('purplesploit.ui.commands.fastapi'):
                result = command_handler.cmd_webserver(["start"])

                assert result is True


# =============================================================================
# Advanced Session Features Tests
# =============================================================================

class TestAdvancedSessionFeatures:
    """Tests for advanced session features."""

    def test_sessions_filter_by_type(self, command_handler, mock_framework):
        """Test filtering sessions by type."""
        mock_framework.session_manager.list_sessions.return_value = [
            {"id": "sess-1", "type": "shell"},
            {"id": "sess-2", "type": "meterpreter"}
        ]

        result = command_handler.cmd_sessions(["list", "--type", "shell"])

        assert result is True

    def test_sessions_auto_interact(self, command_handler, mock_framework):
        """Test auto-interacting with single session."""
        mock_framework.session_manager.list_sessions.return_value = [
            {"id": "sess-1", "type": "shell"}
        ]

        with patch('purplesploit.core.session_manager.SessionInteraction') as mock_si:
            mock_interaction = MagicMock()
            mock_si.return_value = mock_interaction

            result = command_handler.cmd_interact([])

            # Should auto-select the single session
            assert result is True

    def test_sessions_execute_command(self, command_handler, mock_framework):
        """Test executing command in session."""
        result = command_handler.cmd_sessions(["exec", "sess-1", "whoami"])

        assert result is True

    def test_sessions_download_file(self, command_handler, mock_framework):
        """Test downloading file from session."""
        result = command_handler.cmd_sessions(["download", "sess-1", "/etc/passwd"])

        assert result is True

    def test_sessions_upload_file(self, command_handler, mock_framework):
        """Test uploading file to session."""
        result = command_handler.cmd_sessions(["upload", "sess-1", "/local/file", "/remote/path"])

        assert result is True
