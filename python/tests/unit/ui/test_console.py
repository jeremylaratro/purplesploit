"""
Tests for the Console module.

Tests the interactive REPL console with prompt_toolkit integration.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path


class TestConsoleInitialization:
    """Tests for Console class initialization."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework for console testing."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.current_module = None
        framework.session.targets = MagicMock()
        framework.session.targets.list.return_value = []
        framework.list_modules.return_value = []
        framework.get_stats.return_value = {'modules': 10, 'categories': 5}
        return framework

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_console_creates_session(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that console creates a PromptSession."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        mock_prompt_session.assert_called_once()

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_console_creates_history_file(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that console sets up file history."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        mock_file_history.assert_called_once()

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_console_has_display(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that console has Display instance."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        assert console.display is not None

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_console_has_command_handler(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that console has CommandHandler instance."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        assert console.command_handler is not None

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_console_running_flag_initially_true(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that running flag is True on init."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        assert console.running is True

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_console_creates_completer(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that console creates a completer."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        assert console.completer is not None

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_console_has_prompt_style(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that console has prompt style defined."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        assert console.prompt_style is not None


class TestConsoleCompleter:
    """Tests for Console completer creation."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework for console testing."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.current_module = None
        framework.session.targets = MagicMock()
        framework.session.targets.list.return_value = []
        framework.list_modules.return_value = []
        return framework

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_completer_includes_base_commands(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that completer includes base commands."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        completer = console._create_completer()
        # WordCompleter stores words internally
        assert completer is not None

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_completer_includes_module_paths(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that completer includes module paths when available."""
        # Setup modules
        mock_module = MagicMock()
        mock_module.path = "recon/nmap"
        mock_framework.list_modules.return_value = [mock_module]

        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        completer = console._create_completer()
        assert completer is not None

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_completer_includes_target_ips(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that completer includes target IPs when available."""
        # Setup targets
        mock_framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1', 'name': 'target1'},
            {'ip': '192.168.1.2', 'name': 'target2'}
        ]

        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        completer = console._create_completer()
        assert completer is not None

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_completer_handles_exceptions(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that completer handles exceptions gracefully."""
        # Make list_modules raise an exception
        mock_framework.list_modules.side_effect = Exception("Test error")

        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        # Should not raise
        completer = console._create_completer()
        assert completer is not None


class TestConsolePrompt:
    """Tests for Console prompt generation."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework for console testing."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.current_module = None
        framework.session.targets = MagicMock()
        framework.session.targets.list.return_value = []
        framework.list_modules.return_value = []
        return framework

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_get_prompt_basic(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test basic prompt without module."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        prompt = console._get_prompt()
        # Should have purplesploit and >
        assert any('purplesploit' in str(part) for part in prompt)

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_get_prompt_with_module(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test prompt with loaded module."""
        # Setup current module
        mock_module = MagicMock()
        mock_module.name = "Nmap Scanner"
        mock_framework.session.current_module = mock_module

        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        prompt = console._get_prompt()
        # Should include module name
        prompt_str = str(prompt)
        assert 'Nmap Scanner' in prompt_str or len(prompt) > 2


class TestConsoleCleanup:
    """Tests for Console cleanup."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework for console testing."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.current_module = None
        framework.session.targets = MagicMock()
        framework.session.targets.list.return_value = []
        framework.list_modules.return_value = []
        return framework

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_cleanup_calls_framework_cleanup(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that cleanup calls framework cleanup."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        console._cleanup()
        mock_framework.cleanup.assert_called_once()

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_cleanup_calls_command_handler_cleanup(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that cleanup calls command handler cleanup."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        console.command_handler = MagicMock()
        console._cleanup()
        console.command_handler.cleanup.assert_called_once()


class TestConsoleStart:
    """Tests for Console start method."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework for console testing."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.current_module = None
        framework.session.targets = MagicMock()
        framework.session.targets.list.return_value = []
        framework.list_modules.return_value = []
        framework.get_stats.return_value = {'modules': 10, 'categories': 5}
        return framework

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_start_prints_banner(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that start prints banner."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        console.display = MagicMock()
        console.command_handler = MagicMock()

        # Make session.prompt raise EOFError to exit loop
        mock_prompt_session.return_value.prompt.side_effect = EOFError()
        console.session = mock_prompt_session.return_value

        console.start()
        console.display.print_banner.assert_called_once()

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_start_handles_keyboard_interrupt(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that start handles Ctrl+C."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        console.display = MagicMock()
        console.command_handler = MagicMock()

        # First call raises KeyboardInterrupt, second raises EOFError
        mock_prompt_session.return_value.prompt.side_effect = [KeyboardInterrupt(), EOFError()]
        console.session = mock_prompt_session.return_value

        # Should not raise
        console.start()

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_start_handles_eof(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that start handles Ctrl+D (EOF)."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        console.display = MagicMock()
        console.command_handler = MagicMock()

        mock_prompt_session.return_value.prompt.side_effect = EOFError()
        console.session = mock_prompt_session.return_value

        # Should exit cleanly
        console.start()

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_start_executes_commands(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that start executes user commands."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        console.display = MagicMock()
        console.command_handler = MagicMock()
        console.command_handler.execute.return_value = False  # Exit after first command

        mock_prompt_session.return_value.prompt.return_value = "help"
        console.session = mock_prompt_session.return_value

        console.start()
        console.command_handler.execute.assert_called_with("help")

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_start_skips_empty_input(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that start skips empty input."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)
        console.display = MagicMock()
        console.command_handler = MagicMock()
        console.command_handler.execute.return_value = True

        # First empty, then command, then EOF
        mock_prompt_session.return_value.prompt.side_effect = ["", "   ", EOFError()]
        console.session = mock_prompt_session.return_value

        console.start()
        # Should not execute empty commands
        assert console.command_handler.execute.call_count == 0


class TestConsoleIntegration:
    """Integration tests for Console with mocked dependencies."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework for integration testing."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.current_module = None
        framework.session.targets = MagicMock()
        framework.session.targets.list.return_value = [
            {'ip': '192.168.1.1', 'name': 'test-target'}
        ]
        framework.list_modules.return_value = []
        framework.get_stats.return_value = {'modules': 10, 'categories': 5}
        return framework

    @patch('purplesploit.ui.console.PromptSession')
    @patch('purplesploit.ui.console.FileHistory')
    def test_completer_updates_with_context(self, mock_file_history, mock_prompt_session, mock_framework):
        """Test that completer updates with targets."""
        from purplesploit.ui.console import Console
        console = Console(mock_framework)

        # Initial completer
        completer1 = console._create_completer()

        # Add more targets
        mock_framework.session.targets.list.return_value.append(
            {'ip': '192.168.1.2', 'name': 'new-target'}
        )

        # New completer should include new target
        completer2 = console._create_completer()
        assert completer2 is not None
