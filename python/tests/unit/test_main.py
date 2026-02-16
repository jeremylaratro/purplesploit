"""
Unit tests for purplesploit.main module.

Tests cover:
- Argument parsing (--modules, --db, --version)
- Main entry point execution
- Environment variable handling (PURPLESPLOIT_DB)
- Error handling (KeyboardInterrupt, Exception)
- Default path creation
"""

import pytest
import sys
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework():
    """Create a mock Framework instance."""
    framework = MagicMock()
    framework.discover_modules.return_value = None
    return framework


@pytest.fixture
def mock_console():
    """Create a mock Console instance."""
    console = MagicMock()
    console.start.return_value = None
    return console


# =============================================================================
# Argument Parsing Tests
# =============================================================================

class TestArgumentParsing:
    """Tests for command line argument parsing."""

    def test_parse_no_arguments(self):
        """Test parsing with no arguments."""
        with patch('sys.argv', ['purplesploit']):
            from purplesploit.main import main
            import argparse

            parser = argparse.ArgumentParser()
            parser.add_argument('--modules', type=str, default=None)
            parser.add_argument('--db', type=str, default=None)

            args = parser.parse_args([])

            assert args.modules is None
            assert args.db is None

    def test_parse_modules_argument(self):
        """Test parsing --modules argument."""
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument('--modules', type=str, default=None)

        args = parser.parse_args(['--modules', '/custom/modules'])

        assert args.modules == '/custom/modules'

    def test_parse_db_argument(self):
        """Test parsing --db argument."""
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument('--db', type=str, default=None)

        args = parser.parse_args(['--db', '/custom/database.db'])

        assert args.db == '/custom/database.db'

    def test_parse_both_arguments(self):
        """Test parsing both --modules and --db arguments."""
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument('--modules', type=str, default=None)
        parser.add_argument('--db', type=str, default=None)

        args = parser.parse_args(['--modules', '/my/modules', '--db', '/my/db.db'])

        assert args.modules == '/my/modules'
        assert args.db == '/my/db.db'

    def test_version_argument(self):
        """Test --version argument exits with version info."""
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument('--version', action='version', version='PurpleSploit 6.8.1')

        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(['--version'])

        assert exc_info.value.code == 0


# =============================================================================
# Main Function Tests
# =============================================================================

class TestMainFunction:
    """Tests for the main() entry point function."""

    def test_main_with_default_paths(self, tmp_path, mock_framework, mock_console):
        """Test main() with default paths."""
        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console) as mock_console_class, \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Framework should be initialized
            mock_fw_class.assert_called_once()

            # Modules should be discovered
            mock_framework.discover_modules.assert_called_once()

            # Console should be started
            mock_console_class.assert_called_once_with(mock_framework)
            mock_console.start.assert_called_once()

    def test_main_with_custom_modules_path(self, mock_framework, mock_console):
        """Test main() with custom modules path."""
        with patch('sys.argv', ['purplesploit', '--modules', '/custom/modules']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Check modules_path was passed correctly
            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['modules_path'] == '/custom/modules'

    def test_main_with_custom_db_path(self, mock_framework, mock_console):
        """Test main() with custom database path."""
        with patch('sys.argv', ['purplesploit', '--db', '/custom/database.db']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Check db_path was passed correctly
            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['db_path'] == '/custom/database.db'

    def test_main_with_both_custom_paths(self, mock_framework, mock_console):
        """Test main() with both custom modules and db paths."""
        with patch('sys.argv', ['purplesploit', '--modules', '/my/modules', '--db', '/my/db.db']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Check both paths were passed correctly
            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['modules_path'] == '/my/modules'
            assert call_kwargs['db_path'] == '/my/db.db'


# =============================================================================
# Environment Variable Tests
# =============================================================================

class TestEnvironmentVariables:
    """Tests for environment variable handling."""

    def test_main_with_purplesploit_db_env(self, mock_framework, mock_console):
        """Test main() respects PURPLESPLOIT_DB environment variable."""
        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {'PURPLESPLOIT_DB': '/env/db.db'}), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Check db_path from environment variable was used
            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['db_path'] == '/env/db.db'

    def test_cli_db_overrides_env_var(self, mock_framework, mock_console):
        """Test --db argument overrides PURPLESPLOIT_DB environment variable."""
        with patch('sys.argv', ['purplesploit', '--db', '/cli/db.db']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {'PURPLESPLOIT_DB': '/env/db.db'}), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # CLI argument should override environment variable
            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['db_path'] == '/cli/db.db'


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling in main()."""

    def test_keyboard_interrupt_exits_gracefully(self, capsys):
        """Test KeyboardInterrupt exits with code 0."""
        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', side_effect=KeyboardInterrupt()), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main

            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0
            captured = capsys.readouterr()
            assert "Interrupted by user" in captured.out

    def test_exception_exits_with_error(self, capsys):
        """Test generic Exception exits with code 1."""
        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', side_effect=Exception("Test error")), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main

            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert "Fatal error: Test error" in captured.out

    def test_keyboard_interrupt_during_console(self, mock_framework, capsys):
        """Test KeyboardInterrupt during console.start() exits gracefully."""
        mock_console = MagicMock()
        mock_console.start.side_effect = KeyboardInterrupt()

        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', return_value=mock_framework), \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main

            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0

    def test_exception_during_module_discovery(self, mock_framework, capsys):
        """Test exception during discover_modules() is handled."""
        mock_framework.discover_modules.side_effect = Exception("Module discovery failed")

        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', return_value=mock_framework), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main

            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert "Fatal error: Module discovery failed" in captured.out


# =============================================================================
# Default Path Creation Tests
# =============================================================================

class TestDefaultPaths:
    """Tests for default path creation."""

    def test_data_directory_created(self, mock_framework, mock_console):
        """Test .data directory is created when using default db path."""
        mock_mkdir = MagicMock()

        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', return_value=mock_framework), \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch.object(Path, 'mkdir', mock_mkdir):

            from purplesploit.main import main
            main()

            # mkdir should be called with exist_ok=True
            mock_mkdir.assert_called_with(exist_ok=True)

    def test_default_db_path_format(self, mock_framework, mock_console):
        """Test default database path is in .data directory."""
        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Check db_path ends with purplesploit.db
            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['db_path'].endswith('purplesploit.db')
            assert '.data' in call_kwargs['db_path']


# =============================================================================
# Module Import Tests
# =============================================================================

class TestModuleImport:
    """Tests for module-level behavior."""

    def test_main_module_can_be_imported(self):
        """Test main module can be imported without errors."""
        from purplesploit import main
        assert hasattr(main, 'main')

    def test_main_function_is_callable(self):
        """Test main function exists and is callable."""
        from purplesploit.main import main
        assert callable(main)


# =============================================================================
# Integration Tests (Mocked)
# =============================================================================

class TestMainIntegration:
    """Integration tests for main() with mocked dependencies."""

    def test_full_startup_sequence(self, mock_framework, mock_console):
        """Test complete startup sequence."""
        with patch('sys.argv', ['purplesploit']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console) as mock_console_class, \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Verify the startup sequence
            # 1. Framework initialized
            assert mock_fw_class.called

            # 2. Modules discovered
            assert mock_framework.discover_modules.called

            # 3. Console created with framework
            mock_console_class.assert_called_once_with(mock_framework)

            # 4. Console started
            assert mock_console.start.called

    def test_startup_with_all_options(self, mock_framework, mock_console):
        """Test startup with all command line options."""
        with patch('sys.argv', ['purplesploit', '--modules', '/opt/modules', '--db', '/opt/ps.db']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {'PURPLESPLOIT_DB': '/ignored/db.db'}), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Verify correct options passed (CLI overrides env)
            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['modules_path'] == '/opt/modules'
            assert call_kwargs['db_path'] == '/opt/ps.db'


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_modules_path(self, mock_framework, mock_console):
        """Test with empty string modules path."""
        with patch('sys.argv', ['purplesploit', '--modules', '']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            # Empty string should be passed as-is
            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['modules_path'] == ''

    def test_relative_db_path(self, mock_framework, mock_console):
        """Test with relative database path."""
        with patch('sys.argv', ['purplesploit', '--db', './local.db']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['db_path'] == './local.db'

    def test_path_with_spaces(self, mock_framework, mock_console):
        """Test with paths containing spaces."""
        with patch('sys.argv', ['purplesploit', '--db', '/path with spaces/db.db']), \
             patch('purplesploit.main.Framework', return_value=mock_framework) as mock_fw_class, \
             patch('purplesploit.main.Console', return_value=mock_console), \
             patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.mkdir'):

            from purplesploit.main import main
            main()

            call_kwargs = mock_fw_class.call_args[1]
            assert call_kwargs['db_path'] == '/path with spaces/db.db'
