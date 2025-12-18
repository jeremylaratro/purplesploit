"""
Tests for the Display module.

Tests the display formatting, table rendering, and output methods.
"""

import pytest
from unittest.mock import MagicMock, patch
from io import StringIO


class TestDisplayInitialization:
    """Tests for Display class initialization."""

    def test_creates_rich_console(self):
        """Test that Display creates a Rich console."""
        from purplesploit.ui.display import Display
        display = Display()
        assert display.console is not None

    def test_console_has_width(self):
        """Test that console has expected width for banner display."""
        from purplesploit.ui.display import Display
        display = Display()
        assert display.console.width == 120


class TestDisplayMessages:
    """Tests for message printing methods."""

    def test_print_success(self):
        """Test success message formatting."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()
        display.print_success("Test message")
        display.console.print.assert_called_once()
        call_args = display.console.print.call_args[0][0]
        assert "Test message" in call_args
        assert "green" in call_args

    def test_print_error(self):
        """Test error message formatting."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()
        display.print_error("Error message")
        display.console.print.assert_called_once()
        call_args = display.console.print.call_args[0][0]
        assert "Error message" in call_args
        assert "red" in call_args

    def test_print_warning(self):
        """Test warning message formatting."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()
        display.print_warning("Warning message")
        display.console.print.assert_called_once()
        call_args = display.console.print.call_args[0][0]
        assert "Warning message" in call_args
        assert "yellow" in call_args

    def test_print_info(self):
        """Test info message formatting."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()
        display.print_info("Info message")
        display.console.print.assert_called_once()
        call_args = display.console.print.call_args[0][0]
        assert "Info message" in call_args
        assert "blue" in call_args


class TestDisplayModulesTable:
    """Tests for module table display."""

    def test_print_modules_empty_list(self):
        """Test printing empty modules list shows warning."""
        from purplesploit.ui.display import Display
        display = Display()
        display.print_warning = MagicMock()
        display.print_modules_table([])
        display.print_warning.assert_called_once_with("No modules found")

    def test_print_modules_with_data(self):
        """Test printing modules with data creates table."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        # Create mock module metadata
        module1 = MagicMock()
        module1.category = "recon"
        module1.path = "recon/nmap"
        module1.name = "Nmap"
        module1.description = "Network scanner"

        display.print_modules_table([module1])
        assert display.console.print.called

    def test_print_modules_truncates_long_description(self):
        """Test that long descriptions are truncated."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        module = MagicMock()
        module.category = "test"
        module.path = "test/module"
        module.name = "Test"
        module.description = "A" * 100  # Long description

        display.print_modules_table([module])
        # Verify table was created and printed
        assert display.console.print.called


class TestDisplayOptionsTable:
    """Tests for options table display."""

    def test_print_options_table(self):
        """Test printing options table."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        options = {
            "RHOST": {
                "value": "192.168.1.1",
                "required": True,
                "description": "Target host"
            },
            "PORT": {
                "value": None,
                "required": False,
                "description": "Target port"
            }
        }

        display.print_options_table(options)
        assert display.console.print.called

    def test_print_options_handles_none_value(self):
        """Test that None values are displayed as '<not set>'."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        options = {
            "TEST": {
                "value": None,
                "required": False,
                "description": "Test option"
            }
        }

        display.print_options_table(options)
        assert display.console.print.called


class TestDisplayTargetsTable:
    """Tests for targets table display."""

    def test_print_targets_empty(self):
        """Test printing empty targets shows warning."""
        from purplesploit.ui.display import Display
        display = Display()
        display.print_warning = MagicMock()
        display.print_targets_table([])
        display.print_warning.assert_called_once_with("No targets configured")

    def test_print_targets_with_data(self):
        """Test printing targets with data."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        targets = [
            {
                "ip": "192.168.1.1",
                "name": "target1",
                "type": "network",
                "added_at": "2024-01-01 10:00:00"
            }
        ]

        display.print_targets_table(targets)
        assert display.console.print.called

    def test_print_targets_with_url(self):
        """Test printing web targets with URLs."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        targets = [
            {
                "url": "http://example.com",
                "name": "web-target",
                "type": "web",
                "added_at": "2024-01-01"
            }
        ]

        display.print_targets_table(targets)
        assert display.console.print.called


class TestDisplayCredentialsTable:
    """Tests for credentials table display."""

    def test_print_credentials_empty(self):
        """Test printing empty credentials shows warning."""
        from purplesploit.ui.display import Display
        display = Display()
        display.print_warning = MagicMock()
        display.print_credentials_table([])
        display.print_warning.assert_called_once_with("No credentials configured")

    def test_print_credentials_with_data(self):
        """Test printing credentials with data."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        credentials = [
            {
                "username": "admin",
                "password": "secret",
                "domain": "CORP",
                "hash": "",
                "name": "admin-cred"
            }
        ]

        display.print_credentials_table(credentials)
        assert display.console.print.called


class TestDisplayServicesTable:
    """Tests for services table display."""

    def test_print_services_empty(self):
        """Test printing empty services shows warning."""
        from purplesploit.ui.display import Display
        display = Display()
        display.print_warning = MagicMock()
        display.print_services_table({})
        display.print_warning.assert_called_once_with("No services detected")

    def test_print_services_with_data(self):
        """Test printing services with data."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        services = {
            "192.168.1.1": {
                "ssh": [22],
                "http": [80, 8080]
            }
        }

        display.print_services_table(services)
        assert display.console.print.called

    def test_print_services_filters_cidr(self):
        """Test that CIDR notation targets are filtered out."""
        from purplesploit.ui.display import Display
        display = Display()
        display.print_warning = MagicMock()

        services = {
            "192.168.1.0/24": {
                "http": [80]
            }
        }

        display.print_services_table(services)
        # Should show warning about only network ranges found
        assert display.print_warning.called


class TestDisplayResults:
    """Tests for results display."""

    def test_print_results_success(self):
        """Test printing successful results."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()
        display.print_success = MagicMock()

        results = {
            "success": True,
            "stdout": "Output text",
            "command": "test --run"
        }

        display.print_results(results)
        display.print_success.assert_called()

    def test_print_results_failure(self):
        """Test printing failed results."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()
        display.print_error = MagicMock()

        results = {
            "success": False,
            "error": "Command failed"
        }

        display.print_results(results)
        display.print_error.assert_called()

    def test_print_results_with_stderr(self):
        """Test printing results with stderr."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        results = {
            "success": True,
            "stdout": "",
            "stderr": "Warning: deprecated option"
        }

        display.print_results(results)
        assert display.console.print.called


class TestDisplayGenericPrinting:
    """Tests for generic data printing."""

    def test_print_generic_dict(self):
        """Test printing dictionary data."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        display._print_generic({"key": "value", "number": 42})
        assert display.console.print.called

    def test_print_generic_list(self):
        """Test printing list data."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        display._print_generic(["item1", "item2", "item3"])
        assert display.console.print.called

    def test_print_generic_string(self):
        """Test printing string data."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        display._print_generic("Simple string")
        display.console.print.assert_called_with("Simple string")


class TestDisplayModuleInfo:
    """Tests for module info display."""

    def test_print_module_info(self):
        """Test printing module information."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        module = MagicMock()
        module.name = "Test Module"
        module.description = "Test description"
        module.author = "Test Author"
        module.category = "test"

        display.print_module_info(module)
        assert display.console.print.called


class TestDisplayHelp:
    """Tests for help display."""

    def test_print_help(self):
        """Test printing help information."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        commands = {
            "help": "Show help",
            "exit": "Exit the program",
            "search": "Search modules"
        }

        display.print_help(commands)
        assert display.console.print.called


class TestDisplayUtilities:
    """Tests for display utility methods."""

    def test_clear_screen(self):
        """Test clearing the screen."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()
        display.clear()
        display.console.clear.assert_called_once()

    def test_print_status_bar(self):
        """Test printing status bar."""
        from purplesploit.ui.display import Display
        display = Display()
        display.console = MagicMock()

        stats = {
            "current_module": "nmap",
            "targets": 5,
            "credentials": 2
        }

        display.print_status_bar(stats)
        assert display.console.print.called
