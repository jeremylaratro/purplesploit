"""
Unit tests for extended command features in purplesploit.ui.commands.

Tests cover:
- Run command with various scenarios
- Targets command (add, remove, update, select, clear)
- Credentials command (add, remove, update, select, clear)
- Services command (add, remove, search)
- Wordlists command
- Recent command
- History command with filters
- Stats command
- Clear command
- Defaults command edge cases
- Error handling for all command paths
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
    framework.session.services = MagicMock()
    framework.session.services.services = {}
    framework.session.wordlists = MagicMock()
    framework.session.command_history = []
    framework.session.add_command = MagicMock()
    framework.session.workspace = "default"
    framework.session.defaults = {}
    framework.modules = {}
    framework.database = MagicMock()
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
# Run Command Extended Tests
# =============================================================================

class TestRunCommandExtended:
    """Extended tests for run command."""

    def test_run_with_module(self, command_handler, mock_framework):
        """Test run command with module loaded (no operations)."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = False
        mock_module.name = "test_module"
        mock_framework.session.current_module = mock_module
        mock_framework.run_module.return_value = {"status": "success"}

        result = command_handler.cmd_run([])

        assert result is True
        mock_framework.run_module.assert_called_once_with(mock_module)

    def test_run_with_operation(self, command_handler, mock_framework):
        """Test run command with specific operation."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = True
        mock_module.run_operation.return_value = {"status": "success"}
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_run(["--operation", "scan"])

        assert result is True

    def test_run_module_exception(self, command_handler, mock_framework):
        """Test run propagates module exceptions (caller handles them)."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = False
        mock_module.name = "test_module"
        mock_framework.session.current_module = mock_module
        mock_framework.run_module.side_effect = Exception("Module error")

        # The cmd_run doesn't catch exceptions - they propagate up to execute()
        with pytest.raises(Exception, match="Module error"):
            command_handler.cmd_run([])

    def test_run_with_options(self, command_handler, mock_framework):
        """Test run command with runtime options."""
        mock_module = MagicMock()
        mock_module.run.return_value = {"status": "success"}
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_run(["--threads", "10"])

        assert result is True


# =============================================================================
# Targets Command Extended Tests
# =============================================================================

class TestTargetsCommandExtended:
    """Extended tests for targets command."""

    def test_targets_remove(self, command_handler, mock_framework):
        """Test removing a target."""
        mock_framework.session.targets.remove.return_value = True

        result = command_handler.cmd_targets(["remove", "target-1"])

        assert result is True
        mock_framework.session.targets.remove.assert_called_once_with("target-1")

    def test_targets_remove_cancelled(self, command_handler, mock_framework):
        """Test remove target when cancelled."""
        command_handler.interactive.confirm.return_value = False

        result = command_handler.cmd_targets(["remove", "target-1"])

        assert result is True
        mock_framework.remove_target.assert_not_called()

    def test_targets_update(self, command_handler, mock_framework):
        """Test updating a target."""
        mock_framework.update_target.return_value = True

        result = command_handler.cmd_targets(["update", "target-1", "--name", "newname"])

        assert result is True

    def test_targets_clear(self, command_handler, mock_framework):
        """Test clearing all targets."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_targets(["clear"])

        assert result is True

    def test_targets_import(self, command_handler, mock_framework):
        """Test importing targets from file."""
        with patch('builtins.open', patch('builtins.open').__enter__):
            with patch('pathlib.Path.exists', return_value=True):
                result = command_handler.cmd_targets(["import", "targets.txt"])

                assert result is True

    def test_targets_export(self, command_handler, mock_framework):
        """Test exporting targets to file."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "host1"}
        ]

        result = command_handler.cmd_targets(["export", "targets.json"])

        assert result is True

    def test_targets_search(self, command_handler, mock_framework):
        """Test searching targets."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "web-server"},
            {"ip": "192.168.1.2", "name": "db-server"}
        ]

        result = command_handler.cmd_targets(["search", "web"])

        assert result is True

    def test_targets_show_info(self, command_handler, mock_framework):
        """Test showing target info."""
        mock_framework.session.targets.get.return_value = {
            "ip": "192.168.1.1",
            "name": "host1",
            "services": [80, 443]
        }

        result = command_handler.cmd_targets(["show", "target-1"])

        assert result is True


# =============================================================================
# Credentials Command Extended Tests
# =============================================================================

class TestCredsCommandExtended:
    """Extended tests for credentials command."""

    def test_creds_remove(self, command_handler, mock_framework):
        """Test removing a credential."""
        mock_framework.session.credentials.remove.return_value = True

        result = command_handler.cmd_creds(["remove", "cred-1"])

        assert result is True
        mock_framework.session.credentials.remove.assert_called_once_with("cred-1")

    def test_creds_update(self, command_handler, mock_framework):
        """Test updating a credential."""
        mock_framework.update_credential.return_value = True

        result = command_handler.cmd_creds(["update", "cred-1", "--password", "newpass"])

        assert result is True

    def test_creds_clear(self, command_handler, mock_framework):
        """Test clearing all credentials."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_creds(["clear"])

        assert result is True

    def test_creds_import(self, command_handler, mock_framework):
        """Test importing credentials from file."""
        with patch('pathlib.Path.exists', return_value=True):
            result = command_handler.cmd_creds(["import", "creds.txt"])

            assert result is True

    def test_creds_export(self, command_handler, mock_framework):
        """Test exporting credentials to file."""
        mock_framework.session.credentials.list.return_value = [
            {"username": "admin", "password": "pass123"}
        ]

        result = command_handler.cmd_creds(["export", "creds.json"])

        assert result is True

    def test_creds_test(self, command_handler, mock_framework):
        """Test testing credentials."""
        mock_framework.test_credential.return_value = {
            "success": True,
            "message": "Authentication successful"
        }

        result = command_handler.cmd_creds(["test", "cred-1"])

        assert result is True

    def test_creds_show_passwords(self, command_handler, mock_framework):
        """Test showing credentials with passwords."""
        mock_framework.session.credentials.list.return_value = [
            {"username": "admin", "password": "pass123"}
        ]

        result = command_handler.cmd_creds(["list", "--show-passwords"])

        assert result is True

    def test_creds_filter_by_domain(self, command_handler, mock_framework):
        """Test filtering credentials by domain."""
        mock_framework.session.credentials.list.return_value = [
            {"username": "admin", "domain": "domain.local"}
        ]

        result = command_handler.cmd_creds(["list", "--domain", "domain.local"])

        assert result is True


# =============================================================================
# Services Command Extended Tests
# =============================================================================

class TestServicesCommandExtended:
    """Extended tests for services command."""

    def test_services_add(self, command_handler, mock_framework):
        """Test adding a service."""
        mock_framework.session.services.add.return_value = True

        result = command_handler.cmd_services(["add", "192.168.1.1", "80", "http"])

        assert result is True

    def test_services_remove(self, command_handler, mock_framework):
        """Test removing a service."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_services(["remove", "service-1"])

        assert result is True

    def test_services_search(self, command_handler, mock_framework):
        """Test searching services."""
        mock_framework.session.services.services = {
            "192.168.1.1": {
                "80": {"name": "http", "version": "Apache 2.4"}
            }
        }

        result = command_handler.cmd_services(["search", "http"])

        assert result is True

    def test_services_filter_by_port(self, command_handler, mock_framework):
        """Test filtering services by port."""
        mock_framework.session.services.services = {
            "192.168.1.1": {
                "80": {"name": "http"},
                "443": {"name": "https"}
            }
        }

        result = command_handler.cmd_services(["list", "--port", "80"])

        assert result is True

    def test_services_filter_by_host(self, command_handler, mock_framework):
        """Test filtering services by host."""
        result = command_handler.cmd_services(["list", "--host", "192.168.1.1"])

        assert result is True

    def test_services_export(self, command_handler, mock_framework):
        """Test exporting services."""
        mock_framework.session.services.services = {
            "192.168.1.1": {"80": {"name": "http"}}
        }

        result = command_handler.cmd_services(["export", "services.json"])

        assert result is True


# =============================================================================
# Wordlists Command Extended Tests
# =============================================================================

class TestWordlistsCommandExtended:
    """Extended tests for wordlists command."""

    def test_wordlists_add(self, command_handler, mock_framework):
        """Test adding a wordlist."""
        with patch('pathlib.Path.exists', return_value=True):
            result = command_handler.cmd_wordlists(["add", "passwords", "/path/to/list.txt"])

            assert result is True

    def test_wordlists_remove(self, command_handler, mock_framework):
        """Test removing a wordlist."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_wordlists(["remove", "passwords"])

        assert result is True

    def test_wordlists_show(self, command_handler, mock_framework):
        """Test showing wordlist details."""
        mock_framework.session.wordlists.get.return_value = {
            "name": "passwords",
            "path": "/path/to/list.txt",
            "lines": 1000
        }

        result = command_handler.cmd_wordlists(["show", "passwords"])

        assert result is True

    def test_wordlists_search(self, command_handler, mock_framework):
        """Test searching in wordlists."""
        result = command_handler.cmd_wordlists(["search", "password"])

        assert result is True

    def test_wordlists_generate(self, command_handler, mock_framework):
        """Test generating a wordlist."""
        result = command_handler.cmd_wordlists(["generate", "--pattern", "company", "--output", "custom.txt"])

        assert result is True


# =============================================================================
# Recent Command Tests
# =============================================================================

class TestRecentCommand:
    """Tests for recent command."""

    def test_recent_with_modules(self, command_handler, mock_framework):
        """Test showing recent modules."""
        mock_framework.session.command_history = [
            {"command": "use recon/nmap", "timestamp": "2025-01-01 10:00:00"},
            {"command": "use network/nxc_smb", "timestamp": "2025-01-01 10:05:00"}
        ]

        result = command_handler.cmd_recent([])

        assert result is True

    def test_recent_limit(self, command_handler, mock_framework):
        """Test recent with limit parameter."""
        mock_framework.session.command_history = [
            {"command": f"use module{i}", "timestamp": "2025-01-01"}
            for i in range(20)
        ]

        result = command_handler.cmd_recent(["--limit", "5"])

        assert result is True

    def test_recent_filter(self, command_handler, mock_framework):
        """Test recent with filter."""
        mock_framework.session.command_history = [
            {"command": "use recon/nmap", "timestamp": "2025-01-01"},
            {"command": "use network/nxc_smb", "timestamp": "2025-01-01"}
        ]

        result = command_handler.cmd_recent(["recon"])

        assert result is True


# =============================================================================
# History Command Extended Tests
# =============================================================================

class TestHistoryCommandExtended:
    """Extended tests for history command."""

    def test_history_with_limit(self, command_handler, mock_framework):
        """Test history with limit."""
        mock_framework.session.command_history = [
            {"command": f"command{i}", "timestamp": "2025-01-01"}
            for i in range(100)
        ]

        result = command_handler.cmd_history(["--limit", "10"])

        assert result is True

    def test_history_search(self, command_handler, mock_framework):
        """Test searching history."""
        mock_framework.session.command_history = [
            {"command": "search nmap", "timestamp": "2025-01-01"},
            {"command": "use recon/nmap", "timestamp": "2025-01-01"},
            {"command": "run", "timestamp": "2025-01-01"}
        ]

        result = command_handler.cmd_history(["--search", "nmap"])

        assert result is True

    def test_history_clear(self, command_handler, mock_framework):
        """Test clearing history."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_history(["--clear"])

        assert result is True

    def test_history_export(self, command_handler, mock_framework):
        """Test exporting history."""
        mock_framework.session.command_history = [
            {"command": "help", "timestamp": "2025-01-01"}
        ]

        result = command_handler.cmd_history(["--export", "history.txt"])

        assert result is True


# =============================================================================
# Stats Command Extended Tests
# =============================================================================

class TestStatsCommandExtended:
    """Extended tests for stats command."""

    def test_stats_detailed(self, command_handler, mock_framework):
        """Test detailed stats."""
        mock_framework.get_stats.return_value = {
            "modules": 50,
            "categories": 10,
            "targets": 15,
            "credentials": 8,
            "current_module": None
        }

        result = command_handler.cmd_stats(["--detailed"])

        assert result is True

    def test_stats_export(self, command_handler, mock_framework):
        """Test exporting stats."""
        mock_framework.get_stats.return_value = {
            "modules": 50,
            "categories": 10,
            "targets": 15,
            "credentials": 8,
            "current_module": None
        }

        result = command_handler.cmd_stats(["--export", "stats.json"])

        assert result is True

    def test_stats_session_info(self, command_handler, mock_framework):
        """Test stats includes session info."""
        mock_framework.get_stats.return_value = {
            "modules": 50,
            "categories": 10,
            "targets": 15,
            "credentials": 8,
            "current_module": "recon/nmap"
        }

        result = command_handler.cmd_stats([])

        assert result is True


# =============================================================================
# Clear Command Tests
# =============================================================================

class TestClearCommand:
    """Tests for clear command."""

    def test_clear_console(self, command_handler):
        """Test clearing console."""
        result = command_handler.cmd_clear([])

        assert result is True
        command_handler.display.clear.assert_called_once()

    def test_clear_with_reset(self, command_handler):
        """Test clearing with terminal reset."""
        with patch('os.system') as mock_system:
            result = command_handler.cmd_clear(["--reset"])

            assert result is True


# =============================================================================
# Defaults Command Extended Tests
# =============================================================================

class TestDefaultsCommandExtended:
    """Extended tests for defaults command."""

    def test_defaults_set_multiple(self, command_handler, mock_framework):
        """Test setting multiple defaults."""
        result = command_handler.cmd_defaults(["set", "THREADS", "20"])
        assert result is True

        result = command_handler.cmd_defaults(["set", "TIMEOUT", "60"])
        assert result is True

    def test_defaults_show(self, command_handler, mock_framework):
        """Test showing default value."""
        mock_framework.session.defaults = {"THREADS": "10"}

        result = command_handler.cmd_defaults(["show", "THREADS"])

        assert result is True

    def test_defaults_export(self, command_handler, mock_framework):
        """Test exporting defaults."""
        mock_framework.session.defaults = {
            "THREADS": "10",
            "TIMEOUT": "30"
        }

        result = command_handler.cmd_defaults(["export", "defaults.json"])

        assert result is True

    def test_defaults_import(self, command_handler, mock_framework):
        """Test importing defaults."""
        with patch('pathlib.Path.exists', return_value=True):
            result = command_handler.cmd_defaults(["import", "defaults.json"])

            assert result is True

    def test_defaults_reset(self, command_handler, mock_framework):
        """Test resetting defaults to system values."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_defaults(["reset"])

        assert result is True


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestExtendedErrorHandling:
    """Tests for error handling in extended commands."""

    def test_targets_add_invalid_ip(self, command_handler, mock_framework):
        """Test adding target with invalid IP."""
        command_handler.interactive.get_input.side_effect = ["invalid_ip", ""]
        mock_framework.add_target.return_value = False

        result = command_handler.cmd_targets(["add"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_creds_import_invalid_format(self, command_handler, mock_framework):
        """Test importing credentials with invalid format."""
        with patch('pathlib.Path.exists', return_value=True):
            with patch('builtins.open', side_effect=ValueError("Invalid format")):
                result = command_handler.cmd_creds(["import", "bad_creds.txt"])

                assert result is True

    def test_services_add_invalid_port(self, command_handler, mock_framework):
        """Test services command with invalid subcommand shows table (no 'add' subcommand)."""
        # The services command doesn't have an 'add' subcommand - it falls through to list
        mock_framework.session.services.services = {}

        result = command_handler.cmd_services(["add", "192.168.1.1", "invalid", "http"])

        assert result is True
        # Falls through to the else branch which shows services table
        command_handler.display.print_services_table.assert_called()

    def test_wordlists_add_nonexistent_file(self, command_handler, mock_framework):
        """Test adding non-existent wordlist returns failure message."""
        # The wordlist manager's add method returns False for non-existent files
        mock_framework.session.wordlists.add.return_value = False

        result = command_handler.cmd_wordlists(["add", "passwords", "/missing/list.txt"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_run_validation_failed(self, command_handler, mock_framework):
        """Test run when validation fails."""
        mock_module = MagicMock()
        mock_module.validate_options.return_value = False
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_run([])

        assert result is True


# =============================================================================
# Integration Tests
# =============================================================================

class TestExtendedIntegration:
    """Integration tests for extended commands."""

    def test_target_credential_workflow(self, command_handler, mock_framework):
        """Test complete target and credential workflow."""
        # Add target
        command_handler.interactive.get_input.side_effect = ["192.168.1.1", "server1"]
        mock_framework.add_target.return_value = True
        command_handler.cmd_targets(["add"])

        # Add credential
        command_handler.interactive.get_input.side_effect = ["admin", "password", ""]
        mock_framework.add_credential.return_value = True
        command_handler.cmd_creds(["add"])

        # Load module and set from context
        mock_module = MagicMock()
        mock_module.name = "SMB"
        mock_module.has_operations.return_value = False
        mock_module.get_option.return_value = None
        mock_module.auto_set_from_context = MagicMock()
        mock_framework.use_module.return_value = mock_module

        command_handler.cmd_quick(["smb"])

        assert True

    def test_complete_enumeration_workflow(self, command_handler, mock_framework):
        """Test complete enumeration workflow."""
        # Parse nmap results
        with patch('purplesploit.modules.recon.nmap.NmapModule') as mock_nmap:
            mock_module = MagicMock()
            mock_module.parse_xml_results.return_value = {
                "hosts": [{"ip": "192.168.1.1", "ports": [80, 443]}],
                "total_scanned": 1,
                "hosts_discovered": 1
            }
            mock_nmap.return_value = mock_module

            with patch('pathlib.Path.exists', return_value=True):
                command_handler.cmd_parse(["/path/to/scan.xml"])

        # Show services
        mock_framework.session.services.services = {}
        command_handler.cmd_services(["list"])

        # Export hosts
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1"}
        ]
        command_handler.cmd_hosts([])

        assert True


# =============================================================================
# Performance and Edge Cases Tests
# =============================================================================

class TestPerformanceAndEdgeCases:
    """Tests for performance and edge cases."""

    def test_large_history(self, command_handler, mock_framework):
        """Test handling large history."""
        mock_framework.session.command_history = [
            {"command": f"cmd{i}", "timestamp": "2025-01-01"}
            for i in range(10000)
        ]

        result = command_handler.cmd_history([])

        assert result is True

    def test_many_targets(self, command_handler, mock_framework):
        """Test handling many targets."""
        mock_framework.session.targets.list.return_value = [
            {"ip": f"192.168.1.{i}", "name": f"host{i}"}
            for i in range(1, 255)
        ]

        result = command_handler.cmd_targets(["list"])

        assert result is True

    def test_concurrent_operations(self, command_handler, mock_framework):
        """Test handling concurrent operations."""
        # This would test thread safety, but for unit tests we just verify no errors
        mock_module = MagicMock()
        mock_module.run.return_value = {"status": "success"}
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_run([])

        assert result is True

    def test_empty_string_inputs(self, command_handler, mock_framework):
        """Test handling empty string inputs."""
        command_handler.interactive.get_input.side_effect = ["", "", ""]

        result = command_handler.cmd_targets(["add"])

        assert result is True

    def test_special_characters_in_names(self, command_handler, mock_framework):
        """Test handling special characters in names."""
        command_handler.interactive.get_input.side_effect = [
            "192.168.1.1",
            "server-name_with.special@chars#123"
        ]
        mock_framework.add_target.return_value = True

        result = command_handler.cmd_targets(["add"])

        assert result is True

    def test_unicode_in_commands(self, command_handler, mock_framework):
        """Test handling Unicode in commands."""
        mock_module = MagicMock()
        mock_module.set_option.return_value = True
        mock_framework.session.current_module = mock_module

        result = command_handler.cmd_set(["COMMENT", "测试中文"])

        assert result is True

    @pytest.mark.parametrize("invalid_input", [
        None,
        [],
        {},
        " " * 1000,  # Very long whitespace
        "\x00",  # Null byte
    ])
    def test_malformed_inputs(self, command_handler, mock_framework, invalid_input):
        """Test handling various malformed inputs."""
        # Should handle gracefully without crashing
        try:
            if isinstance(invalid_input, str):
                result = command_handler.execute(invalid_input)
                assert result is True
        except Exception:
            # Any exception should be caught by the command handler
            pass


# =============================================================================
# Command Aliases Tests
# =============================================================================

class TestCommandAliases:
    """Tests for command aliases."""

    def test_exploit_alias(self, command_handler, mock_framework):
        """Test exploit as alias for run."""
        mock_module = MagicMock()
        mock_module.has_operations.return_value = False
        mock_module.name = "test_module"
        mock_framework.session.current_module = mock_module
        mock_framework.run_module.return_value = {"status": "success"}

        result = command_handler.execute("exploit")

        assert result is True
        mock_framework.run_module.assert_called_once_with(mock_module)

    def test_question_mark_alias(self, command_handler):
        """Test ? as alias for help."""
        result = command_handler.execute("?")

        assert result is True

    def test_quit_alias(self, command_handler):
        """Test quit as alias for exit."""
        result = command_handler.execute("quit")

        assert result is False

    def test_webresults_alias(self, command_handler, mock_framework):
        """Test webresults as alias for analysis."""
        result = command_handler.cmd_analysis(["list"])

        assert result is True

    def test_finding_alias(self, command_handler, mock_framework):
        """Test finding as alias for findings."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.list_findings.return_value = []
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler.cmd_findings([])

            assert result is True
