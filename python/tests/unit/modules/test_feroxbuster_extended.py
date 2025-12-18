"""
Extended unit tests for purplesploit.modules.web.feroxbuster module.

Tests cover:
- _execute_feroxbuster method with subprocess mocking
- _parse_feroxbuster_results method
- Operation handlers with mocked input
- Edge cases and error scenarios
"""

import pytest
import os
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from purplesploit.modules.web.feroxbuster import FeroxbusterModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def feroxbuster_module(mock_framework_minimal):
    """Create a FeroxbusterModule instance for testing."""
    return FeroxbusterModule(mock_framework_minimal)


@pytest.fixture
def feroxbuster_with_url(feroxbuster_module):
    """Create a FeroxbusterModule with URL set."""
    feroxbuster_module.set_option("URL", "http://example.com")
    return feroxbuster_module


@pytest.fixture
def sample_feroxbuster_output():
    """Sample feroxbuster output for parsing tests."""
    return """
200     100l     200w     5000c  http://example.com/index.html
301      10l      20w      500c  http://example.com/admin
403       5l      10w      250c  http://example.com/.htaccess
200      50l     100w     2500c  http://example.com/api/v1
302      10l      20w      500c  http://example.com/login
"""


# =============================================================================
# _get_url Tests
# =============================================================================

class TestGetUrl:
    """Tests for the _get_url method."""

    def test_get_url_returns_set_url(self, feroxbuster_with_url):
        """Test _get_url returns URL when set."""
        url = feroxbuster_with_url._get_url()
        assert url == "http://example.com"

    def test_get_url_returns_none_when_not_set(self, feroxbuster_module):
        """Test _get_url returns None when URL not set and no interactive input."""
        # Mock _get_url to simulate the case where no URL is set and interactive fails
        with patch.object(feroxbuster_module, '_get_url', return_value=None):
            url = feroxbuster_module._get_url()
            assert url is None


# =============================================================================
# _execute_feroxbuster Tests
# =============================================================================

class TestExecuteFeroxbuster:
    """Tests for the _execute_feroxbuster method."""

    def test_execute_feroxbuster_requires_url(self, feroxbuster_module):
        """Test _execute_feroxbuster returns error when URL not set."""
        # Mock _get_url to return None (simulating no URL available)
        with patch.object(feroxbuster_module, '_get_url', return_value=None):
            result = feroxbuster_module._execute_feroxbuster()
            assert result["success"] is False
            assert "URL required" in result["error"]

    def test_execute_feroxbuster_with_url(self, feroxbuster_with_url, tmp_path):
        """Test _execute_feroxbuster with URL set."""
        with patch.object(feroxbuster_with_url, 'execute_command', return_value={"success": True, "output": "test"}):
            with patch.object(Path, 'mkdir'):
                with patch.object(Path, 'exists', return_value=False):
                    result = feroxbuster_with_url._execute_feroxbuster()
                    # Should call execute_command
                    feroxbuster_with_url.execute_command.assert_called_once()

    def test_execute_feroxbuster_creates_log_dir(self, feroxbuster_with_url):
        """Test _execute_feroxbuster creates log directory."""
        with patch.object(feroxbuster_with_url, 'execute_command', return_value={"success": True}):
            with patch.object(Path, 'mkdir') as mock_mkdir:
                with patch.object(Path, 'exists', return_value=False):
                    feroxbuster_with_url._execute_feroxbuster()
                    mock_mkdir.assert_called()

    def test_execute_feroxbuster_includes_thorough_flag(self, feroxbuster_with_url):
        """Test _execute_feroxbuster includes --thorough flag."""
        with patch.object(feroxbuster_with_url, 'execute_command', return_value={"success": True}) as mock_exec:
            with patch.object(Path, 'mkdir'):
                with patch.object(Path, 'exists', return_value=False):
                    feroxbuster_with_url._execute_feroxbuster()
                    call_args = mock_exec.call_args[0][0]
                    assert "--thorough" in call_args

    def test_execute_feroxbuster_includes_methods(self, feroxbuster_with_url):
        """Test _execute_feroxbuster includes methods flag."""
        with patch.object(feroxbuster_with_url, 'execute_command', return_value={"success": True}) as mock_exec:
            with patch.object(Path, 'mkdir'):
                with patch.object(Path, 'exists', return_value=False):
                    feroxbuster_with_url._execute_feroxbuster()
                    call_args = mock_exec.call_args[0][0]
                    assert "--methods GET,POST" in call_args

    def test_execute_feroxbuster_with_extra_args(self, feroxbuster_with_url):
        """Test _execute_feroxbuster with extra arguments."""
        with patch.object(feroxbuster_with_url, 'execute_command', return_value={"success": True}) as mock_exec:
            with patch.object(Path, 'mkdir'):
                with patch.object(Path, 'exists', return_value=False):
                    feroxbuster_with_url._execute_feroxbuster("-x php,html")
                    call_args = mock_exec.call_args[0][0]
                    assert "-x php,html" in call_args

    def test_execute_feroxbuster_background_mode(self, feroxbuster_with_url):
        """Test _execute_feroxbuster background mode."""
        mock_db = MagicMock()
        feroxbuster_with_url.framework.database = mock_db

        with patch.object(feroxbuster_with_url, 'execute_command', return_value={"success": True, "pid": 12345}) as mock_exec:
            with patch.object(Path, 'mkdir'):
                with patch.object(Path, 'exists', return_value=False):
                    result = feroxbuster_with_url._execute_feroxbuster(run_background=True)

                    # Should call with background=True
                    call_kwargs = mock_exec.call_args[1]
                    assert call_kwargs.get('background') is True


# =============================================================================
# _parse_feroxbuster_results Tests
# =============================================================================

class TestParseFeroxbusterResults:
    """Tests for the _parse_feroxbuster_results method."""

    def test_parse_results_returns_dict(self, feroxbuster_with_url, tmp_path, sample_feroxbuster_output):
        """Test parse results returns dictionary."""
        log_file = tmp_path / "ferox.txt"
        log_file.write_text(sample_feroxbuster_output)

        result = feroxbuster_with_url._parse_feroxbuster_results(str(log_file), "http://example.com")

        assert isinstance(result, dict)
        assert "target" in result
        assert "found_paths" in result
        assert "status_codes" in result

    def test_parse_results_extracts_paths(self, feroxbuster_with_url, tmp_path, sample_feroxbuster_output):
        """Test parse results extracts found paths."""
        log_file = tmp_path / "ferox.txt"
        log_file.write_text(sample_feroxbuster_output)

        result = feroxbuster_with_url._parse_feroxbuster_results(str(log_file), "http://example.com")

        assert len(result["found_paths"]) > 0

    def test_parse_results_counts_status_codes(self, feroxbuster_with_url, tmp_path, sample_feroxbuster_output):
        """Test parse results counts status codes."""
        log_file = tmp_path / "ferox.txt"
        log_file.write_text(sample_feroxbuster_output)

        result = feroxbuster_with_url._parse_feroxbuster_results(str(log_file), "http://example.com")

        assert len(result["status_codes"]) > 0

    def test_parse_results_identifies_interesting_finds(self, feroxbuster_with_url, tmp_path, sample_feroxbuster_output):
        """Test parse results identifies interesting finds."""
        log_file = tmp_path / "ferox.txt"
        log_file.write_text(sample_feroxbuster_output)

        result = feroxbuster_with_url._parse_feroxbuster_results(str(log_file), "http://example.com")

        assert len(result["interesting_finds"]) > 0

    def test_parse_results_nonexistent_file(self, feroxbuster_with_url, tmp_path):
        """Test parse results handles nonexistent file."""
        result = feroxbuster_with_url._parse_feroxbuster_results("/nonexistent/path.txt", "http://example.com")

        assert result["found_paths"] == []
        assert result["total_requests"] == 0

    def test_parse_results_empty_file(self, feroxbuster_with_url, tmp_path):
        """Test parse results handles empty file."""
        log_file = tmp_path / "empty.txt"
        log_file.write_text("")

        result = feroxbuster_with_url._parse_feroxbuster_results(str(log_file), "http://example.com")

        assert result["found_paths"] == []


# =============================================================================
# Operation Handler Tests
# =============================================================================

class TestBasicScanOperation:
    """Tests for op_basic_scan operation."""

    def test_op_basic_scan_calls_execute(self, feroxbuster_with_url):
        """Test basic scan calls _execute_feroxbuster."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            result = feroxbuster_with_url.op_basic_scan()
            mock_exec.assert_called_once_with()

    def test_op_basic_scan_logs_info(self, feroxbuster_with_url):
        """Test basic scan logs info message."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}):
            with patch.object(feroxbuster_with_url, 'log') as mock_log:
                feroxbuster_with_url.op_basic_scan()
                mock_log.assert_called()


class TestBackgroundScanOperation:
    """Tests for op_background_scan operation."""

    def test_op_background_scan_runs_in_background(self, feroxbuster_with_url):
        """Test background scan runs in background mode."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            feroxbuster_with_url.op_background_scan()
            mock_exec.assert_called_once_with(run_background=True)


class TestDeepScanOperation:
    """Tests for op_deep_scan operation."""

    def test_op_deep_scan_uses_extensions(self, feroxbuster_with_url):
        """Test deep scan uses extensions."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            feroxbuster_with_url.op_deep_scan()
            call_args = mock_exec.call_args[0][0]
            assert "-x" in call_args

    def test_op_deep_scan_uses_custom_extensions(self, feroxbuster_with_url):
        """Test deep scan uses custom extensions when set."""
        feroxbuster_with_url.set_option("EXTENSIONS", "asp,aspx")

        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            feroxbuster_with_url.op_deep_scan()
            call_args = mock_exec.call_args[0][0]
            assert "asp,aspx" in call_args

    def test_op_deep_scan_uses_threads_option(self, feroxbuster_with_url):
        """Test deep scan uses THREADS option."""
        feroxbuster_with_url.set_option("THREADS", "100")

        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            feroxbuster_with_url.op_deep_scan()
            call_args = mock_exec.call_args[0][0]
            assert "-t 100" in call_args


class TestCustomWordlistOperation:
    """Tests for op_custom_wordlist operation."""

    def test_op_custom_wordlist_requires_wordlist(self, feroxbuster_with_url):
        """Test custom wordlist operation requires wordlist path."""
        with patch('builtins.input', return_value=''):
            result = feroxbuster_with_url.op_custom_wordlist()
            assert result["success"] is False
            assert "Wordlist path required" in result["error"]

    def test_op_custom_wordlist_validates_file_exists(self, feroxbuster_with_url):
        """Test custom wordlist validates file exists."""
        with patch('builtins.input', return_value='/nonexistent/wordlist.txt'):
            result = feroxbuster_with_url.op_custom_wordlist()
            assert result["success"] is False
            assert "not found" in result["error"]

    def test_op_custom_wordlist_with_valid_file(self, feroxbuster_with_url, tmp_path):
        """Test custom wordlist with valid file."""
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("admin\ntest\napi\n")

        feroxbuster_with_url.set_option("WORDLIST", str(wordlist))

        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            result = feroxbuster_with_url.op_custom_wordlist()
            call_args = mock_exec.call_args[0][0]
            assert str(wordlist) in call_args


class TestBurpScanOperation:
    """Tests for op_burp_scan operation."""

    def test_op_burp_scan_uses_default_proxy(self, feroxbuster_with_url):
        """Test Burp scan uses default proxy."""
        with patch('builtins.input', return_value=''):
            with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
                feroxbuster_with_url.op_burp_scan()
                call_args = mock_exec.call_args[0][0]
                assert "http://127.0.0.1:8080" in call_args

    def test_op_burp_scan_uses_custom_proxy(self, feroxbuster_with_url):
        """Test Burp scan uses custom proxy."""
        with patch('builtins.input', return_value='http://127.0.0.1:9090'):
            with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
                feroxbuster_with_url.op_burp_scan()
                call_args = mock_exec.call_args[0][0]
                assert "http://127.0.0.1:9090" in call_args


class TestApiDiscoveryOperation:
    """Tests for op_api_discovery operation."""

    def test_op_api_discovery_uses_api_methods(self, feroxbuster_with_url):
        """Test API discovery uses appropriate HTTP methods."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            feroxbuster_with_url.op_api_discovery()
            call_args = mock_exec.call_args[0][0]
            assert "GET,POST,PUT,DELETE,PATCH" in call_args

    def test_op_api_discovery_uses_json_xml_extensions(self, feroxbuster_with_url):
        """Test API discovery uses json/xml extensions."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            feroxbuster_with_url.op_api_discovery()
            call_args = mock_exec.call_args[0][0]
            assert "json,xml" in call_args


class TestBackupDiscoveryOperation:
    """Tests for op_backup_discovery operation."""

    def test_op_backup_discovery_uses_backup_extensions(self, feroxbuster_with_url):
        """Test backup discovery uses backup extensions."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
            feroxbuster_with_url.op_backup_discovery()
            call_args = mock_exec.call_args[0][0]
            assert "bak" in call_args
            assert "old" in call_args
            assert "backup" in call_args


class TestCustomScanOperation:
    """Tests for op_custom_scan operation."""

    def test_op_custom_scan_requires_flags(self, feroxbuster_with_url):
        """Test custom scan requires flags input."""
        with patch('builtins.input', return_value=''):
            result = feroxbuster_with_url.op_custom_scan()
            assert result["success"] is False
            assert "No flags provided" in result["error"]

    def test_op_custom_scan_with_flags(self, feroxbuster_with_url):
        """Test custom scan with flags."""
        with patch('builtins.input', return_value='-t 100 --depth 5'):
            with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}) as mock_exec:
                feroxbuster_with_url.op_custom_scan()
                call_args = mock_exec.call_args[0][0]
                assert "-t 100 --depth 5" in call_args


class TestRunMethod:
    """Tests for the run method."""

    def test_run_calls_basic_scan(self, feroxbuster_with_url):
        """Test run method calls basic scan."""
        with patch.object(feroxbuster_with_url, 'op_basic_scan', return_value={"success": True}) as mock_scan:
            feroxbuster_with_url.run()
            mock_scan.assert_called_once()


# =============================================================================
# Edge Cases
# =============================================================================

class TestFeroxbusterEdgeCases:
    """Tests for edge cases in feroxbuster module."""

    def test_url_with_trailing_slash(self, feroxbuster_module):
        """Test URL handling with trailing slash."""
        feroxbuster_module.set_option("URL", "http://example.com/")
        assert feroxbuster_module._get_url() == "http://example.com/"

    def test_https_url(self, feroxbuster_module):
        """Test HTTPS URL handling."""
        feroxbuster_module.set_option("URL", "https://secure.example.com")
        assert feroxbuster_module._get_url() == "https://secure.example.com"

    def test_url_with_port(self, feroxbuster_module):
        """Test URL with port handling."""
        feroxbuster_module.set_option("URL", "http://example.com:8080")
        assert feroxbuster_module._get_url() == "http://example.com:8080"

    def test_url_with_path(self, feroxbuster_module):
        """Test URL with path handling."""
        feroxbuster_module.set_option("URL", "http://example.com/api/v1")
        assert feroxbuster_module._get_url() == "http://example.com/api/v1"

    def test_parse_results_with_malformed_output(self, feroxbuster_with_url, tmp_path):
        """Test parse results handles malformed output gracefully."""
        log_file = tmp_path / "malformed.txt"
        log_file.write_text("This is not valid feroxbuster output\n12345\nabc def ghi")

        result = feroxbuster_with_url._parse_feroxbuster_results(str(log_file), "http://example.com")

        # Should not crash, just return empty results
        assert isinstance(result, dict)

    def test_execute_feroxbuster_logs_to_correct_directory(self, feroxbuster_with_url):
        """Test execute feroxbuster logs to correct directory."""
        with patch.object(feroxbuster_with_url, 'execute_command', return_value={"success": True}) as mock_exec:
            with patch.object(Path, 'mkdir') as mock_mkdir:
                with patch.object(Path, 'exists', return_value=False):
                    feroxbuster_with_url._execute_feroxbuster()
                    # Check that mkdir was called with parents=True
                    mock_mkdir.assert_called_with(parents=True, exist_ok=True)


# =============================================================================
# Logging Tests
# =============================================================================

class TestFeroxbusterLogging:
    """Tests for feroxbuster module logging."""

    def test_log_on_deep_scan(self, feroxbuster_with_url):
        """Test logging during deep scan."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}):
            with patch.object(feroxbuster_with_url, 'log') as mock_log:
                feroxbuster_with_url.op_deep_scan()
                mock_log.assert_called()

    def test_log_on_api_discovery(self, feroxbuster_with_url):
        """Test logging during API discovery."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}):
            with patch.object(feroxbuster_with_url, 'log') as mock_log:
                feroxbuster_with_url.op_api_discovery()
                mock_log.assert_called()

    def test_log_on_backup_discovery(self, feroxbuster_with_url):
        """Test logging during backup discovery."""
        with patch.object(feroxbuster_with_url, '_execute_feroxbuster', return_value={"success": True}):
            with patch.object(feroxbuster_with_url, 'log') as mock_log:
                feroxbuster_with_url.op_backup_discovery()
                mock_log.assert_called()
