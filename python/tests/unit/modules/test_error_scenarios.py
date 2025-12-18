"""
Unit tests for module error scenarios.

Tests cover:
- Malformed tool output parsing
- Network errors during execution
- Missing dependencies
- Invalid option combinations
- Tool-specific error handling
"""

import pytest
import subprocess
from unittest.mock import MagicMock, patch
from pathlib import Path


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def wfuzz_module(mock_framework_minimal):
    """Create a WfuzzModule for testing."""
    from purplesploit.modules.web.wfuzz import WfuzzModule
    return WfuzzModule(mock_framework_minimal)


@pytest.fixture
def feroxbuster_module(mock_framework_minimal):
    """Create a FeroxbusterModule for testing."""
    from purplesploit.modules.web.feroxbuster import FeroxbusterModule
    return FeroxbusterModule(mock_framework_minimal)


@pytest.fixture
def nxc_module(mock_framework_minimal):
    """Create an NXCSMBModule for testing."""
    from purplesploit.modules.network.nxc_smb import NXCSMBModule
    return NXCSMBModule(mock_framework_minimal)


# =============================================================================
# Malformed Output Parsing Tests
# =============================================================================

class TestMalformedOutputParsing:
    """Tests for handling malformed tool output."""

    def test_wfuzz_parse_empty_output(self, wfuzz_module):
        """Test wfuzz parsing with empty output."""
        result = wfuzz_module.parse_output("")
        assert result["found_paths"] == []
        assert result["status_codes"] == {}

    def test_wfuzz_parse_garbage_output(self, wfuzz_module):
        """Test wfuzz parsing with garbage output."""
        garbage = "asdf\n1234\n!@#$%^&*()\nrandom text here"
        result = wfuzz_module.parse_output(garbage)
        assert isinstance(result, dict)
        assert "found_paths" in result

    def test_wfuzz_parse_partial_output(self, wfuzz_module):
        """Test wfuzz parsing with partial/truncated output."""
        partial = """
000000001:   200        7 L
000000002:   301        9 L      28 W       325
"""
        result = wfuzz_module.parse_output(partial)
        assert isinstance(result, dict)

    def test_wfuzz_parse_responses_binary_data(self, wfuzz_module):
        """Test wfuzz response parsing with binary data."""
        binary_like = "\x00\x01\x02\x03 test \xff\xfe"
        result = wfuzz_module._parse_wfuzz_responses(binary_like)
        assert result["total_responses"] >= 0

    def test_feroxbuster_parse_empty_file(self, feroxbuster_module, tmp_path):
        """Test feroxbuster parsing with empty file."""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        result = feroxbuster_module._parse_feroxbuster_results(str(empty_file), "http://test.com")
        assert result["found_paths"] == []
        assert result["total_requests"] == 0

    def test_feroxbuster_parse_corrupted_file(self, feroxbuster_module, tmp_path):
        """Test feroxbuster parsing with corrupted file."""
        corrupted = tmp_path / "corrupted.txt"
        corrupted.write_bytes(b"\x00\x01\x02\xff\xfe corrupted data")

        result = feroxbuster_module._parse_feroxbuster_results(str(corrupted), "http://test.com")
        assert isinstance(result, dict)

    def test_feroxbuster_parse_nonexistent_file(self, feroxbuster_module):
        """Test feroxbuster parsing with nonexistent file."""
        result = feroxbuster_module._parse_feroxbuster_results("/nonexistent/path.txt", "http://test.com")
        assert result["found_paths"] == []


# =============================================================================
# Network Error Tests
# =============================================================================

class TestNetworkErrors:
    """Tests for handling network-related errors."""

    def test_wfuzz_connection_refused(self, wfuzz_module):
        """Test wfuzz when connection is refused."""
        wfuzz_module.set_option("TARGET", "localhost")
        wfuzz_module.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {
                "success": False,
                "error": "Connection refused",
                "output": ""
            }
            result = wfuzz_module._execute_wfuzz("-w /test.txt 'http://localhost/FUZZ'")
            assert result["success"] is False

    def test_wfuzz_dns_resolution_failure(self, wfuzz_module):
        """Test wfuzz with DNS resolution failure."""
        wfuzz_module.set_option("TARGET", "nonexistent.invalid.domain")
        wfuzz_module.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {
                "success": False,
                "error": "Could not resolve host",
                "output": ""
            }
            result = wfuzz_module._execute_wfuzz("-w /test.txt 'http://invalid/FUZZ'")
            assert result["success"] is False

    def test_nxc_smb_connection_timeout(self, nxc_module):
        """Test NXC SMB with connection timeout."""
        nxc_module.set_option("RHOST", "192.168.1.1")

        with patch.object(nxc_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {
                "success": False,
                "error": "Connection timed out",
                "output": ""
            }
            result = nxc_module._execute_nxc()
            assert result["success"] is False

    def test_nxc_smb_host_unreachable(self, nxc_module):
        """Test NXC SMB with unreachable host."""
        nxc_module.set_option("RHOST", "10.255.255.1")

        with patch.object(nxc_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {
                "success": False,
                "error": "No route to host",
                "output": ""
            }
            result = nxc_module._execute_nxc()
            assert result["success"] is False


# =============================================================================
# Missing Dependency Tests
# =============================================================================

class TestMissingDependencies:
    """Tests for handling missing tool dependencies."""

    def test_wfuzz_tool_not_found(self, wfuzz_module):
        """Test wfuzz when tool is not installed."""
        with patch('shutil.which', return_value=None):
            is_available = wfuzz_module.check_tool_installed()
            assert is_available is False

    def test_feroxbuster_tool_not_found(self, feroxbuster_module):
        """Test feroxbuster when tool is not installed."""
        with patch('shutil.which', return_value=None):
            is_available = feroxbuster_module.check_tool_installed()
            assert is_available is False

    def test_nxc_tool_not_found(self, nxc_module):
        """Test NXC when tool is not installed."""
        with patch('shutil.which', return_value=None):
            is_available = nxc_module.check_tool_installed()
            assert is_available is False


# =============================================================================
# Invalid Option Combination Tests
# =============================================================================

class TestInvalidOptionCombinations:
    """Tests for handling invalid option combinations."""

    def test_wfuzz_no_target_no_url(self, wfuzz_module):
        """Test wfuzz without target or URL."""
        result = wfuzz_module.op_dir_fuzz()
        assert result["success"] is False
        assert "TARGET" in result.get("error", "")

    def test_nxc_pass_the_hash_no_hash(self, nxc_module):
        """Test NXC PTH without hash."""
        nxc_module.set_option("RHOST", "192.168.1.1")
        with patch('builtins.input', return_value=''):
            result = nxc_module.op_pass_the_hash()
            assert result["success"] is False
            assert "Hash required" in result.get("error", "")

    def test_feroxbuster_no_url(self, feroxbuster_module):
        """Test feroxbuster without URL."""
        with patch.object(feroxbuster_module, '_get_url', return_value=None):
            result = feroxbuster_module._execute_feroxbuster()
            assert result["success"] is False
            assert "URL required" in result.get("error", "")


# =============================================================================
# Tool-Specific Error Handling Tests
# =============================================================================

class TestToolSpecificErrors:
    """Tests for tool-specific error handling."""

    def test_wfuzz_rate_limiting_output(self, wfuzz_module):
        """Test wfuzz handling rate limiting responses."""
        rate_limited_output = """
000000001:   429        0 L       0 W         0 Ch      "test1"
000000002:   429        0 L       0 W         0 Ch      "test2"
000000003:   429        0 L       0 W         0 Ch      "test3"
"""
        result = wfuzz_module.parse_output(rate_limited_output)
        # Should parse 429 responses
        assert "429" in result.get("status_codes", {})

    def test_wfuzz_all_filtered_output(self, wfuzz_module):
        """Test wfuzz when all responses are filtered."""
        filtered_output = """
Total time: 5.0
Processed Requests: 1000
Filtered Requests: 1000
"""
        result = wfuzz_module.parse_output(filtered_output)
        assert result["found_paths"] == []

    def test_nxc_authentication_failure(self, nxc_module):
        """Test NXC with authentication failure."""
        nxc_module.set_option("RHOST", "192.168.1.1")
        nxc_module.set_option("USERNAME", "admin")
        nxc_module.set_option("PASSWORD", "wrongpass")

        with patch.object(nxc_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {
                "success": True,  # Command ran but auth failed
                "output": "[-] 192.168.1.1:445 admin:wrongpass STATUS_LOGON_FAILURE"
            }
            result = nxc_module._execute_nxc()
            # Should still return successfully (command ran)
            assert result["success"] is True
            assert "LOGON_FAILURE" in result.get("output", "")

    def test_nxc_access_denied(self, nxc_module):
        """Test NXC with access denied."""
        nxc_module.set_option("RHOST", "192.168.1.1")
        nxc_module.set_option("USERNAME", "admin")
        nxc_module.set_option("PASSWORD", "password")

        with patch.object(nxc_module, 'execute_command') as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "output": "[+] 192.168.1.1:445 admin:password (Pwn3d!) ACCESS_DENIED"
            }
            result = nxc_module._execute_nxc("--sam")
            assert result["success"] is True


# =============================================================================
# Resource Exhaustion Tests
# =============================================================================

class TestResourceExhaustion:
    """Tests for handling resource exhaustion scenarios."""

    def test_wfuzz_large_output(self, wfuzz_module):
        """Test wfuzz with very large output."""
        # Generate large output
        large_output = "\n".join([
            f"00000{i:04d}:   200        7 L      11 W       162 Ch      \"path{i}\""
            for i in range(10000)
        ])

        result = wfuzz_module.parse_output(large_output)
        assert len(result["found_paths"]) > 0

    def test_wfuzz_parse_responses_large_output(self, wfuzz_module):
        """Test wfuzz response parsing with large output."""
        large_output = "\n".join([
            f"00000{i:04d}:   200        7 L      11 W       162 Ch      \"path{i}\""
            for i in range(5000)
        ])

        stats = wfuzz_module._parse_wfuzz_responses(large_output)
        assert stats["total_responses"] > 0


# =============================================================================
# Edge Case Input Tests
# =============================================================================

class TestEdgeCaseInputs:
    """Tests for handling edge case inputs."""

    def test_wfuzz_unicode_in_output(self, wfuzz_module):
        """Test wfuzz with unicode characters in output."""
        unicode_output = """
000000001:   200        7 L      11 W       162 Ch      "файл"
000000002:   200        7 L      11 W       162 Ch      "中文"
000000003:   200        7 L      11 W       162 Ch      "🔒secure"
"""
        result = wfuzz_module.parse_output(unicode_output)
        assert isinstance(result, dict)

    def test_nxc_special_chars_in_password(self, nxc_module):
        """Test NXC with special characters in password."""
        nxc_module.set_option("RHOST", "192.168.1.1")
        nxc_module.set_option("USERNAME", "admin")
        nxc_module.set_option("PASSWORD", "P@ss'w\"ord$!#%")

        auth = nxc_module._build_auth()
        assert "-u 'admin'" in auth
        # Password should be in the auth string

    def test_nxc_empty_domain(self, nxc_module):
        """Test NXC with empty domain."""
        nxc_module.set_option("RHOST", "192.168.1.1")
        nxc_module.set_option("DOMAIN", "")

        with patch.object(nxc_module, 'execute_command', return_value={"success": True}) as mock_exec:
            nxc_module._execute_nxc()
            call_args = mock_exec.call_args[0][0]
            # Empty domain should not add -d flag
            assert "-d ''" not in call_args

    def test_wfuzz_url_with_query_params(self, wfuzz_module):
        """Test wfuzz with URL containing query parameters."""
        wfuzz_module.set_option("URL", "http://example.com/path?param=value&other=test")

        command = wfuzz_module.build_command()
        assert "example.com" in command
        # URL should be properly quoted


# =============================================================================
# Interrupt Handling Tests
# =============================================================================

class TestInterruptHandling:
    """Tests for handling interrupts and cancellations."""

    def test_nxc_download_cancelled(self, nxc_module):
        """Test NXC download operation cancelled."""
        nxc_module.set_option("RHOST", "192.168.1.1")

        with patch('builtins.input', return_value='n'):
            result = nxc_module.op_download_all()
            assert result["success"] is False
            assert "cancelled" in result.get("error", "").lower()

    def test_feroxbuster_custom_scan_no_flags(self, feroxbuster_module):
        """Test feroxbuster custom scan with no flags."""
        with patch('builtins.input', return_value=''):
            result = feroxbuster_module.op_custom_scan()
            assert result["success"] is False


# =============================================================================
# State Consistency Tests
# =============================================================================

class TestStateConsistency:
    """Tests for maintaining state consistency after errors."""

    def test_module_state_after_failed_run(self, wfuzz_module):
        """Test module state is consistent after failed run."""
        wfuzz_module.set_option("TARGET", "example.com")
        original_target = wfuzz_module.get_option("TARGET")

        with patch.object(wfuzz_module, 'execute_command', side_effect=Exception("Error")):
            try:
                wfuzz_module._execute_wfuzz("-w /test.txt 'http://example.com/FUZZ'")
            except Exception:
                pass

        # Target should still be set
        assert wfuzz_module.get_option("TARGET") == original_target

    def test_module_options_preserved_after_error(self, nxc_module):
        """Test module options are preserved after error."""
        nxc_module.set_option("RHOST", "192.168.1.1")
        nxc_module.set_option("USERNAME", "admin")
        nxc_module.set_option("PASSWORD", "password")

        with patch.object(nxc_module, 'execute_command', side_effect=Exception("Error")):
            try:
                nxc_module._execute_nxc()
            except Exception:
                pass

        # Options should still be set
        assert nxc_module.get_option("RHOST") == "192.168.1.1"
        assert nxc_module.get_option("USERNAME") == "admin"
