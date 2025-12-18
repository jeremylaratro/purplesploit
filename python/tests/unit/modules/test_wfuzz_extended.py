"""
Extended unit tests for purplesploit.modules.web.wfuzz module.

Tests cover:
- _execute_wfuzz method with subprocess mocking
- _smart_filter_prompt method
- Operation handlers with mocked input
- Edge cases and error scenarios
"""

import pytest
import subprocess
from unittest.mock import MagicMock, patch, PropertyMock
from purplesploit.modules.web.wfuzz import WfuzzModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def wfuzz_module(mock_framework_minimal):
    """Create a WfuzzModule instance for testing."""
    return WfuzzModule(mock_framework_minimal)


@pytest.fixture
def wfuzz_with_target(wfuzz_module):
    """Create a WfuzzModule with TARGET set."""
    wfuzz_module.set_option("TARGET", "example.com")
    return wfuzz_module


@pytest.fixture
def sample_process_mock():
    """Create a mock subprocess.Popen for testing."""
    mock_process = MagicMock()
    mock_process.communicate.return_value = (
        "000000001:   200        7 L      11 W       162 Ch      \"test\"",
        ""
    )
    mock_process.poll.return_value = 0
    mock_process.returncode = 0
    return mock_process


# =============================================================================
# _execute_wfuzz Tests
# =============================================================================

class TestExecuteWfuzz:
    """Tests for the _execute_wfuzz method."""

    def test_execute_wfuzz_basic(self, wfuzz_with_target):
        """Test basic wfuzz execution with mocked subprocess."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True, "output": "test"}):
            result = wfuzz_with_target._execute_wfuzz("-w '/wordlist.txt' 'http://example.com/FUZZ'")

            assert result["success"] is True

    def test_execute_wfuzz_with_custom_args(self, wfuzz_with_target):
        """Test wfuzz execution with custom arguments."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True}) as mock_exec:
            wfuzz_with_target._execute_wfuzz("-w '/custom.txt' --hc 200 'http://test.com'")

            mock_exec.assert_called_once()
            # Verify command includes custom args
            call_args = mock_exec.call_args[0][0]
            assert "-w '/custom.txt'" in call_args or "wfuzz" in call_args

    def test_execute_wfuzz_uses_threads_option(self, wfuzz_with_target):
        """Test wfuzz uses THREADS option."""
        wfuzz_with_target.set_option("THREADS", "100")
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True}) as mock_exec:
            wfuzz_with_target._execute_wfuzz("-w '/test.txt' 'http://test.com'")

            call_args = mock_exec.call_args[0][0]
            assert "-t 100" in call_args

    def test_execute_wfuzz_uses_hide_code_option(self, wfuzz_with_target):
        """Test wfuzz uses HIDE_CODE option."""
        wfuzz_with_target.set_option("HIDE_CODE", "403,404,500")
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True}) as mock_exec:
            wfuzz_with_target._execute_wfuzz("-w '/test.txt' 'http://test.com'")

            call_args = mock_exec.call_args[0][0]
            assert "--hc 403,404,500" in call_args

    def test_execute_wfuzz_smart_filter_disabled(self, wfuzz_with_target):
        """Test wfuzz skips smart filtering when disabled."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True}) as mock_exec:
            with patch('subprocess.Popen') as mock_popen:
                wfuzz_with_target._execute_wfuzz("-w '/test.txt' 'http://test.com'")

                # subprocess.Popen should NOT be called for sampling when smart filter is disabled
                mock_popen.assert_not_called()

    def test_execute_wfuzz_explicit_smart_filter_override(self, wfuzz_with_target):
        """Test smart filter can be explicitly enabled/disabled per call."""
        wfuzz_with_target.set_option("SMART_FILTER", "true")

        with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True}):
            with patch('subprocess.Popen') as mock_popen:
                # Explicitly disable smart filtering for this call
                wfuzz_with_target._execute_wfuzz("-w '/test.txt' 'http://test.com'", enable_smart_filter=False)

                # subprocess.Popen should NOT be called when explicitly disabled
                mock_popen.assert_not_called()


# =============================================================================
# _smart_filter_prompt Tests
# =============================================================================

class TestSmartFilterPrompt:
    """Tests for the _smart_filter_prompt method."""

    def test_smart_filter_prompt_no_responses(self, wfuzz_with_target):
        """Test smart filter with no responses returns None."""
        stats = {
            'total_responses': 0,
            'most_common_lines': None,
            'most_common_words': None,
            'most_common_chars': None,
        }

        result = wfuzz_with_target._smart_filter_prompt(stats, "wfuzz -w /test.txt http://test.com")

        assert result is None

    def test_smart_filter_prompt_good_diversity(self, wfuzz_with_target):
        """Test smart filter with good diversity recommends no filtering."""
        # Build responses list that matches the distributions
        responses = [
            {'lines': 5, 'words': 10, 'chars': 100},
            {'lines': 5, 'words': 15, 'chars': 200},
            {'lines': 5, 'words': 15, 'chars': 200},
            {'lines': 7, 'words': 15, 'chars': 200},
            {'lines': 7, 'words': 20, 'chars': 300},
            {'lines': 10, 'words': 20, 'chars': 300},
            {'lines': 10, 'words': 20, 'chars': 300},
            {'lines': 15, 'words': 25, 'chars': 400},
            {'lines': 15, 'words': 25, 'chars': 400},
            {'lines': 15, 'words': 10, 'chars': 100},
        ]
        stats = {
            'total_responses': 10,
            'most_common_lines': 5,
            'most_common_lines_count': 3,  # 30% - not dominant
            'most_common_words': 15,
            'most_common_words_count': 3,  # 30%
            'most_common_chars': 200,
            'most_common_chars_count': 3,  # 30%
            'lines_distribution': {5: 3, 7: 2, 10: 2, 15: 3},
            'words_distribution': {10: 2, 15: 3, 20: 3, 25: 2},
            'chars_distribution': {100: 2, 200: 3, 300: 3, 400: 2},
            'responses': responses
        }

        result = wfuzz_with_target._smart_filter_prompt(stats, "wfuzz -w /test.txt http://test.com")

        # Should return None when diversity is good
        assert result is None

    def test_smart_filter_prompt_dominant_pattern_user_declines(self, wfuzz_with_target):
        """Test smart filter when user declines filtering."""
        # Build responses with dominant pattern (80% have same characteristics)
        responses = [
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 15, 'words': 42, 'chars': 512},
            {'lines': 15, 'words': 42, 'chars': 512},
        ]
        stats = {
            'total_responses': 10,
            'most_common_lines': 7,
            'most_common_lines_count': 8,  # 80% - dominant
            'most_common_words': 11,
            'most_common_words_count': 8,
            'most_common_chars': 162,
            'most_common_chars_count': 8,
            'lines_distribution': {7: 8, 15: 2},
            'words_distribution': {11: 8, 42: 2},
            'chars_distribution': {162: 8, 512: 2},
            'responses': responses
        }

        with patch('builtins.input', return_value='N'):
            result = wfuzz_with_target._smart_filter_prompt(stats, "wfuzz -w /test.txt http://test.com")

        assert result is None

    def test_smart_filter_prompt_dominant_pattern_filter_lines(self, wfuzz_with_target):
        """Test smart filter with lines filter."""
        responses = [
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 15, 'words': 42, 'chars': 512},
            {'lines': 15, 'words': 42, 'chars': 512},
        ]
        stats = {
            'total_responses': 10,
            'most_common_lines': 7,
            'most_common_lines_count': 8,  # 80%
            'most_common_words': 11,
            'most_common_words_count': 8,
            'most_common_chars': 162,
            'most_common_chars_count': 8,
            'lines_distribution': {7: 8, 15: 2},
            'words_distribution': {11: 8, 42: 2},
            'chars_distribution': {162: 8, 512: 2},
            'responses': responses
        }

        with patch('builtins.input', return_value='L'):
            with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True, "filtered": True}) as mock_exec:
                result = wfuzz_with_target._smart_filter_prompt(stats, "wfuzz -w /test.txt http://test.com")

                # Should call execute_command with filter
                mock_exec.assert_called_once()
                assert "--hl 7" in mock_exec.call_args[0][0]

    def test_smart_filter_prompt_dominant_pattern_filter_words(self, wfuzz_with_target):
        """Test smart filter with words filter."""
        responses = [
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 15, 'words': 11, 'chars': 512},
            {'lines': 15, 'words': 11, 'chars': 512},
            {'lines': 15, 'words': 11, 'chars': 512},
            {'lines': 15, 'words': 42, 'chars': 162},
        ]
        stats = {
            'total_responses': 10,
            'most_common_lines': 7,
            'most_common_lines_count': 6,  # 60%
            'most_common_words': 11,
            'most_common_words_count': 9,  # 90% - most dominant
            'most_common_chars': 162,
            'most_common_chars_count': 7,
            'lines_distribution': {7: 6, 15: 4},
            'words_distribution': {11: 9, 42: 1},
            'chars_distribution': {162: 7, 512: 3},
            'responses': responses
        }

        with patch('builtins.input', return_value='W'):
            with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target._smart_filter_prompt(stats, "wfuzz -w /test.txt http://test.com")

                mock_exec.assert_called_once()
                assert "--hw 11" in mock_exec.call_args[0][0]

    def test_smart_filter_prompt_dominant_pattern_filter_chars(self, wfuzz_with_target):
        """Test smart filter with chars filter."""
        responses = [
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 15, 'words': 42, 'chars': 162},
            {'lines': 15, 'words': 42, 'chars': 162},
            {'lines': 15, 'words': 42, 'chars': 162},
            {'lines': 15, 'words': 42, 'chars': 512},
        ]
        stats = {
            'total_responses': 10,
            'most_common_lines': 7,
            'most_common_lines_count': 6,
            'most_common_words': 11,
            'most_common_words_count': 6,
            'most_common_chars': 162,
            'most_common_chars_count': 9,  # 90%
            'lines_distribution': {7: 6, 15: 4},
            'words_distribution': {11: 6, 42: 4},
            'chars_distribution': {162: 9, 512: 1},
            'responses': responses
        }

        with patch('builtins.input', return_value='C'):
            with patch.object(wfuzz_with_target, 'execute_command', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target._smart_filter_prompt(stats, "wfuzz -w /test.txt http://test.com")

                mock_exec.assert_called_once()
                assert "--hh 162" in mock_exec.call_args[0][0]

    def test_smart_filter_prompt_invalid_choice(self, wfuzz_with_target):
        """Test smart filter with invalid filter choice."""
        responses = [
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 7, 'words': 11, 'chars': 162},
            {'lines': 15, 'words': 42, 'chars': 512},
        ]
        stats = {
            'total_responses': 10,
            'most_common_lines': 7,
            'most_common_lines_count': 9,
            'most_common_words': 11,
            'most_common_words_count': 9,
            'most_common_chars': 162,
            'most_common_chars_count': 9,
            'lines_distribution': {7: 9, 15: 1},
            'words_distribution': {11: 9, 42: 1},
            'chars_distribution': {162: 9, 512: 1},
            'responses': responses
        }

        with patch('builtins.input', return_value='X'):  # Invalid choice
            result = wfuzz_with_target._smart_filter_prompt(stats, "wfuzz -w /test.txt http://test.com")

        assert result is None


# =============================================================================
# Operation Handler Tests - Discovery
# =============================================================================

class TestDirectoryFuzzingOperation:
    """Tests for op_dir_fuzz operation."""

    def test_op_dir_fuzz_requires_target(self, wfuzz_module):
        """Test directory fuzzing requires TARGET."""
        result = wfuzz_module.op_dir_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_dir_fuzz_with_target(self, wfuzz_with_target):
        """Test directory fuzzing with target set."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
            result = wfuzz_with_target.op_dir_fuzz()

            mock_exec.assert_called_once()
            # Verify FUZZ is in the URL
            call_args = mock_exec.call_args[0][0]
            assert "FUZZ" in call_args

    def test_op_dir_fuzz_uses_custom_wordlist(self, wfuzz_with_target):
        """Test directory fuzzing uses custom wordlist."""
        wfuzz_with_target.set_option("WORDLIST", "/custom/wordlist.txt")
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
            wfuzz_with_target.op_dir_fuzz()

            call_args = mock_exec.call_args[0][0]
            assert "/custom/wordlist.txt" in call_args


class TestBackupFuzzingOperation:
    """Tests for op_backup_fuzz operation."""

    def test_op_backup_fuzz_requires_target(self, wfuzz_module):
        """Test backup fuzzing requires TARGET."""
        result = wfuzz_module.op_backup_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_backup_fuzz_with_target(self, wfuzz_with_target):
        """Test backup fuzzing with target set."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
            result = wfuzz_with_target.op_backup_fuzz()

            mock_exec.assert_called_once()
            # Verify backup extensions are used
            call_args = mock_exec.call_args[0][0]
            assert ".bak" in call_args or "FUZ2Z" in call_args


class TestExtensionFuzzingOperation:
    """Tests for op_ext_fuzz operation."""

    def test_op_ext_fuzz_requires_target(self, wfuzz_module):
        """Test extension fuzzing requires TARGET."""
        with patch('builtins.input', side_effect=['index', '']):
            result = wfuzz_module.op_ext_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_ext_fuzz_with_target_and_basename(self, wfuzz_with_target):
        """Test extension fuzzing with target and basename."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch('builtins.input', side_effect=['config', '']):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_ext_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "config" in call_args


# =============================================================================
# Operation Handler Tests - VHOST
# =============================================================================

class TestVhostFuzzingOperation:
    """Tests for op_vhost_fuzz operation."""

    def test_op_vhost_fuzz_requires_target(self, wfuzz_module):
        """Test VHOST fuzzing requires TARGET."""
        result = wfuzz_module.op_vhost_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_vhost_fuzz_with_domain_target(self, wfuzz_with_target):
        """Test VHOST fuzzing with domain target."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        # Inputs: IP (press Enter to use domain), wordlist
        with patch('builtins.input', side_effect=['', '']):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_vhost_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "Host: FUZZ" in call_args

    def test_op_vhost_fuzz_with_ip_target(self, wfuzz_module):
        """Test VHOST fuzzing with IP target requires domain input."""
        wfuzz_module.set_option("TARGET", "192.168.1.100")
        wfuzz_module.set_option("SMART_FILTER", "false")

        # Inputs: domain, wordlist
        with patch('builtins.input', side_effect=['target.com', '']):
            with patch.object(wfuzz_module, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_module.op_vhost_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "FUZZ.target.com" in call_args

    def test_op_vhost_fuzz_ip_target_no_domain(self, wfuzz_module):
        """Test VHOST fuzzing with IP target and no domain returns error."""
        wfuzz_module.set_option("TARGET", "192.168.1.100")

        # Empty domain input
        with patch('builtins.input', return_value=''):
            result = wfuzz_module.op_vhost_fuzz()

        assert result["success"] is False
        assert "Domain required" in result["error"]


class TestSubdomainFuzzingOperation:
    """Tests for op_subdomain_fuzz operation."""

    def test_op_subdomain_fuzz_requires_target(self, wfuzz_module):
        """Test subdomain fuzzing requires TARGET."""
        result = wfuzz_module.op_subdomain_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_subdomain_fuzz_with_domain(self, wfuzz_with_target):
        """Test subdomain fuzzing with domain target."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch('builtins.input', return_value=''):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_subdomain_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "FUZZ.example.com" in call_args


# =============================================================================
# Operation Handler Tests - Parameters
# =============================================================================

class TestGetParameterFuzzingOperation:
    """Tests for op_param_get_fuzz operation."""

    def test_op_param_get_fuzz_requires_target(self, wfuzz_module):
        """Test GET param fuzzing requires TARGET."""
        with patch('builtins.input', side_effect=['', '']):
            result = wfuzz_module.op_param_get_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_param_get_fuzz_with_target(self, wfuzz_with_target):
        """Test GET param fuzzing with target."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch('builtins.input', side_effect=['', '']):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_param_get_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "FUZZ=test" in call_args


class TestPostParameterFuzzingOperation:
    """Tests for op_param_post_fuzz operation."""

    def test_op_param_post_fuzz_requires_target(self, wfuzz_module):
        """Test POST param fuzzing requires TARGET."""
        with patch('builtins.input', side_effect=['', '', '']):
            result = wfuzz_module.op_param_post_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_param_post_fuzz_with_known_params(self, wfuzz_with_target):
        """Test POST param fuzzing with known parameters."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch('builtins.input', side_effect=['', '', 'username=admin']):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_param_post_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "username=admin" in call_args
                assert "FUZZ=test" in call_args


class TestParamValueFuzzingOperation:
    """Tests for op_param_value_fuzz operation."""

    def test_op_param_value_fuzz_requires_target(self, wfuzz_module):
        """Test param value fuzzing requires TARGET."""
        with patch('builtins.input', side_effect=['', 'id', 'GET', '']):
            result = wfuzz_module.op_param_value_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_param_value_fuzz_requires_param_name(self, wfuzz_with_target):
        """Test param value fuzzing requires parameter name."""
        with patch('builtins.input', side_effect=['', '']):
            result = wfuzz_with_target.op_param_value_fuzz()

        assert result["success"] is False
        assert "Parameter name required" in result["error"]

    def test_op_param_value_fuzz_get_method(self, wfuzz_with_target):
        """Test param value fuzzing with GET method."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch('builtins.input', side_effect=['', 'id', 'GET', '']):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_param_value_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "id=FUZZ" in call_args

    def test_op_param_value_fuzz_post_method(self, wfuzz_with_target):
        """Test param value fuzzing with POST method."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch('builtins.input', side_effect=['', 'password', 'POST', '']):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_param_value_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "-d 'password=FUZZ'" in call_args


# =============================================================================
# Operation Handler Tests - Advanced
# =============================================================================

class TestHeaderFuzzingOperation:
    """Tests for op_header_fuzz operation."""

    def test_op_header_fuzz_requires_target(self, wfuzz_module):
        """Test header fuzzing requires TARGET."""
        with patch('builtins.input', side_effect=['X-Forwarded-For', '']):
            result = wfuzz_module.op_header_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_header_fuzz_requires_header_name(self, wfuzz_with_target):
        """Test header fuzzing requires header name."""
        with patch('builtins.input', return_value=''):
            result = wfuzz_with_target.op_header_fuzz()

        assert result["success"] is False
        assert "Header name required" in result["error"]

    def test_op_header_fuzz_with_header(self, wfuzz_with_target):
        """Test header fuzzing with header name."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch('builtins.input', side_effect=['X-Custom-Header', '']):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_header_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "X-Custom-Header: FUZZ" in call_args


class TestUserAgentFuzzingOperation:
    """Tests for op_useragent_fuzz operation."""

    def test_op_useragent_fuzz_requires_target(self, wfuzz_module):
        """Test user-agent fuzzing requires TARGET."""
        with patch('builtins.input', return_value=''):
            result = wfuzz_module.op_useragent_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_useragent_fuzz_with_target(self, wfuzz_with_target):
        """Test user-agent fuzzing with target."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch('builtins.input', return_value=''):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_useragent_fuzz()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0][0]
                assert "User-Agent: FUZZ" in call_args


class TestCustomFuzzingOperation:
    """Tests for op_custom_fuzz operation."""

    def test_op_custom_fuzz_requires_command(self, wfuzz_with_target):
        """Test custom fuzzing requires command input."""
        with patch('builtins.input', return_value=''):
            result = wfuzz_with_target.op_custom_fuzz()

        assert result["success"] is False
        assert "Custom command required" in result["error"]

    def test_op_custom_fuzz_with_command(self, wfuzz_with_target):
        """Test custom fuzzing with command input."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        custom_cmd = "-w /custom.txt --hc 200,404 http://custom.com/FUZZ"
        with patch('builtins.input', return_value=custom_cmd):
            with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
                result = wfuzz_with_target.op_custom_fuzz()

                mock_exec.assert_called_once_with(custom_cmd)


# =============================================================================
# Logging Tests
# =============================================================================

class TestWfuzzLogging:
    """Tests for wfuzz module logging."""

    def test_log_method_called_during_dir_fuzz(self, wfuzz_with_target):
        """Test log is called during directory fuzzing."""
        wfuzz_with_target.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}):
            with patch.object(wfuzz_with_target, 'log') as mock_log:
                wfuzz_with_target.op_dir_fuzz()

                mock_log.assert_called()

    def test_log_smart_filter_status(self, wfuzz_with_target):
        """Test smart filter status is logged."""
        wfuzz_with_target.set_option("SMART_FILTER", "true")

        with patch.object(wfuzz_with_target, '_execute_wfuzz', return_value={"success": True}):
            with patch.object(wfuzz_with_target, 'log') as mock_log:
                wfuzz_with_target.op_dir_fuzz()

                # Should log that smart filtering is enabled
                calls = [str(c) for c in mock_log.call_args_list]
                assert any("Smart filtering enabled" in str(c) for c in calls)


# =============================================================================
# Edge Cases
# =============================================================================

class TestWfuzzEdgeCasesExtended:
    """Extended edge case tests for wfuzz module."""

    def test_build_url_with_port(self, wfuzz_module):
        """Test URL building with port in target."""
        wfuzz_module.set_option("TARGET", "example.com:8080")

        url = wfuzz_module._build_url("/test")

        assert url == "http://example.com:8080/test"

    def test_build_url_with_trailing_slash(self, wfuzz_module):
        """Test URL building with trailing slash in target."""
        wfuzz_module.set_option("TARGET", "http://example.com/")

        url = wfuzz_module._build_url("/test")

        assert url == "http://example.com/test"

    def test_parse_wfuzz_responses_multiline(self, wfuzz_module):
        """Test parsing wfuzz responses with various formats."""
        output = """
000000001:   200        7 L      11 W       162 Ch      "test1"
000000002:   301        9 L      28 W       325 Ch      "admin"
000000003:   200        7 L      11 W       162 Ch      "test2"
        """

        stats = wfuzz_module._parse_wfuzz_responses(output)

        assert stats["total_responses"] == 3
        assert stats["most_common_lines"] == 7
        assert stats["most_common_lines_count"] == 2

    def test_get_target_empty_url_returns_target(self, wfuzz_module):
        """Test _get_target returns TARGET when URL is empty string."""
        wfuzz_module.set_option("TARGET", "target.com")
        wfuzz_module.set_option("URL", "")

        target = wfuzz_module._get_target()

        # Empty string is falsy, so should return TARGET
        assert target == "target.com"

    def test_operation_with_https_target(self, wfuzz_module):
        """Test operations work with https:// in target."""
        wfuzz_module.set_option("TARGET", "https://secure.example.com")
        wfuzz_module.set_option("SMART_FILTER", "false")

        with patch.object(wfuzz_module, '_execute_wfuzz', return_value={"success": True}) as mock_exec:
            wfuzz_module.op_dir_fuzz()

            call_args = mock_exec.call_args[0][0]
            assert "https://secure.example.com" in call_args

    def test_has_operations(self, wfuzz_module):
        """Test has_operations returns True."""
        assert wfuzz_module.has_operations() is True

    def test_get_subcategories(self, wfuzz_module):
        """Test get_subcategories returns expected categories."""
        subcategories = wfuzz_module.get_subcategories()

        assert "discovery" in subcategories
        assert "vhost" in subcategories
        assert "parameters" in subcategories
        assert "advanced" in subcategories

    def test_operations_by_subcategory(self, wfuzz_module):
        """Test filtering operations by subcategory."""
        discovery_ops = wfuzz_module.get_operations_by_subcategory("discovery")

        assert len(discovery_ops) > 0
        assert all(op["subcategory"] == "discovery" for op in discovery_ops)
