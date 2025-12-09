"""
Unit tests for purplesploit.modules.web.wfuzz module.

Tests cover:
- Command building
- Output parsing
- Smart filter analysis
- Operation handlers
- URL building
"""

import pytest
from unittest.mock import MagicMock, patch
from purplesploit.modules.web.wfuzz import WfuzzModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def wfuzz_module(mock_framework_minimal):
    """Create a WfuzzModule instance for testing."""
    return WfuzzModule(mock_framework_minimal)


# =============================================================================
# Module Properties Tests
# =============================================================================

class TestWfuzzModuleProperties:
    """Tests for WfuzzModule properties."""

    def test_name(self, wfuzz_module):
        """Test module name."""
        assert wfuzz_module.name == "Wfuzz"

    def test_description(self, wfuzz_module):
        """Test module description."""
        assert "fuzzer" in wfuzz_module.description.lower()

    def test_category(self, wfuzz_module):
        """Test module category."""
        assert wfuzz_module.category == "web"

    def test_tool_name(self, wfuzz_module):
        """Test tool name is set."""
        assert wfuzz_module.tool_name == "wfuzz"

    def test_has_target_option(self, wfuzz_module):
        """Test TARGET option exists."""
        assert "TARGET" in wfuzz_module.options

    def test_has_wordlist_option(self, wfuzz_module):
        """Test WORDLIST option with default."""
        assert "WORDLIST" in wfuzz_module.options
        assert wfuzz_module.options["WORDLIST"]["default"] is not None


# =============================================================================
# Command Building Tests
# =============================================================================

class TestWfuzzCommandBuilding:
    """Tests for WfuzzModule command building."""

    def test_build_command_basic(self, wfuzz_module):
        """Test basic command building."""
        wfuzz_module.set_option("URL", "http://example.com/FUZZ")
        wfuzz_module.set_option("WORDLIST", "/usr/share/wordlists/test.txt")

        command = wfuzz_module.build_command()

        assert "wfuzz" in command
        assert "-w '/usr/share/wordlists/test.txt'" in command
        assert "http://example.com/FUZZ" in command

    def test_build_command_with_threads(self, wfuzz_module):
        """Test command with thread count."""
        wfuzz_module.set_option("URL", "http://example.com/FUZZ")
        wfuzz_module.set_option("THREADS", "100")

        command = wfuzz_module.build_command()

        assert "-t 100" in command

    def test_build_command_with_hide_code(self, wfuzz_module):
        """Test command with hidden status code."""
        wfuzz_module.set_option("URL", "http://example.com/FUZZ")
        wfuzz_module.set_option("HIDE_CODE", "404,403")

        command = wfuzz_module.build_command()

        assert "--hc 404,403" in command

    def test_build_command_with_hide_words(self, wfuzz_module):
        """Test command with hidden word count."""
        wfuzz_module.set_option("URL", "http://example.com/FUZZ")
        wfuzz_module.set_option("HIDE_WORDS", "100")

        command = wfuzz_module.build_command()

        assert "--hw 100" in command

    def test_build_command_with_hide_chars(self, wfuzz_module):
        """Test command with hidden char count."""
        wfuzz_module.set_option("URL", "http://example.com/FUZZ")
        wfuzz_module.set_option("HIDE_CHARS", "500")

        command = wfuzz_module.build_command()

        assert "--hh 500" in command

    def test_build_command_post_method(self, wfuzz_module):
        """Test command with POST method."""
        wfuzz_module.set_option("URL", "http://example.com/login")
        wfuzz_module.set_option("METHOD", "POST")

        command = wfuzz_module.build_command()

        assert "-X POST" in command

    def test_build_command_get_method_not_added(self, wfuzz_module):
        """Test GET method is not explicitly added."""
        wfuzz_module.set_option("URL", "http://example.com/FUZZ")
        wfuzz_module.set_option("METHOD", "GET")

        command = wfuzz_module.build_command()

        assert "-X GET" not in command

    def test_build_command_with_data(self, wfuzz_module):
        """Test command with POST data."""
        wfuzz_module.set_option("URL", "http://example.com/login")
        wfuzz_module.set_option("DATA", "username=admin&password=FUZZ")

        command = wfuzz_module.build_command()

        assert "-d 'username=admin&password=FUZZ'" in command

    def test_build_command_with_headers(self, wfuzz_module):
        """Test command with custom headers."""
        wfuzz_module.set_option("URL", "http://example.com/FUZZ")
        wfuzz_module.set_option("HEADERS", "Authorization: Bearer token123")

        command = wfuzz_module.build_command()

        assert "-H 'Authorization: Bearer token123'" in command

    def test_build_command_follow_redirects(self, wfuzz_module):
        """Test command with redirect following."""
        wfuzz_module.set_option("URL", "http://example.com/FUZZ")
        wfuzz_module.set_option("FOLLOW", "true")

        command = wfuzz_module.build_command()

        assert "-L" in command


# =============================================================================
# Output Parsing Tests
# =============================================================================

class TestWfuzzOutputParsing:
    """Tests for WfuzzModule output parsing."""

    def test_parse_output_basic(self, wfuzz_module, sample_wfuzz_output):
        """Test basic output parsing."""
        result = wfuzz_module.parse_output(sample_wfuzz_output)

        assert "found_paths" in result
        assert "status_codes" in result
        assert len(result["found_paths"]) > 0

    def test_parse_output_extracts_status(self, wfuzz_module, sample_wfuzz_output):
        """Test status code extraction."""
        result = wfuzz_module.parse_output(sample_wfuzz_output)

        status_codes = result["status_codes"]
        assert "200" in status_codes or "301" in status_codes

    def test_parse_output_empty(self, wfuzz_module):
        """Test parsing empty output."""
        result = wfuzz_module.parse_output("")

        assert result["found_paths"] == []
        assert result["status_codes"] == {}


# =============================================================================
# Smart Filter Analysis Tests
# =============================================================================

class TestWfuzzSmartFilter:
    """Tests for WfuzzModule smart filter analysis."""

    def test_parse_wfuzz_responses(self, wfuzz_module, sample_wfuzz_output_uniform):
        """Test response statistics parsing."""
        stats = wfuzz_module._parse_wfuzz_responses(sample_wfuzz_output_uniform)

        assert "total_responses" in stats
        assert "most_common_lines" in stats
        assert "most_common_words" in stats
        assert "most_common_chars" in stats
        assert stats["total_responses"] > 0

    def test_parse_wfuzz_responses_finds_common(self, wfuzz_module, sample_wfuzz_output_uniform):
        """Test finding most common response characteristics."""
        stats = wfuzz_module._parse_wfuzz_responses(sample_wfuzz_output_uniform)

        # Most responses have 7 lines, 11 words, 162 chars
        assert stats["most_common_lines"] == 7
        assert stats["most_common_words"] == 11
        assert stats["most_common_chars"] == 162

    def test_parse_wfuzz_responses_counts(self, wfuzz_module, sample_wfuzz_output_uniform):
        """Test response counting."""
        stats = wfuzz_module._parse_wfuzz_responses(sample_wfuzz_output_uniform)

        # 9 out of 10 responses should have the common pattern
        assert stats["most_common_lines_count"] >= 8

    def test_parse_wfuzz_responses_empty(self, wfuzz_module):
        """Test parsing empty output."""
        stats = wfuzz_module._parse_wfuzz_responses("")

        assert stats["total_responses"] == 0
        assert stats["most_common_lines"] is None

    def test_is_smart_filter_enabled_default(self, wfuzz_module):
        """Test smart filter is enabled by default."""
        assert wfuzz_module._is_smart_filter_enabled() is True

    def test_is_smart_filter_disabled(self, wfuzz_module):
        """Test smart filter can be disabled."""
        wfuzz_module.set_option("SMART_FILTER", "false")
        assert wfuzz_module._is_smart_filter_enabled() is False


# =============================================================================
# URL Building Tests
# =============================================================================

class TestWfuzzURLBuilding:
    """Tests for WfuzzModule URL building."""

    def test_get_target_from_url(self, wfuzz_module):
        """Test getting target from URL option."""
        wfuzz_module.set_option("URL", "http://example.com")

        target = wfuzz_module._get_target()

        assert target == "http://example.com"

    def test_get_target_from_target_option(self, wfuzz_module):
        """Test getting target from TARGET option."""
        wfuzz_module.set_option("TARGET", "example.com")

        target = wfuzz_module._get_target()

        assert target == "example.com"

    def test_get_target_url_precedence(self, wfuzz_module):
        """Test URL option takes precedence over TARGET."""
        wfuzz_module.set_option("TARGET", "target.com")
        wfuzz_module.set_option("URL", "http://url.com")

        target = wfuzz_module._get_target()

        assert target == "http://url.com"

    def test_build_url_basic(self, wfuzz_module):
        """Test basic URL building."""
        wfuzz_module.set_option("TARGET", "example.com")

        url = wfuzz_module._build_url("/test")

        assert url == "http://example.com/test"

    def test_build_url_https(self, wfuzz_module):
        """Test HTTPS URL building."""
        wfuzz_module.set_option("TARGET", "example.com")

        url = wfuzz_module._build_url("/test", scheme="https")

        assert url == "https://example.com/test"

    def test_build_url_with_scheme_in_target(self, wfuzz_module):
        """Test URL building when target already has scheme."""
        wfuzz_module.set_option("TARGET", "https://example.com")

        url = wfuzz_module._build_url("/test")

        assert url == "https://example.com/test"

    def test_build_url_no_target(self, wfuzz_module):
        """Test URL building returns None without target."""
        url = wfuzz_module._build_url("/test")
        assert url is None


# =============================================================================
# Operations Tests
# =============================================================================

class TestWfuzzOperations:
    """Tests for WfuzzModule operations."""

    def test_get_operations(self, wfuzz_module):
        """Test getting available operations."""
        operations = wfuzz_module.get_operations()

        assert len(operations) > 0
        # Check expected operations exist
        op_names = [op["name"] for op in operations]
        assert "Directory Fuzzing" in op_names
        assert "VHOST Fuzzing" in op_names
        assert "Custom Fuzzing" in op_names

    def test_operations_have_subcategories(self, wfuzz_module):
        """Test operations have subcategory tags."""
        operations = wfuzz_module.get_operations()

        for op in operations:
            assert "subcategory" in op
            assert op["subcategory"] in ["discovery", "vhost", "parameters", "advanced"]

    def test_operations_have_handlers(self, wfuzz_module):
        """Test all operations have handler methods."""
        operations = wfuzz_module.get_operations()

        for op in operations:
            handler_name = op["handler"]
            assert hasattr(wfuzz_module, handler_name), f"Missing handler: {handler_name}"

    def test_op_dir_fuzz_requires_target(self, wfuzz_module):
        """Test directory fuzzing requires TARGET."""
        result = wfuzz_module.op_dir_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]

    def test_op_backup_fuzz_requires_target(self, wfuzz_module):
        """Test backup fuzzing requires TARGET."""
        result = wfuzz_module.op_backup_fuzz()

        assert result["success"] is False
        assert "TARGET" in result["error"]


# =============================================================================
# Edge Cases
# =============================================================================

class TestWfuzzEdgeCases:
    """Tests for edge cases in wfuzz module."""

    def test_parse_output_with_ansi_codes(self, wfuzz_module):
        """Test parsing output with ANSI color codes."""
        output_with_ansi = "\x1b[32m000000001:   200        7 L      11 W       162 Ch      \"test\"\x1b[0m"

        stats = wfuzz_module._parse_wfuzz_responses(output_with_ansi)

        assert stats["total_responses"] > 0

    def test_parse_output_with_box_chars(self, wfuzz_module):
        """Test parsing output with box-drawing characters."""
        output_with_boxes = "│000000001:   200        7 L      11 W       162 Ch      \"test\"│"

        stats = wfuzz_module._parse_wfuzz_responses(output_with_boxes)

        # Should handle gracefully
        assert isinstance(stats, dict)

    def test_build_command_special_chars_in_url(self, wfuzz_module):
        """Test command building with special characters in URL."""
        wfuzz_module.set_option("URL", "http://example.com/path?param=value&other=test")

        command = wfuzz_module.build_command()

        assert "example.com" in command

    def test_module_options_defaults(self, wfuzz_module):
        """Test default option values."""
        assert wfuzz_module.get_option("HIDE_CODE") == "404"
        assert wfuzz_module.get_option("THREADS") == "50"
        assert wfuzz_module.get_option("METHOD") == "GET"
        assert wfuzz_module.get_option("SMART_FILTER") == "true"
