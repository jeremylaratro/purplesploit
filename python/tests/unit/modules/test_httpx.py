"""
Tests for the HTTPx module.

Tests the HTTPx HTTP probe module properties, command building, and output parsing.
"""

import pytest
from unittest.mock import MagicMock, patch


class TestHTTPxModuleProperties:
    """Tests for HTTPx module properties."""

    @pytest.fixture
    def httpx_module(self, mock_framework_minimal):
        """Create HTTPx module instance for testing."""
        from purplesploit.modules.web.httpx import HTTPxModule
        return HTTPxModule(mock_framework_minimal)

    def test_name(self, httpx_module):
        """Test module name."""
        assert httpx_module.name == "HTTPx"

    def test_description(self, httpx_module):
        """Test module description."""
        assert "HTTP probe" in httpx_module.description

    def test_category(self, httpx_module):
        """Test module category is web."""
        assert httpx_module.category == "web"

    def test_tool_name(self, httpx_module):
        """Test tool name is httpx."""
        assert httpx_module.tool_name == "httpx"

    def test_author(self, httpx_module):
        """Test module author."""
        assert httpx_module.author == "PurpleSploit Team"

    def test_has_target_option(self, httpx_module):
        """Test that TARGET option exists."""
        assert "TARGET" in httpx_module.options

    def test_has_ports_option(self, httpx_module):
        """Test that PORTS option exists with default."""
        assert "PORTS" in httpx_module.options
        assert httpx_module.options["PORTS"]["value"] == "80,443,8080,8443"

    def test_target_is_required(self, httpx_module):
        """Test that TARGET is required."""
        assert httpx_module.options["TARGET"]["required"] is True


class TestHTTPxCommandBuilding:
    """Tests for HTTPx command building."""

    @pytest.fixture
    def httpx_module(self, mock_framework_minimal):
        """Create HTTPx module instance for testing."""
        from purplesploit.modules.web.httpx import HTTPxModule
        return HTTPxModule(mock_framework_minimal)

    def test_build_command_with_url(self, httpx_module):
        """Test building command with URL target."""
        httpx_module.set_option("TARGET", "http://example.com")
        cmd = httpx_module.build_command()
        assert "echo 'http://example.com' | httpx" in cmd
        assert "-silent" in cmd

    def test_build_command_with_ip(self, httpx_module):
        """Test building command with IP target."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        cmd = httpx_module.build_command()
        assert "httpx -u '192.168.1.1'" in cmd

    def test_build_command_with_ports(self, httpx_module):
        """Test building command includes ports."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("PORTS", "80,443")
        cmd = httpx_module.build_command()
        assert "-p 80,443" in cmd

    def test_build_command_with_threads(self, httpx_module):
        """Test building command includes threads."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("THREADS", "100")
        cmd = httpx_module.build_command()
        assert "-threads 100" in cmd

    def test_build_command_with_timeout(self, httpx_module):
        """Test building command includes timeout."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("TIMEOUT", "30")
        cmd = httpx_module.build_command()
        assert "-timeout 30" in cmd

    def test_build_command_with_title(self, httpx_module):
        """Test building command includes title extraction."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("TITLE", "true")
        cmd = httpx_module.build_command()
        assert "-title" in cmd

    def test_build_command_without_title(self, httpx_module):
        """Test building command without title extraction."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("TITLE", "false")
        cmd = httpx_module.build_command()
        assert "-title" not in cmd

    def test_build_command_with_status_code(self, httpx_module):
        """Test building command includes status code."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("STATUS_CODE", "true")
        cmd = httpx_module.build_command()
        assert "-status-code" in cmd

    def test_build_command_with_tech_detect(self, httpx_module):
        """Test building command includes tech detection."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("TECH_DETECT", "true")
        cmd = httpx_module.build_command()
        assert "-tech-detect" in cmd

    def test_build_command_with_content_length(self, httpx_module):
        """Test building command includes content length."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("CONTENT_LENGTH", "true")
        cmd = httpx_module.build_command()
        assert "-content-length" in cmd

    def test_build_command_with_follow_redirects(self, httpx_module):
        """Test building command includes follow redirects."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        httpx_module.set_option("FOLLOW_REDIRECTS", "true")
        cmd = httpx_module.build_command()
        assert "-follow-redirects" in cmd

    def test_build_command_always_silent(self, httpx_module):
        """Test that command always includes silent mode."""
        httpx_module.set_option("TARGET", "192.168.1.1")
        cmd = httpx_module.build_command()
        assert "-silent" in cmd


class TestHTTPxOutputParsing:
    """Tests for HTTPx output parsing."""

    @pytest.fixture
    def httpx_module(self, mock_framework_minimal):
        """Create HTTPx module instance for testing."""
        from purplesploit.modules.web.httpx import HTTPxModule
        return HTTPxModule(mock_framework_minimal)

    def test_parse_output_empty(self, httpx_module):
        """Test parsing empty output."""
        result = httpx_module.parse_output("")
        assert result["live_hosts"] == []
        assert result["technologies"] == []

    def test_parse_output_single_host(self, httpx_module):
        """Test parsing single host output."""
        output = "http://example.com [200]"
        result = httpx_module.parse_output(output)
        assert "http://example.com [200]" in result["live_hosts"]

    def test_parse_output_multiple_hosts(self, httpx_module):
        """Test parsing multiple hosts output."""
        output = """http://example.com [200]
http://test.com [301]
http://app.local [404]"""
        result = httpx_module.parse_output(output)
        assert len(result["live_hosts"]) == 3

    def test_parse_output_extracts_technologies(self, httpx_module):
        """Test that technologies are extracted from output."""
        output = "http://example.com [nginx]"
        result = httpx_module.parse_output(output)
        assert "nginx" in result["technologies"]

    def test_parse_output_ignores_non_http_lines(self, httpx_module):
        """Test that non-HTTP lines are ignored."""
        output = """Starting httpx scan...
http://example.com
Scan complete."""
        result = httpx_module.parse_output(output)
        assert len(result["live_hosts"]) == 1
        assert "http://example.com" in result["live_hosts"][0]


class TestHTTPxModuleOptions:
    """Tests for HTTPx module option defaults."""

    @pytest.fixture
    def httpx_module(self, mock_framework_minimal):
        """Create HTTPx module instance for testing."""
        from purplesploit.modules.web.httpx import HTTPxModule
        return HTTPxModule(mock_framework_minimal)

    def test_default_ports(self, httpx_module):
        """Test default ports option."""
        assert httpx_module.options["PORTS"]["default"] == "80,443,8080,8443"

    def test_default_threads(self, httpx_module):
        """Test default threads option."""
        assert httpx_module.options["THREADS"]["default"] == "50"

    def test_default_timeout(self, httpx_module):
        """Test default timeout option."""
        assert httpx_module.options["TIMEOUT"]["default"] == "10"

    def test_default_title_enabled(self, httpx_module):
        """Test that title extraction is enabled by default."""
        assert httpx_module.options["TITLE"]["default"] == "true"

    def test_default_follow_redirects_disabled(self, httpx_module):
        """Test that follow redirects is disabled by default."""
        assert httpx_module.options["FOLLOW_REDIRECTS"]["default"] == "false"
