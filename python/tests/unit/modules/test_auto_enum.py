"""
Tests for the Auto-Enumeration Module.

Tests automated comprehensive enumeration including network, web, DNS,
SMB enumeration and exploit searching.
"""

import pytest
from unittest.mock import MagicMock, patch, mock_open
import subprocess
import json
from pathlib import Path
from typing import Dict, Any


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def auto_enum_module(mock_framework_minimal):
    """Create an AutoEnumModule instance for testing."""
    from purplesploit.modules.recon.auto_enum import AutoEnumModule
    module = AutoEnumModule(mock_framework_minimal)
    return module


@pytest.fixture
def configured_auto_enum(auto_enum_module, tmp_path):
    """Create a fully configured auto enum module."""
    auto_enum_module.set_option("TARGET", "192.168.1.100")
    auto_enum_module.set_option("OUTPUT_DIR", str(tmp_path / "enum_output"))
    return auto_enum_module


# =============================================================================
# Module Property Tests
# =============================================================================

class TestModuleProperties:
    """Tests for basic module properties."""

    def test_name(self, auto_enum_module):
        """Test module name property."""
        assert auto_enum_module.name == "Auto-Enumeration"

    def test_description(self, auto_enum_module):
        """Test module description property."""
        assert "enumeration" in auto_enum_module.description.lower()

    def test_author(self, auto_enum_module):
        """Test module author property."""
        assert "Jeremy Laratro" in auto_enum_module.author

    def test_category(self, auto_enum_module):
        """Test module category property."""
        assert auto_enum_module.category == "recon"

    def test_tool_name(self, auto_enum_module):
        """Test tool name attribute."""
        assert auto_enum_module.tool_name == "auto-enum"


# =============================================================================
# Options Tests
# =============================================================================

class TestModuleOptions:
    """Tests for module options."""

    def test_default_options_exist(self, auto_enum_module):
        """Test that required options are initialized."""
        options = auto_enum_module.options
        assert "TARGET" in options
        assert "DOMAIN" in options
        assert "OUTPUT_DIR" in options
        assert "NETWORK_SCAN" in options
        assert "WEB_SCAN" in options

    def test_target_required(self, auto_enum_module):
        """Test that TARGET is required."""
        assert auto_enum_module.options["TARGET"]["required"] is True

    def test_default_scan_options(self, auto_enum_module):
        """Test default scan option values."""
        assert auto_enum_module.get_option("NETWORK_SCAN") == "true"
        assert auto_enum_module.get_option("WEB_SCAN") == "true"
        assert auto_enum_module.get_option("SMB_SCAN") == "true"
        assert auto_enum_module.get_option("DNS_SCAN") == "false"

    def test_default_wordlist(self, auto_enum_module):
        """Test default wordlist path."""
        wordlist = auto_enum_module.get_option("WORDLIST")
        assert "seclists" in wordlist.lower() or "wordlist" in wordlist.lower()


# =============================================================================
# Output Directory Tests
# =============================================================================

class TestSetupOutputDir:
    """Tests for output directory setup."""

    def test_auto_generate_output_dir(self, auto_enum_module, tmp_path):
        """Test auto-generation of output directory."""
        auto_enum_module.set_option("TARGET", "192.168.1.100")
        auto_enum_module.set_option("OUTPUT_DIR", None)

        with patch('pathlib.Path.mkdir'):
            output_dir = auto_enum_module._setup_output_dir()
            assert "192_168_1_100" in output_dir
            assert "enum_output" in output_dir

    def test_custom_output_dir(self, auto_enum_module, tmp_path):
        """Test using custom output directory."""
        custom_dir = str(tmp_path / "custom_output")
        auto_enum_module.set_option("TARGET", "192.168.1.100")
        auto_enum_module.set_option("OUTPUT_DIR", custom_dir)

        output_dir = auto_enum_module._setup_output_dir()
        assert output_dir == custom_dir

    def test_creates_subdirectories(self, auto_enum_module, tmp_path):
        """Test that subdirectories are created."""
        output_dir = str(tmp_path / "enum_test")
        auto_enum_module.set_option("TARGET", "192.168.1.100")
        auto_enum_module.set_option("OUTPUT_DIR", output_dir)

        auto_enum_module._setup_output_dir()

        assert Path(output_dir).exists()
        assert (Path(output_dir) / "network").exists()
        assert (Path(output_dir) / "web").exists()
        assert (Path(output_dir) / "dns").exists()
        assert (Path(output_dir) / "services").exists()
        assert (Path(output_dir) / "exploits").exists()


# =============================================================================
# Tool Check Tests
# =============================================================================

class TestCheckTool:
    """Tests for tool availability checking."""

    def test_tool_exists(self, auto_enum_module):
        """Test checking for existing tool."""
        with patch('shutil.which', return_value="/usr/bin/nmap"):
            assert auto_enum_module._check_tool("nmap") is True

    def test_tool_not_exists(self, auto_enum_module):
        """Test checking for non-existing tool."""
        with patch('shutil.which', return_value=None):
            assert auto_enum_module._check_tool("nonexistent_tool") is False


# =============================================================================
# Run Command Tests
# =============================================================================

class TestRunCommand:
    """Tests for command execution."""

    def test_successful_command(self, auto_enum_module):
        """Test successful command execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="command output",
                stderr=""
            )

            result = auto_enum_module._run_command("echo test")
            assert result["success"] is True
            assert result["output"] == "command output"

    def test_failed_command(self, auto_enum_module):
        """Test failed command execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="error message"
            )

            result = auto_enum_module._run_command("false")
            assert result["success"] is False

    def test_command_timeout(self, auto_enum_module):
        """Test command timeout handling."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 30)

            result = auto_enum_module._run_command("sleep 999", timeout=30)
            assert result["success"] is False
            assert "Timeout" in result["error"]

    def test_command_with_output_file(self, auto_enum_module, tmp_path):
        """Test saving command output to file."""
        output_file = str(tmp_path / "output.txt")

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="saved output",
                stderr=""
            )

            result = auto_enum_module._run_command("echo test", output_file=output_file)
            assert result["success"] is True
            assert Path(output_file).exists()
            assert "saved output" in Path(output_file).read_text()


# =============================================================================
# Network Enumeration Tests
# =============================================================================

class TestNetworkEnumeration:
    """Tests for network enumeration."""

    def test_network_enumeration_with_rustscan(self, configured_auto_enum):
        """Test network enumeration using rustscan."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/network").mkdir(exist_ok=True)

        with patch.object(configured_auto_enum, '_check_tool', return_value=True):
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {
                    "success": True,
                    "output": "22/tcp open ssh\n80/tcp open http",
                    "stderr": ""
                }

                result = configured_auto_enum._network_enumeration()
                assert "ports" in result
                assert "services" in result

    def test_network_enumeration_nmap_fallback(self, configured_auto_enum):
        """Test falling back to nmap when rustscan not available."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/network").mkdir(exist_ok=True)

        def check_tool_side_effect(tool):
            return tool != "rustscan"

        with patch.object(configured_auto_enum, '_check_tool', side_effect=check_tool_side_effect):
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {
                    "success": True,
                    "output": "22/tcp open ssh\n80/tcp open http",
                    "stderr": ""
                }

                result = configured_auto_enum._network_enumeration()
                assert isinstance(result, dict)


# =============================================================================
# Nmap Parsing Tests
# =============================================================================

class TestNmapParsing:
    """Tests for nmap output parsing."""

    def test_parse_nmap_ports(self, auto_enum_module):
        """Test parsing ports from nmap output."""
        output = """
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  ssl/https
"""
        ports = auto_enum_module._parse_nmap_ports(output)
        assert 22 in ports
        assert 80 in ports
        assert 443 in ports

    def test_parse_nmap_ports_empty(self, auto_enum_module):
        """Test parsing when no ports found."""
        output = "No open ports"
        ports = auto_enum_module._parse_nmap_ports(output)
        assert ports == []

    def test_parse_nmap_services(self, auto_enum_module):
        """Test parsing services from nmap output."""
        output = """
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.0
80/tcp   open  http        nginx 1.18
"""
        services = auto_enum_module._parse_nmap_services(output)
        assert len(services) == 2
        assert services[0]["port"] == 22
        assert services[0]["service"] == "ssh"

    def test_parse_nmap_services_with_version(self, auto_enum_module):
        """Test parsing services with version info."""
        output = "80/tcp   open  http        Apache httpd 2.4.41"
        services = auto_enum_module._parse_nmap_services(output)
        assert len(services) == 1
        assert "Apache" in services[0]["version"]


# =============================================================================
# Web Enumeration Tests
# =============================================================================

class TestWebEnumeration:
    """Tests for web enumeration."""

    def test_web_enumeration_with_ports(self, configured_auto_enum):
        """Test web enumeration with specified ports."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/web").mkdir(exist_ok=True)

        with patch.object(configured_auto_enum, '_check_tool', return_value=True):
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {
                    "success": True,
                    "output": "http://192.168.1.100:80 [200]\nhttp://192.168.1.100:8080 [200]",
                    "stderr": ""
                }

                result = configured_auto_enum._web_enumeration(ports=[80, 8080])
                assert "live_urls" in result

    def test_web_enumeration_default_ports(self, configured_auto_enum):
        """Test web enumeration with default ports."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/web").mkdir(exist_ok=True)

        with patch.object(configured_auto_enum, '_check_tool', return_value=True):
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {
                    "success": True,
                    "output": "",
                    "stderr": ""
                }

                result = configured_auto_enum._web_enumeration()
                assert isinstance(result, dict)


# =============================================================================
# Directory Enumeration Tests
# =============================================================================

class TestDirectoryEnumeration:
    """Tests for directory enumeration."""

    def test_directory_enum_no_urls(self, configured_auto_enum):
        """Test directory enumeration with no URLs."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")

        result = configured_auto_enum._directory_enumeration([])
        assert "discoveries" in result
        assert result["discoveries"] == []

    def test_directory_enum_with_feroxbuster(self, configured_auto_enum):
        """Test directory enumeration with feroxbuster."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/web").mkdir(exist_ok=True)

        with patch.object(configured_auto_enum, '_check_tool') as mock_check:
            mock_check.side_effect = lambda t: t == "feroxbuster"
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {"success": True, "output": "/admin\n/login"}

                result = configured_auto_enum._directory_enumeration(["http://192.168.1.100"])
                assert isinstance(result, dict)


# =============================================================================
# DNS Enumeration Tests
# =============================================================================

class TestDnsEnumeration:
    """Tests for DNS enumeration."""

    def test_dns_enum_no_domain(self, configured_auto_enum):
        """Test DNS enumeration without domain."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        # No DOMAIN set

        result = configured_auto_enum._dns_enumeration()
        assert result == {}

    def test_dns_enum_with_domain(self, configured_auto_enum):
        """Test DNS enumeration with domain."""
        configured_auto_enum.set_option("DOMAIN", "example.com")
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/dns").mkdir(exist_ok=True)

        with patch.object(configured_auto_enum, '_check_tool', return_value=True):
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {
                    "success": True,
                    "output": "192.168.1.100",
                    "stderr": ""
                }

                result = configured_auto_enum._dns_enumeration()
                assert "dns_records" in result
                assert "subdomains" in result


# =============================================================================
# SMB Enumeration Tests
# =============================================================================

class TestSmbEnumeration:
    """Tests for SMB enumeration."""

    def test_smb_enum_with_enum4linux(self, configured_auto_enum):
        """Test SMB enumeration with enum4linux."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/services").mkdir(exist_ok=True)

        with patch.object(configured_auto_enum, '_check_tool') as mock_check:
            mock_check.side_effect = lambda t: t == "enum4linux"
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {
                    "success": True,
                    "output": "Shares: IPC$, ADMIN$",
                    "stderr": ""
                }

                result = configured_auto_enum._smb_enumeration("192.168.1.100")
                assert "enum4linux" in result

    def test_smb_enum_with_nxc(self, configured_auto_enum):
        """Test SMB enumeration with nxc."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/services").mkdir(exist_ok=True)

        with patch.object(configured_auto_enum, '_check_tool') as mock_check:
            mock_check.side_effect = lambda t: t == "nxc"
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {
                    "success": True,
                    "output": "SMB 192.168.1.100 Windows 10",
                    "stderr": ""
                }

                result = configured_auto_enum._smb_enumeration("192.168.1.100")
                assert "nxc" in result


# =============================================================================
# Exploit Search Tests
# =============================================================================

class TestExploitSearch:
    """Tests for exploit searching."""

    def test_exploit_search_no_searchsploit(self, configured_auto_enum):
        """Test exploit search when searchsploit not available."""
        with patch.object(configured_auto_enum, '_check_tool', return_value=False):
            result = configured_auto_enum._exploit_search([])
            assert result == []

    def test_exploit_search_with_services(self, configured_auto_enum):
        """Test exploit search with services."""
        configured_auto_enum.output_dir = configured_auto_enum.get_option("OUTPUT_DIR")
        Path(configured_auto_enum.output_dir).mkdir(parents=True, exist_ok=True)
        Path(configured_auto_enum.output_dir + "/exploits").mkdir(exist_ok=True)

        services = [
            {"service": "ssh", "version": "OpenSSH 7.2", "port": 22},
            {"service": "http", "version": "Apache 2.4.41", "port": 80}
        ]

        with patch.object(configured_auto_enum, '_check_tool', return_value=True):
            with patch.object(configured_auto_enum, '_run_command') as mock_run:
                mock_run.return_value = {
                    "success": True,
                    "output": "OpenSSH 7.2 - Username Enumeration",
                    "stderr": ""
                }

                result = configured_auto_enum._exploit_search(services)
                assert len(result) == 2


# =============================================================================
# Add to Hosts Tests
# =============================================================================

class TestAddToHosts:
    """Tests for /etc/hosts modification."""

    def test_add_to_hosts_no_domain(self, auto_enum_module):
        """Test add to hosts without domain."""
        auto_enum_module.set_option("TARGET", "192.168.1.100")
        # No domain set

        # Should not raise, just return
        auto_enum_module._add_to_hosts()

    def test_add_to_hosts_already_exists(self, auto_enum_module):
        """Test when domain already in hosts."""
        auto_enum_module.set_option("TARGET", "192.168.1.100")
        auto_enum_module.set_option("DOMAIN", "example.com")

        hosts_content = "192.168.1.100 example.com"
        with patch('builtins.open', mock_open(read_data=hosts_content)):
            auto_enum_module._add_to_hosts()
            # Should detect existing entry and return


# =============================================================================
# Summary Generation Tests
# =============================================================================

class TestGenerateSummary:
    """Tests for summary generation."""

    def test_generate_summary_empty_results(self, configured_auto_enum):
        """Test summary generation with empty results."""
        configured_auto_enum.output_dir = "/tmp/test"
        configured_auto_enum.results = {
            "network": {},
            "web": {},
            "dns": {},
            "services": {},
            "vulnerabilities": []
        }

        summary = configured_auto_enum._generate_summary()
        assert "AUTO-ENUMERATION SUMMARY" in summary
        assert "192.168.1.100" in summary

    def test_generate_summary_with_results(self, configured_auto_enum):
        """Test summary generation with actual results."""
        configured_auto_enum.output_dir = "/tmp/test"
        configured_auto_enum.results = {
            "network": {"ports": [22, 80, 443], "services": []},
            "web": {"live_urls": ["http://192.168.1.100"]},
            "dns": {"dns_records": [], "subdomains": ["www"]},
            "services": {},
            "vulnerabilities": [{"service": "ssh", "version": "7.2", "port": 22}]
        }

        summary = configured_auto_enum._generate_summary()
        assert "22, 80, 443" in summary or "3" in summary
        assert "http://192.168.1.100" in summary


# =============================================================================
# Build Command Tests
# =============================================================================

class TestBuildCommand:
    """Tests for build_command method."""

    def test_build_command(self, auto_enum_module):
        """Test build_command returns description."""
        cmd = auto_enum_module.build_command()
        assert "auto-enum" in cmd.lower()


# =============================================================================
# Full Run Tests
# =============================================================================

class TestRunMethod:
    """Tests for the main run method."""

    def test_run_success(self, configured_auto_enum):
        """Test successful run."""
        with patch.object(configured_auto_enum, '_setup_output_dir') as mock_setup:
            mock_setup.return_value = configured_auto_enum.get_option("OUTPUT_DIR")

            with patch.object(configured_auto_enum, '_network_enumeration') as mock_net:
                mock_net.return_value = {"ports": [22, 80], "services": []}

                with patch.object(configured_auto_enum, '_web_enumeration') as mock_web:
                    mock_web.return_value = {"live_urls": [], "technologies": []}

                    with patch.object(configured_auto_enum, '_exploit_search') as mock_exp:
                        mock_exp.return_value = []

                        with patch('builtins.open', mock_open()):
                            result = configured_auto_enum.run()
                            assert result["success"] is True
                            assert "output" in result
                            assert "output_dir" in result

    def test_run_with_all_scans_disabled(self, configured_auto_enum):
        """Test run with all scans disabled."""
        configured_auto_enum.set_option("NETWORK_SCAN", "false")
        configured_auto_enum.set_option("WEB_SCAN", "false")
        configured_auto_enum.set_option("DIR_SCAN", "false")
        configured_auto_enum.set_option("DNS_SCAN", "false")
        configured_auto_enum.set_option("SMB_SCAN", "false")
        configured_auto_enum.set_option("EXPLOIT_SEARCH", "false")

        with patch.object(configured_auto_enum, '_setup_output_dir') as mock_setup:
            mock_setup.return_value = configured_auto_enum.get_option("OUTPUT_DIR")

            with patch('builtins.open', mock_open()):
                result = configured_auto_enum.run()
                assert result["success"] is True

    def test_run_exception_handling(self, configured_auto_enum):
        """Test run exception handling."""
        with patch.object(configured_auto_enum, '_setup_output_dir') as mock_setup:
            mock_setup.side_effect = Exception("Setup failed")

            result = configured_auto_enum.run()
            assert result["success"] is False
            assert "error" in result

    def test_run_with_add_to_hosts(self, configured_auto_enum):
        """Test run with add to hosts enabled."""
        configured_auto_enum.set_option("ADD_TO_HOSTS", "true")
        configured_auto_enum.set_option("DOMAIN", "example.com")

        with patch.object(configured_auto_enum, '_setup_output_dir') as mock_setup:
            mock_setup.return_value = configured_auto_enum.get_option("OUTPUT_DIR")

            with patch.object(configured_auto_enum, '_add_to_hosts') as mock_hosts:
                with patch.object(configured_auto_enum, '_network_enumeration') as mock_net:
                    mock_net.return_value = {"ports": [], "services": []}

                    with patch('builtins.open', mock_open()):
                        configured_auto_enum.set_option("WEB_SCAN", "false")
                        configured_auto_enum.set_option("EXPLOIT_SEARCH", "false")
                        result = configured_auto_enum.run()

                        mock_hosts.assert_called_once()

    def test_run_smb_only_when_port_open(self, configured_auto_enum):
        """Test SMB enumeration only runs when port 445 is open."""
        with patch.object(configured_auto_enum, '_setup_output_dir') as mock_setup:
            mock_setup.return_value = configured_auto_enum.get_option("OUTPUT_DIR")

            with patch.object(configured_auto_enum, '_network_enumeration') as mock_net:
                # Port 445 NOT in ports list
                mock_net.return_value = {"ports": [22, 80], "services": []}

                with patch.object(configured_auto_enum, '_smb_enumeration') as mock_smb:
                    with patch.object(configured_auto_enum, '_web_enumeration') as mock_web:
                        mock_web.return_value = {"live_urls": []}

                        with patch('builtins.open', mock_open()):
                            configured_auto_enum.set_option("EXPLOIT_SEARCH", "false")
                            configured_auto_enum.run()

                            # SMB should NOT be called
                            mock_smb.assert_not_called()
