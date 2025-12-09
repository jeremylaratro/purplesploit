"""
Unit tests for purplesploit.modules.recon.nmap module.

Tests cover:
- Command building
- Output parsing (stdout and XML)
- Operations/scan types
- Service detection and import
"""

import pytest
from unittest.mock import MagicMock, patch
from purplesploit.modules.recon.nmap import NmapModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def nmap_module(mock_framework):
    """Create an NmapModule instance for testing."""
    return NmapModule(mock_framework)


# =============================================================================
# Module Properties Tests
# =============================================================================

class TestNmapModuleProperties:
    """Tests for NmapModule properties."""

    def test_name(self, nmap_module):
        """Test module name."""
        assert nmap_module.name == "Nmap Scan"

    def test_description(self, nmap_module):
        """Test module description."""
        assert "sCV" in nmap_module.description or "version" in nmap_module.description.lower()

    def test_category(self, nmap_module):
        """Test module category."""
        assert nmap_module.category == "recon"

    def test_tool_name(self, nmap_module):
        """Test tool name is set."""
        assert nmap_module.tool_name == "nmap"

    def test_has_rhost_option(self, nmap_module):
        """Test RHOST option exists and is required."""
        assert "RHOST" in nmap_module.options
        assert nmap_module.options["RHOST"]["required"] is True


# =============================================================================
# Command Building Tests
# =============================================================================

class TestNmapCommandBuilding:
    """Tests for NmapModule command building."""

    def test_build_command_basic(self, nmap_module):
        """Test basic command building."""
        nmap_module.set_option("RHOST", "192.168.1.100")

        command = nmap_module.build_command()

        assert "nmap" in command
        assert "192.168.1.100" in command

    def test_build_command_with_scan_type(self, nmap_module):
        """Test command with scan type."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("SCAN_TYPE", "sCV")

        command = nmap_module.build_command()

        assert "-sCV" in command

    def test_build_command_with_ports(self, nmap_module):
        """Test command with port specification."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("PORTS", "22,80,443")

        command = nmap_module.build_command()

        assert "-p 22,80,443" in command

    def test_build_command_all_ports(self, nmap_module):
        """Test command with all ports."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("PORTS", "-")

        command = nmap_module.build_command()

        assert "-p -" in command

    def test_build_command_top_ports(self, nmap_module):
        """Test command with top ports."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("PORTS", None)
        nmap_module.set_option("TOP_PORTS", "100")

        command = nmap_module.build_command()

        assert "--top-ports 100" in command

    def test_build_command_timing(self, nmap_module):
        """Test command with timing template."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("TIMING", "4")

        command = nmap_module.build_command()

        assert "-T4" in command

    def test_build_command_os_detection(self, nmap_module):
        """Test command with OS detection."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("OS_DETECTION", "true")

        command = nmap_module.build_command()

        assert "-O" in command

    def test_build_command_version_intensity(self, nmap_module):
        """Test command with version intensity."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("VERSION_INTENSITY", "9")

        command = nmap_module.build_command()

        assert "--version-intensity 9" in command

    def test_build_command_min_rate(self, nmap_module):
        """Test command with minimum rate."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("MIN_RATE", "5000")

        command = nmap_module.build_command()

        assert "--min-rate 5000" in command

    def test_build_command_max_rtt_timeout(self, nmap_module):
        """Test command with max RTT timeout."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("MAX_RTT_TIMEOUT", "2")

        command = nmap_module.build_command()

        assert "--max-rtt-timeout 2" in command

    def test_build_command_script(self, nmap_module):
        """Test command with NSE script."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("SCRIPT", "vuln")

        command = nmap_module.build_command()

        assert "--script=vuln" in command

    def test_build_command_output_all(self, nmap_module):
        """Test command with all output formats."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("OUTPUT_FORMAT", "all")
        nmap_module.set_option("OUTPUT_FILE", "scan_results")

        command = nmap_module.build_command()

        assert "-oA scan_results" in command

    def test_build_command_output_xml(self, nmap_module):
        """Test command with XML output."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("OUTPUT_FORMAT", "xml")
        nmap_module.set_option("OUTPUT_FILE", "scan_results")

        command = nmap_module.build_command()

        assert "-oX scan_results" in command


# =============================================================================
# Output Parsing Tests
# =============================================================================

class TestNmapOutputParsing:
    """Tests for NmapModule output parsing."""

    def test_parse_output_basic(self, nmap_module, sample_nmap_output):
        """Test basic stdout parsing."""
        result = nmap_module.parse_output(sample_nmap_output)

        assert "open_ports" in result
        assert "services" in result
        assert len(result["open_ports"]) > 0

    def test_parse_output_extracts_ports(self, nmap_module, sample_nmap_output):
        """Test port extraction from output."""
        result = nmap_module.parse_output(sample_nmap_output)

        assert "22/tcp" in result["open_ports"]
        assert "80/tcp" in result["open_ports"]

    def test_parse_output_extracts_services(self, nmap_module, sample_nmap_output):
        """Test service extraction from output."""
        result = nmap_module.parse_output(sample_nmap_output)

        assert "22/tcp" in result["services"]
        assert result["services"]["22/tcp"]["service"] == "ssh"

    def test_parse_output_extracts_version(self, nmap_module, sample_nmap_output):
        """Test version extraction from output."""
        result = nmap_module.parse_output(sample_nmap_output)

        ssh_service = result["services"]["22/tcp"]
        assert "OpenSSH" in ssh_service["version"]

    def test_parse_output_os_detection(self, nmap_module):
        """Test OS detection parsing."""
        output_with_os = """PORT   STATE SERVICE
22/tcp open  ssh

OS details: Linux 4.15 - 5.6"""

        result = nmap_module.parse_output(output_with_os)

        assert result["os_guess"] is not None
        assert "Linux" in result["os_guess"]

    def test_parse_output_empty(self, nmap_module):
        """Test parsing empty output."""
        result = nmap_module.parse_output("")

        assert result["open_ports"] == []
        assert result["services"] == {}


# =============================================================================
# XML Parsing Tests
# =============================================================================

class TestNmapXMLParsing:
    """Tests for NmapModule XML parsing."""

    def test_parse_xml_output(self, nmap_module, temp_xml_file):
        """Test XML output parsing."""
        result = nmap_module.parse_xml_output(temp_xml_file)

        assert "hosts" in result
        assert "total_hosts" in result
        assert "hosts_with_ports" in result
        assert result["total_hosts"] == 1

    def test_parse_xml_extracts_ip(self, nmap_module, temp_xml_file):
        """Test IP extraction from XML."""
        result = nmap_module.parse_xml_output(temp_xml_file)

        assert result["hosts"][0]["ip"] == "192.168.1.1"

    def test_parse_xml_extracts_hostname(self, nmap_module, temp_xml_file):
        """Test hostname extraction from XML."""
        result = nmap_module.parse_xml_output(temp_xml_file)

        assert result["hosts"][0]["hostname"] == "test.local"

    def test_parse_xml_extracts_ports(self, nmap_module, temp_xml_file):
        """Test port extraction from XML."""
        result = nmap_module.parse_xml_output(temp_xml_file)

        host = result["hosts"][0]
        assert "22/tcp" in host["open_ports"]
        assert "80/tcp" in host["open_ports"]
        assert "443/tcp" in host["open_ports"]

    def test_parse_xml_extracts_services(self, nmap_module, temp_xml_file):
        """Test service info extraction from XML."""
        result = nmap_module.parse_xml_output(temp_xml_file)

        host = result["hosts"][0]
        assert host["services"]["22/tcp"]["service"] == "ssh"
        assert host["services"]["80/tcp"]["service"] == "http"

    def test_parse_xml_invalid_file(self, nmap_module):
        """Test parsing invalid XML file."""
        result = nmap_module.parse_xml_output("/nonexistent/file.xml")

        assert result["hosts"] == []
        assert result["total_hosts"] == 0


# =============================================================================
# Operations Tests
# =============================================================================

class TestNmapOperations:
    """Tests for NmapModule operations."""

    def test_get_operations(self, nmap_module):
        """Test getting available operations."""
        operations = nmap_module.get_operations()

        assert len(operations) > 0
        op_names = [op["name"] for op in operations]
        assert "Default Scan" in op_names
        assert "Fast Scan" in op_names
        assert "Stealth Scan" in op_names
        assert "UDP Scan" in op_names

    def test_operations_have_subcategories(self, nmap_module):
        """Test operations have subcategory tags."""
        operations = nmap_module.get_operations()

        for op in operations:
            assert "subcategory" in op
            assert op["subcategory"] in ["standard", "advanced", "specialized"]

    def test_op_default_scan_sets_options(self, nmap_module):
        """Test default scan sets correct options."""
        nmap_module.set_option("RHOST", "192.168.1.100")

        with patch.object(nmap_module, 'run', return_value={"success": True}):
            nmap_module.op_default_scan()

        assert nmap_module.get_option("PORTS") == "-"
        assert nmap_module.get_option("SCAN_TYPE") == "sCV"

    def test_op_fast_scan_sets_options(self, nmap_module):
        """Test fast scan sets correct options."""
        nmap_module.set_option("RHOST", "192.168.1.100")

        with patch.object(nmap_module, 'run', return_value={"success": True}):
            nmap_module.op_fast_scan()

        assert nmap_module.get_option("TOP_PORTS") == "100"
        assert nmap_module.get_option("SCAN_TYPE") == "sV"

    def test_op_stealth_scan_sets_options(self, nmap_module):
        """Test stealth scan sets correct options."""
        nmap_module.set_option("RHOST", "192.168.1.100")

        with patch.object(nmap_module, 'run', return_value={"success": True}):
            nmap_module.op_stealth_scan()

        assert nmap_module.get_option("SCAN_TYPE") == "sS"
        assert nmap_module.get_option("TIMING") == "2"

    def test_op_udp_scan_sets_options(self, nmap_module):
        """Test UDP scan sets correct options."""
        nmap_module.set_option("RHOST", "192.168.1.100")

        with patch.object(nmap_module, 'run', return_value={"success": True}):
            nmap_module.op_udp_scan()

        assert nmap_module.get_option("SCAN_TYPE") == "sU"
        assert nmap_module.get_option("TOP_PORTS") == "100"


# =============================================================================
# Service Processing Tests
# =============================================================================

class TestNmapServiceProcessing:
    """Tests for NmapModule service processing."""

    def test_process_discovered_hosts(self, nmap_module, mock_framework):
        """Test processing discovered hosts."""
        parsed_xml = {
            "hosts": [{
                "ip": "192.168.1.100",
                "hostname": "test.local",
                "open_ports": ["22/tcp", "80/tcp"],
                "services": {
                    "22/tcp": {"service": "ssh", "port": 22, "version": "OpenSSH 8.0", "protocol": "tcp"},
                    "80/tcp": {"service": "http", "port": 80, "version": "nginx", "protocol": "tcp"}
                }
            }]
        }

        nmap_module.process_discovered_hosts(parsed_xml)

        # Should add target
        assert len(mock_framework.session.targets.list()) > 0

    def test_process_hosts_maps_services(self, nmap_module, mock_framework):
        """Test service name mapping during processing."""
        parsed_xml = {
            "hosts": [{
                "ip": "192.168.1.100",
                "hostname": None,
                "open_ports": ["445/tcp"],
                "services": {
                    "445/tcp": {"service": "microsoft-ds", "port": 445, "version": "", "protocol": "tcp"}
                }
            }]
        }

        nmap_module.process_discovered_hosts(parsed_xml)

        # microsoft-ds should be mapped to smb
        assert mock_framework.session.services.has_service("192.168.1.100", "smb")


# =============================================================================
# Run Method Tests
# =============================================================================

class TestNmapRun:
    """Tests for NmapModule run method."""

    def test_run_background_mode(self, nmap_module):
        """Test running in background mode."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("BACKGROUND", "true")
        nmap_module.tool_path = "/usr/bin/nmap"

        with patch.object(nmap_module, 'execute_command', return_value={"success": True, "pid": 12345}):
            result = nmap_module.run()

        assert "note" in result or result.get("success")

    def test_run_foreground_mode(self, nmap_module):
        """Test running in foreground mode."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("BACKGROUND", "false")
        nmap_module.tool_path = "/usr/bin/nmap"

        with patch.object(NmapModule.__bases__[0], 'run', return_value={"success": True, "stdout": ""}):
            result = nmap_module.run()

        assert "success" in result


# =============================================================================
# Edge Cases
# =============================================================================

class TestNmapEdgeCases:
    """Tests for edge cases in nmap module."""

    def test_build_command_network_range(self, nmap_module):
        """Test command building with network range."""
        nmap_module.set_option("RHOST", "192.168.1.0/24")

        command = nmap_module.build_command()

        assert "192.168.1.0/24" in command

    def test_build_command_sanitizes_target(self, nmap_module):
        """Test target sanitization in output filename."""
        nmap_module.set_option("RHOST", "192.168.1.100")
        nmap_module.set_option("OUTPUT_FORMAT", "all")

        command = nmap_module.build_command()

        # Should include sanitized filename
        assert "-oA" in command

    def test_parse_xml_host_down(self, nmap_module, tmp_path):
        """Test XML parsing handles down hosts."""
        xml_content = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
  </host>
</nmaprun>'''
        xml_file = tmp_path / "test.xml"
        xml_file.write_text(xml_content)

        result = nmap_module.parse_xml_output(str(xml_file))

        assert result["total_hosts"] == 0

    def test_parse_xml_no_open_ports(self, nmap_module, tmp_path):
        """Test XML parsing handles hosts with no open ports."""
        xml_content = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
        xml_file = tmp_path / "test.xml"
        xml_file.write_text(xml_content)

        result = nmap_module.parse_xml_output(str(xml_file))

        assert result["hosts_with_ports"] == 0

    def test_module_options_defaults(self, nmap_module):
        """Test default option values."""
        assert nmap_module.get_option("PORTS") == "-"
        assert nmap_module.get_option("SCAN_TYPE") == "sCV"
        assert nmap_module.get_option("TIMING") == "4"
        assert nmap_module.get_option("BACKGROUND") == "true"
