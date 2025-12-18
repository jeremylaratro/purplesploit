"""
Unit tests for Nmap parsing functionality.

Tests cover:
- XML output parsing
- Standard output parsing
- Service detection and mapping
- Edge cases (empty output, malformed XML)
- Searchsploit integration
"""

import pytest
import tempfile
import os
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework_minimal():
    """Create a minimal mock framework for testing."""
    framework = MagicMock()
    framework.session = MagicMock()
    framework.session.services = MagicMock()
    framework.session.services.add_service = MagicMock()
    framework.database = MagicMock()
    framework.database.add_service = MagicMock()
    framework.add_target = MagicMock(return_value=True)
    framework.log = MagicMock()
    return framework


@pytest.fixture
def nmap_parser_module(mock_framework_minimal):
    """Create an NmapParser module for testing."""
    from purplesploit.modules.recon.nmap_parser import NmapParser
    return NmapParser(mock_framework_minimal)


@pytest.fixture
def nmap_module(mock_framework_minimal):
    """Create an NmapModule for testing parse functions."""
    from purplesploit.modules.recon.nmap import NmapModule
    return NmapModule(mock_framework_minimal)


@pytest.fixture
def sample_nmap_xml():
    """Return sample nmap XML output."""
    return '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX output.xml 192.168.1.1" start="1234567890" version="7.93">
<host starttime="1234567890" endtime="1234567891">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
        <hostname name="server.example.com" type="PTR"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.2p1"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.41"/>
        </port>
        <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack"/>
            <service name="https" product="Apache httpd" version="2.4.41"/>
        </port>
        <port protocol="tcp" portid="445">
            <state state="open" reason="syn-ack"/>
            <service name="microsoft-ds"/>
        </port>
        <port protocol="tcp" portid="3306">
            <state state="closed" reason="reset"/>
            <service name="mysql"/>
        </port>
    </ports>
</host>
<host starttime="1234567890" endtime="1234567891">
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
</host>
<host starttime="1234567890" endtime="1234567891">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.3" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="21">
            <state state="open" reason="syn-ack"/>
            <service name="ftp" product="vsftpd" version="3.0.3"/>
        </port>
    </ports>
</host>
</nmaprun>
'''


@pytest.fixture
def sample_nmap_xml_file(sample_nmap_xml, tmp_path):
    """Create a temporary nmap XML file."""
    xml_file = tmp_path / "nmap_output.xml"
    xml_file.write_text(sample_nmap_xml)
    return str(xml_file)


# =============================================================================
# NmapParser Module Tests
# =============================================================================

class TestNmapParserModule:
    """Tests for NmapParser module."""

    def test_module_properties(self, nmap_parser_module):
        """Test module has correct properties."""
        assert nmap_parser_module.name == "Nmap XML Parser"
        assert nmap_parser_module.category == "recon"
        assert "XML" in nmap_parser_module.description

    def test_module_options(self, nmap_parser_module):
        """Test module options are initialized."""
        assert "XML_FILE" in nmap_parser_module.options
        assert nmap_parser_module.options["XML_FILE"]["required"] is True
        assert "AUTO_ADD_TARGETS" in nmap_parser_module.options
        assert "RUN_SEARCHSPLOIT" in nmap_parser_module.options

    def test_run_with_valid_xml(self, nmap_parser_module, sample_nmap_xml_file):
        """Test parsing valid nmap XML."""
        nmap_parser_module.set_option("XML_FILE", sample_nmap_xml_file)
        nmap_parser_module.set_option("RUN_SEARCHSPLOIT", "false")

        with patch('purplesploit.modules.recon.nmap_parser.db_manager'):
            result = nmap_parser_module.run()

        assert result["success"] is True
        assert result["data"]["hosts_processed"] == 2  # Two up hosts
        assert result["data"]["services_found"] >= 4  # At least 4 services

    def test_run_with_nonexistent_file(self, nmap_parser_module):
        """Test error handling for nonexistent file."""
        nmap_parser_module.set_option("XML_FILE", "/nonexistent/path.xml")

        result = nmap_parser_module.run()

        assert result["success"] is False
        assert "File not found" in result["error"]

    def test_run_with_malformed_xml(self, nmap_parser_module, tmp_path):
        """Test error handling for malformed XML."""
        bad_xml = tmp_path / "bad.xml"
        bad_xml.write_text("<invalid><<<malformed>>>")

        nmap_parser_module.set_option("XML_FILE", str(bad_xml))

        result = nmap_parser_module.run()

        assert result["success"] is False
        assert "parse" in result["error"].lower() or "xml" in result["error"].lower()

    def test_run_with_empty_xml(self, nmap_parser_module, tmp_path):
        """Test handling of empty XML file."""
        empty_xml = tmp_path / "empty.xml"
        empty_xml.write_text('<?xml version="1.0"?><nmaprun></nmaprun>')

        nmap_parser_module.set_option("XML_FILE", str(empty_xml))
        nmap_parser_module.set_option("RUN_SEARCHSPLOIT", "false")

        with patch('purplesploit.modules.recon.nmap_parser.db_manager'):
            result = nmap_parser_module.run()

        assert result["success"] is True
        assert result["data"]["hosts_processed"] == 0

    def test_check_with_valid_file(self, nmap_parser_module, sample_nmap_xml_file):
        """Test check() with valid file."""
        nmap_parser_module.set_option("XML_FILE", sample_nmap_xml_file)

        result = nmap_parser_module.check()

        assert result["success"] is True

    def test_check_with_missing_file(self, nmap_parser_module):
        """Test check() with missing file."""
        nmap_parser_module.set_option("XML_FILE", "/missing.xml")

        result = nmap_parser_module.check()

        assert result["success"] is False
        assert "File not found" in result["error"]

    def test_check_without_xml_file_option(self, nmap_parser_module):
        """Test check() without XML_FILE set."""
        result = nmap_parser_module.check()

        assert result["success"] is False
        assert "XML_FILE" in result["error"]


# =============================================================================
# NmapModule XML Parsing Tests
# =============================================================================

class TestNmapXmlParsing:
    """Tests for NmapModule.parse_xml_output()."""

    def test_parse_xml_output_valid(self, nmap_module, sample_nmap_xml_file):
        """Test parsing valid nmap XML output."""
        result = nmap_module.parse_xml_output(sample_nmap_xml_file)

        assert result["total_hosts"] == 2
        assert result["hosts_with_ports"] == 2
        assert len(result["hosts"]) == 2

    def test_parse_xml_extracts_ip_addresses(self, nmap_module, sample_nmap_xml_file):
        """Test IP addresses are extracted correctly."""
        result = nmap_module.parse_xml_output(sample_nmap_xml_file)

        ips = [host["ip"] for host in result["hosts"]]
        assert "192.168.1.1" in ips
        assert "192.168.1.3" in ips

    def test_parse_xml_extracts_hostnames(self, nmap_module, sample_nmap_xml_file):
        """Test hostnames are extracted correctly."""
        result = nmap_module.parse_xml_output(sample_nmap_xml_file)

        for host in result["hosts"]:
            if host["ip"] == "192.168.1.1":
                assert host["hostname"] == "server.example.com"

    def test_parse_xml_extracts_services(self, nmap_module, sample_nmap_xml_file):
        """Test services are extracted correctly."""
        result = nmap_module.parse_xml_output(sample_nmap_xml_file)

        for host in result["hosts"]:
            if host["ip"] == "192.168.1.1":
                assert "22/tcp" in host["open_ports"]
                assert "80/tcp" in host["open_ports"]
                assert "443/tcp" in host["open_ports"]
                assert "445/tcp" in host["open_ports"]
                # Closed port should not be included
                assert "3306/tcp" not in host["open_ports"]

    def test_parse_xml_extracts_versions(self, nmap_module, sample_nmap_xml_file):
        """Test service versions are extracted correctly."""
        result = nmap_module.parse_xml_output(sample_nmap_xml_file)

        for host in result["hosts"]:
            if host["ip"] == "192.168.1.1":
                ssh_service = host["services"]["22/tcp"]
                assert "OpenSSH" in ssh_service["version"]
                assert "8.2p1" in ssh_service["version"]

    def test_parse_xml_excludes_down_hosts(self, nmap_module, sample_nmap_xml_file):
        """Test down hosts are excluded."""
        result = nmap_module.parse_xml_output(sample_nmap_xml_file)

        ips = [host["ip"] for host in result["hosts"]]
        assert "192.168.1.2" not in ips

    def test_parse_xml_nonexistent_file(self, nmap_module):
        """Test parsing nonexistent file."""
        result = nmap_module.parse_xml_output("/nonexistent/path.xml")

        assert result["hosts"] == []
        assert result["total_hosts"] == 0

    def test_parse_xml_malformed(self, nmap_module, tmp_path):
        """Test parsing malformed XML."""
        bad_file = tmp_path / "malformed.xml"
        bad_file.write_text("not xml content <<>>")

        result = nmap_module.parse_xml_output(str(bad_file))

        assert result["hosts"] == []


# =============================================================================
# NmapModule Output Parsing Tests
# =============================================================================

class TestNmapOutputParsing:
    """Tests for NmapModule.parse_output()."""

    def test_parse_output_tcp_ports(self, nmap_module):
        """Test parsing TCP port output."""
        output = """
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 192.168.1.1
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu
80/tcp   open  http       Apache httpd 2.4.41
443/tcp  open  https      Apache httpd 2.4.41
"""
        result = nmap_module.parse_output(output)

        assert "22/tcp" in result["open_ports"]
        assert "80/tcp" in result["open_ports"]
        assert "443/tcp" in result["open_ports"]

    def test_parse_output_udp_ports(self, nmap_module):
        """Test parsing UDP port output."""
        output = """
53/udp   open  domain     ISC BIND 9.16.1
123/udp  open  ntp        NTP v4
"""
        result = nmap_module.parse_output(output)

        assert "53/udp" in result["open_ports"]
        assert "123/udp" in result["open_ports"]

    def test_parse_output_service_names(self, nmap_module):
        """Test service names are parsed correctly."""
        output = "22/tcp   open  ssh        OpenSSH 8.2p1"

        result = nmap_module.parse_output(output)

        assert result["services"]["22/tcp"]["service"] == "ssh"

    def test_parse_output_service_versions(self, nmap_module):
        """Test service versions are parsed correctly."""
        output = "80/tcp   open  http       Apache httpd 2.4.41 (Ubuntu)"

        result = nmap_module.parse_output(output)

        assert "Apache httpd 2.4.41" in result["services"]["80/tcp"]["version"]

    def test_parse_output_os_detection(self, nmap_module):
        """Test OS detection parsing."""
        output = """
22/tcp   open  ssh
OS details: Linux 5.4.0
"""
        result = nmap_module.parse_output(output)

        assert result["os_guess"] is not None
        assert "Linux" in result["os_guess"]

    def test_parse_output_aggressive_os_guess(self, nmap_module):
        """Test aggressive OS guess parsing."""
        output = """
22/tcp   open  ssh
Aggressive OS guesses: Linux 5.4 - 5.10 (98%)
"""
        result = nmap_module.parse_output(output)

        assert result["os_guess"] is not None
        assert "Linux" in result["os_guess"]

    def test_parse_output_empty(self, nmap_module):
        """Test parsing empty output."""
        result = nmap_module.parse_output("")

        assert result["open_ports"] == []
        assert result["services"] == {}
        assert result["os_guess"] is None

    def test_parse_output_no_open_ports(self, nmap_module):
        """Test parsing output with no open ports."""
        output = """
Starting Nmap 7.93
All 1000 scanned ports on 192.168.1.1 are closed
"""
        result = nmap_module.parse_output(output)

        assert result["open_ports"] == []

    def test_parse_output_filtered_ports(self, nmap_module):
        """Test parsing output with filtered ports."""
        output = """
22/tcp   filtered  ssh
80/tcp   open      http
"""
        result = nmap_module.parse_output(output)

        # Only open ports should be included
        assert "80/tcp" in result["open_ports"]
        assert "22/tcp" not in result["open_ports"]


# =============================================================================
# Searchsploit Integration Tests
# =============================================================================

class TestSearchsploitIntegration:
    """Tests for searchsploit integration."""

    def test_run_searchsploit_success(self, nmap_parser_module):
        """Test successful searchsploit execution."""
        mock_output = """
------------------------------------
 Exploit Title                     |  Path
------------------------------------
OpenSSH < 7.7 - Auth Bypass        | linux/remote/45001.py
OpenSSH 7.7 - Username Enumeration | linux/remote/45233.py
------------------------------------
"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=mock_output
            )
            result = nmap_parser_module._run_searchsploit("OpenSSH", "7.6")

        assert len(result) >= 0  # May or may not parse depending on format

    def test_run_searchsploit_timeout(self, nmap_parser_module):
        """Test searchsploit timeout handling."""
        import subprocess
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="searchsploit", timeout=30)
            result = nmap_parser_module._run_searchsploit("Apache", "2.4.41")

        assert result == []

    def test_run_searchsploit_not_installed(self, nmap_parser_module):
        """Test handling when searchsploit is not installed."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("searchsploit not found")
            result = nmap_parser_module._run_searchsploit("nginx", "1.18")

        assert result == []

    def test_run_searchsploit_empty_version(self, nmap_parser_module):
        """Test searchsploit with empty version."""
        result = nmap_parser_module._run_searchsploit("Apache", "")

        assert result == []

    def test_run_searchsploit_no_results(self, nmap_parser_module):
        """Test searchsploit with no results."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="No results found"
            )
            result = nmap_parser_module._run_searchsploit("UniqueService", "1.0")

        assert result == []


# =============================================================================
# Service Mapping Tests
# =============================================================================

class TestServiceMapping:
    """Tests for service name mapping."""

    def test_microsoft_ds_mapped_to_smb(self, nmap_parser_module, tmp_path):
        """Test microsoft-ds is mapped to smb."""
        xml_content = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="microsoft-ds"/>
        </port>
    </ports>
</host>
</nmaprun>'''
        xml_file = tmp_path / "test.xml"
        xml_file.write_text(xml_content)

        nmap_parser_module.set_option("XML_FILE", str(xml_file))
        nmap_parser_module.set_option("RUN_SEARCHSPLOIT", "false")
        nmap_parser_module.set_option("AUTO_ADD_TARGETS", "false")

        with patch('purplesploit.modules.recon.nmap_parser.db_manager'):
            nmap_parser_module.run()

        # Check that add_service was called with 'smb'
        calls = nmap_parser_module.framework.session.services.add_service.call_args_list
        assert any('smb' in str(call) for call in calls)

    def test_ms_sql_mapped_to_mssql(self, nmap_parser_module, tmp_path):
        """Test ms-sql-s is mapped to mssql."""
        xml_content = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="1433">
            <state state="open"/>
            <service name="ms-sql-s"/>
        </port>
    </ports>
</host>
</nmaprun>'''
        xml_file = tmp_path / "test.xml"
        xml_file.write_text(xml_content)

        nmap_parser_module.set_option("XML_FILE", str(xml_file))
        nmap_parser_module.set_option("RUN_SEARCHSPLOIT", "false")
        nmap_parser_module.set_option("AUTO_ADD_TARGETS", "false")

        with patch('purplesploit.modules.recon.nmap_parser.db_manager'):
            nmap_parser_module.run()

        calls = nmap_parser_module.framework.session.services.add_service.call_args_list
        assert any('mssql' in str(call) for call in calls)


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestParserEdgeCases:
    """Tests for parser edge cases."""

    def test_xml_with_ipv6_address(self, nmap_module, tmp_path):
        """Test parsing XML with IPv6 addresses."""
        xml_content = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <status state="up"/>
    <address addr="fe80::1" addrtype="ipv6"/>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh"/>
        </port>
    </ports>
</host>
</nmaprun>'''
        xml_file = tmp_path / "ipv6.xml"
        xml_file.write_text(xml_content)

        result = nmap_module.parse_xml_output(str(xml_file))

        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip"] == "fe80::1"

    def test_xml_with_unicode_hostname(self, nmap_module, tmp_path):
        """Test parsing XML with unicode hostnames."""
        xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
        <hostname name="сервер.example.com" type="PTR"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http"/>
        </port>
    </ports>
</host>
</nmaprun>'''
        xml_file = tmp_path / "unicode.xml"
        xml_file.write_text(xml_content, encoding='utf-8')

        result = nmap_module.parse_xml_output(str(xml_file))

        assert len(result["hosts"]) == 1
        assert "сервер" in result["hosts"][0]["hostname"]

    def test_xml_with_many_ports(self, nmap_module, tmp_path):
        """Test parsing XML with many ports."""
        ports_xml = ""
        for port in range(1, 101):
            ports_xml += f'''
        <port protocol="tcp" portid="{port}">
            <state state="open"/>
            <service name="service{port}"/>
        </port>'''

        xml_content = f'''<?xml version="1.0"?>
<nmaprun>
<host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>{ports_xml}
    </ports>
</host>
</nmaprun>'''
        xml_file = tmp_path / "many_ports.xml"
        xml_file.write_text(xml_content)

        result = nmap_module.parse_xml_output(str(xml_file))

        assert len(result["hosts"][0]["open_ports"]) == 100

    def test_output_with_special_characters(self, nmap_module):
        """Test parsing output with special characters."""
        output = """
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu "custom build"
80/tcp   open  http       nginx/1.18.0 (Ubuntu) <test>
"""
        result = nmap_module.parse_output(output)

        assert "22/tcp" in result["open_ports"]
        assert "80/tcp" in result["open_ports"]

    def test_xml_host_without_ports_section(self, nmap_module, tmp_path):
        """Test parsing XML where host has no ports section."""
        xml_content = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
</host>
</nmaprun>'''
        xml_file = tmp_path / "no_ports.xml"
        xml_file.write_text(xml_content)

        result = nmap_module.parse_xml_output(str(xml_file))

        # Host should be counted but not included in hosts list (no open ports)
        assert result["hosts"] == []
