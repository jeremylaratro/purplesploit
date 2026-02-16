"""
Tests for purplesploit.modules.recon.dns module.

Tests cover:
- DNSModule initialization
- Module properties (name, description, author, category)
- Options initialization
- Command building (build_command)
- DNS operations (zone_transfer, all_records, ns/mx/txt/soa records, reverse lookup)
- Output parsing (_parse_zone_transfer, _parse_records, _parse_soa)
- Target addition (_add_target)
- Default run behavior
"""

import pytest
from unittest.mock import MagicMock, patch

from purplesploit.modules.recon.dns import DNSModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework():
    """Create a mock framework instance."""
    framework = MagicMock()
    framework.session = MagicMock()
    framework.session.targets = MagicMock()
    framework.session.targets.add = MagicMock()
    return framework


@pytest.fixture
def dns_module(mock_framework):
    """Create a DNSModule instance with mocked framework."""
    module = DNSModule(mock_framework)
    return module


# =============================================================================
# Initialization Tests
# =============================================================================

class TestDNSModuleInit:
    """Tests for DNSModule initialization."""

    def test_init(self, mock_framework):
        """Test basic initialization."""
        module = DNSModule(mock_framework)

        assert module.framework == mock_framework
        assert module.tool_name == "dig"

    def test_properties(self, dns_module):
        """Test module properties."""
        assert dns_module.name == "DNS Enumeration"
        assert "dig" in dns_module.description
        assert dns_module.author == "PurpleSploit Team"
        assert dns_module.category == "recon"

    def test_init_options(self, dns_module):
        """Test options are initialized."""
        assert "DOMAIN" in dns_module.options
        assert "NAMESERVER" in dns_module.options
        assert "RECORD_TYPE" in dns_module.options

    def test_domain_option_required(self, dns_module):
        """Test DOMAIN option is required."""
        assert dns_module.options["DOMAIN"]["required"] is True

    def test_nameserver_option_optional(self, dns_module):
        """Test NAMESERVER option is optional."""
        assert dns_module.options["NAMESERVER"]["required"] is False

    def test_record_type_default(self, dns_module):
        """Test RECORD_TYPE has default value."""
        assert dns_module.options["RECORD_TYPE"]["value"] == "ANY"


# =============================================================================
# Operations Tests
# =============================================================================

class TestGetOperations:
    """Tests for get_operations method."""

    def test_get_operations_returns_list(self, dns_module):
        """Test get_operations returns a list."""
        ops = dns_module.get_operations()

        assert isinstance(ops, list)
        assert len(ops) == 7

    def test_zone_transfer_operation(self, dns_module):
        """Test zone transfer operation is defined."""
        ops = dns_module.get_operations()
        zone_transfer = ops[0]

        assert zone_transfer["name"] == "Zone Transfer (AXFR)"
        assert zone_transfer["handler"] == dns_module.op_zone_transfer

    def test_all_records_operation(self, dns_module):
        """Test all records operation is defined."""
        ops = dns_module.get_operations()
        all_records = ops[1]

        assert all_records["name"] == "All Records"
        assert all_records["handler"] == dns_module.op_all_records

    def test_reverse_lookup_operation(self, dns_module):
        """Test reverse lookup operation is defined."""
        ops = dns_module.get_operations()
        reverse = ops[6]

        assert reverse["name"] == "Reverse Lookup"
        assert reverse["handler"] == dns_module.op_reverse_lookup


# =============================================================================
# Command Building Tests
# =============================================================================

class TestBuildCommand:
    """Tests for build_command method."""

    def test_build_basic_command(self, dns_module):
        """Test building basic dig command."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        cmd = dns_module.build_command()

        assert "dig" in cmd
        assert "example.com" in cmd
        assert "+noall" in cmd
        assert "+answer" in cmd

    def test_build_command_with_nameserver(self, dns_module):
        """Test building command with custom nameserver."""
        dns_module.options["DOMAIN"]["value"] = "example.com"
        dns_module.options["NAMESERVER"]["value"] = "8.8.8.8"

        cmd = dns_module.build_command()

        assert "@8.8.8.8" in cmd

    def test_build_command_with_record_type(self, dns_module):
        """Test building command with record type."""
        dns_module.options["DOMAIN"]["value"] = "example.com"
        dns_module.options["RECORD_TYPE"]["value"] = "MX"

        cmd = dns_module.build_command()

        assert "MX" in cmd

    def test_build_command_all_options(self, dns_module):
        """Test building command with all options."""
        dns_module.options["DOMAIN"]["value"] = "example.com"
        dns_module.options["NAMESERVER"]["value"] = "1.1.1.1"
        dns_module.options["RECORD_TYPE"]["value"] = "TXT"

        cmd = dns_module.build_command()

        assert "dig @1.1.1.1 example.com TXT" in cmd


# =============================================================================
# Zone Transfer Tests
# =============================================================================

class TestZoneTransfer:
    """Tests for op_zone_transfer method."""

    def test_zone_transfer_success(self, dns_module):
        """Test successful zone transfer."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        zone_output = """
example.com.    3600    IN    SOA    ns1.example.com. admin.example.com. 2024010101 3600 600 604800 86400
example.com.    3600    IN    NS    ns1.example.com.
www.example.com.    3600    IN    A    192.168.1.100
mail.example.com.    3600    IN    A    192.168.1.101
"""
        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": zone_output
        })

        result = dns_module.op_zone_transfer()

        assert result["success"] is True
        assert "parsed" in result
        assert len(result["parsed"]["records"]) == 4

    def test_zone_transfer_without_nameserver(self, dns_module):
        """Test zone transfer discovers NS first."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        ns_output = "ns1.example.com.\nns2.example.com."
        zone_output = "example.com.    3600    IN    SOA    ns1.example.com. admin.example.com. 1"

        call_count = 0

        def mock_execute(cmd):
            nonlocal call_count
            call_count += 1
            if "NS +short" in cmd:
                return {"success": True, "output": ns_output}
            return {"success": True, "output": zone_output}

        dns_module.execute_command = mock_execute

        result = dns_module.op_zone_transfer()

        assert result["success"] is True

    def test_zone_transfer_failure(self, dns_module):
        """Test zone transfer failure."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": "; Transfer failed\n"
        })

        result = dns_module.op_zone_transfer()

        assert result["message"] == "Zone transfer failed or not allowed"

    def test_zone_transfer_adds_targets(self, dns_module, mock_framework):
        """Test zone transfer adds discovered A records as targets."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        zone_output = """
www.example.com.    3600    IN    A    192.168.1.100
api.example.com.    3600    IN    AAAA    ::1
"""
        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": zone_output
        })

        dns_module.op_zone_transfer()

        # Should add A and AAAA records as targets
        assert mock_framework.session.targets.add.call_count >= 1


# =============================================================================
# All Records Tests
# =============================================================================

class TestAllRecords:
    """Tests for op_all_records method."""

    def test_all_records_queries_multiple_types(self, dns_module):
        """Test all_records queries multiple record types."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        call_count = 0

        def mock_execute(cmd):
            nonlocal call_count
            call_count += 1
            if "A " in cmd:
                return {"success": True, "output": "example.com.  300  IN  A  192.168.1.1"}
            return {"success": True, "output": ""}

        dns_module.execute_command = mock_execute

        result = dns_module.op_all_records()

        assert result["success"] is True
        # Should query 8 record types
        assert call_count == 8

    def test_all_records_message(self, dns_module):
        """Test all_records returns proper message."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": "example.com.  300  IN  A  192.168.1.1"
        })

        result = dns_module.op_all_records()

        assert "Queried" in result["message"]
        assert "record types" in result["message"]


# =============================================================================
# Individual Record Type Tests
# =============================================================================

class TestNSRecords:
    """Tests for op_ns_records method."""

    def test_ns_records(self, dns_module):
        """Test NS records query."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        ns_output = "example.com.    3600    IN    NS    ns1.example.com."
        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": ns_output
        })

        result = dns_module.op_ns_records()

        assert result["success"] is True
        assert "parsed" in result
        dns_module.execute_command.assert_called_once()
        assert "NS" in dns_module.execute_command.call_args[0][0]

    def test_ns_records_with_nameserver(self, dns_module):
        """Test NS records with custom nameserver."""
        dns_module.options["DOMAIN"]["value"] = "example.com"
        dns_module.options["NAMESERVER"]["value"] = "8.8.8.8"

        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": ""
        })

        dns_module.op_ns_records()

        cmd = dns_module.execute_command.call_args[0][0]
        assert "@8.8.8.8" in cmd


class TestMXRecords:
    """Tests for op_mx_records method."""

    def test_mx_records(self, dns_module):
        """Test MX records query."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        mx_output = "example.com.    3600    IN    MX    10 mail.example.com."
        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": mx_output
        })

        result = dns_module.op_mx_records()

        assert result["success"] is True
        assert "parsed" in result
        assert "MX" in dns_module.execute_command.call_args[0][0]


class TestTXTRecords:
    """Tests for op_txt_records method."""

    def test_txt_records(self, dns_module):
        """Test TXT records query."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        txt_output = 'example.com.    3600    IN    TXT    "v=spf1 include:_spf.google.com ~all"'
        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": txt_output
        })

        result = dns_module.op_txt_records()

        assert result["success"] is True
        assert "TXT" in dns_module.execute_command.call_args[0][0]


class TestSOARecord:
    """Tests for op_soa_record method."""

    def test_soa_record(self, dns_module):
        """Test SOA record query."""
        dns_module.options["DOMAIN"]["value"] = "example.com"

        soa_output = "example.com.    3600    IN    SOA    ns1.example.com. admin.example.com. 2024010101 3600 600 604800 86400"
        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": soa_output
        })

        result = dns_module.op_soa_record()

        assert result["success"] is True
        assert "parsed" in result
        assert "SOA" in dns_module.execute_command.call_args[0][0]


class TestReverseLookup:
    """Tests for op_reverse_lookup method."""

    def test_reverse_lookup(self, dns_module):
        """Test reverse DNS lookup."""
        dns_module.options["DOMAIN"]["value"] = "192.168.1.1"

        ptr_output = "1.1.168.192.in-addr.arpa.    3600    IN    PTR    host.example.com."
        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": ptr_output
        })

        result = dns_module.op_reverse_lookup()

        assert result["success"] is True
        cmd = dns_module.execute_command.call_args[0][0]
        assert "-x" in cmd


# =============================================================================
# Output Parsing Tests
# =============================================================================

class TestParseZoneTransfer:
    """Tests for _parse_zone_transfer method."""

    def test_parse_zone_transfer_records(self, dns_module):
        """Test parsing zone transfer output."""
        output = """
www.example.com.    3600    IN    A    192.168.1.100
mail.example.com.    3600    IN    A    192.168.1.101
ns1.example.com.    3600    IN    CNAME    ns.example.net.
"""
        result = dns_module._parse_zone_transfer(output)

        assert len(result["records"]) == 3
        assert result["record_count"] == 3
        assert "www.example.com" in result["subdomains"]

    def test_parse_zone_transfer_extracts_subdomains(self, dns_module):
        """Test subdomain extraction from zone transfer."""
        output = """
sub1.example.com.    3600    IN    A    192.168.1.1
sub2.example.com.    3600    IN    AAAA    ::1
sub3.example.com.    3600    IN    CNAME    sub1.example.com.
"""
        result = dns_module._parse_zone_transfer(output)

        assert "sub1.example.com" in result["subdomains"]
        assert "sub2.example.com" in result["subdomains"]
        assert "sub3.example.com" in result["subdomains"]

    def test_parse_zone_transfer_skips_comments(self, dns_module):
        """Test parsing skips comment lines."""
        output = """
; This is a comment
;; Another comment
www.example.com.    3600    IN    A    192.168.1.100
"""
        result = dns_module._parse_zone_transfer(output)

        assert len(result["records"]) == 1

    def test_parse_zone_transfer_empty_output(self, dns_module):
        """Test parsing empty output."""
        result = dns_module._parse_zone_transfer("")

        assert result["records"] == []
        assert result["subdomains"] == []
        assert result["record_count"] == 0


class TestParseRecords:
    """Tests for _parse_records method."""

    def test_parse_records(self, dns_module):
        """Test parsing standard record output."""
        output = """
example.com.    3600    IN    A    192.168.1.1
example.com.    3600    IN    A    192.168.1.2
"""
        result = dns_module._parse_records(output)

        assert len(result) == 2
        assert result[0]["name"] == "example.com"
        assert result[0]["type"] == "A"
        assert result[0]["value"] == "192.168.1.1"

    def test_parse_records_strips_trailing_dot(self, dns_module):
        """Test trailing dots are stripped."""
        output = "example.com.    3600    IN    NS    ns1.example.com."

        result = dns_module._parse_records(output)

        assert result[0]["name"] == "example.com"
        assert result[0]["value"] == "ns1.example.com"

    def test_parse_records_empty(self, dns_module):
        """Test parsing empty output."""
        result = dns_module._parse_records("")

        assert result == []


class TestParseSOA:
    """Tests for _parse_soa method."""

    def test_parse_soa_full(self, dns_module):
        """Test parsing full SOA record."""
        output = "example.com.    3600    IN    SOA    ns1.example.com. admin.example.com. 2024010101 3600 600 604800 86400"

        result = dns_module._parse_soa(output)

        assert result["primary_ns"] == "ns1.example.com"
        assert result["admin_email"] == "admin@example.com"
        assert result["serial"] == "2024010101"
        assert result["refresh"] == "3600"

    def test_parse_soa_empty(self, dns_module):
        """Test parsing empty SOA output."""
        result = dns_module._parse_soa("")

        assert result == {}

    def test_parse_soa_skips_comments(self, dns_module):
        """Test parsing skips comments."""
        output = "; SOA comment\nexample.com.    3600    IN    SOA    ns1.example.com. admin.example.com. 1"

        result = dns_module._parse_soa(output)

        assert result["primary_ns"] == "ns1.example.com"


# =============================================================================
# Target Addition Tests
# =============================================================================

class TestAddTarget:
    """Tests for _add_target method."""

    def test_add_target_success(self, dns_module, mock_framework):
        """Test adding target to session."""
        dns_module._add_target("192.168.1.100", "www.example.com")

        mock_framework.session.targets.add.assert_called_once()
        call_args = mock_framework.session.targets.add.call_args[0][0]
        assert call_args["ip"] == "192.168.1.100"
        assert call_args["hostname"] == "www.example.com"
        assert call_args["source"] == "dns_enum"

    def test_add_target_no_framework(self, mock_framework):
        """Test adding target without framework."""
        module = DNSModule(None)

        # Should not raise
        module._add_target("192.168.1.100", "www.example.com")

    def test_add_target_exception_handled(self, dns_module, mock_framework):
        """Test exception is handled silently."""
        mock_framework.session.targets.add.side_effect = Exception("Add failed")

        # Should not raise
        dns_module._add_target("192.168.1.100", "www.example.com")


# =============================================================================
# Parse Output and Run Tests
# =============================================================================

class TestParseOutput:
    """Tests for parse_output method."""

    def test_parse_output(self, dns_module):
        """Test parse_output method."""
        output = "example.com.    3600    IN    A    192.168.1.1"

        result = dns_module.parse_output(output)

        assert "records" in result
        assert "raw" in result
        assert result["raw"] == output

    def test_parse_output_empty(self, dns_module):
        """Test parse_output with empty string."""
        result = dns_module.parse_output("")

        assert result["records"] == []
        assert result["raw"] == ""


class TestRun:
    """Tests for run method."""

    def test_run_calls_zone_transfer(self, dns_module):
        """Test run method calls zone_transfer."""
        dns_module.op_zone_transfer = MagicMock(return_value={"success": True})

        result = dns_module.run()

        dns_module.op_zone_transfer.assert_called_once()
        assert result["success"] is True


# =============================================================================
# Edge Cases Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_malformed_record_line(self, dns_module):
        """Test handling malformed record lines."""
        output = """
valid.example.com.    3600    IN    A    192.168.1.1
too short
abc
"""
        result = dns_module._parse_records(output)

        # Only lines with 5+ parts should be parsed
        assert len(result) == 1
        assert result[0]["name"] == "valid.example.com"

    def test_record_with_multiple_values(self, dns_module):
        """Test record with space-separated values."""
        output = "example.com.    3600    IN    MX    10 mail.example.com."

        result = dns_module._parse_records(output)

        assert result[0]["value"] == "10 mail.example.com"

    def test_zone_transfer_with_nameserver_set(self, dns_module):
        """Test zone transfer with explicit nameserver."""
        dns_module.options["DOMAIN"]["value"] = "example.com"
        dns_module.options["NAMESERVER"]["value"] = "ns1.example.com"

        dns_module.execute_command = MagicMock(return_value={
            "success": True,
            "output": ""
        })

        dns_module.op_zone_transfer()

        # Should use provided nameserver without NS lookup
        calls = dns_module.execute_command.call_args_list
        assert len(calls) == 1
        assert "AXFR" in calls[0][0][0]
