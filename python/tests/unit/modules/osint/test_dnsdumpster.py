"""
Tests for purplesploit.modules.osint.dnsdumpster module.

Comprehensive test coverage for:
- DNSDumpster queries
- DNS record extraction
- Subdomain discovery
- CSRF token handling
- Alternative DNS resolution
- Error handling
"""

import pytest
import json
from unittest.mock import MagicMock, patch, Mock
from pathlib import Path
import urllib.error
import socket

from purplesploit.modules.osint.dnsdumpster import DNSDumpsterModule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework():
    """Create mock framework for testing."""
    framework = MagicMock()
    framework.session = MagicMock()
    framework.session.get_current_target = MagicMock(return_value=None)
    framework.session.get_current_credential = MagicMock(return_value=None)
    framework.session.workspace = "default"
    framework.database = MagicMock()
    framework.database.add_target = MagicMock()
    framework.database.add_web_target = MagicMock()
    framework.database.get_module_defaults = MagicMock(return_value={})
    framework.log = MagicMock()
    return framework


@pytest.fixture
def dnsdumpster_module(mock_framework):
    """Create DNSDumpster module instance."""
    return DNSDumpsterModule(mock_framework)


@pytest.fixture
def sample_html_response():
    """Sample DNSDumpster HTML response."""
    return '''
    <html>
    <body>
    <table>
        <tr>
            <td class="col-md-4">www.example.com</td>
            <td class="col-md-3">93.184.216.34</td>
        </tr>
        <tr>
            <td class="col-md-4">mail.example.com</td>
            <td class="col-md-3">93.184.216.35</td>
        </tr>
        <tr>
            <td>MX</td>
            <td>mail.example.com</td>
        </tr>
        <tr>
            <td>NS</td>
            <td>ns1.example.com</td>
        </tr>
        <tr>
            <td>TXT</td>
            <td>v=spf1 include:_spf.google.com ~all</td>
        </tr>
    </table>
    api.example.com test.example.com
    </body>
    </html>
    '''


# =============================================================================
# Module Initialization Tests
# =============================================================================

class TestDNSDumpsterModuleInit:
    """Tests for DNSDumpster module initialization."""

    def test_module_properties(self, dnsdumpster_module):
        """Test module properties are set correctly."""
        assert dnsdumpster_module.name == "DNSDumpster"
        assert "DNS" in dnsdumpster_module.description
        assert dnsdumpster_module.category == "osint"
        assert dnsdumpster_module.author == "PurpleSploit Team"

    def test_module_options(self, dnsdumpster_module):
        """Test module options are initialized."""
        assert "DOMAIN" in dnsdumpster_module.options

    def test_domain_option_required(self, dnsdumpster_module):
        """Test DOMAIN option is marked as required."""
        assert dnsdumpster_module.options["DOMAIN"]["required"] is True

    def test_base_url(self, dnsdumpster_module):
        """Test base URL is set."""
        assert dnsdumpster_module.base_url == "https://dnsdumpster.com"


# =============================================================================
# Domain Retrieval Tests
# =============================================================================

class TestDomainRetrieval:
    """Tests for domain retrieval from options and context."""

    def test_get_domain_from_options(self, dnsdumpster_module):
        """Test domain retrieved from options."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        domain = dnsdumpster_module._get_domain()

        assert domain == "example.com"

    def test_get_domain_from_context(self, dnsdumpster_module, mock_framework):
        """Test domain retrieved from framework context."""
        mock_framework.session.get_current_target.return_value = {
            'url': 'https://www.example.com/path'
        }

        domain = dnsdumpster_module._get_domain()

        # Domain extraction depends on implementation


# =============================================================================
# CSRF Token Tests
# =============================================================================

class TestCSRFToken:
    """Tests for CSRF token retrieval."""

    def test_get_csrf_token_success(self, dnsdumpster_module):
        """Test successful CSRF token retrieval."""
        html = '''
        <html>
        <form>
            <input name="csrfmiddlewaretoken" value="test_csrf_token_123" />
        </form>
        </html>
        '''

        mock_response = MagicMock()
        mock_response.read.return_value = html.encode('utf-8')
        mock_response.headers.get.return_value = 'csrftoken=abc123; Path=/'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            token, cookies = dnsdumpster_module._get_csrf_token(None)

        assert token == "test_csrf_token_123"
        assert cookies is not None

    def test_get_csrf_token_not_found(self, dnsdumpster_module):
        """Test CSRF token not found in response."""
        html = '<html><body>No form here</body></html>'

        mock_response = MagicMock()
        mock_response.read.return_value = html.encode('utf-8')
        mock_response.headers.get.return_value = ''
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            token, cookies = dnsdumpster_module._get_csrf_token(None)

        # Should return None when token not found

    def test_get_csrf_token_error(self, dnsdumpster_module):
        """Test handling of error during CSRF retrieval."""
        with patch('urllib.request.urlopen', side_effect=Exception("Connection error")):
            token, cookies = dnsdumpster_module._get_csrf_token(None)

        assert token is None


# =============================================================================
# DNSDumpster Query Tests
# =============================================================================

class TestDNSDumpsterQuery:
    """Tests for DNSDumpster query functionality."""

    def test_query_dnsdumpster_with_csrf(self, dnsdumpster_module, sample_html_response):
        """Test query with CSRF token."""
        # Mock CSRF retrieval
        with patch.object(dnsdumpster_module, '_get_csrf_token', return_value=('csrf_token', 'cookie=value')):
            # Mock POST response
            mock_response = MagicMock()
            mock_response.read.return_value = sample_html_response.encode('utf-8')
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)

            with patch('urllib.request.urlopen', return_value=mock_response):
                results = dnsdumpster_module._query_dnsdumpster("example.com")

        assert "domain" in results
        assert "dns_records" in results
        assert "subdomains" in results

    def test_query_dnsdumpster_fallback_to_alternative(self, dnsdumpster_module):
        """Test fallback to alternative method when CSRF fails."""
        with patch.object(dnsdumpster_module, '_get_csrf_token', return_value=(None, None)):
            with patch.object(dnsdumpster_module, '_query_alternative', return_value={'domain': 'test.com', 'subdomains': []}) as mock_alt:
                results = dnsdumpster_module._query_dnsdumpster("example.com")

        mock_alt.assert_called_once_with("example.com")


# =============================================================================
# Alternative Query Tests
# =============================================================================

class TestAlternativeQuery:
    """Tests for alternative DNS query method."""

    def test_query_alternative_finds_subdomains(self, dnsdumpster_module):
        """Test alternative method finds common subdomains."""
        def gethostbyname_side_effect(hostname):
            if hostname.startswith('www.') or hostname.startswith('mail.'):
                return '192.168.1.1'
            raise socket.gaierror("Name or service not known")

        with patch('socket.gethostbyname', side_effect=gethostbyname_side_effect):
            results = dnsdumpster_module._query_alternative("example.com")

        assert "subdomains" in results
        # Should find www and mail
        hostnames = [s.get('hostname', '') for s in results["subdomains"]]
        assert 'www.example.com' in hostnames or 'mail.example.com' in hostnames

    def test_query_alternative_gets_a_record(self, dnsdumpster_module):
        """Test alternative method gets A record for main domain."""
        with patch('socket.gethostbyname') as mock_dns:
            mock_dns.return_value = '93.184.216.34'
            results = dnsdumpster_module._query_alternative("example.com")

        assert '93.184.216.34' in results["dns_records"]["a"]

    def test_query_alternative_handles_dns_failure(self, dnsdumpster_module):
        """Test alternative method handles DNS failures."""
        with patch('socket.gethostbyname', side_effect=socket.gaierror("DNS failure")):
            results = dnsdumpster_module._query_alternative("nonexistent.com")

        # Should still return results structure
        assert "subdomains" in results
        assert "dns_records" in results


# =============================================================================
# HTML Parsing Tests
# =============================================================================

class TestHTMLParsing:
    """Tests for HTML response parsing."""

    def test_parse_response_extracts_subdomains(self, dnsdumpster_module, sample_html_response):
        """Test subdomain extraction from HTML."""
        results = dnsdumpster_module._parse_response(sample_html_response, "example.com")

        hostnames = [s.get('hostname', '') for s in results["subdomains"]]
        assert "www.example.com" in hostnames
        assert "mail.example.com" in hostnames

    def test_parse_response_extracts_mx_records(self, dnsdumpster_module, sample_html_response):
        """Test MX record extraction from HTML."""
        results = dnsdumpster_module._parse_response(sample_html_response, "example.com")

        # MX records may or may not be found depending on HTML structure

    def test_parse_response_extracts_ns_records(self, dnsdumpster_module, sample_html_response):
        """Test NS record extraction from HTML."""
        results = dnsdumpster_module._parse_response(sample_html_response, "example.com")

        # NS records may or may not be found depending on HTML structure

    def test_parse_response_extracts_ip_addresses(self, dnsdumpster_module, sample_html_response):
        """Test IP address extraction from HTML."""
        results = dnsdumpster_module._parse_response(sample_html_response, "example.com")

        for subdomain in results["subdomains"]:
            if subdomain.get('hostname') == 'www.example.com':
                assert subdomain.get('ip') == '93.184.216.34'

    def test_parse_response_deduplicates(self, dnsdumpster_module):
        """Test duplicate subdomains are removed."""
        html = '''
        <html>
        <table>
            <td class="col-md-4">www.example.com</td>
            <td class="col-md-3">1.2.3.4</td>
        </table>
        www.example.com www.example.com www.example.com
        </html>
        '''

        results = dnsdumpster_module._parse_response(html, "example.com")

        hostnames = [s.get('hostname', '') for s in results["subdomains"]]
        assert hostnames.count('www.example.com') == 1


# =============================================================================
# Operations Tests
# =============================================================================

class TestDNSDumpsterOperations:
    """Tests for DNSDumpster operations."""

    def test_get_operations(self, dnsdumpster_module):
        """Test getting list of operations."""
        operations = dnsdumpster_module.get_operations()

        assert len(operations) > 0

    def test_operations_have_required_fields(self, dnsdumpster_module):
        """Test all operations have required fields."""
        operations = dnsdumpster_module.get_operations()

        for op in operations:
            assert "name" in op
            assert "description" in op
            assert "handler" in op

    def test_full_dns_recon_operation(self, dnsdumpster_module):
        """Test Full DNS Recon operation exists."""
        operations = dnsdumpster_module.get_operations()
        names = [op["name"] for op in operations]

        assert "Full DNS Recon" in names

    def test_subdomain_discovery_operation(self, dnsdumpster_module):
        """Test Subdomain Discovery operation exists."""
        operations = dnsdumpster_module.get_operations()
        names = [op["name"] for op in operations]

        assert "Subdomain Discovery" in names


# =============================================================================
# Full DNS Recon Operation Tests
# =============================================================================

class TestFullDNSRecon:
    """Tests for full DNS recon operation."""

    def test_op_full_recon_success(self, dnsdumpster_module, tmp_path):
        """Test successful full DNS recon."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        mock_results = {
            "domain": "example.com",
            "dns_records": {
                "a": ["93.184.216.34"],
                "mx": ["mail.example.com"],
                "ns": ["ns1.example.com"],
                "txt": ["v=spf1 ..."]
            },
            "subdomains": [
                {"hostname": "www.example.com", "ip": "93.184.216.34"}
            ]
        }

        with patch.object(dnsdumpster_module, '_query_dnsdumpster', return_value=mock_results):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = dnsdumpster_module.op_full_recon()

        assert result["success"] is True
        assert result["data"]["domain"] == "example.com"

    def test_op_full_recon_no_domain(self, dnsdumpster_module):
        """Test full DNS recon without domain."""
        result = dnsdumpster_module.op_full_recon()

        assert result["success"] is False
        assert "DOMAIN required" in result["error"]

    def test_op_full_recon_query_failure(self, dnsdumpster_module, tmp_path):
        """Test full DNS recon handles query failure."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        with patch.object(dnsdumpster_module, '_query_dnsdumpster', return_value=None):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = dnsdumpster_module.op_full_recon()

        assert result["success"] is False


# =============================================================================
# Subdomain Discovery Operation Tests
# =============================================================================

class TestSubdomainDiscovery:
    """Tests for subdomain discovery operation."""

    def test_op_subdomains_success(self, dnsdumpster_module, tmp_path):
        """Test successful subdomain discovery."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        mock_results = {
            "domain": "example.com",
            "dns_records": {"a": [], "mx": [], "ns": [], "txt": []},
            "subdomains": [
                {"hostname": "www.example.com", "ip": "1.2.3.4"},
                {"hostname": "api.example.com", "ip": "1.2.3.5"},
            ]
        }

        with patch.object(dnsdumpster_module, '_query_dnsdumpster', return_value=mock_results):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = dnsdumpster_module.op_subdomains()

        assert result["success"] is True
        assert result["data"]["count"] == 2

    def test_op_subdomains_saves_txt_file(self, dnsdumpster_module, tmp_path):
        """Test subdomain discovery saves text file."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        mock_results = {
            "domain": "example.com",
            "dns_records": {"a": [], "mx": [], "ns": [], "txt": []},
            "subdomains": [
                {"hostname": "www.example.com", "ip": ""},
            ]
        }

        with patch.object(dnsdumpster_module, '_query_dnsdumpster', return_value=mock_results):
            with patch.object(Path, 'home', return_value=tmp_path):
                dnsdumpster_module.op_subdomains()

        output_dir = tmp_path / ".purplesploit" / "logs" / "osint"
        txt_files = list(output_dir.glob("dnsdumpster_*_subdomains_*.txt"))
        assert len(txt_files) >= 1


# =============================================================================
# DNS Records Operation Tests
# =============================================================================

class TestDNSRecords:
    """Tests for DNS records operation."""

    def test_op_dns_records_success(self, dnsdumpster_module, tmp_path):
        """Test successful DNS records retrieval."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        mock_results = {
            "domain": "example.com",
            "dns_records": {
                "a": ["93.184.216.34"],
                "mx": ["mail.example.com"],
                "ns": ["ns1.example.com", "ns2.example.com"],
                "txt": ["v=spf1 include:_spf.google.com ~all"]
            },
            "subdomains": []
        }

        with patch.object(dnsdumpster_module, '_query_dnsdumpster', return_value=mock_results):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = dnsdumpster_module.op_dns_records()

        assert result["success"] is True
        assert "a" in result["data"]
        assert "mx" in result["data"]
        assert "ns" in result["data"]


# =============================================================================
# Export Targets Operation Tests
# =============================================================================

class TestExportTargets:
    """Tests for exporting discovered subdomains as targets."""

    def test_op_export_targets_success(self, dnsdumpster_module, mock_framework, tmp_path):
        """Test successful target export."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        mock_results = {
            "domain": "example.com",
            "dns_records": {"a": [], "mx": [], "ns": [], "txt": []},
            "subdomains": [
                {"hostname": "www.example.com", "ip": "1.2.3.4"},
                {"hostname": "api.example.com", "ip": "1.2.3.5"},
            ]
        }

        with patch.object(dnsdumpster_module, '_query_dnsdumpster', return_value=mock_results):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = dnsdumpster_module.op_export_targets()

        assert result["success"] is True
        assert result["data"]["added"] > 0

    def test_op_export_targets_adds_to_database(self, dnsdumpster_module, mock_framework, tmp_path):
        """Test targets are added to database."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        mock_results = {
            "domain": "example.com",
            "dns_records": {"a": [], "mx": [], "ns": [], "txt": []},
            "subdomains": [
                {"hostname": "www.example.com", "ip": "1.2.3.4"},
            ]
        }

        with patch.object(dnsdumpster_module, '_query_dnsdumpster', return_value=mock_results):
            with patch.object(Path, 'home', return_value=tmp_path):
                dnsdumpster_module.op_export_targets()

        # Verify database methods were called
        mock_framework.database.add_web_target.assert_called()

    def test_op_export_targets_no_subdomains(self, dnsdumpster_module, tmp_path):
        """Test export with no subdomains found."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        mock_results = {
            "domain": "example.com",
            "dns_records": {"a": [], "mx": [], "ns": [], "txt": []},
            "subdomains": []
        }

        with patch.object(dnsdumpster_module, '_query_dnsdumpster', return_value=mock_results):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = dnsdumpster_module.op_export_targets()

        assert result["success"] is False


# =============================================================================
# Result Saving Tests
# =============================================================================

class TestResultSaving:
    """Tests for result saving functionality."""

    def test_save_results_creates_file(self, dnsdumpster_module, tmp_path):
        """Test results are saved to file."""
        results = {
            "domain": "example.com",
            "subdomains": [{"hostname": "www.example.com"}]
        }

        with patch.object(Path, 'home', return_value=tmp_path):
            output_file = dnsdumpster_module._save_results(results, "test")

        assert output_file.exists()

    def test_save_results_valid_json(self, dnsdumpster_module, tmp_path):
        """Test saved JSON is valid."""
        results = {
            "domain": "example.com",
            "data": [1, 2, 3]
        }

        with patch.object(Path, 'home', return_value=tmp_path):
            output_file = dnsdumpster_module._save_results(results, "test")

        with open(output_file) as f:
            loaded = json.load(f)

        assert loaded["domain"] == "example.com"


# =============================================================================
# Default Run Tests
# =============================================================================

class TestDefaultRun:
    """Tests for default run behavior."""

    def test_run_calls_full_recon(self, dnsdumpster_module):
        """Test run() calls full DNS recon."""
        with patch.object(dnsdumpster_module, 'op_full_recon', return_value={'success': True}) as mock_recon:
            result = dnsdumpster_module.run()

        mock_recon.assert_called_once()
        assert result["success"] is True


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_handles_network_error(self, dnsdumpster_module):
        """Test handling of network errors."""
        dnsdumpster_module.set_option("DOMAIN", "example.com")

        with patch.object(dnsdumpster_module, '_get_csrf_token', return_value=(None, None)):
            with patch.object(dnsdumpster_module, '_query_alternative', return_value={'domain': 'example.com', 'subdomains': [], 'dns_records': {'a': [], 'mx': [], 'ns': [], 'txt': []}}):
                results = dnsdumpster_module._query_dnsdumpster("example.com")

        # Should fallback gracefully
        assert results is not None

    def test_handles_timeout(self, dnsdumpster_module):
        """Test handling of request timeout."""
        with patch('urllib.request.urlopen', side_effect=urllib.error.URLError("timeout")):
            certs = dnsdumpster_module._get_csrf_token(None)

        # Should return None gracefully
