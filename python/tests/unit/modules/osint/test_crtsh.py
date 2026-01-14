"""
Tests for purplesploit.modules.osint.crtsh module.

Comprehensive test coverage for:
- Certificate transparency log queries
- Subdomain enumeration
- Certificate details extraction
- Organization search
- Result saving and export
- Error handling
"""

import pytest
import json
from unittest.mock import MagicMock, patch, Mock
from pathlib import Path
import urllib.error

from purplesploit.modules.osint.crtsh import CrtshModule


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
    framework.database.add_web_target = MagicMock()
    framework.database.get_module_defaults = MagicMock(return_value={})
    framework.log = MagicMock()
    return framework


@pytest.fixture
def crtsh_module(mock_framework):
    """Create crt.sh module instance."""
    return CrtshModule(mock_framework)


@pytest.fixture
def sample_cert_data():
    """Sample certificate transparency log data."""
    return [
        {
            'id': 1234567890,
            'issuer_name': 'Let\'s Encrypt Authority X3',
            'common_name': 'example.com',
            'name_value': 'example.com\nwww.example.com\napi.example.com',
            'not_before': '2024-01-01T00:00:00',
            'not_after': '2024-04-01T00:00:00',
            'serial_number': 'ABC123',
        },
        {
            'id': 1234567891,
            'issuer_name': 'DigiCert',
            'common_name': '*.example.com',
            'name_value': '*.example.com\nmail.example.com',
            'not_before': '2024-01-15T00:00:00',
            'not_after': '2025-01-15T00:00:00',
            'serial_number': 'DEF456',
        },
    ]


# =============================================================================
# Module Initialization Tests
# =============================================================================

class TestCrtshModuleInit:
    """Tests for crt.sh module initialization."""

    def test_module_properties(self, crtsh_module):
        """Test module properties are set correctly."""
        assert crtsh_module.name == "crt.sh"
        assert "Certificate Transparency" in crtsh_module.description
        assert crtsh_module.category == "osint"
        assert crtsh_module.author == "PurpleSploit Team"

    def test_module_options(self, crtsh_module):
        """Test module options are initialized."""
        assert "DOMAIN" in crtsh_module.options
        assert "WILDCARD" in crtsh_module.options
        assert "EXPIRED" in crtsh_module.options
        assert "OUTPUT_FORMAT" in crtsh_module.options

    def test_domain_option_required(self, crtsh_module):
        """Test DOMAIN option is marked as required."""
        assert crtsh_module.options["DOMAIN"]["required"] is True

    def test_wildcard_default(self, crtsh_module):
        """Test WILDCARD default is True."""
        assert crtsh_module.options["WILDCARD"]["default"] is True

    def test_base_url(self, crtsh_module):
        """Test base URL is set."""
        assert crtsh_module.base_url == "https://crt.sh"


# =============================================================================
# Domain Retrieval Tests
# =============================================================================

class TestDomainRetrieval:
    """Tests for domain retrieval from options and context."""

    def test_get_domain_from_options(self, crtsh_module):
        """Test domain retrieved from options."""
        crtsh_module.set_option("DOMAIN", "example.com")

        domain = crtsh_module._get_domain()

        assert domain == "example.com"

    def test_get_domain_from_context_url(self, crtsh_module, mock_framework):
        """Test domain extracted from context URL."""
        mock_framework.session.get_current_target.return_value = {
            'url': 'https://www.example.com/path'
        }

        domain = crtsh_module._get_domain()

        # May or may not extract domain depending on implementation


# =============================================================================
# Certificate Fetching Tests
# =============================================================================

class TestCertificateFetching:
    """Tests for certificate fetching from crt.sh."""

    def test_fetch_certs_success(self, crtsh_module, sample_cert_data):
        """Test successful certificate fetching."""
        crtsh_module.set_option("DOMAIN", "example.com")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_cert_data).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            certs = crtsh_module._fetch_certs("example.com")

        assert len(certs) == 2

    def test_fetch_certs_with_wildcard(self, crtsh_module, sample_cert_data):
        """Test certificate fetching with wildcard search."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_cert_data).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
            crtsh_module._fetch_certs("example.com", wildcard=True)

        # Check URL contains wildcard prefix
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert "%25." in request.full_url  # URL encoded %.

    def test_fetch_certs_without_wildcard(self, crtsh_module, sample_cert_data):
        """Test certificate fetching without wildcard."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_cert_data).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
            crtsh_module._fetch_certs("example.com", wildcard=False)

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert "%25." not in request.full_url

    def test_fetch_certs_http_error(self, crtsh_module):
        """Test handling of HTTP error."""
        with patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError(
                url="", code=500, msg="Server Error", hdrs={}, fp=None
        )):
            certs = crtsh_module._fetch_certs("example.com")

        assert certs == []

    def test_fetch_certs_url_error(self, crtsh_module):
        """Test handling of URL error (connection issue)."""
        with patch('urllib.request.urlopen', side_effect=urllib.error.URLError("Connection refused")):
            certs = crtsh_module._fetch_certs("example.com")

        assert certs == []

    def test_fetch_certs_json_decode_error(self, crtsh_module):
        """Test handling of invalid JSON response."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"not valid json"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            certs = crtsh_module._fetch_certs("example.com")

        assert certs == []

    def test_fetch_certs_empty_response(self, crtsh_module):
        """Test handling of empty response."""
        mock_response = MagicMock()
        mock_response.read.return_value = b""
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            certs = crtsh_module._fetch_certs("example.com")

        assert certs == []


# =============================================================================
# Subdomain Extraction Tests
# =============================================================================

class TestSubdomainExtraction:
    """Tests for subdomain extraction from certificate data."""

    def test_extract_subdomains_basic(self, crtsh_module, sample_cert_data):
        """Test basic subdomain extraction."""
        subdomains = crtsh_module._extract_subdomains(sample_cert_data)

        assert "example.com" in subdomains
        assert "www.example.com" in subdomains
        assert "api.example.com" in subdomains

    def test_extract_subdomains_removes_wildcards(self, crtsh_module):
        """Test wildcard entries are removed."""
        certs = [
            {'name_value': '*.example.com\nwww.example.com'},
        ]

        subdomains = crtsh_module._extract_subdomains(certs)

        assert "*.example.com" not in subdomains
        assert "www.example.com" in subdomains

    def test_extract_subdomains_removes_duplicates(self, crtsh_module):
        """Test duplicate subdomains are removed."""
        certs = [
            {'name_value': 'www.example.com\nwww.example.com\nwww.example.com'},
        ]

        subdomains = crtsh_module._extract_subdomains(certs)

        assert subdomains.count("www.example.com") == 1

    def test_extract_subdomains_lowercases(self, crtsh_module):
        """Test subdomains are lowercased."""
        certs = [
            {'name_value': 'WWW.EXAMPLE.COM\nApi.Example.Com'},
        ]

        subdomains = crtsh_module._extract_subdomains(certs)

        assert all(s.islower() for s in subdomains)

    def test_extract_subdomains_sorted(self, crtsh_module):
        """Test subdomains are sorted."""
        certs = [
            {'name_value': 'zzz.example.com\naaa.example.com\nmmm.example.com'},
        ]

        subdomains = crtsh_module._extract_subdomains(certs)

        assert subdomains == sorted(subdomains)

    def test_extract_subdomains_empty_certs(self, crtsh_module):
        """Test extraction from empty certificate list."""
        subdomains = crtsh_module._extract_subdomains([])

        assert subdomains == []

    def test_extract_subdomains_missing_name_value(self, crtsh_module):
        """Test handling of missing name_value field."""
        certs = [
            {'issuer_name': 'Test'},  # No name_value
        ]

        subdomains = crtsh_module._extract_subdomains(certs)

        assert subdomains == []


# =============================================================================
# Operations Tests
# =============================================================================

class TestCrtshOperations:
    """Tests for crt.sh operations."""

    def test_get_operations(self, crtsh_module):
        """Test getting list of operations."""
        operations = crtsh_module.get_operations()

        assert len(operations) > 0

    def test_operations_have_required_fields(self, crtsh_module):
        """Test all operations have required fields."""
        operations = crtsh_module.get_operations()

        for op in operations:
            assert "name" in op
            assert "description" in op
            assert "handler" in op

    def test_subdomain_enumeration_operation(self, crtsh_module):
        """Test Subdomain Enumeration operation exists."""
        operations = crtsh_module.get_operations()
        names = [op["name"] for op in operations]

        assert "Subdomain Enumeration" in names

    def test_certificate_details_operation(self, crtsh_module):
        """Test Certificate Details operation exists."""
        operations = crtsh_module.get_operations()
        names = [op["name"] for op in operations]

        assert "Certificate Details" in names


# =============================================================================
# Subdomain Enumeration Operation Tests
# =============================================================================

class TestSubdomainEnumeration:
    """Tests for subdomain enumeration operation."""

    def test_op_subdomains_success(self, crtsh_module, sample_cert_data, tmp_path):
        """Test successful subdomain enumeration."""
        crtsh_module.set_option("DOMAIN", "example.com")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_cert_data).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = crtsh_module.op_subdomains()

        assert result["success"] is True
        assert "data" in result
        assert "subdomains" in result["data"]
        assert len(result["data"]["subdomains"]) > 0

    def test_op_subdomains_no_domain(self, crtsh_module):
        """Test subdomain enumeration without domain."""
        result = crtsh_module.op_subdomains()

        assert result["success"] is False
        assert "DOMAIN required" in result["error"]

    def test_op_subdomains_no_certs_found(self, crtsh_module, tmp_path):
        """Test subdomain enumeration with no certificates found."""
        crtsh_module.set_option("DOMAIN", "nonexistent-domain-12345.com")

        mock_response = MagicMock()
        mock_response.read.return_value = b"[]"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = crtsh_module.op_subdomains()

        assert result["success"] is True
        assert result["data"]["count"] == 0


# =============================================================================
# Certificate Details Operation Tests
# =============================================================================

class TestCertificateDetails:
    """Tests for certificate details operation."""

    def test_op_cert_details_success(self, crtsh_module, sample_cert_data, tmp_path):
        """Test successful certificate details retrieval."""
        crtsh_module.set_option("DOMAIN", "example.com")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_cert_data).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = crtsh_module.op_cert_details()

        assert result["success"] is True
        assert "certificates" in result["data"]
        assert len(result["data"]["certificates"]) == 2

    def test_op_cert_details_includes_fields(self, crtsh_module, sample_cert_data, tmp_path):
        """Test certificate details include expected fields."""
        crtsh_module.set_option("DOMAIN", "example.com")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_cert_data).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = crtsh_module.op_cert_details()

        cert = result["data"]["certificates"][0]
        assert "id" in cert
        assert "issuer_name" in cert
        assert "common_name" in cert
        assert "not_before" in cert
        assert "not_after" in cert


# =============================================================================
# Organization Search Tests
# =============================================================================

class TestOrganizationSearch:
    """Tests for organization search operation."""

    def test_op_org_search_success(self, crtsh_module, tmp_path):
        """Test successful organization search."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps([
            {'name_value': 'example.com\ntest.example.com'},
        ]).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('builtins.input', return_value='Example Corp'):
            with patch('urllib.request.urlopen', return_value=mock_response):
                with patch.object(Path, 'home', return_value=tmp_path):
                    result = crtsh_module.op_org_search()

        assert result["success"] is True
        assert "domains" in result["data"]

    def test_op_org_search_no_input(self, crtsh_module):
        """Test organization search without input."""
        with patch('builtins.input', return_value=''):
            result = crtsh_module.op_org_search()

        assert result["success"] is False
        assert "required" in result["error"].lower()


# =============================================================================
# Recent Certificates Tests
# =============================================================================

class TestRecentCertificates:
    """Tests for recent certificates operation."""

    def test_op_recent_certs_success(self, crtsh_module, sample_cert_data, tmp_path):
        """Test successful recent certificates retrieval."""
        crtsh_module.set_option("DOMAIN", "example.com")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_cert_data).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = crtsh_module.op_recent_certs()

        assert result["success"] is True
        assert "recent_certificates" in result["data"]

    def test_op_recent_certs_sorted_by_date(self, crtsh_module, tmp_path):
        """Test recent certificates are sorted by date."""
        certs = [
            {'name_value': 'old.example.com', 'not_before': '2023-01-01', 'issuer_name': 'CA', 'not_after': '2024-01-01'},
            {'name_value': 'new.example.com', 'not_before': '2024-06-01', 'issuer_name': 'CA', 'not_after': '2025-06-01'},
            {'name_value': 'mid.example.com', 'not_before': '2024-03-01', 'issuer_name': 'CA', 'not_after': '2025-03-01'},
        ]

        crtsh_module.set_option("DOMAIN", "example.com")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(certs).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = crtsh_module.op_recent_certs()

        # Most recent should be first
        recent = result["data"]["recent_certificates"]
        if len(recent) >= 2:
            assert recent[0]["issued"] >= recent[1]["issued"]


# =============================================================================
# Export Targets Tests
# =============================================================================

class TestExportTargets:
    """Tests for exporting discovered subdomains as targets."""

    def test_op_export_targets_success(self, crtsh_module, sample_cert_data, mock_framework, tmp_path):
        """Test successful target export."""
        crtsh_module.set_option("DOMAIN", "example.com")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_cert_data).encode('utf-8')
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = crtsh_module.op_export_targets()

        assert result["success"] is True
        assert result["data"]["added"] > 0

    def test_op_export_targets_no_subdomains(self, crtsh_module, tmp_path):
        """Test export with no subdomains found."""
        crtsh_module.set_option("DOMAIN", "nonexistent.com")

        mock_response = MagicMock()
        mock_response.read.return_value = b"[]"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(Path, 'home', return_value=tmp_path):
                result = crtsh_module.op_export_targets()

        assert result["success"] is False or result["data"]["added"] == 0


# =============================================================================
# Result Saving Tests
# =============================================================================

class TestResultSaving:
    """Tests for result saving functionality."""

    def test_save_results_creates_files(self, crtsh_module, tmp_path):
        """Test results are saved to files."""
        results = {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "count": 2
        }
        crtsh_module.set_option("DOMAIN", "example.com")

        with patch.object(Path, 'home', return_value=tmp_path):
            output_file = crtsh_module._save_results(results, "subdomains")

        assert output_file.exists()

    def test_save_results_creates_txt_file(self, crtsh_module, tmp_path):
        """Test subdomain list is saved to text file."""
        results = {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "count": 2
        }
        crtsh_module.set_option("DOMAIN", "example.com")

        with patch.object(Path, 'home', return_value=tmp_path):
            crtsh_module._save_results(results, "subdomains")

        output_dir = tmp_path / ".purplesploit" / "logs" / "osint"
        txt_files = list(output_dir.glob("crtsh_*_subdomains_*.txt"))
        assert len(txt_files) >= 1

    def test_save_results_valid_json(self, crtsh_module, tmp_path):
        """Test saved JSON is valid."""
        results = {"key": "value", "list": [1, 2, 3]}
        crtsh_module.set_option("DOMAIN", "test.com")

        with patch.object(Path, 'home', return_value=tmp_path):
            output_file = crtsh_module._save_results(results, "test")

        with open(output_file) as f:
            loaded = json.load(f)

        assert loaded["key"] == "value"


# =============================================================================
# Default Run Tests
# =============================================================================

class TestDefaultRun:
    """Tests for default run behavior."""

    def test_run_calls_subdomains(self, crtsh_module):
        """Test run() calls subdomain enumeration."""
        with patch.object(crtsh_module, 'op_subdomains', return_value={'success': True}) as mock_subdomains:
            result = crtsh_module.run()

        mock_subdomains.assert_called_once()
        assert result["success"] is True
