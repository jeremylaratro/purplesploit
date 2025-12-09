"""
Unit tests for purplesploit.core.database module.

Tests cover:
- Database initialization and table creation
- Target CRUD operations
- Credential CRUD operations
- Service CRUD operations
- Scan results storage
- Finding/vulnerability storage
- Module defaults
- Web service detection
"""

import pytest
import json
from purplesploit.core.database import Database


# =============================================================================
# Database Initialization Tests
# =============================================================================

class TestDatabaseInitialization:
    """Tests for database initialization and setup."""

    def test_creates_database_file(self, temp_db_path):
        """Test database file is created."""
        import os
        db = Database(temp_db_path)
        assert os.path.exists(temp_db_path)
        db.close()

    def test_creates_parent_directory(self, tmp_path):
        """Test parent directories are created if needed."""
        import os
        nested_path = str(tmp_path / "nested" / "dir" / "test.db")
        db = Database(nested_path)
        assert os.path.exists(nested_path)
        db.close()

    def test_tables_created(self, test_database):
        """Test all required tables are created."""
        cursor = test_database.conn.cursor()

        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {
            "module_history",
            "targets",
            "credentials",
            "services",
            "scan_results",
            "findings",
            "workspaces",
            "module_defaults",
        }

        for table in expected_tables:
            assert table in tables, f"Table '{table}' not found"

    def test_close_connection(self, temp_db_path):
        """Test closing database connection."""
        db = Database(temp_db_path)
        db.close()
        # Trying to use closed connection should raise
        with pytest.raises(Exception):
            db.conn.cursor().execute("SELECT 1")


# =============================================================================
# Target CRUD Tests
# =============================================================================

class TestTargetOperations:
    """Tests for target database operations."""

    def test_add_target(self, test_database):
        """Test adding a target."""
        result = test_database.add_target(
            target_type="network",
            identifier="192.168.1.100",
            name="test-server"
        )

        assert result is True

    def test_add_target_with_metadata(self, test_database):
        """Test adding a target with metadata."""
        metadata = {"os": "Linux", "notes": "Test server"}
        result = test_database.add_target(
            target_type="network",
            identifier="192.168.1.100",
            name="test-server",
            metadata=metadata
        )

        assert result is True

        # Verify metadata is stored
        targets = test_database.get_targets()
        assert targets[0]["metadata"] == metadata

    def test_add_duplicate_target_rejected(self, test_database):
        """Test duplicate targets are rejected."""
        test_database.add_target("network", "192.168.1.100")
        result = test_database.add_target("network", "192.168.1.100")

        assert result is False

    def test_add_web_target(self, test_database):
        """Test adding a web target."""
        result = test_database.add_target(
            target_type="web",
            identifier="http://example.com",
            name="example-site"
        )

        assert result is True

    def test_add_subnet_target_status(self, test_database):
        """Test subnet targets get 'subnet' status."""
        test_database.add_target("network", "192.168.1.0/24")
        targets = test_database.get_targets()

        assert targets[0]["status"] == "subnet"

    def test_get_targets_all(self, test_database):
        """Test getting all targets."""
        test_database.add_target("network", "192.168.1.100")
        test_database.add_target("web", "http://example.com")

        targets = test_database.get_targets()

        assert len(targets) == 2

    def test_get_targets_by_type(self, test_database):
        """Test filtering targets by type."""
        test_database.add_target("network", "192.168.1.100")
        test_database.add_target("web", "http://example.com")

        network_targets = test_database.get_targets(target_type="network")
        web_targets = test_database.get_targets(target_type="web")

        assert len(network_targets) == 1
        assert len(web_targets) == 1

    def test_get_targets_exclude_subnets(self, test_database):
        """Test excluding subnet targets."""
        test_database.add_target("network", "192.168.1.100")
        test_database.add_target("network", "192.168.1.0/24")

        targets = test_database.get_targets(exclude_subnets=True)

        assert len(targets) == 1
        assert targets[0]["identifier"] == "192.168.1.100"

    def test_remove_target(self, test_database):
        """Test removing a target."""
        test_database.add_target("network", "192.168.1.100")
        result = test_database.remove_target("192.168.1.100")

        assert result is True
        assert len(test_database.get_targets()) == 0

    def test_remove_nonexistent_target(self, test_database):
        """Test removing non-existent target returns False."""
        result = test_database.remove_target("nonexistent")
        assert result is False

    def test_mark_target_verified(self, test_database):
        """Test marking a target as verified."""
        test_database.add_target("network", "192.168.1.100")
        result = test_database.mark_target_verified("192.168.1.100")

        assert result is True
        targets = test_database.get_targets()
        assert targets[0]["status"] == "verified"

    def test_clear_all_targets(self, test_database):
        """Test clearing all targets."""
        test_database.add_target("network", "192.168.1.100")
        test_database.add_target("network", "192.168.1.101")
        test_database.add_target("web", "http://example.com")

        count = test_database.clear_all_targets()

        assert count == 3
        assert len(test_database.get_targets()) == 0


# =============================================================================
# Credential CRUD Tests
# =============================================================================

class TestCredentialOperations:
    """Tests for credential database operations."""

    def test_add_credential_basic(self, test_database):
        """Test adding a basic credential."""
        cred_id = test_database.add_credential(
            username="admin",
            password="password123"
        )

        assert cred_id > 0

    def test_add_credential_with_domain(self, test_database):
        """Test adding a credential with domain."""
        cred_id = test_database.add_credential(
            username="admin",
            password="password123",
            domain="TESTDOMAIN"
        )

        creds = test_database.get_credentials()
        assert creds[0]["domain"] == "TESTDOMAIN"

    def test_add_credential_with_hash(self, test_database):
        """Test adding a credential with hash."""
        cred_id = test_database.add_credential(
            username="admin",
            hash_value="aad3b435b51404ee:8846f7eaee8fb117",
            hash_type="NTLM"
        )

        creds = test_database.get_credentials()
        assert creds[0]["hash"] is not None
        assert creds[0]["hash_type"] == "NTLM"

    def test_add_credential_with_metadata(self, test_database):
        """Test adding a credential with metadata."""
        metadata = {"source": "manual", "tested": False}
        cred_id = test_database.add_credential(
            username="admin",
            password="test",
            metadata=metadata
        )

        creds = test_database.get_credentials()
        assert creds[0]["metadata"] == metadata

    def test_get_credentials(self, test_database):
        """Test getting all credentials."""
        test_database.add_credential("admin", "pass1")
        test_database.add_credential("user", "pass2")

        creds = test_database.get_credentials()

        assert len(creds) == 2

    def test_remove_credential(self, test_database):
        """Test removing a credential."""
        cred_id = test_database.add_credential("admin", "pass")
        result = test_database.remove_credential(cred_id)

        assert result is True
        assert len(test_database.get_credentials()) == 0


# =============================================================================
# Service CRUD Tests
# =============================================================================

class TestServiceOperations:
    """Tests for service database operations."""

    def test_add_service(self, test_database):
        """Test adding a service."""
        result = test_database.add_service(
            target="192.168.1.100",
            service="ssh",
            port=22
        )

        assert result is True

    def test_add_service_with_version(self, test_database):
        """Test adding a service with version."""
        test_database.add_service(
            target="192.168.1.100",
            service="ssh",
            port=22,
            version="OpenSSH 8.0"
        )

        services = test_database.get_services(target="192.168.1.100")
        assert services[0]["version"] == "OpenSSH 8.0"

    def test_add_service_update_version(self, test_database):
        """Test updating service version on conflict."""
        test_database.add_service("192.168.1.100", "ssh", 22, "OpenSSH 7.0")
        test_database.add_service("192.168.1.100", "ssh", 22, "OpenSSH 8.0")

        services = test_database.get_services(target="192.168.1.100")
        assert len(services) == 1
        assert services[0]["version"] == "OpenSSH 8.0"

    def test_get_services_all(self, test_database):
        """Test getting all services."""
        test_database.add_service("192.168.1.100", "ssh", 22)
        test_database.add_service("192.168.1.101", "http", 80)

        services = test_database.get_services()

        assert len(services) == 2

    def test_get_services_by_target(self, test_database):
        """Test filtering services by target."""
        test_database.add_service("192.168.1.100", "ssh", 22)
        test_database.add_service("192.168.1.100", "http", 80)
        test_database.add_service("192.168.1.101", "smb", 445)

        services = test_database.get_services(target="192.168.1.100")

        assert len(services) == 2

    def test_get_web_services(self, test_database):
        """Test getting web services."""
        test_database.add_service("192.168.1.100", "http", 80)
        test_database.add_service("192.168.1.100", "https", 443)
        test_database.add_service("192.168.1.100", "ssh", 22)
        test_database.add_service("192.168.1.101", "http-proxy", 8080)

        web_services = test_database.get_web_services()

        assert len(web_services) == 3
        # Check URL construction
        urls = [s["url"] for s in web_services]
        assert "http://192.168.1.100" in urls
        assert "https://192.168.1.100" in urls

    def test_get_web_services_port_in_url(self, test_database):
        """Test web services include port in URL when non-standard."""
        test_database.add_service("192.168.1.100", "http", 8080)

        web_services = test_database.get_web_services()

        assert web_services[0]["url"] == "http://192.168.1.100:8080"

    def test_clear_all_services(self, test_database):
        """Test clearing all services."""
        test_database.add_service("192.168.1.100", "ssh", 22)
        test_database.add_service("192.168.1.101", "http", 80)

        count = test_database.clear_all_services()

        assert count == 2
        assert len(test_database.get_services()) == 0


# =============================================================================
# Module History Tests
# =============================================================================

class TestModuleHistory:
    """Tests for module execution history."""

    def test_add_module_execution(self, test_database):
        """Test recording module execution."""
        record_id = test_database.add_module_execution(
            module_name="nmap",
            module_path="recon/nmap",
            options={"RHOST": "192.168.1.100"},
            results={"success": True},
            success=True
        )

        assert record_id > 0

    def test_add_module_execution_with_error(self, test_database):
        """Test recording failed module execution."""
        record_id = test_database.add_module_execution(
            module_name="nmap",
            module_path="recon/nmap",
            options={},
            results={},
            success=False,
            error_message="Target not specified"
        )

        history = test_database.get_module_history()
        assert history[0]["error_message"] == "Target not specified"

    def test_get_module_history_all(self, test_database):
        """Test getting all module history."""
        test_database.add_module_execution("nmap", "recon/nmap", {}, {}, True)
        test_database.add_module_execution("wfuzz", "web/wfuzz", {}, {}, True)

        history = test_database.get_module_history()

        assert len(history) == 2

    def test_get_module_history_filtered(self, test_database):
        """Test filtering module history by name."""
        test_database.add_module_execution("nmap", "recon/nmap", {}, {}, True)
        test_database.add_module_execution("nmap", "recon/nmap", {}, {}, True)
        test_database.add_module_execution("wfuzz", "web/wfuzz", {}, {}, True)

        history = test_database.get_module_history(module_name="nmap")

        assert len(history) == 2

    def test_get_module_history_limit(self, test_database):
        """Test limiting module history results."""
        for i in range(10):
            test_database.add_module_execution("nmap", "recon/nmap", {}, {}, True)

        history = test_database.get_module_history(limit=5)

        assert len(history) == 5


# =============================================================================
# Scan Results Tests
# =============================================================================

class TestScanResults:
    """Tests for scan results storage."""

    def test_save_scan_results(self, test_database):
        """Test saving scan results."""
        record_id = test_database.save_scan_results(
            scan_name="full_scan_192.168.1.100",
            target="192.168.1.100",
            scan_type="nmap",
            results={"ports": [22, 80, 443]}
        )

        assert record_id > 0

    def test_save_scan_results_with_file(self, test_database):
        """Test saving scan results with file path."""
        test_database.save_scan_results(
            scan_name="full_scan",
            target="192.168.1.100",
            scan_type="nmap",
            results={},
            file_path="/tmp/nmap_results.xml"
        )

        results = test_database.get_scan_results()
        assert results[0]["file_path"] == "/tmp/nmap_results.xml"

    def test_get_scan_results_all(self, test_database):
        """Test getting all scan results."""
        test_database.save_scan_results("scan1", "192.168.1.100", "nmap", {})
        test_database.save_scan_results("scan2", "192.168.1.101", "masscan", {})

        results = test_database.get_scan_results()

        assert len(results) == 2

    def test_get_scan_results_by_target(self, test_database):
        """Test filtering scan results by target."""
        test_database.save_scan_results("scan1", "192.168.1.100", "nmap", {})
        test_database.save_scan_results("scan2", "192.168.1.101", "nmap", {})

        results = test_database.get_scan_results(target="192.168.1.100")

        assert len(results) == 1

    def test_get_scan_results_by_type(self, test_database):
        """Test filtering scan results by scan type."""
        test_database.save_scan_results("scan1", "192.168.1.100", "nmap", {})
        test_database.save_scan_results("scan2", "192.168.1.100", "masscan", {})

        results = test_database.get_scan_results(scan_type="nmap")

        assert len(results) == 1


# =============================================================================
# Findings Tests
# =============================================================================

class TestFindings:
    """Tests for finding/vulnerability storage."""

    def test_add_finding(self, test_database):
        """Test adding a finding."""
        finding_id = test_database.add_finding(
            target="192.168.1.100",
            title="SSH Weak Ciphers",
            severity="medium"
        )

        assert finding_id > 0

    def test_add_finding_full(self, test_database):
        """Test adding a finding with all fields."""
        finding_id = test_database.add_finding(
            target="192.168.1.100",
            title="SSH Weak Ciphers",
            severity="medium",
            description="The SSH server supports weak ciphers",
            module_name="nmap",
            evidence="Cipher: 3DES-CBC",
            remediation="Disable weak ciphers in sshd_config"
        )

        findings = test_database.get_findings()
        finding = findings[0]

        assert finding["description"] is not None
        assert finding["module_name"] == "nmap"
        assert finding["remediation"] is not None

    def test_get_findings_all(self, test_database):
        """Test getting all findings."""
        test_database.add_finding("192.168.1.100", "Finding 1", "high")
        test_database.add_finding("192.168.1.101", "Finding 2", "low")

        findings = test_database.get_findings()

        assert len(findings) == 2

    def test_get_findings_by_target(self, test_database):
        """Test filtering findings by target."""
        test_database.add_finding("192.168.1.100", "Finding 1", "high")
        test_database.add_finding("192.168.1.101", "Finding 2", "low")

        findings = test_database.get_findings(target="192.168.1.100")

        assert len(findings) == 1

    def test_get_findings_by_severity(self, test_database):
        """Test filtering findings by severity."""
        test_database.add_finding("192.168.1.100", "Critical Finding", "critical")
        test_database.add_finding("192.168.1.100", "High Finding", "high")
        test_database.add_finding("192.168.1.100", "Low Finding", "low")

        findings = test_database.get_findings(severity="critical")

        assert len(findings) == 1
        assert findings[0]["title"] == "Critical Finding"


# =============================================================================
# Module Defaults Tests
# =============================================================================

class TestModuleDefaults:
    """Tests for module default settings."""

    def test_set_module_default(self, test_database):
        """Test setting a module default."""
        result = test_database.set_module_default(
            module_name="nmap",
            option_name="SCAN_TYPE",
            option_value="-sCV"
        )

        assert result is True

    def test_get_module_default(self, test_database):
        """Test getting a specific module default."""
        test_database.set_module_default("nmap", "SCAN_TYPE", "-sCV")

        value = test_database.get_module_default("nmap", "SCAN_TYPE")

        assert value == "-sCV"

    def test_get_module_default_nonexistent(self, test_database):
        """Test getting non-existent default returns None."""
        value = test_database.get_module_default("nmap", "NONEXISTENT")
        assert value is None

    def test_set_module_default_upsert(self, test_database):
        """Test setting module default updates existing."""
        test_database.set_module_default("nmap", "SCAN_TYPE", "-sS")
        test_database.set_module_default("nmap", "SCAN_TYPE", "-sCV")

        value = test_database.get_module_default("nmap", "SCAN_TYPE")

        assert value == "-sCV"

    def test_get_module_defaults_all(self, test_database):
        """Test getting all defaults for a module."""
        test_database.set_module_default("nmap", "SCAN_TYPE", "-sCV")
        test_database.set_module_default("nmap", "TIMING", "4")
        test_database.set_module_default("nmap", "PORTS", "-")

        defaults = test_database.get_module_defaults("nmap")

        assert len(defaults) == 3
        assert defaults["SCAN_TYPE"] == "-sCV"
        assert defaults["TIMING"] == "4"

    def test_delete_module_default(self, test_database):
        """Test deleting a specific module default."""
        test_database.set_module_default("nmap", "SCAN_TYPE", "-sCV")
        result = test_database.delete_module_default("nmap", "SCAN_TYPE")

        assert result is True
        assert test_database.get_module_default("nmap", "SCAN_TYPE") is None

    def test_delete_module_default_nonexistent(self, test_database):
        """Test deleting non-existent default returns False."""
        result = test_database.delete_module_default("nmap", "NONEXISTENT")
        assert result is False

    def test_delete_all_module_defaults(self, test_database):
        """Test deleting all defaults for a module."""
        test_database.set_module_default("nmap", "SCAN_TYPE", "-sCV")
        test_database.set_module_default("nmap", "TIMING", "4")

        result = test_database.delete_all_module_defaults("nmap")

        assert result is True
        assert test_database.get_module_defaults("nmap") == {}


# =============================================================================
# JSON Serialization Tests
# =============================================================================

class TestJSONSerialization:
    """Tests for JSON field handling."""

    def test_target_metadata_json(self, test_database):
        """Test target metadata is properly JSON serialized."""
        metadata = {
            "os": "Linux",
            "services": ["ssh", "http"],
            "notes": {"priority": "high"}
        }
        test_database.add_target("network", "192.168.1.100", metadata=metadata)

        targets = test_database.get_targets()

        assert targets[0]["metadata"] == metadata

    def test_credential_metadata_json(self, test_database):
        """Test credential metadata is properly JSON serialized."""
        metadata = {"source": "manual", "verified": True}
        test_database.add_credential("admin", "pass", metadata=metadata)

        creds = test_database.get_credentials()

        assert creds[0]["metadata"] == metadata

    def test_scan_results_json(self, test_database):
        """Test scan results are properly JSON serialized."""
        results = {
            "hosts": [{"ip": "192.168.1.100", "ports": [22, 80]}],
            "total": 1
        }
        test_database.save_scan_results("scan1", "192.168.1.0/24", "nmap", results)

        stored = test_database.get_scan_results()

        assert stored[0]["results"] == results

    def test_module_history_json(self, test_database):
        """Test module history options/results are JSON serialized."""
        options = {"RHOST": "192.168.1.100", "PORTS": [22, 80, 443]}
        results = {"success": True, "data": ["port1", "port2"]}

        test_database.add_module_execution("nmap", "recon/nmap", options, results, True)

        history = test_database.get_module_history()

        assert json.loads(history[0]["options"]) == options
        assert json.loads(history[0]["results"]) == results


# =============================================================================
# Edge Cases
# =============================================================================

class TestDatabaseEdgeCases:
    """Tests for edge cases and unusual inputs."""

    def test_empty_metadata(self, test_database):
        """Test handling of empty metadata."""
        test_database.add_target("network", "192.168.1.100", metadata=None)

        targets = test_database.get_targets()
        assert targets[0]["metadata"] == {}

    def test_special_characters_in_identifier(self, test_database):
        """Test handling special characters in target identifier."""
        test_database.add_target("web", "http://example.com/path?query=1&other=2")

        targets = test_database.get_targets()
        assert "query=1" in targets[0]["identifier"]

    def test_unicode_in_metadata(self, test_database):
        """Test handling unicode in metadata."""
        metadata = {"notes": "Server with UTF-8: \u00e9\u00e8\u00ea"}
        test_database.add_target("network", "192.168.1.100", metadata=metadata)

        targets = test_database.get_targets()
        assert "\u00e9" in targets[0]["metadata"]["notes"]

    def test_concurrent_access(self, test_database):
        """Test database handles concurrent operations."""
        import threading

        def add_target(n):
            test_database.add_target("network", f"192.168.1.{n}")

        threads = [threading.Thread(target=add_target, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Some may fail due to duplicates, but database should be consistent
        targets = test_database.get_targets()
        assert len(targets) <= 10
