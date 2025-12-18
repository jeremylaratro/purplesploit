"""
Unit tests for core database layer.

Tests cover:
- Database initialization and table creation
- Target CRUD operations
- Credential CRUD operations
- Service CRUD operations
- Module history tracking
- Thread safety
- Migration handling
"""

import pytest
import sqlite3
import json
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def database(tmp_path):
    """Create a test database."""
    from purplesploit.core.database import Database
    db_path = str(tmp_path / "test.db")
    db = Database(db_path)
    yield db
    db.close()


@pytest.fixture
def database_with_data(database):
    """Create a database with sample data."""
    # Add targets
    database.add_target("network", "192.168.1.1", "Server1")
    database.add_target("network", "192.168.1.2", "Server2")
    database.add_target("web", "http://example.com", "WebApp1")

    # Add credentials
    database.add_credential("admin", "password123", "DOMAIN")
    database.add_credential("user", None, "DOMAIN", "aad3b435b51404ee:hash", "NTLM")

    # Add services
    database.add_service("192.168.1.1", "ssh", 22, "OpenSSH 8.2")
    database.add_service("192.168.1.1", "http", 80, "Apache 2.4")
    database.add_service("192.168.1.2", "smb", 445)

    return database


# =============================================================================
# Initialization Tests
# =============================================================================

class TestDatabaseInitialization:
    """Tests for database initialization."""

    def test_create_database(self, tmp_path):
        """Test database creation."""
        from purplesploit.core.database import Database
        db_path = str(tmp_path / "new.db")
        db = Database(db_path)

        assert Path(db_path).exists()
        db.close()

    def test_create_nested_directory(self, tmp_path):
        """Test database creation with nested directories."""
        from purplesploit.core.database import Database
        db_path = str(tmp_path / "nested" / "path" / "test.db")
        db = Database(db_path)

        assert Path(db_path).exists()
        db.close()

    def test_tables_created(self, database):
        """Test all required tables are created."""
        cursor = database.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        required_tables = {
            'module_history', 'targets', 'credentials',
            'services', 'scan_results', 'findings',
            'workspaces', 'module_defaults'
        }
        assert required_tables.issubset(tables)

    def test_wal_mode_enabled(self, database):
        """Test WAL journal mode is enabled."""
        cursor = database.conn.cursor()
        cursor.execute("PRAGMA journal_mode")
        mode = cursor.fetchone()[0]
        assert mode.lower() == 'wal'


# =============================================================================
# Target CRUD Tests
# =============================================================================

class TestTargetOperations:
    """Tests for target CRUD operations."""

    def test_add_target(self, database):
        """Test adding a target."""
        result = database.add_target("network", "192.168.1.1", "Server1")
        assert result is True

    def test_add_duplicate_target(self, database):
        """Test adding duplicate target returns False."""
        database.add_target("network", "192.168.1.1", "Server1")
        result = database.add_target("network", "192.168.1.1", "Different Name")
        assert result is False

    def test_add_target_with_metadata(self, database):
        """Test adding target with metadata."""
        metadata = {"os": "Linux", "ports": [22, 80]}
        database.add_target("network", "192.168.1.1", metadata=metadata)

        targets = database.get_targets()
        assert len(targets) == 1
        assert targets[0]['metadata'] == metadata

    def test_add_subnet_target(self, database):
        """Test adding subnet target sets correct status."""
        database.add_target("network", "192.168.1.0/24", "Subnet")

        targets = database.get_targets()
        assert targets[0]['status'] == 'subnet'

    def test_get_targets_all(self, database_with_data):
        """Test getting all targets."""
        targets = database_with_data.get_targets()
        assert len(targets) == 3

    def test_get_targets_by_type(self, database_with_data):
        """Test getting targets by type."""
        network_targets = database_with_data.get_targets(target_type="network")
        assert len(network_targets) == 2

        web_targets = database_with_data.get_targets(target_type="web")
        assert len(web_targets) == 1

    def test_get_targets_exclude_subnets(self, database):
        """Test excluding subnets from results."""
        database.add_target("network", "192.168.1.1", "Host")
        database.add_target("network", "192.168.1.0/24", "Subnet")

        targets = database.get_targets(exclude_subnets=True)
        assert len(targets) == 1
        assert targets[0]['identifier'] == "192.168.1.1"

    def test_remove_target(self, database_with_data):
        """Test removing a target."""
        result = database_with_data.remove_target("192.168.1.1")
        assert result is True

        targets = database_with_data.get_targets()
        identifiers = [t['identifier'] for t in targets]
        assert "192.168.1.1" not in identifiers

    def test_remove_nonexistent_target(self, database):
        """Test removing nonexistent target."""
        result = database.remove_target("nonexistent")
        assert result is False

    def test_mark_target_verified(self, database):
        """Test marking target as verified."""
        database.add_target("network", "192.168.1.1")
        result = database.mark_target_verified("192.168.1.1")

        assert result is True
        targets = database.get_targets()
        assert targets[0]['status'] == 'verified'

    def test_clear_all_targets(self, database_with_data):
        """Test clearing all targets."""
        count = database_with_data.clear_all_targets()

        assert count == 3
        assert len(database_with_data.get_targets()) == 0


# =============================================================================
# Credential CRUD Tests
# =============================================================================

class TestCredentialOperations:
    """Tests for credential CRUD operations."""

    def test_add_credential_with_password(self, database):
        """Test adding credential with password."""
        cred_id = database.add_credential("admin", "password123", "DOMAIN")
        assert cred_id > 0

    def test_add_credential_with_hash(self, database):
        """Test adding credential with hash."""
        cred_id = database.add_credential(
            "admin", None, "DOMAIN",
            hash_value="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM"
        )
        assert cred_id > 0

    def test_add_credential_with_metadata(self, database):
        """Test adding credential with metadata."""
        metadata = {"source": "secretsdump", "verified": True}
        cred_id = database.add_credential("admin", "pass", metadata=metadata)

        creds = database.get_credentials()
        assert len(creds) == 1
        assert creds[0]['metadata'] == metadata

    def test_get_credentials(self, database_with_data):
        """Test getting all credentials."""
        creds = database_with_data.get_credentials()
        assert len(creds) == 2

    def test_get_credentials_empty(self, database):
        """Test getting credentials from empty database."""
        creds = database.get_credentials()
        assert creds == []

    def test_remove_credential(self, database):
        """Test removing a credential."""
        cred_id = database.add_credential("admin", "password")
        result = database.remove_credential(cred_id)

        assert result is True
        assert len(database.get_credentials()) == 0

    def test_remove_nonexistent_credential(self, database):
        """Test removing nonexistent credential."""
        result = database.remove_credential(999)
        assert result is False


# =============================================================================
# Service CRUD Tests
# =============================================================================

class TestServiceOperations:
    """Tests for service CRUD operations."""

    def test_add_service(self, database):
        """Test adding a service."""
        result = database.add_service("192.168.1.1", "ssh", 22, "OpenSSH 8.2")
        assert result is True

    def test_add_service_without_version(self, database):
        """Test adding service without version."""
        result = database.add_service("192.168.1.1", "unknown", 12345)
        assert result is True

    def test_add_duplicate_service_updates_version(self, database):
        """Test adding duplicate service updates version."""
        database.add_service("192.168.1.1", "ssh", 22, "OpenSSH 7.9")
        database.add_service("192.168.1.1", "ssh", 22, "OpenSSH 8.2")

        services = database.get_services("192.168.1.1")
        assert len(services) == 1
        assert services[0]['version'] == "OpenSSH 8.2"

    def test_get_services_all(self, database_with_data):
        """Test getting all services."""
        services = database_with_data.get_services()
        assert len(services) == 3

    def test_get_services_by_target(self, database_with_data):
        """Test getting services by target."""
        services = database_with_data.get_services("192.168.1.1")
        assert len(services) == 2

    def test_get_services_empty(self, database):
        """Test getting services from empty database."""
        services = database.get_services()
        assert services == []

    def test_get_web_services(self, database):
        """Test getting web services."""
        database.add_service("192.168.1.1", "http", 80)
        database.add_service("192.168.1.1", "https", 443)
        database.add_service("192.168.1.1", "ssh", 22)
        database.add_service("192.168.1.2", "http-alt", 8080)

        web_services = database.get_web_services()
        # Should include http (80), https (443), and http-alt (8080)
        assert len(web_services) >= 3


# =============================================================================
# Module History Tests
# =============================================================================

class TestModuleHistory:
    """Tests for module execution history."""

    def test_add_module_execution(self, database):
        """Test recording module execution."""
        exec_id = database.add_module_execution(
            module_name="test_module",
            module_path="test/module",
            options={"RHOST": "192.168.1.1"},
            results={"success": True, "data": "test"},
            success=True
        )
        assert exec_id > 0

    def test_add_failed_module_execution(self, database):
        """Test recording failed module execution."""
        exec_id = database.add_module_execution(
            module_name="test_module",
            module_path="test/module",
            options={"RHOST": "192.168.1.1"},
            results={},
            success=False,
            error_message="Connection refused"
        )
        assert exec_id > 0

    def test_get_module_history(self, database):
        """Test getting module history."""
        database.add_module_execution("mod1", "path/mod1", {}, {}, True)
        database.add_module_execution("mod2", "path/mod2", {}, {}, True)

        history = database.get_module_history()
        assert len(history) == 2

    def test_get_module_history_by_name(self, database):
        """Test filtering history by module name."""
        database.add_module_execution("mod1", "path/mod1", {}, {}, True)
        database.add_module_execution("mod1", "path/mod1", {}, {}, True)
        database.add_module_execution("mod2", "path/mod2", {}, {}, True)

        history = database.get_module_history(module_name="mod1")
        assert len(history) == 2

    def test_get_module_history_limit(self, database):
        """Test history limit."""
        for i in range(50):
            database.add_module_execution(f"mod{i}", f"path/mod{i}", {}, {}, True)

        history = database.get_module_history(limit=10)
        assert len(history) == 10


# =============================================================================
# Thread Safety Tests
# =============================================================================

class TestThreadSafety:
    """Tests for thread-safe database operations."""

    def test_concurrent_writes(self, database):
        """Test concurrent write operations."""
        errors = []

        def add_targets(start):
            try:
                for i in range(10):
                    database.add_target("network", f"192.168.{start}.{i}")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=add_targets, args=(i,))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Should have 50 unique targets
        targets = database.get_targets()
        assert len(targets) == 50

    def test_concurrent_reads_and_writes(self, database):
        """Test concurrent read and write operations."""
        # Pre-populate some data
        for i in range(10):
            database.add_target("network", f"10.0.0.{i}")

        errors = []
        read_counts = []

        def write_targets():
            try:
                for i in range(10):
                    database.add_service(f"10.0.0.{i}", "http", 80)
            except Exception as e:
                errors.append(e)

        def read_targets():
            try:
                for _ in range(10):
                    targets = database.get_targets()
                    read_counts.append(len(targets))
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)

        write_thread = threading.Thread(target=write_targets)
        read_threads = [threading.Thread(target=read_targets) for _ in range(3)]

        write_thread.start()
        for t in read_threads:
            t.start()

        write_thread.join()
        for t in read_threads:
            t.join()

        assert len(errors) == 0
        assert all(count >= 0 for count in read_counts)


# =============================================================================
# Close and Cleanup Tests
# =============================================================================

class TestCleanup:
    """Tests for database cleanup operations."""

    def test_close_database(self, tmp_path):
        """Test closing database."""
        from purplesploit.core.database import Database
        db = Database(str(tmp_path / "test.db"))
        db.close()
        # Should not raise exception
        db.close()  # Double close should be safe

    def test_database_unusable_after_close(self, tmp_path):
        """Test database operations after close raise errors."""
        from purplesploit.core.database import Database
        db = Database(str(tmp_path / "test.db"))
        db.close()

        # Operations after close should fail
        with pytest.raises(Exception):
            db.add_target("network", "192.168.1.1")


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_special_characters_in_target(self, database):
        """Test targets with special characters."""
        database.add_target("web", "http://example.com/path?param=value&other=test")
        targets = database.get_targets()
        assert len(targets) == 1
        assert "?" in targets[0]['identifier']

    def test_unicode_in_name(self, database):
        """Test unicode characters in names."""
        database.add_target("network", "192.168.1.1", "サーバー")
        targets = database.get_targets()
        assert targets[0]['name'] == "サーバー"

    def test_sql_injection_prevention(self, database):
        """Test SQL injection is prevented."""
        malicious_input = "'; DROP TABLE targets; --"
        database.add_target("network", malicious_input)

        # Table should still exist and work
        database.add_target("network", "192.168.1.1")
        targets = database.get_targets()
        assert len(targets) == 2

    def test_empty_string_values(self, database):
        """Test handling of empty strings."""
        database.add_target("network", "192.168.1.1", "")
        targets = database.get_targets()
        assert targets[0]['name'] == ""

    def test_very_long_values(self, database):
        """Test handling of very long values."""
        long_name = "A" * 10000
        database.add_target("network", "192.168.1.1", long_name)
        targets = database.get_targets()
        assert len(targets[0]['name']) == 10000

    def test_null_metadata_parsing(self, database):
        """Test parsing null/empty metadata."""
        database.add_target("network", "192.168.1.1")
        targets = database.get_targets()
        assert targets[0]['metadata'] == {}


# =============================================================================
# Migration Tests
# =============================================================================

class TestMigrations:
    """Tests for database migrations."""

    def test_migration_adds_status_column(self, tmp_path):
        """Test migration adds status column to existing database."""
        from purplesploit.core.database import Database

        # Create a minimal database without status column
        db_path = str(tmp_path / "legacy.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY,
                type TEXT,
                identifier TEXT,
                name TEXT,
                metadata TEXT,
                added_at TIMESTAMP
            )
        """)
        conn.execute("""
            INSERT INTO targets (type, identifier, name, metadata)
            VALUES ('network', '192.168.1.1', 'test', '{}')
        """)
        conn.commit()
        conn.close()

        # Open with our Database class - should migrate
        db = Database(db_path)

        # Check status column exists and has default value
        cursor = db.conn.cursor()
        cursor.execute("SELECT status FROM targets WHERE identifier = '192.168.1.1'")
        status = cursor.fetchone()[0]

        assert status == 'unverified'
        db.close()
