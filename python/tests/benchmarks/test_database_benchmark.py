"""
Database Performance Benchmarks

Measures database query performance, indexing, and optimization.
"""

import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def database():
    """Create a test database instance."""
    from purplesploit.core.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        db = Database(db_path=db_path)
        yield db
        db.close()


@pytest.fixture
def populated_database():
    """Create a database with test data."""
    from purplesploit.core.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        db = Database(db_path=db_path)

        # Add test targets
        for i in range(100):
            db.add_target('network', f'192.168.1.{i}', f'target_{i}')

        # Add test credentials
        for i in range(50):
            db.add_credential(f'user_{i}', f'pass_{i}', name=f'cred_{i}')

        # Add test services
        for i in range(100):
            db.add_service(f'192.168.1.{i % 10}', 'http', 80 + (i % 10))
            db.add_service(f'192.168.1.{i % 10}', 'ssh', 22)

        yield db
        db.close()


def test_target_insertion(benchmark, database):
    """Benchmark target insertion."""
    counter = [0]

    def insert_target():
        counter[0] += 1
        return database.add_target('network', f'192.168.1.{counter[0]}', f'target_{counter[0]}')

    result = benchmark(insert_target)
    assert result is True


def test_target_retrieval_all(benchmark, populated_database):
    """Benchmark retrieving all targets."""
    def get_all_targets():
        return populated_database.get_targets()

    targets = benchmark(get_all_targets)
    assert len(targets) > 0


def test_target_retrieval_filtered(benchmark, populated_database):
    """Benchmark filtered target retrieval."""
    def get_network_targets():
        return populated_database.get_targets(target_type='network')

    targets = benchmark(get_network_targets)
    assert len(targets) > 0


def test_credential_insertion(benchmark, database):
    """Benchmark credential insertion."""
    counter = [0]

    def insert_credential():
        counter[0] += 1
        return database.add_credential(f'user_{counter[0]}', f'pass_{counter[0]}', name=f'cred_{counter[0]}')

    result = benchmark(insert_credential)
    assert result > 0


def test_credential_retrieval(benchmark, populated_database):
    """Benchmark credential retrieval."""
    def get_credentials():
        return populated_database.get_credentials()

    creds = benchmark(get_credentials)
    assert len(creds) > 0


def test_service_insertion(benchmark, database):
    """Benchmark service insertion."""
    counter = [0]

    def insert_service():
        counter[0] += 1
        return database.add_service(f'192.168.1.{counter[0] % 10}', 'http', 80 + (counter[0] % 10))

    result = benchmark(insert_service)
    assert result is True


def test_service_retrieval_all(benchmark, populated_database):
    """Benchmark retrieving all services."""
    def get_all_services():
        return populated_database.get_services()

    services = benchmark(get_all_services)
    assert len(services) > 0


def test_service_retrieval_filtered(benchmark, populated_database):
    """Benchmark filtered service retrieval."""
    def get_target_services():
        return populated_database.get_services(target='192.168.1.1')

    services = benchmark(get_target_services)
    assert isinstance(services, list)


def test_web_services_query(benchmark, populated_database):
    """Benchmark web services query (complex query with IN clauses)."""
    def get_web_services():
        return populated_database.get_web_services()

    services = benchmark(get_web_services)
    assert isinstance(services, list)


def test_module_execution_logging(benchmark, database):
    """Benchmark module execution logging."""
    counter = [0]

    def log_execution():
        counter[0] += 1
        return database.add_module_execution(
            module_name=f'test_module_{counter[0]}',
            module_path='test/path',
            options={'opt1': 'value1'},
            results={'success': True},
            success=True
        )

    result = benchmark(log_execution)
    assert result > 0


def test_module_history_retrieval(benchmark, populated_database):
    """Benchmark module history retrieval."""
    # Add some history
    for i in range(50):
        populated_database.add_module_execution(
            module_name=f'module_{i}',
            module_path='test/path',
            options={},
            results={},
            success=True
        )

    def get_history():
        return populated_database.get_module_history(limit=100)

    history = benchmark(get_history)
    assert len(history) > 0


def test_finding_insertion(benchmark, database):
    """Benchmark finding insertion."""
    counter = [0]

    def insert_finding():
        counter[0] += 1
        return database.add_finding(
            target=f'192.168.1.{counter[0] % 10}',
            title=f'Test Finding {counter[0]}',
            severity='high',
            description='Test description',
            module_name='test_module'
        )

    result = benchmark(insert_finding)
    assert result > 0


def test_finding_retrieval(benchmark, populated_database):
    """Benchmark finding retrieval."""
    # Add some findings
    for i in range(50):
        populated_database.add_finding(
            target=f'192.168.1.{i % 10}',
            title=f'Finding {i}',
            severity='high'
        )

    def get_findings():
        return populated_database.get_findings()

    findings = benchmark(get_findings)
    assert len(findings) > 0


def test_scan_results_storage(benchmark, database):
    """Benchmark scan results storage."""
    counter = [0]

    def store_scan():
        counter[0] += 1
        return database.save_scan_results(
            scan_name=f'scan_{counter[0]}',
            target='192.168.1.1',
            scan_type='nmap',
            results={'ports': [80, 443]},
            file_path='/tmp/scan.xml'
        )

    result = benchmark(store_scan)
    assert result > 0


def test_module_defaults_operations(benchmark, database):
    """Benchmark module defaults operations."""
    counter = [0]

    def defaults_operation():
        counter[0] += 1
        module_name = f'module_{counter[0] % 10}'
        option_name = f'option_{counter[0] % 5}'

        # Set default
        database.set_module_default(module_name, option_name, f'value_{counter[0]}')

        # Get default
        value = database.get_module_default(module_name, option_name)

        # Get all defaults
        defaults = database.get_module_defaults(module_name)

        return value, defaults

    result = benchmark(defaults_operation)
    assert result is not None


def test_bulk_target_insertion(benchmark, database):
    """Benchmark bulk target insertion."""
    def bulk_insert():
        for i in range(100):
            database.add_target('network', f'10.0.0.{i}', f'bulk_target_{i}')

    benchmark(bulk_insert)
    targets = database.get_targets()
    assert len(targets) >= 100


def test_concurrent_database_access(benchmark, database):
    """Benchmark database under simulated concurrent access."""
    def concurrent_operations():
        # Simulate multiple operations that might happen concurrently
        database.add_target('network', '192.168.2.1', 'concurrent_test')
        database.get_targets()
        database.add_credential('testuser', 'testpass', name='concurrent_cred')
        database.get_credentials()
        database.add_service('192.168.2.1', 'http', 80)
        database.get_services()

    benchmark(concurrent_operations)


@pytest.mark.parametrize("batch_size", [10, 50, 100, 500])
def test_query_performance_scaling(benchmark, batch_size):
    """Test query performance with different data sizes."""
    from purplesploit.core.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        db = Database(db_path=db_path)

        # Populate with batch_size records
        for i in range(batch_size):
            db.add_target('network', f'192.168.3.{i % 256}', f'target_{i}')

        def query_all():
            return db.get_targets()

        targets = benchmark(query_all)
        assert len(targets) == batch_size

        db.close()
