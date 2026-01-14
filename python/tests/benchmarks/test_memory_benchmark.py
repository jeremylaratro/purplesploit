"""
Memory Usage Benchmarks

Measures memory consumption patterns and identifies potential leaks.
"""

import pytest
import gc
import sys
import tracemalloc
import tempfile
from pathlib import Path


def get_object_size(obj):
    """Get size of object and referenced objects."""
    seen = set()
    size = 0

    def _get_size(obj):
        nonlocal size
        obj_id = id(obj)

        if obj_id in seen:
            return

        seen.add(obj_id)
        size += sys.getsizeof(obj)

        if isinstance(obj, dict):
            for k, v in obj.items():
                _get_size(k)
                _get_size(v)
        elif hasattr(obj, '__dict__'):
            _get_size(obj.__dict__)
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
            try:
                for item in obj:
                    _get_size(item)
            except:
                pass

    _get_size(obj)
    return size


def test_framework_memory_footprint(benchmark):
    """Measure framework memory footprint."""
    from purplesploit.core.framework import Framework

    def create_framework():
        gc.collect()
        tracemalloc.start()

        framework = Framework(db_path=':memory:')
        framework.discover_modules()

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return framework, current, peak

    framework, current, peak = benchmark(create_framework)

    # Log memory usage
    print(f"\nFramework memory: current={current/1024/1024:.2f}MB, peak={peak/1024/1024:.2f}MB")

    assert framework is not None
    assert current > 0
    assert peak > 0


def test_database_memory_usage(benchmark):
    """Measure database memory usage."""
    from purplesploit.core.database import Database

    def create_and_use_database():
        gc.collect()
        tracemalloc.start()

        db = Database(db_path=':memory:')

        # Add some data
        for i in range(100):
            db.add_target('network', f'192.168.1.{i}', f'target_{i}')

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        db.close()
        return current, peak

    current, peak = benchmark(create_and_use_database)

    print(f"\nDatabase memory: current={current/1024/1024:.2f}MB, peak={peak/1024/1024:.2f}MB")

    assert current > 0


def test_session_memory_usage(benchmark):
    """Measure session memory usage."""
    from purplesploit.core.session import Session

    def create_and_use_session():
        gc.collect()
        tracemalloc.start()

        session = Session()

        # Add test data
        for i in range(100):
            session.targets.add({
                'type': 'network',
                'ip': f'192.168.1.{i}',
                'name': f'target_{i}'
            })

        for i in range(50):
            session.credentials.add({
                'username': f'user_{i}',
                'password': f'pass_{i}',
                'name': f'cred_{i}'
            })

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return session, current, peak

    session, current, peak = benchmark(create_and_use_session)

    print(f"\nSession memory: current={current/1024/1024:.2f}MB, peak={peak/1024/1024:.2f}MB")

    assert session is not None
    assert current > 0


def test_module_memory_footprint(benchmark):
    """Measure memory footprint of loading modules."""
    from purplesploit.core.framework import Framework

    framework = Framework(db_path=':memory:')
    framework.discover_modules()

    # Get first module path
    module_path = next(iter(framework.modules.keys()))

    def load_and_measure_module():
        gc.collect()
        tracemalloc.start()

        module = framework.use_module(module_path)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return module, current, peak

    module, current, peak = benchmark(load_and_measure_module)

    print(f"\nModule memory: current={current/1024/1024:.2f}MB, peak={peak/1024/1024:.2f}MB")

    assert module is not None


def test_memory_leak_detection_targets(benchmark):
    """Test for memory leaks in target operations."""
    from purplesploit.core.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        db = Database(db_path=db_path)

        def repeated_operations():
            gc.collect()
            initial = tracemalloc.get_traced_memory()[0] if tracemalloc.is_tracing() else 0

            # Perform operations multiple times
            for cycle in range(10):
                for i in range(50):
                    db.add_target('network', f'192.168.{cycle}.{i}', f'target_{cycle}_{i}')

                targets = db.get_targets()

                # Clear some targets
                for target in targets[:25]:
                    db.remove_target(target['identifier'])

            gc.collect()
            final = tracemalloc.get_traced_memory()[0] if tracemalloc.is_tracing() else 0

            return final - initial

        tracemalloc.start()
        growth = benchmark(repeated_operations)
        tracemalloc.stop()

        print(f"\nMemory growth after repeated operations: {growth/1024/1024:.2f}MB")

        db.close()


def test_module_discovery_memory(benchmark):
    """Measure memory used by module discovery."""
    from purplesploit.core.framework import Framework

    def discover_and_measure():
        gc.collect()
        tracemalloc.start()

        framework = Framework(db_path=':memory:')
        count = framework.discover_modules()

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return count, current, peak

    count, current, peak = benchmark(discover_and_measure)

    print(f"\nModule discovery: {count} modules, memory: current={current/1024/1024:.2f}MB, peak={peak/1024/1024:.2f}MB")

    assert count > 0


def test_large_dataset_memory_scaling(benchmark):
    """Test memory scaling with large datasets."""
    from purplesploit.core.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        db = Database(db_path=db_path)

        def populate_and_measure():
            gc.collect()
            tracemalloc.start()

            # Add 1000 targets
            for i in range(1000):
                db.add_target('network', f'10.0.{i//256}.{i%256}', f'target_{i}')

            # Add 500 credentials
            for i in range(500):
                db.add_credential(f'user_{i}', f'pass_{i}', name=f'cred_{i}')

            # Add 2000 services
            for i in range(2000):
                db.add_service(f'10.0.{i//256}.{i%256}', f'service_{i%10}', 8000 + (i % 100))

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            return current, peak

        current, peak = benchmark(populate_and_measure)

        print(f"\nLarge dataset memory: current={current/1024/1024:.2f}MB, peak={peak/1024/1024:.2f}MB")

        db.close()


def test_json_serialization_memory(benchmark):
    """Test memory usage of JSON serialization in database."""
    from purplesploit.core.database import Database
    import json

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        db = Database(db_path=db_path)

        def serialize_and_store():
            gc.collect()
            tracemalloc.start()

            # Store results with large JSON payloads
            large_results = {
                'hosts': [{'ip': f'192.168.1.{i}', 'ports': list(range(100))} for i in range(50)],
                'services': [{'name': f'service_{i}', 'data': 'x' * 1000} for i in range(100)]
            }

            for i in range(50):
                db.save_scan_results(
                    scan_name=f'scan_{i}',
                    target='192.168.1.1',
                    scan_type='nmap',
                    results=large_results
                )

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            return current, peak

        current, peak = benchmark(serialize_and_store)

        print(f"\nJSON serialization memory: current={current/1024/1024:.2f}MB, peak={peak/1024/1024:.2f}MB")

        db.close()


@pytest.mark.parametrize("object_count", [100, 500, 1000])
def test_session_scaling(benchmark, object_count):
    """Test session memory scaling with different object counts."""
    from purplesploit.core.session import Session

    def create_populated_session():
        gc.collect()
        tracemalloc.start()

        session = Session()

        for i in range(object_count):
            session.targets.add({
                'type': 'network',
                'ip': f'192.168.{i//256}.{i%256}',
                'name': f'target_{i}'
            })

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return session, current, peak

    session, current, peak = benchmark(create_populated_session)

    print(f"\nSession with {object_count} objects: current={current/1024/1024:.2f}MB, peak={peak/1024/1024:.2f}MB")

    assert len(session.targets.list()) == object_count
