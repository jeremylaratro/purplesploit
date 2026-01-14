"""
Startup Time Benchmarks

Measures framework initialization and module discovery performance.
"""

import pytest
import time
import tempfile
from pathlib import Path


def test_import_framework(benchmark):
    """Benchmark framework import time."""
    def import_framework():
        # Clear from cache to ensure fresh import measurement
        import sys
        modules_to_clear = [k for k in sys.modules.keys() if k.startswith('purplesploit')]
        for mod in modules_to_clear:
            del sys.modules[mod]

        from purplesploit.core.framework import Framework
        return Framework

    result = benchmark(import_framework)
    assert result is not None


def test_framework_initialization(benchmark):
    """Benchmark framework initialization with in-memory database."""
    from purplesploit.core.framework import Framework

    def init_framework():
        return Framework(db_path=':memory:')

    framework = benchmark(init_framework)
    assert framework is not None
    assert framework.database is not None
    assert framework.session is not None


def test_framework_initialization_with_file_db(benchmark):
    """Benchmark framework initialization with file database."""
    from purplesploit.core.framework import Framework

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")

        def init_framework():
            return Framework(db_path=db_path)

        framework = benchmark(init_framework)
        assert framework is not None


def test_module_discovery(benchmark):
    """Benchmark module discovery performance."""
    from purplesploit.core.framework import Framework

    framework = Framework(db_path=':memory:')

    def discover_modules():
        framework.modules.clear()  # Clear previous discoveries
        return framework.discover_modules()

    count = benchmark(discover_modules)
    assert count > 0


def test_full_startup(benchmark):
    """Benchmark complete startup sequence."""
    from purplesploit.core.framework import Framework

    def full_startup():
        framework = Framework(db_path=':memory:')
        count = framework.discover_modules()
        return framework, count

    framework, count = benchmark(full_startup)
    assert framework is not None
    assert count > 0
    assert len(framework.modules) == count


def test_module_loading(benchmark):
    """Benchmark individual module loading."""
    from purplesploit.core.framework import Framework

    framework = Framework(db_path=':memory:')
    framework.discover_modules()

    # Find first available module
    module_path = next(iter(framework.modules.keys()))

    def load_module():
        return framework.use_module(module_path)

    module = benchmark(load_module)
    assert module is not None


def test_database_connection_pool(benchmark):
    """Benchmark database connection creation."""
    from purplesploit.core.database import Database

    def create_db_connection():
        db = Database(db_path=':memory:')
        return db

    db = benchmark(create_db_connection)
    assert db is not None
    db.close()


def test_session_initialization(benchmark):
    """Benchmark session initialization."""
    from purplesploit.core.session import Session

    def create_session():
        return Session()

    session = benchmark(create_session)
    assert session is not None


@pytest.mark.parametrize("module_count", [10, 25, 50])
def test_module_search_performance(benchmark, module_count):
    """Benchmark module search with different module counts."""
    from purplesploit.core.framework import Framework

    framework = Framework(db_path=':memory:')
    framework.discover_modules()

    def search_modules():
        return framework.search_modules("test")

    results = benchmark(search_modules)
    assert isinstance(results, list)


def test_lazy_import_simulation(benchmark):
    """Test performance impact of lazy importing."""
    def lazy_import():
        # Simulate lazy importing pattern
        import importlib
        spec = importlib.util.find_spec("purplesploit.core.framework")
        return spec is not None

    result = benchmark(lazy_import)
    assert result is True
