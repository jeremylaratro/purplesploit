"""Tests for the OCD AD mind-map capability registry."""
from purplesploit.capabilities import ocd


def test_registry_has_17_categories():
    doc = ocd.load_registry()
    assert len(doc["categories"]) == 17


def test_all_statuses_valid():
    for c in ocd.categories():
        assert c.module_status in ocd.STATUSES
        assert c.subjects  # every category names its subjects


def test_backing_modules_all_resolve():
    # The registry must not claim a backing module that does not exist on disk.
    assert ocd.validate_backing_modules() == []


def test_coverage_report_runs():
    report = ocd.coverage_report()
    assert "capability coverage" in report
    assert "crack_hash" in report
