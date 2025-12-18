"""
Tests for purplesploit.reporting.html module.

Tests the HTMLReportGenerator class.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import datetime

from purplesploit.reporting.html import HTMLReportGenerator, JINJA2_AVAILABLE
from purplesploit.reporting.models import (
    Finding,
    Severity,
    FindingStatus,
    ReportConfig,
    ReportData,
)


@pytest.fixture
def sample_report_data():
    """Create sample report data for testing."""
    config = ReportConfig(
        title="Test Security Report",
        subtitle="Web Application Assessment",
        client_name="ACME Corp",
        assessor_name="Security Tester",
    )

    findings = [
        Finding(
            id="f1",
            title="SQL Injection",
            severity=Severity.CRITICAL,
            description="SQL injection vulnerability in login form",
            target="192.168.1.100",
            port=443,
            service="https",
            impact="Full database compromise",
            remediation="Use parameterized queries",
            cvss_score=9.8,
        ),
        Finding(
            id="f2",
            title="XSS",
            severity=Severity.MEDIUM,
            description="Reflected XSS in search parameter",
            target="192.168.1.100",
            port=443,
            service="https",
            impact="Session hijacking",
            remediation="Encode output",
        ),
    ]

    return ReportData(
        config=config,
        findings=findings,
        targets=[{"ip": "192.168.1.100", "name": "Web Server"}],
        services=[{"target": "192.168.1.100", "port": 443, "service": "https"}],
    )


class TestHTMLReportGeneratorInit:
    """Tests for HTMLReportGenerator initialization."""

    def test_init_default(self):
        """Test default initialization."""
        gen = HTMLReportGenerator()

        assert gen.template_dir is None

    def test_init_with_template_dir(self, tmp_path):
        """Test initialization with custom template directory."""
        gen = HTMLReportGenerator(template_dir=str(tmp_path))

        assert gen.template_dir == str(tmp_path)


class TestHTMLReportGeneratorHelpers:
    """Tests for helper methods."""

    def test_severity_color_critical(self):
        """Test severity color for critical."""
        gen = HTMLReportGenerator()
        color = gen._severity_color(Severity.CRITICAL)

        assert color == "#7b241c"

    def test_severity_color_high(self):
        """Test severity color for high."""
        gen = HTMLReportGenerator()
        color = gen._severity_color(Severity.HIGH)

        assert color == "#c0392b"

    def test_severity_color_medium(self):
        """Test severity color for medium."""
        gen = HTMLReportGenerator()
        color = gen._severity_color(Severity.MEDIUM)

        assert color == "#e67e22"

    def test_severity_color_low(self):
        """Test severity color for low."""
        gen = HTMLReportGenerator()
        color = gen._severity_color(Severity.LOW)

        assert color == "#f1c40f"

    def test_severity_color_info(self):
        """Test severity color for info."""
        gen = HTMLReportGenerator()
        color = gen._severity_color(Severity.INFO)

        assert color == "#3498db"

    def test_severity_color_unknown(self):
        """Test severity color fallback for unknown."""
        gen = HTMLReportGenerator()
        # Test with a mock severity-like object
        mock_severity = Mock()
        color = gen._severity_color(mock_severity)

        assert color == "#95a5a6"

    def test_severity_badge(self):
        """Test badge HTML generation."""
        gen = HTMLReportGenerator()
        badge = gen._severity_badge(Severity.HIGH)

        assert 'class="badge"' in badge
        assert "#c0392b" in badge
        assert "HIGH" in badge

    def test_format_datetime_valid(self):
        """Test datetime formatting with valid datetime."""
        gen = HTMLReportGenerator()
        dt = datetime(2025, 1, 15, 10, 30, 0)

        result = gen._format_datetime(dt)

        assert result == "2025-01-15 10:30"

    def test_format_datetime_custom_format(self):
        """Test datetime formatting with custom format."""
        gen = HTMLReportGenerator()
        dt = datetime(2025, 1, 15, 10, 30, 0)

        result = gen._format_datetime(dt, "%Y/%m/%d")

        assert result == "2025/01/15"

    def test_format_datetime_none(self):
        """Test datetime formatting with None."""
        gen = HTMLReportGenerator()

        result = gen._format_datetime(None)

        assert result == ""


class TestHTMLReportGeneratorEscape:
    """Tests for HTML escaping."""

    def test_escape_html_special_chars(self):
        """Test escaping special HTML characters."""
        gen = HTMLReportGenerator()

        result = gen._escape_html("<script>alert('xss')</script>")

        assert "&lt;" in result
        assert "&gt;" in result
        assert "&#x27;" in result
        assert "<script>" not in result

    def test_escape_html_ampersand(self):
        """Test escaping ampersand."""
        gen = HTMLReportGenerator()

        result = gen._escape_html("Tom & Jerry")

        assert result == "Tom &amp; Jerry"

    def test_escape_html_quotes(self):
        """Test escaping quotes."""
        gen = HTMLReportGenerator()

        result = gen._escape_html('He said "hello"')

        assert "&quot;" in result

    def test_escape_html_empty(self):
        """Test escaping empty string."""
        gen = HTMLReportGenerator()

        result = gen._escape_html("")

        assert result == ""

    def test_escape_html_none(self):
        """Test escaping None."""
        gen = HTMLReportGenerator()

        result = gen._escape_html(None)

        assert result == ""


class TestHTMLReportGeneratorGenerate:
    """Tests for report generation."""

    def test_generate_simple_without_jinja2(self, sample_report_data, tmp_path):
        """Test simple HTML generation (no jinja2)."""
        gen = HTMLReportGenerator()
        # Force simple generation
        gen.env = None

        output_path = tmp_path / "report.html"
        result = gen.generate(sample_report_data, output_path)

        assert Path(result).exists()
        content = Path(result).read_text()
        assert "Test Security Report" in content
        assert "SQL Injection" in content
        assert "XSS" in content

    def test_generate_simple_contains_statistics(self, sample_report_data, tmp_path):
        """Test that simple HTML contains statistics."""
        gen = HTMLReportGenerator()
        gen.env = None

        output_path = tmp_path / "report.html"
        gen.generate(sample_report_data, output_path)

        content = Path(output_path).read_text()
        # Should have severity count cards
        assert "Critical" in content
        assert "Total" in content

    def test_generate_simple_contains_findings(self, sample_report_data, tmp_path):
        """Test that simple HTML contains findings details."""
        gen = HTMLReportGenerator()
        gen.env = None

        output_path = tmp_path / "report.html"
        gen.generate(sample_report_data, output_path)

        content = Path(output_path).read_text()
        # Should have finding details
        assert "SQL injection vulnerability" in content
        assert "192.168.1.100" in content
        assert "443" in content

    def test_generate_simple_contains_impact_remediation(self, sample_report_data, tmp_path):
        """Test that impact and remediation are included."""
        gen = HTMLReportGenerator()
        gen.env = None

        output_path = tmp_path / "report.html"
        gen.generate(sample_report_data, output_path)

        content = Path(output_path).read_text()
        assert "Full database compromise" in content
        assert "parameterized queries" in content

    def test_generate_creates_output_file(self, sample_report_data, tmp_path):
        """Test that output file is created."""
        gen = HTMLReportGenerator()

        output_path = tmp_path / "test_report.html"
        result = gen.generate(sample_report_data, output_path)

        assert Path(result).exists()
        assert Path(result).stat().st_size > 0

    def test_generate_valid_html_structure(self, sample_report_data, tmp_path):
        """Test that generated HTML has valid structure."""
        gen = HTMLReportGenerator()
        gen.env = None

        output_path = tmp_path / "report.html"
        gen.generate(sample_report_data, output_path)

        content = Path(output_path).read_text()
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content
        assert "<head>" in content
        assert "</head>" in content
        assert "<body>" in content
        assert "</body>" in content

    def test_generate_contains_css(self, sample_report_data, tmp_path):
        """Test that generated HTML contains embedded CSS."""
        gen = HTMLReportGenerator()
        gen.env = None

        output_path = tmp_path / "report.html"
        gen.generate(sample_report_data, output_path)

        content = Path(output_path).read_text()
        assert "<style>" in content
        assert "</style>" in content

    def test_generate_with_subtitle(self, tmp_path):
        """Test generation with subtitle."""
        config = ReportConfig(
            title="Report",
            subtitle="Subtitle Text",
        )
        report_data = ReportData(config=config, findings=[])

        gen = HTMLReportGenerator()
        gen.env = None

        output_path = tmp_path / "report.html"
        gen.generate(report_data, output_path)

        content = Path(output_path).read_text()
        assert "Subtitle Text" in content

    def test_generate_empty_findings(self, tmp_path):
        """Test generation with no findings."""
        config = ReportConfig(title="Empty Report")
        report_data = ReportData(config=config, findings=[])

        gen = HTMLReportGenerator()
        gen.env = None

        output_path = tmp_path / "report.html"
        result = gen.generate(report_data, output_path)

        assert Path(result).exists()
        content = Path(result).read_text()
        assert "Empty Report" in content

    def test_generate_filters_findings(self, tmp_path):
        """Test that findings are filtered based on config."""
        config = ReportConfig(
            title="Filtered Report",
            statuses_to_include=[FindingStatus.DRAFT],
        )

        findings = [
            Finding(
                id="f1",
                title="Draft Finding",
                severity=Severity.HIGH,
                description="Draft",
                target="192.168.1.1",
                status=FindingStatus.DRAFT,
            ),
            Finding(
                id="f2",
                title="Confirmed Finding",
                severity=Severity.HIGH,
                description="Confirmed",
                target="192.168.1.1",
                status=FindingStatus.CONFIRMED,
            ),
        ]

        report_data = ReportData(config=config, findings=findings)

        gen = HTMLReportGenerator()
        gen.env = None

        output_path = tmp_path / "report.html"
        gen.generate(report_data, output_path)

        content = Path(output_path).read_text()
        assert "Draft Finding" in content
        # Confirmed finding should be filtered out (but may still appear in stats)


class TestHTMLReportGeneratorDefaultTemplate:
    """Tests for default template."""

    def test_get_default_template(self):
        """Test that default template returns valid HTML."""
        gen = HTMLReportGenerator()
        template = gen._get_default_template()

        assert "<!DOCTYPE html>" in template
        assert "{{ config.title }}" in template
        assert "{{ findings }}" in template or "{% for finding in findings %}" in template


@pytest.mark.skipif(not JINJA2_AVAILABLE, reason="jinja2 not installed")
class TestHTMLReportGeneratorJinja2:
    """Tests for Jinja2-based generation."""

    def test_jinja2_generation(self, sample_report_data, tmp_path):
        """Test HTML generation with Jinja2."""
        gen = HTMLReportGenerator()

        output_path = tmp_path / "jinja2_report.html"
        result = gen.generate(sample_report_data, output_path)

        assert Path(result).exists()
        content = Path(result).read_text()
        assert "Test Security Report" in content

    def test_jinja2_custom_filters_registered(self):
        """Test that custom filters are registered."""
        gen = HTMLReportGenerator()

        if gen.env is not None:
            assert "severity_color" in gen.env.filters
            assert "severity_badge" in gen.env.filters
            assert "format_datetime" in gen.env.filters
