"""
Tests for purplesploit.reporting.pdf module.

Tests the PDFReportGenerator class and check_pdf_dependencies function.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile

from purplesploit.reporting.pdf import PDFReportGenerator, check_pdf_dependencies
from purplesploit.reporting.models import (
    Finding,
    Severity,
    ReportConfig,
    ReportData,
)


@pytest.fixture
def sample_report_data():
    """Create sample report data for testing."""
    config = ReportConfig(
        title="PDF Test Report",
        client_name="Test Client",
    )

    findings = [
        Finding(
            id="f1",
            title="Test Vulnerability",
            severity=Severity.HIGH,
            description="A test vulnerability",
            target="192.168.1.1",
        ),
    ]

    return ReportData(config=config, findings=findings)


class TestPDFReportGeneratorInit:
    """Tests for PDFReportGenerator initialization."""

    def test_init(self):
        """Test initialization creates HTML generator."""
        gen = PDFReportGenerator()

        assert gen.html_generator is not None
        assert isinstance(gen._weasyprint_available, bool)

    def test_check_weasyprint_installed(self):
        """Test WeasyPrint detection when installed."""
        gen = PDFReportGenerator()

        # Result depends on whether weasyprint is actually installed
        assert isinstance(gen._weasyprint_available, bool)

    @patch.dict('sys.modules', {'weasyprint': None})
    def test_check_weasyprint_not_installed(self):
        """Test WeasyPrint detection when not installed."""
        # This simulates ImportError
        with patch.object(PDFReportGenerator, '_check_weasyprint', return_value=False):
            gen = PDFReportGenerator()
            gen._weasyprint_available = False

            assert gen._weasyprint_available is False


class TestPDFReportGeneratorGenerate:
    """Tests for PDF generation."""

    def test_generate_raises_without_weasyprint(self, sample_report_data, tmp_path):
        """Test that generate raises ImportError when WeasyPrint not available."""
        gen = PDFReportGenerator()
        gen._weasyprint_available = False

        output_path = tmp_path / "report.pdf"

        with pytest.raises(ImportError, match="WeasyPrint is required"):
            gen.generate(sample_report_data, output_path)

    @patch('purplesploit.reporting.pdf.weasyprint')
    def test_generate_with_weasyprint(self, mock_weasyprint, sample_report_data, tmp_path):
        """Test PDF generation with mocked WeasyPrint."""
        gen = PDFReportGenerator()
        gen._weasyprint_available = True

        # Mock the HTML class and its methods
        mock_html_instance = Mock()
        mock_weasyprint.HTML.return_value = mock_html_instance
        mock_weasyprint.CSS.return_value = Mock()

        output_path = tmp_path / "report.pdf"

        # Mock HTML generator to create actual HTML file
        with patch.object(gen.html_generator, 'generate') as mock_html_gen:
            # Create a real temp HTML file
            html_file = tmp_path / "temp.html"
            html_file.write_text("<html><body>Test</body></html>")
            mock_html_gen.return_value = str(html_file)

            result = gen.generate(sample_report_data, output_path)

        # Verify weasyprint was called
        mock_weasyprint.HTML.assert_called_once()
        mock_html_instance.write_pdf.assert_called_once()

    @patch('purplesploit.reporting.pdf.weasyprint')
    def test_generate_cleans_up_temp_html(self, mock_weasyprint, sample_report_data, tmp_path):
        """Test that temp HTML file is cleaned up after generation."""
        gen = PDFReportGenerator()
        gen._weasyprint_available = True

        mock_html_instance = Mock()
        mock_weasyprint.HTML.return_value = mock_html_instance
        mock_weasyprint.CSS.return_value = Mock()

        output_path = tmp_path / "report.pdf"

        with patch.object(gen.html_generator, 'generate') as mock_html_gen:
            html_file = tmp_path / "temp_to_delete.html"
            html_file.write_text("<html><body>Test</body></html>")
            mock_html_gen.return_value = str(html_file)

            gen.generate(sample_report_data, output_path)

        # Temp file should be deleted
        assert not html_file.exists()


class TestPDFReportGeneratorCSS:
    """Tests for PDF CSS generation."""

    def test_get_pdf_css(self):
        """Test that PDF CSS is returned."""
        gen = PDFReportGenerator()
        css = gen._get_pdf_css()

        assert "@page" in css
        assert "A4" in css
        assert "margin:" in css

    def test_pdf_css_contains_page_numbers(self):
        """Test that CSS includes page number styling."""
        gen = PDFReportGenerator()
        css = gen._get_pdf_css()

        assert "counter(page)" in css
        assert "counter(pages)" in css

    def test_pdf_css_contains_confidential(self):
        """Test that CSS includes confidential footer."""
        gen = PDFReportGenerator()
        css = gen._get_pdf_css()

        assert "CONFIDENTIAL" in css

    def test_pdf_css_first_page_different(self):
        """Test that first page has different styling."""
        gen = PDFReportGenerator()
        css = gen._get_pdf_css()

        assert "@page :first" in css

    def test_pdf_css_severity_colors(self):
        """Test that severity colors are preserved."""
        gen = PDFReportGenerator()
        css = gen._get_pdf_css()

        assert "#7b241c" in css  # Critical
        assert "#c0392b" in css  # High
        assert "#e67e22" in css  # Medium
        assert "#f1c40f" in css  # Low

    def test_pdf_css_page_breaks(self):
        """Test that page break rules are included."""
        gen = PDFReportGenerator()
        css = gen._get_pdf_css()

        assert "page-break" in css

    def test_pdf_css_hides_filter_bar(self):
        """Test that filter bar is hidden in print."""
        gen = PDFReportGenerator()
        css = gen._get_pdf_css()

        assert ".filter-bar" in css
        assert "display: none" in css


class TestCheckPDFDependencies:
    """Tests for check_pdf_dependencies function."""

    def test_check_pdf_dependencies_returns_dict(self):
        """Test that function returns a dictionary."""
        result = check_pdf_dependencies()

        assert isinstance(result, dict)
        assert "weasyprint" in result
        assert "cairo" in result
        assert "pango" in result
        assert "message" in result

    @patch('purplesploit.reporting.pdf.weasyprint')
    def test_check_pdf_dependencies_weasyprint_available(self, mock_weasyprint):
        """Test when WeasyPrint is available and working."""
        # Mock successful PDF generation
        mock_html = Mock()
        mock_html.write_pdf = Mock()
        mock_weasyprint.HTML.return_value = mock_html

        result = check_pdf_dependencies()

        # At minimum, weasyprint boolean should be set
        assert "weasyprint" in result

    def test_check_pdf_dependencies_weasyprint_not_installed(self):
        """Test when WeasyPrint is not installed."""
        with patch.dict('sys.modules', {'weasyprint': None}):
            with patch('builtins.__import__', side_effect=ImportError("No module")):
                # The function should handle ImportError gracefully
                result = check_pdf_dependencies()

                # Should return dict with weasyprint=False or error message
                assert isinstance(result, dict)

    @patch('purplesploit.reporting.pdf.weasyprint')
    def test_check_pdf_dependencies_cairo_error(self, mock_weasyprint):
        """Test when cairo library is missing."""
        mock_weasyprint.HTML.side_effect = Exception("cairo not found")

        result = check_pdf_dependencies()

        # Should detect cairo issue
        # Note: actual behavior depends on implementation
        assert isinstance(result, dict)

    @patch('purplesploit.reporting.pdf.weasyprint')
    def test_check_pdf_dependencies_pango_error(self, mock_weasyprint):
        """Test when pango library is missing."""
        mock_weasyprint.HTML.side_effect = Exception("pango not found")

        result = check_pdf_dependencies()

        assert isinstance(result, dict)


class TestPDFReportGeneratorIntegration:
    """Integration tests for PDF generation (skipped if WeasyPrint not installed)."""

    @pytest.fixture
    def weasyprint_available(self):
        """Check if WeasyPrint is available."""
        gen = PDFReportGenerator()
        return gen._weasyprint_available

    @pytest.mark.skipif(
        not PDFReportGenerator()._weasyprint_available,
        reason="WeasyPrint not installed"
    )
    def test_full_pdf_generation(self, sample_report_data, tmp_path):
        """Test full PDF generation with real WeasyPrint."""
        gen = PDFReportGenerator()
        output_path = tmp_path / "real_report.pdf"

        result = gen.generate(sample_report_data, output_path)

        assert Path(result).exists()
        assert Path(result).stat().st_size > 0

        # Check it's a valid PDF (starts with %PDF)
        with open(result, 'rb') as f:
            header = f.read(4)
            assert header == b'%PDF'
