"""
PDF Report Generator for PurpleSploit.

Generates professional PDF reports using WeasyPrint.
Falls back to HTML-only if WeasyPrint is not available.
"""

from pathlib import Path
from typing import Optional
import tempfile

from .models import ReportData
from .html import HTMLReportGenerator


class PDFReportGenerator:
    """Generates PDF reports from ReportData"""

    def __init__(self):
        """Initialize PDF generator"""
        self.html_generator = HTMLReportGenerator()
        self._weasyprint_available = self._check_weasyprint()

    def _check_weasyprint(self) -> bool:
        """Check if WeasyPrint is available"""
        try:
            import weasyprint
            return True
        except ImportError:
            return False

    def generate(
        self,
        report_data: ReportData,
        output_path: Path,
        **kwargs
    ) -> str:
        """
        Generate PDF report.

        Args:
            report_data: Report data to render
            output_path: Output file path
            **kwargs: Additional options

        Returns:
            Path to generated report

        Raises:
            ImportError: If WeasyPrint is not installed
        """
        if not self._weasyprint_available:
            raise ImportError(
                "WeasyPrint is required for PDF generation. "
                "Install with: pip install weasyprint"
            )

        import weasyprint

        # Generate HTML first
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.html',
            delete=False,
            encoding='utf-8'
        ) as tmp_file:
            html_path = tmp_file.name

        # Generate HTML with print-optimized styles
        self.html_generator.generate(
            report_data,
            html_path,
            standalone=True,
            pdf_mode=True,
            **kwargs
        )

        # Convert to PDF
        output_path = Path(output_path)

        # Add PDF-specific CSS
        pdf_css = weasyprint.CSS(string=self._get_pdf_css())

        # Generate PDF
        html_doc = weasyprint.HTML(filename=html_path)
        html_doc.write_pdf(
            output_path,
            stylesheets=[pdf_css]
        )

        # Clean up temp file
        Path(html_path).unlink(missing_ok=True)

        return str(output_path)

    def _get_pdf_css(self) -> str:
        """Get PDF-specific CSS overrides"""
        return '''
        @page {
            size: A4;
            margin: 2cm;

            @top-right {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 9pt;
                color: #666;
            }

            @bottom-center {
                content: "CONFIDENTIAL";
                font-size: 8pt;
                color: #999;
            }
        }

        @page :first {
            @top-right { content: none; }
        }

        body {
            font-size: 10pt;
            background: white !important;
            color: #333 !important;
        }

        .container {
            max-width: 100%;
            padding: 0;
        }

        header {
            background: #2c3e50 !important;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            page-break-after: avoid;
        }

        .stats-grid {
            page-break-after: avoid;
        }

        .stat-card {
            background: #f8f9fa !important;
            border: 1px solid #ddd;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }

        .section {
            background: white !important;
            border: 1px solid #ddd;
            page-break-inside: avoid;
        }

        .finding {
            background: #f8f9fa !important;
            page-break-inside: avoid;
            border: 1px solid #ddd;
        }

        .finding.critical { border-left: 4px solid #7b241c !important; }
        .finding.high { border-left: 4px solid #c0392b !important; }
        .finding.medium { border-left: 4px solid #e67e22 !important; }
        .finding.low { border-left: 4px solid #f1c40f !important; }
        .finding.info { border-left: 4px solid #3498db !important; }

        .badge {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }

        .badge.critical { background: #7b241c !important; }
        .badge.high { background: #c0392b !important; }
        .badge.medium { background: #e67e22 !important; }
        .badge.low { background: #f1c40f !important; }
        .badge.info { background: #3498db !important; }

        pre {
            background: #f5f5f5 !important;
            border: 1px solid #ddd;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 8pt;
        }

        table {
            page-break-inside: avoid;
        }

        th {
            background: #f0f0f0 !important;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }

        a {
            color: #3498db;
            text-decoration: none;
        }

        .filter-bar {
            display: none !important;
        }

        footer {
            page-break-before: avoid;
        }

        /* Color overrides for print */
        .stat-card.critical { border-left-color: #7b241c !important; }
        .stat-card.high { border-left-color: #c0392b !important; }
        .stat-card.medium { border-left-color: #e67e22 !important; }
        .stat-card.low { border-left-color: #f1c40f !important; }

        /* Ensure colors print */
        * {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }
        '''


def check_pdf_dependencies() -> dict:
    """
    Check if PDF generation dependencies are available.

    Returns:
        Dict with dependency status
    """
    result = {
        "weasyprint": False,
        "cairo": False,
        "pango": False,
        "message": ""
    }

    try:
        import weasyprint
        result["weasyprint"] = True

        # Try to create a simple PDF to verify cairo/pango
        from io import BytesIO
        html = weasyprint.HTML(string="<html><body>Test</body></html>")
        html.write_pdf(BytesIO())
        result["cairo"] = True
        result["pango"] = True
        result["message"] = "PDF generation is available"

    except ImportError as e:
        result["message"] = f"WeasyPrint not installed: {e}"
    except Exception as e:
        error_str = str(e).lower()
        if "cairo" in error_str:
            result["message"] = "Cairo library not found. Install with: sudo dnf install cairo-devel"
        elif "pango" in error_str:
            result["message"] = "Pango library not found. Install with: sudo dnf install pango-devel"
        else:
            result["message"] = f"PDF generation error: {e}"

    return result
