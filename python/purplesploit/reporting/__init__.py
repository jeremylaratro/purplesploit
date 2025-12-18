"""
PurpleSploit Reporting Module

Professional report generation for penetration testing engagements.
Supports PDF, HTML, XLSX, and Markdown output formats.
"""

from .generator import ReportGenerator, quick_report
from .models import (
    Finding,
    Evidence,
    ReportConfig,
    ReportData,
    Severity,
    FindingStatus,
)
from .html import HTMLReportGenerator
from .markdown import MarkdownReportGenerator
from .xlsx import XLSXReportGenerator
from .pdf import PDFReportGenerator, check_pdf_dependencies

__all__ = [
    # Main generator
    'ReportGenerator',
    'quick_report',
    # Models
    'Finding',
    'Evidence',
    'ReportConfig',
    'ReportData',
    'Severity',
    'FindingStatus',
    # Format-specific generators
    'HTMLReportGenerator',
    'MarkdownReportGenerator',
    'XLSXReportGenerator',
    'PDFReportGenerator',
    # Utilities
    'check_pdf_dependencies',
]
