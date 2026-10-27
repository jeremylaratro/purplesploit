"""S22 active-content neutralization and private-output tests."""

import csv
import io
import sys
from types import SimpleNamespace

import openpyxl
import pytest

from purplesploit.core.findings import Finding
from purplesploit.interop.canonical import CanonicalDocument, export_csv, import_csv
from purplesploit.reporting.html import HTMLReportGenerator
from purplesploit.reporting.models import ReportConfig, ReportData
from purplesploit.reporting.pdf import PDFReportGenerator
from purplesploit.reporting.xlsx import XLSXReportGenerator


def _report():
    return ReportData(
        ReportConfig(title="Private report"),
        [Finding(
            id="formula", title="=HYPERLINK(\"https://evil.invalid\")",
            target="+cmd", description="@SUM(1,1)",
            references=["javascript:alert(1)", "https://safe.invalid/reference"],
        )],
    )


def test_csv_and_xlsx_formula_neutralization_preserves_canonical_roundtrip(tmp_path):
    document = CanonicalDocument.from_mapping({
        "findings": [{
            "id": "formula", "title": "=2+2", "severity": "info", "target": "+cmd"
        }]
    })
    exported = export_csv(document).data
    rows = list(csv.DictReader(io.StringIO(exported)))
    assert rows[1]["title"].startswith("'=")
    assert rows[1]["target"].startswith("'+")
    assert import_csv(exported).document.to_dict() == document.to_dict()

    path = tmp_path / "report.xlsx"
    XLSXReportGenerator().generate(_report(), path)
    workbook = openpyxl.load_workbook(path, data_only=False)
    row = next(workbook["Findings"].iter_rows(min_row=2, values_only=True))
    assert row[1].startswith("'=")
    assert row[4].startswith("'+")
    assert path.stat().st_mode & 0o777 == 0o600


def test_html_escapes_content_and_disables_unsafe_links(tmp_path):
    path = tmp_path / "report.html"
    HTMLReportGenerator().generate(_report(), path)
    text = path.read_text()
    assert "href=\"javascript:" not in text
    assert 'href="https://safe.invalid/reference"' in text
    assert "rel=\"noopener noreferrer\"" in text
    assert path.stat().st_mode & 0o777 == 0o600


def test_pdf_temporary_html_is_removed_on_renderer_failure(tmp_path, monkeypatch):
    created = []
    import tempfile

    original = tempfile.NamedTemporaryFile

    def named(*args, **kwargs):
        value = original(*args, **kwargs)
        created.append(value.name)
        return value

    class BrokenHTML:
        def __init__(self, **kwargs):
            pass

        def write_pdf(self, *args, **kwargs):
            raise RuntimeError("renderer failed")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", named)
    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(
        CSS=lambda **kwargs: object(), HTML=BrokenHTML,
    ))
    generator = PDFReportGenerator()
    generator._weasyprint_available = True
    with pytest.raises(RuntimeError, match="renderer failed"):
        generator.generate(_report(), tmp_path / "report.pdf")
    assert created and all(not __import__("pathlib").Path(path).exists() for path in created)
