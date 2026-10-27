"""
Report Generator - Main orchestrator for PurpleSploit reporting.

Coordinates generation of reports in multiple formats (PDF, HTML, XLSX, Markdown).
"""

from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
import json

from .models import Finding, ReportConfig, ReportData
from purplesploit.core.findings import FindingsManager


class ReportGenerator:
    """
    Main report generator that orchestrates report creation.

    Supports multiple output formats and provides a unified interface
    for generating professional penetration test reports.
    """

    def __init__(self, framework=None):
        """
        Initialize the report generator.

        Args:
            framework: Optional reference to the PurpleSploit framework
        """
        self.framework = framework
        self.findings: List[Finding] = []
        self.config = ReportConfig()
        self._report_data: Optional[ReportData] = None

    def add_finding(self, finding: Union[Finding, Dict[str, Any]]) -> None:
        """Add a canonical finding or adapt a legacy dictionary losslessly."""
        if isinstance(finding, dict):
            finding = Finding.from_dict(finding)
        if not isinstance(finding, Finding):
            raise TypeError("Report findings must be canonical Finding objects or dictionaries")
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings to the report"""
        for finding in findings:
            self.add_finding(finding)

    def clear_findings(self) -> None:
        """Clear all findings"""
        self.findings = []

    def set_config(self, config: ReportConfig) -> None:
        """Set report configuration"""
        self.config = config

    def create_finding(
        self, title: str, severity: str, description: str, target: str, **kwargs
    ) -> Finding:
        """
        Create and add a new finding.

        Args:
            title: Finding title
            severity: Severity level (critical, high, medium, low, info)
            description: Detailed description
            target: Affected target
            **kwargs: Additional finding attributes

        Returns:
            The created Finding object
        """
        finding = Finding.from_dict(
            {
                **kwargs,
                "title": title,
                "severity": severity,
                "description": description,
                "target": target,
            }
        )

        self.add_finding(finding)
        return finding

    def _build_report_data(self, findings=None) -> ReportData:
        """Use supplied/local findings, then framework manager and legacy DB.

        Explicit report selections take precedence. Only when no findings were
        selected do we discover framework findings; conversion failures surface
        to the caller instead of silently producing an empty report.
        """
        targets = []
        services = []
        credentials = []

        selected = self.findings if findings is None else findings
        if isinstance(selected, Finding):
            selected = [selected]
        elif isinstance(selected, dict) and "title" in selected:
            selected = [selected]
        elif isinstance(selected, dict):
            selected = selected.values()
        selected = list(selected)

        # Pull data from framework if available
        if self.framework:
            if findings is None and not selected:
                for name in ("findings_manager", "_findings_manager"):
                    manager = getattr(self.framework, name, None)
                    if isinstance(manager, FindingsManager):
                        selected.extend(manager.findings.values())
            if hasattr(self.framework, "database"):
                db = self.framework.database
                targets = db.get_targets()
                services = db.get_services()
                credentials = []
                for credential in db.get_credentials():
                    safe_credential = dict(credential)
                    safe_credential["has_password"] = bool(safe_credential.pop("password", None))
                    safe_credential["has_hash"] = bool(safe_credential.pop("hash", None))
                    credentials.append(safe_credential)

                if findings is None and not selected:
                    if callable(getattr(db, "get_findings", None)):
                        rows = db.get_findings()
                        if not isinstance(rows, (list, tuple)):
                            raise TypeError("Database.get_findings() must return finding rows")
                        selected.extend(rows)

        return ReportData(
            config=self.config,
            findings=selected,
            targets=targets,
            services=services,
            credentials=credentials,
        )

    def generate(self, format: str, output_path: Optional[str] = None, **kwargs) -> str:
        """
        Generate a report in the specified format.

        Args:
            format: Output format (pdf, html, xlsx, markdown, json)
            output_path: Optional output file path
            **kwargs: Additional format-specific options

        Returns:
            Path to the generated report
        """
        format = format.lower()

        # Build report data
        report_data = self._build_report_data()

        # Determine output path
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = "md" if format == "markdown" else format
            output_path = (
                f"{self.config.output_dir}/{self.config.filename_prefix}_{timestamp}.{ext}"
            )

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Generate based on format
        if format == "pdf":
            result = self._generate_pdf(report_data, output_path, **kwargs)
        elif format == "html":
            result = self._generate_html(report_data, output_path, **kwargs)
        elif format == "xlsx":
            result = self._generate_xlsx(report_data, output_path, **kwargs)
        elif format == "markdown" or format == "md":
            result = self._generate_markdown(report_data, output_path, **kwargs)
        elif format == "json":
            result = self._generate_json(report_data, output_path, **kwargs)
        else:
            raise ValueError(f"Unsupported format: {format}")
        result_path = Path(result)
        if result_path.exists():
            result_path.chmod(0o600)
        return result

    def _generate_pdf(self, report_data: ReportData, output_path: Path, **kwargs) -> str:
        """Generate PDF report"""
        from .pdf import PDFReportGenerator

        generator = PDFReportGenerator()
        return generator.generate(report_data, output_path, **kwargs)

    def _generate_html(self, report_data: ReportData, output_path: Path, **kwargs) -> str:
        """Generate HTML report"""
        from .html import HTMLReportGenerator

        generator = HTMLReportGenerator()
        return generator.generate(report_data, output_path, **kwargs)

    def _generate_xlsx(self, report_data: ReportData, output_path: Path, **kwargs) -> str:
        """Generate Excel report"""
        from .xlsx import XLSXReportGenerator

        generator = XLSXReportGenerator()
        return generator.generate(report_data, output_path, **kwargs)

    def _generate_markdown(self, report_data: ReportData, output_path: Path, **kwargs) -> str:
        """Generate Markdown report"""
        from .markdown import MarkdownReportGenerator

        generator = MarkdownReportGenerator()
        return generator.generate(report_data, output_path, **kwargs)

    def _generate_json(self, report_data: ReportData, output_path: Path, **kwargs) -> str:
        """Generate JSON export of report data"""
        data = report_data.to_dict()

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return str(output_path)

    def load_findings_from_json(self, json_path: str) -> None:
        """Load findings from a JSON file"""
        with open(json_path, "r") as f:
            data = json.load(f)

        if isinstance(data, list):
            # List of findings
            for item in data:
                self.findings.append(Finding.from_dict(item))
        elif isinstance(data, dict) and "findings" in data:
            # Full report data
            for item in data["findings"]:
                self.findings.append(Finding.from_dict(item))

    def save_findings_to_json(self, json_path: str) -> None:
        """Save current findings to a JSON file"""
        data = [f.to_dict() for f in self.findings]

        with open(json_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of current findings"""
        report_data = self._build_report_data()

        return {
            "total_findings": report_data.total_findings,
            "severity_counts": report_data.severity_counts,
            "unique_targets": report_data.unique_targets,
            "critical_count": report_data.critical_count,
            "high_count": report_data.high_count,
            "findings_by_target": {
                target: len(findings) for target, findings in report_data.findings_by_target.items()
            },
        }

    def import_from_module_result(
        self, module_name: str, result: Dict[str, Any], target: str, auto_severity: str = "medium"
    ) -> Optional[Finding]:
        """
        Import a finding from a module execution result.

        Args:
            module_name: Name of the module that produced the result
            result: Module execution result dict
            target: Target that was tested
            auto_severity: Default severity if not determinable

        Returns:
            Created Finding or None if no finding warranted
        """
        if not result.get("success"):
            return None

        # Try to extract finding info from result
        title = result.get("title", f"{module_name} Finding")
        description = result.get("description", result.get("output", ""))
        severity = result.get("severity", auto_severity)

        if not description:
            return None

        details = dict(result)
        for name in ("title", "severity", "description", "target", "module_name"):
            details.pop(name, None)
        details.setdefault("raw_output", result.get("stdout", result.get("output", "")))
        finding = self.create_finding(
            title=title,
            severity=severity,
            description=description,
            target=target,
            module_name=module_name,
            **details,
        )

        return finding


# Convenience functions for CLI usage
def quick_report(
    findings: List[Dict[str, Any]], output_path: str, format: str = "html", **config_options
) -> str:
    """
    Generate a quick report from a list of finding dicts.

    Args:
        findings: List of finding dictionaries
        output_path: Output file path
        format: Output format
        **config_options: Report configuration options

    Returns:
        Path to generated report
    """
    generator = ReportGenerator()

    # Set config from options
    config = ReportConfig(**config_options)
    generator.set_config(config)

    # Add findings
    for f_data in findings:
        generator.add_finding(f_data)

    return generator.generate(format, output_path)
