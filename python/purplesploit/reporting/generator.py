"""
Report Generator - Main orchestrator for PurpleSploit reporting.

Coordinates generation of reports in multiple formats (PDF, HTML, XLSX, Markdown).
"""

from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
import json

from .models import (
    Finding, Evidence, ReportConfig, ReportData, Severity, FindingStatus
)


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

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report"""
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings to the report"""
        self.findings.extend(findings)

    def clear_findings(self) -> None:
        """Clear all findings"""
        self.findings = []

    def set_config(self, config: ReportConfig) -> None:
        """Set report configuration"""
        self.config = config

    def create_finding(
        self,
        title: str,
        severity: str,
        description: str,
        target: str,
        **kwargs
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
        import uuid

        finding = Finding(
            id=kwargs.get("id", str(uuid.uuid4())[:8]),
            title=title,
            severity=Severity(severity.lower()),
            description=description,
            target=target,
            cvss_score=kwargs.get("cvss_score"),
            cvss_vector=kwargs.get("cvss_vector"),
            cve_ids=kwargs.get("cve_ids", []),
            cwe_ids=kwargs.get("cwe_ids", []),
            impact=kwargs.get("impact", ""),
            remediation=kwargs.get("remediation", ""),
            references=kwargs.get("references", []),
            mitre_tactics=kwargs.get("mitre_tactics", []),
            mitre_techniques=kwargs.get("mitre_techniques", []),
            module_name=kwargs.get("module_name"),
            port=kwargs.get("port"),
            service=kwargs.get("service"),
            raw_output=kwargs.get("raw_output"),
            status=FindingStatus(kwargs.get("status", "draft")),
            notes=kwargs.get("notes", ""),
        )

        self.add_finding(finding)
        return finding

    def _build_report_data(self) -> ReportData:
        """Build ReportData from current state"""
        targets = []
        services = []
        credentials = []

        # Pull data from framework if available
        if self.framework:
            if hasattr(self.framework, 'database'):
                db = self.framework.database
                targets = [t.to_dict() for t in db.get_all_targets()]
                services = [s.to_dict() for s in db.get_all_services()]
                credentials = [c.to_dict() for c in db.get_all_credentials()]

        return ReportData(
            config=self.config,
            findings=self.findings,
            targets=targets,
            services=services,
            credentials=credentials,
        )

    def generate(
        self,
        format: str,
        output_path: Optional[str] = None,
        **kwargs
    ) -> str:
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
            output_path = f"{self.config.output_dir}/{self.config.filename_prefix}_{timestamp}.{ext}"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Generate based on format
        if format == "pdf":
            return self._generate_pdf(report_data, output_path, **kwargs)
        elif format == "html":
            return self._generate_html(report_data, output_path, **kwargs)
        elif format == "xlsx":
            return self._generate_xlsx(report_data, output_path, **kwargs)
        elif format == "markdown" or format == "md":
            return self._generate_markdown(report_data, output_path, **kwargs)
        elif format == "json":
            return self._generate_json(report_data, output_path, **kwargs)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_pdf(
        self,
        report_data: ReportData,
        output_path: Path,
        **kwargs
    ) -> str:
        """Generate PDF report"""
        from .pdf import PDFReportGenerator

        generator = PDFReportGenerator()
        return generator.generate(report_data, output_path, **kwargs)

    def _generate_html(
        self,
        report_data: ReportData,
        output_path: Path,
        **kwargs
    ) -> str:
        """Generate HTML report"""
        from .html import HTMLReportGenerator

        generator = HTMLReportGenerator()
        return generator.generate(report_data, output_path, **kwargs)

    def _generate_xlsx(
        self,
        report_data: ReportData,
        output_path: Path,
        **kwargs
    ) -> str:
        """Generate Excel report"""
        from .xlsx import XLSXReportGenerator

        generator = XLSXReportGenerator()
        return generator.generate(report_data, output_path, **kwargs)

    def _generate_markdown(
        self,
        report_data: ReportData,
        output_path: Path,
        **kwargs
    ) -> str:
        """Generate Markdown report"""
        from .markdown import MarkdownReportGenerator

        generator = MarkdownReportGenerator()
        return generator.generate(report_data, output_path, **kwargs)

    def _generate_json(
        self,
        report_data: ReportData,
        output_path: Path,
        **kwargs
    ) -> str:
        """Generate JSON export of report data"""
        data = report_data.to_dict()

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return str(output_path)

    def load_findings_from_json(self, json_path: str) -> None:
        """Load findings from a JSON file"""
        with open(json_path, 'r') as f:
            data = json.load(f)

        if isinstance(data, list):
            # List of findings
            for item in data:
                self.findings.append(Finding.from_dict(item))
        elif isinstance(data, dict) and 'findings' in data:
            # Full report data
            for item in data['findings']:
                self.findings.append(Finding.from_dict(item))

    def save_findings_to_json(self, json_path: str) -> None:
        """Save current findings to a JSON file"""
        data = [f.to_dict() for f in self.findings]

        with open(json_path, 'w') as f:
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
                target: len(findings)
                for target, findings in report_data.findings_by_target.items()
            }
        }

    def import_from_module_result(
        self,
        module_name: str,
        result: Dict[str, Any],
        target: str,
        auto_severity: str = "medium"
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

        finding = self.create_finding(
            title=title,
            severity=severity,
            description=description,
            target=target,
            module_name=module_name,
            port=result.get("port"),
            service=result.get("service"),
            raw_output=result.get("stdout", result.get("output")),
        )

        return finding


# Convenience functions for CLI usage
def quick_report(
    findings: List[Dict[str, Any]],
    output_path: str,
    format: str = "html",
    **config_options
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
        generator.create_finding(**f_data)

    return generator.generate(format, output_path)
