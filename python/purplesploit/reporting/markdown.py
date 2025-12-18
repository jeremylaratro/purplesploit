"""
Markdown Report Generator for PurpleSploit.

Generates Markdown reports suitable for GitHub, wikis, and documentation.
"""

from pathlib import Path
from typing import Optional
from datetime import datetime

from .models import ReportData, Finding, Severity


class MarkdownReportGenerator:
    """Generates Markdown reports from ReportData"""

    def generate(
        self,
        report_data: ReportData,
        output_path: Path,
        **kwargs
    ) -> str:
        """
        Generate Markdown report.

        Args:
            report_data: Report data to render
            output_path: Output file path
            **kwargs: Additional options
                - include_toc: Include table of contents (default: True)
                - include_badge_images: Use shield.io badges (default: False)

        Returns:
            Path to generated report
        """
        include_toc = kwargs.get("include_toc", True)
        include_badges = kwargs.get("include_badge_images", False)

        lines = []

        # Title
        lines.append(f"# {report_data.config.title}")
        lines.append("")

        if report_data.config.subtitle:
            lines.append(f"*{report_data.config.subtitle}*")
            lines.append("")

        # Metadata
        lines.append("## Report Information")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")

        if report_data.config.client_name:
            lines.append(f"| Client | {report_data.config.client_name} |")
        if report_data.config.assessor_name:
            lines.append(f"| Assessor | {report_data.config.assessor_name} |")
        if report_data.config.report_date:
            lines.append(f"| Report Date | {report_data.config.report_date.strftime('%Y-%m-%d')} |")
        if report_data.config.start_date and report_data.config.end_date:
            lines.append(
                f"| Assessment Period | {report_data.config.start_date.strftime('%Y-%m-%d')} - "
                f"{report_data.config.end_date.strftime('%Y-%m-%d')} |"
            )
        lines.append(f"| Assessment Type | {report_data.config.assessment_type} |")
        lines.append("")

        # Table of Contents
        if include_toc:
            lines.append("## Table of Contents")
            lines.append("")
            lines.append("- [Executive Summary](#executive-summary)")
            lines.append("- [Findings Summary](#findings-summary)")
            lines.append("- [Detailed Findings](#detailed-findings)")
            if report_data.targets:
                lines.append("- [Targets](#targets)")
            if report_data.services:
                lines.append("- [Services](#services)")
            lines.append("")

        # Executive Summary
        if report_data.config.include_executive_summary:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(
                f"This penetration test assessment identified **{report_data.total_findings}** security findings "
                f"across **{report_data.unique_targets}** target(s)."
            )
            lines.append("")

            if report_data.critical_count > 0 or report_data.high_count > 0:
                lines.append("**Immediate attention required:**")
                if report_data.critical_count > 0:
                    lines.append(f"- {report_data.critical_count} Critical severity finding(s)")
                if report_data.high_count > 0:
                    lines.append(f"- {report_data.high_count} High severity finding(s)")
                lines.append("")

            if report_data.config.scope:
                lines.append("### Scope")
                lines.append("")
                for item in report_data.config.scope:
                    lines.append(f"- {item}")
                lines.append("")

        # Findings Summary
        lines.append("## Findings Summary")
        lines.append("")

        if include_badges:
            # Use shields.io badges
            lines.append("### Severity Distribution")
            lines.append("")
            for severity in Severity:
                count = report_data.severity_counts.get(severity.value, 0)
                color = self._get_badge_color(severity)
                badge = f"![{severity.value}](https://img.shields.io/badge/{severity.value}-{count}-{color})"
                lines.append(badge)
            lines.append("")
        else:
            # Use table
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for severity in Severity:
                count = report_data.severity_counts.get(severity.value, 0)
                emoji = self._get_severity_emoji(severity)
                lines.append(f"| {emoji} {severity.value.upper()} | {count} |")
            lines.append(f"| **TOTAL** | **{report_data.total_findings}** |")
            lines.append("")

        # Findings by Target
        if report_data.findings_by_target:
            lines.append("### Findings by Target")
            lines.append("")
            lines.append("| Target | Findings |")
            lines.append("|--------|----------|")
            for target, findings in report_data.findings_by_target.items():
                lines.append(f"| {target} | {len(findings)} |")
            lines.append("")

        # Detailed Findings
        if report_data.config.include_findings_detail:
            lines.append("## Detailed Findings")
            lines.append("")

            # Filter findings based on config
            filtered_findings = report_data.filter_findings(report_data.config)

            # Group by severity
            for severity in Severity:
                severity_findings = [f for f in filtered_findings if f.severity == severity]
                if not severity_findings:
                    continue

                emoji = self._get_severity_emoji(severity)
                lines.append(f"### {emoji} {severity.value.upper()} Severity")
                lines.append("")

                for finding in severity_findings:
                    lines.extend(self._format_finding(finding, report_data.config))
                    lines.append("")

        # Targets
        if report_data.config.include_appendix and report_data.targets:
            lines.append("## Targets")
            lines.append("")
            lines.append("| Name | IP/URL | Description |")
            lines.append("|------|--------|-------------|")
            for target in report_data.targets:
                name = target.get("name", "")
                addr = target.get("ip") or target.get("url", "")
                desc = target.get("description", "-")
                lines.append(f"| {name} | {addr} | {desc} |")
            lines.append("")

        # Services
        if report_data.config.include_appendix and report_data.services:
            lines.append("## Services")
            lines.append("")
            lines.append("| Target | Port | Service | Version |")
            lines.append("|--------|------|---------|---------|")
            for service in report_data.services:
                lines.append(
                    f"| {service.get('target', '')} | {service.get('port', '')} | "
                    f"{service.get('service', '')} | {service.get('version', '-')} |"
                )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append(f"*Generated by PurpleSploit on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        if report_data.config.company_name:
            company_line = report_data.config.company_name
            if report_data.config.company_website:
                company_line += f" | {report_data.config.company_website}"
            lines.append(f"*{company_line}*")

        # Write output
        output_path = Path(output_path)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        return str(output_path)

    def _get_severity_emoji(self, severity: Severity) -> str:
        """Get emoji for severity level"""
        emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵",
        }
        return emojis.get(severity, "⚪")

    def _get_badge_color(self, severity: Severity) -> str:
        """Get shields.io color for severity"""
        colors = {
            Severity.CRITICAL: "7b241c",
            Severity.HIGH: "c0392b",
            Severity.MEDIUM: "e67e22",
            Severity.LOW: "f1c40f",
            Severity.INFO: "3498db",
        }
        return colors.get(severity, "95a5a6")

    def _format_finding(self, finding: Finding, config) -> list:
        """Format a single finding as Markdown"""
        lines = []

        # Title with anchor
        anchor = finding.title.lower().replace(" ", "-").replace(".", "")
        lines.append(f"#### {finding.title}")
        lines.append("")

        # Metadata table
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| **ID** | {finding.id} |")
        lines.append(f"| **Severity** | {finding.severity.value.upper()} |")
        lines.append(f"| **Target** | {finding.target} |")

        if finding.cvss_score:
            lines.append(f"| **CVSS Score** | {finding.cvss_score} |")
        if finding.cvss_vector:
            lines.append(f"| **CVSS Vector** | `{finding.cvss_vector}` |")
        if finding.port:
            lines.append(f"| **Port** | {finding.port} |")
        if finding.service:
            lines.append(f"| **Service** | {finding.service} |")
        if finding.module_name:
            lines.append(f"| **Module** | {finding.module_name} |")
        lines.append(f"| **Status** | {finding.status.value} |")
        lines.append("")

        # Description
        lines.append("**Description:**")
        lines.append("")
        lines.append(finding.description)
        lines.append("")

        # Impact
        if finding.impact:
            lines.append("**Impact:**")
            lines.append("")
            lines.append(finding.impact)
            lines.append("")

        # Remediation
        if finding.remediation:
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(finding.remediation)
            lines.append("")

        # CVEs
        if finding.cve_ids:
            lines.append("**CVE References:**")
            lines.append("")
            for cve in finding.cve_ids:
                lines.append(f"- [{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
            lines.append("")

        # CWEs
        if finding.cwe_ids:
            lines.append("**CWE References:**")
            lines.append("")
            for cwe in finding.cwe_ids:
                cwe_num = cwe.replace("CWE-", "")
                lines.append(f"- [{cwe}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
            lines.append("")

        # MITRE ATT&CK
        if finding.mitre_tactics or finding.mitre_techniques:
            lines.append("**MITRE ATT&CK Mapping:**")
            lines.append("")
            if finding.mitre_tactics:
                lines.append(f"- Tactics: {', '.join(finding.mitre_tactics)}")
            if finding.mitre_techniques:
                lines.append(f"- Techniques: {', '.join(finding.mitre_techniques)}")
            lines.append("")

        # References
        if finding.references:
            lines.append("**References:**")
            lines.append("")
            for ref in finding.references:
                lines.append(f"- <{ref}>")
            lines.append("")

        # Raw output
        if config.include_raw_output and finding.raw_output:
            lines.append("<details>")
            lines.append("<summary>Raw Output</summary>")
            lines.append("")
            lines.append("```")
            lines.append(finding.raw_output)
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")

        # Evidence
        if config.include_evidence and finding.evidence:
            lines.append("**Evidence:**")
            lines.append("")
            for evidence in finding.evidence:
                if evidence.description:
                    lines.append(f"*{evidence.description}*")
                if evidence.content:
                    lines.append("```")
                    lines.append(evidence.content)
                    lines.append("```")
                if evidence.file_path:
                    lines.append(f"File: `{evidence.file_path}`")
                lines.append("")

        lines.append("---")

        return lines
