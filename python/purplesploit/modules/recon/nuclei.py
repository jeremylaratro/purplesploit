"""
Nuclei Module

Template-based vulnerability scanning using Project Discovery's Nuclei.
Supports 8000+ community templates for comprehensive vulnerability detection.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime
import json
import re


class NucleiModule(ExternalToolModule):
    """
    Nuclei vulnerability scanner module.

    Provides template-based scanning with filtering by severity, type, and tags.
    Supports custom templates and automatic finding import.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nuclei"

    @property
    def name(self) -> str:
        return "Nuclei"

    @property
    def description(self) -> str:
        return "Template-based vulnerability scanning with 8000+ templates"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "recon"

    def _init_options(self):
        """Initialize nuclei-specific options."""
        self.options = {
            "TARGET": {
                "value": None,
                "required": True,
                "description": "Target URL, IP, or file with targets",
                "default": None
            },
            "TEMPLATES": {
                "value": None,
                "required": False,
                "description": "Specific template or directory to use",
                "default": None
            },
            "SEVERITY": {
                "value": None,
                "required": False,
                "description": "Filter by severity (critical,high,medium,low,info)",
                "default": None
            },
            "TAGS": {
                "value": None,
                "required": False,
                "description": "Filter templates by tags (e.g., cve,rce,sqli)",
                "default": None
            },
            "EXCLUDE_TAGS": {
                "value": None,
                "required": False,
                "description": "Exclude templates with these tags",
                "default": None
            },
            "RATE_LIMIT": {
                "value": 150,
                "required": False,
                "description": "Maximum requests per second",
                "default": 150
            },
            "CONCURRENCY": {
                "value": 25,
                "required": False,
                "description": "Number of concurrent templates to run",
                "default": 25
            },
            "TIMEOUT": {
                "value": 10,
                "required": False,
                "description": "Timeout for each request in seconds",
                "default": 10
            },
            "RETRIES": {
                "value": 1,
                "required": False,
                "description": "Number of retries for failed requests",
                "default": 1
            },
            "PROXY": {
                "value": None,
                "required": False,
                "description": "HTTP proxy (e.g., http://127.0.0.1:8080)",
                "default": None
            },
            "HEADERS": {
                "value": None,
                "required": False,
                "description": "Custom headers (e.g., 'Authorization: Bearer token')",
                "default": None
            },
            "OUTPUT_FORMAT": {
                "value": "json",
                "required": False,
                "description": "Output format (json, jsonl, csv)",
                "default": "json"
            },
        }

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of nuclei scan operations."""
        return [
            # Severity-based scans
            {
                "name": "Full Scan",
                "description": "Run all templates (comprehensive)",
                "handler": "op_full_scan",
                "subcategory": "severity"
            },
            {
                "name": "Critical/High Only",
                "description": "Only critical and high severity templates",
                "handler": "op_critical_high",
                "subcategory": "severity"
            },
            {
                "name": "Quick Scan",
                "description": "Fast scan with critical templates only",
                "handler": "op_quick_scan",
                "subcategory": "severity"
            },
            # Type-based scans
            {
                "name": "CVE Scan",
                "description": "Scan for known CVEs",
                "handler": "op_cve_scan",
                "subcategory": "type"
            },
            {
                "name": "Technology Detection",
                "description": "Detect technologies and versions",
                "handler": "op_tech_detect",
                "subcategory": "type"
            },
            {
                "name": "Exposed Panels",
                "description": "Find exposed admin panels and dashboards",
                "handler": "op_exposed_panels",
                "subcategory": "type"
            },
            {
                "name": "Takeover Detection",
                "description": "Subdomain takeover vulnerabilities",
                "handler": "op_takeover",
                "subcategory": "type"
            },
            {
                "name": "Misconfiguration Scan",
                "description": "Find misconfigurations",
                "handler": "op_misconfig",
                "subcategory": "type"
            },
            # Specialized scans
            {
                "name": "Network Scan",
                "description": "Network service vulnerabilities",
                "handler": "op_network_scan",
                "subcategory": "specialized"
            },
            {
                "name": "API Security",
                "description": "API-specific vulnerability templates",
                "handler": "op_api_scan",
                "subcategory": "specialized"
            },
            {
                "name": "Default Credentials",
                "description": "Check for default login credentials",
                "handler": "op_default_creds",
                "subcategory": "specialized"
            },
            {
                "name": "Custom Templates",
                "description": "Use custom template path",
                "handler": "op_custom_templates",
                "subcategory": "specialized"
            },
            # Background
            {
                "name": "Background Full Scan",
                "description": "Run full scan in background",
                "handler": "op_background_full",
                "subcategory": "background"
            },
        ]

    def _get_target(self) -> str:
        """Get target from options or context."""
        target = self.get_option("TARGET")
        if target:
            return target

        # Try to get from framework context
        self.auto_set_from_context()
        context = self.get_context()

        if context.get('current_target'):
            t = context['current_target']
            if isinstance(t, dict):
                target = t.get('ip') or t.get('url')
            else:
                target = t

            if target:
                self.set_option("TARGET", target)
                return target

        return None

    def _build_base_command(self) -> str:
        """Build base nuclei command with common options."""
        target = self._get_target()
        if not target:
            return None

        cmd_parts = ["nuclei"]

        # Target - check if file or single target
        if Path(target).is_file():
            cmd_parts.append(f"-l '{target}'")
        else:
            cmd_parts.append(f"-u '{target}'")

        # Rate limiting
        rate_limit = self.get_option("RATE_LIMIT")
        if rate_limit:
            cmd_parts.append(f"-rl {rate_limit}")

        # Concurrency
        concurrency = self.get_option("CONCURRENCY")
        if concurrency:
            cmd_parts.append(f"-c {concurrency}")

        # Timeout
        timeout = self.get_option("TIMEOUT")
        if timeout:
            cmd_parts.append(f"-timeout {timeout}")

        # Retries
        retries = self.get_option("RETRIES")
        if retries:
            cmd_parts.append(f"-retries {retries}")

        # Proxy
        proxy = self.get_option("PROXY")
        if proxy:
            cmd_parts.append(f"-proxy '{proxy}'")

        # Headers
        headers = self.get_option("HEADERS")
        if headers:
            cmd_parts.append(f"-H '{headers}'")

        return " ".join(cmd_parts)

    def _execute_nuclei(
        self,
        extra_args: str = "",
        run_background: bool = False,
        scan_name: str = "nuclei"
    ) -> Dict[str, Any]:
        """
        Execute nuclei with specified arguments.

        Args:
            extra_args: Additional nuclei arguments
            run_background: Run in background
            scan_name: Name for logging/database

        Returns:
            Execution result dictionary
        """
        base_cmd = self._build_base_command()
        if not base_cmd:
            return {"success": False, "error": "TARGET required"}

        # Create output directory
        log_dir = Path.home() / ".purplesploit" / "logs" / "nuclei"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = self._get_target()
        safe_target = re.sub(r'[:/\\]', '_', target)[:50]
        output_file = log_dir / f"nuclei_{safe_target}_{scan_name}_{timestamp}.json"

        # Build full command
        cmd = f"{base_cmd} {extra_args} -json -o '{output_file}'"

        self.log(f"Starting nuclei {scan_name} scan", "info")
        self.log(f"Output: {output_file}", "info")

        if run_background:
            result = self.execute_command(cmd, background=True, timeout=3600)
            if result.get('success'):
                result['output_file'] = str(output_file)
                result['message'] = f"Scan running in background (PID: {result.get('pid')})"
                # Store scan info
                self.framework.database.save_scan_results(
                    scan_name="nuclei",
                    target=target,
                    scan_type="vuln",
                    results={"status": "running", "pid": result.get('pid')},
                    file_path=str(output_file)
                )
        else:
            result = self.execute_command(cmd, timeout=3600)
            if result.get('success') and output_file.exists():
                parsed = self._parse_results(output_file)
                result['findings'] = parsed['findings']
                result['summary'] = parsed['summary']
                result['output_file'] = str(output_file)

                # Import findings to database
                self._import_findings(parsed['findings'], target)

                # Store scan results
                self.framework.database.save_scan_results(
                    scan_name="nuclei",
                    target=target,
                    scan_type="vuln",
                    results=parsed,
                    file_path=str(output_file)
                )

                self.log(f"Found {len(parsed['findings'])} vulnerabilities", "success")

        return result

    def _parse_results(self, output_file: Path) -> Dict[str, Any]:
        """Parse nuclei JSON output."""
        findings = []
        summary = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        findings.append(finding)

                        # Count by severity
                        severity = finding.get('info', {}).get('severity', 'info').lower()
                        if severity in summary:
                            summary[severity] += 1
                        summary['total'] += 1

                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            self.log(f"Error parsing results: {e}", "error")

        return {"findings": findings, "summary": summary}

    def _import_findings(self, findings: List[Dict], target: str):
        """Import nuclei findings to the reporting module."""
        try:
            from purplesploit.reporting import ReportGenerator, Severity

            # Get or create report generator on framework
            if not hasattr(self.framework, 'report_generator'):
                self.framework.report_generator = ReportGenerator(self.framework)

            gen = self.framework.report_generator

            for finding in findings:
                info = finding.get('info', {})

                # Map nuclei severity to our severity
                sev_map = {
                    'critical': 'critical',
                    'high': 'high',
                    'medium': 'medium',
                    'low': 'low',
                    'info': 'info',
                }
                severity = sev_map.get(info.get('severity', 'info').lower(), 'info')

                # Extract CVE IDs
                cve_ids = []
                classification = info.get('classification', {})
                if classification.get('cve-id'):
                    cve_ids = classification['cve-id'] if isinstance(
                        classification['cve-id'], list
                    ) else [classification['cve-id']]

                # Create finding
                gen.create_finding(
                    title=info.get('name', 'Unknown Vulnerability'),
                    severity=severity,
                    description=info.get('description', ''),
                    target=finding.get('host', target),
                    cvss_score=classification.get('cvss-score'),
                    cve_ids=cve_ids,
                    cwe_ids=classification.get('cwe-id', []),
                    remediation=info.get('remediation', ''),
                    references=info.get('reference', []),
                    module_name="nuclei",
                    raw_output=finding.get('matched-at', ''),
                    notes=f"Template: {finding.get('template-id', 'unknown')}",
                )

            self.log(f"Imported {len(findings)} findings to report generator", "info")

        except ImportError:
            self.log("Reporting module not available for finding import", "warning")
        except Exception as e:
            self.log(f"Error importing findings: {e}", "error")

    # ========================================================================
    # Operation Handlers
    # ========================================================================

    def op_full_scan(self) -> Dict[str, Any]:
        """Run full scan with all templates."""
        self.log("Running full vulnerability scan (this may take a while)", "info")
        return self._execute_nuclei(scan_name="full")

    def op_critical_high(self) -> Dict[str, Any]:
        """Scan with only critical and high severity templates."""
        self.log("Running critical/high severity scan", "info")
        return self._execute_nuclei("-s critical,high", scan_name="critical-high")

    def op_quick_scan(self) -> Dict[str, Any]:
        """Quick scan with critical templates only."""
        self.log("Running quick critical-only scan", "info")
        return self._execute_nuclei("-s critical", scan_name="quick")

    def op_cve_scan(self) -> Dict[str, Any]:
        """Scan for known CVEs."""
        self.log("Scanning for known CVEs", "info")
        return self._execute_nuclei("-tags cve", scan_name="cve")

    def op_tech_detect(self) -> Dict[str, Any]:
        """Technology detection scan."""
        self.log("Running technology detection", "info")
        return self._execute_nuclei("-tags tech", scan_name="tech-detect")

    def op_exposed_panels(self) -> Dict[str, Any]:
        """Find exposed admin panels."""
        self.log("Scanning for exposed panels", "info")
        return self._execute_nuclei("-tags panel,login,admin", scan_name="panels")

    def op_takeover(self) -> Dict[str, Any]:
        """Subdomain takeover detection."""
        self.log("Scanning for subdomain takeover vulnerabilities", "info")
        return self._execute_nuclei("-tags takeover", scan_name="takeover")

    def op_misconfig(self) -> Dict[str, Any]:
        """Misconfiguration detection."""
        self.log("Scanning for misconfigurations", "info")
        return self._execute_nuclei("-tags misconfig,exposure", scan_name="misconfig")

    def op_network_scan(self) -> Dict[str, Any]:
        """Network service vulnerability scan."""
        self.log("Scanning network services", "info")
        return self._execute_nuclei("-tags network", scan_name="network")

    def op_api_scan(self) -> Dict[str, Any]:
        """API security scan."""
        self.log("Scanning for API vulnerabilities", "info")
        return self._execute_nuclei("-tags api", scan_name="api")

    def op_default_creds(self) -> Dict[str, Any]:
        """Default credentials check."""
        self.log("Checking for default credentials", "info")
        return self._execute_nuclei("-tags default-login", scan_name="default-creds")

    def op_custom_templates(self) -> Dict[str, Any]:
        """Use custom template path."""
        templates = self.get_option("TEMPLATES")
        if not templates:
            templates = input("Template path or directory: ")
            if not templates:
                return {"success": False, "error": "Template path required"}

        if not Path(templates).exists():
            return {"success": False, "error": f"Template not found: {templates}"}

        self.log(f"Running custom templates from: {templates}", "info")
        return self._execute_nuclei(f"-t '{templates}'", scan_name="custom")

    def op_background_full(self) -> Dict[str, Any]:
        """Run full scan in background."""
        self.log("Starting full scan in background", "info")
        return self._execute_nuclei(run_background=True, scan_name="full-bg")

    def run(self) -> Dict[str, Any]:
        """Default run - critical/high severity scan."""
        return self.op_critical_high()

    def build_command(self) -> str:
        """Build default command for preview."""
        base = self._build_base_command()
        if base:
            return f"{base} -s critical,high -json"
        return ""
