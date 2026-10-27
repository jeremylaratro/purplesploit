"""
Nuclei Module

Template-based vulnerability scanning using Project Discovery's Nuclei.
Supports 8000+ community templates for comprehensive vulnerability detection.
"""

from purplesploit.web_observations import WebToolModule, json_records, observation
from typing import Dict, Any, List
from pathlib import Path
import shlex
from uuid import uuid4


class NucleiModule(WebToolModule):
    """
    Nuclei vulnerability scanner module.

    Provides template-based scanning with filtering by severity, type, and tags.
    Supports custom templates and automatic finding import.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nuclei"

    emits = ["finding"]
    supported_tool_versions = ["Nuclei 3.x (-jsonl)", "Nuclei 2.x (JSON_FLAG=-json)"]

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
            "JSON_FLAG": {
                "value": "-jsonl", "default": "-jsonl", "required": False,
                "description": "JSON output flag: -jsonl for current Nuclei; -json for legacy 2.x",
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

    def _build_base_argv(self):
        target = self._get_target()
        if not target:
            return []
        argv = ["nuclei", "-l" if Path(str(target)).is_file() else "-u", str(target)]
        for option, flag in (("RATE_LIMIT", "-rl"), ("CONCURRENCY", "-c"), ("TIMEOUT", "-timeout"),
                             ("RETRIES", "-retries"), ("PROXY", "-proxy"), ("HEADERS", "-H"),
                             ("TEMPLATES", "-t"), ("SEVERITY", "-s"), ("TAGS", "-tags"),
                             ("EXCLUDE_TAGS", "-etags")):
            value = self.get_option(option)
            if value is not None and value != "":
                argv.extend([flag, str(value)])
        return argv

    def _build_base_command(self):
        return shlex.join(self._build_base_argv())

    def _execute_nuclei(self, extra_args="", run_background=False, scan_name="nuclei"):
        argv = self._build_base_argv()
        if not argv:
            return {"success": False, "error": "TARGET required"}
        flag = self.get_option("JSON_FLAG") or "-jsonl"
        if flag not in {"-jsonl", "-json"}:
            return {"success": False, "error": "JSON_FLAG must be -jsonl or -json"}
        request = self.execution_request or getattr(self, "_execution_context_request", None)
        log_dir = Path(request.run_dir) if request and request.run_dir else Path.home() / ".purplesploit/logs/nuclei"
        log_dir.mkdir(parents=True, exist_ok=True)
        output_file = log_dir / f"nuclei_{scan_name}_{uuid4().hex}.jsonl"
        extra = shlex.split(extra_args) if isinstance(extra_args, str) else list(extra_args)
        result = self.execute_command([*argv, *extra, flag, "-silent", "-o", str(output_file)],
                                      background=run_background, timeout=3600)
        result["output_file"] = str(output_file)
        result["artifacts"] = [str(output_file)]
        if result.get("background"):
            return result
        parsed = self._parse_results(output_file) if output_file.exists() else self.parse_output(result.get("stdout", ""))
        result.update(parsed=parsed, findings=parsed["findings"], summary=parsed["summary"],
                      observations=parsed["observations"])
        if result.get("success"):
            self._import_findings(parsed["findings"], self._get_target())
        database = getattr(self.framework, "database", None)
        if database is not None:
            database.save_scan_results(scan_name="nuclei", target=self._get_target(), scan_type="vuln",
                                       results=parsed, file_path=str(output_file))
        return result

    def _parse_results(self, output_file):
        return self.parse_output(Path(output_file).read_text(errors="replace"))

    def parse_output(self, output):
        findings, errors = json_records(output)
        findings = [item for item in findings if item.get("template-id") or item.get("templateID") or item.get("info")]
        summary = dict.fromkeys(("total", "critical", "high", "medium", "low", "info", "unknown"), 0)
        observations = []
        finding_records = []
        for finding in findings:
            info = finding.get("info") or {}
            severity = str(info.get("severity", "info")).lower()
            summary[severity if severity in summary else "unknown"] += 1
            summary["total"] += 1
            url = finding.get("matched-at") or finding.get("matched") or finding.get("host") or self._get_target() or ""
            observations.append(observation("finding", url,
                title=info.get("name", finding.get("template-id", "Nuclei finding")),
                severity=severity, description=info.get("description", ""),
                template_id=finding.get("template-id", finding.get("templateID")),
                matcher_name=finding.get("matcher-name"), extracted_results=finding.get("extracted-results", []),
                classification=info.get("classification", {}), references=info.get("reference", []),
                matched_at=url, raw=finding, source="nuclei"))
            from purplesploit.core.findings import Finding, Severity
            finding_records.append(Finding(title=info.get("name", "Nuclei finding"),
                severity=Severity(severity if severity in {"critical", "high", "medium", "low", "info"} else "info"),
                description=info.get("description", ""), target=finding.get("host") or url,
                url=url, module_name="nuclei", raw_output=str(finding)).to_dict())
        return {"findings": findings, "finding_records": finding_records, "summary": summary,
                "observations": observations, "parse_errors": errors}

    def _import_findings(self, findings, target):
        """Use the existing lifecycle manager if present; observations always remain available."""
        manager = getattr(self.framework, "findings", None)
        if manager is None or not callable(getattr(manager, "create", None)):
            return
        for finding in findings:
            info = finding.get("info") or {}
            classification = info.get("classification") or {}
            severity = str(info.get("severity", "info")).lower()
            severity = severity if severity in {"critical", "high", "medium", "low", "info"} else "info"
            def values(key):
                value = classification.get(key) or []
                return [value] if isinstance(value, str) else value
            manager.create(title=info.get("name", "Nuclei finding"), severity=severity,
                description=info.get("description", ""), target=finding.get("host") or target,
                url=finding.get("matched-at"), cve_ids=values("cve-id"), cwe_ids=values("cwe-id"),
                cvss_score=classification.get("cvss-score"), remediation=info.get("remediation", ""),
                references=info.get("reference") or [], module_name="nuclei", raw_output=str(finding))

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
            return {"success": False, "error": "TEMPLATES required"}

        if not Path(templates).exists():
            return {"success": False, "error": f"Template not found: {templates}"}

        self.log(f"Running custom templates from: {templates}", "info")
        return self._execute_nuclei(scan_name="custom")

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
            return f"{base} -s critical,high {self.get_option('JSON_FLAG') or '-jsonl'}"
        return ""
