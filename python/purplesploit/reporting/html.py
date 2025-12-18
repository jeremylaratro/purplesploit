"""
HTML Report Generator for PurpleSploit.

Generates interactive HTML reports with filtering and search capabilities.
"""

from pathlib import Path
from typing import Optional
from datetime import datetime

# Jinja2 is optional - use built-in string formatting as fallback
try:
    from jinja2 import Environment, select_autoescape, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

from .models import ReportData, Severity


class HTMLReportGenerator:
    """Generates HTML reports from ReportData"""

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize HTML generator.

        Args:
            template_dir: Optional custom template directory
        """
        self.env = None
        self.template_dir = template_dir

        if JINJA2_AVAILABLE:
            if template_dir:
                self.env = Environment(
                    loader=FileSystemLoader(template_dir),
                    autoescape=select_autoescape(['html', 'xml'])
                )
            else:
                # Use built-in templates
                self.env = Environment(
                    loader=FileSystemLoader(
                        Path(__file__).parent / "templates"
                    ),
                    autoescape=select_autoescape(['html', 'xml'])
                )

            # Register custom filters
            self.env.filters['severity_color'] = self._severity_color
            self.env.filters['severity_badge'] = self._severity_badge
            self.env.filters['format_datetime'] = self._format_datetime

    def _severity_color(self, severity: Severity) -> str:
        """Get color for severity level"""
        colors = {
            Severity.CRITICAL: "#7b241c",
            Severity.HIGH: "#c0392b",
            Severity.MEDIUM: "#e67e22",
            Severity.LOW: "#f1c40f",
            Severity.INFO: "#3498db",
        }
        return colors.get(severity, "#95a5a6")

    def _severity_badge(self, severity: Severity) -> str:
        """Get badge HTML for severity"""
        color = self._severity_color(severity)
        return f'<span class="badge" style="background-color: {color}">{severity.value.upper()}</span>'

    def _format_datetime(self, dt: datetime, fmt: str = "%Y-%m-%d %H:%M") -> str:
        """Format datetime for display"""
        if not dt:
            return ""
        return dt.strftime(fmt)

    def generate(
        self,
        report_data: ReportData,
        output_path: Path,
        standalone: bool = True,
        **kwargs
    ) -> str:
        """
        Generate HTML report.

        Args:
            report_data: Report data to render
            output_path: Output file path
            standalone: If True, embed CSS/JS in HTML
            **kwargs: Additional template variables

        Returns:
            Path to generated report
        """
        # If jinja2 not available, use simple string-based generation
        if not JINJA2_AVAILABLE or self.env is None:
            return self._generate_simple(report_data, output_path, **kwargs)

        # Get template
        template_name = report_data.config.template_name or "default"
        try:
            template = self.env.get_template(f"{template_name}.html")
        except Exception:
            # Fall back to inline template
            template = self.env.from_string(self._get_default_template())

        # Filter findings based on config
        filtered_findings = report_data.filter_findings(report_data.config)

        # Build template context
        context = {
            "config": report_data.config,
            "findings": filtered_findings,
            "findings_by_severity": report_data.findings_by_severity,
            "findings_by_target": report_data.findings_by_target,
            "severity_counts": report_data.severity_counts,
            "statistics": {
                "total": report_data.total_findings,
                "critical": report_data.critical_count,
                "high": report_data.high_count,
                "unique_targets": report_data.unique_targets,
            },
            "targets": report_data.targets,
            "services": report_data.services,
            "credentials": report_data.credentials,
            "generated_at": datetime.now(),
            "standalone": standalone,
            "Severity": Severity,
            **kwargs
        }

        # Render template
        html_content = template.render(**context)

        # Write output
        output_path = Path(output_path)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(output_path)

    def _generate_simple(
        self,
        report_data: ReportData,
        output_path: Path,
        **kwargs
    ) -> str:
        """
        Generate HTML report without Jinja2 using simple string formatting.

        This is a fallback when Jinja2 is not installed.
        """
        filtered_findings = report_data.filter_findings(report_data.config)
        config = report_data.config

        # Build findings HTML
        findings_html = []
        for finding in filtered_findings:
            finding_html = f'''
            <div class="finding {finding.severity.value}">
                <div class="finding-header">
                    <div class="finding-title">{self._escape_html(finding.title)}</div>
                    <span class="badge {finding.severity.value}">{finding.severity.value.upper()}</span>
                </div>
                <div class="finding-meta">
                    <span>Target: {self._escape_html(finding.target)}</span>
                    {f'<span>Port: {finding.port}</span>' if finding.port else ''}
                    {f'<span>Service: {self._escape_html(finding.service)}</span>' if finding.service else ''}
                    {f'<span>CVSS: {finding.cvss_score}</span>' if finding.cvss_score else ''}
                </div>
                <div class="finding-description">
                    <p>{self._escape_html(finding.description)}</p>
                </div>
                {f'<div class="detail-section"><h4>Impact</h4><p>{self._escape_html(finding.impact)}</p></div>' if finding.impact else ''}
                {f'<div class="detail-section"><h4>Remediation</h4><p>{self._escape_html(finding.remediation)}</p></div>' if finding.remediation else ''}
            </div>
            '''
            findings_html.append(finding_html)

        # Build the full HTML
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self._escape_html(config.title)}</title>
    <style>
        :root {{
            --critical: #7b241c;
            --high: #c0392b;
            --medium: #e67e22;
            --low: #f1c40f;
            --info: #3498db;
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: var(--bg-dark); color: var(--text-primary); line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; margin-bottom: 30px; }}
        header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: var(--bg-card); border-radius: 10px; padding: 20px; text-align: center; border-left: 4px solid var(--info); }}
        .stat-card.critical {{ border-left-color: var(--critical); }}
        .stat-card.high {{ border-left-color: var(--high); }}
        .stat-card.medium {{ border-left-color: var(--medium); }}
        .stat-card.low {{ border-left-color: var(--low); }}
        .stat-card .number {{ font-size: 2.5rem; font-weight: bold; }}
        .stat-card .label {{ font-size: 0.9rem; color: var(--text-secondary); text-transform: uppercase; }}
        .section {{ background: var(--bg-card); border-radius: 10px; padding: 25px; margin-bottom: 25px; }}
        .section h2 {{ font-size: 1.5rem; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #333; }}
        .finding {{ background: rgba(0,0,0,0.2); border-radius: 8px; padding: 20px; margin-bottom: 15px; border-left: 4px solid var(--info); }}
        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px; }}
        .finding-title {{ font-size: 1.2rem; font-weight: 600; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; color: white; }}
        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); }}
        .badge.low {{ background: var(--low); }}
        .badge.info {{ background: var(--info); }}
        .finding-meta {{ display: flex; gap: 20px; margin-bottom: 15px; font-size: 0.9rem; color: var(--text-secondary); }}
        .finding-description {{ margin-bottom: 15px; }}
        .detail-section h4 {{ font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 8px; text-transform: uppercase; }}
        footer {{ text-align: center; padding: 30px; color: var(--text-secondary); font-size: 0.9rem; }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>{self._escape_html(config.title)}</h1>
            {f'<p class="subtitle">{self._escape_html(config.subtitle)}</p>' if config.subtitle else ''}
        </div>
    </header>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card critical"><div class="number">{report_data.severity_counts.get('critical', 0)}</div><div class="label">Critical</div></div>
            <div class="stat-card high"><div class="number">{report_data.severity_counts.get('high', 0)}</div><div class="label">High</div></div>
            <div class="stat-card medium"><div class="number">{report_data.severity_counts.get('medium', 0)}</div><div class="label">Medium</div></div>
            <div class="stat-card low"><div class="number">{report_data.severity_counts.get('low', 0)}</div><div class="label">Low</div></div>
            <div class="stat-card"><div class="number">{report_data.total_findings}</div><div class="label">Total</div></div>
            <div class="stat-card"><div class="number">{report_data.unique_targets}</div><div class="label">Targets</div></div>
        </div>

        <div class="section">
            <h2>Security Findings</h2>
            {''.join(findings_html)}
        </div>
    </div>

    <footer>
        <p>Generated by PurpleSploit on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </footer>
</body>
</html>'''

        output_path = Path(output_path)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(output_path)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

    def _get_default_template(self) -> str:
        """Return default HTML template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ config.title }}</title>
    <style>
        :root {
            --critical: #7b241c;
            --high: #c0392b;
            --medium: #e67e22;
            --low: #f1c40f;
            --info: #3498db;
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --border-color: #333;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px 20px;
            margin-bottom: 30px;
        }

        header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .meta-item {
            background: rgba(255,255,255,0.1);
            padding: 10px 15px;
            border-radius: 5px;
        }

        .meta-item label {
            font-size: 0.8rem;
            text-transform: uppercase;
            opacity: 0.7;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid var(--info);
        }

        .stat-card.critical { border-left-color: var(--critical); }
        .stat-card.high { border-left-color: var(--high); }
        .stat-card.medium { border-left-color: var(--medium); }
        .stat-card.low { border-left-color: var(--low); }

        .stat-card .number {
            font-size: 2.5rem;
            font-weight: bold;
        }

        .stat-card .label {
            font-size: 0.9rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }

        .section {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
        }

        .section h2 {
            font-size: 1.5rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }

        .finding {
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--info);
        }

        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .finding-title {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }

        .badge.critical { background: var(--critical); }
        .badge.high { background: var(--high); }
        .badge.medium { background: var(--medium); }
        .badge.low { background: var(--low); }
        .badge.info { background: var(--info); }

        .finding-meta {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .finding-description {
            margin-bottom: 15px;
        }

        .finding-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }

        .detail-section h4 {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
            text-transform: uppercase;
        }

        .detail-section p, .detail-section ul {
            font-size: 0.95rem;
        }

        .detail-section ul {
            list-style: none;
            padding-left: 0;
        }

        .detail-section li {
            padding: 3px 0;
        }

        .detail-section li:before {
            content: "→ ";
            color: var(--info);
        }

        pre {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.85rem;
        }

        .evidence {
            margin-top: 15px;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 5px;
        }

        .evidence img {
            max-width: 100%;
            border-radius: 5px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background: rgba(0,0,0,0.2);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
        }

        tr:hover {
            background: rgba(255,255,255,0.02);
        }

        .filter-bar {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .filter-bar input, .filter-bar select {
            background: rgba(0,0,0,0.2);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 10px 15px;
            border-radius: 5px;
            font-size: 0.9rem;
        }

        .filter-bar input {
            flex: 1;
            min-width: 200px;
        }

        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        @media print {
            body {
                background: white;
                color: black;
            }

            .stat-card, .section, .finding {
                background: #f5f5f5;
                break-inside: avoid;
            }

            header {
                background: #333;
                -webkit-print-color-adjust: exact;
            }

            .filter-bar {
                display: none;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>{{ config.title }}</h1>
            {% if config.subtitle %}
            <p class="subtitle">{{ config.subtitle }}</p>
            {% endif %}
            <div class="meta-info">
                {% if config.client_name %}
                <div class="meta-item">
                    <label>Client</label>
                    <div>{{ config.client_name }}</div>
                </div>
                {% endif %}
                {% if config.assessor_name %}
                <div class="meta-item">
                    <label>Assessor</label>
                    <div>{{ config.assessor_name }}</div>
                </div>
                {% endif %}
                <div class="meta-item">
                    <label>Report Date</label>
                    <div>{{ config.report_date|format_datetime('%B %d, %Y') }}</div>
                </div>
                {% if config.start_date and config.end_date %}
                <div class="meta-item">
                    <label>Assessment Period</label>
                    <div>{{ config.start_date|format_datetime('%Y-%m-%d') }} - {{ config.end_date|format_datetime('%Y-%m-%d') }}</div>
                </div>
                {% endif %}
            </div>
        </div>
    </header>

    <div class="container">
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="number">{{ severity_counts.get('critical', 0) }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{{ severity_counts.get('high', 0) }}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{{ severity_counts.get('medium', 0) }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{{ severity_counts.get('low', 0) }}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ statistics.total }}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ statistics.unique_targets }}</div>
                <div class="label">Targets</div>
            </div>
        </div>

        {% if config.include_executive_summary %}
        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <p>
                This penetration test assessment identified <strong>{{ statistics.total }}</strong> security findings
                across <strong>{{ statistics.unique_targets }}</strong> target(s).
                {% if statistics.critical > 0 %}
                <strong style="color: var(--critical)">{{ statistics.critical }} critical</strong> and
                {% endif %}
                {% if statistics.high > 0 %}
                <strong style="color: var(--high)">{{ statistics.high }} high</strong>
                {% endif %}
                severity issues require immediate attention.
            </p>

            {% if config.scope %}
            <h3 style="margin-top: 20px; margin-bottom: 10px;">Scope</h3>
            <ul>
                {% for item in config.scope %}
                <li>{{ item }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endif %}

        {% if config.include_findings_detail %}
        <!-- Findings -->
        <div class="section">
            <h2>Security Findings</h2>

            <div class="filter-bar">
                <input type="text" id="searchInput" placeholder="Search findings..." onkeyup="filterFindings()">
                <select id="severityFilter" onchange="filterFindings()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
            </div>

            <div id="findingsList">
            {% for finding in findings %}
            <div class="finding {{ finding.severity.value }}" data-severity="{{ finding.severity.value }}">
                <div class="finding-header">
                    <div class="finding-title">{{ finding.title }}</div>
                    <span class="badge {{ finding.severity.value }}">{{ finding.severity.value }}</span>
                </div>

                <div class="finding-meta">
                    <span>Target: {{ finding.target }}</span>
                    {% if finding.port %}
                    <span>Port: {{ finding.port }}</span>
                    {% endif %}
                    {% if finding.service %}
                    <span>Service: {{ finding.service }}</span>
                    {% endif %}
                    {% if finding.cvss_score %}
                    <span>CVSS: {{ finding.cvss_score }}</span>
                    {% endif %}
                </div>

                <div class="finding-description">
                    <p>{{ finding.description }}</p>
                </div>

                <div class="finding-details">
                    {% if finding.impact %}
                    <div class="detail-section">
                        <h4>Impact</h4>
                        <p>{{ finding.impact }}</p>
                    </div>
                    {% endif %}

                    {% if finding.remediation %}
                    <div class="detail-section">
                        <h4>Remediation</h4>
                        <p>{{ finding.remediation }}</p>
                    </div>
                    {% endif %}

                    {% if finding.cve_ids %}
                    <div class="detail-section">
                        <h4>CVE References</h4>
                        <ul>
                        {% for cve in finding.cve_ids %}
                            <li>{{ cve }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}

                    {% if finding.references %}
                    <div class="detail-section">
                        <h4>References</h4>
                        <ul>
                        {% for ref in finding.references %}
                            <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>

                {% if config.include_raw_output and finding.raw_output %}
                <div class="evidence">
                    <h4>Raw Output</h4>
                    <pre>{{ finding.raw_output }}</pre>
                </div>
                {% endif %}

                {% if config.include_evidence and finding.evidence %}
                <div class="evidence">
                    <h4>Evidence</h4>
                    {% for evidence in finding.evidence %}
                    <div style="margin-bottom: 10px;">
                        <strong>{{ evidence.description }}</strong>
                        {% if evidence.content %}
                        <pre>{{ evidence.content }}</pre>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
            </div>
        </div>
        {% endif %}

        {% if config.include_appendix and (targets or services) %}
        <!-- Appendix -->
        <div class="section">
            <h2>Appendix</h2>

            {% if targets %}
            <h3 style="margin-bottom: 15px;">Targets</h3>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP/URL</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                {% for target in targets %}
                    <tr>
                        <td>{{ target.name }}</td>
                        <td>{{ target.ip or target.url }}</td>
                        <td>{{ target.description or '-' }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            {% endif %}

            {% if services %}
            <h3 style="margin: 25px 0 15px;">Discovered Services</h3>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                {% for service in services %}
                    <tr>
                        <td>{{ service.target }}</td>
                        <td>{{ service.port }}</td>
                        <td>{{ service.service }}</td>
                        <td>{{ service.version or '-' }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </div>
        {% endif %}
    </div>

    <footer>
        <p>Generated by PurpleSploit on {{ generated_at|format_datetime('%Y-%m-%d %H:%M:%S') }}</p>
        {% if config.company_name %}
        <p>{{ config.company_name }}{% if config.company_website %} | {{ config.company_website }}{% endif %}</p>
        {% endif %}
    </footer>

    <script>
        function filterFindings() {
            const searchText = document.getElementById('searchInput').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value;
            const findings = document.querySelectorAll('.finding');

            findings.forEach(finding => {
                const text = finding.textContent.toLowerCase();
                const severity = finding.dataset.severity;

                const matchesSearch = text.includes(searchText);
                const matchesSeverity = !severityFilter || severity === severityFilter;

                finding.style.display = matchesSearch && matchesSeverity ? 'block' : 'none';
            });
        }
    </script>
</body>
</html>'''
