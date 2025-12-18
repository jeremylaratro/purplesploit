"""
WPScan Module

WordPress security scanner for vulnerability detection and enumeration.
"""

from purplesploit.core.module import ExternalToolModule
from typing import List, Dict, Any
import json
import re


class WPScanModule(ExternalToolModule):
    """
    WPScan - WordPress Security Scanner.

    Scans WordPress installations for vulnerabilities, plugin enumeration,
    user enumeration, and configuration issues.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "wpscan"

    @property
    def name(self) -> str:
        return "WPScan"

    @property
    def description(self) -> str:
        return "WordPress security scanner for vulnerabilities and enumeration"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "web"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "URL": {
                "value": None,
                "required": True,
                "description": "Target WordPress URL",
                "default": None
            },
            "API_TOKEN": {
                "value": None,
                "required": False,
                "description": "WPScan API token for vulnerability data",
                "default": None
            },
            "ENUMERATE": {
                "value": "vp,vt,u",
                "required": False,
                "description": "Enumeration options (vp,ap,p,vt,at,t,tt,cb,dbe,u,m)",
                "default": "vp,vt,u"
            },
            "PLUGINS_DETECTION": {
                "value": "mixed",
                "required": False,
                "description": "Plugin detection mode (passive, aggressive, mixed)",
                "default": "mixed"
            },
            "USERLIST": {
                "value": None,
                "required": False,
                "description": "Path to username list for brute force",
                "default": None
            },
            "PASSLIST": {
                "value": None,
                "required": False,
                "description": "Path to password list for brute force",
                "default": None
            },
            "USERNAME": {
                "value": None,
                "required": False,
                "description": "Single username for brute force",
                "default": None
            },
            "PASSWORD": {
                "value": None,
                "required": False,
                "description": "Single password to try",
                "default": None
            },
            "THREADS": {
                "value": "5",
                "required": False,
                "description": "Number of threads",
                "default": "5"
            },
            "USER_AGENT": {
                "value": None,
                "required": False,
                "description": "Custom User-Agent string",
                "default": None
            },
            "PROXY": {
                "value": None,
                "required": False,
                "description": "Proxy URL (e.g., http://127.0.0.1:8080)",
                "default": None
            },
            "RANDOM_USER_AGENT": {
                "value": "true",
                "required": False,
                "description": "Use random User-Agent",
                "default": "true"
            },
            "FORCE": {
                "value": "false",
                "required": False,
                "description": "Force scan even if WordPress not detected",
                "default": "false"
            },
            "STEALTHY": {
                "value": "false",
                "required": False,
                "description": "Stealthy mode (random UA, passive detection)",
                "default": "false"
            },
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get available WPScan operations."""
        return [
            {
                "name": "Full Scan",
                "description": "Comprehensive WordPress scan with enumeration",
                "handler": self.op_full_scan
            },
            {
                "name": "Enumerate Users",
                "description": "Enumerate WordPress users",
                "handler": self.op_enum_users
            },
            {
                "name": "Enumerate Plugins",
                "description": "Enumerate installed plugins",
                "handler": self.op_enum_plugins
            },
            {
                "name": "Enumerate Themes",
                "description": "Enumerate installed themes",
                "handler": self.op_enum_themes
            },
            {
                "name": "Vulnerability Scan",
                "description": "Scan for known vulnerabilities",
                "handler": self.op_vuln_scan
            },
            {
                "name": "Password Attack",
                "description": "Brute force WordPress login",
                "handler": self.op_password_attack
            },
            {
                "name": "Stealthy Scan",
                "description": "Low-profile passive scan",
                "handler": self.op_stealthy_scan
            },
        ]

    def build_command(self) -> str:
        """Build the wpscan command."""
        return self._build_full_scan_command()

    def _build_base_command(self) -> str:
        """Build base command with common options."""
        url = self.get_option("URL")
        api_token = self.get_option("API_TOKEN")
        threads = self.get_option("THREADS")
        user_agent = self.get_option("USER_AGENT")
        proxy = self.get_option("PROXY")
        random_ua = self.get_option("RANDOM_USER_AGENT")
        force = self.get_option("FORCE")

        cmd = f"wpscan --url {url}"

        # API token
        if api_token:
            cmd += f" --api-token {api_token}"

        # Threads
        if threads:
            cmd += f" -t {threads}"

        # User agent
        if user_agent:
            cmd += f" --user-agent '{user_agent}'"
        elif random_ua and random_ua.lower() == "true":
            cmd += " --random-user-agent"

        # Proxy
        if proxy:
            cmd += f" --proxy {proxy}"

        # Force
        if force and force.lower() == "true":
            cmd += " --force"

        # JSON output for parsing
        cmd += " --format json"

        return cmd

    def _build_full_scan_command(self) -> str:
        """Build full scan command."""
        cmd = self._build_base_command()
        enumerate = self.get_option("ENUMERATE")
        plugins_detection = self.get_option("PLUGINS_DETECTION")

        if enumerate:
            cmd += f" -e {enumerate}"

        if plugins_detection:
            cmd += f" --plugins-detection {plugins_detection}"

        return cmd

    def _build_enum_users_command(self) -> str:
        """Build user enumeration command."""
        cmd = self._build_base_command()
        cmd += " -e u"
        return cmd

    def _build_enum_plugins_command(self) -> str:
        """Build plugin enumeration command."""
        cmd = self._build_base_command()
        plugins_detection = self.get_option("PLUGINS_DETECTION")

        cmd += " -e ap"  # All plugins

        if plugins_detection:
            cmd += f" --plugins-detection {plugins_detection}"

        return cmd

    def _build_enum_themes_command(self) -> str:
        """Build theme enumeration command."""
        cmd = self._build_base_command()
        cmd += " -e at"  # All themes
        return cmd

    def _build_vuln_scan_command(self) -> str:
        """Build vulnerability scan command."""
        cmd = self._build_base_command()
        cmd += " -e vp,vt"  # Vulnerable plugins and themes
        return cmd

    def _build_password_attack_command(self) -> str:
        """Build password attack command."""
        cmd = self._build_base_command()
        userlist = self.get_option("USERLIST")
        passlist = self.get_option("PASSLIST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")

        # Users
        if userlist:
            cmd += f" -U {userlist}"
        elif username:
            cmd += f" -U {username}"
        else:
            cmd += " -e u"  # Enumerate users first

        # Passwords
        if passlist:
            cmd += f" -P {passlist}"
        elif password:
            cmd += f" -P <(echo '{password}')"
        else:
            return "echo 'Error: PASSLIST or PASSWORD required for password attack'"

        return cmd

    def _build_stealthy_scan_command(self) -> str:
        """Build stealthy scan command."""
        cmd = self._build_base_command()
        cmd += " --stealthy"
        cmd += " -e vp,vt,u"
        return cmd

    def op_full_scan(self) -> Dict[str, Any]:
        """Perform comprehensive WordPress scan."""
        cmd = self._build_full_scan_command()
        result = self.execute_command(cmd, timeout=600)

        if result.get("success"):
            parsed = self._parse_json_output(result.get("output", ""))
            result["parsed"] = parsed
            result["message"] = self._generate_summary(parsed)

            # Add discovered users to session
            for user in parsed.get("users", []):
                self._add_credential(user.get("username"))

        return result

    def op_enum_users(self) -> Dict[str, Any]:
        """Enumerate WordPress users."""
        cmd = self._build_enum_users_command()
        result = self.execute_command(cmd)

        if result.get("success"):
            parsed = self._parse_json_output(result.get("output", ""))
            result["parsed"] = parsed
            users = parsed.get("users", [])
            result["message"] = f"Found {len(users)} users"

            for user in users:
                self._add_credential(user.get("username"))

        return result

    def op_enum_plugins(self) -> Dict[str, Any]:
        """Enumerate installed plugins."""
        cmd = self._build_enum_plugins_command()
        result = self.execute_command(cmd, timeout=600)

        if result.get("success"):
            parsed = self._parse_json_output(result.get("output", ""))
            result["parsed"] = parsed
            plugins = parsed.get("plugins", [])
            vuln_plugins = [p for p in plugins if p.get("vulnerabilities")]
            result["message"] = f"Found {len(plugins)} plugins, {len(vuln_plugins)} vulnerable"

        return result

    def op_enum_themes(self) -> Dict[str, Any]:
        """Enumerate installed themes."""
        cmd = self._build_enum_themes_command()
        result = self.execute_command(cmd)

        if result.get("success"):
            parsed = self._parse_json_output(result.get("output", ""))
            result["parsed"] = parsed
            themes = parsed.get("themes", [])
            result["message"] = f"Found {len(themes)} themes"

        return result

    def op_vuln_scan(self) -> Dict[str, Any]:
        """Scan for known vulnerabilities."""
        cmd = self._build_vuln_scan_command()
        result = self.execute_command(cmd, timeout=600)

        if result.get("success"):
            parsed = self._parse_json_output(result.get("output", ""))
            result["parsed"] = parsed

            vuln_count = 0
            for plugin in parsed.get("plugins", []):
                vuln_count += len(plugin.get("vulnerabilities", []))
            for theme in parsed.get("themes", []):
                vuln_count += len(theme.get("vulnerabilities", []))

            result["message"] = f"Found {vuln_count} vulnerabilities"

            # Add findings to session
            self._add_vulnerabilities(parsed)

        return result

    def op_password_attack(self) -> Dict[str, Any]:
        """Brute force WordPress login."""
        cmd = self._build_password_attack_command()
        result = self.execute_command(cmd, timeout=1800)  # 30 min timeout

        if result.get("success"):
            parsed = self._parse_json_output(result.get("output", ""))
            result["parsed"] = parsed

            valid_creds = parsed.get("password_attack", {}).get("found", [])
            result["message"] = f"Found {len(valid_creds)} valid credentials"

            for cred in valid_creds:
                self._add_credential(cred.get("username"), cred.get("password"))

        return result

    def op_stealthy_scan(self) -> Dict[str, Any]:
        """Perform stealthy low-profile scan."""
        cmd = self._build_stealthy_scan_command()
        result = self.execute_command(cmd)

        if result.get("success"):
            parsed = self._parse_json_output(result.get("output", ""))
            result["parsed"] = parsed
            result["message"] = self._generate_summary(parsed)

        return result

    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """Parse WPScan JSON output."""
        # Try to find JSON in output
        try:
            # Find JSON block
            json_start = output.find('{')
            if json_start != -1:
                json_str = output[json_start:]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Fall back to text parsing
        return self._parse_text_output(output)

    def _parse_text_output(self, output: str) -> Dict[str, Any]:
        """Parse WPScan text output."""
        result = {
            "wordpress": {},
            "users": [],
            "plugins": [],
            "themes": [],
            "vulnerabilities": []
        }

        current_section = None

        for line in output.split('\n'):
            line = line.strip()

            # Detect sections
            if "WordPress version" in line:
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', line)
                if version_match:
                    result["wordpress"]["version"] = version_match.group(1)

            elif "User(s) Identified" in line:
                current_section = "users"

            elif "Plugin(s) Identified" in line:
                current_section = "plugins"

            elif "Theme(s) Identified" in line:
                current_section = "themes"

            elif "[!]" in line:  # Vulnerability indicator
                result["vulnerabilities"].append(line)

            # Extract data based on section
            elif current_section == "users" and line.startswith("[+]"):
                username = line.replace("[+]", "").strip()
                if username:
                    result["users"].append({"username": username})

            elif current_section == "plugins" and line.startswith("[+]"):
                plugin_name = line.replace("[+]", "").strip()
                if plugin_name:
                    result["plugins"].append({"name": plugin_name})

            elif current_section == "themes" and line.startswith("[+]"):
                theme_name = line.replace("[+]", "").strip()
                if theme_name:
                    result["themes"].append({"name": theme_name})

        return result

    def _generate_summary(self, parsed: Dict[str, Any]) -> str:
        """Generate scan summary."""
        parts = []

        wp_version = parsed.get("wordpress", {}).get("version")
        if wp_version:
            parts.append(f"WordPress {wp_version}")

        users = len(parsed.get("users", []))
        if users:
            parts.append(f"{users} users")

        plugins = len(parsed.get("plugins", []))
        if plugins:
            parts.append(f"{plugins} plugins")

        themes = len(parsed.get("themes", []))
        if themes:
            parts.append(f"{themes} themes")

        vulns = len(parsed.get("vulnerabilities", []))
        if vulns:
            parts.append(f"{vulns} vulnerabilities")

        return "Found: " + ", ".join(parts) if parts else "Scan complete"

    def _add_credential(self, username: str, password: str = None):
        """Add discovered credential to session."""
        if not username:
            return

        if self.framework and hasattr(self.framework, 'session'):
            try:
                url = self.get_option("URL")
                cred_data = {
                    'username': username,
                    'service': 'wordpress',
                    'url': url,
                    'source': 'wpscan'
                }
                if password:
                    cred_data['password'] = password

                self.framework.session.credentials.add(cred_data)
            except Exception:
                pass

    def _add_vulnerabilities(self, parsed: Dict[str, Any]):
        """Add discovered vulnerabilities to session."""
        if not self.framework or not hasattr(self.framework, 'session'):
            return

        url = self.get_option("URL")

        # Add plugin vulnerabilities
        for plugin in parsed.get("plugins", []):
            for vuln in plugin.get("vulnerabilities", []):
                try:
                    self.framework.session.add_finding({
                        'type': 'vulnerability',
                        'title': vuln.get("title", "WordPress Plugin Vulnerability"),
                        'target': url,
                        'component': plugin.get("name"),
                        'severity': vuln.get("severity", "unknown"),
                        'cve': vuln.get("cve"),
                        'source': 'wpscan'
                    })
                except Exception:
                    pass

        # Add theme vulnerabilities
        for theme in parsed.get("themes", []):
            for vuln in theme.get("vulnerabilities", []):
                try:
                    self.framework.session.add_finding({
                        'type': 'vulnerability',
                        'title': vuln.get("title", "WordPress Theme Vulnerability"),
                        'target': url,
                        'component': theme.get("name"),
                        'severity': vuln.get("severity", "unknown"),
                        'cve': vuln.get("cve"),
                        'source': 'wpscan'
                    })
                except Exception:
                    pass

    def parse_output(self, output: str) -> dict:
        """Parse wpscan output."""
        return self._parse_json_output(output)

    def run(self) -> Dict[str, Any]:
        """Default run performs full scan."""
        return self.op_full_scan()
