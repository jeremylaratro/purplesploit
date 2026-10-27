"""
SQLMap Module

Automatic SQL injection and database takeover tool.
"""

import re
import shlex
from urllib.parse import parse_qsl, urlsplit
from purplesploit.web_observations import WebToolModule, observation, strip_ansi


class SQLMapModule(WebToolModule):
    """
    SQLMap - Automatic SQL injection and database takeover tool.

    Detects and exploits SQL injection vulnerabilities.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "sqlmap"

    emits = ["parameter", "finding"]
    supported_tool_versions = ["sqlmap 1.x console injection summary"]

    @property
    def name(self) -> str:
        return "SQLMap"

    @property
    def description(self) -> str:
        return "Automatic SQL injection detection and exploitation tool"

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
                "description": "Target URL (e.g., http://target.com/page.php?id=1)",
                "default": None
            },
            "DATA": {
                "value": None,
                "required": False,
                "description": "POST data string",
                "default": None
            },
            "COOKIE": {
                "value": None,
                "required": False,
                "description": "HTTP Cookie header value",
                "default": None
            },
            "LEVEL": {
                "value": "1",
                "required": False,
                "description": "Level of tests to perform (1-5)",
                "default": "1"
            },
            "RISK": {
                "value": "1",
                "required": False,
                "description": "Risk of tests to perform (1-3)",
                "default": "1"
            },
            "DBS": {
                "value": "false",
                "required": False,
                "description": "Enumerate databases",
                "default": "false"
            },
            "TABLES": {
                "value": "false",
                "required": False,
                "description": "Enumerate tables",
                "default": "false"
            },
            "DUMP": {
                "value": "false",
                "required": False,
                "description": "Dump database table entries",
                "default": "false"
            },
            "DUMP_ALL": {
                "value": "false",
                "required": False,
                "description": "Dump all database tables",
                "default": "false"
            },
            "DB": {
                "value": None,
                "required": False,
                "description": "Specific database to enumerate",
                "default": None
            },
            "TBL": {
                "value": None,
                "required": False,
                "description": "Specific table to enumerate",
                "default": None
            },
            "BATCH": {
                "value": "true",
                "required": False,
                "description": "Never ask for user input (batch mode)",
                "default": "true"
            },
            "THREADS": {
                "value": "10",
                "required": False,
                "description": "Maximum number of concurrent threads",
                "default": "10"
            }
        })

    def build_command(self) -> str:
        """
        Build the sqlmap command.

        Returns:
            Command string to execute
        """
        url = self.get_option("URL")
        data = self.get_option("DATA")
        cookie = self.get_option("COOKIE")
        level = self.get_option("LEVEL")
        risk = self.get_option("RISK")
        threads = self.get_option("THREADS")

        # Base command
        cmd = f"sqlmap -u {self.quote_arg(url)}"

        # POST data
        if data:
            cmd += f" --data={self.quote_arg(data)}"

        # Cookie
        if cookie:
            cmd += f" --cookie={self.quote_arg(cookie)}"

        # Level and risk
        if level:
            cmd += f" --level={self.quote_arg(level)}"
        if risk:
            cmd += f" --risk={self.quote_arg(risk)}"

        # Threads
        if threads:
            cmd += f" --threads={self.quote_arg(threads)}"

        # Batch mode
        cmd += " --batch"

        # Enumeration options
        if self.option_enabled("DBS"):
            cmd += " --dbs"

        if self.option_enabled("TABLES"):
            cmd += " --tables"
            db = self.get_option("DB")
            if db:
                cmd += f" -D {self.quote_arg(db)}"

        if self.option_enabled("DUMP"):
            cmd += " --dump"
            db = self.get_option("DB")
            tbl = self.get_option("TBL")
            if db:
                cmd += f" -D {self.quote_arg(db)}"
            if tbl:
                cmd += f" -T {self.quote_arg(tbl)}"

        if self.option_enabled("DUMP_ALL"):
            cmd += " --dump-all"

        return cmd

    def build_argv(self):
        return shlex.split(self.build_command())

    def parse_output(self, output: str) -> dict:
        """
        Parse sqlmap output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "vulnerable": False,
            "injection_type": [],
            "databases": [],
            "tables": [],
            "parameters": [],
            "findings": [],
            "observations": [],
        }

        url = self.get_option("URL") or ""
        for location, text in (("query", urlsplit(url).query), ("body", self.get_option("DATA") or "")):
            for name, value in parse_qsl(text, keep_blank_values=True):
                parameter = {"name": name, "value": value, "location": location}
                results["parameters"].append(parameter)
                results["observations"].append(observation("parameter", url, **parameter))
        current = None
        confirmed = []

        # Parse output
        for line in strip_ansi(output).splitlines():
            if "is vulnerable" in line.lower() and "not vulnerable" not in line.lower():
                results["vulnerable"] = True
                detected = re.search(r"(GET|POST|URI|Cookie|HEADER)?\s*parameter\s+['\"]([^'\"]+)['\"].*is vulnerable", line, re.I)
                if detected:
                    confirmed.append({"parameter": detected.group(2), "location": detected.group(1) or "unknown",
                                      "injections": [{"type": "reported injectable", "evidence": line.strip()}]})

            match = re.match(r"\s*Parameter:\s*(.*?)\s*\(([^)]+)\)", line)
            if match:
                current = {"parameter": match.group(1), "location": match.group(2), "injections": []}
                confirmed.append(current)

            if "Type:" in line:
                # Extract injection type
                parts = line.split("Type:")
                if len(parts) > 1:
                    results["injection_type"].append(parts[1].strip())
                    if current is not None:
                        current["injections"].append({"type": parts[1].strip()})

            for label in ("Title", "Payload"):
                if current is not None and current["injections"] and line.strip().startswith(label + ":"):
                    current["injections"][-1][label.lower()] = line.split(":", 1)[1].strip()

            if "available databases" in line.lower():
                results["found_databases"] = True

            if "[*]" in line:
                # Possible database or table name
                name = line.split("[*]")[1].strip()
                if name and not name.startswith("starting"):
                    results["databases"].append(name)

        for item in confirmed:
            if not item["injections"]:
                continue
            results["vulnerable"] = True
            finding = {"title": f"SQL injection in {item['parameter']}", "severity": "high",
                       "source": "sqlmap", **item}
            results["findings"].append(finding)
            results["observations"].append(observation("finding", url, **finding))
            results["observations"].append(observation("parameter", url, name=item["parameter"],
                                                       location=item["location"], injectable=True))
        return results
