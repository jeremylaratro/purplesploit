"""
SQLMap Module

Automatic SQL injection and database takeover tool.
"""

from purplesploit.core.module import ExternalToolModule


class SQLMapModule(ExternalToolModule):
    """
    SQLMap - Automatic SQL injection and database takeover tool.

    Detects and exploits SQL injection vulnerabilities.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "sqlmap"

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
        batch = self.get_option("BATCH")

        # Base command
        cmd = f"sqlmap -u '{url}'"

        # POST data
        if data:
            cmd += f" --data='{data}'"

        # Cookie
        if cookie:
            cmd += f" --cookie='{cookie}'"

        # Level and risk
        if level:
            cmd += f" --level={level}"
        if risk:
            cmd += f" --risk={risk}"

        # Threads
        if threads:
            cmd += f" --threads={threads}"

        # Batch mode
        if batch and batch.lower() == "true":
            cmd += " --batch"

        # Enumeration options
        if self.get_option("DBS") and self.get_option("DBS").lower() == "true":
            cmd += " --dbs"

        if self.get_option("TABLES") and self.get_option("TABLES").lower() == "true":
            cmd += " --tables"
            db = self.get_option("DB")
            if db:
                cmd += f" -D {db}"

        if self.get_option("DUMP") and self.get_option("DUMP").lower() == "true":
            cmd += " --dump"
            db = self.get_option("DB")
            tbl = self.get_option("TBL")
            if db:
                cmd += f" -D {db}"
            if tbl:
                cmd += f" -T {tbl}"

        if self.get_option("DUMP_ALL") and self.get_option("DUMP_ALL").lower() == "true":
            cmd += " --dump-all"

        return cmd

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
        }

        # Parse output
        for line in output.split('\n'):
            if "is vulnerable" in line.lower():
                results["vulnerable"] = True

            if "Type:" in line:
                # Extract injection type
                parts = line.split("Type:")
                if len(parts) > 1:
                    results["injection_type"].append(parts[1].strip())

            if "available databases" in line.lower():
                results["found_databases"] = True

            if "[*]" in line:
                # Possible database or table name
                name = line.split("[*]")[1].strip()
                if name and not name.startswith("starting"):
                    results["databases"].append(name)

        return results
