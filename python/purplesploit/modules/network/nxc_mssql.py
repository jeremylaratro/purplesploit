"""
NetExec (NXC) MSSQL Module

Microsoft SQL Server operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule


class NXCMSSQLModule(ExternalToolModule):
    """
    NetExec MSSQL module for Microsoft SQL Server testing.

    Supports authentication, query execution, and MSSQL enumeration.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec MSSQL"

    @property
    def description(self) -> str:
        return "Microsoft SQL Server testing and enumeration using NetExec"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "network"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target SQL Server IP address",
                "default": None
            },
            "RPORT": {
                "value": "1433",
                "required": False,
                "description": "SQL Server port",
                "default": "1433"
            },
            "USERNAME": {
                "value": None,
                "required": False,
                "description": "Username for authentication",
                "default": None
            },
            "PASSWORD": {
                "value": None,
                "required": False,
                "description": "Password for authentication",
                "default": None
            },
            "DOMAIN": {
                "value": None,
                "required": False,
                "description": "Domain name",
                "default": None
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash for pass-the-hash",
                "default": None
            },
            "QUERY": {
                "value": None,
                "required": False,
                "description": "SQL query to execute (-q flag)",
                "default": None
            },
            "COMMAND": {
                "value": None,
                "required": False,
                "description": "OS command to execute via xp_cmdshell (-x flag)",
                "default": None
            },
            "LOCAL_AUTH": {
                "value": "false",
                "required": False,
                "description": "Use local authentication",
                "default": "false"
            },
            "MODULE": {
                "value": None,
                "required": False,
                "description": "NXC module to run (-M flag)",
                "default": None
            }
        })

    def build_command(self) -> str:
        """
        Build the nxc mssql command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        rport = self.get_option("RPORT")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        query = self.get_option("QUERY")
        command = self.get_option("COMMAND")
        local_auth = self.get_option("LOCAL_AUTH")
        module = self.get_option("MODULE")

        # Base command
        cmd = f"nxc mssql {rhost}"

        # Port
        if rport and rport != "1433":
            cmd += f" --port {rport}"

        # Authentication
        if username:
            cmd += f" -u '{username}'"

            if password:
                cmd += f" -p '{password}'"
            elif hash_val:
                cmd += f" -H '{hash_val}'"
            else:
                cmd += " -p ''"

        # Domain
        if domain:
            cmd += f" -d '{domain}'"

        # Local auth
        if local_auth and local_auth.lower() == "true":
            cmd += " --local-auth"

        # Query execution
        if query:
            cmd += f" -q \"{query}\""

        # Command execution via xp_cmdshell
        if command:
            cmd += f" -x '{command}'"

        # Module execution
        if module:
            cmd += f" -M {module}"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse nxc mssql output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "authentication": "unknown",
            "admin_access": False,
            "query_results": [],
            "command_output": [],
        }

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Check authentication
            if "Pwn3d!" in line:
                results["authentication"] = "admin"
                results["admin_access"] = True
            elif "[+]" in line:
                results["authentication"] = "success"
            elif "[-]" in line and "STATUS_LOGON_FAILURE" in line:
                results["authentication"] = "failed"

            # Capture query results
            if query and line and not line.startswith('['):
                results["query_results"].append(line)

            # Capture command output
            if command and line and not line.startswith('['):
                results["command_output"].append(line)

        return results
