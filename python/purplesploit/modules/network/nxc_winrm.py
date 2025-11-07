"""
NetExec (NXC) WinRM Module

WinRM protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule


class NXCWinRMModule(ExternalToolModule):
    """
    NetExec WinRM module for Windows Remote Management operations.

    Supports authentication, command execution, and enumeration via WinRM.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec WinRM"

    @property
    def description(self) -> str:
        return "Windows Remote Management operations using NetExec"

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
                "description": "Target host IP address",
                "default": None
            },
            "RPORT": {
                "value": "5985",
                "required": False,
                "description": "WinRM port (5985 HTTP, 5986 HTTPS)",
                "default": "5985"
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
            "COMMAND": {
                "value": None,
                "required": False,
                "description": "Command to execute (-x flag)",
                "default": None
            },
            "POWERSHELL": {
                "value": None,
                "required": False,
                "description": "PowerShell command to execute (-X flag)",
                "default": None
            },
            "MODULE": {
                "value": None,
                "required": False,
                "description": "NXC module to run (-M flag)",
                "default": None
            },
            "SSL": {
                "value": "false",
                "required": False,
                "description": "Use SSL/TLS (port 5986)",
                "default": "false"
            }
        })

    def build_command(self) -> str:
        """
        Build the nxc winrm command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        rport = self.get_option("RPORT")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        command = self.get_option("COMMAND")
        powershell = self.get_option("POWERSHELL")
        module = self.get_option("MODULE")
        ssl = self.get_option("SSL")

        # Base command
        cmd = f"nxc winrm {rhost}"

        # Port
        if rport:
            cmd += f" --port {rport}"

        # SSL
        if ssl and ssl.lower() == "true":
            cmd += " --ssl"

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

        # Command execution
        if command:
            cmd += f" -x '{command}'"

        # PowerShell execution
        if powershell:
            cmd += f" -X '{powershell}'"

        # Module execution
        if module:
            cmd += f" -M {module}"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse nxc winrm output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "authentication": "unknown",
            "admin_access": False,
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
            elif "[-]" in line and ("LOGON_FAILURE" in line or "ACCESS_DENIED" in line):
                results["authentication"] = "failed"

            # Capture command output
            if command and line and not line.startswith('['):
                results["command_output"].append(line)

        return results
