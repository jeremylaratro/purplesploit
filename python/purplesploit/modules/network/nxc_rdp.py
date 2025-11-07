"""
NetExec (NXC) RDP Module

Remote Desktop Protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule


class NXCRDPModule(ExternalToolModule):
    """
    NetExec RDP module for Remote Desktop Protocol testing.

    Supports authentication testing and RDP enumeration.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec RDP"

    @property
    def description(self) -> str:
        return "Remote Desktop Protocol testing and enumeration using NetExec"

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
                "value": "3389",
                "required": False,
                "description": "RDP port",
                "default": "3389"
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
            "SCREENSHOT": {
                "value": "false",
                "required": False,
                "description": "Take screenshot of login screen",
                "default": "false"
            },
            "NLA": {
                "value": "true",
                "required": False,
                "description": "Test NLA (Network Level Authentication)",
                "default": "true"
            }
        })

    def build_command(self) -> str:
        """
        Build the nxc rdp command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        rport = self.get_option("RPORT")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        screenshot = self.get_option("SCREENSHOT")
        nla = self.get_option("NLA")

        # Base command
        cmd = f"nxc rdp {rhost}"

        # Port
        if rport and rport != "3389":
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

        # Screenshot
        if screenshot and screenshot.lower() == "true":
            cmd += " --screenshot"

        # NLA
        if nla and nla.lower() == "false":
            cmd += " --nla-false"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse nxc rdp output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "authentication": "unknown",
            "nla_enabled": None,
            "screenshot_taken": False,
        }

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Check authentication
            if "[+]" in line:
                results["authentication"] = "success"
            elif "[-]" in line and "LOGON_FAILURE" in line:
                results["authentication"] = "failed"

            # Check NLA status
            if "NLA: True" in line:
                results["nla_enabled"] = True
            elif "NLA: False" in line:
                results["nla_enabled"] = False

            # Check screenshot
            if "Screenshot" in line or "screenshot" in line:
                results["screenshot_taken"] = True

        return results
