"""
NetExec (NXC) SSH Module

SSH protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule


class NXCSSHModule(ExternalToolModule):
    """
    NetExec SSH module for SSH protocol testing.

    Supports authentication, command execution, and SSH enumeration.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec SSH"

    @property
    def description(self) -> str:
        return "SSH protocol testing and command execution using NetExec"

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
                "value": "22",
                "required": False,
                "description": "SSH port",
                "default": "22"
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
            "KEY_FILE": {
                "value": None,
                "required": False,
                "description": "SSH private key file path",
                "default": None
            },
            "COMMAND": {
                "value": None,
                "required": False,
                "description": "Command to execute (-x flag)",
                "default": None
            },
            "SUDO": {
                "value": "false",
                "required": False,
                "description": "Execute command with sudo",
                "default": "false"
            },
            "SUDO_CHECK": {
                "value": "false",
                "required": False,
                "description": "Check sudo privileges (--sudo-check)",
                "default": "false"
            }
        })

    def build_command(self) -> str:
        """
        Build the nxc ssh command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        rport = self.get_option("RPORT")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        key_file = self.get_option("KEY_FILE")
        command = self.get_option("COMMAND")
        sudo = self.get_option("SUDO")
        sudo_check = self.get_option("SUDO_CHECK")

        # Base command
        cmd = f"nxc ssh {rhost}"

        # Port
        if rport and rport != "22":
            cmd += f" --port {rport}"

        # Authentication
        if username:
            cmd += f" -u '{username}'"

            if password:
                cmd += f" -p '{password}'"
            elif key_file:
                cmd += f" --key-file '{key_file}'"
            else:
                cmd += " -p ''"

        # Command execution
        if command:
            cmd += f" -x '{command}'"

        # Sudo
        if sudo and sudo.lower() == "true":
            cmd += " --sudo"

        # Sudo check
        if sudo_check and sudo_check.lower() == "true":
            cmd += " --sudo-check"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse nxc ssh output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "authentication": "unknown",
            "sudo_available": False,
            "command_output": [],
        }

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Check authentication
            if "[+]" in line:
                results["authentication"] = "success"
            elif "[-]" in line and ("Authentication failed" in line or "LOGON_FAILURE" in line):
                results["authentication"] = "failed"

            # Check sudo
            if "sudo" in line.lower() and "available" in line.lower():
                results["sudo_available"] = True

            # Capture command output
            if command and line and not line.startswith('['):
                results["command_output"].append(line)

        return results
