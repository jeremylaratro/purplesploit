"""
Impacket PSExec Module

Remote command execution via PSExec.
"""

from purplesploit.core.module import ExternalToolModule


class ImpacketPSExecModule(ExternalToolModule):
    """
    Impacket PSExec - Remote command execution.

    PSEXEC-like functionality using RemComSvc service.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-psexec"

    @property
    def name(self) -> str:
        return "Impacket PSExec"

    @property
    def description(self) -> str:
        return "Remote command execution via PSExec (RemComSvc service)"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "impacket"

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
            "USERNAME": {
                "value": None,
                "required": True,
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
                "value": ".",
                "required": False,
                "description": "Domain name (use '.' for local)",
                "default": "."
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash (LM:NT format)",
                "default": None
            },
            "COMMAND": {
                "value": None,
                "required": False,
                "description": "Command to execute (if not interactive)",
                "default": None
            },
            "SHARE": {
                "value": "ADMIN$",
                "required": False,
                "description": "Share to use for upload",
                "default": "ADMIN$"
            }
        })

    def build_command(self) -> str:
        """
        Build the impacket-psexec command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        command = self.get_option("COMMAND")
        share = self.get_option("SHARE")

        # Build target string
        if hash_val:
            # Hash authentication
            target = f"{domain}/{username}@{rhost} -hashes {hash_val}"
        elif password:
            # Password authentication
            target = f"{domain}/{username}:{password}@{rhost}"
        else:
            # No authentication (will fail)
            target = f"{domain}/{username}@{rhost}"

        # Base command
        cmd = f"impacket-psexec {target}"

        # Share
        if share:
            cmd += f" -share {share}"

        # Command execution
        if command:
            cmd += f" '{command}'"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse psexec output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "success": False,
            "shell_obtained": False,
            "command_output": [],
        }

        # Parse output
        for line in output.split('\n'):
            if "C:\\Windows\\system32>" in line or "C:\\>" in line:
                results["shell_obtained"] = True
                results["success"] = True

            if line.strip() and not line.startswith('['):
                results["command_output"].append(line)

        return results
