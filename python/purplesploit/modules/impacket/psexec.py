"""
Impacket PSExec Module

Remote command execution via PSExec.
"""

from .common import ImpacketAdapter


class ImpacketPSExecModule(ImpacketAdapter):
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

    emits = ("session",)
    interactive = True

    def build_argv(self) -> list[str]:
        """
        Build the impacket-psexec command.

        Returns:
            Command string to execute
        """
        command = self.get_option("COMMAND")
        share = self.get_option("SHARE")

        # Build target string
        cmd = self.authentication_argv()

        # Share
        if share:
            cmd += ["-share", str(share)]

        # Command execution
        if command:
            cmd.append(str(command))

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

        return self.execution_observations(results)
