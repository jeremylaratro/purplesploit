"""
Impacket WMIExec Module

Remote command execution via WMI.
"""

from .common import ImpacketAdapter


class ImpacketWMIExecModule(ImpacketAdapter):
    """
    Impacket WMIExec - Semi-interactive shell via WMI.

    Uses Windows Management Instrumentation for command execution.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-wmiexec"

    @property
    def name(self) -> str:
        return "Impacket WMIExec"

    @property
    def description(self) -> str:
        return "Remote command execution via WMI (stealthier than PSExec)"

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
            "CODEC": {
                "value": "utf-8",
                "required": False,
                "description": "Output encoding codec",
                "default": "utf-8"
            }
        })

    emits = ("session",)
    interactive = True

    def build_argv(self) -> list[str]:
        """
        Build the impacket-wmiexec command.

        Returns:
            Command string to execute
        """
        command = self.get_option("COMMAND")
        codec = self.get_option("CODEC")

        # Build target string
        cmd = self.authentication_argv()

        # Codec
        if codec:
            cmd += ["-codec", str(codec)]

        # Command execution
        if command:
            cmd.append(str(command))

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse wmiexec output.

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
            if "C:\\>" in line:
                results["shell_obtained"] = True
                results["success"] = True

            if line.strip() and not line.startswith('['):
                results["command_output"].append(line)

        return self.execution_observations(results)
