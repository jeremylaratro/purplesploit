"""
SMB Execution Module

Execute commands and scripts on remote systems via SMB.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class SMBExecutionModule(ExternalToolModule):
    """SMB command and script execution operations."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "SMB Execution"

    @property
    def description(self) -> str:
        return "SMB command and script execution"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "smb"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target host IP address or hostname",
                "default": None
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
                "default": "WORKGROUP"
            },
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of execution operations."""
        return [
            {"name": "Execute Command (CMD)", "description": "Execute Windows command", "handler": "op_exec_cmd"},
            {"name": "Execute PowerShell", "description": "Execute PowerShell command", "handler": "op_exec_ps"},
            {"name": "Get System Info", "description": "Run systeminfo command", "handler": "op_system_info"},
            {"name": "List Processes", "description": "List running processes", "handler": "op_list_processes"},
            {"name": "Network Configuration", "description": "Get network config (ipconfig)", "handler": "op_network_config"},
            {"name": "List Administrators", "description": "List local administrators", "handler": "op_list_admins"},
            {"name": "Check Privileges", "description": "Check current privileges (whoami /priv)", "handler": "op_check_privs"},
        ]

    def _build_auth(self) -> str:
        """Build authentication string for nxc."""
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")

        if not username:
            return ""

        auth = f"-u '{username}'"
        if password:
            auth += f" -p '{password}'"
        else:
            auth += " -p ''"

        return auth

    def _execute_nxc(self, extra_args: str = "") -> Dict[str, Any]:
        """Execute nxc smb command."""
        rhost = self.get_option("RHOST")
        domain = self.get_option("DOMAIN")
        auth = self._build_auth()

        cmd = f"nxc smb {rhost} {auth}"

        if domain and domain != "WORKGROUP":
            cmd += f" -d {domain}"

        if extra_args:
            cmd += f" {extra_args}"

        return self.execute_command(cmd, timeout=300)

    def op_exec_cmd(self) -> Dict[str, Any]:
        """Execute Windows command."""
        cmd = input("Command to execute: ")
        if not cmd:
            return {"success": False, "error": "Command required"}

        return self._execute_nxc(f"-x '{cmd}'")

    def op_exec_ps(self) -> Dict[str, Any]:
        """Execute PowerShell command."""
        ps_cmd = input("PowerShell command: ")
        if not ps_cmd:
            return {"success": False, "error": "Command required"}

        return self._execute_nxc(f"-X '{ps_cmd}'")

    def op_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        return self._execute_nxc("-x 'systeminfo'")

    def op_list_processes(self) -> Dict[str, Any]:
        """List running processes."""
        return self._execute_nxc("-x 'tasklist /v'")

    def op_network_config(self) -> Dict[str, Any]:
        """Get network configuration."""
        return self._execute_nxc("-x 'ipconfig /all'")

    def op_list_admins(self) -> Dict[str, Any]:
        """List local administrators."""
        return self._execute_nxc("-x 'net localgroup administrators'")

    def op_check_privs(self) -> Dict[str, Any]:
        """Check current privileges."""
        return self._execute_nxc("-x 'whoami /priv'")

    def run(self) -> Dict[str, Any]:
        """Default run - execute command."""
        return self.op_exec_cmd()
