"""
NetExec (NXC) SSH Module

SSH protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class NXCSSHModule(ExternalToolModule):
    """NetExec SSH module for SSH authentication and command execution."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec SSH"

    @property
    def description(self) -> str:
        return "SSH operations with 6 commands"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "network"

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "RHOST": {"value": None, "required": True, "description": "Target host IP", "default": None},
            "USERNAME": {"value": None, "required": False, "description": "Username", "default": None},
            "PASSWORD": {"value": None, "required": False, "description": "Password", "default": None},
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        return [
            {"name": "Test Authentication", "description": "Test SSH authentication", "handler": "op_test_auth"},
            {"name": "Execute Command", "description": "Execute remote command", "handler": "op_exec_cmd"},
            {"name": "Get System Info", "description": "Get uname and OS info", "handler": "op_sysinfo"},
            {"name": "List Users", "description": "List system users", "handler": "op_users"},
            {"name": "Check Sudo", "description": "Check sudo privileges", "handler": "op_sudo"},
            {"name": "Network Info", "description": "Get network configuration", "handler": "op_netinfo"},
        ]

    def _build_auth(self) -> str:
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
        rhost = self.get_option("RHOST")
        auth = self._build_auth()
        cmd = f"nxc ssh {rhost} {auth}"
        if extra_args:
            cmd += f" {extra_args}"
        return self.execute_command(cmd, timeout=120)

    def op_test_auth(self) -> Dict[str, Any]:
        return self._execute_nxc()

    def op_exec_cmd(self) -> Dict[str, Any]:
        cmd = input("Command: ")
        return self._execute_nxc(f"-x '{cmd}'")

    def op_sysinfo(self) -> Dict[str, Any]:
        return self._execute_nxc("-x 'uname -a'")

    def op_users(self) -> Dict[str, Any]:
        return self._execute_nxc("-x 'cat /etc/passwd'")

    def op_sudo(self) -> Dict[str, Any]:
        return self._execute_nxc("-x 'sudo -l'")

    def op_netinfo(self) -> Dict[str, Any]:
        return self._execute_nxc("-x 'ip a'")

    def run(self) -> Dict[str, Any]:
        return self.op_test_auth()
