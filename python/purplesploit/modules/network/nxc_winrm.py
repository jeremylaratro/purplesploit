"""
NetExec (NXC) WinRM Module

WinRM protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class NXCWinRMModule(ExternalToolModule):
    """NetExec WinRM module for Windows Remote Management operations."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec WinRM"

    @property
    def description(self) -> str:
        return "WinRM operations with 7 commands"

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
            "DOMAIN": {"value": None, "required": False, "description": "Domain", "default": "WORKGROUP"},
            "HASH": {"value": None, "required": False, "description": "NTLM hash", "default": None},
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        return [
            {"name": "Test Authentication", "description": "Test WinRM authentication", "handler": "op_test_auth"},
            {"name": "Execute Command", "description": "Execute Windows command", "handler": "op_exec_cmd"},
            {"name": "Execute PowerShell", "description": "Execute PowerShell command", "handler": "op_exec_ps"},
            {"name": "Get System Info", "description": "Run systeminfo", "handler": "op_sysinfo"},
            {"name": "Check Privileges", "description": "Check user privileges", "handler": "op_privs"},
            {"name": "List Local Users", "description": "List local users", "handler": "op_users"},
            {"name": "Network Configuration", "description": "Get ipconfig", "handler": "op_ipconfig"},
        ]

    def _build_auth(self) -> str:
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        hash_val = self.get_option("HASH")
        if not username:
            return ""
        auth = f"-u '{username}'"
        if hash_val:
            auth += f" -H '{hash_val}'"
        elif password:
            auth += f" -p '{password}'"
        else:
            auth += " -p ''"
        return auth

    def _execute_nxc(self, extra_args: str = "") -> Dict[str, Any]:
        rhost = self.get_option("RHOST")
        auth = self._build_auth()
        cmd = f"nxc winrm {rhost} {auth}"
        if extra_args:
            cmd += f" {extra_args}"
        return self.execute_command(cmd, timeout=180)

    def op_test_auth(self) -> Dict[str, Any]:
        return self._execute_nxc()

    def op_exec_cmd(self) -> Dict[str, Any]:
        cmd = input("Command: ")
        return self._execute_nxc(f"-x '{cmd}'")

    def op_exec_ps(self) -> Dict[str, Any]:
        ps = input("PowerShell command: ")
        return self._execute_nxc(f"-X '{ps}'")

    def op_sysinfo(self) -> Dict[str, Any]:
        return self._execute_nxc("-x 'systeminfo'")

    def op_privs(self) -> Dict[str, Any]:
        return self._execute_nxc("-x 'whoami /priv'")

    def op_users(self) -> Dict[str, Any]:
        return self._execute_nxc("-x 'net user'")

    def op_ipconfig(self) -> Dict[str, Any]:
        return self._execute_nxc("-x 'ipconfig /all'")

    def run(self) -> Dict[str, Any]:
        return self.op_test_auth()
