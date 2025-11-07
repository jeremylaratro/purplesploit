"""
NetExec (NXC) RDP Module

RDP protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class NXCRDPModule(ExternalToolModule):
    """NetExec RDP module for Remote Desktop Protocol testing."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec RDP"

    @property
    def description(self) -> str:
        return "RDP authentication and enumeration with 4 operations"

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
            "DOMAIN": {"value": None, "required": False, "description": "Domain", "default": None},
            "HASH": {"value": None, "required": False, "description": "NTLM hash", "default": None},
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        return [
            {"name": "Test Authentication", "description": "Test RDP authentication", "handler": "op_test_auth"},
            {"name": "Test with Domain", "description": "Test with domain", "handler": "op_test_domain"},
            {"name": "Pass-the-Hash", "description": "PTH authentication", "handler": "op_pth"},
            {"name": "Check NLA Status", "description": "Check Network Level Authentication", "handler": "op_nla"},
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
        cmd = f"nxc rdp {rhost} {auth}"
        if extra_args:
            cmd += f" {extra_args}"
        return self.execute_command(cmd, timeout=60)

    def op_test_auth(self) -> Dict[str, Any]:
        return self._execute_nxc()

    def op_test_domain(self) -> Dict[str, Any]:
        domain = self.get_option("DOMAIN") or input("Domain: ")
        self.set_option("DOMAIN", domain)
        return self._execute_nxc(f"-d {domain}")

    def op_pth(self) -> Dict[str, Any]:
        hash_val = input("NTLM Hash: ")
        username = self.get_option("USERNAME") or input("Username: ")
        self.set_option("USERNAME", username)
        self.set_option("HASH", hash_val)
        return self._execute_nxc()

    def op_nla(self) -> Dict[str, Any]:
        rhost = self.get_option("RHOST")
        return self.execute_command(f"nxc rdp {rhost}")

    def run(self) -> Dict[str, Any]:
        return self.op_test_auth()
