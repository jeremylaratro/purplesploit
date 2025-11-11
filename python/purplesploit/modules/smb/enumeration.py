"""
SMB Enumeration Module

Enumerate shares, users, groups, sessions, and other SMB information.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class SMBEnumerationModule(ExternalToolModule):
    """SMB enumeration and reconnaissance operations."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "SMB Enumeration"

    @property
    def description(self) -> str:
        return "SMB enumeration and information gathering"

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
        """Get list of enumeration operations."""
        return [
            {"name": "List Shares", "description": "Enumerate SMB shares", "handler": "op_list_shares"},
            {"name": "Enumerate Users", "description": "Enumerate domain/local users", "handler": "op_enum_users"},
            {"name": "Enumerate Local Users", "description": "Enumerate local users only", "handler": "op_enum_local_users"},
            {"name": "Enumerate Groups", "description": "Enumerate domain groups", "handler": "op_enum_groups"},
            {"name": "Password Policy", "description": "Get domain password policy", "handler": "op_password_policy"},
            {"name": "Active Sessions", "description": "Enumerate active sessions", "handler": "op_active_sessions"},
            {"name": "Logged On Users", "description": "Enumerate logged on users", "handler": "op_loggedon_users"},
            {"name": "RID Bruteforce", "description": "Bruteforce RIDs to enumerate users", "handler": "op_rid_brute"},
            {"name": "List Disks", "description": "List available disks", "handler": "op_list_disks"},
            {"name": "Full Enumeration", "description": "Run all enumeration checks", "handler": "op_full_enum"},
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

    def op_list_shares(self) -> Dict[str, Any]:
        """List SMB shares."""
        return self._execute_nxc("--shares")

    def op_enum_users(self) -> Dict[str, Any]:
        """Enumerate domain/local users."""
        return self._execute_nxc("--users")

    def op_enum_local_users(self) -> Dict[str, Any]:
        """Enumerate local users only."""
        return self._execute_nxc("--local-users")

    def op_enum_groups(self) -> Dict[str, Any]:
        """Enumerate domain groups."""
        return self._execute_nxc("--groups")

    def op_password_policy(self) -> Dict[str, Any]:
        """Get domain password policy."""
        return self._execute_nxc("--pass-pol")

    def op_active_sessions(self) -> Dict[str, Any]:
        """Enumerate active sessions."""
        return self._execute_nxc("--sessions")

    def op_loggedon_users(self) -> Dict[str, Any]:
        """Enumerate logged on users."""
        return self._execute_nxc("--loggedon-users")

    def op_rid_brute(self) -> Dict[str, Any]:
        """RID bruteforce to enumerate users."""
        return self._execute_nxc("--rid-brute")

    def op_list_disks(self) -> Dict[str, Any]:
        """List available disks."""
        return self._execute_nxc("--disks")

    def op_full_enum(self) -> Dict[str, Any]:
        """Run all enumeration checks."""
        return self._execute_nxc("--users --groups --shares --sessions --pass-pol --disks")

    def run(self) -> Dict[str, Any]:
        """Default run - list shares."""
        return self.op_list_shares()
