"""
SMB Authentication Module

Test SMB authentication with various methods including standard auth,
pass-the-hash, and local authentication.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class SMBAuthenticationModule(ExternalToolModule):
    """SMB Authentication testing operations."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "SMB Authentication"

    @property
    def description(self) -> str:
        return "SMB authentication testing with multiple methods"

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
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash for pass-the-hash",
                "default": None
            },
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of authentication operations."""
        return [
            {"name": "Test Authentication", "description": "Test basic SMB authentication", "handler": "op_test_auth"},
            {"name": "Test with Domain", "description": "Test authentication with domain", "handler": "op_test_domain"},
            {"name": "Pass-the-Hash", "description": "Authenticate using NTLM hash", "handler": "op_pass_the_hash"},
            {"name": "Local Authentication", "description": "Test local authentication (--local-auth)", "handler": "op_local_auth"},
        ]

    def _build_auth(self) -> str:
        """Build authentication string for nxc."""
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
        """Execute nxc smb command with extra arguments."""
        rhost = self.get_option("RHOST")
        domain = self.get_option("DOMAIN")
        auth = self._build_auth()

        cmd = f"nxc smb {rhost} {auth}"

        if domain and domain != "WORKGROUP":
            cmd += f" -d {domain}"

        if extra_args:
            cmd += f" {extra_args}"

        return self.execute_command(cmd, timeout=300)

    def op_test_auth(self) -> Dict[str, Any]:
        """Test basic SMB authentication."""
        return self._execute_nxc()

    def op_test_domain(self) -> Dict[str, Any]:
        """Test authentication with explicit domain."""
        domain = self.get_option("DOMAIN") or input("Domain [default: WORKGROUP]: ") or "WORKGROUP"
        self.set_option("DOMAIN", domain)
        return self._execute_nxc()

    def op_pass_the_hash(self) -> Dict[str, Any]:
        """Authenticate using NTLM hash."""
        hash_val = input("NTLM Hash: ")
        if not hash_val:
            return {"success": False, "error": "Hash required"}

        username = self.get_option("USERNAME") or input("Username: ")
        self.set_option("USERNAME", username)
        self.set_option("HASH", hash_val)
        self.set_option("PASSWORD", None)

        return self._execute_nxc()

    def op_local_auth(self) -> Dict[str, Any]:
        """Test local authentication."""
        return self._execute_nxc("--local-auth")

    def run(self) -> Dict[str, Any]:
        """Default run - test basic authentication."""
        return self.op_test_auth()
