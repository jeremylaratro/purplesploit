"""
NetExec (NXC) LDAP Module

LDAP protocol operations using NetExec.
"""

from purplesploit.core.module import ExternalToolModule


class NXCLDAPModule(ExternalToolModule):
    """
    NetExec LDAP module for LDAP/Active Directory enumeration.

    Supports authentication, user/group enumeration, and LDAP queries.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec LDAP"

    @property
    def description(self) -> str:
        return "LDAP/Active Directory enumeration using NetExec"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "network"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target Domain Controller IP",
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
                "default": None
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash for pass-the-hash",
                "default": None
            },
            "USERS": {
                "value": "false",
                "required": False,
                "description": "Enumerate users (--users)",
                "default": "false"
            },
            "GROUPS": {
                "value": "false",
                "required": False,
                "description": "Enumerate groups (--groups)",
                "default": "false"
            },
            "TRUSTED_DOMAINS": {
                "value": "false",
                "required": False,
                "description": "Enumerate trusted domains (--trusted-for-delegation)",
                "default": "false"
            },
            "ASREPROAST": {
                "value": "false",
                "required": False,
                "description": "Get AS-REP roastable users (--asreproast)",
                "default": "false"
            },
            "KERBEROAST": {
                "value": "false",
                "required": False,
                "description": "Get kerberoastable users (--kerberoasting)",
                "default": "false"
            },
            "ADMIN_COUNT": {
                "value": "false",
                "required": False,
                "description": "Get users with adminCount=1 (--admin-count)",
                "default": "false"
            },
            "MODULE": {
                "value": None,
                "required": False,
                "description": "NXC module to run (-M flag)",
                "default": None
            }
        })

    def build_command(self) -> str:
        """
        Build the nxc ldap command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        module = self.get_option("MODULE")

        # Base command
        cmd = f"nxc ldap {rhost}"

        # Authentication
        if username:
            cmd += f" -u '{username}'"

            if password:
                cmd += f" -p '{password}'"
            elif hash_val:
                cmd += f" -H '{hash_val}'"
            else:
                cmd += " -p ''"

        # Domain
        if domain:
            cmd += f" -d '{domain}'"

        # Enumeration options
        if self.get_option("USERS") and self.get_option("USERS").lower() == "true":
            cmd += " --users"

        if self.get_option("GROUPS") and self.get_option("GROUPS").lower() == "true":
            cmd += " --groups"

        if self.get_option("TRUSTED_DOMAINS") and self.get_option("TRUSTED_DOMAINS").lower() == "true":
            cmd += " --trusted-for-delegation"

        if self.get_option("ASREPROAST") and self.get_option("ASREPROAST").lower() == "true":
            cmd += " --asreproast"

        if self.get_option("KERBEROAST") and self.get_option("KERBEROAST").lower() == "true":
            cmd += " --kerberoasting"

        if self.get_option("ADMIN_COUNT") and self.get_option("ADMIN_COUNT").lower() == "true":
            cmd += " --admin-count"

        # Module execution
        if module:
            cmd += f" -M {module}"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse nxc ldap output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "authentication": "unknown",
            "users": [],
            "groups": [],
            "hashes": [],
        }

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Check authentication
            if "[+]" in line and ":" in line:
                results["authentication"] = "success"
            elif "[-]" in line:
                results["authentication"] = "failed"

            # Parse users
            if "User:" in line or "username" in line.lower():
                results["users"].append(line)

            # Parse groups
            if "Group:" in line or "group" in line.lower():
                results["groups"].append(line)

            # Parse hashes (AS-REP or Kerberoast)
            if "$krb5" in line:
                results["hashes"].append(line)

        return results
