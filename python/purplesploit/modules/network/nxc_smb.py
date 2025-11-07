"""
NetExec (NXC) SMB Module

SMB protocol operations using NetExec (formerly CrackMapExec).
"""

from purplesploit.core.module import ExternalToolModule


class NXCSMBModule(ExternalToolModule):
    """
    NetExec SMB module for SMB protocol testing and exploitation.

    Supports authentication, enumeration, execution, and various SMB attacks.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec SMB"

    @property
    def description(self) -> str:
        return "SMB protocol operations using NetExec (authentication, enumeration, execution)"

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
                "default": None
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash for pass-the-hash",
                "default": None
            },
            "COMMAND": {
                "value": None,
                "required": False,
                "description": "Command to execute (-x flag)",
                "default": None
            },
            "MODULE": {
                "value": None,
                "required": False,
                "description": "NXC module to run (-M flag)",
                "default": None
            },
            "SHARES": {
                "value": "false",
                "required": False,
                "description": "Enumerate shares (--shares)",
                "default": "false"
            },
            "SESSIONS": {
                "value": "false",
                "required": False,
                "description": "Enumerate sessions (--sessions)",
                "default": "false"
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
            "LOCAL_AUTH": {
                "value": "false",
                "required": False,
                "description": "Use local authentication (--local-auth)",
                "default": "false"
            },
            "SAM": {
                "value": "false",
                "required": False,
                "description": "Dump SAM hashes (--sam)",
                "default": "false"
            },
            "LSA": {
                "value": "false",
                "required": False,
                "description": "Dump LSA secrets (--lsa)",
                "default": "false"
            }
        })

    def build_command(self) -> str:
        """
        Build the nxc smb command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        command = self.get_option("COMMAND")
        module = self.get_option("MODULE")

        # Base command
        cmd = f"nxc smb {rhost}"

        # Authentication
        if username:
            cmd += f" -u '{username}'"

            if password:
                cmd += f" -p '{password}'"
            elif hash_val:
                cmd += f" -H '{hash_val}'"
            else:
                # Try empty password
                cmd += " -p ''"

        # Domain
        if domain:
            cmd += f" -d '{domain}'"

        # Local auth
        if self.get_option("LOCAL_AUTH") and self.get_option("LOCAL_AUTH").lower() == "true":
            cmd += " --local-auth"

        # Enumeration options
        if self.get_option("SHARES") and self.get_option("SHARES").lower() == "true":
            cmd += " --shares"

        if self.get_option("SESSIONS") and self.get_option("SESSIONS").lower() == "true":
            cmd += " --sessions"

        if self.get_option("USERS") and self.get_option("USERS").lower() == "true":
            cmd += " --users"

        if self.get_option("GROUPS") and self.get_option("GROUPS").lower() == "true":
            cmd += " --groups"

        # Credential dumping
        if self.get_option("SAM") and self.get_option("SAM").lower() == "true":
            cmd += " --sam"

        if self.get_option("LSA") and self.get_option("LSA").lower() == "true":
            cmd += " --lsa"

        # Command execution
        if command:
            cmd += f" -x '{command}'"

        # Module execution
        if module:
            cmd += f" -M {module}"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse nxc output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "authentication": "unknown",
            "shares": [],
            "users": [],
            "sessions": [],
            "hashes": [],
        }

        # Parse output line by line
        for line in output.split('\n'):
            line = line.strip()

            # Check authentication status
            if "Pwn3d!" in line:
                results["authentication"] = "admin"
            elif "[+]" in line and (":" in line or "STATUS" in line):
                results["authentication"] = "success"
            elif "[-]" in line and "STATUS_LOGON_FAILURE" in line:
                results["authentication"] = "failed"

            # Parse shares
            if "Disk" in line or "IPC" in line or "Print" in line:
                results["shares"].append(line)

            # Parse users
            if "User:" in line:
                results["users"].append(line)

            # Parse hashes
            if ":" in line and len(line.split(":")) >= 3:
                # Possible hash format
                results["hashes"].append(line)

        return results
