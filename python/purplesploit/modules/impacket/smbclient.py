"""
Impacket SMBClient Module

Interactive SMB client for file operations.
"""

from purplesploit.core.module import ExternalToolModule


class ImpacketSMBClientModule(ExternalToolModule):
    """
    Impacket smbclient - Interactive SMB client.

    Provides SMB file system access for browsing shares, downloading,
    and uploading files.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-smbclient"

    @property
    def name(self) -> str:
        return "Impacket SMBClient"

    @property
    def description(self) -> str:
        return "Interactive SMB client for file operations and share browsing"

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
            "SHARE": {
                "value": None,
                "required": False,
                "description": "Share to connect to (e.g., C$, ADMIN$)",
                "default": None
            },
            "COMMAND": {
                "value": None,
                "required": False,
                "description": "SMB command to execute (e.g., 'ls', 'get file.txt')",
                "default": None
            }
        })

    def build_command(self) -> str:
        """
        Build the impacket-smbclient command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        share = self.get_option("SHARE")
        command = self.get_option("COMMAND")

        # Build target string
        if hash_val:
            target = f"{domain}/{username}@{rhost} -hashes {hash_val}"
        elif password:
            target = f"{domain}/{username}:{password}@{rhost}"
        else:
            target = f"{domain}/{username}@{rhost}"

        # Base command
        cmd = f"impacket-smbclient {target}"

        # Share
        if share:
            cmd += f" -share {share}"

        # Command (for non-interactive mode)
        if command:
            cmd += f" -c '{command}'"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse smbclient output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "success": False,
            "shares": [],
            "files": [],
        }

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Check connection success
            if "Type help for list of commands" in line:
                results["success"] = True

            # Parse shares
            if "$" in line and ("Disk" in line or "IPC" in line):
                results["shares"].append(line)

            # Parse file listings
            if line and not line.startswith('#') and not line.startswith('['):
                parts = line.split()
                if len(parts) >= 2 and (parts[0].endswith('.') or parts[0] == 'D'):
                    results["files"].append(line)

        return results
