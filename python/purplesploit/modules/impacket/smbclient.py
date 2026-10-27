"""
Impacket SMBClient Module

Interactive SMB client for file operations.
"""

import os
import tempfile

from .common import ImpacketAdapter, observation


class ImpacketSMBClientModule(ImpacketAdapter):
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

    emits = ("share",)
    interactive = True

    def get_operation_manifest(self):
        manifest = super().get_operation_manifest()
        manifest[0]["interactive"] = not bool(self.get_option("SHARE") or self.get_option("COMMAND"))
        return manifest

    def build_argv(self) -> list[str]:
        """
        Build the impacket-smbclient command.

        Returns:
            Command string to execute
        """
        cmd = self.authentication_argv()
        input_file = getattr(self, "_input_file", None)
        if input_file:
            cmd += ["-inputfile", input_file]
        return cmd

    def run(self):
        share, command = self.get_option("SHARE"), self.get_option("COMMAND")
        if not share and not command:
            return super().run()
        if share and any(char in str(share) for char in "\r\n"):
            return {"success": False, "error": "SHARE must be a single SMB share name"}
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as handle:
                self._input_file = handle.name
                if share:
                    handle.write(f"use {share}\n")
                if command:
                    handle.write(f"{command}\n")
                elif share:
                    handle.write("ls\n")
            return super().run()
        finally:
            if getattr(self, "_input_file", None):
                os.unlink(self._input_file)
                self._input_file = None

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
            "observations": [],
        }

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Check connection success
            if "Type help for list of commands" in line:
                results["success"] = True

            # Parse shares
            if line and ("Disk" in line or "IPC" in line) and not line.startswith(("[", "#")):
                results["shares"].append(line)
                parts = line.split(None, 2)
                results["observations"].append(observation(
                    "share", self.get_option("RHOST"), name=parts[0],
                    share_type=parts[1] if len(parts) > 1 else "", protocol="smb"))
            elif (str(self.get_option("COMMAND") or "").strip() == "shares" and line
                  and not line.startswith(("[", "#", "Impacket", "Type ")) and len(line.split()) == 1):
                # Impacket's mini-shell `shares` command prints names only.
                results["shares"].append(line)
                results["observations"].append(observation("share", self.get_option("RHOST"), name=line, protocol="smb"))

            # Parse file listings
            if line and not line.startswith('#') and not line.startswith('['):
                parts = line.split()
                if len(parts) >= 2 and (parts[0].endswith('.') or parts[0] == 'D'):
                    results["files"].append(line)

        return results
