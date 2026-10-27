"""
Impacket SecretsDump Module

Dump credentials from Windows systems.
"""

from .common import ImpacketAdapter, account, observation


class ImpacketSecretsDumpModule(ImpacketAdapter):
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

    emits = ("credential",)

    def build_argv(self) -> list[str]:
        """
        Build the impacket-secretsdump command.

        Returns:
            Command string to execute
        """
        output_file = self.get_option("OUTPUT_FILE")

        # Build target string
        cmd = self.authentication_argv()

        # Options
        # By default, dumps SAM and LSA
        # For NTDS, need -just-dc flag
        if self.option_enabled("NTDS"):
            cmd.append("-just-dc")

        if self.option_enabled("HISTORY"):
            cmd.append("-history")

        # Output file
        if output_file:
            cmd += ["-outputfile", str(output_file)]

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
            "credentials": [],
            "observations": [],
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

            # Parse only data lines; colon-bearing progress/error messages are not secrets.
            if ":" in line and not line.startswith(("[", "Impacket ")):
                parts = line.split(":")
                if in_sam:
                    if len(parts) >= 4 and parts[1].isdigit():
                        results["sam_hashes"].append(line)
                        results["total_hashes"] += 1
                elif in_lsa:
                    results["lsa_secrets"].append(line)
                elif in_ntds:
                    if len(parts) >= 4 and parts[1].isdigit():
                        results["ntds_hashes"].append(line)
                        results["total_hashes"] += 1

        for section, key in (("sam", "sam_hashes"), ("lsa", "lsa_secrets"), ("ntds", "ntds_hashes")):
            for line in results[key]:
                parts = line.split(":")
                domain, username = account(parts[0], self.get_option("DOMAIN") or "")
                record = {"username": username, "domain": domain, "source": self.tool_name,
                          "secret_source": section, "authenticated": False}
                if section in {"sam", "ntds"}:
                    record.update(rid=int(parts[1]), hash=f"{parts[2]}:{parts[3]}",
                                  lmhash=parts[2], nthash=parts[3], credential_type="ntlm")
                elif len(parts) >= 3 and parts[1].startswith(("aes", "des", "rc4")):
                    record.update(secret_type=parts[1], secret=":".join(parts[2:]), credential_type="kerberos_key")
                elif "\\" in parts[0] or "@" in parts[0]:
                    record.update(password=":".join(parts[1:]), credential_type="password")
                else:
                    record.update(secret=":".join(parts[1:]), credential_type="lsa_secret")
                results["credentials"].append(record)
                results["observations"].append(observation("credential", self.get_option("RHOST"), **record))
        results["success"] = results["success"] or bool(results["credentials"])

        return results
