"""
Kerbrute Module

Kerberos user enumeration and password spraying using kerbrute.
"""

from purplesploit.core.module import ExternalToolModule
from typing import List, Dict, Any
import os


class KerbruteModule(ExternalToolModule):
    """
    Kerbrute - Kerberos brute force and user enumeration.

    Fast Kerberos user enumeration and password spraying tool.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "kerbrute"

    @property
    def name(self) -> str:
        return "Kerbrute"

    @property
    def description(self) -> str:
        return "Kerberos user enumeration and password spraying"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "ad"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "DOMAIN": {
                "value": None,
                "required": True,
                "description": "Target domain (e.g., corp.local)",
                "default": None
            },
            "DC": {
                "value": None,
                "required": False,
                "description": "Domain controller IP/hostname (auto-detected if not set)",
                "default": None
            },
            "USERLIST": {
                "value": None,
                "required": False,
                "description": "Path to file containing usernames",
                "default": None
            },
            "USERNAME": {
                "value": None,
                "required": False,
                "description": "Single username to test",
                "default": None
            },
            "PASSWORD": {
                "value": None,
                "required": False,
                "description": "Password for spraying",
                "default": None
            },
            "PASSLIST": {
                "value": None,
                "required": False,
                "description": "Path to file containing passwords",
                "default": None
            },
            "THREADS": {
                "value": "10",
                "required": False,
                "description": "Number of threads",
                "default": "10"
            },
            "OUTPUT": {
                "value": None,
                "required": False,
                "description": "Output file for results",
                "default": None
            },
            "SAFE": {
                "value": "true",
                "required": False,
                "description": "Safe mode - stop on lockout detection",
                "default": "true"
            },
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get available Kerbrute operations."""
        return [
            {
                "name": "User Enumeration",
                "description": "Enumerate valid domain users via Kerberos",
                "handler": self.op_userenum
            },
            {
                "name": "Password Spray",
                "description": "Spray single password against user list",
                "handler": self.op_passwordspray
            },
            {
                "name": "Brute Force",
                "description": "Brute force passwords for users",
                "handler": self.op_bruteforce
            },
            {
                "name": "Brute User",
                "description": "Brute force passwords for single user",
                "handler": self.op_bruteuser
            },
        ]

    def build_command(self) -> str:
        """Build the kerbrute command."""
        # Default to userenum
        return self._build_userenum_command()

    def _build_base_command(self) -> str:
        """Build base command with common options."""
        domain = self.get_option("DOMAIN")
        dc = self.get_option("DC")
        threads = self.get_option("THREADS")
        output = self.get_option("OUTPUT")
        safe = self.get_option("SAFE")

        cmd = "kerbrute"

        # Domain controller
        if dc:
            cmd += f" --dc {dc}"

        # Domain
        cmd += f" -d {domain}"

        # Threads
        if threads:
            cmd += f" -t {threads}"

        # Output file
        if output:
            cmd += f" -o {output}"

        # Safe mode
        if safe and safe.lower() == "true":
            cmd += " --safe"

        return cmd

    def _build_userenum_command(self) -> str:
        """Build user enumeration command."""
        cmd = self._build_base_command()
        userlist = self.get_option("USERLIST")
        username = self.get_option("USERNAME")

        cmd += " userenum"

        if userlist and os.path.exists(userlist):
            cmd += f" {userlist}"
        elif username:
            # Create temp file with single user
            cmd += f" <(echo '{username}')"
        else:
            return "echo 'Error: USERLIST or USERNAME required'"

        return cmd

    def _build_passwordspray_command(self) -> str:
        """Build password spray command."""
        cmd = self._build_base_command()
        userlist = self.get_option("USERLIST")
        password = self.get_option("PASSWORD")

        if not userlist or not password:
            return "echo 'Error: USERLIST and PASSWORD required for spray'"

        cmd += f" passwordspray {userlist} '{password}'"

        return cmd

    def _build_bruteforce_command(self) -> str:
        """Build brute force command."""
        cmd = self._build_base_command()
        userlist = self.get_option("USERLIST")
        passlist = self.get_option("PASSLIST")

        if not userlist or not passlist:
            return "echo 'Error: USERLIST and PASSLIST required for brute'"

        cmd += f" bruteforce {userlist} {passlist}"

        return cmd

    def _build_bruteuser_command(self) -> str:
        """Build brute user command."""
        cmd = self._build_base_command()
        username = self.get_option("USERNAME")
        passlist = self.get_option("PASSLIST")

        if not username or not passlist:
            return "echo 'Error: USERNAME and PASSLIST required for bruteuser'"

        cmd += f" bruteuser {passlist} {username}"

        return cmd

    def op_userenum(self) -> Dict[str, Any]:
        """Enumerate valid domain users."""
        cmd = self._build_userenum_command()
        result = self.execute_command(cmd)

        if result.get("success"):
            parsed = self._parse_userenum(result.get("output", ""))
            result["parsed"] = parsed
            result["message"] = f"Found {len(parsed.get('valid_users', []))} valid users"

            # Add valid users to session
            for user in parsed.get("valid_users", []):
                self._add_credential(user)

        return result

    def op_passwordspray(self) -> Dict[str, Any]:
        """Spray password against user list."""
        cmd = self._build_passwordspray_command()
        result = self.execute_command(cmd)

        if result.get("success"):
            parsed = self._parse_spray(result.get("output", ""))
            result["parsed"] = parsed
            result["message"] = f"Found {len(parsed.get('valid_creds', []))} valid credentials"

            # Add valid credentials to session
            password = self.get_option("PASSWORD")
            for user in parsed.get("valid_creds", []):
                self._add_credential(user, password)

        return result

    def op_bruteforce(self) -> Dict[str, Any]:
        """Brute force passwords for users."""
        cmd = self._build_bruteforce_command()
        result = self.execute_command(cmd)

        if result.get("success"):
            parsed = self._parse_brute(result.get("output", ""))
            result["parsed"] = parsed
            result["message"] = f"Found {len(parsed.get('valid_creds', []))} valid credentials"

            # Add valid credentials to session
            for cred in parsed.get("valid_creds", []):
                self._add_credential(cred.get("user"), cred.get("password"))

        return result

    def op_bruteuser(self) -> Dict[str, Any]:
        """Brute force passwords for single user."""
        cmd = self._build_bruteuser_command()
        result = self.execute_command(cmd)

        if result.get("success"):
            parsed = self._parse_brute(result.get("output", ""))
            result["parsed"] = parsed

            if parsed.get("valid_creds"):
                cred = parsed["valid_creds"][0]
                result["message"] = f"Found password for {cred.get('user')}: {cred.get('password')}"
                self._add_credential(cred.get("user"), cred.get("password"))
            else:
                result["message"] = "No valid password found"

        return result

    def _parse_userenum(self, output: str) -> Dict[str, Any]:
        """Parse user enumeration output."""
        valid_users = []
        invalid_users = []

        for line in output.split('\n'):
            line = line.strip()

            # Look for valid user indicators
            if "VALID USERNAME:" in line.upper() or "[+]" in line:
                # Extract username
                parts = line.split()
                for i, part in enumerate(parts):
                    if "@" in part:
                        username = part.split("@")[0]
                        valid_users.append(username)
                        break

            # Look for invalid user indicators
            elif "INVALID" in line.upper() or "[-]" in line:
                parts = line.split()
                for part in parts:
                    if "@" in part:
                        username = part.split("@")[0]
                        invalid_users.append(username)
                        break

        return {
            "valid_users": valid_users,
            "invalid_users": invalid_users,
            "total_valid": len(valid_users),
            "total_tested": len(valid_users) + len(invalid_users)
        }

    def _parse_spray(self, output: str) -> Dict[str, Any]:
        """Parse password spray output."""
        valid_creds = []
        locked_out = []

        for line in output.split('\n'):
            line = line.strip()

            if "VALID LOGIN" in line.upper() or "[+]" in line:
                parts = line.split()
                for part in parts:
                    if "@" in part:
                        username = part.split("@")[0]
                        valid_creds.append(username)
                        break

            elif "LOCKED" in line.upper():
                parts = line.split()
                for part in parts:
                    if "@" in part:
                        username = part.split("@")[0]
                        locked_out.append(username)
                        break

        return {
            "valid_creds": valid_creds,
            "locked_out": locked_out,
            "total_valid": len(valid_creds)
        }

    def _parse_brute(self, output: str) -> Dict[str, Any]:
        """Parse brute force output."""
        valid_creds = []

        for line in output.split('\n'):
            line = line.strip()

            if "VALID LOGIN" in line.upper() or "[+]" in line:
                # Try to extract user:pass
                if ":" in line:
                    # Find the credential pair
                    parts = line.split()
                    for part in parts:
                        if "@" in part and ":" in part:
                            user_domain, password = part.rsplit(":", 1)
                            username = user_domain.split("@")[0]
                            valid_creds.append({
                                "user": username,
                                "password": password
                            })
                            break

        return {
            "valid_creds": valid_creds,
            "total_valid": len(valid_creds)
        }

    def _add_credential(self, username: str, password: str = None):
        """Add discovered credential to session."""
        if self.framework and hasattr(self.framework, 'session'):
            try:
                domain = self.get_option("DOMAIN")
                cred_data = {
                    'username': username,
                    'domain': domain,
                    'source': 'kerbrute'
                }
                if password:
                    cred_data['password'] = password

                self.framework.session.credentials.add(cred_data)
            except Exception:
                pass

    def parse_output(self, output: str) -> dict:
        """Parse kerbrute output."""
        return self._parse_userenum(output)

    def run(self) -> Dict[str, Any]:
        """Default run performs user enumeration."""
        return self.op_userenum()
