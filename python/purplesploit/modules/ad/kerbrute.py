"""
Kerbrute Module

Kerberos user enumeration and password spraying using kerbrute.
"""

from purplesploit.core.module import ExternalToolModule
from typing import List, Dict, Any
import os
import tempfile
import re
import shlex

from purplesploit.modules.impacket.common import account, observation


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
            "DC_IP": {
                "value": None, "required": False,
                "description": "Domain controller IP (takes precedence over DC)", "default": None
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
        operations = [
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
        requirements = {
            "User Enumeration": ["DOMAIN"], "Password Spray": ["DOMAIN", "PASSWORD"],
            "Brute Force": ["DOMAIN", "USERLIST", "PASSLIST"],
            "Brute User": ["DOMAIN", "USERNAME", "PASSLIST"],
        }
        for operation in operations:
            required = requirements[operation["name"]]
            operation.update(
                id=operation["handler"].__name__.removeprefix("op_"), tool="kerbrute",
                requires=required, optional=[key for key in self.options if key not in required],
                interactive=False, background=False,
                emits=["user"] if operation["name"] == "User Enumeration" else ["credential", "user"],
                supported_tool_versions=["1.0.3"], standards=[], subcategory="kerberos",
            )
        return operations

    def build_argv(self, operation="userenum", userlist=None):
        if not self.get_option("DOMAIN"):
            raise ValueError("DOMAIN required for Kerbrute")
        argv = shlex.split(self._build_base_command())
        argv.append(operation)
        if operation in {"userenum", "passwordspray"}:
            users = userlist or self.get_option("USERLIST")
            if not users or not os.path.isfile(str(users)):
                raise ValueError("USERLIST or USERNAME required; user list must exist")
            argv.append(str(users))
            if operation == "passwordspray":
                password = self.get_option("PASSWORD")
                if password is None:
                    raise ValueError("PASSWORD required for spray")
                argv.append(str(password))
        elif operation == "bruteforce":
            if not userlist:
                raise ValueError("Credential combinations must be materialized by op_bruteforce")
            argv.append(str(userlist))
        elif operation == "bruteuser":
            username, passlist = self.get_option("USERNAME"), self.get_option("PASSLIST")
            if not username or not passlist:
                raise ValueError("USERNAME and PASSLIST required for bruteuser")
            argv += [str(passlist), str(username)]
        else:
            raise ValueError(f"Unknown Kerbrute operation: {operation}")
        return argv

    def build_command(self) -> str:
        """Build the kerbrute command."""
        # Default to userenum
        return self._build_userenum_command()

    def _build_base_command(self) -> str:
        """Build base command with common options."""
        domain = self.get_option("DOMAIN")
        dc = self.get_option("DC_IP") or self.get_option("DC")
        threads = self.get_option("THREADS")
        output = self.get_option("OUTPUT")

        cmd = "kerbrute"

        # Domain controller
        if dc:
            cmd += f" --dc {self.quote_arg(dc)}"

        # Domain
        cmd += f" -d {self.quote_arg(domain)}"

        # Threads
        if threads:
            cmd += f" -t {self.quote_arg(threads)}"

        # Output file
        if output:
            cmd += f" -o {self.quote_arg(output)}"

        # Safe mode
        if self.option_enabled("SAFE"):
            cmd += " --safe"

        return cmd

    def _build_userenum_command(self) -> str:
        """Build user enumeration command."""
        cmd = self._build_base_command()
        userlist = self.get_option("USERLIST")
        username = self.get_option("USERNAME")

        cmd += " userenum"

        if userlist and os.path.exists(userlist):
            cmd += f" {self.quote_arg(userlist)}"
        elif username:
            return "echo 'Error: USERNAME must be materialized by op_userenum'"
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

        cmd += f" passwordspray {self.quote_arg(userlist)} {self.quote_arg(password)}"

        return cmd

    def _build_bruteforce_command(self) -> str:
        """Build brute force command."""
        cmd = self._build_base_command()
        userlist = self.get_option("USERLIST")
        passlist = self.get_option("PASSLIST")

        if not userlist or not passlist:
            return "echo 'Error: USERLIST and PASSLIST required for brute'"

        cmd += f" bruteforce {self.quote_arg(userlist)} {self.quote_arg(passlist)}"

        return cmd

    def _build_bruteuser_command(self) -> str:
        """Build brute user command."""
        cmd = self._build_base_command()
        username = self.get_option("USERNAME")
        passlist = self.get_option("PASSLIST")

        if not username or not passlist:
            return "echo 'Error: USERNAME and PASSLIST required for bruteuser'"

        cmd += f" bruteuser {self.quote_arg(passlist)} {self.quote_arg(username)}"

        return cmd

    def op_userenum(self) -> Dict[str, Any]:
        """Enumerate valid domain users."""
        temporary_userlist = None
        original_userlist = self.get_option("USERLIST")
        username = self.get_option("USERNAME")
        try:
            if (not original_userlist or not os.path.exists(str(original_userlist))) and username:
                if any(char in str(username) for char in "\r\n"):
                    raise ValueError("USERNAME must contain a single account")
                with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as handle:
                    handle.write(f"{username}\n")
                    temporary_userlist = handle.name
                os.chmod(temporary_userlist, 0o600)
                self.set_option("USERLIST", temporary_userlist)
            result = self.execute_command(self.build_argv("userenum"))
        except (ValueError, OSError) as exc:
            return {"success": False, "error": str(exc)}
        finally:
            if temporary_userlist:
                self.set_option("USERLIST", original_userlist)
                try:
                    os.unlink(temporary_userlist)
                except FileNotFoundError:
                    pass

        if "stdout" in result or "output" in result:
            parsed = self._parse_userenum(result.get("stdout", result.get("output", "")))
            result["parsed"] = parsed
            result["observations"] = parsed["observations"]
            result["message"] = f"Found {len(parsed.get('valid_users', []))} valid users"

            # Add valid users to session
            for user in parsed.get("valid_users", []):
                self._add_credential(user)

        return result

    def op_passwordspray(self) -> Dict[str, Any]:
        """Spray password against user list."""
        temporary_userlist = None
        try:
            userlist = self.get_option("USERLIST")
            if not userlist and self.get_option("USERNAME"):
                username = str(self.get_option("USERNAME"))
                if any(char in username for char in "\r\n"):
                    raise ValueError("USERNAME must contain a single account")
                with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as handle:
                    handle.write(f"{username}\n")
                    temporary_userlist = handle.name
                userlist = temporary_userlist
            result = self.execute_command(self.build_argv("passwordspray", userlist))
        except (ValueError, OSError) as exc:
            return {"success": False, "error": str(exc)}
        finally:
            if temporary_userlist:
                os.unlink(temporary_userlist)

        if "stdout" in result or "output" in result:
            parsed = self._parse_spray(result.get("stdout", result.get("output", "")))
            result["parsed"] = parsed
            result["observations"] = parsed["observations"]
            result["credentials"] = parsed["credentials"]
            result["authenticated"] = bool(parsed["valid_creds"])
            result["locked_out"] = bool(parsed["locked_out"])
            result["message"] = f"Found {len(parsed.get('valid_creds', []))} valid credentials"

            # Add valid credentials to session
            password = self.get_option("PASSWORD")
            for user in parsed.get("valid_creds", []):
                self._add_credential(user, password)

        return result

    def op_bruteforce(self) -> Dict[str, Any]:
        """Brute force passwords for users."""
        combos = None
        try:
            userlist, passlist = self.get_option("USERLIST"), self.get_option("PASSLIST")
            if not userlist or not passlist:
                raise ValueError("USERLIST and PASSLIST required for brute")
            with open(userlist, encoding="utf-8") as users, open(passlist, encoding="utf-8") as passwords:
                password_values = [value.rstrip("\r\n") for value in passwords]
                with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as handle:
                    combos = handle.name
                    for username in users:
                        username = username.strip()
                        if username:
                            for password in password_values:
                                handle.write(f"{username}:{password}\n")
            result = self.execute_command(self.build_argv("bruteforce", combos))
        except (ValueError, OSError) as exc:
            return {"success": False, "error": str(exc)}
        finally:
            if combos:
                os.unlink(combos)

        if "stdout" in result or "output" in result:
            parsed = self._parse_brute(result.get("stdout", result.get("output", "")))
            result["parsed"] = parsed
            result["observations"] = parsed["observations"]
            result["message"] = f"Found {len(parsed.get('valid_creds', []))} valid credentials"

            # Add valid credentials to session
            for cred in parsed.get("valid_creds", []):
                self._add_credential(cred.get("user"), cred.get("password"))

        return result

    def op_bruteuser(self) -> Dict[str, Any]:
        """Brute force passwords for single user."""
        try:
            result = self.execute_command(self.build_argv("bruteuser"))
        except (ValueError, OSError) as exc:
            return {"success": False, "error": str(exc)}

        if "stdout" in result or "output" in result:
            parsed = self._parse_brute(result.get("stdout", result.get("output", "")))
            result["parsed"] = parsed
            result["observations"] = parsed["observations"]

            if parsed.get("valid_creds"):
                cred = parsed["valid_creds"][0]
                result["message"] = f"Found password for {cred.get('user')}"
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
            if "VALID USERNAME:" in line.upper():
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

        observation_target = (
            self.get_option("DC_IP")
            or self.get_option("DC")
            or self.get_option("DOMAIN")
        )
        observations = [observation("user", observation_target, username=user, domain=self.get_option("DOMAIN"),
                                    valid=True, source="kerbrute") for user in valid_users]
        return {
            "valid_users": valid_users,
            "invalid_users": invalid_users,
            "total_valid": len(valid_users),
            "total_tested": len(valid_users) + len(invalid_users),
            "observations": observations,
        }

    def _parse_spray(self, output: str) -> Dict[str, Any]:
        """Parse password spray output."""
        valid_creds = []
        locked_out = []
        observations = []
        credentials = []

        for line in output.split('\n'):
            line = re.sub(r"\x1b\[[0-9;]*m", "", line).rstrip("\r")
            locked = "LOCKED" in line.upper() or "KDC_ERR_CLIENT_REVOKED" in line.upper()
            valid = "VALID LOGIN:" in line.upper()
            if not locked and not valid:
                continue
            match = re.search(r"([^\s@]+)@([^\s:]+)(?::(.*))?", line)
            if not match:
                continue
            domain, username = account(f"{match[1]}@{match[2]}")
            record = {"username": username, "domain": domain, "source": "kerbrute",
                      "protocol": "kerberos", "authenticated": valid and not locked,
                      "locked_out": locked, "status": "locked_out" if locked else "authenticated"}
            if locked:
                locked_out.append(username)
            else:
                valid_creds.append(username)
                password = match[3] if match[3] is not None else self.get_option("PASSWORD")
                if password is not None:
                    record["password"] = password
                credentials.append(record)
            observations.append(observation("credential", self.get_option("DC_IP") or self.get_option("DC") or domain,
                                            **record))
            observations.append(observation("user", self.get_option("DC_IP") or self.get_option("DC") or domain,
                                            username=username, domain=domain,
                                            locked_out=locked, valid=True))

        return {
            "valid_creds": valid_creds,
            "locked_out": locked_out,
            "total_valid": len(valid_creds),
            "credentials": credentials,
            "observations": observations,
        }

    def _parse_brute(self, output: str) -> Dict[str, Any]:
        """Parse brute force output."""
        result = self._parse_spray(output)
        result["valid_creds"] = [{"user": credential["username"], "password": credential.get("password")}
                                 for credential in result["credentials"]]
        return result

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
