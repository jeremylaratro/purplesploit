"""
SMB Shares Module

Browse, download, and upload files via SMB shares.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class SMBSharesModule(ExternalToolModule):
    """SMB share browsing and file operations."""

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nxc"

    @property
    def name(self) -> str:
        return "SMB Shares"

    @property
    def description(self) -> str:
        return "SMB share browsing and file operations"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "smb"

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
                "default": "WORKGROUP"
            },
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of share operations."""
        return [
            {"name": "Browse & Download (Interactive)", "description": "Spider and download files interactively", "handler": "op_browse_download"},
            {"name": "Download All Files", "description": "Recursively download all files from shares", "handler": "op_download_all"},
            {"name": "Download by Pattern", "description": "Download files matching pattern (e.g., *.xlsx)", "handler": "op_download_pattern"},
            {"name": "Spider Only (No Download)", "description": "List files without downloading", "handler": "op_spider_only"},
            {"name": "Spider Specific Share", "description": "Spider a specific share name", "handler": "op_spider_share"},
            {"name": "Download Specific File", "description": "Download file from manual path", "handler": "op_download_file"},
            {"name": "Upload File", "description": "Upload file to target", "handler": "op_upload_file"},
        ]

    def _build_auth(self) -> str:
        """Build authentication string for nxc."""
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")

        if not username:
            return ""

        auth = f"-u '{username}'"
        if password:
            auth += f" -p '{password}'"
        else:
            auth += " -p ''"

        return auth

    def _execute_nxc(self, extra_args: str = "") -> Dict[str, Any]:
        """Execute nxc smb command."""
        rhost = self.get_option("RHOST")
        domain = self.get_option("DOMAIN")
        auth = self._build_auth()

        cmd = f"nxc smb {rhost} {auth}"

        if domain and domain != "WORKGROUP":
            cmd += f" -d {domain}"

        if extra_args:
            cmd += f" {extra_args}"

        return self.execute_command(cmd, timeout=300)

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

    def run(self) -> Dict[str, Any]:
        """Default run - browse and download interactively."""
        return self.op_browse_download()
