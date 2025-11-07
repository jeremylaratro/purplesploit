"""
Feroxbuster Module

Directory and file discovery using feroxbuster.
"""

from purplesploit.core.module import ExternalToolModule
from typing import Dict, Any, List


class FeroxbusterModule(ExternalToolModule):
    """
    Feroxbuster module for directory and file discovery.

    Supports various scan types including basic, deep, custom wordlist,
    Burp integration, API discovery, and backup file discovery.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "feroxbuster"

    @property
    def name(self) -> str:
        return "Feroxbuster"

    @property
    def description(self) -> str:
        return "Directory and file discovery with 7 scan types"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "web"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "URL": {
                "value": None,
                "required": True,
                "description": "Target URL",
                "default": None
            },
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """
        Get list of feroxbuster scan operations.

        Returns:
            List of operation dictionaries
        """
        return [
            {"name": "Basic Directory Scan", "description": "Basic scan with thorough mode", "handler": "op_basic_scan"},
            {"name": "Deep Scan with Extensions", "description": "Deep scan with file extensions", "handler": "op_deep_scan"},
            {"name": "Custom Wordlist Scan", "description": "Scan with custom wordlist", "handler": "op_custom_wordlist"},
            {"name": "Burp Integration Scan", "description": "Scan with Burp Suite proxy", "handler": "op_burp_scan"},
            {"name": "API Discovery", "description": "Scan for API endpoints", "handler": "op_api_discovery"},
            {"name": "Backup File Discovery", "description": "Scan for backup files", "handler": "op_backup_discovery"},
            {"name": "Custom Scan", "description": "Custom scan with your own flags", "handler": "op_custom_scan"},
        ]

    def _get_url(self) -> str:
        """Get URL from options or prompt."""
        url = self.get_option("URL")
        if not url:
            url = input("Target URL: ")
            if url:
                self.set_option("URL", url)
        return url

    def _execute_feroxbuster(self, extra_args: str = "") -> Dict[str, Any]:
        """Execute feroxbuster with extra arguments."""
        url = self._get_url()
        if not url:
            return {"success": False, "error": "URL required"}

        cmd = f"feroxbuster -u '{url}' --thorough --methods GET,POST"

        if extra_args:
            cmd += f" {extra_args}"

        return self.execute_command(cmd, timeout=600)

    # ========================================================================
    # Operation Handlers
    # ========================================================================

    def op_basic_scan(self) -> Dict[str, Any]:
        """Basic directory scan with thorough mode."""
        self.log("Running basic scan with thorough mode", "info")
        return self._execute_feroxbuster()

    def op_deep_scan(self) -> Dict[str, Any]:
        """Deep scan with custom extensions."""
        exts = input("Extensions (e.g., php,html,js,txt) [default: php,html,js,txt,asp,aspx,jsp]: ")
        if not exts:
            exts = "php,html,js,txt,asp,aspx,jsp"

        self.log(f"Deep scan with extensions: {exts}", "info")
        return self._execute_feroxbuster(f"-x '{exts}' -t 50")

    def op_custom_wordlist(self) -> Dict[str, Any]:
        """Scan with custom wordlist."""
        wordlist = input("Wordlist path: ")
        if not wordlist:
            return {"success": False, "error": "Wordlist path required"}

        import os
        if not os.path.isfile(wordlist):
            return {"success": False, "error": f"Wordlist not found: {wordlist}"}

        return self._execute_feroxbuster(f"-w '{wordlist}'")

    def op_burp_scan(self) -> Dict[str, Any]:
        """Scan with Burp Suite integration."""
        proxy = input("Burp proxy [default: http://127.0.0.1:8080]: ")
        if not proxy:
            proxy = "http://127.0.0.1:8080"

        self.log("Scanning with Burp integration", "info")
        self.log("Make sure Burp is running and listening!", "warning")
        return self._execute_feroxbuster(f"--proxy '{proxy}'")

    def op_api_discovery(self) -> Dict[str, Any]:
        """Scan for API endpoints."""
        self.log("Scanning for API endpoints", "info")
        return self._execute_feroxbuster("--methods GET,POST,PUT,DELETE,PATCH -x json,xml")

    def op_backup_discovery(self) -> Dict[str, Any]:
        """Scan for backup files."""
        self.log("Scanning for backup files", "info")
        return self._execute_feroxbuster("-x bak,old,backup,zip,tar,gz,sql,db,config")

    def op_custom_scan(self) -> Dict[str, Any]:
        """Custom scan with user-provided flags."""
        custom_flags = input("Additional feroxbuster flags: ")
        if not custom_flags:
            return {"success": False, "error": "No flags provided"}

        return self._execute_feroxbuster(custom_flags)

    def run(self) -> Dict[str, Any]:
        """
        Fallback run method for basic scan.
        """
        return self.op_basic_scan()
