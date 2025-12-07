"""
Wfuzz Module

Web application fuzzer for discovering hidden resources and parameters.
"""

from typing import Dict, Any, List
from purplesploit.core.module import ExternalToolModule


class WfuzzModule(ExternalToolModule):
    """
    Wfuzz - Web application fuzzer.

    Fuzzes web applications to discover hidden resources, parameters, and vulnerabilities.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "wfuzz"

    @property
    def name(self) -> str:
        return "Wfuzz"

    @property
    def description(self) -> str:
        return "Web application fuzzer for discovering hidden resources and testing parameters"

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
                "description": "Target URL with FUZZ keyword (e.g., http://target.com/FUZZ)",
                "default": None
            },
            "WORDLIST": {
                "value": "/usr/share/wordlists/dirb/common.txt",
                "required": False,
                "description": "Wordlist path",
                "default": "/usr/share/wordlists/dirb/common.txt"
            },
            "HIDE_CODE": {
                "value": "404",
                "required": False,
                "description": "Hide responses with this status code",
                "default": "404"
            },
            "HIDE_WORDS": {
                "value": None,
                "required": False,
                "description": "Hide responses with this number of words",
                "default": None
            },
            "HIDE_CHARS": {
                "value": None,
                "required": False,
                "description": "Hide responses with this number of chars",
                "default": None
            },
            "THREADS": {
                "value": "50",
                "required": False,
                "description": "Number of concurrent connections",
                "default": "50"
            },
            "METHOD": {
                "value": "GET",
                "required": False,
                "description": "HTTP method (GET, POST, PUT, etc.)",
                "default": "GET"
            },
            "DATA": {
                "value": None,
                "required": False,
                "description": "POST data (use FUZZ for fuzzing)",
                "default": None
            },
            "HEADERS": {
                "value": None,
                "required": False,
                "description": "Additional headers (e.g., 'Header: value')",
                "default": None
            },
            "FOLLOW": {
                "value": "false",
                "required": False,
                "description": "Follow redirects",
                "default": "false"
            }
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """
        Get list of wfuzz fuzzing operations.

        Subcategories:
        - discovery: Directory and file discovery
        - vhost: Virtual host and subdomain fuzzing
        - parameters: Parameter fuzzing (GET/POST)
        - advanced: Advanced fuzzing techniques

        Returns:
            List of operation dictionaries with subcategory tags
        """
        return [
            # === Discovery Operations ===
            {"name": "Directory Fuzzing", "description": "Fuzz directories and files", "handler": "op_dir_fuzz", "subcategory": "discovery"},
            {"name": "File Extension Fuzzing", "description": "Fuzz file extensions", "handler": "op_ext_fuzz", "subcategory": "discovery"},
            {"name": "Backup File Discovery", "description": "Search for backup files (.bak, .old, etc.)", "handler": "op_backup_fuzz", "subcategory": "discovery"},

            # === VHOST Operations ===
            {"name": "VHOST Fuzzing", "description": "Fuzz virtual hosts using Host header", "handler": "op_vhost_fuzz", "subcategory": "vhost"},
            {"name": "Subdomain Fuzzing", "description": "Fuzz subdomains", "handler": "op_subdomain_fuzz", "subcategory": "vhost"},

            # === Parameter Operations ===
            {"name": "GET Parameter Fuzzing", "description": "Fuzz GET parameters", "handler": "op_param_get_fuzz", "subcategory": "parameters"},
            {"name": "POST Parameter Fuzzing", "description": "Fuzz POST parameters", "handler": "op_param_post_fuzz", "subcategory": "parameters"},
            {"name": "Parameter Value Fuzzing", "description": "Fuzz parameter values", "handler": "op_param_value_fuzz", "subcategory": "parameters"},

            # === Advanced Operations ===
            {"name": "Header Fuzzing", "description": "Fuzz HTTP headers", "handler": "op_header_fuzz", "subcategory": "advanced"},
            {"name": "User-Agent Fuzzing", "description": "Fuzz User-Agent header", "handler": "op_useragent_fuzz", "subcategory": "advanced"},
            {"name": "Custom Fuzzing", "description": "Custom wfuzz command", "handler": "op_custom_fuzz", "subcategory": "advanced"},
        ]

    def build_command(self) -> str:
        """
        Build the wfuzz command.

        Returns:
            Command string to execute
        """
        url = self.get_option("URL")
        wordlist = self.get_option("WORDLIST")
        hide_code = self.get_option("HIDE_CODE")
        hide_words = self.get_option("HIDE_WORDS")
        hide_chars = self.get_option("HIDE_CHARS")
        threads = self.get_option("THREADS")
        method = self.get_option("METHOD")
        data = self.get_option("DATA")
        headers = self.get_option("HEADERS")
        follow = self.get_option("FOLLOW")

        # Base command
        cmd = f"wfuzz -w '{wordlist}'"

        # Threads
        if threads:
            cmd += f" -t {threads}"

        # Hide responses
        if hide_code:
            cmd += f" --hc {hide_code}"
        if hide_words:
            cmd += f" --hw {hide_words}"
        if hide_chars:
            cmd += f" --hh {hide_chars}"

        # HTTP method
        if method and method.upper() != "GET":
            cmd += f" -X {method.upper()}"

        # POST data
        if data:
            cmd += f" -d '{data}'"

        # Headers
        if headers:
            cmd += f" -H '{headers}'"

        # Follow redirects
        if follow and follow.lower() == "true":
            cmd += " -L"

        # URL (must be last)
        cmd += f" '{url}'"

        return cmd

    def parse_output(self, output: str) -> dict:
        """
        Parse wfuzz output.

        Args:
            output: Command stdout

        Returns:
            Parsed results dictionary
        """
        results = {
            "found_paths": [],
            "status_codes": {},
        }

        # Parse output
        for line in output.split('\n'):
            # Wfuzz output format: ID Response Lines Word Chars Request
            if line.strip() and not line.startswith('=') and not line.startswith('*'):
                parts = line.split()
                if len(parts) >= 4 and parts[1].isdigit():
                    status_code = parts[1]
                    path = parts[-1] if parts else ""

                    results["found_paths"].append({
                        "status": status_code,
                        "path": path,
                        "line": line.strip()
                    })

                    if status_code not in results["status_codes"]:
                        results["status_codes"][status_code] = 0
                    results["status_codes"][status_code] += 1

        return results

    # ========================================================================
    # Operation Handlers
    # ========================================================================

    def _execute_wfuzz(self, custom_args: str = "") -> Dict[str, Any]:
        """
        Execute wfuzz with custom arguments.

        Args:
            custom_args: Additional arguments to pass to wfuzz

        Returns:
            Execution results
        """
        threads = self.get_option("THREADS") or "50"
        hide_code = self.get_option("HIDE_CODE") or "404"

        # Build base command with just the custom args
        if custom_args:
            cmd = f"wfuzz -t {threads} --hc {hide_code} {custom_args}"
        else:
            cmd = self.build_command()

        return self.execute_command(cmd)

    # === Discovery Operations ===

    def op_dir_fuzz(self) -> Dict[str, Any]:
        """Fuzz directories and files."""
        url = self.get_option("URL") or input("Target URL (without path): ").strip()
        if not url:
            return {"success": False, "error": "URL required"}

        # Ensure URL ends with /
        if not url.endswith('/'):
            url += '/'

        wordlist = self.get_option("WORDLIST") or "/usr/share/wordlists/dirb/common.txt"

        # Build URL with FUZZ
        fuzz_url = f"{url}FUZZ"

        self.log(f"Fuzzing directories at: {url}", "info")
        return self._execute_wfuzz(f"-w '{wordlist}' '{fuzz_url}'")

    def op_ext_fuzz(self) -> Dict[str, Any]:
        """Fuzz file extensions."""
        url = self.get_option("URL") or input("Target URL (base filename, e.g., http://target.com/index): ").strip()
        if not url:
            return {"success": False, "error": "URL required"}

        # Extension wordlist
        ext_wordlist = input("Extension wordlist [/usr/share/seclists/Discovery/Web-Content/web-extensions.txt]: ").strip()
        if not ext_wordlist:
            ext_wordlist = "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt"

        # Build URL with FUZZ for extension
        fuzz_url = f"{url}FUZ2Z"

        self.log(f"Fuzzing extensions for: {url}", "info")
        return self._execute_wfuzz(f"-w '{ext_wordlist}' -z list,.FUZZ '{fuzz_url}'")

    def op_backup_fuzz(self) -> Dict[str, Any]:
        """Search for backup files."""
        url = self.get_option("URL") or input("Target URL (without path): ").strip()
        if not url:
            return {"success": False, "error": "URL required"}

        if not url.endswith('/'):
            url += '/'

        # Common backup extensions
        backup_exts = ".bak-.old-.backup-.copy-.tmp-~"
        wordlist = self.get_option("WORDLIST") or "/usr/share/wordlists/dirb/common.txt"

        fuzz_url = f"{url}FUZZFUZ2Z"

        self.log(f"Searching for backup files at: {url}", "info")
        return self._execute_wfuzz(f"-w '{wordlist}' -z list,{backup_exts} '{fuzz_url}'")

    # === VHOST Operations ===

    def op_vhost_fuzz(self) -> Dict[str, Any]:
        """Fuzz virtual hosts using Host header."""
        ip = input("Target IP address: ").strip()
        if not ip:
            return {"success": False, "error": "IP address required"}

        domain = input("Base domain (e.g., target.com): ").strip()
        if not domain:
            return {"success": False, "error": "Domain required"}

        wordlist = input("Wordlist [/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

        # Ask for hide options
        hide_chars = input("Hide responses with this many chars (optional, press Enter to skip): ").strip()
        hide_words = input("Hide responses with this many words (optional, press Enter to skip): ").strip()

        url = f"http://{ip}/"

        # Build hide options
        hide_opts = ""
        if hide_chars:
            hide_opts += f" --hh {hide_chars}"
        if hide_words:
            hide_opts += f" --hw {hide_words}"

        self.log(f"VHOST fuzzing: {domain} -> {ip}", "info")
        self.log("TIP: First run without filters, then re-run with --hh or --hw to hide common responses", "info")

        return self._execute_wfuzz(f"-w '{wordlist}' -H 'Host: FUZZ.{domain}'{hide_opts} '{url}'")

    def op_subdomain_fuzz(self) -> Dict[str, Any]:
        """Fuzz subdomains."""
        domain = input("Base domain (e.g., target.com): ").strip()
        if not domain:
            return {"success": False, "error": "Domain required"}

        wordlist = input("Wordlist [/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

        # Ask for hide options
        hide_chars = input("Hide responses with this many chars (optional, press Enter to skip): ").strip()

        url = f"http://FUZZ.{domain}/"

        # Build hide options
        hide_opts = ""
        if hide_chars:
            hide_opts += f" --hh {hide_chars}"

        self.log(f"Subdomain fuzzing for: {domain}", "info")
        return self._execute_wfuzz(f"-w '{wordlist}'{hide_opts} '{url}'")

    # === Parameter Operations ===

    def op_param_get_fuzz(self) -> Dict[str, Any]:
        """Fuzz GET parameters."""
        url = self.get_option("URL") or input("Target URL (e.g., http://target.com/page.php): ").strip()
        if not url:
            return {"success": False, "error": "URL required"}

        wordlist = input("Parameter wordlist [/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"

        # Build URL with GET parameter
        if '?' in url:
            fuzz_url = f"{url}&FUZZ=test"
        else:
            fuzz_url = f"{url}?FUZZ=test"

        self.log(f"GET parameter fuzzing: {url}", "info")
        return self._execute_wfuzz(f"-w '{wordlist}' '{fuzz_url}'")

    def op_param_post_fuzz(self) -> Dict[str, Any]:
        """Fuzz POST parameters."""
        url = self.get_option("URL") or input("Target URL: ").strip()
        if not url:
            return {"success": False, "error": "URL required"}

        wordlist = input("Parameter wordlist [/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"

        known_params = input("Known POST parameters (e.g., 'username=admin&password=test', optional): ").strip()

        # Build POST data
        if known_params:
            post_data = f"{known_params}&FUZZ=test"
        else:
            post_data = "FUZZ=test"

        self.log(f"POST parameter fuzzing: {url}", "info")
        return self._execute_wfuzz(f"-w '{wordlist}' -d '{post_data}' '{url}'")

    def op_param_value_fuzz(self) -> Dict[str, Any]:
        """Fuzz parameter values."""
        url = self.get_option("URL") or input("Target URL: ").strip()
        if not url:
            return {"success": False, "error": "URL required"}

        param_name = input("Parameter name to fuzz: ").strip()
        if not param_name:
            return {"success": False, "error": "Parameter name required"}

        method = input("Method (GET/POST) [GET]: ").strip().upper() or "GET"

        wordlist = input("Value wordlist [/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt"

        if method == "POST":
            post_data = f"{param_name}=FUZZ"
            self.log(f"POST parameter value fuzzing: {param_name}", "info")
            return self._execute_wfuzz(f"-w '{wordlist}' -d '{post_data}' '{url}'")
        else:
            if '?' in url:
                fuzz_url = f"{url}&{param_name}=FUZZ"
            else:
                fuzz_url = f"{url}?{param_name}=FUZZ"

            self.log(f"GET parameter value fuzzing: {param_name}", "info")
            return self._execute_wfuzz(f"-w '{wordlist}' '{fuzz_url}'")

    # === Advanced Operations ===

    def op_header_fuzz(self) -> Dict[str, Any]:
        """Fuzz HTTP headers."""
        url = self.get_option("URL") or input("Target URL: ").strip()
        if not url:
            return {"success": False, "error": "URL required"}

        header_name = input("Header name to fuzz (e.g., X-Forwarded-For): ").strip()
        if not header_name:
            return {"success": False, "error": "Header name required"}

        wordlist = input("Value wordlist [/usr/share/seclists/Fuzzing/special-chars.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Fuzzing/special-chars.txt"

        self.log(f"Header fuzzing: {header_name}", "info")
        return self._execute_wfuzz(f"-w '{wordlist}' -H '{header_name}: FUZZ' '{url}'")

    def op_useragent_fuzz(self) -> Dict[str, Any]:
        """Fuzz User-Agent header."""
        url = self.get_option("URL") or input("Target URL: ").strip()
        if not url:
            return {"success": False, "error": "URL required"}

        wordlist = input("User-Agent wordlist [/usr/share/seclists/Fuzzing/User-Agents/UserAgents.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Fuzzing/User-Agents/UserAgents.txt"

        self.log(f"User-Agent fuzzing: {url}", "info")
        return self._execute_wfuzz(f"-w '{wordlist}' -H 'User-Agent: FUZZ' '{url}'")

    def op_custom_fuzz(self) -> Dict[str, Any]:
        """Custom wfuzz command."""
        custom_cmd = input("Enter custom wfuzz arguments (without 'wfuzz'): ").strip()
        if not custom_cmd:
            return {"success": False, "error": "Custom command required"}

        self.log("Executing custom wfuzz command", "info")
        return self._execute_wfuzz(custom_cmd)
