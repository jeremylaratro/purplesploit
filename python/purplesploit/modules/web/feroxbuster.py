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

    @property
    def parameter_profiles(self) -> List[str]:
        """Use web scanning parameter profile."""
        return ["web_scan_advanced"]

    # Legacy _init_options removed - now using parameter profiles

    def _init_parameters(self):
        """Set URL as required parameter."""
        super()._init_parameters()
        # Make URL required for web scanning
        if "URL" in self.parameters:
            self.parameters["URL"].required = True
            self.options["URL"]["required"] = True

    def get_operations(self) -> List[Dict[str, Any]]:
        """
        Get list of feroxbuster scan operations.

        Returns:
            List of operation dictionaries
        """
        return [
            {"name": "Basic Directory Scan", "description": "Basic scan with thorough mode", "handler": "op_basic_scan"},
            {"name": "Background Basic Scan", "description": "Basic scan running in background", "handler": "op_background_scan"},
            {"name": "Deep Scan with Extensions", "description": "Deep scan with file extensions", "handler": "op_deep_scan"},
            {"name": "Custom Wordlist Scan", "description": "Scan with custom wordlist", "handler": "op_custom_wordlist"},
            {"name": "Burp Integration Scan", "description": "Scan with Burp Suite proxy", "handler": "op_burp_scan"},
            {"name": "API Discovery", "description": "Scan for API endpoints", "handler": "op_api_discovery"},
            {"name": "Backup File Discovery", "description": "Scan for backup files", "handler": "op_backup_discovery"},
            {"name": "Custom Scan", "description": "Custom scan with your own flags", "handler": "op_custom_scan"},
        ]

    def _get_url(self) -> str:
        """Get URL from options or prompt with web service selection support."""
        url = self.get_option("URL")
        if url:
            return url

        # Interactive URL selection
        from purplesploit.ui.interactive import InteractiveSelector
        selector = InteractiveSelector()

        # Prompt: Select from DB or use selected target
        try:
            with open('/dev/tty', 'r') as tty_in, open('/dev/tty', 'w') as tty_out:
                print("\n" + "="*60, file=tty_out)
                print("Web Target Selection", file=tty_out)
                print("="*60, file=tty_out)
                print("\nOptions:", file=tty_out)
                print("  1. Select web target from database", file=tty_out)
                print("  2. Use selected target from framework", file=tty_out)
                print("  3. Enter URL manually", file=tty_out)
                print("\nChoice (1-3): ", file=tty_out, end='', flush=True)
                choice = tty_in.readline().strip()

                if choice == '1':
                    # Get web services from database
                    web_services = self.framework.database.get_web_services()
                    if not web_services:
                        print("\n[!] No web services found in database", file=tty_out)
                        print("[!] Run an nmap scan first to discover web services", file=tty_out)
                        return None

                    # Format for FZF selection
                    service_lines = []
                    for i, ws in enumerate(web_services, 1):
                        line = f"{i:2d}. {ws['url']:40s} [{ws['service']:10s}] port {ws['port']}"
                        service_lines.append(line)

                    # Use FZF to select
                    if selector.has_fzf:
                        selected = selector.select_from_list(
                            service_lines,
                            prompt="Select Web Target: "
                        )
                        if selected:
                            # Extract index and get URL
                            try:
                                idx = int(selected.split('.')[0].strip()) - 1
                                url = web_services[idx]['url']
                                self.set_option("URL", url)
                                return url
                            except (ValueError, IndexError):
                                return None
                    else:
                        # Fallback without FZF
                        print("\nAvailable web targets:", file=tty_out)
                        for line in service_lines:
                            print(f"  {line}", file=tty_out)
                        print(f"\nSelect (1-{len(web_services)}): ", file=tty_out, end='', flush=True)
                        sel = tty_in.readline().strip()
                        if sel.isdigit():
                            idx = int(sel) - 1
                            if 0 <= idx < len(web_services):
                                url = web_services[idx]['url']
                                self.set_option("URL", url)
                                return url

                elif choice == '2':
                    # Use selected target from framework
                    target = self.framework.session.current_target
                    if not target:
                        print("\n[!] No target selected in framework", file=tty_out)
                        print("[!] Use 'target <ip>' command first", file=tty_out)
                        return None

                    # Add http:// protocol if not present
                    if target.startswith('http://') or target.startswith('https://'):
                        url = target
                    else:
                        url = f"http://{target}"

                    self.set_option("URL", url)
                    return url

                elif choice == '3':
                    # Manual entry
                    print("\nTarget URL: ", file=tty_out, end='', flush=True)
                    url = tty_in.readline().strip()
                    if url:
                        # Add protocol if not present
                        if not url.startswith('http://') and not url.startswith('https://'):
                            url = f"http://{url}"
                        self.set_option("URL", url)
                        return url

        except (KeyboardInterrupt, EOFError):
            return None

        return None

    def _execute_feroxbuster(self, extra_args: str = "", run_background: bool = False) -> Dict[str, Any]:
        """
        Execute feroxbuster with extra arguments.

        Args:
            extra_args: Additional arguments to pass to feroxbuster
            run_background: If True, run in background

        Returns:
            Dictionary with execution results
        """
        import os
        from pathlib import Path
        from datetime import datetime

        url = self._get_url()
        if not url:
            return {"success": False, "error": "URL required"}

        # Create logs directory if it doesn't exist
        log_dir = Path.home() / ".purplesploit" / "logs" / "web"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Generate log filename with timestamp and target
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = url.replace('://', '_').replace('/', '_').replace(':', '_')
        log_file = log_dir / f"feroxbuster_{safe_url}_{timestamp}.txt"

        # Build feroxbuster command with output file
        cmd = f"feroxbuster -u '{url}' --thorough --methods GET,POST -o '{log_file}'"

        if extra_args:
            cmd += f" {extra_args}"

        # Execute command
        if run_background:
            self.log(f"Starting feroxbuster scan in background", "info")
            self.log(f"Log file: {log_file}", "info")
            result = self.execute_command(cmd, background=True, timeout=600)

            if result.get('success'):
                # Store scan info in database for later retrieval
                self.framework.database.save_scan_results(
                    scan_name="feroxbuster",
                    target=url,
                    scan_type="web",
                    results={"status": "running", "pid": result.get('pid')},
                    file_path=str(log_file)
                )
                result['log_file'] = str(log_file)
                result['message'] = f"Scan started in background (PID: {result.get('pid')}). Results will be saved to {log_file}"

            return result
        else:
            # Run synchronously
            self.log(f"Starting feroxbuster scan", "info")
            self.log(f"Log file: {log_file}", "info")
            result = self.execute_command(cmd, timeout=600)

            # Parse and store results
            if result.get('success') and os.path.exists(log_file):
                parsed_results = self._parse_feroxbuster_results(log_file, url)
                result['parsed_results'] = parsed_results

                # Store in database
                self.framework.database.save_scan_results(
                    scan_name="feroxbuster",
                    target=url,
                    scan_type="web",
                    results=parsed_results,
                    file_path=str(log_file)
                )

                result['log_file'] = str(log_file)
                self.log(f"Results saved to {log_file}", "success")

            return result

    def _parse_feroxbuster_results(self, log_file: str, url: str) -> Dict[str, Any]:
        """
        Parse feroxbuster results from log file.

        Args:
            log_file: Path to feroxbuster output file
            url: Target URL

        Returns:
            Dictionary with parsed results
        """
        import re
        from pathlib import Path

        results = {
            'target': url,
            'found_paths': [],
            'total_requests': 0,
            'status_codes': {},
            'interesting_finds': []
        }

        if not Path(log_file).exists():
            return results

        try:
            with open(log_file, 'r') as f:
                content = f.read()

            # Parse discovered paths (format: STATUS SIZE URL)
            path_pattern = r'(\d{3})\s+(\d+)l?\s+(\d+)w?\s+(\d+)c?\s+(https?://[^\s]+)'
            matches = re.findall(path_pattern, content)

            for match in matches:
                status, lines, words, chars, found_url = match
                status = int(status)

                path_info = {
                    'url': found_url,
                    'status': status,
                    'size': int(chars),
                    'path': found_url.replace(url, '')
                }

                results['found_paths'].append(path_info)
                results['total_requests'] += 1

                # Track status codes
                status_key = str(status)
                results['status_codes'][status_key] = results['status_codes'].get(status_key, 0) + 1

                # Flag interesting findings
                if status == 200:
                    results['interesting_finds'].append(path_info)
                elif status in (301, 302, 307, 308):
                    results['interesting_finds'].append({**path_info, 'note': 'redirect'})
                elif status == 403:
                    results['interesting_finds'].append({**path_info, 'note': 'forbidden'})

        except Exception as e:
            self.log(f"Error parsing results: {str(e)}", "error")

        return results

    # ========================================================================
    # Operation Handlers
    # ========================================================================

    def op_basic_scan(self) -> Dict[str, Any]:
        """Basic directory scan with thorough mode."""
        self.log("Running basic scan with thorough mode", "info")
        return self._execute_feroxbuster()

    def op_background_scan(self) -> Dict[str, Any]:
        """Basic directory scan running in background."""
        self.log("Starting basic scan in background", "info")
        return self._execute_feroxbuster(run_background=True)

    def op_deep_scan(self) -> Dict[str, Any]:
        """Deep scan with custom extensions."""
        # Use EXTENSIONS parameter from profile
        exts = self.get_option("EXTENSIONS")
        if not exts:
            exts = "php,html,js,txt,asp,aspx,jsp"

        # Use THREADS parameter from profile
        threads = self.get_option("THREADS") or 50

        self.log(f"Deep scan with extensions: {exts}, threads: {threads}", "info")
        return self._execute_feroxbuster(f"-x '{exts}' -t {threads}")

    def op_custom_wordlist(self) -> Dict[str, Any]:
        """Scan with custom wordlist."""
        # Use WORDLIST parameter from profile
        wordlist = self.get_option("WORDLIST")
        if not wordlist:
            # Prompt if not set
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
