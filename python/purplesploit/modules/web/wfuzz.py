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
            "TARGET": {
                "value": None,
                "required": True,
                "description": "Target domain or IP (e.g., target.com or 192.168.1.10)",
                "default": None
            },
            "URL": {
                "value": None,
                "required": False,
                "description": "Full URL override (optional, overrides TARGET)",
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
            },
            "SMART_FILTER": {
                "value": "true",
                "required": False,
                "description": "Enable smart response filtering (auto-detect common responses)",
                "default": "true"
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
    # Helper Methods
    # ========================================================================

    def _parse_wfuzz_responses(self, output: str) -> Dict[str, Any]:
        """
        Parse wfuzz output to analyze response patterns.

        Args:
            output: Wfuzz command output

        Returns:
            Dictionary with response statistics
        """
        from collections import Counter
        import re

        lines_count = Counter()
        words_count = Counter()
        chars_count = Counter()
        responses = []

        # Strip ANSI color codes first
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean_output = ansi_escape.sub('', output)

        for line in clean_output.split('\n'):
            # Wfuzz output format: ID Response Lines Word Chars Request
            # Example: 000000001:   301        7 L      11 W       162 Ch      "www"
            # Strip box-drawing characters and whitespace
            clean_line = line.replace('│', '').replace('├', '').replace('─', '').replace('╭', '').replace('╮', '').replace('╯', '').replace('╰', '').strip()

            # More flexible regex to handle variable spacing
            # Pattern: 7 L   11 W    162 Ch
            match = re.search(r'(\d+)\s+L\s+(\d+)\s+W\s+(\d+)\s+Ch', clean_line)
            if match:
                lines = int(match.group(1))
                words = int(match.group(2))
                chars = int(match.group(3))

                lines_count[lines] += 1
                words_count[words] += 1
                chars_count[chars] += 1

                responses.append({
                    'lines': lines,
                    'words': words,
                    'chars': chars,
                    'full_line': clean_line
                })

        # Find most common values
        most_common_lines = lines_count.most_common(1)[0] if lines_count else (0, 0)
        most_common_words = words_count.most_common(1)[0] if words_count else (0, 0)
        most_common_chars = chars_count.most_common(1)[0] if chars_count else (0, 0)

        result = {
            'responses': responses,
            'total_responses': len(responses),
            'most_common_lines': most_common_lines[0] if most_common_lines[1] > 0 else None,
            'most_common_lines_count': most_common_lines[1] if most_common_lines[1] > 0 else 0,
            'most_common_words': most_common_words[0] if most_common_words[1] > 0 else None,
            'most_common_words_count': most_common_words[1] if most_common_words[1] > 0 else 0,
            'most_common_chars': most_common_chars[0] if most_common_chars[1] > 0 else None,
            'most_common_chars_count': most_common_chars[1] if most_common_chars[1] > 0 else 0,
            'lines_distribution': dict(lines_count),
            'words_distribution': dict(words_count),
            'chars_distribution': dict(chars_count),
        }

        return result

    def _smart_filter_prompt(self, stats: Dict[str, Any], original_cmd: str) -> Dict[str, Any]:
        """
        Analyze wfuzz results and prompt to re-run with smart filters.

        Args:
            stats: Response statistics from _parse_wfuzz_responses
            original_cmd: Original wfuzz command

        Returns:
            Re-run results or original results
        """
        if stats['total_responses'] == 0:
            self.log("No responses parsed - smart filtering unavailable", "warning")
            self.log("(This might be due to no results or parsing issues)", "debug")
            return None

        # Calculate what percentage of responses are the most common
        total = stats['total_responses']
        common_lines_pct = (stats['most_common_lines_count'] / total * 100) if total > 0 else 0
        common_words_pct = (stats['most_common_words_count'] / total * 100) if total > 0 else 0
        common_chars_pct = (stats['most_common_chars_count'] / total * 100) if total > 0 else 0

        # Show analysis
        self.log("\n" + "="*70, "info")
        self.log("SMART FILTER ANALYSIS", "info")
        self.log("="*70, "info")
        self.log(f"Total responses: {total}", "info")

        if stats['most_common_lines']:
            self.log(f"\nMost common LINES: {stats['most_common_lines']} ({stats['most_common_lines_count']} responses = {common_lines_pct:.1f}%)", "info")

        if stats['most_common_words']:
            self.log(f"Most common WORDS: {stats['most_common_words']} ({stats['most_common_words_count']} responses = {common_words_pct:.1f}%)", "info")

        if stats['most_common_chars']:
            self.log(f"Most common CHARS: {stats['most_common_chars']} ({stats['most_common_chars_count']} responses = {common_chars_pct:.1f}%)", "info")

        # Show unique response sizes if not too many
        unique_sizes = len(stats['lines_distribution'])
        if unique_sizes <= 5:
            self.log(f"\nUnique response sizes found: {unique_sizes}", "info")
            for lines, count in sorted(stats['lines_distribution'].items()):
                words = [w for r in stats['responses'] if r['lines'] == lines for w in [r['words']]][0]
                chars = [c for r in stats['responses'] if r['lines'] == lines for c in [r['chars']]][0]
                self.log(f"  {lines}L / {words}W / {chars}Ch: {count} responses", "info")

        # Determine if filtering would be beneficial (if most common response is >50% of results)
        should_filter = max(common_lines_pct, common_words_pct, common_chars_pct) > 50

        if should_filter:
            self.log("\n🎯 A dominant response pattern detected! Filtering recommended.", "success")
            self.log("="*70 + "\n", "info")

            # Ask user which filter to use
            filter_choice = input("Re-run with filter? (L=lines, W=words, C=chars, N=no) [L]: ").strip().upper() or "L"

            if filter_choice == "N":
                self.log("Keeping original results (no filter applied)", "info")
                return None

            # Build filter command
            filter_arg = ""
            if filter_choice == "L" and stats['most_common_lines']:
                filter_arg = f"--hl {stats['most_common_lines']}"
                self.log(f"Re-running with filter: hiding {stats['most_common_lines']} lines...", "info")
            elif filter_choice == "W" and stats['most_common_words']:
                filter_arg = f"--hw {stats['most_common_words']}"
                self.log(f"Re-running with filter: hiding {stats['most_common_words']} words...", "info")
            elif filter_choice == "C" and stats['most_common_chars']:
                filter_arg = f"--hh {stats['most_common_chars']}"
                self.log(f"Re-running with filter: hiding {stats['most_common_chars']} chars...", "info")
            else:
                self.log("Invalid choice, keeping original results", "warning")
                return None

            # Re-run with filter
            filtered_cmd = f"{original_cmd} {filter_arg}"
            return self.execute_command(filtered_cmd)
        else:
            self.log("\n✓ Good result diversity - no filtering needed", "success")
            self.log("="*70 + "\n", "info")
            return None

    def _is_smart_filter_enabled(self) -> bool:
        """Check if smart filtering is enabled."""
        smart_filter = self.get_option("SMART_FILTER")
        return smart_filter and smart_filter.lower() == "true"

    def _get_target(self) -> str:
        """
        Get target from TARGET or URL option.

        Returns:
            Target domain/IP or None
        """
        # URL takes precedence if set
        url = self.get_option("URL")
        if url:
            return url

        return self.get_option("TARGET")

    def _build_url(self, path: str = "/", scheme: str = "http") -> str:
        """
        Build full URL from TARGET.

        Args:
            path: Path to append (default: /)
            scheme: http or https (default: http)

        Returns:
            Full URL
        """
        target = self._get_target()
        if not target:
            return None

        # If target already has a scheme, use it as-is
        if target.startswith("http://") or target.startswith("https://"):
            return target if not path or path == "/" else f"{target.rstrip('/')}{path}"

        # Otherwise build URL
        return f"{scheme}://{target}{path}"

    # ========================================================================
    # Operation Handlers
    # ========================================================================

    def _execute_wfuzz(self, custom_args: str = "", enable_smart_filter: bool = None) -> Dict[str, Any]:
        """
        Execute wfuzz with custom arguments and optional smart filtering.

        Args:
            custom_args: Additional arguments to pass to wfuzz
            enable_smart_filter: Enable smart response analysis and filtering (None = use SMART_FILTER option)

        Returns:
            Execution results
        """
        import subprocess
        import time
        import signal

        threads = self.get_option("THREADS") or "50"
        hide_code = self.get_option("HIDE_CODE") or "404"

        # Build base command
        if custom_args:
            cmd = f"wfuzz -t {threads} --hc {hide_code} {custom_args}"
        else:
            cmd = self.build_command()

        # Check if smart filtering is enabled
        if enable_smart_filter is None:
            enable_smart_filter = self._is_smart_filter_enabled()

        # If smart filtering enabled, do sample run first
        if enable_smart_filter:
            print("\n" + "="*70)
            print("🚀 SMART FILTERING V3.0 - WITH CHAR FILTER FIX")
            print("="*70 + "\n")
            print(f"[*] Starting wfuzz sample...")
            print(f"[*] Command: {cmd[:100]}...")

            try:
                # Run wfuzz for 5 seconds to sample responses
                print("[*] Launching process...")
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )

                # Wait 5 seconds with progress
                print("[*] Sampling for 5 seconds", end='', flush=True)
                for i in range(5):
                    time.sleep(1)
                    print(".", end='', flush=True)
                print()

                # Kill the process
                print("[*] Stopping sample...")
                process.send_signal(signal.SIGTERM)
                time.sleep(0.5)

                # Get partial output
                print("[*] Collecting output...")
                try:
                    stdout, stderr = process.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()

                output = stdout + stderr
                print(f"[*] Captured {len(output)} chars of output")

                # Parse sample responses
                print("[*] Parsing responses...")
                stats = self._parse_wfuzz_responses(output)
                print(f"[*] Found {stats['total_responses']} responses in sample")

                if stats['total_responses'] > 5:  # Need at least 5 samples
                    # Show analysis with print() for immediate output
                    print("\n" + "="*70)
                    print("SMART FILTER ANALYSIS (based on sample)")
                    print("="*70)
                    print(f"Sampled responses: {stats['total_responses']}")

                    if stats['most_common_lines']:
                        total = stats['total_responses']
                        common_lines_pct = (stats['most_common_lines_count'] / total * 100)
                        print(f"\nMost common LINES: {stats['most_common_lines']} ({stats['most_common_lines_count']} responses = {common_lines_pct:.1f}%)")

                    if stats['most_common_words']:
                        common_words_pct = (stats['most_common_words_count'] / total * 100)
                        print(f"Most common WORDS: {stats['most_common_words']} ({stats['most_common_words_count']} responses = {common_words_pct:.1f}%)")

                    if stats['most_common_chars']:
                        common_chars_pct = (stats['most_common_chars_count'] / total * 100)
                        print(f"Most common CHARS: {stats['most_common_chars']} ({stats['most_common_chars_count']} responses = {common_chars_pct:.1f}%)")

                    # Show unique response sizes if not too many
                    unique_sizes = len(stats['lines_distribution'])
                    if unique_sizes <= 5:
                        print(f"\nUnique response sizes found: {unique_sizes}")
                        for lines, count in sorted(stats['lines_distribution'].items()):
                            words = [w for r in stats['responses'] if r['lines'] == lines for w in [r['words']]][0]
                            chars = [c for r in stats['responses'] if r['lines'] == lines for c in [r['chars']]][0]
                            print(f"  {lines}L / {words}W / {chars}Ch: {count} responses")

                    # Check if filtering would help
                    max_pct = max(common_lines_pct, common_words_pct, common_chars_pct)
                    if max_pct > 50:
                        print("\n🎯 Dominant pattern detected! Filtering recommended.")
                        print("="*70)
                        print(f"💡 Recommended: Hide {stats['most_common_chars']}Ch responses")
                        print("   (NOTE: wfuzz --hl/lines has a bug, use chars instead)")
                        print()

                        # Ask user which filter to use (default to C since --hl is buggy in wfuzz)
                        filter_choice = input("Apply filter? (L=lines, W=words, C=chars, N=no) [C]: ").strip().upper() or "C"

                        if filter_choice != "N":
                            # Build filter
                            filter_arg = ""
                            if filter_choice == "L" and stats['most_common_lines']:
                                filter_arg = f"--hl {stats['most_common_lines']}"
                                self.log(f"Applying filter: hiding {stats['most_common_lines']} lines", "info")
                            elif filter_choice == "W" and stats['most_common_words']:
                                filter_arg = f"--hw {stats['most_common_words']}"
                                self.log(f"Applying filter: hiding {stats['most_common_words']} words", "info")
                            elif filter_choice == "C" and stats['most_common_chars']:
                                filter_arg = f"--hh {stats['most_common_chars']}"
                                self.log(f"Applying filter: hiding {stats['most_common_chars']} chars", "info")

                            # Add filter to command (must go before URL, after --hc)
                            if filter_arg:
                                # Insert filter after --hc XXX and before the rest
                                cmd = cmd.replace(f"--hc {hide_code}", f"--hc {hide_code} {filter_arg}")
                                self.log(f"\n▶ Running full scan with filter...\n", "info")
                    else:
                        self.log("\n✓ Good diversity - running full scan without filter", "success")
                        self.log("="*70 + "\n", "info")
                else:
                    print(f"[!] Only {stats['total_responses']} responses sampled - running full scan without filter")

            except Exception as e:
                print(f"[!] Sample run failed: {e}")
                print(f"[!] Running full scan without filtering...")
                import traceback
                traceback.print_exc()

        # Execute full command
        print(f"\n[*] Running full wfuzz scan...")
        print(f"[*] Command to execute: {cmd}")
        print(f"[*] Command length: {len(cmd)} chars")

        # Double-check the command has the filter
        if '--hl ' in cmd:
            print(f"[*] ✓ Command contains --hl filter")
        elif '--hw ' in cmd:
            print(f"[*] ✓ Command contains --hw filter")
        elif '--hh ' in cmd:
            print(f"[*] ✓ Command contains --hh filter")
        else:
            print(f"[!] WARNING: No filter detected in command!")

        result = self.execute_command(cmd)
        return result

    # === Discovery Operations ===

    def op_dir_fuzz(self) -> Dict[str, Any]:
        """Fuzz directories and files."""
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

        wordlist = self.get_option("WORDLIST") or "/usr/share/wordlists/dirb/common.txt"

        # Build URL with FUZZ
        fuzz_url = f"{url}FUZZ"

        self.log(f"Fuzzing directories at: {url}", "info")
        if self._is_smart_filter_enabled():
            self.log("Smart filtering enabled - will analyze responses and offer to filter common patterns", "info")

        return self._execute_wfuzz(f"-w '{wordlist}' '{fuzz_url}'")

    def op_ext_fuzz(self) -> Dict[str, Any]:
        """Fuzz file extensions."""
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

        # Ask for base filename
        basename = input("Base filename (e.g., index, admin, config): ").strip()
        if not basename:
            basename = "index"

        # Extension wordlist
        ext_wordlist = input("Extension wordlist [/usr/share/seclists/Discovery/Web-Content/web-extensions.txt]: ").strip()
        if not ext_wordlist:
            ext_wordlist = "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt"

        # Build URL with FUZZ for extension
        fuzz_url = f"{url}{basename}FUZ2Z"

        self.log(f"Fuzzing extensions for: {basename}", "info")
        return self._execute_wfuzz(f"-w '{ext_wordlist}' -z list,.FUZZ '{fuzz_url}'")

    def op_backup_fuzz(self) -> Dict[str, Any]:
        """Search for backup files."""
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

        # Common backup extensions
        backup_exts = ".bak-.old-.backup-.copy-.tmp-~"
        wordlist = self.get_option("WORDLIST") or "/usr/share/wordlists/dirb/common.txt"

        fuzz_url = f"{url}FUZZFUZ2Z"

        self.log(f"Searching for backup files at: {url}", "info")
        return self._execute_wfuzz(f"-w '{wordlist}' -z list,{backup_exts} '{fuzz_url}'")

    # === VHOST Operations ===

    def op_vhost_fuzz(self) -> Dict[str, Any]:
        """Fuzz virtual hosts using Host header."""
        # Get target from options
        target = self._get_target()
        if not target:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

        # Ask for domain if target is an IP, otherwise use target as domain
        # Check if target looks like an IP
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

        if re.match(ip_pattern, target):
            # Target is IP, need domain
            ip = target
            domain = input("Base domain (e.g., target.com): ").strip()
            if not domain:
                return {"success": False, "error": "Domain required when TARGET is an IP"}
        else:
            # Target is domain
            domain = target.replace("http://", "").replace("https://", "").split('/')[0]
            # Ask for IP if needed, or use domain for DNS resolution
            ip_input = input(f"Target IP [press Enter to use {domain}]: ").strip()
            ip = ip_input if ip_input else domain

        wordlist = input("Wordlist [/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

        url = f"http://{ip}/"

        self.log(f"VHOST fuzzing: {domain} -> {ip}", "info")
        if self._is_smart_filter_enabled():
            self.log("Smart filtering enabled - will analyze responses and offer to filter common patterns", "info")

        return self._execute_wfuzz(f"-w '{wordlist}' -H 'Host: FUZZ.{domain}' '{url}'")

    def op_subdomain_fuzz(self) -> Dict[str, Any]:
        """Fuzz subdomains."""
        # Get target from options
        target = self._get_target()
        if not target:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

        # If target is IP, ask for domain, otherwise use target as domain
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

        if re.match(ip_pattern, target):
            domain = input("Base domain (e.g., target.com): ").strip()
            if not domain:
                return {"success": False, "error": "Domain required when TARGET is an IP"}
        else:
            domain = target.replace("http://", "").replace("https://", "").split('/')[0]

        wordlist = input("Wordlist [/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: ").strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

        url = f"http://FUZZ.{domain}/"

        self.log(f"Subdomain fuzzing for: {domain}", "info")
        if self._is_smart_filter_enabled():
            self.log("Smart filtering enabled - will analyze responses and offer to filter common patterns", "info")

        return self._execute_wfuzz(f"-w '{wordlist}' '{url}'")

    # === Parameter Operations ===

    def op_param_get_fuzz(self) -> Dict[str, Any]:
        """Fuzz GET parameters."""
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

        # Allow user to specify a specific page
        page = input(f"Specific page to test [press Enter to use {url}]: ").strip()
        if page:
            url = page if page.startswith("http") else f"{url.rstrip('/')}/{page.lstrip('/')}"

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
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

        # Allow user to specify a specific page
        page = input(f"Specific page to test [press Enter to use {url}]: ").strip()
        if page:
            url = page if page.startswith("http") else f"{url.rstrip('/')}/{page.lstrip('/')}"

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
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

        # Allow user to specify a specific page
        page = input(f"Specific page to test [press Enter to use {url}]: ").strip()
        if page:
            url = page if page.startswith("http") else f"{url.rstrip('/')}/{page.lstrip('/')}"

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
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

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
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET option not set. Use 'set TARGET <domain_or_ip>'"}

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
