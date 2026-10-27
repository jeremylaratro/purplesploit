"""
Wfuzz Module

Web application fuzzer for discovering hidden resources and parameters.
"""

from typing import Dict, Any, List
import re
import shlex
import ipaddress
from urllib.parse import urlsplit
from purplesploit.web_observations import WebToolModule, observation, strip_ansi


class WfuzzModule(WebToolModule):
    """
    Wfuzz - Web application fuzzer.

    Fuzzes web applications to discover hidden resources, parameters, and vulnerabilities.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "wfuzz"

    emits = ["path", "parameter", "http_endpoint"]
    supported_tool_versions = ["wfuzz 3.x console response format"]

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
            **{name: {"value": value, "default": value, "required": False, "description": name}
               for name, value in (("BASENAME", "index"), ("DOMAIN", None), ("PARAMETER", None), ("CUSTOM_FLAGS", ""))},
            "TARGET": {
                "value": None,
                "required": False,
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
                "description": "Report response statistics; set HIDE_* options to apply filters",
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

    def build_argv(self):
        url = self.get_option("URL") or self._build_url("/")
        if not url:
            return []
        if "FUZZ" not in url and "FUZZ" not in str(self.get_option("DATA") or "") and "FUZZ" not in str(self.get_option("HEADERS") or ""):
            url = url.rstrip("/") + "/FUZZ"
        argv = ["wfuzz", "-w", str(self.get_option("WORDLIST"))]
        for key, flag in (("THREADS", "-t"), ("HIDE_CODE", "--hc"), ("HIDE_WORDS", "--hw"),
                          ("HIDE_CHARS", "--hh"), ("DATA", "-d"), ("HEADERS", "-H")):
            value = self.get_option(key)
            if value is not None and value != "":
                argv += [flag, str(value)]
        method = str(self.get_option("METHOD") or "GET").upper()
        if method != "GET":
            argv += ["-X", method]
        if self.option_enabled("FOLLOW"):
            argv.append("-L")
        argv.append(url)
        return argv

    def build_command(self):
        return shlex.join(self.build_argv())

    def parse_output(self, output):
        results = {"found_paths": [], "responses": [], "status_codes": {}, "observations": []}
        url_template = getattr(self, "_fuzz_url", None) or self.get_option("URL") or self._build_url("/") or ""
        data_template = getattr(self, "_fuzz_data", None) or self.get_option("DATA") or ""
        if not getattr(self, "_fuzz_url", None) and "FUZZ" not in url_template and "FUZZ" not in data_template:
            url_template = url_template.rstrip("/") + "/FUZZ"
        for line in strip_ansi(output).splitlines():
            match = re.search(r"""^\s*(\d+):?\s+(\d{3})\s+(\d+)\s+L\s+(\d+)\s+W\s+(\d+)\s+Ch\s+["']?(.*?)["']?\s*$""", line)
            if not match:
                continue
            identity, status, lines, words, chars, payload = match.groups()
            payload = payload.strip('"\'')
            values = payload.split(" - ")
            url = url_template.replace("FUZZ", values[0])
            for index, value in enumerate(values[1:], 2):
                url = url.replace(f"FUZ{index}Z", value)
            item = {"id": identity, "status": status, "path": payload, "payload": payload,
                    "url": url, "lines": int(lines), "words": int(words), "chars": int(chars),
                    "line": line.strip(), "method": getattr(self, "_fuzz_method", None) or self.get_option("METHOD") or "GET"}
            results["found_paths"].append(item)
            results["responses"].append(item)
            results["status_codes"][status] = results["status_codes"].get(status, 0) + 1
            kind = "parameter" if "FUZZ" in data_template or "FUZZ" in urlsplit(url_template).query else "path"
            attrs = {k: v for k, v in item.items() if k != "url"}
            if kind == "parameter":
                template = data_template if "FUZZ" in data_template else urlsplit(url_template).query
                parameter = next((part for part in template.split("&") if "FUZZ" in part), "")
                name, _, value = parameter.partition("=")
                attrs.update(name=name.replace("FUZZ", payload),
                             value=value.replace("FUZZ", payload),
                             location="body" if "FUZZ" in data_template else "query")
            results["observations"].append(observation(kind, url, **attrs))
            results["observations"].append(observation("http_endpoint", url, **attrs))
        return results

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

    def _smart_filter_prompt(self, stats, original_cmd):
        """Retained analysis hook. Filters are selected explicitly using HIDE_* options."""
        return None

    def _is_smart_filter_enabled(self):
        return self.option_enabled("SMART_FILTER")

    def _get_target(self):
        return self.get_option("URL") or self.get_option("TARGET")

    def _build_url(self, path="/", scheme="http"):
        target = self._get_target()
        if not target:
            return None
        base = str(target) if str(target).startswith(("http://", "https://")) else f"{scheme}://{target}"
        return base if not path or path == "/" else f"{base.rstrip('/')}/{path.lstrip('/')}"

    def _execute_wfuzz(self, custom_args="", enable_smart_filter=None):
        if custom_args:
            extra = shlex.split(custom_args) if isinstance(custom_args, str) else list(custom_args)
            argv = ["wfuzz", "-t", str(self.get_option("THREADS") or "50"), "--hc",
                    str(self.get_option("HIDE_CODE") or "404"), *extra]
            for key, flag in (("HIDE_WORDS", "--hw"), ("HIDE_CHARS", "--hh")):
                if self.get_option(key) and flag not in argv:
                    argv[1:1] = [flag, str(self.get_option(key))]
            if self.option_enabled("FOLLOW") and "-L" not in argv:
                argv.insert(1, "-L")
        else:
            argv = self.build_argv()
        if not argv:
            return {"success": False, "error": "TARGET or URL required"}
        self._fuzz_url = argv[-1]
        self._fuzz_data = argv[argv.index("-d") + 1] if "-d" in argv else ""
        self._fuzz_method = argv[argv.index("-X") + 1] if "-X" in argv else "GET"
        result = self.execute_command(argv)
        if self._is_smart_filter_enabled():
            result["response_statistics"] = self._parse_wfuzz_responses(result.get("stdout", ""))
        return result

    def _discovery_url(self):
        url = self._build_url("/")
        return url.rstrip("/") + "/" if url else None

    def op_dir_fuzz(self):
        url = self._discovery_url()
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        self.log(f"Fuzzing directories at {url}", "info")
        if self._is_smart_filter_enabled():
            self.log("Smart filtering enabled: reporting response statistics; filters use HIDE_* options", "info")
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), url + "FUZZ"])

    def op_ext_fuzz(self):
        url = self._discovery_url()
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")),
                                   url + str(self.get_option("BASENAME") or "index") + ".FUZZ"])

    def op_backup_fuzz(self):
        url = self._discovery_url()
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), "-z", "list,.bak-.old-.backup-.copy-.tmp-~",
                                   url + "FUZZFUZ2Z"])

    def _domain(self):
        if self.get_option("DOMAIN"):
            return self.get_option("DOMAIN")
        domain = urlsplit(self._build_url("/") or "").hostname
        try:
            ipaddress.ip_address(domain)
            return None
        except ValueError:
            return domain

    def op_vhost_fuzz(self):
        url = self._discovery_url()
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        if not self._domain():
            return {"success": False, "error": "DOMAIN required when TARGET is an IP"}
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), "-H", f"Host: FUZZ.{self._domain()}", url])

    def op_subdomain_fuzz(self):
        if not self._domain():
            return {"success": False, "error": "TARGET or DOMAIN required"}
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), f"http://FUZZ.{self._domain()}/"])

    def op_param_get_fuzz(self):
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), url + ("&" if "?" in url else "?") + "FUZZ=test"])

    def op_param_post_fuzz(self):
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), "-X", "POST", "-d",
                                   str(self.get_option("DATA") or "FUZZ=test"), url])

    def op_param_value_fuzz(self):
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        name = self.get_option("PARAMETER")
        if not name:
            return {"success": False, "error": "PARAMETER required"}
        if str(self.get_option("METHOD") or "GET").upper() == "POST":
            return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), "-X", "POST", "-d", f"{name}=FUZZ", url])
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), url + ("&" if "?" in url else "?") + f"{name}=FUZZ"])

    def op_header_fuzz(self):
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        header = self.get_option("HEADERS")
        if not header:
            return {"success": False, "error": "HEADERS required"}
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), "-H", str(header), url])

    def op_useragent_fuzz(self):
        url = self._build_url("/")
        if not url:
            return {"success": False, "error": "TARGET or URL required"}
        return self._execute_wfuzz(["-w", str(self.get_option("WORDLIST")), "-H", "User-Agent: FUZZ", url])

    def op_custom_fuzz(self):
        flags = self.get_option("CUSTOM_FLAGS")
        return self._execute_wfuzz(flags) if flags else {"success": False, "error": "CUSTOM_FLAGS required"}

    def run(self):
        return self._execute_wfuzz()
