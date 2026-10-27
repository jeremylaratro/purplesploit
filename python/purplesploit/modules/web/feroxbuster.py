"""Noninteractive Feroxbuster directory and endpoint discovery."""

from pathlib import Path
import re
import shlex
from typing import Any, Dict, List
from urllib.parse import urlsplit
from uuid import uuid4

from purplesploit.web_observations import WebToolModule, json_records, observation, strip_ansi


class FeroxbusterModule(WebToolModule):
    emits = ["path", "http_endpoint"]
    supported_tool_versions = ["feroxbuster 2.x (--json --no-state)"]

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "feroxbuster"

    name = property(lambda self: "Feroxbuster")
    description = property(lambda self: "Directory and file discovery with explicit scan options")
    author = property(lambda self: "PurpleSploit Team")
    category = property(lambda self: "web")
    parameter_profiles = property(lambda self: ["web_scan_advanced"])

    def _init_options(self):
        super()._init_options()
        for name, default in (("URL", None), ("WORDLIST", None), ("EXTENSIONS", "php,html,js,txt,asp,aspx,jsp"),
                              ("THREADS", "50"), ("PROXY", "http://127.0.0.1:8080"), ("CUSTOM_FLAGS", "")):
            self.options[name] = {"value": default, "default": default, "required": name == "URL",
                                  "description": name.replace("_", " ").title()}

    def _init_parameters(self):
        super()._init_parameters()
        if "URL" in self.parameters:
            self.parameters["URL"].required = True
            self.options["URL"]["required"] = True

    def get_operations(self) -> List[Dict[str, Any]]:
        entries = [
            ("Basic Directory Scan", "basic_scan", []),
            ("Background Basic Scan", "background_scan", []),
            ("Deep Scan with Extensions", "deep_scan", []),
            ("Custom Wordlist Scan", "custom_wordlist", ["WORDLIST"]),
            ("Burp Integration Scan", "burp_scan", []),
            ("API Discovery", "api_discovery", []),
            ("Backup File Discovery", "backup_discovery", []),
            ("Custom Scan", "custom_scan", ["CUSTOM_FLAGS"]),
        ]
        return [{"name": name, "description": name, "handler": f"op_{handler}",
                 "interactive": False, "requires": ["URL", *required],
                 "background": handler == "background_scan", "emits": self.emits}
                for name, handler, required in entries]

    def _get_url(self):
        return self.get_option("URL")

    def build_argv(self):
        argv = ["feroxbuster", "-u", str(self._get_url()), "--thorough", "--methods", "GET", "POST", "--json", "--no-state"]
        for option, flag in (("THREADS", "-t"), ("WORDLIST", "-w")):
            if self.get_option(option):
                argv += [flag, str(self.get_option(option))]
        return argv

    def build_command(self):
        return shlex.join(self.build_argv())

    def _execute_feroxbuster(self, extra_args="", run_background=False):
        url = self._get_url()
        if not url:
            return {"success": False, "error": "URL required"}
        request = self.execution_request or getattr(self, "_execution_context_request", None)
        log_dir = Path(request.run_dir) if request and request.run_dir else Path.home() / ".purplesploit/logs/web"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"feroxbuster_{uuid4().hex}.jsonl"
        extra = shlex.split(extra_args) if isinstance(extra_args, str) else list(extra_args)
        result = self.execute_command([*self.build_argv(), *extra, "-o", str(log_file)],
                                      background=run_background, timeout=600)
        result["log_file"] = str(log_file)
        result["artifacts"] = [str(log_file)]
        if result.get("background"):
            return result
        parsed = self._parse_feroxbuster_results(log_file, url) if log_file.exists() else result.get("parsed", self.parse_output(""))
        result.update(parsed=parsed, parsed_results=parsed, observations=parsed["observations"])
        database = getattr(self.framework, "database", None)
        if database is not None:
            database.save_scan_results(scan_name="feroxbuster", target=url, scan_type="web",
                                       results=parsed, file_path=str(log_file))
        return result

    def parse_output(self, output):
        results = {"target": self._get_url(), "found_paths": [], "total_requests": 0,
                   "status_codes": {}, "interesting_finds": [], "observations": []}
        records, errors = json_records(output)
        if output.strip().startswith(("{", "[")):
            results["parse_errors"] = errors
        if not records:
            pattern = r"(?m)^\s*(\d{3})\s+(?:\S+\s+)?(\d+)l?\s+(\d+)w?\s+(\d+)c?\s+(https?://\S+)"
            records = [{"status": int(status), "url": url, "content_length": int(chars),
                        "line_count": int(lines), "word_count": int(words)}
                       for status, lines, words, chars, url in re.findall(pattern, strip_ansi(output))]
        for record in records:
            url = record.get("url")
            if not url or record.get("type", "response") not in {"response", "result"}:
                continue
            status = record.get("status", record.get("status_code"))
            if status is None:
                continue
            item = {**record, "status": int(status), "path": urlsplit(url).path,
                    "size": record.get("content_length", record.get("size", 0))}
            results["found_paths"].append(item)
            key = str(status)
            results["status_codes"][key] = results["status_codes"].get(key, 0) + 1
            if int(status) in {200, 301, 302, 307, 308, 403}:
                results["interesting_finds"].append(item)
            for kind in self.emits:
                results["observations"].append(observation(kind, url, **{k: v for k, v in item.items() if k != "url"}))
        results["total_requests"] = len(results["found_paths"])
        return results

    def _parse_feroxbuster_results(self, log_file, url):
        path = Path(log_file)
        parsed = self.parse_output(path.read_text(errors="replace") if path.exists() else "")
        parsed["target"] = url
        return parsed

    def op_basic_scan(self):
        self.log("Running directory discovery", "info")
        return self._execute_feroxbuster()

    def op_background_scan(self):
        return self._execute_feroxbuster(run_background=True)

    def op_deep_scan(self):
        self.log("Running directory discovery with extensions", "info")
        return self._execute_feroxbuster(["-x", str(self.get_option("EXTENSIONS") or "php,html,js,txt,asp,aspx,jsp")])

    def op_custom_wordlist(self):
        wordlist = self.get_option("WORDLIST")
        if not wordlist:
            return {"success": False, "error": "WORDLIST required"}
        if not Path(wordlist).is_file():
            return {"success": False, "error": f"Wordlist not found: {wordlist}"}
        return self._execute_feroxbuster()

    def op_burp_scan(self):
        return self._execute_feroxbuster(["--proxy", str(self.get_option("PROXY") or "http://127.0.0.1:8080")])

    def op_api_discovery(self):
        self.log("Running API endpoint discovery", "info")
        return self._execute_feroxbuster(["--methods", "GET", "POST", "PUT", "DELETE", "PATCH", "-x", "json,xml"])

    def op_backup_discovery(self):
        self.log("Running backup file discovery", "info")
        return self._execute_feroxbuster(["-x", "bak,old,backup,zip,tar,gz,sql,db,config"])

    def op_custom_scan(self):
        flags = self.get_option("CUSTOM_FLAGS")
        if not flags:
            return {"success": False, "error": "CUSTOM_FLAGS required"}
        return self._execute_feroxbuster(flags)

    def run(self):
        return self.op_basic_scan()
