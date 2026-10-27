"""Canonical Nmap profiles, argv construction and completed-result import.

Legacy scan modules select a profile here; XML supplies concrete host identities.
"""

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import shlex

from purplesploit.core.module import ExternalToolModule
from purplesploit.models.database import db_manager
from purplesploit.modules.recon.nmap_importer import (
    import_discovered_hosts, observations_for_hosts, parse_nmap_xml,
)


@dataclass(frozen=True)
class NmapProfile:
    """One profile definition shared by operations and legacy module aliases."""

    name: str
    title: str
    description: str
    subcategory: str = "standard"
    scan_type: str = "sCV"
    ports: str = "-"
    top_ports: str = ""
    timing: str = "4"
    min_rate: str = "3900"
    max_rtt_timeout: str = "4.5"
    max_retries: str = ""
    version_intensity: str = ""
    os_detection: bool = False
    skip_discovery: bool = False
    traceroute: bool = False

    def options(self) -> dict:
        values = {key.upper(): getattr(self, key) for key in (
            "scan_type", "ports", "top_ports", "timing", "min_rate",
            "max_rtt_timeout", "max_retries", "version_intensity",
            "os_detection", "skip_discovery", "traceroute",
        )}
        return {key: str(value).lower() if isinstance(value, bool) else value
                for key, value in values.items()}


NMAP_PROFILES = {
    "default": NmapProfile("default", "Default Scan", "All TCP ports + version/script detection (-p- -sCV)"),
    "fast": NmapProfile("fast", "Fast Scan", "Top 100 TCP ports + quick version detection", scan_type="sV",
                        ports="", top_ports="100", min_rate="5000", max_rtt_timeout="2",
                        max_retries="1", version_intensity="2"),
    "comprehensive": NmapProfile("comprehensive", "Comprehensive Scan", "All TCP ports + maximum version intensity",
                                 version_intensity="9"),
    "aggressive": NmapProfile("aggressive", "Aggressive Scan", "Version/scripts + OS detection + traceroute",
                              "advanced", version_intensity="9", os_detection=True, traceroute=True),
    "stealth": NmapProfile("stealth", "Stealth Scan", "SYN scan with slow timing (requires privileges)",
                           "advanced", scan_type="sS", timing="2", min_rate="100", max_rtt_timeout="10"),
    "udp": NmapProfile("udp", "UDP Scan", "Top 100 UDP ports", "specialized", scan_type="sU",
                       ports="", top_ports="100", min_rate="1000"),
    "udp_full": NmapProfile("udp_full", "UDP Full Scan", "All UDP ports", "specialized", scan_type="sU",
                            min_rate="1000"),
    "no_ping": NmapProfile("no_ping", "No Ping Scan", "All TCP ports + version/scripts, skip host discovery",
                           "specialized", skip_discovery=True),
}
PROFILE_ALIASES = {"tcp_full": "default", "tcp_top": "fast", "udp_top": "udp"}


class NmapModule(ExternalToolModule):
    profile_name = "default"

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "nmap"

    @property
    def name(self) -> str:
        return "Nmap Scan"

    @property
    def description(self) -> str:
        return NMAP_PROFILES[self.profile_name].description

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "recon"

    def _init_options(self):
        super()._init_options()
        definitions = {
            "RHOST": (None, "Target host, network, or whitespace-separated targets"),
            "TARGETS": (None, "Additional target list (list or whitespace-separated string)"),
            "TARGET_FILE": (None, "Nmap target input file (-iL), one segment per run"),
            "IPV6": ("false", "Use IPv6 (-6); literal IPv6 targets are detected automatically"),
            "PROFILE": (self.profile_name, "Canonical scan profile"),
            "PORTS": ("-", "Port specification; empty selects TOP_PORTS"),
            "SCAN_TYPE": ("sCV", "Scan switches without leading dash (e.g. sCV, sU, sS -sU)"),
            "TOP_PORTS": ("", "Top N ports; PORTS must be empty"),
            "SCRIPT": (None, "NSE script expression"),
            "OUTPUT_FORMAT": ("all", "normal, xml, grepable, all"),
            "OUTPUT_FILE": (None, "Output path; all uses a basename, xml uses the exact filename"),
            "RUN_DIR": (None, "Directory for relative Nmap output paths"),
            "TIMING": ("4", "Timing template (0-5)"),
            "OS_DETECTION": ("false", "Enable OS detection (-O)"),
            "VERSION_INTENSITY": ("", "Version detection intensity (0-9)"),
            "MIN_RATE": ("3900", "Minimum packets per second"),
            "MAX_RTT_TIMEOUT": ("4.5", "Maximum round-trip time timeout"),
            "MAX_RETRIES": ("", "Maximum scan probe retransmissions"),
            "HOST_TIMEOUT": (None, "Give up on host after this long (e.g. 30m)"),
            "BACKGROUND": ("true", "Launch in background; import XML separately after completion"),
            "SKIP_DISCOVERY": ("false", "Skip host discovery (-Pn)"),
            "NO_PING": ("false", "Legacy alias for SKIP_DISCOVERY"),
            "TRACEROUTE": ("false", "Trace path to each host"),
            "FRAGMENT": ("false", "Fragment probes (-f), where supported by Nmap"),
            "DECOY": (None, "Decoy specification (-D), where supported by Nmap"),
        }
        for key, (value, description) in definitions.items():
            self.options[key] = {"value": value, "default": value, "required": key == "RHOST",
                                 "description": description}
        self.apply_profile(self.profile_name, defaults=True)

    def apply_profile(self, name: str, *, defaults: bool = False):
        name = PROFILE_ALIASES.get(name.replace("-", "_"), name.replace("-", "_"))
        if name not in NMAP_PROFILES:
            raise ValueError(f"Unknown Nmap profile: {name}")
        values = {**NMAP_PROFILES[name].options(), "PROFILE": name,
                  "NO_PING": "false", "FRAGMENT": "false", "DECOY": ""}
        for key, value in values.items():
            self.options[key]["value"] = value
            if defaults:
                self.options[key]["default"] = value

    def set_option(self, key, value):
        if key.upper() == "PROFILE":
            self.apply_profile(str(value))
            return True
        return super().set_option(key, value)

    def validate_options(self):
        # Preserve RHOST's legacy metadata while accepting list/file input.
        if not any(self.get_option(key) for key in ("RHOST", "TARGETS", "TARGET_FILE")):
            return False, "RHOST, TARGETS or TARGET_FILE is required"
        try:
            self.build_argv()
        except (TypeError, ValueError, OSError) as exc:
            return False, str(exc)
        return True, ""

    def get_operations(self) -> list[dict]:
        handlers = {"default": "default_scan", "fast": "fast_scan", "comprehensive": "comprehensive_scan",
                    "aggressive": "aggressive_scan", "stealth": "stealth_scan", "udp": "udp_scan",
                    "udp_full": "udp_full_scan", "no_ping": "no_ping_scan"}
        return [{"id": handlers[name].replace("_", "-"), "name": profile.title, "description": profile.description,
                 "handler": f"op_{handlers[name]}", "subcategory": profile.subcategory,
                 # Nmap supports synchronous orchestration.  BACKGROUND is an
                 # interactive invocation preference, not an inherent
                 # operation requirement advertised by the catalog.
                 "background": False, "emits": ["host", "service"], "tool": "nmap",
                 "supported_tool_versions": [], "standards": []}
                for name, profile in NMAP_PROFILES.items()]

    def _run_profile(self, name):
        self.apply_profile(name)
        return self.run()

    def op_default_scan(self):
        return self._run_profile("default")

    def op_fast_scan(self):
        return self._run_profile("fast")

    def op_comprehensive_scan(self):
        return self._run_profile("comprehensive")

    def op_aggressive_scan(self):
        return self._run_profile("aggressive")

    def op_stealth_scan(self):
        return self._run_profile("stealth")

    def op_udp_scan(self):
        return self._run_profile("udp")

    def op_udp_full_scan(self):
        return self._run_profile("udp_full")

    def op_no_ping_scan(self):
        return self._run_profile("no_ping")

    @staticmethod
    def _split_targets(value):
        if not value:
            return []
        values = list(value) if isinstance(value, (list, tuple)) else shlex.split(str(value))
        if any(not isinstance(item, str) or not item or item.startswith("-") for item in values):
            raise ValueError("Targets must be nonempty host/network arguments")
        return values

    def _targets(self):
        return self._split_targets(self.get_option("RHOST")) + self._split_targets(self.get_option("TARGETS"))

    def _request(self):
        return self.execution_request or getattr(self, "_execution_context_request", None)

    def _background(self):
        request = self.execution_request
        return request.background if request is not None else self.option_enabled("BACKGROUND")

    def _output_path(self):
        output = self.get_option("OUTPUT_FILE")
        output_format = self.get_option("OUTPUT_FORMAT")
        if not output and output_format != "normal":
            targets = self._targets()
            label = targets[0] if len(targets) == 1 and not self.get_option("TARGET_FILE") else "targets"
            output = "nmap_" + re.sub(r"[^\w.-]", "_", label)
        if not output:
            return None
        request = self._request()
        run_dir = self.get_option("RUN_DIR") or ((request.cwd or request.run_dir) if request else None)
        path = Path(str(output))
        if run_dir and not path.is_absolute():
            path = Path(run_dir).resolve() / path
        return str(path)

    def build_argv(self) -> list[str]:
        targets = self._targets()
        target_file = self.get_option("TARGET_FILE")
        if not targets and not target_file:
            raise ValueError("RHOST, TARGETS or TARGET_FILE is required")
        family_targets = list(targets)
        if target_file and Path(str(target_file)).is_file():
            family_targets.extend(token for line in Path(str(target_file)).read_text().splitlines()
                                  for token in line.split("#", 1)[0].split())
        families = set()
        for target in family_targets:
            try:
                families.add(ipaddress.ip_network(target, strict=False).version)
            except ValueError:
                if ":" in target:
                    families.add(6)
        ipv6 = self.option_enabled("IPV6") or 6 in families
        if ipv6 and 4 in families:
            raise ValueError("IPv4 and IPv6 targets must be segmented into separate Nmap runs")
        argv = ["nmap"]
        if ipv6:
            argv.append("-6")
        scan_type = str(self.get_option("SCAN_TYPE") or "")
        for flag in shlex.split(scan_type):
            argv.append(flag if flag.startswith("-") else "-" + flag)
        ports, top_ports = self.get_option("PORTS"), self.get_option("TOP_PORTS")
        if ports:
            argv += ["-p", str(ports)]
        elif top_ports:
            argv += ["--top-ports", str(top_ports)]
        if self.get_option("TIMING"):
            argv.append("-T" + str(self.get_option("TIMING")))
        for enabled, flag in (("OS_DETECTION", "-O"), ("TRACEROUTE", "--traceroute"),
                              ("FRAGMENT", "-f")):
            if self.option_enabled(enabled):
                argv.append(flag)
        if self.option_enabled("SKIP_DISCOVERY") or self.option_enabled("NO_PING"):
            argv.append("-Pn")
        for key, flag in (("VERSION_INTENSITY", "--version-intensity"), ("MIN_RATE", "--min-rate"),
                          ("MAX_RTT_TIMEOUT", "--max-rtt-timeout"), ("MAX_RETRIES", "--max-retries"),
                          ("HOST_TIMEOUT", "--host-timeout"), ("DECOY", "-D")):
            value = self.get_option(key)
            if value is not None and value != "":
                argv += [flag, str(value)]
        if self.get_option("SCRIPT"):
            argv.append("--script=" + str(self.get_option("SCRIPT")))
        output_format = self.get_option("OUTPUT_FORMAT")
        output_flags = {"all": "-oA", "xml": "-oX", "grepable": "-oG", "normal": "-oN"}
        if output_format not in output_flags:
            raise ValueError(f"Unknown Nmap OUTPUT_FORMAT: {output_format}")
        output = self._output_path()
        if output:
            argv += [output_flags[output_format], output]
        if target_file:
            argv += ["-iL", str(Path(str(target_file)).resolve())]
        return argv + targets

    def build_command(self) -> str:
        return shlex.join(self.build_argv())

    def parse_xml_output(self, xml_path: str) -> dict:
        try:
            request = self._request()
            return parse_nmap_xml(xml_path, source_execution_id=request.request_id if request else "",
                                  module_path=request.module_path if request else "recon/nmap")
        except (OSError, ValueError) as exc:
            self.log(f"Error parsing XML: {exc}", "error")
            return {"hosts": [], "total_hosts": 0, "hosts_with_ports": 0, "observations": [], "error": str(exc)}

    def parse_output(self, output: str) -> dict:
        results = {"open_ports": [], "services": {}, "os_guess": None}
        for line in output.splitlines():
            match = re.match(r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line)
            if match:
                port, protocol, service, version = match.groups()
                key = f"{port}/{protocol}"
                results["open_ports"].append(key)
                results["services"][key] = {"service": service, "version": version or "",
                                            "port": int(port), "protocol": protocol}
            if "OS details:" in line or "Aggressive OS guesses:" in line:
                results["os_guess"] = line.split(":", 1)[1].strip()
        return results

    def process_discovered_hosts(self, parsed_xml: dict):
        return import_discovered_hosts(self.framework, parsed_xml, models_db=db_manager, log=self.log)

    def run(self) -> dict:
        valid, error = self.validate_options()
        if not valid:
            return {"success": False, "error": error, "observations": []}
        output = self._output_path()
        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
        output_format = self.get_option("OUTPUT_FORMAT")
        xml_path = output if output_format == "xml" else f"{output}.xml" if output_format == "all" else None
        if self._background():
            if not self.check_tool_installed():
                return {"success": False, "error": "Tool not found: nmap", "observations": []}
            result = self.execute_command(self.build_argv(), background=True)
            if result.get("pid") or result.get("background"):
                result.update(success=False, background=True, observations=[])
                result["note"] = (f"Scan running in background. Import {xml_path} after completion." if xml_path
                                  else "Scan running in background; selected output format does not produce XML.")
            return result
        result = super().run()
        result.setdefault("observations", [])
        if not result.get("success"):
            return result
        if result.get("background"):
            result["success"] = False
            return result
        if xml_path and Path(xml_path).is_file():
            parsed = self.parse_xml_output(xml_path)
            if parsed.get("error"):
                return {**result, "success": False, "xml_parsed": False,
                        "error": "Nmap XML parsing failed: " + parsed["error"]}
            self.process_discovered_hosts(parsed)
            return {**result, "hosts": parsed["hosts"], "observations": parsed["observations"],
                    "xml_parsed": True, "hosts_discovered": parsed["hosts_with_ports"],
                    "total_scanned": parsed["total_hosts"], "xml_path": xml_path}
        # Text-only legacy results can safely associate ports with one literal IP.
        # A flat port map has no host association for a range, target file or list.
        targets = self._targets()
        try:
            concrete = len(targets) == 1 and not self.get_option("TARGET_FILE")
            if concrete:
                ipaddress.ip_address(targets[0])
        except ValueError:
            concrete = False
        services = result.get("parsed", {}).get("services", {})
        if not concrete:
            result.update(success=False, error="Nmap range/list discovery requires completed per-host XML output")
        elif services:
            host = {"ip": targets[0], "hostname": None, "services": services,
                    "open_ports": list(services)}
            self.process_discovered_hosts({"hosts": [host]})
            result["observations"] = [item.to_dict() for item in observations_for_hosts([host])]
        return result
