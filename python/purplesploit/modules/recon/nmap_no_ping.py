"""Compatibility alias for the canonical Nmap no_ping profile."""

from purplesploit.modules.recon.nmap import NmapModule


class NmapNoPingModule(NmapModule):
    profile_name = "no_ping"

    @property
    def name(self) -> str:
        return "Nmap No Ping Scan"
