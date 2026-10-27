"""Compatibility alias for the canonical Nmap udp profile."""

from purplesploit.modules.recon.nmap import NmapModule


class NmapUdpModule(NmapModule):
    profile_name = "udp"

    @property
    def name(self) -> str:
        return "Nmap UDP Scan"
