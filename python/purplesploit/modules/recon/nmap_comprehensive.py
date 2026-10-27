"""Compatibility alias for the canonical Nmap comprehensive profile."""

from purplesploit.modules.recon.nmap import NmapModule


class NmapComprehensiveModule(NmapModule):
    profile_name = "comprehensive"

    @property
    def name(self) -> str:
        return "Nmap Comprehensive Scan"
