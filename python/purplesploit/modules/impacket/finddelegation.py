"""
Impacket findDelegation Module (Kerberos delegation enumeration).

Enumerates accounts configured for Kerberos delegation — unconstrained,
constrained (with/without protocol transition) and resource-based constrained
delegation (RBCD). Maps the OCD AD mind-map `delegation` category's enumeration
entry point onto the module system.
"""

from .common import ImpacketAdapter, observation


class ImpacketFindDelegationModule(ImpacketAdapter):
    """
    Impacket findDelegation — list accounts with Kerberos delegation set.

    Authenticated read against the DC; returns the account name, the kind of
    delegation, and the targets each account may delegate to. No tickets are
    requested here — this is the reconnaissance step that feeds getST abuse.
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "impacket-findDelegation"

    @property
    def name(self) -> str:
        return "Impacket findDelegation (delegation enum)"

    @property
    def description(self) -> str:
        return "Enumerate accounts with unconstrained/constrained/RBCD Kerberos delegation"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "impacket"

    emits = ("user", "resource")

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "RHOST": {
                "value": None, "required": True,
                "description": "Target Domain Controller IP", "default": None,
            },
            "USERNAME": {
                "value": None, "required": True,
                "description": "Domain username", "default": None,
            },
            "PASSWORD": {
                "value": None, "required": False,
                "description": "Password for authentication", "default": None,
            },
            "DOMAIN": {
                "value": None, "required": True,
                "description": "Domain name (e.g., CORP.LOCAL)", "default": None,
            },
            "HASH": {
                "value": None, "required": False,
                "description": "NTLM hash (LM:NT format) for pass-the-hash", "default": None,
            },
            "DC_IP": {
                "value": None, "required": False,
                "description": "Domain Controller IP (if different from RHOST)", "default": None,
            },
        })

    def build_argv(self) -> list[str]:
        """Build the impacket-findDelegation argv (auth target + DC IP)."""
        # findDelegation targets the realm, not a host — no @RHOST in the target.
        cmd = self.authentication_argv(remote=False)
        dc = self.get_option("DC_IP") or self.get_option("RHOST")
        if dc:
            cmd += ["-dc-ip", str(dc)]
        return cmd

    @staticmethod
    def _column_spans(separator: str) -> list[tuple[int, int]]:
        """Derive (start, end) column spans from a run-of-dashes separator row."""
        spans, start = [], None
        for i, ch in enumerate(separator):
            if ch == "-" and start is None:
                start = i
            elif ch != "-" and start is not None:
                spans.append((start, i))
                start = None
        if start is not None:
            spans.append((start, len(separator)))
        return spans

    def parse_table(self, output: str) -> list[dict]:
        """Parse Impacket's fixed-width printTable into header-keyed row dicts.

        findDelegation prints an aligned table whose second row is runs of dashes
        sized to each column. Slicing by those spans preserves multi-word cells
        (e.g. "Constrained w/ Protocol Transition") and tolerates the extra
        "SPN Exists" column present in newer Impacket, instead of naively taking
        the last two whitespace tokens.
        """
        lines = output.splitlines()
        header_idx = None
        for i, line in enumerate(lines):
            if "AccountName" not in line or i + 1 >= len(lines):
                continue
            sep = lines[i + 1]
            # The separator row is runs of dashes joined by spaces (printTable).
            if sep.strip() and set(sep.strip()) <= {"-", " "} and "-" in sep:
                header_idx = i
                break
        if header_idx is None:
            return []
        spans = self._column_spans(lines[header_idx + 1])
        if not spans:
            return []
        header = lines[header_idx]
        columns = [header[s:e].strip() for s, e in spans]
        rows = []
        for line in lines[header_idx + 2:]:
            if not line.strip():
                continue
            # Only consume well-formed table rows; stop at trailing banners/notes
            # ("No entries found!", "[*] ...") so they can never become a record.
            if line.lstrip().startswith("[") or line[spans[0][0]:spans[0][1]].strip() == "":
                continue
            cells = [line[s:e].strip() for s, e in spans]
            if not cells[0]:
                continue
            rows.append(dict(zip(columns, cells)))
        return rows

    def parse_output(self, output: str) -> dict:
        """Parse the findDelegation table into delegation observations."""
        results = {
            "success": False,
            "delegations": [],
            "observations": [],
            "credentials": [],
        }
        domain = self.get_option("DOMAIN")
        for row in self.parse_table(output):
            account_name = row.get("AccountName", "")
            delegation_type = row.get("DelegationType", "")
            delegation_to = row.get("DelegationRightsTo", "")
            # A genuine row always has both an account and a delegation type; a
            # short sentinel line ("No entries found!") sliced by the column grid
            # yields an empty type and must not become a record.
            if not account_name or not delegation_type:
                continue
            entry = {
                "account": account_name,
                "delegation_type": delegation_type,
                "delegation_to": delegation_to,
            }
            results["delegations"].append(entry)
            results["success"] = True
            results["observations"].append(observation(
                "user", account_name, username=account_name, domain=domain,
                delegation_type=delegation_type, delegation_to=delegation_to))
            if delegation_to:
                results["observations"].append(observation(
                    "resource", delegation_to, resource_type="delegation_target",
                    account=account_name, delegation_type=delegation_type))
        return results
