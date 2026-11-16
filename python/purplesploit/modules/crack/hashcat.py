"""
Hashcat Module (offline hash cracking — OCD `crack_hash`).

Wraps the hashcat CLI to crack hashes harvested by the roasting, relay and
secretsdump paths (NTLM, krb5tgs/asrep, NetNTLMv2, DCC2, etc.). This is the
offline sink the OCD AD mind-map's `crack_hash` category points every
credential-extraction technique toward. The module forms the argv and parses
the cracked ``hash:plaintext`` pairs; it does not ship wordlists.
"""

import re
import shlex

from purplesploit.core.module import ExternalToolModule


# Attack modes whose run consumes a wordlist; without one, hashcat falls back to
# reading candidates from stdin and blocks forever behind no module timeout.
_WORDLIST_ATTACK_MODES = {"0", "1", "6", "7"}

_HEX_RE = re.compile(r"^\$HEX\[([0-9a-fA-F]*)\]$")


def _decode_plaintext(plain: str) -> str:
    """Decode hashcat's ``$HEX[..]`` wrapper (used when the plaintext contains the
    field separator, leading/trailing whitespace, or non-printable bytes)."""
    match = _HEX_RE.match(plain)
    if not match:
        return plain
    try:
        return bytes.fromhex(match.group(1)).decode("utf-8", "replace")
    except ValueError:
        return plain


# A few of the hashcat modes that matter for AD work, for operator reference.
AD_HASH_MODES = {
    "1000": "NTLM",
    "1100": "Domain Cached Credentials (DCC/MS-Cache)",
    "2100": "Domain Cached Credentials 2 (DCC2/MS-Cache v2)",
    "3000": "LM",
    "5600": "NetNTLMv2",
    "5500": "NetNTLMv1",
    "13100": "Kerberos 5 TGS-REP (Kerberoast)",
    "18200": "Kerberos 5 AS-REP (ASREPRoast)",
    "19700": "Kerberos 5 TGS-REP AES256",
}


class HashcatModule(ExternalToolModule):
    """
    Hashcat offline cracking wrapper.

    Dictionary attack by default (``-a 0``). Set SHOW to read already-cracked
    results out of the potfile without running an attack. HASH_MODE is the
    hashcat ``-m`` number (see AD_HASH_MODES for the common AD ones).
    """

    def __init__(self, framework):
        super().__init__(framework)
        self.tool_name = "hashcat"

    @property
    def name(self) -> str:
        return "Hashcat (offline crack)"

    @property
    def description(self) -> str:
        return "Crack harvested AD hashes offline (NTLM, krb5tgs/asrep, NetNTLMv2, DCC2) with hashcat"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "crack"

    emits = ("credential",)

    def _init_options(self):
        super()._init_options()
        self.options.update({
            "HASH_FILE": {
                "value": None, "required": True,
                "description": "Path to the file of hashes to crack", "default": None,
            },
            "HASH_MODE": {
                "value": None, "required": True,
                "description": "hashcat -m mode number (e.g., 1000 NTLM, 13100 krb5tgs, 18200 asrep)",
                "default": None,
            },
            "WORDLIST": {
                "value": None, "required": False,
                "description": "Wordlist path (required unless SHOW is set)", "default": None,
            },
            "ATTACK_MODE": {
                "value": "0", "required": False,
                "description": "hashcat -a attack mode (0 dict, 3 mask, 6/7 hybrid)", "default": "0",
            },
            "RULES": {
                "value": None, "required": False,
                "description": "Rules file to apply (-r), e.g., best64.rule", "default": None,
            },
            "POTFILE": {
                "value": None, "required": False,
                "description": "Explicit potfile path (--potfile-path)", "default": None,
            },
            "SHOW": {
                "value": "false", "required": False,
                "description": "Only print already-cracked results from the potfile (--show)",
                "default": "false",
            },
        })

    def build_argv(self) -> list[str]:
        """Build the hashcat argv from the current options."""
        mode = self.get_option("HASH_MODE")
        hash_file = self.get_option("HASH_FILE")
        cmd = [self.tool_name, "-m", str(mode), "--quiet"]

        potfile = self.get_option("POTFILE")
        if potfile:
            cmd += ["--potfile-path", str(potfile)]

        if self.option_enabled("SHOW"):
            # Read cracked pairs out of the potfile; no attack, no wordlist.
            cmd += ["--show", str(hash_file)]
            return cmd

        cmd += ["-a", str(self.get_option("ATTACK_MODE") or "0"), str(hash_file)]
        wordlist = self.get_option("WORDLIST")
        if wordlist:
            cmd.append(str(wordlist))
        rules = self.get_option("RULES")
        if rules:
            cmd += ["-r", str(rules)]
        return cmd

    def build_command(self) -> str:
        """Shell-free display form of the argv."""
        return shlex.join(self.build_argv())

    def run(self) -> dict:
        """Check the tool, run hashcat, and lift cracked credentials to the top level."""
        if not self.check_tool_installed():
            return {"success": False,
                    "error": f"Tool not found: {self.tool_name}. Please install it first."}
        # Guard the stdin-hang: a dictionary attack with no wordlist makes hashcat
        # wait on stdin for candidates indefinitely.
        if not self.option_enabled("SHOW"):
            attack_mode = str(self.get_option("ATTACK_MODE") or "0")
            if attack_mode in _WORDLIST_ATTACK_MODES and not self.get_option("WORDLIST"):
                return {"success": False,
                        "error": f"WORDLIST is required for attack mode {attack_mode} "
                                 "(hashcat would otherwise read candidates from stdin and hang)."}
        try:
            result = self.execute_command(self.build_argv())
        except (ValueError, OSError) as exc:
            return {"success": False, "error": str(exc)}
        parsed = self.parse_output(result.get("stdout", ""))
        result["parsed"] = parsed
        result["observations"] = parsed.get("observations", [])
        if parsed.get("credentials"):
            result["credentials"] = parsed["credentials"]
        # Success means a credential was actually recovered, not merely that the
        # tool exited 0 (--show exits 0 with no hits; an exhausted run exits 1).
        result["success"] = bool(result.get("success")) and bool(parsed.get("success"))
        return result

    @staticmethod
    def _looks_like_record(hash_part: str) -> bool:
        """Reject hashcat status/label text so it cannot become a credential.

        Real AD-mode hashes (NTLM hex, $krb5tgs$/$krb5asrep$, NetNTLMv2) carry no
        whitespace and no run of consecutive dots; hashcat status labels
        ("Status...........:", "Progress.........:") always do.
        """
        if not hash_part:
            return False
        if any(ch.isspace() for ch in hash_part):
            return False
        if ".." in hash_part:
            return False
        return True

    def parse_output(self, output: str) -> dict:
        """Parse hashcat's ``hash:plaintext`` cracked lines (from --show or --quiet).

        The hash itself can contain colons (NetNTLMv2, AS-REP, --username files), so
        the hash/plaintext boundary is the LAST colon, not the first. hashcat
        ``$HEX[..]``-encodes any plaintext that contains the separator or surrounding
        whitespace, so the decoded value is restored and its whitespace preserved.
        """
        results = {
            "success": False,
            "cracked": [],
            "observations": [],
            "credentials": [],
        }
        mode = str(self.get_option("HASH_MODE") or "")
        for raw in output.splitlines():
            line = raw.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("["):
                continue
            if ":" not in line:
                continue
            hash_part, plain_raw = line.rsplit(":", 1)
            if not self._looks_like_record(hash_part):
                continue
            plaintext = _decode_plaintext(plain_raw)
            entry = {"hash": hash_part, "plaintext": plaintext, "hash_mode": mode}
            results["cracked"].append(entry)
            results["success"] = True
            record = {
                "hash": hash_part,
                "plaintext": plaintext,
                "hash_mode": mode,
                "hash_type": AD_HASH_MODES.get(mode, mode),
                "source": self.tool_name,
                "credential_type": "cracked_password",
                "authenticated": False,
            }
            results["credentials"].append(record)
            results["observations"].append(
                {"kind": "credential", "target": "", "attributes": record})
        return results
