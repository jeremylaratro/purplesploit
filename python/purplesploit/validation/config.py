"""Operator-supplied configuration for the AD validation automation.

The UX (claude-mem #66142) requires the operator to set *all* inputs up front:
domain, DC IP, credentials, extra targets, output dir. This dataclass is that
single config object. It is target-agnostic -- nothing here is GOAD-specific;
GOAD is only the authorized lab the recipes were proven against.

Secrets (password / NT hash / AES key) live here only to be passed to the
Kerberos/impacket tooling; :meth:`ValidationConfig.redacted` strips them for any
log, receipt, or operator preview.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


_SAFE_LABEL = re.compile(r"[^A-Za-z0-9._-]+")


def principal_base(username: Optional[str]) -> str:
    """The bare, lowercased account label used to derive recommended names.

    ``NORTH\\joe`` / ``joe@north.local`` / ``joe`` all collapse to ``joe``. This
    is the seed for recommended defaults like ``<user>_escalation_test`` and
    ``<user>_cmp_delegation`` (the owner worked example, #66142).
    """
    if not username:
        return "op"
    name = str(username)
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    name = _SAFE_LABEL.sub("_", name).strip("_").lower()
    return name or "op"


@dataclass
class ValidationConfig:
    """All operator inputs for one validation run.

    Required: ``domain`` + ``dc_ip``. Credentials are optional only because a
    few chains (e.g. unauthenticated coercion) do not need them; every
    authenticated chain checks :meth:`has_credentials` and fails closed.
    """

    # --- target identity -------------------------------------------------
    domain: str
    dc_ip: str
    # NetBIOS short name of the domain. Defaults (where None) to the FQDN's first
    # label uppercased -- the usual case. Set it only for the rare domain whose
    # NetBIOS name differs from its first DNS label (used to disambiguate names
    # like krbtgt in a multi-domain forest).
    netbios_domain: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    nt_hash: Optional[str] = None           # 'LM:NT', ':NT', or bare NT
    aes_key: Optional[str] = None
    # T4 forging signing key (SECRET): the krbtgt NT/AES key (Golden/Diamond/
    # Sapphire) or a service-account key (Silver), supplied out-of-band by the
    # operator (CLI --forge-key-file / env) for standalone dispatch. NEVER a
    # ParamSpec (would leak via params_preview) and NEVER serialized -- masked in
    # redacted(). In a chain the key is threaded from the KRBTGT capability instead.
    forge_key: Optional[str] = None
    forge_key_kind: Optional[str] = None    # 'aes' | 'nt' (how to pass it to ticketer)
    forge_key_nt: Optional[str] = None      # SECRET: the krbtgt NT hash for Sapphire (needs both NT+AES)
    extra_targets: list[str] = field(default_factory=list)  # member hosts / DCs by IP or FQDN

    # --- run i/o ---------------------------------------------------------
    output_dir: Path = Path("./validation-run")

    # --- detection layer (aranum) ---------------------------------------
    aranum_bin: str = "aranum"
    nmap_input: Optional[Path] = None       # fed to `aranum run -i`; required unless findings_json set
    findings_json: Optional[Path] = None    # pre-existing aranum findings.json -> skip enumeration

    # --- scoring layer (ad-lab-harness) ---------------------------------
    # argv prefix that runs adlab.score_proof, e.g.
    #   ["python3", "-m", "adlab.score_proof"] with cwd on the harness, or an
    #   absolute path to a wrapper. None -> scoring is skipped, receipts only.
    score_proof_cmd: Optional[list[str]] = None
    proof_truth: Optional[Path] = None      # adlab.plan003.proof-truth.v1 facet

    # Raw-host -> canonical identity attributes for scoring. The proof-truth
    # facet keys on identity attributes (host_id/domain/principal/share). For a
    # generic target the operator maps each raw host/IP to the attributes the
    # facet uses, e.g. {"192.168.56.10": {"host_id": "dc01"}}. Optional: when a
    # host is unmapped the receipt target carries the raw host only.
    host_aliases: dict[str, dict[str, Any]] = field(default_factory=dict)

    # --- behaviour -------------------------------------------------------
    authorized: bool = True                 # engagement/lab is authorized (gate default not_required)
    auto_confirm: bool = False              # accept recommended defaults without prompting
    # T3: explicit, operator-set pre-authorization for a NON-INTERACTIVE run's
    # destructive ops (ChainEngine's own `allow_destructive` kwarg shares this
    # exact name/meaning -- deliberately one flag, not two similarly-named
    # things). Never a silent default-on bypass: it only stands in for the
    # interactive press-yes prompt when there is genuinely no stdin to block on.
    allow_destructive: bool = False
    tool_timeout_s: int = 300
    # Interval between listener-output polls for the listener-based executors
    # (ADR-001). Small by default; the total poll is bounded by tool_timeout_s.
    # Tests inject a tiny/zero interval so the poll loop never actually sleeps.
    poll_interval_s: float = 2.0

    def __post_init__(self) -> None:
        if not self.domain:
            raise ValueError("domain is required")
        if not self.dc_ip:
            raise ValueError("dc_ip is required")
        self.output_dir = Path(self.output_dir)
        if self.nmap_input is not None:
            self.nmap_input = Path(self.nmap_input)
        if self.findings_json is not None:
            self.findings_json = Path(self.findings_json)
        if self.proof_truth is not None:
            self.proof_truth = Path(self.proof_truth)
        if not isinstance(self.extra_targets, list):
            raise ValueError("extra_targets must be a list")

    # --- derived helpers -------------------------------------------------
    @property
    def principal_base(self) -> str:
        return principal_base(self.username)

    @property
    def netbios(self) -> str:
        """The leftmost domain label, upper-cased (best-effort NetBIOS name)."""
        return (self.domain.split(".", 1)[0] or self.domain).upper()

    def has_credentials(self) -> bool:
        return bool(self.password or self.nt_hash or self.aes_key)

    def auth_method(self) -> str:
        if self.nt_hash:
            return "hash"
        if self.aes_key:
            return "aeskey"
        if self.password:
            return "password"
        return "none"

    def resolve_target_identity(self, host: str) -> dict[str, Any]:
        """Identity attributes for ``host`` for proof-truth matching.

        Always carries ``host`` and ``domain``; merges any operator-supplied
        :attr:`host_aliases` (e.g. a ``host_id``) so the receipt target can
        match a facet that keys on canonical identifiers.
        """
        identity: dict[str, Any] = {"host": host, "domain": self.domain}
        alias = self.host_aliases.get(host)
        if isinstance(alias, dict):
            identity.update(alias)
        return identity

    def redacted(self) -> dict[str, Any]:
        """Config as a dict with secret fields masked -- safe to log/preview."""
        data = asdict(self)
        for key in ("password", "nt_hash", "aes_key", "forge_key", "forge_key_nt"):
            if data.get(key):
                data[key] = "***redacted***"
        for key in ("output_dir", "nmap_input", "findings_json", "proof_truth"):
            if data.get(key) is not None:
                data[key] = str(data[key])
        return data
