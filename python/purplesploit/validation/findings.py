"""Parse aranum structured findings and map them to validatable techniques.

The detection layer is aranum: ``aranum run`` (-> auto-enum.sh) then
``aranum report`` (-> report.py) emit ``findings.json`` at the output-tree root.
report.py's AD promoters emit typed, per-entity findings with stable ``rule_id``
stamps (``promoted-adcs-ca``/``-tpl``, ``promoted-relay-candidate``,
``promoted-kerberoast-spn``, ``promoted-asrep-user``/``-userlist``,
``promoted-coerce-signal``, ``promoted-shadow-creds``) and an additive
``category``; delegation / LAPS findings come from the enum-ldap/enum-smb
severity rules and are classified by ``category`` + the line marker.

This module normalizes each raw finding into :class:`NormalizedFinding` and
attaches the proof technique it can be validated by (matching the technique keys
in ad-lab-harness ``truth/GOAD-proof.json``). Signals verified against aranum's
``report.py`` carry ``verified=True``; a few (CONSTRAINED-DELEG-PT,
OPENSHARES-WRITE) are mapped on category + a plausible line marker and flagged
``verified=False`` -- see the architecture doc's "unverified assumptions".

findings.json schema cross-ref: aranum ``aranumtoolkit/network/report.py``
``_structured_finding`` + the ``_promote_*`` promoters.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


# ------------------------------------------------------------------ normalized record
@dataclass
class NormalizedFinding:
    """One aranum finding normalized + mapped to a proof technique (if any)."""
    source: dict[str, Any]                 # the raw aranum finding
    finding_id: str = ""
    logical_id: str = ""
    host: str = ""
    port: str = ""
    service: str = ""
    severity: str = ""
    category: str = ""
    rule_id: str = ""
    line: str = ""
    evidence_path: str = ""
    technique: Optional[str] = None        # e.g. 'RBCD'; None -> not validatable
    technique_class: Optional[str] = None  # e.g. 'delegation'
    verified_signal: bool = True           # mapping confidence (see module docstring)
    entity: dict[str, Any] = field(default_factory=dict)  # principal/template/spn/share/esc...

    @property
    def validatable(self) -> bool:
        return self.technique is not None

    def summary(self) -> str:
        bits = [self.technique or "(unmapped)", self.severity, self.host or "-"]
        if self.entity:
            ent = ", ".join(f"{k}={v}" for k, v in self.entity.items())
            bits.append(f"[{ent}]")
        return " ".join(b for b in bits if b)


# ------------------------------------------------------------------ entity extractors
_RE_KERBEROAST = re.compile(r"Kerberoastable SPN account\s+([^\s:]+)\s*:", re.I)
_RE_ASREP = re.compile(r"AS-REP-roastable account\s+([^\s:]+)\s*:", re.I)
_RE_ESC = re.compile(r"\b(ESC\d+)\b", re.I)
_RE_ADCS_TPL = re.compile(r"AD CS template\s+([^\s:]+)", re.I)
_RE_ADCS_CA = re.compile(r"AD CS CA\s+([^\s:(]+)", re.I)


def _extract_kerberoast(f: dict) -> dict:
    m = _RE_KERBEROAST.search(f.get("line", ""))
    return {"principal": m.group(1)} if m else {}


def _extract_asrep(f: dict) -> dict:
    m = _RE_ASREP.search(f.get("line", ""))
    return {"principal": m.group(1)} if m else {}


def _extract_adcs(f: dict) -> dict:
    line = f.get("line", "")
    entity: dict[str, Any] = {}
    esc = _RE_ESC.search(line)
    if esc:
        entity["esc"] = esc.group(1).upper()
    tpl = _RE_ADCS_TPL.search(line)
    if tpl:
        entity["template"] = tpl.group(1)
    ca = _RE_ADCS_CA.search(line)
    if ca:
        entity["ca"] = ca.group(1)
    if f.get("host"):
        entity["ca_host"] = f["host"]
    return entity


def _extract_host(f: dict) -> dict:
    return {"host": f["host"]} if f.get("host") else {}


# ------------------------------------------------------------------ mapping table
@dataclass
class TechniqueSignal:
    """A rule that maps a raw finding to a proof technique."""
    technique: str
    technique_class: str
    verified: bool
    extractor: Callable[[dict], dict]
    rule_ids: tuple[str, ...] = ()          # exact aranum rule_id match (strongest)
    categories: tuple[str, ...] = ()        # additive category match
    line_regex: Optional[re.Pattern] = None  # fallback / disambiguation on the line text

    def matches(self, f: dict) -> bool:
        rid = str(f.get("rule_id", ""))
        if self.rule_ids and rid in self.rule_ids:
            return True
        cat = str(f.get("category", "")).lower()
        line = str(f.get("line", ""))
        cat_ok = (not self.categories) or (cat in self.categories)
        line_ok = (self.line_regex is None) or bool(self.line_regex.search(line))
        if self.rule_ids and not (self.categories or self.line_regex):
            return False  # rule-id-only signal did not match above
        if self.categories or self.line_regex:
            return cat_ok and line_ok
        return False


# Ordered: first match wins. Rule-id signals (verified) precede the softer
# category/line signals so a promoted finding is mapped by its stable rule_id.
SIGNALS: tuple[TechniqueSignal, ...] = (
    # --- VERIFIED: aranum promoter rule_ids -------------------------------
    TechniqueSignal("KERBEROAST", "kerberoast", True, _extract_kerberoast,
                    rule_ids=("promoted-kerberoast-spn",)),
    TechniqueSignal("ASREP", "asrep", True, _extract_asrep,
                    rule_ids=("promoted-asrep-user", "promoted-asrep-userlist")),
    TechniqueSignal("ADCS-ESC1", "adcs", True, _extract_adcs,
                    rule_ids=("promoted-adcs-ca", "promoted-adcs-tpl")),
    TechniqueSignal("NTLM-RELAY", "relay", True, _extract_host,
                    rule_ids=("promoted-relay-candidate",)),
    TechniqueSignal("COERCION", "coerce", True, _extract_host,
                    rule_ids=("promoted-coerce-signal",)),
    TechniqueSignal("SHADOW-CREDS", "shadow_creds", True, _extract_host,
                    rule_ids=("promoted-shadow-creds",)),
    # --- VERIFIED: enum-ldap/enum-smb severity-rule line markers ----------
    TechniqueSignal("RBCD", "delegation", True, _extract_host,
                    line_regex=re.compile(r"msDS-AllowedToActOnBehalfOfOtherIdentity", re.I)),
    TechniqueSignal("UNCONSTRAINED-DELEG", "delegation", True, _extract_host,
                    line_regex=re.compile(r"\bUNCONSTRAINED DELEGATION\b", re.I)),
    TechniqueSignal("LAPS", "laps", True, _extract_host,
                    line_regex=re.compile(r"(READABLE \(LAPSv[12]|ENCRYPTED \(LAPSv2\))", re.I)),
    # --- ASSUMED: mapped on category + plausible marker (verified=False) --
    # Constrained delegation w/ protocol transition: aranum surfaces the
    # msDS-AllowedToDelegateTo / TRUSTED_TO_AUTH signal under the delegation
    # category, but the exact marker string is not pinned in report.py here.
    TechniqueSignal("CONSTRAINED-DELEG-PT", "delegation", False, _extract_host,
                    line_regex=re.compile(
                        r"(msDS-AllowedToDelegateTo|TRUSTED_TO_AUTH_FOR_DELEGATION|"
                        r"constrained delegation)", re.I)),
    # Open RW share: mapped on a writable-share marker; exact aranum wording TBD.
    TechniqueSignal("OPENSHARES-WRITE", "openshares", False,
                    lambda f: {k: v for k, v in (("host", f.get("host")),
                                                 ("share", _share_name(f))) if v},
                    line_regex=re.compile(r"(writable share|RW share|READ[,/ ]WRITE|non-default RW)", re.I)),
)


_RE_SHARE = re.compile(r"share\s+['\"]?([A-Za-z0-9$_.-]+)['\"]?", re.I)


def _share_name(f: dict) -> Optional[str]:
    m = _RE_SHARE.search(f.get("line", ""))
    return m.group(1) if m else None


def map_finding(raw: dict) -> NormalizedFinding:
    """Normalize one raw aranum finding and attach its technique (if mappable)."""
    nf = NormalizedFinding(
        source=raw,
        finding_id=str(raw.get("finding_id", "")),
        logical_id=str(raw.get("logical_id", "")),
        host=str(raw.get("host", "")),
        port=str(raw.get("port", "")),
        service=str(raw.get("service", "")),
        severity=str(raw.get("severity", "")),
        category=str(raw.get("category", "")),
        rule_id=str(raw.get("rule_id", "")),
        line=str(raw.get("line", "")),
        evidence_path=str(raw.get("evidence_path", "")),
    )
    for signal in SIGNALS:
        if signal.matches(raw):
            nf.technique = signal.technique
            nf.technique_class = signal.technique_class
            nf.verified_signal = signal.verified
            try:
                nf.entity = signal.extractor(raw) or {}
            except Exception:  # an extractor must never crash the mapping
                nf.entity = {}
            break
    return nf


def load_findings(path: str | Path) -> list[NormalizedFinding]:
    """Load an aranum ``findings.json`` and return normalized, mapped findings.

    Accepts the object form (``{"findings": [...]}``, current schema) and a bare
    list for forward/backward tolerance. A malformed file raises ``ValueError``.
    """
    path = Path(path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        raw_findings = doc.get("findings", [])
    elif isinstance(doc, list):
        raw_findings = doc
    else:
        raise ValueError("findings.json is neither an object nor a list")
    if not isinstance(raw_findings, list):
        raise ValueError("findings.json 'findings' is not a list")
    return [map_finding(f) for f in raw_findings if isinstance(f, dict)]


def validatable(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """The subset that mapped to a technique (an executor may still be a stub)."""
    return [f for f in findings if f.validatable]
