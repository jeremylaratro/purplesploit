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

    _overrides: dict[str, Any] = field(default_factory=dict, repr=False)

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


# T3 (25NOV2026) ACL/object-takeover edges. UNVERIFIED (pin in-lab): the exact
# aranum rule_id / line wording for a promoted ACL (BloodHound-derived) finding
# is not pinned here -- see module docstring's "ASSUMED" caveat, same shape as
# CONSTRAINED-DELEG-PT/OPENSHARES-WRITE. ``target`` is the finding host (the AD
# object the ACE/ownership grants control over); ``trustee`` is a best-effort
# pull of the controlling principal named in the line, for the executor's
# ``trustee`` param default (falls back to ``cfg.username`` if absent).
_RE_ACL_TRUSTEE = re.compile(r"([A-Za-z0-9_.$-]+)\s+has\s+(WriteDacl|WriteOwner|GenericAll)", re.I)
_RE_ACL_GROUP = re.compile(
    r"([A-Za-z0-9_.$-]+)\s+has\s+(Self-?Membership|GenericWrite|GenericAll)\s+over\s+"
    r"group\s+([A-Za-z0-9_.$ -]+)", re.I)


def _extract_acl(f: dict) -> dict:
    entity = _extract_host(f)
    m = _RE_ACL_TRUSTEE.search(f.get("line", ""))
    if m:
        entity["trustee"] = m.group(1)
    entity.setdefault("target", entity.get("host", ""))
    return entity


def _extract_acl_group(f: dict) -> dict:
    entity: dict[str, Any] = {}
    m = _RE_ACL_GROUP.search(f.get("line", ""))
    if m:
        entity["trustee"] = m.group(1)
        entity["group"] = m.group(3).strip()
    elif f.get("host"):
        entity["group"] = f["host"]
    return entity


# GPO-ABUSE: the GPO's own GUID (bare or braced) pulled from the line text;
# falls back to the finding's host when no GUID-shaped token is present
# (mirrors `_extract_acl_group`'s own host fallback). `linked_host` is a
# best-effort pull of an explicitly-stated linked computer -- UNVERIFIED
# aranum wording (see module docstring's "ASSUMED" caveat); its absence is
# never an extraction failure, since `GpoAbuseExecutor` itself treats a
# missing `linked_host` as a narrower, advisory-flagged proof, not a block.
_RE_GPO_GUID = re.compile(
    r"\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?")
_RE_GPO_LINKED = re.compile(r"linked\s+(?:to|host)\s*[:\s]\s*([A-Za-z0-9_.$-]+)", re.I)


def _extract_gpo(f: dict) -> dict:
    entity: dict[str, Any] = {}
    line = f.get("line", "")
    m = _RE_GPO_GUID.search(line)
    if m:
        entity["gpo_guid"] = m.group(1)
    elif f.get("host"):
        entity["gpo_guid"] = f["host"]
    lm = _RE_GPO_LINKED.search(line)
    if lm:
        entity["linked_host"] = lm.group(1)
    return entity


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
    # T3 (25NOV2026) -- ACL / object-takeover edges (category "acl", BloodHound-
    # derived; exact aranum rule_id/wording not pinned here, see _extract_acl).
    TechniqueSignal("WRITE-DACL", "acl", False, _extract_acl,
                    categories=("acl",),
                    line_regex=re.compile(r"WriteDacl", re.I)),
    TechniqueSignal("WRITE-OWNER", "acl", False, _extract_acl,
                    categories=("acl",),
                    line_regex=re.compile(r"WriteOwner", re.I)),
    # NOTE: ADD-MEMBER's and TARGETED-KERBEROAST's rights markers overlap
    # (both are plausibly reported via GenericWrite/GenericAll) -- the only
    # thing that disambiguates a BloodHound-style line is whether the ACE is
    # held OVER A GROUP (ADD-MEMBER) or over a user/computer (TARGETED-
    # KERBEROAST). ADD-MEMBER's line_regex therefore requires the "over
    # group" wording for its Generic* alternative (mirroring its own
    # _RE_ACL_GROUP extractor exactly); Self-Membership/AddMember are already
    # group-specific markers and need no such qualifier. Checked FIRST (order
    # matters -- first match wins), so a plain "... GenericWrite over <user>"
    # line falls through to TARGETED-KERBEROAST below, never mis-mapped here.
    TechniqueSignal("ADD-MEMBER", "acl", False, _extract_acl_group,
                    categories=("acl",),
                    line_regex=re.compile(
                        r"(Self-?Membership|AddMember|"
                        r"(?:GenericWrite|GenericAll)\s+over\s+group)", re.I)),
    # TARGETED-KERBEROAST shares the same GenericAll/GenericWrite ACL entity
    # shape as WRITE-DACL/WRITE-OWNER (_extract_acl populates target/trustee;
    # the executor's own `victim` param reads `entity["principal"]`, so the
    # extractor additionally mirrors `target` into `principal`).
    TechniqueSignal("TARGETED-KERBEROAST", "acl", False,
                    lambda f: {**_extract_acl(f),
                              "principal": _extract_acl(f).get("target", "")},
                    categories=("acl",),
                    line_regex=re.compile(r"GenericWrite", re.I)),
    # FORCE-CHANGE-PASSWORD: the BloodHound edge name for the
    # User-Force-Change-Password extended right is distinct ("ForceChangePassword"),
    # so unlike ADD-MEMBER/TARGETED-KERBEROAST it shares no substring with any
    # earlier signal's line_regex (WriteDacl/WriteOwner/"... over group"/bare
    # GenericWrite) -- no ordering hazard here. Same principal-mirroring
    # extractor shape as TARGETED-KERBEROAST (the executor's `victim` param
    # reads `entity["principal"]`).
    TechniqueSignal("FORCE-CHANGE-PASSWORD", "acl", False,
                    lambda f: {**_extract_acl(f),
                              "principal": _extract_acl(f).get("target", "")},
                    categories=("acl",),
                    line_regex=re.compile(r"ForceChangePassword", re.I)),
    # GENERIC-ALL: ordered LAST among the ACL signals, deliberately -- a bare
    # "GenericAll" marker is otherwise unclaimed by every signal above it:
    # ADD-MEMBER already requires "over group" for its own GenericAll/
    # GenericWrite alternative (so a group-qualified line is claimed there
    # first); TARGETED-KERBEROAST's line_regex is the literal "GenericWrite"
    # only (a bare "GenericAll" line never matches it); WRITE-DACL/WRITE-OWNER
    # match only the literals "WriteDacl"/"WriteOwner". `_extract_acl` already
    # populates `target` (GENERIC-ALL's own param reads `entity["target"]`
    # directly, so no principal-mirror is needed here unlike TARGETED-
    # KERBEROAST/FORCE-CHANGE-PASSWORD).
    TechniqueSignal("GENERIC-ALL", "acl", False, _extract_acl,
                    categories=("acl",),
                    line_regex=re.compile(r"GenericAll", re.I)),
    # GPO-ABUSE: ordered LAST, but deliberately NOT via a bare "GenericAll"/
    # "GenericWrite" marker (unlike every other T3 signal) -- a BloodHound-
    # style "... GenericAll over GPO {guid}" line would otherwise ALSO match
    # GENERIC-ALL's own bare "GenericAll" line_regex two entries above, and
    # since that signal is checked first, it would win the finding (first
    # match wins). Requiring the literal "WriteGPO"/"GPLink" marker (per the
    # plan's own suggestion) avoids this entirely: neither literal is a
    # substring of, nor contains, any earlier signal's own marker (WriteDacl/
    # WriteOwner/ForceChangePassword/AddMember/Self-Membership/bare
    # GenericWrite/GenericAll), so there is no ordering hazard in either
    # direction -- placement here is purely cosmetic (grouped with the other
    # ACL-edge signals). `target_identity`'s own `gpo_guid` reads
    # `entity["gpo_guid"]`.
    TechniqueSignal("GPO-ABUSE", "acl", False, _extract_gpo,
                    categories=("acl",),
                    line_regex=re.compile(r"(WriteGPO|GPLink)", re.I)),
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
