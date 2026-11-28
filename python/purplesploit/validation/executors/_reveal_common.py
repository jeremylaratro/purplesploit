"""Runtime-only reveal parsing; no receipt, producer, or display behavior."""
from __future__ import annotations

import base64
import re
from pathlib import Path

from .base import SecretReveal
from .dcsync import _RE_DUMP_NT, _RE_DUMP_AES


def key_material(technique: str, kind: str, principal: str, path) -> list[SecretReveal]:
    """Snapshot actual bearer bytes before destruction, as recoverable base64.

    A missing/unreadable file is no recovered material; never reveal a guessed
    path or let a display-only read interrupt proof/rollback.
    """
    if not path:
        return []
    try:
        data = Path(path).read_bytes()
    except OSError:
        return []
    return ([SecretReveal(technique, kind + "_base64", principal,
                          base64.b64encode(data).decode("ascii"))] if data else [])


def pkinit_hashes(technique: str, principal: str, output: str) -> list[SecretReveal]:
    """Certipy shadow/auth: Got hash for / NT hash for <account>: [LM:]NT.

    Some versions print just the LM:NT pair. Capture complete values only, never
    the presence-only success banner. Principal falls back to the requested one.
    """
    named = re.compile(
        r"(?:Got hash for|NT hash for)\s+['\"]?([^'\"\s:]+)['\"]?:\s*"
        r"(?:[0-9a-f]{32}:)?([0-9a-f]{32})(?![0-9a-f])", re.I)
    reveals = [SecretReveal(technique, "nt_hash", m.group(1), m.group(2))
               for m in named.finditer(output)]
    seen = {r.value for r in reveals}
    for m in re.finditer(r"(?<![0-9a-f])[0-9a-f]{32}:([0-9a-f]{32})(?![0-9a-f])",
                         output, re.I):
        if m.group(1) not in seen:
            reveals.append(SecretReveal(technique, "nt_hash", principal, m.group(1)))
            seen.add(m.group(1))
    return reveals


def dump_hashes(technique: str, output: str) -> list[SecretReveal]:
    """Every complete SAM/replication NT and AES record (not only krbtgt)."""
    return ([SecretReveal(technique, "nt_hash", principal, key)
             for principal, key in _RE_DUMP_NT.findall(output)]
            + [SecretReveal(technique, "aes_key", principal, key)
               for principal, algorithm, key in _RE_DUMP_AES.findall(output)
               if len(key) == (64 if "256" in algorithm else 32)])


def loot_secrets(technique: str, location: str, data: bytes) -> list[SecretReveal]:
    """All values found in inspected content, independent of usable GPP creds.

    File-name hits alone recover no secret. Scan full decoded content rather
    than the intentionally truncated, one-hit-per-category store summaries.
    """
    from . import loot_rules

    patterns = [
        ("private_key", re.compile(
            r"-----BEGIN (?P<label>(?:(?:RSA|EC|OPENSSH|DSA|ENCRYPTED) )?PRIVATE KEY)-----"
            r".*?-----END (?P=label)-----", re.S), 0),
        ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
        ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), 0),
        ("gpp_cpassword", re.compile(r'cpassword\s*=\s*"([^"]+)"', re.I), 1),
        ("aws_secret_access_key", re.compile(
            r"aws_secret_access_key\s*[=:]\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s;<>]+))", re.I), None),
        ("api_token", re.compile(
            r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[=:]\s*"
            r"(?:\"([^\"]+)\"|'([^']+)'|([^\s;<>]+))", re.I), None),
        ("password", re.compile(
            r"(?<![\w])(?:[\w-]*password|[\w-]*passwd|pwd|pass)\s*[=:]\s*"
            r"(?:\"([^\"]+)\"|'([^']+)'|([^\s;<>]+))", re.I), None),
    ]
    reveals = []
    for view in loot_rules._decoded_text_views(data):
        for kind, pattern, group in patterns:
            for match in pattern.finditer(view):
                value = (match.group(group) if group is not None
                         else next((v for v in match.groups() if v is not None), ""))
                # cpassword is encrypted material, not a plaintext password.
                if kind == "password" and match.group(0).lower().startswith("cpassword"):
                    continue
                reveal = SecretReveal(technique, kind, location, value)
                if value and reveal not in reveals:
                    reveals.append(reveal)
    # A PuTTY key is a whole inspected file, not a PEM block.
    if data.startswith((b"PuTTY-User-Key-File-2:", b"PuTTY-User-Key-File-3:")):
        reveals.append(SecretReveal(technique, "private_key", location, data.decode("utf-8")))
    return reveals
