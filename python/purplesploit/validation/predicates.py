"""Robust output / positive-confirmation predicate helpers -- ADR-002 D3.

Tool output varies across versions and terminals: ANSI colour codes, ``[*]`` /
``[+]`` / ``[-]`` prefixes, and inconsistent whitespace. Two rules keep the
framework bulletproof against that variation:

1. **Normalize before matching.** :func:`strip_ansi` is applied to every live
   tool's stdout/stderr at the ``SubprocessRunner`` boundary, so an executor's
   marker regex never has to cope with colour escapes. :func:`normalize`
   additionally collapses horizontal whitespace for tolerant matching.

2. **Assert on POSITIVE confirmation, never absence-of-error.** The independent
   review (25NOV2026) found a class of "vacuous verified" bugs where a rollback
   or terminal was accepted because an error *wasn't seen* (a transport-failed
   read taken as "gone", a never-created file taken as "destroyed"). The helpers
   here confirm an end state positively -- an artifact exists, a file was really
   removed, a token is genuinely present -- so callers can't fall back into the
   absence-of-error trap.

Stdlib only; no LLM.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

# CSI/SGR sequences (colour, cursor moves) and OSC sequences.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def strip_ansi(text: Optional[str]) -> str:
    """Remove ANSI escape sequences. ANSI codes are never meaningful content, so
    stripping is always safe and makes marker matching version/terminal-robust."""
    return _ANSI.sub("", text or "")


def normalize(text: Optional[str]) -> str:
    """ANSI-stripped, with each line's runs of spaces/tabs collapsed to one space
    and trimmed (newlines preserved). For tolerant marker matching; do NOT use on
    output whose exact spacing is significant (e.g. a hash blob)."""
    stripped = strip_ansi(text)
    return "\n".join(re.sub(r"[ \t]+", " ", line).strip()
                     for line in stripped.splitlines())


def search(pattern: "re.Pattern[str]", text: Optional[str]) -> bool:
    """True iff ``pattern`` matches the ANSI-stripped text. A thin helper so call
    sites read as a positive assertion over clean output."""
    return bool(pattern.search(strip_ansi(text)))


def file_destroyed(path: Optional[str], existed_before: bool) -> bool:
    """Positive-confirmation destruction check: the file is absent NOW *and* it
    actually existed before (so absence is not vacuous). Callers that cannot
    observe ``existed_before`` must treat a never-present path as unverified."""
    if not path:
        return False
    try:
        gone = not Path(path).exists()
    except OSError:
        return False
    return gone and existed_before


def file_present_nonempty(path: Optional[str]) -> bool:
    """Positive artifact check: the path is a non-empty regular file."""
    if not path:
        return False
    try:
        p = Path(path)
        return p.is_file() and p.stat().st_size > 0
    except OSError:
        return False


def any_present(paths: Iterable[Optional[str]]) -> bool:
    """True iff at least one of ``paths`` is a non-empty file (a loot/artifact set)."""
    return any(file_present_nonempty(p) for p in paths)


def positive_absence(bind_ok: bool, haystack: Optional[str], needle: str) -> bool:
    """Positive-confirmation "is this gone?" check (the T3 ACL-rollback idiom).

    ``bind_ok`` AND ``needle`` not present in ``haystack`` -- never vacuous: an
    errored/empty read (``bind_ok=False``) is never "absent", it is unverified.
    Callers supply their own bind-ok determination (e.g. an LDAP read-back
    actually RAN, per ``_account_read_ok``-style anchors)."""
    return bool(bind_ok) and needle.lower() not in (haystack or "").lower()
