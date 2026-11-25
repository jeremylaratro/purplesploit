"""Robust-output / positive-confirmation predicate helpers (ADR-002 D3).

Covers ANSI stripping + whitespace normalization (so marker matching is immune
to tool colour/terminal/version formatting -- the owner's "formatting
differences" concern), the positive-confirmation artifact helpers, and that the
real ``SubprocessRunner`` strips ANSI at the boundary so every executor sees
clean output.
"""
from __future__ import annotations

from purplesploit.validation import predicates as P
from purplesploit.validation.executors.base import SubprocessRunner


# ----------------------------------------------------------------- strip / normalize
def test_strip_ansi_removes_colour_and_osc():
    coloured = "\x1b[31mSMB\x1b[0m  10.0.0.1  445  \x1b[1;32m[+]\x1b[0m north\\Administrator (Pwn3d!)"
    out = P.strip_ansi(coloured)
    assert "\x1b" not in out
    assert "SMB" in out and "[+]" in out and "(Pwn3d!)" in out
    # An OSC sequence (title set) is also removed.
    assert P.strip_ansi("\x1b]0;title\x07done") == "done"


def test_strip_ansi_handles_none_and_plain():
    assert P.strip_ansi(None) == ""
    assert P.strip_ansi("plain text") == "plain text"


def test_normalize_collapses_horizontal_whitespace_preserves_lines():
    raw = "\x1b[31m[*]   Saving   ticket\x1b[0m   in\tfoo.ccache  \nline  two"
    assert P.normalize(raw) == "[*] Saving ticket in foo.ccache\nline two"


# ----------------------------------------------------------------- positive confirmation
def test_file_destroyed_requires_existed_and_gone(tmp_path):
    p = tmp_path / "cert.pfx"
    # never existed -> not a verified destruction (vacuous absence rejected)
    assert P.file_destroyed(str(p), existed_before=False) is False
    # existed and now gone -> verified
    assert P.file_destroyed(str(p), existed_before=True) is True
    # still present -> not destroyed
    p.write_bytes(b"x")
    assert P.file_destroyed(str(p), existed_before=True) is False
    assert P.file_destroyed(None, existed_before=True) is False


def test_file_present_nonempty_and_any_present(tmp_path):
    empty = tmp_path / "empty.sam"
    empty.write_bytes(b"")
    full = tmp_path / "loot.sam"
    full.write_bytes(b"hashes")
    assert P.file_present_nonempty(str(full)) is True
    assert P.file_present_nonempty(str(empty)) is False          # empty != present loot
    assert P.file_present_nonempty(str(tmp_path / "nope")) is False
    assert P.any_present([str(empty), str(full)]) is True
    assert P.any_present([str(empty), None]) is False


# ----------------------------------------------------------------- runner boundary
def test_subprocess_runner_strips_ansi_from_real_output():
    # A real host subprocess emits coloured output; the runner must return it
    # ANSI-clean so downstream predicates match regardless of terminal formatting.
    runner = SubprocessRunner(default_timeout=10)
    res = runner.run(["python3", "-c",
                      r"import sys; sys.stdout.write('\x1b[32mSMB\x1b[0m [+] ok')"])
    assert res.returncode == 0
    assert "\x1b" not in res.stdout
    assert res.stdout == "SMB [+] ok"
