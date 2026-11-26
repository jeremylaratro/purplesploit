"""confirm_ace block-parsing contract (shared T3 ACL infra).

Exercises confirm_ace against the REAL impacket-dacledit 0.13.x multi-line ACE
block format (``ACE[N] info`` header; ``Access mask`` and ``Trustee (SID)`` on
SEPARATE lines) AND the single-line synthetic fixture format, plus the two
precision guards: a superstring account must not be attributed to the trustee,
and a DENY ace must not be read as a grant.
"""
from __future__ import annotations

from purplesploit.validation.executors.acl_common import (
    confirm_ace, _RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_DACL,
)
from purplesploit.validation.executors.base import RunResult

_OK = RunResult(0, stdout="x")
_RIGHTS = (_RE_ACE_GENERIC_ALL,)


def _impacket_block(ace_type: str, mask: str, trustee: str) -> str:
    return (f"[*] Parsing DACL\n[*] Printing parsed DACL\n"
            f"[*]   ACE[0] info\n"
            f"[*]     ACE Type                  : {ace_type}\n"
            f"[*]     Access mask               : {mask}\n"
            f"[*]     Trustee (SID)             : {trustee} (S-1-5-21-1-2-3-1100)\n")


def test_impacket_multiline_allow_grant_is_confirmed():
    # The real 0.13.x shape: rights + trustee on different lines of one block.
    text = _impacket_block("ACCESS_ALLOWED_ACE", "FullControl (0xf01ff)", "vagrant")
    assert confirm_ace(_OK, text, "vagrant", _RIGHTS) is True


def test_domain_qualified_trustee_matches_on_component():
    text = _impacket_block("ACCESS_ALLOWED_ACE", "FullControl (0xf01ff)", "NORTH\\vagrant")
    assert confirm_ace(_OK, text, "vagrant", _RIGHTS) is True


def test_superstring_account_is_not_the_trustee():
    # 'jon.snow.backup' holding FullControl must NOT confirm 'jon.snow' -> None
    # (trustee's own ACE not located), never True.
    text = _impacket_block("ACCESS_ALLOWED_ACE", "FullControl (0xf01ff)", "jon.snow.backup")
    assert confirm_ace(_OK, text, "jon.snow", _RIGHTS) is None


def test_deny_ace_is_not_a_grant():
    # A DENY ace carrying the same mask name is positively INSUFFICIENT (False),
    # never a grant (True).
    text = _impacket_block("ACCESS_DENIED_ACE", "FullControl (0xf01ff)", "jon.snow")
    assert confirm_ace(_OK, text, "jon.snow", _RIGHTS) is False


def test_allow_grant_wins_when_both_allow_and_deny_present():
    # Trustee has a deny block AND an allow-FullControl block -> the allow grant
    # is confirmed.
    text = (_impacket_block("ACCESS_DENIED_ACE", "WriteProperty (0x20)", "jon.snow")
            + "[*]   ACE[1] info\n"
              "[*]     ACE Type                  : ACCESS_ALLOWED_ACE\n"
              "[*]     Access mask               : FullControl (0xf01ff)\n"
              "[*]     Trustee (SID)             : jon.snow (S-1-5-21-1-2-3-1101)\n")
    assert confirm_ace(_OK, text, "jon.snow", _RIGHTS) is True


def test_single_line_fixture_format_still_supported():
    # The synthetic one-line format (trustee+rights on one line) stays valid.
    allow = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: GenericAll\n"
    assert confirm_ace(_OK, allow, "jon.snow", _RIGHTS) is True
    insufficient = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: ReadProperty\n"
    assert confirm_ace(_OK, insufficient, "jon.snow", (_RE_ACE_WRITE_DACL,)) is False
    other = "ACCESS ALLOWED ACE\n  Trustee: Administrator  Rights: FullControl\n"
    assert confirm_ace(_OK, other, "jon.snow", _RIGHTS) is None


def test_unreadable_read_is_unknown():
    assert confirm_ace(RunResult(1, stdout="", error="OSError"), "", "jon.snow", _RIGHTS) is None
    assert confirm_ace(_OK, "connection refused\n", "jon.snow", _RIGHTS) is None


# --- field-structured parsing: labels / names must not be confused for fields ---

def test_field_label_is_not_matched_as_a_trustee():
    # Querying "sid" must NOT match the "Trustee (SID)" label -> None, not True.
    text = _impacket_block("ACCESS_ALLOWED_ACE", "FullControl (0xf01ff)", "arya.stark")
    assert confirm_ace(_OK, text, "sid", _RIGHTS) is None


def test_apostrophe_in_account_name_is_not_split():
    # A valid account name with an apostrophe is one principal, not two.
    text = _impacket_block("ACCESS_ALLOWED_ACE", "FullControl (0xf01ff)", "jon.snow'backup")
    assert confirm_ace(_OK, text, "jon.snow", _RIGHTS) is None          # prefix is not the trustee
    assert confirm_ace(_OK, text, "jon.snow'backup", _RIGHTS) is True   # exact name is


def test_trustee_named_like_an_ace_type_does_not_flip_allow_to_deny():
    # An account literally named ACCESS_DENIED$ in an ALLOW block is still a grant:
    # allow/deny comes from the ACE-TYPE field, never the trustee name.
    text = _impacket_block("ACCESS_ALLOWED_ACE", "FullControl (0xf01ff)", "ACCESS_DENIED$")
    assert confirm_ace(_OK, text, "ACCESS_DENIED$", _RIGHTS) is True


def test_object_ace_allow_is_a_grant():
    text = _impacket_block("ACCESS_ALLOWED_OBJECT_ACE", "FullControl (0xf01ff)", "vagrant")
    assert confirm_ace(_OK, text, "vagrant", _RIGHTS) is True
