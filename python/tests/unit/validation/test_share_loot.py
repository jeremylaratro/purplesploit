"""SHARE-LOOT S1 — read-only SMB share discovery + bounded crawl.

Security-critical invariants, non-vacuous:
- READ-ONLY by construction: the executor touches ONLY the narrow `ShareReader`
  (list_shares/list_dir/close); a fake records every call and we assert no other
  (write/delete) method is ever invoked, and the interface exposes none.
- Opaque location IDs: a SECRET-BEARING filename in the tree appears in the
  operator store but NEVER in the receipt.
- Bounds enforced during traversal (depth / entries / files / deadline) → explicit
  `partial`, never silent truncation; cycles can't hang the crawl.
- Exhaustiveness: denied/unreachable shares make coverage incomplete; observed
  access (terminal ok) is separate from coverage completeness.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import ExecutorContext, AuthorizedLabProvider
from purplesploit.validation.executors.share_loot import ShareReader, _Entry
from purplesploit.validation import proof


HOST = "winterfell.north.sevenkingdoms.local"
SECRET_NAME = "domain_admin_password_backup.txt"      # a secret-BEARING filename


class _FakeReader(ShareReader):
    """Scripted read-only reader. `tree` maps (share, relpath) -> [_Entry]. Records
    EVERY method call so a test can prove no write method is ever used."""
    def __init__(self, shares, tree, *, deny_share_enum=False, deny_dirs=(), contents=None):
        self.shares = list(shares)
        self.tree = {(s, p.strip("/\\")): list(v) for (s, p), v in tree.items()}
        self.deny_share_enum = deny_share_enum
        self.deny_dirs = {(s, p.strip("/\\")) for s, p in deny_dirs}
        self.contents = {(s, p.strip("/\\")): v for (s, p), v in (contents or {}).items()}
        self.calls: list[tuple] = []

    def read_file(self, share, path, max_bytes):
        self.calls.append(("read_file", share, path.strip("/\\")))
        data = self.contents.get((share, path.strip("/\\")), b"")
        return data[: max(0, int(max_bytes))]

    def list_shares(self):
        self.calls.append(("list_shares",))
        if self.deny_share_enum:
            raise PermissionError("STATUS_ACCESS_DENIED")
        return list(self.shares)

    def list_dir(self, share, path, limit=10**9):
        self.calls.append(("list_dir", share, path.strip("/\\")))
        if (share, path.strip("/\\")) in self.deny_dirs:
            raise PermissionError("STATUS_ACCESS_DENIED")
        entries = list(self.tree.get((share, path.strip("/\\")), []))
        return entries[: max(0, int(limit)) + 1]      # honor the per-dir cap (limit+1 overflow)

    def close(self):
        self.calls.append(("close",))


def _cfg(**kw):
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="pw")
    base.update(kw)
    return ValidationConfig(**base)


def _ctx(cfg, tmp_path, reader=None, raise_connect=False):
    ctx = ExecutorContext(cfg, runner=None, authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    def factory(c, host, timeout):
        if raise_connect:
            raise ConnectionError("unreachable")
        return reader
    ctx.share_reader_factory = factory
    return ctx


def _finding(host=HOST):
    return map_finding({"finding_id": "SH", "host": host, "category": "smb",
                        "severity": "info", "line": f"smb shares on {host}"})


def _run(cfg, tmp_path, reader=None, raise_connect=False, overrides=None):
    return get_executor("SHARE-LOOT").run(_ctx(cfg, tmp_path, reader, raise_connect),
                                          _finding(), overrides)


# a small tree: SYSVOL with a subdir and a secret-named file
def _tree():
    return {
        ("SYSVOL", ""): [_Entry("policies", True, 0), _Entry("readme.txt", False, 10)],
        ("SYSVOL", "policies"): [_Entry(SECRET_NAME, False, 42), _Entry("scripts", True, 0)],
        ("SYSVOL", "policies/scripts"): [_Entry("logon.bat", False, 7)],
    }


# ============================================================ positive + secret-safety

def test_positive_crawl_produces_share_inventory(tmp_path):
    reader = _FakeReader(["SYSVOL", "NETLOGON"], _tree())
    r = _run(_cfg(), tmp_path, reader)
    assert r["technique"] == "SHARE-LOOT" and r["class"] == "share_loot"
    tf = r["terminal_fact"]
    assert tf and tf["kind"] == "share_inventory" and tf["ok"] is True and tf["proof_token"]
    assert r["complete"] is False or r["complete"] is True   # shape only; completeness asserted below
    cov = tf["coverage"]
    assert cov["files"] == 3 and cov["dirs"] == 2            # readme, secret, logon.bat; policies, scripts
    # NETLOGON returns no tree entries -> listed (empty), SYSVOL listed
    assert cov["shares_total"] == 2 and cov["shares_denied"] == 0


def test_read_only_invariant_only_read_methods_called(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())
    _run(_cfg(), tmp_path, reader)
    used = {c[0] for c in reader.calls}
    assert used <= {"list_shares", "list_dir", "read_file", "close"}   # all READ ops; no write/delete/mkdir
    # and the interface itself exposes no write verb
    assert not any(hasattr(ShareReader, m) for m in ("put_file", "write", "delete", "mkdir", "rename"))


def test_secret_bearing_path_never_in_receipt_only_in_store(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(), tmp_path, reader)
    blob = json.dumps(r)
    assert SECRET_NAME not in blob                           # raw path NEVER in the receipt
    assert "policies" not in blob                            # no raw dir component either
    # ... but it IS in the operator store (opaque-ID -> raw map)
    store_ref = Path(r["terminal_fact"]["store_ref"])
    assert store_ref.exists()
    store = json.loads(store_ref.read_text())
    assert any(v["path"].endswith(SECRET_NAME) for v in store.values())
    assert all(k.startswith("loc:") for k in store)          # opaque IDs


def test_produces_no_capability(tmp_path):
    ex = get_executor("SHARE-LOOT")
    res = ex.run_composable(_ctx(_cfg(), tmp_path, _FakeReader(["SYSVOL"], _tree())), _finding())
    assert res.capabilities == []                            # discovery, not cred recovery


# ======================================================================= bounds

def test_depth_bound_yields_partial(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_max_depth=1), tmp_path, reader)      # can't descend into policies/scripts
    assert r["terminal_fact"]["coverage"]["truncated"] is True
    assert "partial:bounds_reached" in r["errors"] and r["terminal_fact"]["coverage"]["complete"] is False


def test_file_count_bound_yields_partial(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_max_files=1), tmp_path, reader)
    assert r["terminal_fact"]["coverage"]["truncated"] is True
    assert "partial:bounds_reached" in r["errors"] and r["terminal_fact"]["coverage"]["complete"] is False


def test_deadline_bound_yields_partial(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_crawl_deadline_s=0), tmp_path, reader)   # already past -> immediate stop
    cov = r["terminal_fact"]["coverage"]
    assert cov["deadline_hit"] is True and "partial:deadline" in r["errors"]
    assert r["complete"] is False


def test_expired_deadline_does_not_fabricate_observed_access(tmp_path):
    # S1-review #5: a deadline that expired before the first listing must NOT report
    # terminal ok=True, and must not even call list_dir.
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_crawl_deadline_s=0), tmp_path, reader)
    assert r["terminal_fact"]["ok"] is False
    assert not any(c[0] == "list_dir" for c in reader.calls)


def test_child_subtree_denial_makes_share_partial_not_complete(tmp_path):
    # S1-review #3: root lists but a child dir is denied -> share 'partial', coverage
    # incomplete, yet terminal ok=True (the root WAS listed = observed access).
    reader = _FakeReader(["SYSVOL"], _tree(), deny_dirs=[("SYSVOL", "policies")])
    r = _run(_cfg(), tmp_path, reader)
    tf = r["terminal_fact"]
    assert tf["ok"] is True                                   # observed access at the root
    assert any(p["share"] == "SYSVOL" and p["outcome"] == "partial" for p in tf["per_share"])
    assert tf["coverage"]["complete"] is False and r["complete"] is True   # observed access despite partial coverage
    assert "partial:subtree_denied" in r["errors"]


def test_share_cap_omission_is_incomplete(tmp_path):
    # S1-review #4: discovering more shares than the cap must mark coverage incomplete.
    reader = _FakeReader(["SYSVOL", "NETLOGON", "C$"], _tree())
    r = _run(_cfg(share_max_shares=1), tmp_path, reader)
    cov = r["terminal_fact"]["coverage"]
    assert cov["shares_omitted"] == 2 and cov["complete"] is False
    assert "partial:share_cap" in r["errors"] and r["complete"] is True    # accessed; coverage incomplete


def test_listing_that_overruns_the_deadline_is_recorded_incomplete(tmp_path, monkeypatch):
    # S1-review r2 #2: a single blocking listing that OVERRUNS the deadline must be
    # caught (post-op recheck), not reported complete. Fake clock: list_dir "takes" 5s.
    import purplesploit.validation.executors.share_loot as sl
    clock = {"t": 1000.0}
    monkeypatch.setattr(sl.time, "monotonic", lambda: clock["t"])

    class _SlowReader(_FakeReader):
        def list_dir(self, share, path, limit=10**9):
            clock["t"] += 5.0                                # the listing overruns the 2s budget
            return super().list_dir(share, path, limit)

    reader = _SlowReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_crawl_deadline_s=2), tmp_path, reader)   # deadline = 1000 + 2 = 1002
    cov = r["terminal_fact"]["coverage"]
    assert cov["deadline_hit"] is True and cov["complete"] is False        # overran; accessed first
    assert r["terminal_fact"]["ok"] is True                     # root WAS listed before the overrun


def test_directory_cycle_does_not_hang(tmp_path):
    # a dir that lists itself as a child would loop without the visited guard
    cyc = {("S", ""): [_Entry("loop", True, 0)], ("S", "loop"): [_Entry("loop", True, 0)]}
    reader = _FakeReader(["S"], cyc)
    r = _run(_cfg(), tmp_path, reader)                        # must terminate
    assert r["terminal_fact"]["kind"] == "share_inventory"


# ================================================================= exhaustiveness

def test_denied_share_makes_coverage_incomplete(tmp_path):
    reader = _FakeReader(["SYSVOL", "C$"], _tree(), deny_dirs=[("C$", "")])
    r = _run(_cfg(), tmp_path, reader)
    cov = r["terminal_fact"]["coverage"]
    assert cov["shares_denied"] == 1 and cov["complete"] is False
    assert r["terminal_fact"]["ok"] is True                  # SYSVOL still listed (observed access)


def test_unreachable_host_is_not_a_fabricated_success(tmp_path):
    r = _run(_cfg(), tmp_path, reader=None, raise_connect=True)
    assert r["terminal_fact"]["ok"] is False and r["complete"] is False
    assert any(p["outcome"] == "unreachable" for p in r["terminal_fact"]["per_share"])


def test_share_enum_denied_is_recorded(tmp_path):
    reader = _FakeReader([], {}, deny_share_enum=True)
    r = _run(_cfg(), tmp_path, reader)
    assert r["terminal_fact"]["ok"] is False
    assert any(p["outcome"] == "denied" for p in r["terminal_fact"]["per_share"])


# ===================================================================== mount defer

def test_mount_mode_no_longer_deferred(tmp_path):
    # S1b: mount mode is implemented (see test_mount_reader.py for the contained reader).
    # The deprecated `mount_mode_deferred` inconclusive is gone; access_mode is recorded.
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_access_mode="mount"), tmp_path, reader)
    assert not any("mount_mode_deferred" in e for e in r["errors"])
    assert r["terminal_fact"] is not None                    # it actually ran
    assert r["terminal_fact"]["access_mode"] == "mount"


# ===================================================================== S3 loot

SECRET_PW = "S3cr3t!Admin#Pass2026"       # a real secret VALUE that must stay out of the receipt


def _loot_tree():
    return {("DATA", ""): [_Entry("id_rsa", False, 1400), _Entry("web.config", False, 600),
                           _Entry("notes.txt", False, 50), _Entry("big.pem", False, 99999999)]}


def _loot_contents():
    return {
        ("DATA", "id_rsa"): b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + SECRET_PW.encode() + b"\n",
        ("DATA", "web.config"): b'<connectionStrings><add connectionString="Data Source=x;Password=' + SECRET_PW.encode() + b'"/></connectionStrings>',
        ("DATA", "notes.txt"): b"nothing interesting here",
    }


def test_loot_finds_content_secrets_presence_only_in_receipt(tmp_path):
    reader = _FakeReader(["DATA"], _loot_tree(), contents=_loot_contents())
    r = _run(_cfg(), tmp_path, reader)
    loot = r["terminal_fact"]["loot"]
    cats = loot["by_category"]
    assert loot["findings"] >= 2
    assert "private_key_block" in cats and "db_connection_string" in cats  # content rules fired
    assert "ssh_private_key" in cats                                       # filename rule fired
    # the SECRET VALUE and raw paths NEVER appear in the receipt
    blob = json.dumps(r)
    assert SECRET_PW not in blob and "id_rsa" not in blob and "web.config" not in blob
    assert all(h.startswith("loc:") for h in loot["hits"])                 # opaque only


def test_loot_values_and_paths_are_in_the_operator_store(tmp_path):
    reader = _FakeReader(["DATA"], _loot_tree(), contents=_loot_contents())
    r = _run(_cfg(), tmp_path, reader)
    store = json.loads(Path(r["terminal_fact"]["store_ref"]).read_text())
    # the store (0600, operator-only) holds the raw path + the matched secret context
    hit = next(v for v in store.values() if v["path"].endswith("id_rsa"))
    assert "findings" in hit and any(f["category"] == "private_key_block" for f in hit["findings"])
    assert any(SECRET_PW in f["detail"] for v in store.values() for f in v.get("findings", []))


def test_loot_oversize_file_is_not_fetched_but_still_name_flagged(tmp_path):
    # big.pem (99MB) exceeds loot_max_file_bytes -> NOT fetched, but the .pem name is flagged
    reader = _FakeReader(["DATA"], _loot_tree(), contents=_loot_contents())
    r = _run(_cfg(loot_max_file_bytes=10000), tmp_path, reader)
    assert not any(c[0] == "read_file" and c[2] == "big.pem" for c in reader.calls)   # never fetched
    assert "private_key_file" in r["terminal_fact"]["loot"]["by_category"]            # name flagged


def test_loot_fetch_file_cap_is_bounded(tmp_path):
    reader = _FakeReader(["DATA"], _loot_tree(), contents=_loot_contents())
    _run(_cfg(loot_max_fetch_files=1), tmp_path, reader)
    assert sum(1 for c in reader.calls if c[0] == "read_file") <= 1     # fetch count bounded


def test_loot_disabled_does_no_fetch(tmp_path):
    reader = _FakeReader(["DATA"], _loot_tree(), contents=_loot_contents())
    r = _run(_cfg(loot_enabled=False), tmp_path, reader)
    assert not any(c[0] == "read_file" for c in reader.calls)
    assert r["terminal_fact"]["loot"]["findings"] == 0


def test_clean_share_has_no_loot(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())    # the S1 tree has a 'password' filename -> 1 name hit
    r = _run(_cfg(), tmp_path, reader)
    # only the suggestive-name finding from the S1 tree's secret filename; no content findings
    assert all(f == "suggestive_name" for f in r["terminal_fact"]["loot"]["by_category"])


def test_loot_rules_unit():
    from purplesploit.validation.executors import loot_rules as lr
    # prefixed password field now matches (db_password=, user_passwd:)
    assert any(f.category == "password_assignment" for f in lr.content_findings(b"db_password = hunter2x"))
    assert any(f.category == "password_assignment" for f in lr.content_findings(b"user_passwd: s3cr3tval"))
    # a bare placeholder is NOT a hit (value too short)
    assert not any(f.category == "password_assignment" for f in lr.content_findings(b"password="))
    # filename rules + should_fetch
    assert any(f.category == "ssh_private_key" for f in lr.filename_findings("home/user/.ssh/id_rsa"))
    assert lr.should_fetch("a/id_rsa", 1000, 2_000_000) is True
    assert lr.should_fetch("a/big.exe", 1000, 2_000_000) is False      # binary not fetched
    assert lr.should_fetch("a/id_rsa", 9_999_999, 2_000_000) is False  # over the per-file cap
    assert lr.content_findings(b"ordinary text, no secrets here") == []


# ===================================================================== S4 looted creds
# The canonical published MS GPP example cpassword -> "Local*P4ssword!".
GPP_CPW = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPP_USER = "MyDomain\\SvcBackup"
GPP_PLAINTEXT = "GPPstillStandingStrong2k18"
GROUPS_XML = (f'<?xml version="1.0"?><Groups><User name="x"><Properties userName="{GPP_USER}" '
              f'cpassword="{GPP_CPW}"/></User></Groups>').encode()


def test_gpp_cpassword_decrypt_and_extract():
    from purplesploit.validation.executors import loot_rules as lr
    assert lr.gpp_decrypt(GPP_CPW) == GPP_PLAINTEXT
    creds = lr.extract_credentials("x/Groups.xml", GROUPS_XML)
    assert creds and creds[0].principal == GPP_USER and creds[0].secret == GPP_PLAINTEXT
    assert creds[0].source == "gpp_cpassword"


def test_looted_credential_becomes_capability_not_in_receipt(tmp_path):
    from purplesploit.validation.executors.base import CAP_PASSWORD
    from purplesploit.validation import states as st
    tree = {("SYSVOL", ""): [_Entry("Groups.xml", False, len(GROUPS_XML))]}
    reader = _FakeReader(["SYSVOL"], tree, contents={("SYSVOL", "Groups.xml"): GROUPS_XML})
    res = get_executor("SHARE-LOOT").run_composable(_ctx(_cfg(), tmp_path, reader), _finding())
    looted = [c for c in res.capabilities if c.state == st.S_LOOTED_CREDS]
    assert looted and looted[0].channel == CAP_PASSWORD
    assert looted[0].value == GPP_PLAINTEXT and looted[0].principal == GPP_USER
    assert looted[0].secret is True                    # SECRET channel -> engine keeps it in-memory
    # the receipt carries PRESENCE only: no secret, no principal, no cpassword
    blob = json.dumps(res.receipt)
    assert GPP_PLAINTEXT not in blob and GPP_USER not in blob and GPP_CPW not in blob
    assert res.receipt["terminal_fact"]["loot"]["usable_credentials"] == 1
    # but the operator store has the usable credential (the loot)
    store = json.loads(Path(res.receipt["terminal_fact"]["store_ref"]).read_text())
    assert any(GPP_PLAINTEXT == cr["secret"] for v in store.values() for cr in v.get("credentials", []))


def test_malformed_cpassword_is_rejected_not_fabricated(tmp_path):
    # S3/S4 review HIGH: a hostile/garbage cpassword must decrypt to None (no
    # fabricated credential), and must NOT produce a looted-credential capability.
    from purplesploit.validation.executors import loot_rules as lr
    for bad in ("AAAAAAAAAAAAAAAAAAAAAA", "not!base64!!", "", "A", "####"):
        assert lr.gpp_decrypt(bad) is None, bad
    from purplesploit.validation import states as st
    xml = b'<Groups><User><Properties userName="DOM\\svc" cpassword="AAAAAAAAAAAAAAAAAAAAAA"/></User></Groups>'
    assert lr.extract_credentials("x/Groups.xml", xml) == []           # no credential extracted
    reader = _FakeReader(["SYSVOL"], {("SYSVOL", ""): [_Entry("Groups.xml", False, len(xml))]},
                         contents={("SYSVOL", "Groups.xml"): xml})
    res = get_executor("SHARE-LOOT").run_composable(_ctx(_cfg(), tmp_path, reader), _finding())
    assert not any(c.state == st.S_LOOTED_CREDS for c in res.capabilities)   # no fabricated capability
    # ... and the real vector still decrypts (regression)
    assert lr.gpp_decrypt(GPP_CPW) == GPP_PLAINTEXT


# ================================================ cross-FS robustness (Win/Linux NFS+SMB)

def test_case_sensitive_distinct_dirs_are_both_crawled(tmp_path):
    # Linux Samba/NFS is case-SENSITIVE: "Admin" and "admin" are DIFFERENT dirs. The
    # cycle guard must not collapse them (lower-casing would skip one -> missed loot).
    tree = {("S", ""): [_Entry("Admin", True, 0), _Entry("admin", True, 0)],
            ("S", "Admin"): [_Entry("fileA.txt", False, 10)],
            ("S", "admin"): [_Entry("fileB.txt", False, 10)]}
    reader = _FakeReader(["S"], tree)
    r = _run(_cfg(), tmp_path, reader)
    store = json.loads(Path(r["terminal_fact"]["store_ref"]).read_text())
    paths = {v["path"] for v in store.values()}
    assert "Admin/fileA.txt" in paths and "admin/fileB.txt" in paths   # BOTH crawled
    assert r["terminal_fact"]["coverage"]["files"] == 2


def test_utf16le_windows_config_secret_is_detected(tmp_path):
    # Windows files are often UTF-16LE -> ASCII byte regexes would evade them.
    body = ('<connectionStrings><add connectionString="Data Source=db;Password='
            + SECRET_PW + '"/></connectionStrings>').encode("utf-16-le")
    tree = {("C", ""): [_Entry("web.config", False, len(body))]}
    reader = _FakeReader(["C"], tree, contents={("C", "web.config"): body})
    r = _run(_cfg(), tmp_path, reader)
    cats = r["terminal_fact"]["loot"]["by_category"]
    assert "db_connection_string" in cats or "password_assignment" in cats   # UTF-16 content found
    assert SECRET_PW not in json.dumps(r)                                     # value still not in receipt


def test_utf16_gpp_cpassword_yields_capability(tmp_path):
    from purplesploit.validation import states as st
    xml = (f'<Groups><User><Properties userName="{GPP_USER}" cpassword="{GPP_CPW}"/></User></Groups>').encode("utf-16-le")
    tree = {("SYSVOL", ""): [_Entry("Groups.xml", False, len(xml))]}
    reader = _FakeReader(["SYSVOL"], tree, contents={("SYSVOL", "Groups.xml"): xml})
    res = get_executor("SHARE-LOOT").run_composable(_ctx(_cfg(), tmp_path, reader), _finding())
    assert any(c.state == st.S_LOOTED_CREDS and c.value == GPP_PLAINTEXT for c in res.capabilities)


def test_filename_rules_match_both_path_separators():
    from purplesploit.validation.executors import loot_rules as lr
    for p in ("home/user/.ssh/id_rsa", "C:\\Users\\u\\.ssh\\id_rsa", "share\\sub/web.config"):
        assert lr.filename_findings(p), p


def test_crlf_and_lf_both_scan():
    from purplesploit.validation.executors import loot_rules as lr
    assert any(f.category == "password_assignment" for f in lr.content_findings(b"password = x9\r\n"))
    assert any(f.category == "password_assignment" for f in lr.content_findings(b"password = x9\n"))


def test_non_ascii_principal_preserved_across_encodings():
    # review HIGH: de-NUL + utf-8-ignore corrupted "DOM\Jose" accented names -> wrong
    # account. Proper decoding must preserve the EXACT Unicode principal (LE/BE/UTF-8).
    from purplesploit.validation.executors import loot_rules as lr
    user = "NORTH\\José"              # DOM\José
    xml = f'<Groups><Properties userName="{user}" cpassword="{GPP_CPW}"/></Groups>'
    for enc in ("utf-8", "utf-16-le", "utf-16-be"):
        creds = lr.extract_credentials("x/Groups.xml", xml.encode(enc))
        assert creds and creds[0].principal == user, (enc, creds)
        assert creds[0].secret == GPP_PLAINTEXT
    # BOM-prefixed too
    for bom, enc in ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"), (b"\xef\xbb\xbf", "utf-8")):
        creds = lr.extract_credentials("x/Groups.xml", bom + xml.encode(enc))
        assert creds and creds[0].principal == user, (enc, "bom")
