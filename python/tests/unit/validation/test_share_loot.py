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
    def __init__(self, shares, tree, *, deny_share_enum=False, deny_dirs=()):
        self.shares = list(shares)
        self.tree = {(s, p.strip("/\\")): list(v) for (s, p), v in tree.items()}
        self.deny_share_enum = deny_share_enum
        self.deny_dirs = {(s, p.strip("/\\")) for s, p in deny_dirs}
        self.calls: list[tuple] = []

    def list_shares(self):
        self.calls.append(("list_shares",))
        if self.deny_share_enum:
            raise PermissionError("STATUS_ACCESS_DENIED")
        return list(self.shares)

    def list_dir(self, share, path):
        self.calls.append(("list_dir", share, path.strip("/\\")))
        if (share, path.strip("/\\")) in self.deny_dirs:
            raise PermissionError("STATUS_ACCESS_DENIED")
        return list(self.tree.get((share, path.strip("/\\")), []))

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
    assert used <= {"list_shares", "list_dir", "close"}      # NEVER a write/delete/mkdir
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
    assert "partial:bounds_reached" in r["errors"] and r["complete"] is False


def test_file_count_bound_yields_partial(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_max_files=1), tmp_path, reader)
    assert r["terminal_fact"]["coverage"]["truncated"] is True
    assert "partial:bounds_reached" in r["errors"] and r["complete"] is False


def test_deadline_bound_yields_partial(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_crawl_deadline_s=0), tmp_path, reader)   # already past -> immediate stop
    cov = r["terminal_fact"]["coverage"]
    assert cov["deadline_hit"] is True and "partial:deadline" in r["errors"]
    assert r["complete"] is False


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

def test_mount_mode_is_deferred_inconclusive(tmp_path):
    reader = _FakeReader(["SYSVOL"], _tree())
    r = _run(_cfg(share_access_mode="mount"), tmp_path, reader)
    assert r["complete"] is False and r["terminal_fact"] is None
    assert "inconclusive:mount_mode_deferred" in r["errors"]
    assert reader.calls == []                                # never even connected
