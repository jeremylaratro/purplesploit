"""SHARE-LOOT S1b -- mount-mode descriptor-anchored containment + mount lifecycle.

Security-critical invariants, non-vacuous (an attacker controls the mounted share):
- CONTAINMENT: a symlink / symlinked-dir / `..` / cross-mount inside the share can
  NEVER cause a read or list outside the pinned mount root. The escape TARGET's bytes
  are never returned (RED proof). A FIFO/device cannot block or fire an open-handler.
  Unverifiable mount identity fails CLOSED.
- LIFECYCLE: SMB creds never reach argv (a 0600 file, unlinked post-mount); a mount
  failure is a per-share `denied`; NO mountable share -> `inconclusive:mount_unavailable`
  (never a false success); teardown closes all fds then unmounts.

The containment tests run on LOCAL fixtures (no privilege/mount needed) because the
openat walk treats the mount root as an ordinary directory -- the FS-level escape
properties are identical whether the tree came from a real mount or a local dir."""
from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from pathlib import Path

import pytest

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, mount_reader
from purplesploit.validation.executors.base import ExecutorContext, AuthorizedLabProvider, RunResult
from purplesploit.validation.executors.mount_reader import _ContainedDir, _Contained, MountReader


# =============================================================== fixtures / helpers
GPP_CPW = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPP_PLAINTEXT = "GPPstillStandingStrong2k18"
GPP_USER = "NORTH\\José"
GROUPS_XML = (f'<?xml version="1.0"?><Groups><User name="x"><Properties userName="{GPP_USER}" '
              f'cpassword="{GPP_CPW}"/></User></Groups>').encode("utf-8")
IDRSA = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"


def _loot_tree(root: Path) -> None:
    """A share tree with real loot + case-variant dirs."""
    (root / "home/svc/.ssh").mkdir(parents=True)
    (root / "home/svc/.ssh/id_rsa").write_bytes(IDRSA)
    (root / "sysvol/Policies").mkdir(parents=True)
    (root / "sysvol/Policies/Groups.xml").write_bytes(GROUPS_XML)
    (root / "Admin").mkdir(); (root / "Admin/upper.txt").write_text("U")
    (root / "admin").mkdir(); (root / "admin/lower.txt").write_text("L")
    (root / "readme.txt").write_text("nothing here")


def _escape_tree(root: Path) -> None:
    """A hostile share: loot + planted escapes (symlink to host file, symlinked dir)."""
    (root / "f.txt").write_text("in-bounds")
    (root / "sub").mkdir(); (root / "sub/deep.txt").write_text("deep-in-bounds")
    os.symlink("/etc/passwd", str(root / "escape"))          # symlink -> host file OUTSIDE root
    os.symlink("/etc", str(root / "escdir"))                 # symlink -> host dir OUTSIDE root


# =============================================================== _ContainedDir (core)
def test_contained_lists_and_reads(tmp_path):
    _loot_tree(tmp_path)
    cd = _ContainedDir(str(tmp_path))
    top = {e[0]: e[1] for e in cd.list_dir("", 1000)}
    assert top.get("home") is True and top.get("readme.txt") is False
    assert cd.read_file("home/svc/.ssh/id_rsa", 10_000) == IDRSA
    assert {e[0] for e in cd.list_dir("", 1000)} >= {"Admin", "admin"}   # case-variant dirs both present
    cd.close()


def test_symlink_entry_skipped_in_listing(tmp_path):
    _escape_tree(tmp_path)
    cd = _ContainedDir(str(tmp_path))
    names = {e[0] for e in cd.list_dir("", 1000)}
    assert "escape" not in names and "escdir" not in names    # symlinks never surface
    assert cd.symlinks_skipped == 2
    assert "f.txt" in names and "sub" in names                # in-bounds entries do
    cd.close()


def test_symlink_read_never_returns_target_bytes(tmp_path):
    # RED proof: reading the planted symlink must NOT return /etc/passwd -- O_PATH|O_NOFOLLOW
    # pins the LINK (S_ISREG false) -> b"". (Disabling O_NOFOLLOW would leak the host file.)
    _escape_tree(tmp_path)
    cd = _ContainedDir(str(tmp_path))
    data = cd.read_file("escape", 10_000)
    assert data == b""
    assert b"root:" not in data                               # the host passwd is never read
    cd.close()


def test_symlinked_dir_component_not_descended(tmp_path):
    _escape_tree(tmp_path)
    cd = _ContainedDir(str(tmp_path))
    with pytest.raises(OSError):                              # O_NOFOLLOW on 'escdir' -> ELOOP
        cd.list_dir("escdir", 1000)
    cd.close()


def test_dotdot_cannot_escape(tmp_path):
    _escape_tree(tmp_path)
    cd = _ContainedDir(str(tmp_path))
    try:
        data = cd.read_file("sub/../../../../etc/passwd", 10_000)
    except OSError:
        data = b""
    assert b"root:" not in data                               # '..' stripped -> stays beneath root
    cd.close()


def test_fifo_is_skipped_and_read_does_not_block(tmp_path):
    _escape_tree(tmp_path)
    os.mkfifo(str(tmp_path / "pipe"))
    cd = _ContainedDir(str(tmp_path))
    names = {e[0] for e in cd.list_dir("", 1000)}
    assert "pipe" not in names and cd.special_skipped == 1    # FIFO skipped (not a regular file)
    assert cd.read_file("pipe", 10) == b""                    # O_PATH pin -> no block, no data
    cd.close()


def test_mnt_id_mismatch_refused(tmp_path, monkeypatch):
    (tmp_path / "subdir").mkdir()
    cd = _ContainedDir(str(tmp_path))                         # pins the real root mnt_id
    monkeypatch.setattr(mount_reader, "_mnt_id", lambda fd: "DIFFERENT")   # child now mismatches
    with pytest.raises(_Contained):
        cd.list_dir("subdir", 1000)                          # _verify fails -> boundary crossed
    cd.close()


def test_unreadable_mnt_id_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(mount_reader, "_mnt_id", lambda fd: None)
    with pytest.raises(_Contained):                          # cannot pin identity -> fail closed
        _ContainedDir(str(tmp_path))


def test_per_dir_cap_overflow_detectable(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}").write_text("x")
    cd = _ContainedDir(str(tmp_path))
    assert len(cd.list_dir("", 2)) == 3                      # retain limit+1 (overflow detectable)
    cd.close()


def test_read_file_bounded(tmp_path):
    (tmp_path / "big").write_bytes(b"A" * 100)
    cd = _ContainedDir(str(tmp_path))
    assert cd.read_file("big", 10) == b"A" * 10
    cd.close()


# =============================================================== MountReader lifecycle
class _FakeDiscovery:
    def __init__(self, shares):
        self.shares = list(shares)
        self.closed = False
    def list_shares(self):
        return list(self.shares)
    def close(self):
        self.closed = True


class _FakeRunner:
    def __init__(self):
        self.calls = []
    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        return RunResult(returncode=0)


def _cfg(**kw):
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="pw", share_access_mode="mount")
    base.update(kw)
    return ValidationConfig(**base)


def test_mount_argv_smb_creds_never_in_argv(tmp_path):
    mr = MountReader(_cfg(), "fs01", "smb", _FakeDiscovery(["DATA"]), _FakeRunner())
    argv, cred = mr._mount_argv("DATA", str(tmp_path))
    assert argv[0] == "mount.cifs" and argv[1] == "//fs01/DATA"
    opts = argv[argv.index("-o") + 1]
    for flag in ("ro", "nosuid", "nodev", "noexec"):
        assert flag in opts
    assert "pw" not in " ".join(argv)                        # password NOT in argv
    assert cred and f"cred={cred}" in opts
    assert oct(os.stat(cred).st_mode & 0o777) == "0o600"     # creds file locked down
    assert "password=pw" in Path(cred).read_text()
    os.unlink(cred)


def test_mount_argv_nfs(tmp_path):
    mr = MountReader(_cfg(share_protocol="nfs"), "nfs01", "nfs", _FakeDiscovery(["/export"]), _FakeRunner())
    argv, cred = mr._mount_argv("/export", str(tmp_path))
    assert argv[:3] == ["mount.nfs", "nfs01:/export", str(tmp_path)]
    opts = argv[argv.index("-o") + 1]
    for flag in ("ro", "nosuid", "nodev", "noexec"):
        assert flag in opts
    assert cred is None                                      # NFS AUTH_SYS: no creds file


class _FixtureMountReader(MountReader):
    """Test double: instead of a privileged kernel mount, populate the mountpoint from
    a local fixture dir (same contained reader runs over it)."""
    def __init__(self, *a, fixtures, **kw):
        super().__init__(*a, **kw)
        self._fixtures = fixtures
    def _do_mount(self, share, mp):
        src = self._fixtures.get(share)
        if src is None:
            return False                                     # unmountable share
        shutil.copytree(src, mp, dirs_exist_ok=True, symlinks=True)
        return True


def _mount_reader_over(fixtures, runner, shares=None, **cfgkw):
    disc = _FakeDiscovery(shares if shares is not None else list(fixtures))
    return _FixtureMountReader(_cfg(**cfgkw), "fs01", "smb", disc, runner, fixtures=fixtures)


def test_mount_reader_crawls_contained_and_tears_down(tmp_path):
    src = tmp_path / "share_src"; src.mkdir(); _escape_tree(src)
    runner = _FakeRunner()
    mr = _mount_reader_over({"DATA": str(src)}, runner)
    names = {e.name for e in mr.list_dir("DATA", "", 1000)}
    assert "f.txt" in names and "escape" not in names        # contained: symlink skipped
    assert mr.read_file("DATA", "f.txt", 100) == b"in-bounds"
    assert mr.read_file("DATA", "escape", 100) == b""        # escape never read
    assert mr.mount_succeeded is True
    mr.close()
    assert any(c[:1] == ["umount"] for c in runner.calls)    # teardown unmounted
    assert mr._discovery.closed is True


def test_mount_failure_propagates_as_denied(tmp_path):
    runner = _FakeRunner()
    mr = _mount_reader_over({}, runner, shares=["DATA"])      # no fixture for DATA -> _do_mount False
    with pytest.raises(OSError):
        mr.list_dir("DATA", "", 1000)
    assert mr.mount_succeeded is False
    mr.close()


# =============================================================== executor integration
HOST = "fs01.north.sevenkingdoms.local"


def _finding(host=HOST):
    return map_finding({"finding_id": "SH", "host": host, "category": "smb",
                        "severity": "info", "line": f"shares on {host}"})


def _nctx(cfg, tmp_path, reader):
    ctx = ExecutorContext(cfg, runner=_FakeRunner(), authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    ctx.share_reader_factory = lambda c, host, timeout: reader
    return ctx


def test_executor_mount_mode_end_to_end(tmp_path):
    src = tmp_path / "share_src"; src.mkdir(); _loot_tree(src)
    os.symlink("/etc/passwd", str(src / "pwned"))            # planted escape in the loot share
    reader = _mount_reader_over({"DATA": str(src)}, _FakeRunner())
    res = get_executor("SHARE-LOOT").run(_nctx(_cfg(), tmp_path, reader), _finding())
    tf = res["terminal_fact"]
    assert tf["ok"] is True and tf["access_mode"] == "mount"
    assert tf["mount"]["mounted_any"] is True and tf["mount"]["symlinks_skipped"] >= 1
    cats = tf["loot"]["by_category"]
    assert "ssh_private_key" in cats and "gpp_cpassword" in cats   # loot detected through the mount
    blob = json.dumps(res)
    assert "root:" not in blob and GPP_PLAINTEXT not in blob       # no escape bytes / secret in receipt
    assert "id_rsa" not in blob                                     # raw paths opaque


def test_executor_mount_unavailable_is_inconclusive(tmp_path):
    reader = _mount_reader_over({}, _FakeRunner(), shares=["DATA", "NETLOGON"])   # nothing mountable
    res = get_executor("SHARE-LOOT").run(_nctx(_cfg(), tmp_path, reader), _finding())
    tf = res["terminal_fact"]
    assert tf["ok"] is False
    assert "inconclusive:mount_unavailable" in res["errors"]       # fail-closed, never a false success


def test_config_rejects_unknown_access_mode():
    with pytest.raises(ValueError):
        ValidationConfig(domain="d", dc_ip="1.2.3.4", share_access_mode="fuse")


# ------------------------------------------------- diff-review r1 fixes (adversarial)
def test_close_unmounts_when_flag_unset_but_really_mounted(tmp_path, monkeypatch):
    # review HIGH (r1+r2): an interrupt can leave entry["mounted"] False while the mount is
    # really installed, and a stale backing fs makes os.path.ismount lie -> close() must read
    # the REAL state from /proc/self/mountinfo (_is_mounted) as source of truth.
    runner = _FakeRunner()
    mr = MountReader(_cfg(), "fs01", "smb", _FakeDiscovery([]), runner)
    mr._mounts["X"] = {"mp": str(tmp_path), "fs": None, "mounted": False, "cred": None}
    monkeypatch.setattr(mount_reader, "_is_mounted",          # mountinfo says mounted (ESTALE-robust)
                        lambda p: p == str(tmp_path))
    mr.close()
    assert any(c[:1] == ["umount"] for c in runner.calls)     # unmounted despite the False flag + bad ismount


def test_contained_dir_construction_failure_closes_root_fd(tmp_path, monkeypatch):
    # review HIGH: a post-open fstat failure must not leak the root fd.
    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr(mount_reader.os, "fstat", lambda fd: (_ for _ in ()).throw(OSError("ESTALE")))
    with pytest.raises(OSError):
        _ContainedDir(str(tmp_path))
    assert len(os.listdir("/proc/self/fd")) <= before         # no descriptor leaked


def test_list_dir_bounds_hostile_enumeration(tmp_path, monkeypatch):
    # review HIGH: skipped entries (symlinks/specials) bypass the retained cap; a bound on
    # ENTRIES SCANNED stops an endless hostile directory instead of hanging.
    for i in range(6):
        os.symlink("/etc/passwd", str(tmp_path / f"s{i}"))    # all skipped (symlinks)
    monkeypatch.setattr(mount_reader, "_SCAN_SLACK", 2)
    cd = _ContainedDir(str(tmp_path))
    cd.list_dir("", 0)                                        # cap 0 + slack 2 -> truncates at scan 3
    assert cd.scan_truncated is True
    cd.close()


def test_write_cred_cleans_up_on_write_failure(monkeypatch):
    # review HIGH: a partial creds write (e.g. ENOSPC) still wrote the secret -> must shred.
    import glob
    tmpdir = tempfile.gettempdir()
    before = set(glob.glob(os.path.join(tmpdir, "sl-cred-*")))

    class _BoomFile:
        def __init__(self, fd): self._fd = fd
        def __enter__(self): return self
        def __exit__(self, *a): os.close(self._fd); return False
        def write(self, *a): raise OSError("ENOSPC")

    monkeypatch.setattr(mount_reader.os, "fdopen", lambda fd, mode: _BoomFile(fd))
    with pytest.raises(OSError):
        mount_reader._write_cred(_cfg())
    after = set(glob.glob(os.path.join(tmpdir, "sl-cred-*")))
    assert after <= before                                   # no leaked plaintext creds file
