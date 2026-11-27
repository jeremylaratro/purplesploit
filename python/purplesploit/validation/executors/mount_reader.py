"""SHARE-LOOT S1b -- mount-mode access with descriptor-anchored containment.

Mount mode uses the KERNEL SMB/NFS client (handles dialects, SMB3 encryption,
Kerberos-auth mounts, NFSv4, DFS that the Python libraries cannot), then crawls the
mounted, ATTACKER-CONTROLLED share for loot. Reading such a mount naively
(``os.walk``/``open``) risks symlink-escape, ``..``-escape, cross-mount escape, and
blocking/device-handler traps. :class:`_ContainedDir` prevents all of these with a
descriptor-anchored walk (equivalent to ``RESOLVE_BENEATH|NO_SYMLINKS|NO_XDEV`` --
CPython does not expose ``os.openat2``), validated by an adversarial plan review:

- **Directories** are opened READABLE + anchored: ``os.open(name, O_RDONLY|O_DIRECTORY
  |O_NOFOLLOW|O_CLOEXEC, dir_fd=parent)`` -- ``O_DIRECTORY`` makes a FIFO/file/device
  named as a path component fail ``ENOTDIR`` (no block, no device open-handler);
  ``O_NOFOLLOW`` makes a symlink component fail ``ELOOP``. The readable fd is used for
  ``scandir`` AND as the ``openat`` anchor (an ``O_PATH`` dir fd cannot be scanned --
  ``fdopendir`` needs a readable fd).
- **Files** are PINNED first (``O_PATH|O_NOFOLLOW`` -- no block, no handler, no
  follow), ``fstat``-verified ``S_ISREG`` + identity, then reopened for reading via
  ``/proc/self/fd/<pin>`` (the SAME inode -- no name re-resolution race).
- **Mount identity** is pinned at the root via ``mnt_id`` (``/proc/self/fdinfo/<fd>``);
  every opened dir/file fd must match it (plus ``st_dev``). Unverifiable identity ->
  **fail closed**. Symlink + non-regular/non-dir entries are SKIPPED (and counted);
  ``..`` is never passed to any ``openat``.

:class:`MountReader` adds the per-share lifecycle: a hardened read-only mount
(``ro,nosuid,nodev,noexec``; SMB creds via a ``0600`` file unlinked right after the
mount, never argv), fail-closed handling (a mount failure -> that share
``unreachable``; NO share mountable -> the executor emits
``inconclusive:mount_unavailable``, never a false success), and guaranteed teardown
(close ALL fds first so the mount is not busy, then a bounded ``umount`` with a lazy
fallback, then ``rmdir`` only if confirmed unmounted).
"""
from __future__ import annotations

import os
import stat
import tempfile
from typing import Optional


class _Contained(OSError):
    """Raised when a traversal step would cross the pinned mount boundary."""


def _mnt_id(fd: int) -> Optional[str]:
    """The mount id of an open fd (``/proc/self/fdinfo/<fd>``) -- the robust mount
    boundary (``st_dev`` is shared by two mounts of one filesystem). ``None`` if it
    cannot be read, which the caller treats as a fail-closed boundary violation."""
    try:
        with open(f"/proc/self/fdinfo/{fd}") as fh:
            for line in fh:
                if line.startswith("mnt_id:"):
                    return line.split("\t", 1)[-1].strip()
    except OSError:
        return None
    return None


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_PIN_FLAGS = os.O_PATH | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

# Bound on entries SCANNED per directory (not just retained): a hostile network fs can
# stream an endless directory of skip-able entries (symlinks/specials) that never grow
# the retained cap, so the per-dir cap alone does not bound the work. Generous vs any
# real directory; skipped entries beyond this truncate the listing instead of hanging.
_SCAN_SLACK = 8192


class _ContainedDir:
    """Descriptor-anchored read-only walker pinned beneath ``root_path``. Usable over
    any directory tree (a real mount in production; a local fixture in tests)."""

    def __init__(self, root_path: str):
        root_fd = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
        try:
            self._root_mnt = _mnt_id(root_fd)
            if self._root_mnt is None:                 # cannot pin identity -> fail closed
                raise _Contained(f"cannot read mnt_id for {root_path!r} (fail closed)")
            self._root_dev = os.fstat(root_fd).st_dev
        except BaseException:                          # any construction failure must not leak the fd
            os.close(root_fd)
            raise
        self._dirfds: dict[str, int] = {"": root_fd}   # relpath -> readable dir fd (anchor + scandir)
        self.symlinks_skipped = 0
        self.special_skipped = 0
        self.scan_truncated = False

    def _verify(self, fd: int) -> None:
        """Every opened fd must stay on the pinned mount (mnt_id + st_dev)."""
        if _mnt_id(fd) != self._root_mnt or os.fstat(fd).st_dev != self._root_dev:
            raise _Contained("mount boundary crossed")

    def _opendir(self, parent_fd: int, name: str) -> int:
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)   # readable, nofollow, O_DIRECTORY
        try:
            self._verify(fd)
        except Exception:
            os.close(fd)
            raise
        return fd

    def _resolve_dir(self, relpath: str) -> int:
        rel = relpath.strip("/")
        cached = self._dirfds.get(rel)
        if cached is not None:
            return cached
        fd = self._dirfds[""]
        acc = ""
        for comp in rel.split("/"):
            if comp in ("", ".", ".."):                # never traverse '..'/'.' (stay beneath root)
                continue
            acc = (acc + "/" + comp) if acc else comp
            nxt = self._dirfds.get(acc)
            if nxt is None:
                nxt = self._opendir(fd, comp)
                self._dirfds[acc] = nxt
            fd = nxt
        return fd

    def list_dir(self, relpath: str, limit: int) -> list:
        dfd = self._resolve_dir(relpath)
        cap = max(0, int(limit))
        out: list = []
        scanned = 0
        with os.scandir(dfd) as it:                    # readable dir fd (O_PATH would EBADF)
            for e in it:
                scanned += 1
                if scanned > cap + _SCAN_SLACK:        # hostile endless/huge dir -> bound total work
                    self.scan_truncated = True
                    break
                if e.name in (".", ".."):
                    continue
                if e.is_symlink():                     # never follow a symlink -> skip + count
                    self.symlinks_skipped += 1
                    continue
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    out.append((e.name, True, 0))
                elif stat.S_ISREG(st.st_mode):
                    out.append((e.name, False, int(st.st_size)))
                else:
                    self.special_skipped += 1          # FIFO/socket/device -> skip (no block/handler)
                    continue
                if len(out) > cap:                     # retain cap+1 (overflow detectable)
                    break
        return out

    def read_file(self, relpath: str, max_bytes: int) -> bytes:
        rel = relpath.strip("/")
        parent, _, name = rel.rpartition("/")
        if not name:
            return b""
        dfd = self._resolve_dir(parent)
        try:
            pfd = os.open(name, _PIN_FLAGS, dir_fd=dfd)    # O_PATH pin: no block, no handler, no follow
        except OSError:
            return b""
        try:
            st = os.fstat(pfd)
            if not stat.S_ISREG(st.st_mode):               # FIFO/dir/device/socket/symlink -> not a file
                return b""
            if _mnt_id(pfd) != self._root_mnt or st.st_dev != self._root_dev:
                return b""                                 # boundary crossed (TOCTOU swap) -> no leak
            try:
                rfd = os.open(f"/proc/self/fd/{pfd}", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            except OSError:
                return b""
        finally:
            os.close(pfd)
        try:
            cap = max(0, int(max_bytes))
            buf = bytearray()
            while len(buf) < cap:
                chunk = os.read(rfd, min(1 << 16, cap - len(buf)))
                if not chunk:
                    break
                buf.extend(chunk)
            return bytes(buf[:cap])
        finally:
            os.close(rfd)

    def close(self) -> None:
        for fd in self._dirfds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self._dirfds.clear()


# ------------------------------------------------------------------- creds handling
def _write_cred(cfg) -> str:
    """A ``0600`` ``mount.cifs`` credentials file (``mkstemp`` is ``O_EXCL`` + ``0600``).
    Keeps the password OUT of argv (the process list); unlinked right after the mount."""
    fd, path = tempfile.mkstemp(prefix="sl-cred-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(f"username={cfg.username or ''}\n")
            fh.write(f"password={cfg.password or ''}\n")
            if cfg.domain:
                fh.write(f"domain={cfg.domain}\n")
    except BaseException:                              # a partial write still wrote the secret -> shred
        _shred_unlink(path)
        raise
    return path


def _shred_unlink(path: str) -> None:
    try:
        n = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * n)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        os.unlink(path)
    except OSError:
        pass


# --------------------------------------------------------------------- mount reader
class MountReader:
    """``ShareReader`` that mounts each discovered share READ-ONLY and crawls it with
    :class:`_ContainedDir`. Discovery is delegated to a programmatic reader (unchanged
    from crawl mode); only ACCESS differs."""

    def __init__(self, cfg, host: str, protocol: str, discovery, runner):
        self._cfg = cfg
        self._host = host
        self._protocol = protocol
        self._discovery = discovery
        self._runner = runner
        self._mounts: dict[str, dict] = {}     # share -> {mp, fs, mounted, cred}
        self.mount_succeeded = False
        self.symlinks_skipped = 0
        self.special_skipped = 0

    # -- discovery (delegated) -------------------------------------------------
    def list_shares(self) -> list[str]:
        return self._discovery.list_shares()

    # -- mount lifecycle -------------------------------------------------------
    def _mount_argv(self, share: str, mp: str) -> tuple[list[str], Optional[str]]:
        if self._protocol == "nfs":
            src = f"{self._host}:{share}"           # share == export path, e.g. /export
            return (["mount.nfs", src, mp, "-o",
                     "ro,nosuid,nodev,noexec,soft,timeo=100,retrans=2"], None)
        opts = "ro,nosuid,nodev,noexec,vers=3.0"    # SMB
        cred = None
        if self._cfg.username and self._cfg.password:
            cred = _write_cred(self._cfg)
            opts += f",cred={cred}"
        else:
            opts += ",guest"                        # no password -> guest (NT-hash/krb5 mount = follow-up)
        return (["mount.cifs", f"//{self._host}/{share}", mp, "-o", opts], cred)

    def _do_mount(self, share: str, mp: str) -> bool:
        """Run the hardened RO mount; return whether a mount is actually installed
        (``os.path.ismount``, reconciled from the real state, NOT the helper's rc).
        Overridable test seam. The creds file is unlinked right after the call."""
        argv, cred = self._mount_argv(share, mp)
        self._mounts[share]["cred"] = cred           # register BEFORE running (cleanup covers partial)
        try:
            self._runner.run(argv, timeout=getattr(self._cfg, "tool_timeout_s", 60))
        finally:
            if cred:
                _shred_unlink(cred)                  # consumed at mount time -> shrink leak window
                self._mounts[share]["cred"] = None
        return os.path.ismount(mp)

    def _ensure_mounted(self, share: str) -> dict:
        entry = self._mounts.get(share)
        if entry is not None:
            if entry["fs"] is None:                  # a prior mount attempt failed
                raise OSError(f"mount {share!r} previously failed")
            return entry
        mp = tempfile.mkdtemp(prefix="sl-mnt-")       # 0700
        entry = {"mp": mp, "fs": None, "mounted": False, "cred": None}
        self._mounts[share] = entry                   # REGISTER before mount (crash/partial cleanup)
        try:
            mounted = self._do_mount(share, mp)
        except BaseException:                         # incl. KeyboardInterrupt: reconcile then re-raise
            entry["mounted"] = os.path.ismount(mp)    # a late/partial mount still needs teardown
            raise
        entry["mounted"] = mounted
        if not mounted:
            raise OSError(f"mount {share!r} failed")
        self.mount_succeeded = True
        entry["fs"] = _ContainedDir(mp)
        return entry

    # -- read-only access (contained) -----------------------------------------
    def list_dir(self, share: str, path: str, limit: int) -> list:
        from .share_loot import _Entry
        entry = self._ensure_mounted(share)
        return [_Entry(n, d, s) for (n, d, s) in entry["fs"].list_dir(path, limit)]

    def read_file(self, share: str, path: str, max_bytes: int) -> bytes:
        entry = self._ensure_mounted(share)
        return entry["fs"].read_file(path, max_bytes)

    # -- teardown (guaranteed, independent per resource) -----------------------
    def _umount(self, mp: str) -> None:
        self._runner.run(["umount", mp], timeout=getattr(self._cfg, "tool_timeout_s", 60))
        if os.path.ismount(mp):                       # still busy/failed -> lazy detach fallback
            self._runner.run(["umount", "-l", mp], timeout=getattr(self._cfg, "tool_timeout_s", 60))

    def close(self) -> None:
        for entry in self._mounts.values():
            fs = entry.get("fs")
            if fs is not None:
                self.symlinks_skipped += fs.symlinks_skipped
                self.special_skipped += fs.special_skipped
                try:
                    fs.close()                        # close ALL fds FIRST (unbusy the mount)
                except Exception:
                    pass
            try:                                      # source of truth = the REAL mount state, not just
                really_mounted = entry.get("mounted") or os.path.ismount(entry["mp"])
            except OSError:
                really_mounted = bool(entry.get("mounted"))  # the stored flag (set before an interrupt)
            if really_mounted:
                try:
                    self._umount(entry["mp"])
                except Exception:
                    pass
            if entry.get("cred"):
                _shred_unlink(entry["cred"])
            try:
                if not os.path.ismount(entry["mp"]):  # rmdir only if confirmed unmounted
                    os.rmdir(entry["mp"])
            except OSError:
                pass
        self._mounts.clear()
        try:
            self._discovery.close()
        except Exception:
            pass
