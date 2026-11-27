"""NFS (NFSv3) read-only reader + multi-method export discovery for SHARE-LOOT (S2).

The Linux half of the first joint Windows/Linux module (S1 = SMB; S2 = NFS). The
crawl + loot engine (``_Crawler`` / ``loot_rules``) is transport-agnostic; only
discovery and the read-only reader differ by protocol.

READ-ONLY by construction: :class:`_NfsReader` drives pyNfsClient through the
NFSv3 *read* procedures only -- ``Mount.export``/``mnt``/``umnt`` and
``NFSv3.readdirplus``/``lookup``/``read``. It never calls ``write``/``create``/
``remove``/``mkdir``/``setattr``, so the executor cannot mutate an export (the same
invariant the impacket ``ShareReader`` holds for SMB). It implements the narrow
:class:`~.share_loot.ShareReader` interface (``list_shares``/``list_dir``/
``read_file``/``close``) so the executor crawls SMB and NFS through one code path.

MULTI-METHOD discovery (:func:`nfs_discover`) UNIONS four independent methods so a
single wrong or filtered source cannot hide an export (owner directive: "do not
only rely on showmount, it is wrong sometimes"):

  1. programmatic ``Mount.export()`` (pyNfsClient)   -- primary, no external tool
  2. ``showmount -e <host>``                           -- classic mountd dump
  3. ``nmap --script nfs-showmount``                   -- independent backup enum
  4. ``rpcinfo``                                        -- liveness (NFS + mountd up)

Every CLI method runs through the injected :class:`~.base.CommandRunner` as an
argv **list** (never a shell string), so there is no command-string injection --
the same injection-safe posture as S1's programmatic SMB client. Export PATHS are
the NFS access-control catalog (the analogue of SMB share names), so they surface
in the receipt under the justified safe-name policy; file/dir paths beneath an
export stay opaque (``loc:<rand>``) exactly as on the SMB path.
"""
from __future__ import annotations

import re
from typing import Any, Optional

# NFSv3 file types (RFC 1813 ftype3).
_NF3REG = 1   # regular file
_NF3DIR = 2   # directory

# The read-only NFS auth (AUTH_UNIX / AUTH_SYS, flavor 1). uid/gid 0 only requests
# access; the server's export policy decides what is actually readable. No secret.
_AUTH = {"flavor": 1, "machine_name": "shareloot", "uid": 0, "gid": 0, "aux_gid": []}


# ----------------------------------------------------------------- reply accessors
def _decode_name(name: Any) -> str:
    """Decode an NFS entry name. ``surrogateescape`` round-trips non-UTF-8 bytes
    without raising (a crafted share may hold arbitrary byte names); the loot
    engine's own decoders handle content separately."""
    if isinstance(name, bytes):
        return name.decode("utf-8", "surrogateescape")
    return str(name)


def _entry_fh(entry: dict) -> Optional[bytes]:
    """The post-op file handle readdirplus attached to a directory entry (so we can
    descend/read without a follow-up ``lookup``). ``None`` if the server omitted it."""
    return ((entry.get("name_handle") or {}).get("handle") or {}).get("data")


def _entry_attrs(entry: dict) -> dict:
    return ((entry.get("name_attributes") or {}).get("attributes")) or {}


def _lookup_fh(res: dict) -> Optional[bytes]:
    """Extract the object handle from an NFSv3 ``lookup`` result (status 0 only)."""
    if (res or {}).get("status") != 0:
        return None
    return (((res.get("resok") or {}).get("object")) or {}).get("data")


# ------------------------------------------------------------------- the NFS reader
class _NfsReader:
    """Read-only :class:`ShareReader` over pyNfsClient (NFSv3).

    "Shares" are export paths (e.g. ``/export``). A per-export root handle is mounted
    lazily on first access; child handles discovered during ``list_dir`` are cached by
    full relative path, so the crawler's descend/read walk needs no extra ``lookup``
    round-trips (and ``_resolve`` falls back to ``lookup`` for any uncached path)."""

    def __init__(self, pm, mount, nfs, auth: Optional[dict] = None):
        self._pm, self._mount, self._nfs = pm, mount, nfs
        self._auth = auth or _AUTH
        self._root_fh: dict[str, bytes] = {}        # export -> root fh (from mnt)
        self._fh: dict[tuple[str, str], bytes] = {}  # (export, relpath) -> fh cache

    # -- discovery -------------------------------------------------------------
    def list_shares(self) -> list[str]:
        """Programmatic ``Mount.export()`` -- the export catalog (method 1 of 4)."""
        out: list[str] = []
        try:
            exports = self._mount.export()
        except Exception:
            return []
        for e in (exports or []):
            d = getattr(e, "ex_dir", None)
            if d is None and isinstance(e, dict):
                d = e.get("ex_dir")
            if d is None:
                continue
            out.append(d.decode("utf-8", "surrogateescape") if isinstance(d, bytes) else str(d))
        return out

    # -- handle resolution -----------------------------------------------------
    def _export_root(self, export: str) -> bytes:
        if export not in self._root_fh:
            res = self._mount.mnt(export, self._auth)
            info = (res or {}).get("mountinfo") or {}
            if info.get("status", 0) != 0 or "fhandle" not in info:
                raise OSError(f"mnt {export!r} failed (status={info.get('status')})")
            self._root_fh[export] = info["fhandle"]
            self._fh[(export, "")] = info["fhandle"]
        return self._root_fh[export]

    def _resolve(self, export: str, path: str) -> bytes:
        """Resolve a (export, relpath) to an NFS file handle. Uses the per-path cache
        populated by ``list_dir`` first; falls back to component-wise ``lookup`` from
        the export root for any uncached path."""
        rel = path.strip("/")
        cached = self._fh.get((export, rel))
        if cached is not None:
            return cached
        fh = self._export_root(export)
        acc = ""
        for comp in (c for c in rel.split("/") if c):
            acc = (acc + "/" + comp) if acc else comp
            step = self._fh.get((export, acc))
            if step is None:
                res = self._nfs.lookup(fh, comp, auth=self._auth)
                step = _lookup_fh(res)
                if step is None:
                    raise OSError(f"lookup {export!r}:{acc!r} failed")
                self._fh[(export, acc)] = step
            fh = step
        return fh

    # -- read-only listing/read ------------------------------------------------
    def list_dir(self, export: str, path: str, limit: int) -> list:
        """List one directory via ``readdirplus`` (paged by cookie until ``eof``),
        retaining at most ``limit`` + 1 entries so the caller can detect overflow
        (mirrors the impacket reader's per-dir cap semantics)."""
        from .share_loot import _Entry   # local import avoids a module import cycle

        fh = self._resolve(export, path)
        cap = max(0, int(limit))
        base = path.strip("/")
        out: list = []
        cookie: Any = 0
        verf: Any = 0
        while True:
            rd = self._nfs.readdirplus(fh, cookie, verf, 8192, auth=self._auth)
            resok = (rd or {}).get("resok") or {}
            reply = resok.get("reply") or {}
            verf = resok.get("cookieverf", verf)
            node = reply.get("entries")
            saw_entry = False
            while node:
                en = node[0] if isinstance(node, (list, tuple)) else node
                saw_entry = True
                nm = _decode_name(en.get("name"))
                cookie = en.get("cookie", cookie)
                if nm not in (".", ".."):
                    attrs = _entry_attrs(en)
                    is_dir = attrs.get("type") == _NF3DIR
                    size = int(attrs.get("size") or 0)
                    child_fh = _entry_fh(en)
                    if child_fh is not None:
                        rel = (base + "/" + nm) if base else nm
                        self._fh[(export, rel)] = child_fh   # cache for descend/read
                    out.append(_Entry(nm, is_dir, size))
                    if len(out) > cap:                       # retain cap+1 (overflow detectable)
                        return out
                node = en.get("nextentry")
            if reply.get("eof"):
                break
            if not saw_entry:                                # no progress, not eof -> stop (defensive)
                break
        return out

    def read_file(self, export: str, path: str, max_bytes: int) -> bytes:
        """Read AT MOST ``max_bytes`` of a file (looped ``read`` by offset, stopping at
        the cap or server ``eof``). Read-only."""
        fh = self._resolve(export, path)
        cap = max(0, int(max_bytes))
        buf = bytearray()
        off = 0
        while len(buf) < cap:
            want = min(1024 * 1024, cap - len(buf))
            r = self._nfs.read(fh, offset=off, chunk_count=want, auth=self._auth)
            resok = (r or {}).get("resok") or {}
            data = resok.get("data") or b""
            if not data:
                break
            buf.extend(data)
            off += len(data)
            if resok.get("eof"):
                break
        return bytes(buf[:cap])

    def close(self) -> None:
        for conn in (self._nfs, self._mount, self._pm):
            try:
                conn.disconnect()
            except Exception:
                pass


def nfs_reader_factory(cfg, host: str, timeout: int) -> _NfsReader:
    """Default NFS reader factory: connect Portmap + Mount + NFSv3 to ``host``.

    Imported lazily so the module loads without pyNfsClient (tests inject a fake
    reader via ``ctx.share_reader_factory``). Raises on connection failure so the
    executor records the host as ``unreachable`` (never a fabricated success)."""
    from pyNfsClient import Portmap, Mount, NFSv3, NFS_PROGRAM, NFS_V3

    t = max(1, int(timeout))
    pm = Portmap(host, timeout=t)
    pm.connect()
    mount = Mount(host=host, port=pm.getport(Mount.program, Mount.program_version),
                  timeout=t, auth=_AUTH)
    mount.connect()
    nfs = NFSv3(host, pm.getport(NFS_PROGRAM, NFS_V3), t, _AUTH)
    nfs.connect()
    return _NfsReader(pm, mount, nfs, _AUTH)


# ------------------------------------------------------------- multi-method discovery
def _parse_showmount(stdout: str) -> list[str]:
    """Export paths from ``showmount -e``. The first line is an 'Export list for ...'
    header; each later line is ``<path> <clients>`` -- take the leading path token."""
    out: list[str] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s or s.lower().startswith("export list"):
            continue
        tok = s.split()[0]
        if tok.startswith("/"):
            out.append(tok)
    return out


_NMAP_EXPORT = re.compile(r"^\|?_?\s*(/\S+)")


def _parse_nmap_showmount(stdout: str) -> list[str]:
    """Export paths from ``nmap --script nfs-showmount`` output lines like
    ``|_  /export *`` / ``|   /home 10.0.0.0/8``."""
    out: list[str] = []
    for line in (stdout or "").splitlines():
        m = _NMAP_EXPORT.match(line.strip())
        if m:
            out.append(m.group(1))
    return out


def _rpcinfo_shows_nfs(stdout: str) -> bool:
    """Liveness: does ``rpcinfo`` output register the nfs program (and/or mountd)?"""
    low = (stdout or "").lower()
    return ("nfs" in low) or ("100003" in low) or ("mountd" in low) or ("100005" in low)


def nfs_discover(runner, reader: _NfsReader, host: str, timeout: int) -> tuple[list[str], list[dict]]:
    """UNION export discovery across four independent methods (owner directive: do
    not rely on showmount alone). Returns ``(exports, methods)`` where ``exports`` is
    the de-duplicated union (first-seen order) and ``methods`` records, per method,
    whether it ran and how many exports it contributed -- receipt-safe transparency
    that multi-method discovery actually happened.

    ``runner`` is an injected :class:`~.base.CommandRunner`; a missing CLI tool or a
    timeout degrades that one method to ``ran=False`` and never aborts discovery."""
    seen: dict[str, None] = {}
    methods: list[dict] = []

    def _record(name: str, exports: Optional[list[str]], ran: bool, note: str = "") -> None:
        added = 0
        for e in (exports or []):
            if e not in seen:
                seen[e] = None
                added += 1
        methods.append({"method": name, "ran": ran, "found": len(exports or []),
                        "new": added, **({"note": note} if note else {})})

    # 1. programmatic Mount.export() -- primary, no external tool.
    try:
        prog = reader.list_shares()
        _record("mount.export", prog, True)
    except Exception as exc:
        _record("mount.export", None, False, f"{type(exc).__name__}")

    t = max(1, int(timeout))

    # 2. showmount -e <host>
    try:
        res = runner.run(["showmount", "--no-headers", "-e", host], timeout=t)
        if getattr(res, "error", None) and _tool_missing(res):
            _record("showmount", None, False, "tool_absent")
        else:
            _record("showmount", _parse_showmount(res.stdout), True)
    except Exception as exc:
        _record("showmount", None, False, f"{type(exc).__name__}")

    # 3. nmap --script nfs-showmount (independent backup enumerator)
    try:
        res = runner.run(["nmap", "-Pn", "-p", "2049,111", "--script", "nfs-showmount", host],
                         timeout=max(t, 30))
        if getattr(res, "error", None) and _tool_missing(res):
            _record("nmap.nfs-showmount", None, False, "tool_absent")
        else:
            _record("nmap.nfs-showmount", _parse_nmap_showmount(res.stdout), True)
    except Exception as exc:
        _record("nmap.nfs-showmount", None, False, f"{type(exc).__name__}")

    # 4. rpcinfo -- liveness signal only (confirms NFS/mountd up; contributes no path).
    try:
        res = runner.run(["rpcinfo", "-p", host], timeout=t)
        if getattr(res, "error", None) and _tool_missing(res):
            methods.append({"method": "rpcinfo", "ran": False, "found": 0, "new": 0,
                            "note": "tool_absent"})
        else:
            methods.append({"method": "rpcinfo", "ran": True, "found": 0, "new": 0,
                            "nfs_up": _rpcinfo_shows_nfs(res.stdout)})
    except Exception as exc:
        methods.append({"method": "rpcinfo", "ran": False, "found": 0, "new": 0,
                        "note": type(exc).__name__})

    return list(seen.keys()), methods


def _tool_missing(res) -> bool:
    err = (getattr(res, "error", None) or "").lower()
    return any(m in err for m in ("filenotfounderror", "no such file", "not found"))
