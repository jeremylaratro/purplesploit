"""SHARE-LOOT S2 -- NFS (NFSv3) read-only reader + multi-method export discovery.

Security-critical invariants, non-vacuous:
- READ-ONLY by construction: the reader drives ONLY NFSv3 read procedures
  (export/mnt/readdirplus/lookup/read); a fake backend records every call and we
  assert no write/create/remove is ever invoked, and :class:`_NfsReader` exposes none.
- Multi-method discovery UNIONS four sources so showmount alone cannot HIDE an
  export (owner directive): an export only nmap/programmatic sees is still found,
  and the single-method parse that WOULD miss it is shown empty (gate RED proof).
- The transport-agnostic loot engine detects UTF-16 content + a non-ASCII GPP
  principal + case-variant dirs through the NFS reader exactly as over SMB, and a
  secret path/principal never reaches the receipt (opaque IDs only).

The fake backend mirrors the EXACT pyNfsClient return shapes verified live against
an nfs-kernel-server export (readdirplus entries as a cookie-paged linked list;
lookup -> resok.object.data; read -> resok.{data,eof,count})."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, nfs_reader
from purplesploit.validation.executors.base import (ExecutorContext, AuthorizedLabProvider,
                                                    RunResult)
from purplesploit.validation.executors.nfs_reader import (
    _NfsReader, nfs_discover, _parse_showmount, _parse_nmap_showmount, _rpcinfo_shows_nfs)


HOST = "fileserver.north.sevenkingdoms.local"


# --------------------------------------------------------------- fake NFSv3 backend
class _Node:
    """A file (data) or directory (children) with a stable file handle."""
    def __init__(self, fh: bytes, is_dir: bool, data: bytes = b""):
        self.fh, self.is_dir, self.data = fh, is_dir, data
        self.children: dict[str, "_Node"] = {}


class _Export:
    def __init__(self, ex_dir: bytes):
        self.ex_dir = ex_dir


def _dir(fh: str, children: dict | None = None) -> _Node:
    n = _Node(fh.encode(), True)
    n.children = children or {}
    return n


def _file(fh: str, data: bytes) -> _Node:
    return _Node(fh.encode(), False, data)


class _FakeNfs:
    """Models Portmap+Mount+NFSv3 as one object (the reader calls disconnect on each
    of its three handles). ``roots`` maps export path -> root :class:`_Node`.
    Records every procedure call so a test can prove read-only operation."""
    program = 100005          # Mount.program stand-ins for the factory (unused in tests)
    program_version = 3

    def __init__(self, roots: dict[str, _Node], *, exports=None, page_size: int | None = None):
        self.roots = roots
        self.exports = list(exports) if exports is not None else list(roots.keys())
        self.page_size = page_size
        self.calls: list[tuple] = []
        self._by_fh: dict[bytes, _Node] = {}
        for root in roots.values():
            self._index(root)

    def _index(self, node: _Node) -> None:
        self._by_fh[node.fh] = node
        for ch in node.children.values():
            self._index(ch)

    # -- Mount --
    def export(self):
        self.calls.append(("export",))
        return [_Export(e.encode()) for e in self.exports]

    def mnt(self, export, auth):
        self.calls.append(("mnt", export))
        root = self.roots.get(export)
        if root is None:
            return {"mountinfo": {"status": 1}}
        return {"mountinfo": {"status": 0, "fhandle": root.fh}}

    def umnt(self, auth):
        self.calls.append(("umnt",))

    # -- NFSv3 --
    def readdirplus(self, dir_handle, cookie=0, cookie_verf=0, dircount=4096, auth=None):
        self.calls.append(("readdirplus", dir_handle, int(cookie)))
        node = self._by_fh.get(dir_handle)
        if node is None or not node.is_dir:
            return {"resok": {"cookieverf": cookie_verf, "reply": {"entries": None, "eof": True}}}
        items = [(".", node), ("..", node)] + list(node.children.items())
        start = int(cookie)
        if self.page_size:
            chunk = items[start:start + self.page_size]
            eof = (start + len(chunk)) >= len(items)
        else:
            chunk = items[start:]
            eof = True
        head = None
        for i in range(len(chunk) - 1, -1, -1):          # build the linked list tail-first
            name, child = chunk[i]
            idx = start + i
            en = {
                "name": name.encode(),
                "cookie": idx + 1,                       # resume-AFTER cookie (absolute)
                "name_attributes": {"attributes": {
                    "type": 2 if child.is_dir else 1, "size": len(child.data)}},
                "name_handle": {"handle": {"data": child.fh}},
                "nextentry": [head] if head is not None else None,
            }
            head = en
        return {"resok": {"cookieverf": cookie_verf,
                          "reply": {"entries": [head] if head else None, "eof": eof}}}

    def lookup(self, dir_handle, file_folder, auth=None):
        self.calls.append(("lookup", dir_handle, file_folder))
        node = self._by_fh.get(dir_handle)
        nm = file_folder.decode() if isinstance(file_folder, bytes) else file_folder
        child = node.children.get(nm) if node else None
        if child is None:
            return {"status": 2}                          # NFS3ERR_NOENT
        return {"status": 0, "resok": {"object": {"data": child.fh}}}

    def read(self, file_handle, offset=0, chunk_count=0, auth=None):
        self.calls.append(("read", file_handle, offset, chunk_count))
        node = self._by_fh.get(file_handle)
        if node is None or node.is_dir:
            return {"status": 1}
        data = node.data[offset:offset + chunk_count]
        eof = (offset + len(data)) >= len(node.data)
        return {"status": 0, "resok": {"data": data, "count": len(data), "eof": eof}}

    def getport(self, prog, ver=None):
        return 2049

    def connect(self):
        return self

    def disconnect(self):
        self.calls.append(("disconnect",))

    def method_names(self) -> set:
        return {c[0] for c in self.calls}


def _reader(roots, *, exports=None, page_size=None) -> tuple[_NfsReader, _FakeNfs]:
    fake = _FakeNfs(roots, exports=exports, page_size=page_size)
    return _NfsReader(fake, fake, fake), fake


# ------------------------------------------------------------------- runner for discovery
class _FakeRunner:
    """Scripted CommandRunner. ``outputs`` maps argv[0] -> RunResult (or callable).
    An unmapped tool -> a FileNotFoundError RunResult (tool absent)."""
    def __init__(self, outputs: dict):
        self.outputs = outputs
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        out = self.outputs.get(argv[0])
        if out is None:
            return RunResult(returncode=None, error="FileNotFoundError: no such file")
        return out(argv) if callable(out) else out


# ============================================================================ reader
def test_nfs_reader_lists_and_reads():
    roots = {"/export": _dir("r", {
        "readme.txt": _file("f1", b"hello"),
        "configs": _dir("d1", {"web.config": _file("f2", b"<x>secret</x>")}),
    })}
    rdr, fake = _reader(roots)
    assert set(rdr.list_shares()) == {"/export"}
    top = {e.name: (e.is_dir, e.size) for e in rdr.list_dir("/export", "", 1000)}
    assert top == {"readme.txt": (False, 5), "configs": (True, 0)}
    assert rdr.read_file("/export", "readme.txt", 1000) == b"hello"
    sub = [e.name for e in rdr.list_dir("/export", "configs", 1000)]
    assert sub == ["web.config"]
    assert rdr.read_file("/export", "configs/web.config", 1000) == b"<x>secret</x>"


def test_readdirplus_linked_list_all_entries():
    kids = {f"f{i}": _file(f"h{i}", b"x") for i in range(5)}
    rdr, _ = _reader({"/e": _dir("r", kids)})
    names = sorted(e.name for e in rdr.list_dir("/e", "", 1000))
    assert names == [f"f{i}" for i in range(5)]           # whole chain traversed via nextentry


def test_readdirplus_paging_cookie_eof():
    kids = {f"f{i}": _file(f"h{i}", b"x") for i in range(7)}
    rdr, fake = _reader({"/e": _dir("r", kids)}, page_size=2)   # forces many batches incl. '.'/'..' only
    names = sorted(e.name for e in rdr.list_dir("/e", "", 1000))
    assert names == [f"f{i}" for i in range(7)]
    assert sum(1 for c in fake.calls if c[0] == "readdirplus") >= 3   # genuinely paged


def test_list_dir_caches_child_handles_no_lookup():
    roots = {"/e": _dir("r", {"configs": _dir("d1", {"web.config": _file("f2", b"data")})})}
    rdr, fake = _reader(roots)
    rdr.list_dir("/e", "", 1000)                          # caches 'configs' fh
    rdr.list_dir("/e", "configs", 1000)                   # caches 'configs/web.config' fh
    rdr.read_file("/e", "configs/web.config", 1000)       # resolved from cache
    assert not any(c[0] == "lookup" for c in fake.calls)  # the crawl walk needs no lookup round-trips


def test_read_file_resolves_via_lookup_when_uncached():
    roots = {"/e": _dir("r", {"a": _dir("d1", {"b": _dir("d2", {"secret": _file("f", b"TOP")})})})}
    rdr, fake = _reader(roots)
    assert rdr.read_file("/e", "a/b/secret", 1000) == b"TOP"   # no prior list_dir -> lookup per component
    assert [c for c in fake.calls if c[0] == "lookup"]         # lookup fallback exercised


def test_list_dir_per_dir_cap_overflow_detectable():
    kids = {f"f{i}": _file(f"h{i}", b"x") for i in range(5)}
    rdr, _ = _reader({"/e": _dir("r", kids)})
    entries = rdr.list_dir("/e", "", 2)                   # limit 2 -> retain at most 3 (overflow detectable)
    assert len(entries) == 3


def test_read_file_bounded_max_bytes():
    rdr, _ = _reader({"/e": _dir("r", {"big": _file("f", b"A" * 100)})})
    assert rdr.read_file("/e", "big", 10) == b"A" * 10    # stop at the cap, mid-file


def test_nfs_reader_exposes_no_write_verbs():
    for m in ("write", "create", "remove", "mkdir", "rmdir", "setattr", "rename", "put_file"):
        assert not hasattr(_NfsReader, m)


# ========================================================= read-only via the executor
def _cfg(**kw):
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="pw", share_protocol="nfs")
    base.update(kw)
    return ValidationConfig(**base)


def _finding(host=HOST):
    return map_finding({"finding_id": "SH", "host": host, "category": "nfs",
                        "severity": "info", "line": f"nfs exports on {host}"})


def _nctx(cfg, tmp_path, reader, runner):
    ctx = ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    ctx.share_reader_factory = lambda c, host, timeout: reader
    return ctx


def _showmount(stdout):
    return RunResult(returncode=0, stdout=stdout)


def test_read_only_only_read_methods_called_via_executor(tmp_path):
    roots = {"/export": _dir("r", {"f.txt": _file("f1", b"hi"),
                                   "sub": _dir("d", {"g.txt": _file("f2", b"yo")})})}
    reader, fake = _reader(roots)
    runner = _FakeRunner({"showmount": _showmount("Export list for x:\n/export *\n")})
    get_executor("SHARE-LOOT").run(_nctx(_cfg(), tmp_path, reader, runner), _finding())
    assert fake.method_names() <= {"export", "mnt", "umnt", "readdirplus", "lookup",
                                   "read", "disconnect"}   # NO write/create/remove ever


# ===================================================================== loot through NFS
GPP_CPW = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPP_PLAINTEXT = "GPPstillStandingStrong2k18"
GPP_USER = "NORTH\\Jos\u00e9"                             # non-ASCII principal (Jose with acute e)
GROUPS_XML = (f'<?xml version="1.0"?><Groups><User name="x"><Properties userName="{GPP_USER}" '
              f'cpassword="{GPP_CPW}"/></User></Groups>').encode("utf-8")
WEBCONFIG_UTF16 = ('<configuration><connectionStrings><add connectionString='
                   '"Server=db;Password=Pr0d_SqlP@ss1"/></connectionStrings></configuration>'
                   ).encode("utf-16-le")                  # Windows-style UTF-16LE config


def test_utf16_password_detected_through_nfs_reader():
    from purplesploit.validation.executors import loot_rules as lr
    rdr, _ = _reader({"/e": _dir("r", {"web.config": _file("f", WEBCONFIG_UTF16)})})
    data = rdr.read_file("/e", "web.config", 10_000)
    cats = {f.category for f in lr.content_findings(data)}
    assert "db_connection_string" in cats or "password_assignment" in cats


def test_gpp_nonascii_principal_extracted_through_nfs(tmp_path):
    from purplesploit.validation.executors.base import CAP_PASSWORD
    from purplesploit.validation import states as st
    roots = {"/sysvol": _dir("r", {"Groups.xml": _file("f", GROUPS_XML)})}
    reader, _ = _reader(roots)
    runner = _FakeRunner({"showmount": _showmount("Export list for x:\n/sysvol *\n")})
    res = get_executor("SHARE-LOOT").run_composable(
        _nctx(_cfg(), tmp_path, reader, runner), _finding())
    looted = [c for c in res.capabilities if c.state == st.S_LOOTED_CREDS]
    assert looted and looted[0].channel == CAP_PASSWORD
    assert looted[0].value == GPP_PLAINTEXT and looted[0].principal == GPP_USER   # exact non-ASCII
    blob = json.dumps(res.receipt)                        # detection-only receipt: no secret/principal
    assert GPP_PLAINTEXT not in blob and GPP_USER not in blob and GPP_CPW not in blob
    assert res.receipt["terminal_fact"]["loot"]["usable_credentials"] == 1


def test_case_variant_dirs_both_crawled_via_nfs(tmp_path):
    # NFS backing FS is case-SENSITIVE: Admin and admin are distinct dirs; the crawl
    # must descend BOTH (lower-casing the cycle key would drop one -> missed loot).
    roots = {"/e": _dir("r", {
        "Admin": _dir("d1", {"upper.txt": _file("f1", b"U")}),
        "admin": _dir("d2", {"lower.txt": _file("f2", b"L")}),
    })}
    reader, _ = _reader(roots)
    runner = _FakeRunner({"showmount": _showmount("Export list for x:\n/e *\n")})
    res = get_executor("SHARE-LOOT").run(_nctx(_cfg(), tmp_path, reader, runner), _finding())
    store = json.loads(Path(res["terminal_fact"]["store_ref"]).read_text())
    paths = {v["path"] for v in store.values()}
    assert "Admin/upper.txt" in paths and "admin/lower.txt" in paths   # both case variants crawled


# ============================================================ multi-method discovery
def test_nfs_discover_unions_all_methods():
    rdr, _ = _reader({"/export": _dir("r")}, exports=["/export"])
    runner = _FakeRunner({
        "showmount": _showmount("Export list for h:\n/export *\n/home 10.0.0.0/8\n"),
        "nmap": _showmount("PORT\n| nfs-showmount:\n|_  /srv/data *\n"),
        "rpcinfo": _showmount("program vers proto port service\n100003 3 tcp 2049 nfs\n"),
    })
    exports, methods = nfs_discover(runner, rdr, HOST, 30)
    assert set(exports) == {"/export", "/home", "/srv/data"}      # UNION across 3 sources
    ran = {m["method"] for m in methods if m["ran"]}
    assert {"mount.export", "showmount", "nmap.nfs-showmount", "rpcinfo"} <= ran | {
        m["method"] for m in methods}


def test_discovery_recovers_export_showmount_misses():
    # OWNER DIRECTIVE gate: "do not only rely on showmount, it is wrong sometimes".
    # showmount returns a filtered/empty dump; nmap still sees the export -> it is NOT
    # hidden. The single-method parse that WOULD miss it is empty (gate RED proof).
    filtered = "Export list for h:\n"                     # mountd hid every export from us
    assert _parse_showmount(filtered) == []               # single-method => export MISSED (RED)
    rdr, _ = _reader({}, exports=[])                      # programmatic also blind here
    runner = _FakeRunner({
        "showmount": _showmount(filtered),
        "nmap": _showmount("| nfs-showmount:\n|_  /export *\n"),   # independent method sees it
    })
    exports, methods = nfs_discover(runner, rdr, HOST, 30)
    assert "/export" in exports                            # UNION recovers what showmount missed
    nmap = next(m for m in methods if m["method"] == "nmap.nfs-showmount")
    assert nmap["new"] == 1                                # nmap is the method that found it


def test_discovery_degrades_when_cli_tools_absent():
    rdr, _ = _reader({"/export": _dir("r")}, exports=["/export"])
    runner = _FakeRunner({})                               # no showmount / nmap / rpcinfo binaries
    exports, methods = nfs_discover(runner, rdr, HOST, 30)
    assert exports == ["/export"]                          # programmatic export still succeeds
    absent = {m["method"] for m in methods if not m["ran"]}
    assert {"showmount", "nmap.nfs-showmount", "rpcinfo"} <= absent


def test_rpcinfo_liveness_flag():
    rdr, _ = _reader({}, exports=[])
    runner = _FakeRunner({"rpcinfo": _showmount("100003 3 tcp 2049 nfs\n100005 3 udp 635 mountd\n")})
    _, methods = nfs_discover(runner, rdr, HOST, 30)
    rpc = next(m for m in methods if m["method"] == "rpcinfo")
    assert rpc["ran"] is True and rpc.get("nfs_up") is True


def test_parse_helpers():
    assert _parse_showmount("Export list for h:\n/export *\n/srv/x 10.0.0.0/8\n") == ["/export", "/srv/x"]
    assert _parse_showmount("Export list for h:\n") == []
    assert _parse_nmap_showmount("| nfs-showmount:\n|_  /export *\n|   /home *\n") == ["/export", "/home"]
    assert _rpcinfo_shows_nfs("100003 3 tcp 2049 nfs") is True
    assert _rpcinfo_shows_nfs("111 portmapper") is False


# ================================================================ executor integration
def test_executor_protocol_nfs_end_to_end(tmp_path):
    roots = {"/export": _dir("r", {
        "home": _dir("d1", {"svc": _dir("d2", {"id_rsa": _file(
            "f1", b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")})}),
        "readme.txt": _file("f2", b"nothing here"),
    })}
    reader, _ = _reader(roots)
    runner = _FakeRunner({
        "showmount": _showmount("Export list for h:\n/export *\n"),
        "rpcinfo": _showmount("100003 3 tcp 2049 nfs\n"),
    })
    res = get_executor("SHARE-LOOT").run(_nctx(_cfg(), tmp_path, reader, runner), _finding())
    tf = res["terminal_fact"]
    assert tf["kind"] == "share_inventory" and tf["ok"] is True
    assert tf["protocol"] == "nfs"
    assert tf["discovery"] and tf["discovery"][0]["methods"]          # multi-method recorded
    assert "nfs" in tf["predicate"].lower()
    assert any(f == "ssh_private_key" for f in tf["loot"]["by_category"])
    blob = json.dumps(res)
    assert "id_rsa" not in blob and "/export/home" not in blob        # raw paths opaque in the receipt
    store_ref = Path(tf["store_ref"])
    assert oct(store_ref.stat().st_mode & 0o777) == "0o600"           # operator store locked down


def test_config_rejects_unknown_protocol():
    with pytest.raises(ValueError):
        ValidationConfig(domain="d", dc_ip="1.2.3.4", share_protocol="ftp")


def test_default_protocol_is_smb():
    assert ValidationConfig(domain="d", dc_ip="1.2.3.4").share_protocol == "smb"
