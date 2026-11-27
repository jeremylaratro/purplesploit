"""SHARE-LOOT validation executor -- SMB (S1) + NFS (S2) share discovery + crawl.

The first joint Windows/Linux module (S1 = SMB; S2 = NFS). The crawl + loot engine
below is transport-agnostic (``_Crawler`` / ``loot_rules``); the transport is chosen
by ``config.share_protocol`` and only discovery + the read-only reader differ (SMB:
impacket here; NFS: :mod:`nfs_reader`). READ-ONLY by construction, injection-safe by
construction, secret-safe by construction:

- **Discovery + crawl use a PROGRAMMATIC client** -- impacket ``SMBConnection`` (SMB)
  or pyNfsClient NFSv3 (NFS) -- through a narrow read-only interface
  (:class:`ShareReader`: ``list_shares`` / ``list_dir`` / ``read_file`` / ``close``
  only). There is NO ``smbclient -c`` command string, so no shell / command-parser
  injection (plan review r1 #2); and no local mount / ``os.walk``, so no TOCTOU /
  symlink-escape (r2 #2/#3 -- that is the DEFERRED mount mode, S1b). NFS export
  discovery is MULTI-METHOD (programmatic + showmount + nmap + rpcinfo), each CLI
  method an argv list (no shell string), so showmount alone cannot hide an export.
- **Opaque location IDs** (r1 #5): a file/dir path can CONTAIN a secret, so a raw
  path NEVER enters a receipt. Each crawled path gets ``loc:<rand>``; the raw
  ``id -> {host,share,path,size,...}`` map goes ONLY to the operator's out-of-band
  store (created ``O_EXCL`` mode ``0600``). Share NAMES (the SMB access-control
  catalog) are the justified safe-name policy the review allowed.
- **Bounds enforced DURING traversal** (r2 #4): a per-directory retained-entry cap,
  total entries / files / shares, max depth, and a whole-run wall-clock deadline
  checked before EVERY network op -- a bound hit yields an explicit ``partial``
  outcome, never a silent truncation. A ``(share, path)`` visited-set breaks cycles.
- **Honest, exhaustive coverage** (r1 #7, S1-review): per-host/share outcome
  (``listed`` fully / ``partial`` / ``denied`` / ``unreachable`` / ``not_crawled``);
  a denied SUBTREE or an omitted share makes coverage incomplete; terminal ``ok``
  (observed access) is True ONLY when a directory was actually listed -- a budget
  that expired before the first listing is NOT a success.

Terminal: ``share_inventory`` (ok = at least one directory listed read-only). A
DISCOVERY result, never a credential capability. ``mutating=False``; no rollback.

Known residual (documented): impacket ``listPath`` materializes one directory's
entries as a list before returning; a per-directory cap bounds what is RETAINED,
and the whole-run deadline bounds wall-clock, but a single pathologically huge
directory's transient listing is bounded by the deadline rather than streamed. A
paged-listing follow-up is tracked (S1b).
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Optional

from ..recommend import ParamSpec, ParamValue, values
from .. import proof, states
from . import loot_rules, nfs_reader
from .base import (ValidationExecutor, ExecutorContext, StepRecord, Capability, CAP_PASSWORD)


# ------------------------------------------------------------ read-only SMB reader
class _Entry:
    __slots__ = ("name", "is_dir", "size")

    def __init__(self, name: str, is_dir: bool, size: int):
        self.name, self.is_dir, self.size = name, bool(is_dir), int(size or 0)


class ShareReader:
    """The NARROW read-only SMB interface the executor is allowed to use. Exposes
    ONLY enumeration + listing -- never a write/delete/mkdir -- so the read-only
    invariant holds by construction (the executor cannot mutate a share)."""

    def list_shares(self) -> list[str]:            # pragma: no cover - interface
        raise NotImplementedError

    def list_dir(self, share: str, path: str, limit: int) -> list[_Entry]:  # pragma: no cover
        raise NotImplementedError

    def read_file(self, share: str, path: str, max_bytes: int) -> bytes:  # pragma: no cover
        """Read AT MOST ``max_bytes`` of a file (stop mid-file at the cap). Read-only."""
        raise NotImplementedError

    def close(self) -> None:                       # pragma: no cover - interface
        raise NotImplementedError


class _ImpacketReader(ShareReader):
    """``ShareReader`` over an impacket ``SMBConnection`` -- read ops only."""

    def __init__(self, conn):
        self._c = conn

    def list_shares(self) -> list[str]:
        out: list[str] = []
        for s in self._c.listShares():
            name = s["shi1_netname"]
            name = name[:-1] if name.endswith("\x00") else name
            out.append(name)
        return out

    def list_dir(self, share: str, path: str, limit: int) -> list[_Entry]:
        spec = (path.rstrip("/\\") + "/*") if path not in ("", "/", "\\") else "*"
        out: list[_Entry] = []
        for f in self._c.listPath(share, spec):
            n = f.get_longname()
            if n in (".", ".."):
                continue
            out.append(_Entry(n, f.is_directory() != 0, f.get_filesize()))
            if len(out) > max(0, int(limit)):      # retain at most limit+1 (overflow detectable)
                break
        return out

    def read_file(self, share: str, path: str, max_bytes: int) -> bytes:
        cap = max(0, int(max_bytes))
        buf = bytearray()

        class _Stop(Exception):
            pass

        def _cb(data: bytes):
            buf.extend(data)
            if len(buf) >= cap:
                raise _Stop()                      # bounded: stop mid-file at the cap

        try:
            self._c.getFile(share, path.replace("/", "\\"), _cb)   # read-only transfer
        except _Stop:
            pass
        except Exception:
            return b""
        return bytes(buf[:cap])

    def close(self) -> None:
        try:
            self._c.close()
        except Exception:
            pass


def _impacket_reader(cfg, host: str, timeout: int) -> ShareReader:
    """Default factory: a read-only impacket SMB session to ``host`` (password or
    NT-hash auth from ``cfg``). Imported lazily so the module loads without
    impacket (tests inject a fake reader)."""
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(host, host, sess_port=445, timeout=timeout)
    lm = nt = ""
    if getattr(cfg, "nt_hash", None):
        parts = cfg.nt_hash.split(":")
        nt = parts[-1]
        lm = parts[0] if len(parts) > 1 and parts[0] else "aad3b435b51404eeaad3b435b51404ee"
    conn.login(cfg.username or "", "" if nt else (cfg.password or ""),
               cfg.domain or "", lm, nt)
    return _ImpacketReader(conn)


# ------------------------------------------------------------------- the executor
class ShareLootExecutor(ValidationExecutor):
    technique = "SHARE-LOOT"
    technique_class = "share_loot"
    terminal_kind = "share_inventory"
    mutating = False
    verified_recipe = False                       # until lab-proven on an owned share
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_LOOTED_CREDS})      # S4: may produce usable looted credentials
    recipe_ref = ("SHARE-LOOT = SMB (impacket listShares+listPath) or NFS (pyNfsClient "
                  "multi-method export discovery + readdirplus) -- read-only, bounded, "
                  "opaque IDs + loot search + GPP-cpassword creds")

    reader_factory = staticmethod(_impacket_reader)   # test seam (ctx.share_reader_factory overrides)

    def _default_factory(self, protocol: str) -> Callable:
        """The read-only reader factory for this transport (NFS adds S2)."""
        if protocol == "nfs":
            return nfs_reader.nfs_reader_factory
        return type(self).reader_factory

    def _discover(self, ctx, cfg, protocol, reader, host, crawler, discovery_log) -> list[str]:
        """Enumerate shares/exports. SMB: one programmatic listShares. NFS: the
        multi-method UNION (programmatic export + showmount + nmap + rpcinfo), so a
        single wrong source cannot hide an export (owner directive)."""
        if protocol == "nfs":
            exports, methods = nfs_reader.nfs_discover(
                ctx.runner, reader, host, crawler.op_timeout(cfg.tool_timeout_s))
            discovery_log.append({"host": host, "methods": methods})
            return exports
        return reader.list_shares()

    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        e = finding.entity or {}
        return [
            ParamSpec(name="hosts", kind="free",
                      description="Comma-separated hosts to enumerate SMB shares on "
                                  "(defaults to the finding host + configured extra targets).",
                      recommended=e.get("hosts") or finding.host or "",
                      rationale="Scope of the share discovery.", required=False),
        ]

    def target_identity(self, ctx, finding, params) -> dict[str, Any]:
        host = finding.host or ""
        return dict(ctx.config.resolve_target_identity(host)) if host else dict(finding.entity)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        if getattr(ctx.config, "share_protocol", "smb") == "nfs":
            return ["multi-method NFS export discovery (Mount.export + showmount + nmap + rpcinfo)",
                    "pyNfsClient readdirplus/lookup/read crawl with bounds -> opaque-ID inventory",
                    "raw path map -> operator out-of-band store; receipt carries opaque IDs only"]
        return ["impacket SMBConnection.listShares() per host (read-only)",
                "recursive listPath() with bounds -> opaque-ID inventory (no content fetched)",
                "raw path map -> operator out-of-band store; receipt carries opaque IDs only"]

    def _hosts(self, ctx, finding, params) -> list[str]:
        v = values(params)
        raw = (v.get("hosts") or "").strip()
        hosts = [h.strip() for h in raw.split(",") if h.strip()] if raw else []
        if not hosts and finding.host:
            hosts = [finding.host]
        for t in (getattr(ctx.config, "extra_targets", None) or []):
            if t and t not in hosts:
                hosts.append(t)
        return hosts

    # --------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params) -> dict:
        cfg = ctx.config
        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}

        def rec(name, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=[], returncode=None, note=note))

        mode = getattr(cfg, "share_access_mode", "crawl")
        if mode != "crawl":                       # mount mode DEFERRED (S1b) -- fail closed
            errors.append("inconclusive:mount_mode_deferred")
            rec("access_mode", False, f"mode={mode} deferred to S1b (crawl only in S1)")
            return self._artifact(steps, gate, None, False, errors)

        hosts = self._hosts(ctx, finding, params)
        if not hosts:
            errors.append("no_target_hosts")
            return self._artifact(steps, gate, None, False, errors)

        protocol = getattr(cfg, "share_protocol", "smb")
        discovery_log: list[dict] = []
        factory: Callable = (getattr(ctx, "share_reader_factory", None)
                             or self._default_factory(protocol))
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        store_dir = Path(getattr(cfg, "loot_store_dir", None) or (out_dir / "loot-store"))
        store_dir.mkdir(parents=True, exist_ok=True)

        crawler = _Crawler(cfg)
        per_share: list[dict] = []
        hosts_skipped = 0
        for host in hosts:
            if crawler.past_deadline():            # deadline bounds network work (r2 #2) -- stop connecting
                hosts_skipped += 1
                per_share.append({"host": host, "share": None, "outcome": "not_crawled"})
                continue
            reader = None
            try:
                reader = factory(cfg, host, crawler.op_timeout(cfg.tool_timeout_s))
            except Exception as exc:
                ctx._private_errors.append(f"{host}: {exc}")
                per_share.append({"host": host, "share": None, "outcome": "unreachable"})
                rec("connect", False, f"{host}: unreachable")
                continue
            try:
                if crawler.past_deadline():
                    per_share.append({"host": host, "share": None, "outcome": "not_crawled"})
                    continue
                try:
                    all_shares = self._discover(ctx, cfg, protocol, reader, host,
                                                crawler, discovery_log)
                except Exception as exc:
                    ctx._private_errors.append(f"{host} list_shares: {exc}")
                    per_share.append({"host": host, "share": None, "outcome": "denied"})
                    rec("list_shares", False, f"{host}: share enum denied")
                    continue
                shares = all_shares[: cfg.share_max_shares]
                if len(all_shares) > len(shares):          # share cap omitted some (r1-review #4)
                    crawler.shares_omitted += len(all_shares) - len(shares)
                rec("list_shares", True, f"{host}: {len(all_shares)} shares"
                    + (f" ({crawler.shares_omitted} over cap)" if crawler.shares_omitted else ""))
                for share in shares:
                    per_share.append(crawler.crawl_share(reader, host, share))
            finally:
                if reader is not None:
                    reader.close()

        # Persist the raw opaque-ID -> path map to the OPERATOR store ONLY, created
        # EXCLUSIVELY with mode 0600 (no 0644 window -- r1-review #6).
        store_ref = store_dir / f"share-loot-{secrets.token_hex(6)}.json"
        try:
            fd = os.open(str(store_ref), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(crawler.store, fh, indent=2)   # raw paths + loot detail (values) -> operator only
        except OSError as exc:
            ctx._private_errors.append(f"store write: {exc}")
            errors.append("loot_store_unwritable")

        coverage = crawler.coverage(per_share, hosts_skipped)
        any_listed = crawler.any_dir_listed            # OBSERVED ACCESS = a real listing (r1-review #5)
        # The receipt `complete` means the EDGE DID ITS JOB (observed access), so a
        # bounded/partial crawl still yields its loot + produced capabilities. EXHAUSTIVE
        # COVERAGE is a separate dimension: coverage["complete"] + the partial:* errors
        # (the edge never CLAIMS exhaustive coverage when it is partial).
        complete = bool(any_listed)
        if coverage["truncated"]:
            errors.append("partial:bounds_reached")
        if coverage["deadline_hit"]:
            errors.append("partial:deadline")
        if coverage["shares_omitted"]:
            errors.append("partial:share_cap")
        if coverage["incomplete_subtrees"]:
            errors.append("partial:subtree_denied")

        terminal = proof.build_terminal_fact(
            self.terminal_kind, ok=bool(any_listed),
            predicate=(f"read-only {protocol.upper()} share discovery + crawl over "
                       f"{len(hosts)} host(s); {coverage['files']} files / "
                       f"{coverage['dirs']} dirs inventoried "
                       f"({'complete' if complete else 'partial'})"),
            proof_token=proof.proof_token("SHARE-LOOT", cfg.domain, ",".join(sorted(hosts)),
                                          "listed" if any_listed else "none"),
            extra={"coverage": coverage, "per_share": per_share,
                   "store_ref": str(store_ref), "access_mode": "crawl",
                   "protocol": protocol, "discovery": discovery_log,
                   # LOOT summary: PRESENCE + CATEGORY + opaque loc_ids only. No
                   # values, no raw paths -- the loot itself is in the operator store.
                   "loot": {"findings": crawler.loot_findings,
                            "by_category": crawler.loot_by_category,
                            "fetched_files": crawler.fetched_files,
                            # PRESENCE count only -- the (principal, secret) pairs are in
                            # the operator store + the in-memory capability, never here.
                            "usable_credentials": len(crawler.usable_creds),
                            "hits": crawler.loot_hits[:200]}},
        )
        art = self._artifact(steps, gate, terminal, bool(complete), errors)
        art["_usable_creds"] = crawler.usable_creds    # engine-only (dropped by _receipt_from)
        return art

    def produced(self, ctx, finding, params, artifact) -> list:
        """S4: a usable looted credential (GPP cpassword decrypt) becomes an in-memory
        SECRET capability the engine can thread to a downstream edge (looted cred ->
        pivot). Never serialized; the receipt carries only a presence count."""
        caps = []
        for c in artifact.get("_usable_creds", []):
            if c.get("secret") and c.get("principal"):
                caps.append(Capability(state=states.S_LOOTED_CREDS, channel=CAP_PASSWORD,
                                       value=c["secret"], principal=c["principal"]))
        return caps

    @staticmethod
    def _artifact(steps, gate, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "verified": True, "method": None}},
                "terminal_fact": terminal_fact, "complete": complete, "errors": errors}


# ------------------------------------------------------------------- the crawler
class _Crawler:
    """Bounded, cycle-safe recursive lister. Every bound is enforced DURING
    traversal (before each network op), outcomes distinguish full/partial/denied,
    and observed access (`any_dir_listed`) is tracked separately from truncation."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.store: dict[str, dict] = {}          # operator out-of-band map: loc_id -> {path,...,findings}
        self.files = 0
        self.dirs = 0
        self.entries = 0
        self.deadline = time.monotonic() + max(0, int(getattr(cfg, "share_crawl_deadline_s", 300)))
        self.deadline_hit = False
        self.truncated = False
        self.any_dir_listed = False
        self.shares_omitted = 0
        # S3 loot
        self.loot_findings = 0
        self.loot_by_category: dict[str, int] = {}
        self.loot_hits: list[str] = []            # opaque loc_ids with findings (receipt-safe)
        self.fetched_files = 0
        self.fetched_bytes = 0
        self.usable_creds: list[dict] = []        # S4: {principal,secret,source,loc} -- in-memory/store only

    def past_deadline(self) -> bool:
        if time.monotonic() >= self.deadline:
            self.deadline_hit = True
            return True
        return False

    def op_timeout(self, default: int) -> int:
        """Bound a single blocking op's timeout to the REMAINING wall-clock budget
        (capped by ``default``), so one slow network op cannot overrun the whole-run
        deadline (S1-review r2 #2)."""
        remaining = int(self.deadline - time.monotonic())
        return max(1, min(int(default), remaining)) if remaining > 0 else 1

    def _over_budget(self) -> bool:
        if self.past_deadline():
            return True
        if self.entries >= self.cfg.share_max_entries or self.files >= self.cfg.share_max_files:
            self.truncated = True
            return True
        return False

    def _loc(self, host, share, path, is_dir, size) -> str:
        lid = "loc:" + secrets.token_hex(8)
        self.store[lid] = {"host": host, "share": share, "path": path,
                           "is_dir": bool(is_dir), "size": int(size or 0)}
        return lid

    def _loot_file(self, reader: ShareReader, share: str, path: str, size: int, lid: str) -> None:
        """Scan a crawled FILE for loot: filename rules always; fetch + content rules
        when worthwhile and within the fetch budget + deadline. Findings-with-detail
        (possible secret context) go to the STORE entry (operator), never a receipt;
        only public category counts + the opaque loc_id surface in the receipt."""
        if not getattr(self.cfg, "loot_enabled", True):
            return
        findings = loot_rules.filename_findings(path)
        if (loot_rules.should_fetch(path, size, self.cfg.loot_max_file_bytes)
                and self.fetched_files < self.cfg.loot_max_fetch_files
                and self.fetched_bytes < self.cfg.loot_max_fetch_bytes_total
                and not self.past_deadline()):
            cap = min(self.cfg.loot_max_file_bytes,
                      self.cfg.loot_max_fetch_bytes_total - self.fetched_bytes)
            try:
                data = reader.read_file(share, path, cap)
            except Exception:
                data = b""
            self.fetched_files += 1
            self.fetched_bytes += len(data)
            findings += loot_rules.content_findings(data)
            # S4: extract USABLE (principal, secret) credentials (GPP cpassword decrypt).
            for cred in loot_rules.extract_credentials(path, data):
                self.usable_creds.append({"principal": cred.principal, "secret": cred.secret,
                                          "source": cred.source, "loc": lid})
                self.store[lid].setdefault("credentials", []).append(
                    {"principal": cred.principal, "secret": cred.secret, "source": cred.source})
        if findings:
            self.store[lid]["findings"] = [{"category": f.category, "match_type": f.match_type,
                                            "detail": f.detail} for f in findings]
            self.loot_findings += len(findings)
            self.loot_hits.append(lid)
            for f in findings:
                self.loot_by_category[f.category] = self.loot_by_category.get(f.category, 0) + 1

    def crawl_share(self, reader: ShareReader, host: str, share: str) -> dict:
        res = {"host": host, "share": share, "outcome": "listed",
               "files": 0, "dirs": 0, "bytes": 0}
        if self._over_budget():                        # budget spent BEFORE this share -> no access
            res["outcome"] = "not_crawled"
            return res
        visited: set = set()
        stack: list[tuple[str, int]] = [("", 0)]
        root_ok = False
        incomplete = False                             # a denied subtree / bound hit here
        while stack:
            if self._over_budget():
                incomplete = True
                break
            path, depth = stack.pop()
            # Cycle guard keyed on the EXACT path (NOT lower-cased): a case-SENSITIVE
            # backing FS (Linux Samba/NFS) has distinct "Admin" vs "admin" dirs that
            # lower-casing would collapse -> skipping real directories / missing loot.
            # The depth/entry/deadline caps backstop any case-variant loop on Windows.
            key = path.strip("/\\")
            if key in visited:
                continue
            visited.add(key)
            remaining = max(0, self.cfg.share_max_entries - self.entries)
            try:
                entries = reader.list_dir(share, path, remaining)
            except Exception:
                if path == "" and not root_ok:
                    res["outcome"] = "denied"          # root unreadable -> whole share denied
                    return res
                incomplete = True                      # a child subtree is denied -> partial (r1-review #3)
                continue
            if path == "":
                root_ok = True
            self.any_dir_listed = True                 # a REAL listing happened (observed access)
            if self.past_deadline():                   # the listing itself may have OVERRUN (r2 #2)
                incomplete = True
                break
            if len(entries) > remaining:               # per-dir cap overflowed -> partial (r1-review #1)
                entries = entries[:remaining]
                incomplete = True
                self.truncated = True
            for e in entries:
                if self._over_budget():
                    incomplete = True
                    break
                self.entries += 1
                child = (path.rstrip("/\\") + "/" + e.name) if path else e.name
                lid = self._loc(host, share, child, e.is_dir, e.size)
                if e.is_dir:
                    self.dirs += 1
                    res["dirs"] += 1
                    if depth + 1 <= self.cfg.share_max_depth:
                        stack.append((child, depth + 1))
                    else:
                        incomplete = True
                        self.truncated = True
                else:
                    self.files += 1
                    res["files"] += 1
                    res["bytes"] += int(e.size or 0)
                    self._loot_file(reader, share, child, e.size, lid)    # S3 loot scan
        if res["outcome"] == "listed" and incomplete:
            res["outcome"] = "partial"                 # listed something but not fully covered
        return res

    def coverage(self, per_share: list[dict], hosts_skipped: int) -> dict:
        outcomes = [p["outcome"] for p in per_share]
        incomplete_subtrees = outcomes.count("partial")
        # coverage is COMPLETE only when nothing was truncated/deadlined, no share was
        # omitted by the cap, no host was skipped, and EVERY share fully listed (a
        # denied/unreachable/not_crawled/partial share makes it incomplete).
        complete = (not self.truncated and not self.deadline_hit and self.shares_omitted == 0
                    and hosts_skipped == 0 and bool(outcomes)
                    and all(o == "listed" for o in outcomes))
        return {
            "hosts": len({p["host"] for p in per_share}),
            "shares_total": sum(1 for p in per_share if p.get("share") is not None),
            "shares_listed": outcomes.count("listed"),
            "shares_partial": incomplete_subtrees,
            "shares_denied": outcomes.count("denied"),
            "shares_unreachable": outcomes.count("unreachable"),
            "shares_not_crawled": outcomes.count("not_crawled"),
            "shares_omitted": self.shares_omitted,
            "hosts_skipped_deadline": hosts_skipped,
            "files": self.files, "dirs": self.dirs, "entries_visited": self.entries,
            "truncated": self.truncated, "deadline_hit": self.deadline_hit,
            "incomplete_subtrees": incomplete_subtrees,
            "complete": complete,
        }
