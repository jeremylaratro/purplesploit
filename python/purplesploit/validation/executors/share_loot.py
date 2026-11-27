"""SHARE-LOOT validation executor -- S1: SMB share discovery + read-only crawl.

The first joint Windows/Linux module (S1 = SMB; NFS = S2). READ-ONLY by
construction, injection-safe by construction, secret-safe by construction:

- **Discovery + crawl use a PROGRAMMATIC SMB client** (impacket ``SMBConnection``)
  through a narrow read-only interface (:class:`ShareReader`: ``list_shares`` /
  ``list_dir`` / ``close`` only). There is NO ``smbclient -c`` command string, so
  no shell / command-parser injection (plan review r1 #2); and no local mount /
  ``os.walk``, so no TOCTOU / symlink-escape (r2 #2/#3 -- those are the DEFERRED
  mount mode, S1b).
- **Opaque location IDs** (r1 #5): a file/dir path can CONTAIN a secret, so a raw
  path NEVER enters a receipt. Each crawled path gets ``loc:<rand>``; the raw
  ``id -> {host,share,path,size,...}`` map goes ONLY to the operator's out-of-band
  store. Share NAMES (the SMB access-control catalog, admin-defined) are reported
  as the justified safe-name policy the review allowed.
- **Bounds enforced DURING traversal** (r2 #4): depth, total entries, files, shares,
  and a whole-run wall-clock deadline -- a bound hit yields an explicit ``partial``
  outcome, never a silent truncation. A ``(share, path)`` visited-set breaks cycles.
- **Exhaustiveness** (r1 #7): per-host/share outcome (``listed`` / ``denied`` /
  ``unreachable`` / ``truncated``); *observed access* is separate from *coverage
  completeness* -- a mixed/bounded run is ``complete=False`` (partial).

Terminal: ``share_inventory`` (ok = at least one share listed read-only). This is a
DISCOVERY result, never a credential capability. ``mutating=False``; no rollback.
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
from .base import (ValidationExecutor, ExecutorContext, StepRecord)


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

    def list_dir(self, share: str, path: str) -> list[_Entry]:  # pragma: no cover
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

    def list_dir(self, share: str, path: str) -> list[_Entry]:
        spec = (path.rstrip("/\\") + "/*") if path not in ("", "/", "\\") else "*"
        out: list[_Entry] = []
        for f in self._c.listPath(share, spec):
            n = f.get_longname()
            if n in (".", ".."):
                continue
            out.append(_Entry(n, f.is_directory() != 0, f.get_filesize()))
        return out

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
    eff = frozenset()                             # discovery, not an escalation state
    recipe_ref = ("SHARE-LOOT S1 = impacket SMBConnection listShares + recursive listPath "
                  "(read-only, bounded, opaque location IDs); inventory receipt")

    # Test seam: ``(cfg, host, timeout) -> ShareReader``. Overridden via
    # ``ctx.share_reader_factory`` in tests; defaults to the impacket reader.
    reader_factory = staticmethod(_impacket_reader)

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
        return ["impacket SMBConnection.listShares() per host (read-only)",
                "recursive listPath() with bounds -> opaque-ID inventory (no content fetched)",
                "raw path map -> operator out-of-band store; receipt carries opaque IDs only"]

    # --------------------------------------------------------------- scope
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

        # mount mode is DEFERRED (S1b) -- fail closed, never a fabricated result.
        mode = getattr(cfg, "share_access_mode", "crawl")
        if mode != "crawl":
            errors.append("inconclusive:mount_mode_deferred")
            rec("access_mode", False, f"mode={mode} deferred to S1b (crawl only in S1)")
            return self._artifact(steps, gate, None, False, errors)

        hosts = self._hosts(ctx, finding, params)
        if not hosts:
            errors.append("no_target_hosts")
            return self._artifact(steps, gate, None, False, errors)

        factory: Callable = getattr(ctx, "share_reader_factory", None) or type(self).reader_factory
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        store_dir = Path(getattr(cfg, "loot_store_dir", None) or (out_dir / "loot-store"))
        store_dir.mkdir(parents=True, exist_ok=True)

        crawler = _Crawler(cfg)
        per_share: list[dict] = []
        any_listed = False
        for host in hosts:
            reader = None
            try:
                reader = factory(cfg, host, cfg.tool_timeout_s)
            except Exception as exc:
                ctx._private_errors.append(f"{host}: {exc}")
                per_share.append({"host": host, "share": None, "outcome": "unreachable"})
                rec("connect", False, f"{host}: unreachable")
                continue
            try:
                try:
                    shares = reader.list_shares()[: cfg.share_max_shares]
                except Exception as exc:
                    ctx._private_errors.append(f"{host} list_shares: {exc}")
                    per_share.append({"host": host, "share": None, "outcome": "denied"})
                    rec("list_shares", False, f"{host}: share enum denied")
                    continue
                rec("list_shares", True, f"{host}: {len(shares)} shares")
                for share in shares:
                    outcome = crawler.crawl_share(reader, host, share)
                    per_share.append(outcome)
                    if outcome["outcome"] in ("listed", "truncated"):
                        any_listed = True
            finally:
                if reader is not None:
                    reader.close()

        # Persist the raw opaque-ID -> path map to the OPERATOR store ONLY.
        store_ref = store_dir / f"share-loot-{secrets.token_hex(6)}.json"
        try:
            store_ref.write_text(json.dumps(crawler.locmap, indent=2))
            os.chmod(store_ref, 0o600)
        except OSError as exc:
            ctx._private_errors.append(f"store write: {exc}")
            errors.append("loot_store_unwritable")

        coverage = crawler.coverage(per_share)
        complete = coverage["complete"] and any_listed
        if coverage["truncated"]:
            errors.append("partial:bounds_reached")
        if coverage["deadline_hit"]:
            errors.append("partial:deadline")

        terminal = proof.build_terminal_fact(
            self.terminal_kind, ok=any_listed,
            predicate=(f"read-only SMB share discovery + crawl over {len(hosts)} host(s); "
                       f"{coverage['files']} files / {coverage['dirs']} dirs inventoried "
                       f"({'complete' if complete else 'partial'})"),
            proof_token=proof.proof_token("SHARE-LOOT", cfg.domain, ",".join(sorted(hosts)),
                                          "listed" if any_listed else "none"),
            extra={
                "coverage": coverage,
                # per-share: host + SHARE NAME (public catalog) + outcome + public counts.
                # NO raw file/dir paths -- those live only as opaque IDs in the store.
                "per_share": per_share,
                "store_ref": str(store_ref),      # operator's own path to the raw map
                "access_mode": "crawl",
            },
        )
        # terminal `ok` reflects OBSERVED ACCESS (any share listed); the receipt's
        # `complete` reflects COVERAGE COMPLETENESS (nothing truncated/denied) -- a
        # bounded or mixed run is complete=False even though access was observed.
        return self._artifact(steps, gate, terminal, bool(complete), errors)

    def produced(self, ctx, finding, params, artifact) -> list:
        # Discovery produces NO credential/capability (review r1 #6).
        return []

    @staticmethod
    def _artifact(steps, gate, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "verified": True, "method": None}},
                "terminal_fact": terminal_fact, "complete": complete, "errors": errors}


# ------------------------------------------------------------------- the crawler
class _Crawler:
    """Bounded, cycle-safe recursive lister. Enforces every bound DURING traversal
    (not after), tracks opaque location IDs, and records per-share outcomes."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.locmap: dict[str, dict] = {}
        self.files = 0
        self.dirs = 0
        self.entries = 0
        self.deadline = time.monotonic() + max(0, int(getattr(cfg, "share_crawl_deadline_s", 300)))
        self.deadline_hit = False
        self.truncated = False

    def _over_budget(self) -> bool:
        if time.monotonic() >= self.deadline:
            self.deadline_hit = True
            return True
        if self.entries >= self.cfg.share_max_entries or self.files >= self.cfg.share_max_files:
            self.truncated = True
            return True
        return False

    def _loc(self, host, share, path, is_dir, size) -> str:
        lid = "loc:" + secrets.token_hex(8)
        self.locmap[lid] = {"host": host, "share": share, "path": path,
                            "is_dir": bool(is_dir), "size": int(size or 0)}
        return lid

    def crawl_share(self, reader: ShareReader, host: str, share: str) -> dict:
        res = {"host": host, "share": share, "outcome": "listed",
               "files": 0, "dirs": 0, "bytes": 0}
        if self._over_budget():
            res["outcome"] = "truncated"
            return res
        visited: set = set()
        stack: list[tuple[str, int]] = [("", 0)]        # (path, depth)
        listed_any = False
        try:
            while stack:
                if self._over_budget():
                    res["outcome"] = "truncated"
                    break
                path, depth = stack.pop()
                key = path.strip("/\\").lower()
                if key in visited:
                    continue                            # cycle / repeat guard
                visited.add(key)
                try:
                    entries = reader.list_dir(share, path)
                except Exception:
                    # a denied/failed subdir doesn't fail the whole share
                    if not listed_any and not path:
                        res["outcome"] = "denied"
                    continue
                listed_any = True
                for e in entries:
                    self.entries += 1
                    if self._over_budget():
                        res["outcome"] = "truncated"
                        break
                    child = (path.rstrip("/\\") + "/" + e.name) if path else e.name
                    self._loc(host, share, child, e.is_dir, e.size)
                    if e.is_dir:
                        self.dirs += 1
                        res["dirs"] += 1
                        if depth + 1 <= self.cfg.share_max_depth:
                            stack.append((child, depth + 1))
                        else:
                            self.truncated = True
                            res["outcome"] = "truncated"
                    else:
                        self.files += 1
                        res["files"] += 1
                        res["bytes"] += int(e.size or 0)
        except Exception:
            if not listed_any:
                res["outcome"] = "denied"
        return res

    def coverage(self, per_share: list[dict]) -> dict:
        outcomes = [p["outcome"] for p in per_share]
        return {
            "hosts": len({p["host"] for p in per_share}),
            "shares_total": sum(1 for p in per_share if p.get("share") is not None),
            "shares_listed": outcomes.count("listed"),
            "shares_denied": outcomes.count("denied"),
            "shares_unreachable": outcomes.count("unreachable"),
            "shares_truncated": outcomes.count("truncated"),
            "files": self.files, "dirs": self.dirs, "entries_visited": self.entries,
            "truncated": self.truncated, "deadline_hit": self.deadline_hit,
            # coverage is COMPLETE only if nothing was truncated/deadlined and no
            # share was denied/unreachable (observed access != full coverage).
            "complete": (not self.truncated and not self.deadline_hit
                         and outcomes.count("denied") == 0
                         and outcomes.count("unreachable") == 0
                         and outcomes.count("truncated") == 0),
        }
