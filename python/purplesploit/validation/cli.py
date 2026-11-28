"""Individual dispatch, automatic composition, or the enumeration pipeline.

Legacy invocations without a subcommand continue to select ``pipeline``.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Optional

from .config import ValidationConfig
from .orchestrator import (ValidationOrchestrator, ConfirmationProvider, Choice,
                           AutoConfirm)
from .executors import is_implemented, get_executor, IMPLEMENTED
from .executors.base import ValidationPlan
from .inputs import finding_from_inputs, InputError
from .engine import da_in_minutes, default_edges
from . import states, proof
from .orchestrator import ValidationOutcome
from .reveal_sink import reveal_to_terminal


def _display_reveals(executor, artifact):
    """CLI-only channel; neither the artifact nor reveals enter a report."""
    reveals = executor.revealed_secrets(artifact)
    if reveals:
        reveal_to_terminal(reveals)


class InteractivePrompt(ConfirmationProvider):
    """Prompt the operator per issue: validate? and override any parameter."""

    def __init__(self, stream=sys.stdin, out=sys.stdout):
        self.stream = stream
        self.out = out

    def _ask(self, prompt: str) -> str:
        self.out.write(prompt)
        self.out.flush()
        return (self.stream.readline() or "").strip()

    def confirm(self, plan: ValidationPlan) -> Choice:
        tag = "" if is_implemented(plan.technique) else " [STUB - not wired]"
        verified = "verified" if plan.verified_recipe else "UNVERIFIED recipe"
        self.out.write(f"\n=== {plan.technique} ({plan.technique_class}){tag} ===\n")
        self.out.write(f"  finding : {plan.finding_summary}\n")
        self.out.write(f"  target  : {plan.target}\n")
        self.out.write(f"  recipe  : {verified}; mutating={plan.mutating}; "
                       f"terminal={plan.terminal_kind}\n")
        for step in plan.steps_preview:
            self.out.write(f"    - {step}\n")
        ans = self._ask(f"Validate {plan.technique}? [y/N] ").lower()
        if ans not in ("y", "yes"):
            return Choice(validate=False)
        overrides: dict = {}
        for pv in plan.params.values():
            spec = pv.spec
            warn = f"  (warn: {pv.warning})" if pv.warning else ""
            new = self._ask(f"  {spec.name} [{pv.value}] ({spec.description}){warn}\n"
                            f"    override (enter to keep): ")
            if new:
                overrides[spec.name] = new
        return Choice(validate=True, overrides=overrides)


def _read_key(path: Optional[str]) -> Optional[str]:
    """Read a signing key from a file (so it never appears in argv / ps / a
    preview). The file holds the bare hex key (whitespace stripped)."""
    if not path:
        return None
    return Path(path).read_text().strip() or None


def build_config(args: argparse.Namespace) -> ValidationConfig:
    host_aliases: dict = {}
    if args.host_alias:
        for item in args.host_alias:
            raw, _, hid = item.partition("=")
            if raw and hid:
                host_aliases[raw] = {"host_id": hid}
    kwargs = dict(
        forge_key=_read_key(getattr(args, "forge_key_file", None)),
        forge_key_kind=getattr(args, "forge_key_kind", None),
        forge_key_nt=_read_key(getattr(args, "forge_key_nt_file", None)),
        domain=args.domain, dc_ip=args.dc_ip,
        username=args.user, password=args.password,
        nt_hash=args.hash, aes_key=args.aes_key,
        extra_targets=list(args.target or []),
        output_dir=Path(args.output),
        aranum_bin=args.aranum_bin,
        nmap_input=Path(args.nmap) if args.nmap else None,
        findings_json=Path(args.findings_json) if args.findings_json else None,
        score_proof_cmd=shlex.split(args.score_proof) if args.score_proof else None,
        proof_truth=Path(args.proof_truth) if args.proof_truth else None,
        host_aliases=host_aliases,
        authorized=not args.unauthorized,
        auto_confirm=args.yes,
        tool_timeout_s=args.timeout,
        allow_destructive=args.allow_destructive,
        show_flag=getattr(args, "show_flag", False),
    )
    # SHARE-LOOT knobs: pass through ONLY when the operator set them, so the
    # ValidationConfig defaults stay the single source of truth otherwise.
    sl_map = {"share_protocol": "share_protocol", "share_access_mode": "share_access_mode",
              "loot_store_dir": "loot_store_dir", "share_max_shares": "share_max_shares",
              "share_max_depth": "share_max_depth", "share_max_entries": "share_max_entries",
              "share_max_files": "share_max_files", "share_crawl_deadline": "share_crawl_deadline_s"}
    for arg_name, cfg_name in sl_map.items():
        val = getattr(args, arg_name, None)
        if val is not None:
            kwargs[cfg_name] = val
    if getattr(args, "no_loot", False):
        kwargs["loot_enabled"] = False
    return ValidationConfig(**kwargs)


class DispatchParser(argparse.ArgumentParser):
    def parse_args(self, args=None, namespace=None):
        args = list(sys.argv[1:] if args is None else args)
        # Move an explicit subcommand ahead of shared options. Skip option values
        # so a password/target equal to "run" cannot change the selected mode.
        i = 0
        while i < len(args):
            token = args[i]
            if token in {"pipeline", "run", "chain", "discover"}:
                args.insert(0, args.pop(i))
                break
            if not token.startswith("-"):
                args.insert(0, "pipeline")
                break
            option = token.split("=", 1)[0]
            i += 1 if "=" in token or option in self._switches else 2
        else:
            if args not in (["--help"], ["-h"]):
                args.insert(0, "pipeline")
        return super().parse_args(args, namespace)


def build_parser() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    p = shared
    p.add_argument("--domain", required=True)
    p.add_argument("--dc-ip", required=True)
    p.add_argument("--user")
    p.add_argument("--password")
    p.add_argument("--hash", help="NTLM hash (LM:NT or :NT)")
    p.add_argument("--aes-key")
    p.add_argument("--target", action="append", help="extra target host (repeatable)")
    p.add_argument("--output", default="./validation-run")
    p.add_argument("--aranum-bin", default="aranum")
    p.add_argument("--nmap", help="nmap output file for 'aranum run -i'")
    p.add_argument("--findings-json", help="pre-existing aranum findings.json (skip enum)")
    p.add_argument("--score-proof", help="argv to run adlab.score_proof, e.g. "
                                         "'python3 -m adlab.score_proof'")
    p.add_argument("--proof-truth", help="adlab.plan003.proof-truth.v1 facet JSON")
    p.add_argument("--host-alias", action="append",
                   help="RAW=HOSTID identity mapping for scoring (repeatable), "
                        "e.g. 10.0.0.10=dc01")
    p.add_argument("--unauthorized", action="store_true",
                   help="mark the engagement NOT authorized (gates deny -> fail closed)")
    p.add_argument("--yes", action="store_true",
                   help="accept recommended defaults non-interactively "
                        "(implemented, verified recipes only)")
    p.add_argument("--allow-destructive", action="store_true",
                   help="pre-authorize destructive (irreversible/code-exec) ops "
                        "for a NON-INTERACTIVE (--yes) run; has NO effect on an "
                        "interactive run (which always gets the press-yes prompt "
                        "instead). Still prints a loud warning per op -- never a "
                        "silent bypass.")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--show-flag", action="store_true",
                   help="reveal recovered secrets on /dev/tty only; refuse without "
                        "an interactive terminal (never included in receipts)")
    # T4 ticket forging: the signing key is a SECRET -- supplied via a FILE (never
    # argv/preview). krbtgt key (Golden/Diamond/Sapphire) or service key (Silver).
    p.add_argument("--forge-key-file", help="file holding the hex signing key "
                   "(krbtgt/service) for ticket forging")
    p.add_argument("--forge-key-kind", choices=["aes", "nt"], default="aes",
                   help="how to pass the forge key to ticketer (default aes)")
    p.add_argument("--forge-key-nt-file", help="file holding the krbtgt NT hash "
                   "(Sapphire needs both AES and NT)")
    # SHARE-LOOT (SMB/NFS share discovery + crawl + loot). Defaults track the
    # ValidationConfig defaults; omitted flags leave those untouched.
    sl = p.add_argument_group("SHARE-LOOT (share discovery + loot)")
    sl.add_argument("--share-protocol", choices=["smb", "nfs"],
                    help="share transport (default smb)")
    sl.add_argument("--share-access-mode", choices=["crawl", "mount"],
                    help="crawl=programmatic reads (default); mount=kernel RO mount "
                         "with contained crawl (needs CAP_SYS_ADMIN)")
    sl.add_argument("--loot-store-dir", help="operator out-of-band store for the "
                    "raw path map + recovered values (default <output>/loot-store, 0600)")
    sl.add_argument("--no-loot", action="store_true",
                    help="disable the loot content search (inventory only)")
    sl.add_argument("--share-max-shares", type=int, help="max shares per host (default 64)")
    sl.add_argument("--share-max-depth", type=int, help="max crawl depth (default 12)")
    sl.add_argument("--share-max-entries", type=int, help="max dir entries per run (default 50000)")
    sl.add_argument("--share-max-files", type=int, help="max files inventoried (default 20000)")
    sl.add_argument("--share-crawl-deadline", type=int,
                    help="whole-run crawl wall-clock deadline in seconds (default 300)")
    root = DispatchParser(prog="purplesploit-validate", description=__doc__)
    root._switches = {o for action in shared._actions if action.nargs == 0
                      for o in action.option_strings} | {"-h", "--help"}
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("pipeline", parents=[shared], help="enumerate and validate findings")
    run = commands.add_parser("run", parents=[shared], help="dispatch one technique")
    run.add_argument("technique", choices=sorted(IMPLEMENTED), type=str.upper)
    run.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    discover = commands.add_parser("discover", parents=[shared],
                                   help="probe EVERY technique from the creds+scope; report "
                                        "viability (read-only), optionally auto-exploit the eligible set")
    discover.add_argument("--exploit", action="store_true",
                          help="auto-exploit the eligible techniques (verified + viable + complete + "
                               "non-mutating unless --allow-destructive); discovery alone is read-only")
    chain = commands.add_parser("chain", parents=[shared], help="compose a capability path")
    chain.add_argument("--goal", default=states.S_DA)
    chain.add_argument("--allow-crack", action="store_true")
    chain.add_argument("--map", action="append", default=[], metavar="TECH=TARGET")
    chain.add_argument("--param", action="append", default=[], metavar="TECH.KEY=VALUE",
                       help="per-edge parameters, e.g. WRITE-DACL.trustee=operator")
    return root


def _pairs(items):
    result = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key or not value:
            raise InputError("invalid_assignment")
        result[key] = value
    return result


def _score_exit(score):
    if score.get("scored"):
        return {"proved": 0, "not-proved": 1, "inconclusive": 2}.get(
            score.get("result", {}).get("verdict"), 2)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = build_config(args)
    confirmer = AutoConfirm() if args.yes else InteractivePrompt()
    orch = ValidationOrchestrator(config, confirmer=confirmer)
    if config.show_flag:
        orch.context.on_artifact = _display_reveals
    try:
        if args.command == "pipeline":
            report = orch.run()
            status = _score_exit(report.get("score", {}))
        elif args.command == "discover":
            report = orch.discover(list(args.target or []), exploit=args.exploit,
                                   allow_destructive=args.allow_destructive)
            status = (_score_exit(report.get("score", {})) if report.get("exploited")
                      else 0)   # read-only discovery always exits 0; exploit exits on the score

        elif args.command == "run":
            if len(args.target or []) > 1:
                raise InputError("one_target_required")
            edge = get_executor(args.technique)
            params = _pairs(args.param)
            finding = finding_from_inputs(orch.context, edge,
                                          (args.target or [None])[0], params)
            report = edge.run(orch.context, finding, params)
            path = proof.write_receipt(report, config.output_dir / "receipts" / (edge.technique + ".json"))
            score = orch.score([ValidationOutcome(edge.technique, finding.finding_id, path, report)])
            status = _score_exit(score) if score.get("scored") else (0 if report.get("complete") else 1)
        else:
            if not states.is_state(args.goal):
                raise InputError("unknown_goal")
            targets = {key.upper(): value for key, value in _pairs(args.map).items()}
            scoped = {}
            for key, value in _pairs(args.param).items():
                tech, sep, param = key.partition(".")
                if not sep or not param:
                    raise InputError("expected_technique_parameter")
                scoped.setdefault(tech.upper(), {})[param] = value
            if (set(targets) | set(scoped)) - IMPLEMENTED:
                raise InputError("unknown_technique")
            # Validate all requested bindings BEFORE any mutation. Unmapped edges
            # have no finding; DCSYNC gets an explicit DC binding by default.
            bindings = {}
            for edge in default_edges():
                if edge.technique in targets or edge.technique in scoped or edge.technique == "DCSYNC":
                    bindings[edge.technique] = finding_from_inputs(
                        orch.context, edge, targets.get(edge.technique), scoped.get(edge.technique))
            chain = da_in_minutes(orch.context, lambda edge: bindings.get(edge.technique),
                                  goal=args.goal, allow_crack=args.allow_crack,
                                  allow_destructive=args.allow_destructive)
            report = chain.to_dict()
            config.output_dir.mkdir(parents=True, exist_ok=True)
            (config.output_dir / "chain-report.json").write_text(json.dumps(report, indent=2) + "\n")
            status = 0 if chain.reached else 1
    except InputError as exc:
        # InputError messages are constructed only from fixed codes/spec names.
        report, status = {"errors": [str(exc)]}, 2
    except Exception as exc:
        orch.context._private_errors.append(str(exc))
        report, status = {"errors": ["dispatch_error"]}, 2
    json.dump(report, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
