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
from .credential_store import CredentialStore
from .identity import credential_scope, CredentialScopeError
from .orchestrator import (ValidationOrchestrator, ConfirmationProvider, Choice,
                           AutoConfirm)
from .executors import is_implemented, get_executor, IMPLEMENTED
from .executors.base import ValidationPlan, SecretReveal
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
    planner = getattr(args, "command", None) == "autopwn"
    kwargs = dict(
        forge_key=None if planner else _read_key(getattr(args, "forge_key_file", None)),
        forge_key_kind=getattr(args, "forge_key_kind", None),
        forge_key_nt=None if planner else _read_key(getattr(args, "forge_key_nt_file", None)),
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
        cred_store_dir=getattr(args, "cred_store_dir", None),
        cred_store_file=getattr(args, "cred_store_file", None),
        collect_creds=not getattr(args, "no_collect_creds", False),
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
            if token in {"pipeline", "run", "chain", "discover", "autopwn", "creds"}:
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
    p.add_argument("--cred-store-dir", help="private credential store directory (default <output>/cred-store)")
    p.add_argument("--cred-store-file", help="explicit private credential store file path")
    p.add_argument("--no-collect-creds", action="store_true", help="disable recovered credential collection")
    p.add_argument("--as-cred", metavar="SELECTOR",
                   help="act as a stored credential: principal, principal@domain, or zero-based store index")
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
    # Permit --execute to fail with the Phase 4b error even without auth/scope.
    import copy
    planner_shared = copy.deepcopy(shared)
    for action in planner_shared._actions:
        if action.dest in ("domain", "dc_ip"):
            action.required = False
    autopwn = commands.add_parser("autopwn", parents=[planner_shared],
                                  help="fenced autopwn: non-secret dry-run planner (default) "
                                       "or the gated execution loop (--execute)")
    autopwn.add_argument("--execute", action="store_true",
                         help="run the EXECUTION loop (auto-executes mutating AD techniques). "
                              "Requires ALL of --yes --allow-destructive and a scope fence, "
                              "PLUS a typed risk acceptance (or --dangerous). Dry-run otherwise.")
    autopwn.add_argument("--dangerous", action="store_true",
                         help="bypass ONLY the interactive risk-acceptance prompt (for "
                              "non-interactive --execute runs); never bypasses the flag/scope gate")
    autopwn.add_argument("--scope", action="append", default=[], metavar="HOST,...")
    autopwn.add_argument("--scope-domain", action="append", default=[], metavar="DOMAIN,...")
    autopwn.add_argument("--scope-enumerate", action="append", default=[], metavar="DOMAIN",
                         help="materialize computer hosts via an explicitly fenced DC")
    autopwn.add_argument("--goal", default=states.S_DA)
    autopwn.add_argument("--kill-file")
    autopwn.add_argument("--max-hops", type=int, default=1000,
                         help="maximum candidate expansions, including skipped candidates")
    autopwn.add_argument("--max-time", type=float, default=300)
    autopwn.add_argument("--param", action="append", default=[], metavar="TECH.KEY=VALUE",
                         help="public per-technique selectors; never executed")
    chain = commands.add_parser("chain", parents=[shared], help="compose a capability path")
    chain.add_argument("--goal", default=states.S_DA)
    chain.add_argument("--allow-crack", action="store_true")
    chain.add_argument("--map", action="append", default=[], metavar="TECH=TARGET")
    chain.add_argument("--param", action="append", default=[], metavar="TECH.KEY=VALUE",
                       help="per-edge parameters, e.g. WRITE-DACL.trustee=operator")
    creds = commands.add_parser("creds", help="list or clear the private credential store")
    # Store commands need no target or authentication. Accept store/display
    # options on either side of the list/clear subcommand.
    def store_options(parser, suppress=False):
        default = argparse.SUPPRESS if suppress else None
        parser.add_argument("--output", default=argparse.SUPPRESS if suppress else "./validation-run")
        parser.add_argument("--cred-store-dir", default=default)
        parser.add_argument("--cred-store-file", default=default)
        parser.add_argument("--show-flag", action="store_true",
                            default=argparse.SUPPRESS if suppress else False,
                            help="reveal stored values on /dev/tty only")
    store_options(creds)
    actions = creds.add_subparsers(dest="creds_action", required=True)
    store_options(actions.add_parser("list", help="show credential metadata"), suppress=True)
    store_options(actions.add_parser("clear", help="wipe stored credentials"), suppress=True)
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


def _creds(args) -> int:
    args.output_dir = Path(args.output)
    store = CredentialStore.from_config(args)
    try:
        if args.creds_action == "clear":
            store.clear()
            report = {"cleared": True}
        else:
            report = store.list()
            if args.show_flag:
                kinds = {"nthash": "nt_hash", "aeskey": "aes_key",
                         "ccache": "ccache_base64", "pfx": "pfx_base64"}
                reveals = [SecretReveal(entry["source_technique"],
                                        kinds.get(entry["secret_type"], entry["secret_type"]),
                                        entry["principal"], entry["value"])
                           for entry in store.load()]
                if reveals:
                    reveal_to_terminal(reveals)
    except Exception:
        # JSON/parser/filesystem exceptions can contain secret values or paths.
        json.dump({"errors": ["credential_store_error"]}, sys.stdout)
        sys.stdout.write("\n")
        return 2
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "creds":
        return _creds(args)
    if args.command == "autopwn":
        # Phase 4b execution gate: enforce ALL of --execute --yes
        # --allow-destructive and a scope fence BEFORE build_config (which reads
        # files) or any identity re-scope. --dangerous bypasses ONLY the later
        # interactive acceptance, never this gate.
        if args.execute:
            has_fence = bool(args.scope or args.scope_domain or args.scope_enumerate)
            missing = [name for name, present in (
                ("--yes", args.yes), ("--allow-destructive", args.allow_destructive),
                ("--scope", has_fence)) if not present]
            if missing:
                parser.error("autopwn --execute requires " + ", ".join(missing)
                             + " (a scope fence is --scope / --scope-domain / --scope-enumerate)")
        if not args.domain or not args.dc_ip:
            parser.error("autopwn requires --domain and --dc-ip")
        if args.as_cred or args.forge_key_file or args.forge_key_nt_file or args.show_flag:
            parser.error("autopwn supports configured start authentication only; secret-file reads and reveal are disabled")
        try:
            scoped = {}
            for key, value in _pairs(args.param).items():
                tech, sep, param = key.partition('.')
                if not sep or not param:
                    raise InputError("invalid_parameter")
                scoped.setdefault(tech.upper(), {})[param] = value
            if args.execute:
                from .autopwn import execute
                report = execute(build_config(args), scope=args.scope,
                                 scope_domain=args.scope_domain, scope_enumerate=args.scope_enumerate,
                                 goal=args.goal, max_hops=args.max_hops, max_time=args.max_time,
                                 kill_file=args.kill_file, params=scoped, dangerous=args.dangerous)
                status = 2 if report["status"] in (
                    "acceptance_declined", "execution_failed") else 0
            else:
                from .autopwn import plan
                report = plan(build_config(args), scope=args.scope, scope_domain=args.scope_domain,
                              scope_enumerate=args.scope_enumerate, goal=args.goal,
                              max_hops=args.max_hops, max_time=args.max_time, kill_file=args.kill_file,
                              params=scoped)
                status = 2 if report["status"] in ("empty_scope", "planning_failed") else 0
                if report["status"] == "empty_scope":
                    print("empty in-scope set; planning halted (no implicit targets)", file=sys.stderr)
        except Exception:
            report, status = {"errors": ["planner_input_or_audit_error"]}, 2
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write('\n')
        return status
    config = build_config(args)
    if args.as_cred is not None:
        try:
            with credential_scope(config, args.as_cred) as (active, credential):
                # Only public identity metadata goes to the live banner.
                identity = f"{active.username}@{active.domain}"
                source = credential["source_technique"]
                print(f"now acting as {identity} [source: {source}]")
                return _dispatch(args, active)
        except CredentialScopeError as exc:
            json.dump({"errors": [str(exc)]}, sys.stdout)
            sys.stdout.write("\n")
            return 2
    return _dispatch(args, config)


def _dispatch(args: argparse.Namespace, config: ValidationConfig) -> int:
    confirmer = AutoConfirm() if args.yes else InteractivePrompt()
    orch = ValidationOrchestrator(config, confirmer=confirmer)
    if config.collect_creds:
        store = CredentialStore.from_config(config)

        def collect(capabilities):
            try:
                store.upsert(capabilities)
            except Exception as exc:
                # Store errors stay private; they must not change proof output.
                orch.context._private_errors.append(str(exc))

        orch.context.on_capabilities = collect
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
