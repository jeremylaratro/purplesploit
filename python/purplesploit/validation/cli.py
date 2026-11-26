"""CLI entrypoint for the operator-driven AD validation automation.

    python -m purplesploit.validation.cli \
        --domain north.sevenkingdoms.local --dc-ip 10.0.0.10 \
        --user joe --password '...' \
        --findings-json ./enum/findings.json \
        --output ./validation-run \
        [--proof-truth GOAD-proof.json --score-proof 'python3 -m adlab.score_proof'] \
        [--yes]

Implements the #66142 flow: enumerate -> present discovered issues -> offer to
validate each (opt-in) -> propose recommended defaults the operator can override
-> execute -> score. ``--yes`` accepts recommended defaults non-interactively
(implemented, verified recipes only); without it the operator is prompted per
issue and may override any parameter.
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
from .executors import is_implemented
from .executors.base import ValidationPlan


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


def build_config(args: argparse.Namespace) -> ValidationConfig:
    host_aliases: dict = {}
    if args.host_alias:
        for item in args.host_alias:
            raw, _, hid = item.partition("=")
            if raw and hid:
                host_aliases[raw] = {"host_id": hid}
    return ValidationConfig(
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
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="purplesploit-validate", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
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
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = build_config(args)
    confirmer = AutoConfirm() if args.yes else InteractivePrompt()
    orch = ValidationOrchestrator(config, confirmer=confirmer)
    report = orch.run()
    json.dump(report, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    score = report.get("score", {})
    if score.get("scored"):
        verdict = score.get("result", {}).get("verdict")
        return {"proved": 0, "not-proved": 1, "inconclusive": 2}.get(verdict, 2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
