"""Stub validation executors -- NONE REMAIN.

All eleven PROVEN/recipe-known techniques (claude-mem #66146) now have a full
:class:`~purplesploit.validation.executors.base.ValidationExecutor`:

* T1a: KERBEROAST + ASREP (``roast.py``), LAPS (``laps.py``)
* T1b: CONSTRAINED-DELEG-PT (``constrained_deleg.py``), OPENSHARES-WRITE
  (``openshares.py``), SHADOW-CREDS (``shadow_creds.py``)
* T1c:  ADCS-ESC1 (``adcs_esc1.py``)
* T1c-2 (listener trio, ADR-001): COERCION (``coercion.py``), NTLM-RELAY
  (``ntlm_relay.py``), UNCONSTRAINED-DELEG (``unconstrained_deleg.py``) on the
  :class:`~purplesploit.validation.executors.process_manager.ProcessManager`
  chassis.

The T1c-2 trio ships ``verified_recipe=False`` (recipe-known-not-run on GOAD,
#66146 C2/C5/C8): honest / opt-in, with all tool invocations + success markers
flagged UNVERIFIED in-module for lab-pinning.

``STUB_EXECUTORS`` is retained (now EMPTY) so the registry import in
``executors/__init__.py`` stays stable; there is nothing left to stub.
"""
from __future__ import annotations

from .base import ValidationExecutor


# No stubs remain -- every technique is fully implemented.
STUB_EXECUTORS: dict[str, type[ValidationExecutor]] = {}
