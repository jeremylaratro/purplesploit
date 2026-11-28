"""Opt-in live secret display, isolated from stdout and receipt persistence."""
from __future__ import annotations

import sys

from .executors.base import SecretReveal


def reveal_to_terminal(reveals: list[SecretReveal]) -> None:
    """Write ONLY to the controlling terminal; never fall back to a log stream."""
    try:
        with open("/dev/tty", "w", encoding="utf-8") as terminal:
            if not terminal.isatty():
                raise OSError("not a terminal")
            terminal.write("\n⚠  --show-flag: LIVE SECRETS — terminal only, "
                           "NOT in any receipt/log  ⚠\n")
            for reveal in reveals:
                terminal.write(f"  [{reveal.technique}]  {reveal.kind}  "
                               f"{reveal.principal}  {reveal.value}\n")
            terminal.flush()
    except OSError:
        # A lost terminal must not interrupt chain teardown or fall back to a log.
        print("[--show-flag] suppressed: no interactive terminal", file=sys.stderr)
