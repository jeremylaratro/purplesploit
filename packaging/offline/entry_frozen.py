"""
PyInstaller entry point for the single-file PurpleSploit binary.

Two things differ from running from source, and both are handled here:

1. The database. purplesploit.main defaults the DB to
   ``<project_root>/.data/purplesploit.db``, resolved from ``__file__``. In a
   onefile build ``__file__`` lives under the ephemeral ``sys._MEIPASS``
   extraction dir, which is deleted on exit — the DB would vanish every run.
   main() honours ``$PURPLESPLOIT_DB``, so we point it at a stable per-user
   path unless the operator has already set one.

2. Module discovery. Framework.discover_modules() walks the filesystem and
   loads each module with importlib.util.spec_from_file_location, so it needs
   real ``.py`` files on disk — not frozen bytecode. The .spec ships
   ``purplesploit/modules`` as *data*, which lands at
   ``$_MEIPASS/purplesploit/modules`` and is exactly where the framework's
   default ``Path(__file__).parent.parent / "modules"`` resolves to. No
   override needed; this note exists so the coupling isn't silently broken.
"""

import os
import sys
from pathlib import Path


def _default_db_path() -> str:
    data_home = os.getenv("XDG_DATA_HOME")
    base = Path(data_home) if data_home else Path.home() / ".local" / "share"
    target = base / "purplesploit"
    target.mkdir(parents=True, exist_ok=True)
    return str(target / "purplesploit.db")


def main() -> None:
    if not os.getenv("PURPLESPLOIT_DB"):
        os.environ["PURPLESPLOIT_DB"] = _default_db_path()

    from purplesploit.main import main as _main

    _main()


if __name__ == "__main__":
    sys.exit(main())
