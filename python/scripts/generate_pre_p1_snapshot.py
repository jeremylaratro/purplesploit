#!/usr/bin/env python3
"""Generate the PLAN-002 pre-P1 importer identity corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


PYTHON_ROOT = Path(__file__).resolve().parents[1]
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from tests.tools.pre_p1_snapshot import DEFAULT_OUTPUT, generate_snapshot  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="snapshot directory (default: tests/fixtures/interop/pre-p1)",
    )
    args = parser.parse_args()
    manifest = generate_snapshot(args.output.resolve())
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
