#!/usr/bin/env python3
"""Create a compact build provenance and checksum manifest."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone


def main():
    directory, output = Path(sys.argv[1]), Path(sys.argv[2])
    files = {}
    for path in sorted(directory.iterdir()):
        if path.is_file() and path != output:
            files[path.name] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
            }
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    document = {
        "schema": "https://slsa.dev/provenance/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_revision": revision,
        "builder": "github-actions" if __import__("os").getenv("GITHUB_ACTIONS") else "local",
        "artifacts": files,
    }
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
