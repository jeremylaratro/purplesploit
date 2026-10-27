#!/usr/bin/env python3
"""Fail release certification when metadata or artifacts drift."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tarfile
import tomllib
import zipfile


FORBIDDEN_TRACKED = {
    "my_sessions.json",
    "python/graph.dot",
    "python/graph.json",
    "python/my_sessions.json",
    "test/writeup100.pdf",
}
FORBIDDEN_PREFIXES = ("enum_output/", "python/build/", "python/dist/")


def certify(source_tree: Path, dist: Path | None = None) -> dict:
    python_root = source_tree / "python"
    version_scope: dict = {}
    exec((python_root / "purplesploit/_version.py").read_text(), version_scope)
    version = version_scope["VERSION"]
    metadata = tomllib.loads((python_root / "pyproject.toml").read_text())
    if metadata["project"]["license"] != "CC-BY-NC-SA-4.0":
        raise SystemExit("Package license does not match repository license decision")
    if version != "7.0.0":
        raise SystemExit(f"Unexpected release version: {version}")
    if not (python_root / "LICENSE").is_file():
        raise SystemExit("Python package license file is missing")

    tracked = set(subprocess.run(
        ["git", "ls-files"], cwd=source_tree, check=True,
        capture_output=True, text=True,
    ).stdout.splitlines())
    forbidden = sorted(
        path for path in tracked
        if (path in FORBIDDEN_TRACKED or path.startswith(FORBIDDEN_PREFIXES))
        and (source_tree / path).exists()
    )
    if forbidden:
        raise SystemExit(f"Operational/generated artifacts are tracked: {forbidden}")

    artifacts = []
    if dist:
        wheels = sorted(dist.glob("*.whl"))
        sdists = sorted(dist.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sdists) != 1:
            raise SystemExit("Expected exactly one wheel and one source distribution")
        with zipfile.ZipFile(wheels[0]) as archive:
            names = archive.namelist()
            if not any(name.endswith(".dist-info/licenses/LICENSE") for name in names):
                raise SystemExit("Wheel does not contain LICENSE")
            metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
            wheel_metadata = archive.read(metadata_name).decode()
            if f"Version: {version}" not in wheel_metadata or "License-Expression: CC-BY-NC-SA-4.0" not in wheel_metadata:
                raise SystemExit("Wheel version/license metadata is inconsistent")
        with tarfile.open(sdists[0]) as archive:
            if not any(name.endswith("/LICENSE") for name in archive.getnames()):
                raise SystemExit("Source distribution does not contain LICENSE")
        artifacts = [path.name for path in [*wheels, *sdists]]
    return {"version": version, "license": metadata["project"]["license"],
            "artifacts": artifacts, "forbidden_tracked": forbidden, "certified": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-tree", type=Path, required=True)
    parser.add_argument("--dist", type=Path)
    args = parser.parse_args()
    print(json.dumps(certify(args.source_tree.resolve(), args.dist.resolve() if args.dist else None), indent=2))


if __name__ == "__main__":
    main()
