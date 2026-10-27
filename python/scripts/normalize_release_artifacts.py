#!/usr/bin/env python3
"""Normalize source-distribution metadata for byte-reproducible releases."""

from __future__ import annotations

import argparse
import copy
import gzip
from io import BytesIO
import os
from pathlib import Path
import tarfile
import tempfile


def normalize_sdist(path: Path, epoch: int) -> None:
    """Rewrite a ``.tar.gz`` with stable ordering, ownership, modes, and times."""
    if not path.name.endswith(".tar.gz"):
        raise ValueError(f"not a source distribution: {path}")

    with tarfile.open(path, "r:gz") as source:
        entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
        for original in source.getmembers():
            member = copy.copy(original)
            payload = source.extractfile(original).read() if original.isfile() else None
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = epoch
            member.pax_headers = {}
            if member.isdir():
                member.mode = 0o755
            elif member.isfile():
                member.mode = 0o755 if original.mode & 0o111 else 0o644
            entries.append((member, payload))

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as output:
                    for member, payload in sorted(entries, key=lambda item: item[0].name):
                        if payload is None:
                            output.addfile(member)
                        else:
                            output.addfile(member, BytesIO(payload))
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="+", type=Path)
    parser.add_argument(
        "--epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
        help="stable Unix timestamp (defaults to SOURCE_DATE_EPOCH)",
    )
    args = parser.parse_args()
    if args.epoch < 0:
        raise SystemExit("epoch must be non-negative")
    for artifact in args.artifacts:
        normalize_sdist(artifact, args.epoch)


if __name__ == "__main__":
    main()
