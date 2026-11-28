"""Engine-only key-material tracking for interrupted certificate writes."""
from pathlib import Path


def key_material_obligation(out_dir: Path, **targets) -> dict:
    """Snapshot before the write so recovery can find unreported output files.

    Explicit paths are added as soon as tool output is parsed. Discovery only
    adds created or replaced files; unrelated pre-existing credentials stay untouched.
    This dict, like every teardown obligation, must never enter a receipt.
    """
    return {**targets, "paths": [], "output_dir": str(out_dir),
            "existing_key_material": _key_files(out_dir)}


def _key_files(out_dir: Path) -> dict[str, tuple[int, int, int, int]]:
    files = {}
    for path in out_dir.iterdir():
        if path.suffix.lower() in {".pfx", ".ccache"} and path.is_file():
            stat = path.stat()
            files[str(path)] = (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    return files


def key_material_paths(obligation: dict) -> list[str]:
    paths = list(obligation.get("paths") or [])
    paths.extend(p for p in (obligation.get("pfx"), obligation.get("ccache")) if p)
    if obligation.get("output_dir"):
        before = obligation["existing_key_material"]
        paths.extend(p for p, stat in _key_files(Path(obligation["output_dir"])).items()
                     if before.get(p) != stat)
    return list(dict.fromkeys(paths))
