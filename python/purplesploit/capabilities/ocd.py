"""OCD Active Directory mind-map capability registry.

Loads the parsed Orange Cyberdefense AD mind map (v2025.03) coverage registry and
reports, for each of the 17 attack-phase categories, which PurpleSploit modules back
it and what is still missing. This is the executable spine that relates the mind-map
methodology to the module system.

Data: ``ocd_registry.json`` (generated from the parsed taxonomy; see
``docs/research/OCD-AD-MINDMAP-CAPABILITY-MAPPING-16NOV2026.md``).

``module_status`` per category means (is there code?):
  HAVE    – one or more backing modules cover the core subjects
  PARTIAL – core subjects backed, key operations still need a module
  STUB    – the denominator tool exists but no module wraps the OCD operation yet
  GAP     – no denominator capability at all
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REGISTRY_PATH = Path(__file__).with_name("ocd_registry.json")
_MODULES_ROOT = Path(__file__).resolve().parent.parent / "modules"

STATUSES = ("HAVE", "PARTIAL", "STUB", "GAP")


@dataclass(frozen=True)
class Category:
    key: str
    title: str
    subjects: tuple[str, ...]
    denominator_capabilities: tuple[str, ...]
    backing_modules: tuple[str, ...]
    missing_modules: tuple[str, ...]
    module_status: str
    mapping_verdict: str


def load_registry(path: Path | None = None) -> dict[str, Any]:
    """Load and lightly validate the registry document."""
    doc = json.loads((path or _REGISTRY_PATH).read_text(encoding="utf-8"))
    cats = doc.get("categories")
    if not isinstance(cats, list) or len(cats) != 17:
        raise ValueError(f"registry must hold 17 categories, found {len(cats) if isinstance(cats, list) else 'n/a'}")
    seen = set()
    for c in cats:
        key = c.get("key")
        if key in seen:
            raise ValueError(f"duplicate category key: {key}")
        seen.add(key)
        if c.get("module_status") not in STATUSES:
            raise ValueError(f"{key}: bad module_status {c.get('module_status')!r}")
    return doc


def categories(path: Path | None = None) -> list[Category]:
    doc = load_registry(path)
    return [
        Category(
            key=c["key"],
            title=c["title"],
            subjects=tuple(c.get("subjects", ())),
            denominator_capabilities=tuple(c.get("denominator_capabilities", ())),
            backing_modules=tuple(c.get("backing_modules", ())),
            missing_modules=tuple(c.get("missing_modules", ())),
            module_status=c["module_status"],
            mapping_verdict=c.get("mapping_verdict", "?"),
        )
        for c in doc["categories"]
    ]


def _module_file(ref: str) -> Path:
    """Resolve a 'category/name' ref to its module file path."""
    return _MODULES_ROOT / f"{ref}.py"


def validate_backing_modules(path: Path | None = None) -> list[tuple[str, str]]:
    """Return (category_key, module_ref) pairs whose backing module file is absent.

    An empty list means every claimed backing module resolves to a real file —
    the registry does not over-claim coverage.
    """
    stale: list[tuple[str, str]] = []
    for c in categories(path):
        for ref in c.backing_modules:
            if not _module_file(ref).is_file():
                stale.append((c.key, ref))
    return stale


def coverage_report(path: Path | None = None) -> str:
    cats = categories(path)
    counts = {s: sum(1 for c in cats if c.module_status == s) for s in STATUSES}
    lines = [
        "OCD AD mind-map — PurpleSploit capability coverage",
        f"  module_status: " + " · ".join(f"{s} {counts[s]}" for s in STATUSES),
        "",
        f"  {'category':22} {'status':8} {'verdict':8} backing / missing",
    ]
    for c in cats:
        lines.append(
            f"  {c.key:22} {c.module_status:8} {c.mapping_verdict:8} "
            f"{len(c.backing_modules)} / {len(c.missing_modules)}"
        )
    stale = validate_backing_modules(path)
    lines.append("")
    lines.append(
        "  backing modules all resolve to files."
        if not stale
        else f"  STALE backing refs: {stale}"
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print(coverage_report())
