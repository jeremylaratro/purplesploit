# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the single-file PurpleSploit binary.

Run from packaging/offline/ via container-build.sh, which sets SRC_ROOT to the
repo's python/ directory.
"""

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

SRC_ROOT = Path(os.environ["SRC_ROOT"]).resolve()          # <repo>/python
REPO_ROOT = SRC_ROOT.parent
PKG = SRC_ROOT / "purplesploit"

# Ship the module tree as DATA, not just as frozen bytecode: discover_modules()
# os.walk()s for .py files and loads them with spec_from_file_location.
datas = [
    (str(PKG / "modules"), "purplesploit/modules"),
    (str(PKG / "web" / "templates"), "purplesploit/web/templates"),
    (str(PKG / "web" / "static"), "purplesploit/web/static"),
    (str(PKG / "reporting" / "templates"), "purplesploit/reporting/templates"),
    (str(REPO_ROOT / "templates"), "templates"),
]
datas = [(src, dst) for src, dst in datas if Path(src).exists()]

# Dynamically-loaded modules are invisible to PyInstaller's static analysis, so
# every third-party package they import must be declared explicitly.
hiddenimports = collect_submodules("purplesploit") + [
    "anthropic",
    "openai",
    "shodan",
    "defusedxml",
    "defusedxml.ElementTree",
    "sqlalchemy",
    "sqlalchemy.dialects.sqlite",
    "pydantic",
    "fastapi",
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "slowapi",
    "websockets",
    "jinja2",
    "openpyxl",
    "requests",
    "yaml",
    "packaging",
    "pandas",
    "rich",
    "prompt_toolkit",
]

a = Analysis(
    ["entry_frozen.py"],
    pathex=[str(SRC_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Test/plot machinery that would balloon the binary without being reachable
    # from the console entry point.
    excludes=[
        "tkinter",
        "pytest",
        "_pytest",
        "IPython",
        "notebook",
        "textual",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="purplesploit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
