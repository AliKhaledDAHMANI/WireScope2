# PyInstaller one-file backend sidecar. Electron supplies the desktop runtime.
from PyInstaller.utils.hooks import collect_all
from PyInstaller.building.datastruct import Tree
import sys
from pathlib import Path

# SPEC is provided by PyInstaller as the complete spec-file argument. Resolve it
# before deriving the adjacent helper directory; SPECPATH may be empty when the
# spec is invoked by basename from the repository root.
spec_directory = Path(SPEC).resolve().parent
helper_directory = spec_directory / "scripts"
if not helper_directory.is_dir():
    raise FileNotFoundError(f"PyInstaller spec helper directory not found: {helper_directory}")
sys.path.insert(0, str(helper_directory))
from pyinstaller_datas import tree_toc_to_analysis_datas, validate_analysis_pairs

mitm_datas, mitm_bins, mitm_hidden = collect_all("mitmproxy")
# Tree emits (destination_name, source_name, typecode) TOC triples. Analysis
# expects (source_path, destination_directory) pairs. Preserve the destination
# directory of each file so nested static folders remain under wirescope/static/.
static_tree = Tree("src/wirescope/static", prefix="wirescope/static")
static_datas = tree_toc_to_analysis_datas(static_tree, destination_prefix="wirescope/static")
all_datas = validate_analysis_pairs("datas", list(mitm_datas) + static_datas)
all_binaries = validate_analysis_pairs("binaries", list(mitm_bins))
all_hidden = list(mitm_hidden) + [
    "wirescope.api", "wirescope.proxy", "wirescope.repeater", "wirescope.scope",
    "wirescope.store", "wirescope.server", "fastapi", "uvicorn", "uvicorn.logging",
    "uvicorn.loops.auto", "uvicorn.protocols.http.auto", "uvicorn.lifespan.on",
    "starlette.staticfiles", "anyio", "sniffio",
]

a = Analysis(
    ["scripts/backend_entry.py"],
    pathex=["src"],
    binaries=all_binaries,
    datas=all_datas,
    hiddenimports=all_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "coverage", "httpx", "webview"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="wirescope-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
