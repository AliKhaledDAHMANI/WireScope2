from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "dist" / ("wirescope-backend.exe" if sys.platform == "win32" else "wirescope-backend")
DEST_DIR = ROOT / "dist-backend"
DEST = DEST_DIR / SOURCE.name

if not SOURCE.is_file():
    raise SystemExit(f"PyInstaller output not found: {SOURCE}. Build wirescope-backend.spec first.")
DEST_DIR.mkdir(parents=True, exist_ok=True)
shutil.copy2(SOURCE, DEST)
if sys.platform != "win32":
    DEST.chmod(0o755)
print(f"Staged Electron backend resource: {DEST.relative_to(ROOT)}")
