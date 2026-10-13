from __future__ import annotations

import os
import stat
from pathlib import Path

APP_NAME = "WireScope"


def data_dir() -> Path:
    """Return a per-user data directory without relying on a cloud service."""
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif os.sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    result = root / "WireScope"
    result.mkdir(parents=True, exist_ok=True)
    _private_dir(result)
    return result


def _private_dir(path: Path) -> None:
    if os.name != "nt":
        try:
            path.chmod(stat.S_IRWXU)
        except OSError:
            pass


def secure_file(path: Path) -> None:
    """Best-effort owner-only permissions for local traffic/project files."""
    if os.name != "nt" and path.exists():
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
