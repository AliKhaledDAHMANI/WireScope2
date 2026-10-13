"""Preflight the source/destination entry formats consumed by the PyInstaller spec."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from PyInstaller.building.datastruct import Tree  # noqa: E402
from PyInstaller.utils.hooks import collect_all  # noqa: E402
from pyinstaller_datas import tree_toc_to_analysis_datas, validate_analysis_pairs  # noqa: E402


def main() -> None:
    mitm_datas, mitm_binaries, _ = collect_all("mitmproxy")
    static_root = ROOT / "src" / "wirescope" / "static"
    static_datas = [
        (
            str(path),
            str(Path("wirescope/static") / path.relative_to(static_root).parent),
        )
        for path in sorted(static_root.rglob("*"))
        if path.is_file()
    ]

    data_pairs = validate_analysis_pairs("datas", list(mitm_datas) + static_datas)
    binary_pairs = validate_analysis_pairs("binaries", list(mitm_binaries))
    print(
        "PyInstaller entry validation passed: "
        f"{len(data_pairs)} data pairs, {len(binary_pairs)} binary pairs, "
        f"{len(static_datas)} static assets."
    )


if __name__ == "__main__":
    main()
