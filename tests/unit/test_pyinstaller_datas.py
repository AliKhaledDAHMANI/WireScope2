from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from pyinstaller_datas import tree_toc_to_analysis_datas, validate_analysis_pairs  # noqa: E402


def test_tree_toc_conversion_preserves_root_and_nested_destinations(tmp_path):
    root = tmp_path / "static"
    nested = root / "assets" / "icons"
    nested.mkdir(parents=True)
    first = root / "index.html"
    second = nested / "app.svg"
    first.write_text("index", encoding="utf-8")
    second.write_text("svg", encoding="utf-8")
    entries = [
        ("wirescope/static/index.html", str(first), "DATA"),
        ("wirescope/static/assets/icons/app.svg", str(second), "DATA"),
    ]

    assert tree_toc_to_analysis_datas(entries, destination_prefix="wirescope/static") == [
        (str(first), "wirescope/static"),
        (str(second), "wirescope/static/assets/icons"),
    ]


def test_tree_conversion_rejects_three_tuple_analysis_input(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("ok", encoding="utf-8")
    with pytest.raises(ValueError, match="expected a 3-item"):
        tree_toc_to_analysis_datas([("wirescope/static/app.js", str(source))], destination_prefix="wirescope/static")


def test_tree_conversion_rejects_destination_escape(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("ok", encoding="utf-8")
    with pytest.raises(ValueError, match="outside expected prefix"):
        tree_toc_to_analysis_datas([("elsewhere/app.js", str(source), "DATA")], destination_prefix="wirescope/static")



def test_tree_conversion_rejects_source_destination_basename_mismatch(tmp_path):
    source = tmp_path / "source-name.js"
    source.write_text("ok", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match destination basename"):
        tree_toc_to_analysis_datas(
            [("wirescope/static/destination-name.js", str(source), "DATA")],
            destination_prefix="wirescope/static",
        )

def test_tree_conversion_rejects_missing_source(tmp_path):
    with pytest.raises(ValueError, match="source file does not exist"):
        tree_toc_to_analysis_datas([("wirescope/static/missing.js", str(tmp_path / "missing.js"), "DATA")], destination_prefix="wirescope/static")


def test_analysis_pair_validation_rejects_malformed_data_and_binaries():
    with pytest.raises(ValueError, match="datas entry at index 0"):
        validate_analysis_pairs("datas", [("source", "dest", "DATA")])
    with pytest.raises(ValueError, match="binaries entry at index 0"):
        validate_analysis_pairs("binaries", ["not-a-pair"])


def test_analysis_pair_validation_keeps_valid_pairs():
    assert validate_analysis_pairs("binaries", [(Path("lib.so"), "mitmproxy")]) == [("lib.so", "mitmproxy")]


def test_spec_helper_import_resolution_from_repository_root():
    """The spec's helper import pattern works when PyInstaller gets a basename."""
    import subprocess

    code = (
        "from pathlib import Path; import sys; "
        "SPEC = 'wirescope-backend.spec'; "
        "spec_directory = Path(SPEC).resolve().parent; "
        "helper_directory = spec_directory / 'scripts'; "
        "assert helper_directory.is_dir(), helper_directory; "
        "sys.path.insert(0, str(helper_directory)); "
        "import pyinstaller_datas; "
        "assert Path(pyinstaller_datas.__file__).resolve().parent == helper_directory.resolve()"
    )
    subprocess.run([sys.executable, '-c', code], cwd=ROOT, check=True, capture_output=True, text=True)
