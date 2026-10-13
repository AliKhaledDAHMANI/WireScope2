"""Validate and normalize PyInstaller data/binary entries used by the spec.

PyInstaller's ``Tree`` helper returns TOC entries in the form
``(destination_name, source_name, typecode)``. ``Analysis(datas=...)`` and
``Analysis(binaries=...)`` instead accept pairs ``(source_path, destination_dir)``.
This module is kept dependency-light so the conversion can be unit-tested without
running a complete PyInstaller build.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


def validate_analysis_pairs(label: str, entries: Iterable[Sequence[object]]) -> list[tuple[str, str]]:
    """Return validated ``(source, destination_directory)`` pairs or raise clearly."""
    validated: list[tuple[str, str]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            actual = len(entry) if isinstance(entry, (tuple, list)) else type(entry).__name__
            raise ValueError(
                f"Invalid PyInstaller {label} entry at index {index}: expected a 2-item "
                f"(source_path, destination_directory) pair; got {actual}."
            )
        source, destination = entry
        if not isinstance(source, (str, Path)) or not str(source):
            raise ValueError(f"Invalid PyInstaller {label} entry at index {index}: source path is empty or not a path.")
        if not isinstance(destination, (str, Path)) or not str(destination):
            raise ValueError(
                f"Invalid PyInstaller {label} entry at index {index}: destination directory is empty or not a path."
            )
        validated.append((str(source), str(destination)))
    return validated


def tree_toc_to_analysis_datas(
    entries: Iterable[Sequence[object]], *, destination_prefix: str
) -> list[tuple[str, str]]:
    """Convert ``Tree`` TOC entries to ``Analysis(datas=...)`` pair entries.

    Destination names remain rooted at ``destination_prefix``. Each file's
    destination directory is used, preserving nested subdirectories under that
    runtime root.
    """
    prefix = PurePosixPath(destination_prefix.replace("\\", "/"))
    if not prefix.parts or prefix.is_absolute() or ".." in prefix.parts:
        raise ValueError(f"Invalid PyInstaller Tree destination prefix: {destination_prefix!r}")

    converted: list[tuple[str, str]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, (tuple, list)) or len(entry) != 3:
            actual = len(entry) if isinstance(entry, (tuple, list)) else type(entry).__name__
            raise ValueError(
                f"Invalid PyInstaller Tree entry at index {index}: expected a 3-item "
                f"(destination_name, source_name, typecode) entry; got {actual}."
            )
        destination_name, source_name, typecode = entry
        if not isinstance(destination_name, (str, Path)) or not str(destination_name):
            raise ValueError(f"Invalid PyInstaller Tree entry at index {index}: missing destination name.")
        if not isinstance(source_name, (str, Path)) or not str(source_name):
            raise ValueError(f"Invalid PyInstaller Tree entry at index {index}: missing source name.")
        if typecode != "DATA":
            raise ValueError(
                f"Invalid PyInstaller Tree entry at index {index}: expected typecode 'DATA', got {typecode!r}."
            )

        destination = PurePosixPath(str(destination_name).replace("\\", "/"))
        if destination.is_absolute() or destination.parts[: len(prefix.parts)] != prefix.parts:
            raise ValueError(
                f"PyInstaller Tree destination {str(destination)!r} is outside expected prefix {str(prefix)!r}."
            )
        if len(destination.parts) <= len(prefix.parts):
            raise ValueError(f"PyInstaller Tree destination {str(destination)!r} does not name a file below the prefix.")

        source = Path(source_name)
        if not source.is_file():
            raise ValueError(f"PyInstaller Tree source file does not exist: {source}")
        if source.name != destination.name:
            raise ValueError(
                f"PyInstaller Tree source basename {source.name!r} does not match "
                f"destination basename {destination.name!r}; Analysis data pairs cannot preserve renaming."
            )
        converted.append((str(source), destination.parent.as_posix()))

    if not converted:
        raise ValueError(f"PyInstaller Tree contained no data files for {destination_prefix!r}.")
    return validate_analysis_pairs("datas", converted)
