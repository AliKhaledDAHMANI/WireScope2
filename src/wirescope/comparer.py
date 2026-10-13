"""Local line-oriented comparison helpers; no networking or mutation of inputs."""
from __future__ import annotations

import difflib
import re
from typing import Any

MAX_COMPARE_CHARS = 2 * 1024 * 1024
VALID_MODES = {"text", "request", "response", "headers", "bodies"}
MAX_COMPARE_LINES = 20_000


class CompareError(ValueError):
    pass


def _split_message(value: str) -> tuple[str, list[str], str]:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" in normalized:
        head, body = normalized.split("\n\n", 1)
    else:
        head, body = normalized, ""
    lines = head.split("\n") if head else []
    start_line = lines[0] if lines else ""
    headers = lines[1:] if len(lines) > 1 else []
    return start_line, headers, body


def _lines(value: str) -> list[str]:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    # splitlines() treats empty input as no lines, while preserving meaningful interior blanks.
    return normalized.splitlines()


def compare(left: str, right: str, mode: str = "text") -> dict[str, Any]:
    if not isinstance(left, str) or not isinstance(right, str):
        raise CompareError("Both comparison inputs must be text")
    try:
        left_bytes = left.encode("utf-8", errors="strict")
        right_bytes = right.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CompareError("Inputs must contain valid UTF-8 text") from exc
    if len(left_bytes) > MAX_COMPARE_CHARS or len(right_bytes) > MAX_COMPARE_CHARS:
        raise CompareError("Each comparison input is limited to 2 MiB of UTF-8 text")
    mode = mode.casefold().strip()
    if mode not in VALID_MODES:
        raise CompareError("Unsupported comparison mode")

    def relevant_line_count(value: str) -> int:
        normalized = value.replace("\r\n", "\n").replace("\r", "\n")
        if mode in {"headers", "bodies"} and "\n\n" in normalized:
            head, body = normalized.split("\n\n", 1)
            normalized = head if mode == "headers" else body
        return normalized.count("\n") + (1 if normalized else 0)

    if relevant_line_count(left) > MAX_COMPARE_LINES or relevant_line_count(right) > MAX_COMPARE_LINES:
        raise CompareError(f"Each compared section is limited to {MAX_COMPARE_LINES:,} lines")

    if mode == "headers":
        def header_lines(value: str) -> list[str]:
            normalized = value.replace("\r\n", "\n").replace("\r", "\n")
            head = normalized.split("\n\n", 1)[0]
            lines = head.split("\n") if head else []
            if lines and (re.match(r"^[A-Z]+\s+\S+\s+HTTP/\d(?:\.\d)?$", lines[0], re.I)
                          or re.match(r"^HTTP/\d(?:\.\d)?\s+\d{3}(?:\s|$)", lines[0], re.I)):
                return lines[1:]
            return lines
        left_lines, right_lines = header_lines(left), header_lines(right)
    elif mode == "bodies":
        _, _, left_body = _split_message(left)
        _, _, right_body = _split_message(right)
        # If neither side has a header/body separator, compare the supplied text as body.
        left_lines = _lines(left_body if "\n\n" in left.replace("\r\n", "\n").replace("\r", "\n") else left)
        right_lines = _lines(right_body if "\n\n" in right.replace("\r\n", "\n").replace("\r", "\n") else right)
    elif mode in {"request", "response"}:
        left_start, left_headers, left_body = _split_message(left)
        right_start, right_headers, right_body = _split_message(right)
        left_lines = ([left_start] if left_start else []) + left_headers + ["", *(_lines(left_body))]
        right_lines = ([right_start] if right_start else []) + right_headers + ["", *(_lines(right_body))]
    else:
        left_lines, right_lines = _lines(left), _lines(right)

    matcher = difflib.SequenceMatcher(a=left_lines, b=right_lines, autojunk=True)
    rows: list[dict[str, Any]] = []
    added = removed = modified = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset, text in enumerate(left_lines[i1:i2]):
                rows.append({"type": "context", "left_line": i1 + offset + 1, "right_line": j1 + offset + 1, "left": text, "right": text})
        elif tag == "replace":
            left_chunk, right_chunk = left_lines[i1:i2], right_lines[j1:j2]
            pairs = min(len(left_chunk), len(right_chunk))
            for offset in range(pairs):
                rows.append({"type": "modified", "left_line": i1 + offset + 1, "right_line": j1 + offset + 1, "left": left_chunk[offset], "right": right_chunk[offset]})
                modified += 1
            for offset in range(pairs, len(left_chunk)):
                rows.append({"type": "removed", "left_line": i1 + offset + 1, "right_line": None, "left": left_chunk[offset], "right": ""})
                removed += 1
            for offset in range(pairs, len(right_chunk)):
                rows.append({"type": "added", "left_line": None, "right_line": j1 + offset + 1, "left": "", "right": right_chunk[offset]})
                added += 1
        elif tag == "delete":
            for offset, text in enumerate(left_lines[i1:i2]):
                rows.append({"type": "removed", "left_line": i1 + offset + 1, "right_line": None, "left": text, "right": ""})
                removed += 1
        elif tag == "insert":
            for offset, text in enumerate(right_lines[j1:j2]):
                rows.append({"type": "added", "left_line": None, "right_line": j1 + offset + 1, "left": "", "right": text})
                added += 1
    return {"mode": mode, "identical": left_lines == right_lines, "added": added, "removed": removed,
            "modified": modified, "rows": rows, "unified_diff": "\n".join(difflib.unified_diff(left_lines, right_lines, fromfile="left", tofile="right", lineterm=""))}
