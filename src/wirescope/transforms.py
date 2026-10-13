"""Local text encoders/decoders with explicit binary handling."""
from __future__ import annotations

import base64
import binascii
import html
import re
from urllib.parse import quote, unquote_to_bytes

MAX_TRANSFORM_BYTES = 2 * 1024 * 1024
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


class TransformError(ValueError):
    pass


def transform(operation: str, value: str) -> dict[str, object]:
    if not isinstance(value, str):
        raise TransformError("Input must be a UTF-8 text string")
    try:
        value_bytes = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise TransformError("Input contains an invalid Unicode surrogate; provide valid UTF-8 text") from exc
    if len(value_bytes) > MAX_TRANSFORM_BYTES:
        raise TransformError("Input exceeds the 2 MiB transformation limit")
    op = operation.strip().lower()
    binary = False
    warning = None
    if op == "url_encode":
        output = quote(value, safe="", encoding="utf-8", errors="strict")
        raw = output.encode("utf-8")
    elif op == "url_decode":
        if _BAD_PERCENT.search(value):
            raise TransformError("Invalid percent escape: every % must be followed by two hexadecimal digits")
        raw = unquote_to_bytes(value)
        output, binary, warning = _decode_utf8_or_binary(raw)
    elif op == "base64_encode":
        raw = base64.b64encode(value_bytes)
        output = raw.decode("ascii")
    elif op == "base64_decode":
        try:
            raw = base64.b64decode("".join(value.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise TransformError("Invalid Base64 input") from exc
        output, binary, warning = _decode_utf8_or_binary(raw)
    elif op == "hex_encode":
        raw = value_bytes.hex().encode("ascii")
        output = raw.decode("ascii")
    elif op == "hex_decode":
        compact = "".join(value.split())
        if len(compact) % 2:
            raise TransformError("Hexadecimal input must contain an even number of digits")
        if re.fullmatch(r"[0-9a-fA-F]*", compact) is None:
            raise TransformError("Hexadecimal input contains a non-hexadecimal character")
        raw = bytes.fromhex(compact)
        output, binary, warning = _decode_utf8_or_binary(raw)
    elif op == "html_encode":
        output = html.escape(value, quote=True)
        raw = output.encode("utf-8", errors="strict")
    elif op == "html_decode":
        output = html.unescape(value)
        raw = output.encode("utf-8")
    else:
        raise TransformError("Unsupported operation")
    result: dict[str, object] = {"operation": op, "output": output, "binary": binary, "bytes": len(raw)}
    if binary:
        # Never replace invalid UTF-8 with U+FFFD and pretend it is the original data.
        result["hex"] = raw.hex()
        result["base64"] = base64.b64encode(raw).decode("ascii")
    if warning:
        result["warning"] = warning
    return result


def _decode_utf8_or_binary(raw: bytes) -> tuple[str, bool, str | None]:
    try:
        return raw.decode("utf-8", errors="strict"), False, None
    except UnicodeDecodeError:
        return "", True, "Decoded bytes are not valid UTF-8. Exact bytes are preserved in the hex and Base64 fields."
