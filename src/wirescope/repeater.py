from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from .scope import ScopePolicy

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 30


class RepeaterError(ValueError):
    pass


@dataclass
class ParsedRequest:
    method: str
    url: str
    headers: list[tuple[str, str]]
    body: bytes


def parse_raw_request(raw: str) -> ParsedRequest:
    """Parse a simple raw HTTP/1 request editor format with an absolute URL."""
    if not isinstance(raw, str) or not raw.strip():
        raise RepeaterError("Request is empty")
    if len(raw.encode("utf-8", errors="replace")) > MAX_REQUEST_BYTES:
        raise RepeaterError("Request exceeds the 2 MiB editor limit")
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    head, separator, body_text = normalized.partition("\n\n")
    lines = head.split("\n")
    if not lines:
        raise RepeaterError("Missing request line")
    bits = lines[0].strip().split()
    if len(bits) not in (2, 3):
        raise RepeaterError("Request line must look like: GET https://host/path HTTP/1.1")
    method, url = bits[0].upper(), bits[1]
    if not method.isascii() or not method.replace("-", "").isalnum():
        raise RepeaterError("Invalid HTTP method")
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise RepeaterError("Use an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise RepeaterError("Credentials embedded in URLs are not allowed")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise RepeaterError("Invalid URL port") from exc
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if line[:1] in {" ", "\t"}:
            raise RepeaterError("Folded HTTP header lines are not supported")
        name, colon, value = line.partition(":")
        if not colon or not name.strip() or any(ch in name for ch in " \t\r\n"):
            raise RepeaterError(f"Invalid header: {line[:80]}")
        if "\r" in value or "\n" in value:
            raise RepeaterError("Invalid newline in header")
        headers.append((name.strip(), value.strip()))
    body = body_text.encode("utf-8") if separator else b""
    if len(body) > MAX_REQUEST_BYTES:
        raise RepeaterError("Request body exceeds the 2 MiB limit")
    return ParsedRequest(method, url, headers, body)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirects to the user instead of silently issuing a second request."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RepeaterClient:
    def __init__(self, scope: ScopePolicy):
        self.scope = scope

    def send(self, raw_request: str, timeout: int = 10) -> dict:
        parsed = parse_raw_request(raw_request)
        if not self.scope.url_in_scope(parsed.url):
            raise RepeaterError("Target is out of scope. Add an explicit include rule in Settings first.")
        # A custom Host header can select a different virtual host than the URL hostname.
        # Require that name to be in scope too, rather than allowing it to bypass the guard.
        host_header_values = [value for name, value in parsed.headers if name.lower() == "host"]
        if len(host_header_values) > 1:
            raise RepeaterError("Multiple Host headers are not supported by Repeater")
        if host_header_values:
            try:
                override_host = urlsplit("//" + host_header_values[0]).hostname
            except ValueError as exc:
                raise RepeaterError("Invalid Host header") from exc
            if not override_host or not self.scope.host_in_scope(override_host):
                raise RepeaterError("Host header is out of scope. Include that hostname in Settings first.")
        timeout = max(1, min(int(timeout), MAX_TIMEOUT_SECONDS))
        headers = {name: value for name, value in parsed.headers if name.lower() not in {"connection", "proxy-connection", "content-length", "transfer-encoding"}}
        request = urllib.request.Request(
            parsed.url,
            data=parsed.body if parsed.body else None,
            headers=headers,
            method=parsed.method,
        )
        # Deliberately bypass system proxy variables to prevent accidental loops through WireScope.
        # TLS certificate validation remains enabled.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirectHandler(),
        )
        started = time.monotonic()
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        try:
            content = response.read(MAX_RESPONSE_BYTES + 1)
            truncated = len(content) > MAX_RESPONSE_BYTES
            content = content[:MAX_RESPONSE_BYTES]
            status = int(response.code)
            reason = str(getattr(response, "reason", ""))
            response_headers = [(str(k), str(v)) for k, v in response.headers.items()]
        finally:
            response.close()
        return {
            "url": parsed.url,
            "method": parsed.method,
            "status": status,
            "reason": reason,
            "headers": response_headers,
            "body": content.decode("utf-8", errors="replace"),
            "body_base64": __import__("base64").b64encode(content).decode("ascii"),
            "body_bytes": len(content),
            "truncated": truncated,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
