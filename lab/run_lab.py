#!/usr/bin/env python3
"""A tiny, non-destructive HTTP test target bound to loopback by default."""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class LabHandler(BaseHTTPRequestHandler):
    server_version = "WireScopeLab/1.0"

    def _send(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8", extra=()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Lab-Only", "true")
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/":
            self._send(200, b"WireScope local lab is running. Safe endpoints: /, /json, /headers\n")
        elif self.path == "/json":
            self._send(200, json.dumps({"lab": True, "message": "local-only test response", "path": self.path}).encode(), "application/json; charset=utf-8")
        elif self.path == "/headers":
            payload = json.dumps({key: value for key, value in self.headers.items()}, indent=2).encode()
            self._send(200, payload, "application/json; charset=utf-8")
        else:
            self._send(404, b"Not found in local lab\n")

    def do_POST(self) -> None:
        # Echo only a bounded request body; this endpoint performs no side effects.
        size = min(1024 * 1024, int(self.headers.get("Content-Length", "0") or 0))
        body = self.rfile.read(size)
        self._send(200, b"LAB ECHO (no changes made):\n" + body)

    def log_message(self, format, *args):
        # Keep test traffic out of console logs; use WireScope's local history instead.
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost"], help="loopback only")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), LabHandler)
    print(f"WireScope lab ready at http://{args.host}:{server.server_port}/ (loopback only; Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local lab…")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
