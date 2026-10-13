from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from wirescope.repeater import RepeaterClient, RepeaterError, parse_raw_request
from wirescope.scope import ScopePolicy
from wirescope.store import Store


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.org/out-of-scope")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = f"method={self.command};path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = b"echo:" + body
        self.send_response(201)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


@pytest.fixture
def lab_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_parse_request():
    parsed = parse_raw_request("POST http://127.0.0.1:5000/echo HTTP/1.1\nHost: 127.0.0.1:5000\nContent-Type: text/plain\n\nhello")
    assert parsed.method == "POST"
    assert parsed.url.endswith("/echo")
    assert parsed.body == b"hello"


@pytest.mark.parametrize("raw", [
    "GET /relative HTTP/1.1\n\n",
    "GET ftp://example.org/ HTTP/1.1\n\n",
    "GET http://user:pass@example.org/ HTTP/1.1\n\n",
    "not a request",
])
def test_parser_rejects_unsafe_or_invalid_requests(raw):
    with pytest.raises(RepeaterError):
        parse_raw_request(raw)


def test_repeater_sends_to_loopback_lab(lab_server, tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    repeater = RepeaterClient(ScopePolicy(store))
    result = repeater.send(f"GET http://127.0.0.1:{lab_server}/check?q=1 HTTP/1.1\nHost: 127.0.0.1:{lab_server}\n\n")
    assert result["status"] == 200
    assert "path=/check?q=1" in result["body"]
    assert result["duration_ms"] >= 0


def test_repeater_post_body(lab_server, tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    repeater = RepeaterClient(ScopePolicy(store))
    result = repeater.send(f"POST http://127.0.0.1:{lab_server}/echo HTTP/1.1\nHost: 127.0.0.1:{lab_server}\nContent-Type: text/plain\n\nhello lab")
    assert result["status"] == 201
    assert result["body"] == "echo:hello lab"


def test_repeater_blocks_out_of_scope(lab_server, tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    repeater = RepeaterClient(ScopePolicy(store))
    with pytest.raises(RepeaterError, match="out of scope"):
        repeater.send("GET https://example.org/ HTTP/1.1\n\n")


def test_repeater_does_not_follow_redirects(lab_server, tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    repeater = RepeaterClient(ScopePolicy(store))
    result = repeater.send(f"GET http://127.0.0.1:{lab_server}/redirect HTTP/1.1\nHost: 127.0.0.1:{lab_server}\n\n")
    assert result["status"] == 302
    assert any(key.lower() == "location" and "example.org" in value for key, value in result["headers"])


def test_repeater_rejects_out_of_scope_host_header(lab_server, tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    repeater = RepeaterClient(ScopePolicy(store))
    raw = f"GET http://127.0.0.1:{lab_server}/ HTTP/1.1\nHost: example.org\n\n"
    with pytest.raises(RepeaterError, match="Host header is out of scope"):
        repeater.send(raw)
