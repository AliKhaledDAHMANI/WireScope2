from pathlib import Path

from fastapi.testclient import TestClient

from wirescope.api import create_app
from wirescope.proxy import ProxyService
from wirescope.repeater import RepeaterClient
from wirescope.scope import ScopePolicy
from wirescope.store import Store


def build_client(tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    scope = ScopePolicy(store)
    proxy = ProxyService(store, tmp_path)
    app = create_app(store, proxy, scope, RepeaterClient(scope))
    client = TestClient(app)
    token = client.get("/api/session").json()["token"]
    client.headers.update({"X-WireScope-Token": token})
    return client


def test_api_requires_session_token(tmp_path: Path):
    client = build_client(tmp_path)
    client.headers.pop("X-WireScope-Token")
    assert client.get("/api/status").status_code == 403


def test_api_adds_and_removes_scope_rule(tmp_path: Path):
    client = build_client(tmp_path)
    response = client.post("/api/scope", json={"pattern": "*.lab.local", "mode": "include"})
    assert response.status_code == 200
    rule_id = response.json()["id"]
    assert client.get("/api/scope").json()["rules"][0]["pattern"] == "*.lab.local"
    assert client.delete(f"/api/scope/{rule_id}").status_code == 200


def test_api_repeater_runs_against_loopback_test_server(tmp_path: Path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"api-lab-ok"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *_args): pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=target.serve_forever, daemon=True); thread.start()
    try:
        client = build_client(tmp_path)
        port = target.server_port
        response = client.post("/api/repeater/send", json={"raw_request": f"GET http://127.0.0.1:{port}/ HTTP/1.1\nHost: 127.0.0.1:{port}\n\n"})
        assert response.status_code == 200
        assert response.json()["body"] == "api-lab-ok"
    finally:
        target.shutdown(); target.server_close(); thread.join(timeout=2)


def test_local_ui_and_assets_are_served_without_remote_shell(tmp_path: Path):
    client = build_client(tmp_path)
    page = client.get("/")
    assert page.status_code == 200
    assert "WireScope" in page.text
    assert "/static/app.js" in page.text
    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "repeater/send" in script.text
    assert "https://" not in script.text
