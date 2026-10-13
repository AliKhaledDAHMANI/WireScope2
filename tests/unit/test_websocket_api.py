from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from wirescope.api import create_app
from wirescope.proxy import ProxyService, WireScopeAddon
from wirescope.repeater import RepeaterClient
from wirescope.scope import ScopePolicy
from wirescope.store import Store


class DirectLoop:
    def is_running(self): return True
    def call_soon_threadsafe(self, callback): callback()


class Commands:
    def __init__(self): self.calls = []
    def call(self, *args): self.calls.append(args)


def setup_client(tmp_path: Path):
    store = Store(tmp_path / "ws-api.sqlite3")
    scope = ScopePolicy(store)
    proxy = ProxyService(store, tmp_path, scope=scope)
    app = create_app(store, proxy, scope, RepeaterClient(scope))
    client = TestClient(app)
    token = client.get("/api/session").json()["token"]
    client.headers.update({"X-WireScope-Token": token})
    return client, store, scope, proxy, app


def seed_connection(store: Store, connection_id="ws-api"):
    store.record_request(flow_id=connection_id, started_at=10, method="GET", url="ws://127.0.0.1:8766/echo?secret=hidden", host="127.0.0.1", path="/echo", headers=[("Upgrade", "websocket")], body=b"")
    store.record_response(flow_id=connection_id, status=101, headers=[("Upgrade", "websocket")], body=b"", duration_ms=2)
    store.start_websocket(connection_id=connection_id, flow_id=connection_id, url="ws://127.0.0.1:8766/echo?secret=hidden", host="127.0.0.1", scheme="ws", started_at=10, request_headers=[("Cookie", "sensitive")], response_headers=[("Upgrade", "websocket")], handshake_status=101, remote_ip="127.0.0.1")
    store.append_websocket_message(connection_id=connection_id, timestamp=11, direction="client_to_server", opcode=2, payload=b"\x00\xff\x80")
    store.append_websocket_message(connection_id=connection_id, timestamp=12, direction="server_to_client", opcode=1, payload=b"hello world")


def active_fake_connection(store, proxy, flow_id="ws-api"):
    addon = WireScopeAddon(store, {}, threading.RLock(), threading.Event(), proxy.scope)
    flow = SimpleNamespace(id=flow_id, websocket=SimpleNamespace(timestamp_end=None), request=SimpleNamespace(url="ws://127.0.0.1:8766/echo", host="127.0.0.1"), server_conn=SimpleNamespace(ip_address=("127.0.0.1", 8766)))
    addon.websocket_flows[flow_id] = flow
    commands = Commands()
    proxy._addon = addon
    proxy._loop = DirectLoop()
    proxy._master = SimpleNamespace(commands=commands)
    return addon, flow, commands


def test_websocket_api_auth_redaction_pagination_and_payload(tmp_path):
    client, store, _, _, app = setup_client(tmp_path)
    seed_connection(store)
    unauthorized = TestClient(app).get("/api/websockets/connections")
    assert unauthorized.status_code == 403

    page = client.get("/api/websockets/connections?search=8766&limit=1&offset=0")
    assert page.status_code == 200 and page.json()["count"] == 1
    assert client.get("/api/websockets/connections?state=connecting").status_code == 200
    connection = page.json()["connections"][0]
    assert "hidden" not in connection["url"] and "[REDACTED]" in connection["url"]
    assert "request_headers" not in connection
    detail = client.get("/api/websockets/connections/ws-api").json()
    assert detail["handshake_status"] == 101
    assert detail["request_headers"][0] == ["Cookie", "sensitive"]

    messages = client.get("/api/websockets/connections/ws-api/messages?direction=client_to_server&opcode=2")
    assert messages.status_code == 200 and messages.json()["count"] == 1
    msg_id = messages.json()["messages"][0]["id"]
    payload = client.get(f"/api/websockets/connections/ws-api/messages/{msg_id}").json()
    assert payload["payload_hex"] == "00ff80"
    assert payload["payload_text"] is None
    assert payload["payload_base64"] == "AP+A"
    assert client.get("/api/websockets/connections/ws-api/messages?opcode=3").status_code == 422
    assert client.get("/api/websockets/connections/nope/messages").status_code == 404


def test_websocket_manual_send_only_active_in_scope_and_marks_user_source(tmp_path):
    client, store, scope, proxy, _ = setup_client(tmp_path)
    seed_connection(store)
    addon, flow, commands = active_fake_connection(store, proxy)
    try:
        result = proxy.send_websocket_message("ws-api", "sent by user ✓".encode(), is_text=True)
        assert result["status"] == "sent" and result["source"] == "user"
        assert commands.calls[0][0] == "inject.websocket"
        assert commands.calls[0][1] is flow
        assert commands.calls[0][2] is False  # `to_client=False`: send to the server
        assert commands.calls[0][3] == "sent by user ✓".encode()
        messages = store.list_websocket_messages("ws-api", limit=20)["messages"]
        stored = store.get_websocket_message(next(item["id"] for item in messages if item["source"] == "user"))
        assert stored["payload"] == "sent by user ✓".encode()
    finally:
        addon.close()

    store.add_scope_rule("127.0.0.1", "exclude")
    addon, flow, commands = active_fake_connection(store, proxy)
    try:
        with pytest.raises(PermissionError):
            proxy.send_websocket_message("ws-api", b"must not send", is_text=True)
        assert commands.calls == []
    finally:
        addon.close()


def test_websocket_send_api_validates_binary_and_size_without_network(tmp_path, monkeypatch):
    client, store, _, _, _ = setup_client(tmp_path)
    monkeypatch.setattr(store, "max_ws_message_bytes", 1024)
    assert client.post("/api/websockets/connections/nope/send", json={"payload": "%%%", "binary": True}).status_code == 422
    large = "x" * 1025
    # Payload is rejected from declared configuration before checking whether a live connection exists.
    # Use multibyte-free ASCII to make the byte count unambiguous.
    assert client.post("/api/websockets/connections/nope/send", json={"payload": large, "binary": False}).status_code == 413


def test_manual_send_fails_closed_when_peer_is_unavailable_and_exclusions_exist(tmp_path):
    client, store, _, proxy, _ = setup_client(tmp_path)
    seed_connection(store)
    store.add_scope_rule("192.0.2.*", "exclude")
    addon, flow, commands = active_fake_connection(store, proxy)
    flow.server_conn.ip_address = None
    flow.server_conn.peername = None
    flow.server_conn.address = None
    try:
        with pytest.raises(PermissionError, match="Cannot verify"):
            proxy.send_websocket_message("ws-api", b"must not send", is_text=True)
        assert commands.calls == []
    finally:
        addon.close()
