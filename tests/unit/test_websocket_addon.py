from pathlib import Path
import threading
from types import SimpleNamespace

from wirescope.proxy import WireScopeAddon
from wirescope.scope import ScopePolicy
from wirescope.store import Store


class FakeHeaders:
    def __init__(self, pairs): self.pairs = list(pairs)
    def items(self, multi=False): return iter(self.pairs)


def make_flow(flow_id="ws-one", url="ws://127.0.0.1:8766/echo"):
    flow = SimpleNamespace(id=flow_id, metadata={}, response=None, intercepted=False)
    flow.request = SimpleNamespace(
        url=url, host="127.0.0.1", path="/echo", method="GET", raw_content=b"", timestamp_start=10.0,
        headers=FakeHeaders([("Host", "127.0.0.1:8766"), ("Connection", "Upgrade"), ("Upgrade", "websocket")]),
    )
    flow.server_conn = SimpleNamespace(ip_address=("127.0.0.1", 8766), peername=None)
    flow.intercept = lambda: setattr(flow, "intercepted", True)
    flow.kill = lambda: setattr(flow, "killed", True)
    flow.websocket = SimpleNamespace(messages=[], timestamp_end=None, close_code=None, close_reason=None)
    return flow


def build_addon(tmp_path):
    store = Store(tmp_path / "addon.sqlite3")
    pending = {}
    addon = WireScopeAddon(store, pending, threading.RLock(), threading.Event(), ScopePolicy(store))
    return store, pending, addon


def test_addon_captures_handshake_text_binary_and_close(tmp_path: Path):
    store, pending, addon = build_addon(tmp_path)
    flow = make_flow()
    try:
        addon.request(flow)
        flow.response = SimpleNamespace(status_code=101, headers=FakeHeaders([("Upgrade", "websocket")]), raw_content=b"", timestamp_end=10.1)
        addon.response(flow)
        addon.websocket_start(flow)
        flow.websocket.messages.append(SimpleNamespace(type=1, from_client=True, content="snow 雪".encode(), timestamp=10.2, injected=False))
        addon.websocket_message(flow)
        binary = b"\x00\xff\x80\x01"
        flow.websocket.messages.append(SimpleNamespace(type=2, from_client=False, content=binary, timestamp=10.3, injected=False))
        addon.websocket_message(flow)

        connection = store.get_websocket_connection(flow.id)
        assert connection and connection["handshake_status"] == 101 and connection["state"] == "open"
        captured = store.list_websocket_messages(flow.id, limit=20)["messages"]
        assert len(captured) == 2
        first = store.get_websocket_message(next(x["id"] for x in captured if x["opcode"] == 1))
        second = store.get_websocket_message(next(x["id"] for x in captured if x["opcode"] == 2))
        assert first["payload"] == "snow 雪".encode()
        assert first["direction"] == "client_to_server" and first["source"] == "captured"
        assert second["payload"] == binary and second["direction"] == "server_to_client"

        flow.websocket.timestamp_end = 10.5
        flow.websocket.close_code = 1000
        flow.websocket.close_reason = "normal close"
        addon.websocket_end(flow)
        connection = store.get_websocket_connection(flow.id)
        assert connection["state"] == "closed" and connection["close_code"] == 1000
        assert flow.id not in addon.websocket_flows
    finally:
        addon.close()


def test_addon_rejects_explicitly_excluded_websocket_target(tmp_path: Path):
    store, pending, addon = build_addon(tmp_path)
    store.add_scope_rule("127.0.0.1", "exclude")
    flow = make_flow(flow_id="blocked")
    try:
        addon.request(flow)
        assert flow.response.status_code == 403
        assert "blocked" not in pending
        saved = store.get_websocket_connection("blocked")
        assert saved and saved["state"] == "rejected"
        assert "outside configured scope" in saved["error"]
    finally:
        addon.close()


def test_resolved_ip_exclusion_rejects_websocket_before_upgrade_forwarding(tmp_path: Path):
    store, pending, addon = build_addon(tmp_path)
    store.add_scope_rule("allowed.example", "include")
    store.add_scope_rule("203.0.113.4", "exclude")
    flow = make_flow(flow_id="dns-blocked", url="ws://allowed.example/echo")
    flow.request.host = "allowed.example"
    flow.server_conn.ip_address = None
    flow.server_conn.address = ("allowed.example", 8766)
    try:
        addon.request(flow)
        assert store.get_websocket_connection(flow.id)["state"] == "connecting"
        # mitmproxy's server_connected hook runs after resolution/TCP connect but
        # before it forwards the HTTP upgrade request to the peer.
        flow.server_conn.ip_address = ("203.0.113.4", 8766)
        addon.server_connected(SimpleNamespace(server=flow.server_conn, client=SimpleNamespace()))
        saved = store.get_websocket_connection(flow.id)
        assert saved["state"] == "rejected"
        assert "resolved peer" in saved["error"].lower()
        assert getattr(flow, "killed", False)
        assert flow.id not in pending
    finally:
        addon.close()


def test_addon_records_interrupted_websocket_error_without_losing_handshake(tmp_path: Path):
    store, pending, addon = build_addon(tmp_path)
    flow = make_flow(flow_id="socket-error")
    try:
        addon.request(flow)
        flow.response = SimpleNamespace(status_code=101, headers=FakeHeaders([("Upgrade", "websocket")]), raw_content=b"", timestamp_end=10.1)
        addon.response(flow)
        addon.websocket_start(flow)
        flow.error = SimpleNamespace(msg="lab connection interrupted")
        addon.error(flow)
        connection = store.get_websocket_connection(flow.id)
        assert connection["state"] == "error"
        assert "interrupted" in connection["error"]
        assert flow.id not in addon.websocket_flows
        # The HTTP history row retains the successful 101 handshake, rather than
        # rewriting it to a failed HTTP response just because the socket ended later.
        assert store.get_flow(flow.id)["status"] == 101
    finally:
        addon.close()


def test_addon_persists_upstream_websocket_connection_error(tmp_path: Path):
    store, pending, addon = build_addon(tmp_path)
    flow = make_flow(flow_id="connect-error")
    flow.server_conn.ip_address = None
    flow.server_conn.address = ("127.0.0.1", 8766)
    flow.server_conn.error = "connection refused"
    try:
        addon.request(flow)
        addon.server_connect_error(SimpleNamespace(server=flow.server_conn, client=SimpleNamespace()))
        connection = store.get_websocket_connection(flow.id)
        assert connection["state"] == "error"
        assert "connection refused" in connection["error"]
        assert store.get_flow(flow.id)["error"] == "connection refused"
        assert flow.id not in pending
    finally:
        addon.close()


def test_server_connect_rejects_actual_out_of_scope_authority_before_connect(tmp_path: Path):
    store, pending, addon = build_addon(tmp_path)
    store.add_scope_rule("allowed.example", "include")
    flow = make_flow(flow_id="authority-mismatch", url="ws://allowed.example/echo")
    flow.request.host = "allowed.example"
    flow.server_conn.ip_address = None
    flow.server_conn.peername = None
    flow.server_conn.address = ("unlisted.example", 8766)
    try:
        addon.request(flow)
        assert store.get_websocket_connection(flow.id)["state"] == "connecting"
        addon.server_connect(SimpleNamespace(server=flow.server_conn, client=SimpleNamespace()))
        assert flow.server_conn.error and "outside configured scope" in flow.server_conn.error
        saved = store.get_websocket_connection(flow.id)
        assert saved["state"] == "rejected"
        assert flow.id not in pending
        assert store.get_flow(flow.id)["error"]
        # The flow was rejected before a connection existed, so no kill of a live
        # upstream connection was required; mitmproxy's server.error aborts connect.
        assert not getattr(flow, "killed", False)
    finally:
        addon.close()


def test_server_connect_fails_closed_when_destination_is_unavailable_and_exclusions_exist(tmp_path: Path):
    store, pending, addon = build_addon(tmp_path)
    store.add_scope_rule("allowed.example", "include")
    store.add_scope_rule("192.0.2.*", "exclude")
    flow = make_flow(flow_id="unknown-peer", url="ws://allowed.example/echo")
    flow.request.host = "allowed.example"
    flow.server_conn.ip_address = None
    flow.server_conn.peername = None
    flow.server_conn.address = None
    try:
        addon.request(flow)
        addon.server_connect(SimpleNamespace(server=flow.server_conn, client=SimpleNamespace()))
        assert flow.server_conn.error and "cannot verify" in flow.server_conn.error.lower()
        assert store.get_websocket_connection(flow.id)["state"] == "rejected"
        assert flow.id not in pending
    finally:
        addon.close()


def test_server_connected_rejects_unknown_peer_when_exclusions_exist(tmp_path: Path):
    store, pending, addon = build_addon(tmp_path)
    store.add_scope_rule("allowed.example", "include")
    store.add_scope_rule("192.0.2.*", "exclude")
    flow = make_flow(flow_id="unknown-resolved-peer", url="ws://allowed.example/echo")
    flow.request.host = "allowed.example"
    flow.server_conn.ip_address = None
    flow.server_conn.peername = None
    flow.server_conn.address = ("allowed.example", 8766)
    try:
        addon.request(flow)
        addon.server_connected(SimpleNamespace(server=flow.server_conn, client=SimpleNamespace()))
        saved = store.get_websocket_connection(flow.id)
        assert saved["state"] == "rejected"
        assert "unavailable" in saved["error"].lower()
        assert getattr(flow, "killed", False)
        assert flow.id not in pending
    finally:
        addon.close()
