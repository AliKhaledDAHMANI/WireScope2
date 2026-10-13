from __future__ import annotations

import sqlite3
import time

from wirescope.store import Store


def add_flow(store: Store, flow_id: str, url: str = "ws://127.0.0.1:8766/echo") -> None:
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    store.record_request(
        flow_id=flow_id, started_at=time.time(), method="GET", url=url,
        host=parsed.hostname or "127.0.0.1", path=parsed.path or "/",
        headers=[("Upgrade", "websocket")], body=b"",
    )
    store.record_response(flow_id=flow_id, status=101, headers=[("Upgrade", "websocket")], body=b"", duration_ms=2)


def start(store: Store, flow_id: str, state: str = "open") -> None:
    add_flow(store, flow_id)
    store.start_websocket(
        connection_id=flow_id, flow_id=flow_id, url="ws://127.0.0.1:8766/echo?token=secret",
        host="127.0.0.1", scheme="ws", started_at=1.0,
        request_headers=[("Upgrade", "websocket"), ("Sec-WebSocket-Key", "secret-key")],
        response_headers=[("Upgrade", "websocket")], handshake_status=101, remote_ip="127.0.0.1", state=state,
    )


def test_websocket_binary_persistence_filtering_and_pagination(tmp_path):
    store = Store(tmp_path / "ws.sqlite3")
    start(store, "connection-1")
    binary = b"\x00\xff\x80\x01binary"
    store.append_websocket_message(connection_id="connection-1", timestamp=2.0, direction="client_to_server", opcode=2, payload=binary)
    store.append_websocket_message(connection_id="connection-1", timestamp=3.0, direction="server_to_client", opcode=1, payload=b"echo:hello")
    store.append_websocket_message(connection_id="connection-1", timestamp=4.0, direction="client_to_server", opcode=1, payload=b"hello again", source="user")

    conn = store.get_websocket_connection("connection-1")
    assert conn and conn["handshake_status"] == 101 and conn["state"] == "open"
    assert conn["message_count"] == 3
    page = store.list_websocket_messages("connection-1", limit=2, offset=0)
    assert page["count"] == 3 and len(page["messages"]) == 2
    binary_id = next(row["id"] for row in store.list_websocket_messages("connection-1")["messages"] if row["opcode"] == 2)
    saved = store.get_websocket_message(binary_id)
    assert saved["payload"] == binary
    assert saved["payload_size"] == len(binary) and saved["truncated"] == 0
    assert store.list_websocket_messages("connection-1", direction="server_to_client")["count"] == 1
    assert store.list_websocket_messages("connection-1", opcode=1, search="hello")["count"] == 2
    assert store.list_websocket_connections(search="8766", state="open")["count"] == 1
    assert store.list_websocket_connections(state="closed")["count"] == 0
    assert store.get_websocket_connection("connection-1")["request_headers"]


def test_websocket_configured_message_limit_flags_truncation(tmp_path, monkeypatch):
    monkeypatch.setenv("WIRESCOPE_MAX_WS_MESSAGE_BYTES", "1024")
    store = Store(tmp_path / "bounded.sqlite3")
    start(store, "bounded")
    raw = b"\x00\xff" * 700
    saved = store.append_websocket_message(connection_id="bounded", timestamp=3, direction="server_to_client", opcode=2, payload=raw)
    assert len(saved["payload"]) == 1024
    assert saved["payload_size"] == len(raw)
    assert saved["truncated"] == 1


def test_restart_marks_open_websocket_interrupted_and_preserves_capture(tmp_path):
    database = tmp_path / "restart.sqlite3"
    store = Store(database)
    start(store, "interrupted")
    start(store, "interrupted-connecting", state="connecting")
    store.append_websocket_message(connection_id="interrupted", timestamp=2, direction="server_to_client", opcode=2, payload=b"\x00\xff")
    store.close()
    reopened = Store(database)
    connection = reopened.get_websocket_connection("interrupted")
    assert connection["state"] == "interrupted"
    assert connection["ended_at"] is not None
    connecting = reopened.get_websocket_connection("interrupted-connecting")
    assert connecting["state"] == "interrupted" and connecting["ended_at"] is not None
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall() == [(1,), (2,), (3,)]
    assert reopened.get_websocket_message(1)["payload"] == b"\x00\xff"


def test_websocket_storage_caps_oldest_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("WIRESCOPE_MAX_WS_MESSAGES", "100")
    store = Store(tmp_path / "retention.sqlite3")
    start(store, "retention")
    for n in range(120):
        store.append_websocket_message(connection_id="retention", timestamp=n + 2, direction="client_to_server", opcode=1, payload=f"m{n}".encode())
    page = store.list_websocket_messages("retention", limit=200)
    assert page["count"] == 100
    assert store.get_websocket_message(1) is None
    # Per-connection count tracks retained rows after global pruning.
    assert store.get_websocket_connection("retention")["message_count"] == 100


def test_websocket_storage_byte_limit_is_enforced_under_concurrent_capture(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setenv("WIRESCOPE_MAX_WS_MESSAGES", "1000")
    monkeypatch.setenv("WIRESCOPE_MAX_WS_STORAGE_BYTES", str(1024 * 1024))
    store = Store(tmp_path / "concurrent-retention.sqlite3")
    start(store, "concurrent-retention")
    payload = b"x" * 20_000
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(
                lambda n: store.append_websocket_message(
                    connection_id="concurrent-retention", timestamp=float(n + 2),
                    direction="client_to_server" if n % 2 else "server_to_client",
                    opcode=2, payload=payload,
                ), range(120),
            ))
        page = store.list_websocket_messages("concurrent-retention", limit=200)
        rows = [store.get_websocket_message(row["id"]) for row in page["messages"]]
        assert page["count"] <= 1000
        assert sum(len(row["payload"]) for row in rows if row is not None) <= 1024 * 1024
        assert store.get_websocket_connection("concurrent-retention")["message_count"] == page["count"]
        assert all(result is not None for result in results)
    finally:
        store.close()
