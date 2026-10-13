"""Real WebSocket capture through WireScope's mitmproxy listener and a loopback lab."""
from __future__ import annotations

import asyncio
import base64
import os
import socket
import struct
import threading
import time
from pathlib import Path

import pytest
pytest.importorskip("mitmproxy", reason="install mitmproxy to run live WebSocket proxy integration")
pytest.importorskip("cryptography", reason="install dev dependencies to run local integration tests")

from lab.websocket_lab import handle_client
from wirescope.proxy import ProxyService
from wirescope.store import Store


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_lab():
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    result = {}

    def run():
        asyncio.set_event_loop(loop)
        async def setup():
            result["server"] = await asyncio.start_server(handle_client, "127.0.0.1", 0)
            result["port"] = result["server"].sockets[0].getsockname()[1]
            ready.set()
        loop.run_until_complete(setup())
        loop.run_forever()
        result["server"].close()
        loop.run_until_complete(result["server"].wait_closed())
        loop.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(3)
    return loop, thread, result


def client_frame(opcode: int, payload: bytes) -> bytes:
    mask = b"\x11\x22\x33\x44"
    n = len(payload)
    if n < 126:
        head = bytes([0x80 | opcode, 0x80 | n])
    elif n < 65536:
        head = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", n)
    else:
        raise AssertionError("payload too large for integration test")
    return head + mask + bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))


def read_exact(sock: socket.socket, length: int) -> bytes:
    output = b""
    while len(output) < length:
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise ConnectionError("WebSocket test socket closed early")
        output += chunk
    return output


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    first, second = read_exact(sock, 2)
    size = second & 0x7f
    if size == 126:
        size = struct.unpack("!H", read_exact(sock, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", read_exact(sock, 8))[0]
    return first & 0x0f, read_exact(sock, size)


def wait_for_connection(store: Store, timeout: float = 6):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = store.list_websocket_connections(limit=20)
        if result["connections"] and result["connections"][0]["state"] == "open":
            return result["connections"][0]
        time.sleep(0.05)
    raise AssertionError("No established WebSocket captured by proxy")


def wait_for_messages(store: Store, conn_id: str, count: int, timeout: float = 6):
    deadline = time.time() + timeout
    while time.time() < deadline:
        messages = store.list_websocket_messages(conn_id, limit=100)
        if messages["count"] >= count:
            return messages
        time.sleep(0.05)
    raise AssertionError(f"Expected at least {count} captured messages")


def test_proxy_captures_live_websocket_handshake_text_and_binary(tmp_path: Path):
    loop, lab_thread, lab = start_lab()
    store = Store(tmp_path / "ws-live.sqlite3")
    proxy = ProxyService(store, tmp_path)
    proxy_port = free_port()
    client = None
    try:
        proxy.start(port=proxy_port)
        client = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
        client.settimeout(5)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        client.sendall((
            f"GET http://127.0.0.1:{lab['port']}/echo HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{lab['port']}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii"))
        response = b""
        while b"\r\n\r\n" not in response:
            response += client.recv(4096)
        assert response.startswith(b"HTTP/1.1 101"), response[:200]
        connection = wait_for_connection(store)
        assert connection["handshake_status"] == 101
        assert connection["flow_id"] == connection["id"]
        assert (connection["request_headers"] if isinstance(connection["request_headers"], str) else connection["request_headers"])

        text = "hello through proxy 雪".encode("utf-8")
        client.sendall(client_frame(1, text))
        assert read_frame(client) == (1, text)
        binary = b"\x00\xff\x80\x01"
        client.sendall(client_frame(2, binary))
        assert read_frame(client) == (2, b"lab-binary-ack:" + binary)

        stored = wait_for_messages(store, connection["id"], 4)
        actual = [store.get_websocket_message(row["id"]) for row in stored["messages"]]
        assert any(msg["direction"] == "client_to_server" and msg["opcode"] == 1 and msg["payload"] == text for msg in actual)
        assert any(msg["direction"] == "server_to_client" and msg["opcode"] == 1 and msg["payload"] == text for msg in actual)
        assert any(msg["direction"] == "client_to_server" and msg["opcode"] == 2 and msg["payload"] == binary for msg in actual)
        assert any(msg["direction"] == "server_to_client" and msg["opcode"] == 2 and msg["payload"] == b"lab-binary-ack:" + binary for msg in actual)

        # Exercise the real mitmproxy injection command against this live socket,
        # not only the unit-test command-dispatch double.
        manual = b"sent manually from WireScope"
        send_result = proxy.send_websocket_message(connection["id"], manual, is_text=True)
        assert send_result["status"] == "sent" and send_result["source"] == "user"
        assert read_frame(client) == (1, manual)  # the local lab echoes the injected frame
        stored = wait_for_messages(store, connection["id"], 6)
        actual = [store.get_websocket_message(row["id"]) for row in stored["messages"]]
        assert any(msg["source"] == "user" and msg["payload"] == manual for msg in actual)
        assert any(msg["direction"] == "server_to_client" and msg["payload"] == manual for msg in actual)

        # Ask the loopback lab to close gracefully, then reopen SQLite to prove
        # connection state and frames survive the proxy/application lifetime.
        client.sendall(client_frame(1, b"close"))
        close_opcode, close_payload = read_frame(client)
        assert close_opcode == 8 and close_payload[:2] == struct.pack("!H", 1000)
        deadline = time.time() + 5
        while time.time() < deadline and store.get_websocket_connection(connection["id"])["state"] not in {"closed", "error"}:
            time.sleep(0.05)
        assert store.get_websocket_connection(connection["id"])["state"] == "closed"
        client.close()
        client = None
        proxy.stop()
        store.close()
        reopened = Store(tmp_path / "ws-live.sqlite3")
        persisted = reopened.get_websocket_connection(connection["id"])
        assert persisted["state"] == "closed"
        persisted_messages = reopened.list_websocket_messages(connection["id"], limit=100)
        assert persisted_messages["count"] >= 6
        assert any(reopened.get_websocket_message(row["id"])["payload"] == manual for row in persisted_messages["messages"])
        reopened.close()
    finally:
        if client:
            try:
                client.sendall(client_frame(8, struct.pack("!H", 1000)))
                client.close()
            except OSError:
                pass
        proxy.stop()
        store.close()
        loop.call_soon_threadsafe(loop.stop)
        lab_thread.join(timeout=3)
