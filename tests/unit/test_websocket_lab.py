from __future__ import annotations

import asyncio
import base64
import os
import socket
import struct
import threading
import time
from pathlib import Path

from lab.websocket_lab import handle_client


def _client_frame(opcode: int, payload: bytes) -> bytes:
    key = b"\x13\x37\x42\x99"
    size = len(payload)
    if size < 126:
        head = bytes([0x80 | opcode, 0x80 | size])
    elif size < 65536:
        head = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", size)
    else:
        raise AssertionError("test helper payload too large")
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def _read_server_frame(sock: socket.socket) -> tuple[int, bytes]:
    head = sock.recv(2)
    assert len(head) == 2
    opcode, size = head[0] & 0x0F, head[1] & 0x7F
    if size == 126:
        extra = b""
        while len(extra) < 2: extra += sock.recv(2 - len(extra))
        size = struct.unpack("!H", extra)[0]
    data = b""
    while len(data) < size: data += sock.recv(size - len(data))
    return opcode, data


def test_local_websocket_lab_echoes_text_binary_and_closes_gracefully():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server_ready = threading.Event()
    context = {}

    def server_thread():
        async def setup():
            server = await asyncio.start_server(handle_client, host="127.0.0.1", port=0)
            context["server"] = server
            context["port"] = server.sockets[0].getsockname()[1]
            server_ready.set()
        loop.run_until_complete(setup())
        loop.run_forever()
        loop.run_until_complete(context["server"].wait_closed())
        loop.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    assert server_ready.wait(3)
    sock = socket.create_connection(("127.0.0.1", context["port"]), timeout=3)
    sock.settimeout(3)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            "GET /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        sock.sendall(handshake)
        response = b""
        while b"\r\n\r\n" not in response: response += sock.recv(4096)
        assert response.startswith(b"HTTP/1.1 101")
        sock.sendall(_client_frame(1, "hello 雪".encode()))
        assert _read_server_frame(sock) == (1, "hello 雪".encode())
        binary = b"\x00\xff\x80\x01"
        sock.sendall(_client_frame(2, binary))
        assert _read_server_frame(sock) == (2, b"lab-binary-ack:" + binary)
        sock.sendall(_client_frame(1, b"close"))
        opcode, payload = _read_server_frame(sock)
        assert opcode == 8 and struct.unpack("!H", payload[:2])[0] == 1000
        sock.close()

        # A second, independent lab session deterministically exercises the error close.
        sock = socket.create_connection(("127.0.0.1", context["port"]), timeout=3)
        sock.settimeout(3)
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall((
            "GET /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        response = b""
        while b"\r\n\r\n" not in response: response += sock.recv(4096)
        assert response.startswith(b"HTTP/1.1 101")
        sock.sendall(_client_frame(1, b"error"))
        opcode, payload = _read_server_frame(sock)
        assert opcode == 8 and struct.unpack("!H", payload[:2])[0] == 1011
    finally:
        sock.close()
        context["server"].close()
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=3)
