#!/usr/bin/env python3
"""Deterministic, non-destructive WebSocket test service bound only to 127.0.0.1.

Text is echoed. Binary frames receive ``b"lab-binary-ack:" + payload``.
Send the text ``close`` to close gracefully (1000), or ``error`` to simulate an
application failure (1011). Messages are bounded and the server never opens
outbound connections.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_LAB_MESSAGE_BYTES = 64 * 1024


def frame(opcode: int, payload: bytes = b"", *, fin: bool = True) -> bytes:
    head = bytes([(0x80 if fin else 0) | (opcode & 0x0F)])
    size = len(payload)
    if size < 126:
        head += bytes([size])
    elif size < 65536:
        head += bytes([126]) + struct.pack("!H", size)
    else:
        head += bytes([127]) + struct.pack("!Q", size)
    return head + payload


async def read_frame(reader: asyncio.StreamReader) -> tuple[bool, int, bytes]:
    head = await reader.readexactly(2)
    fin, opcode = bool(head[0] & 0x80), head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    size = head[1] & 0x7F
    if size == 126:
        size = struct.unpack("!H", await reader.readexactly(2))[0]
    elif size == 127:
        size = struct.unpack("!Q", await reader.readexactly(8))[0]
    if size > MAX_LAB_MESSAGE_BYTES:
        raise ValueError("message exceeds lab limit")
    if not masked:
        raise ValueError("client frame must be masked")
    mask = await reader.readexactly(4)
    payload = await reader.readexactly(size)
    return fin, opcode, bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        if len(header) > 16 * 1024:
            raise ValueError("handshake headers too large")
        lines = header.decode("latin-1").split("\r\n")
        if not lines or not lines[0].startswith("GET "):
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().casefold()] = value.strip()
        if headers.get("upgrade", "").casefold() != "websocket" or "upgrade" not in headers.get("connection", "").casefold():
            writer.write(b"HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return
        key = headers.get("sec-websocket-key", "")
        try:
            decoded_key = base64.b64decode(key, validate=True)
        except Exception:
            decoded_key = b""
        if len(decoded_key) != 16:
            writer.write(b"HTTP/1.1 400 Bad WebSocket Key\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\nX-WireScope-Lab: true\r\n\r\n").encode("ascii"))
        await writer.drain()
        while True:
            try:
                fin, opcode, payload = await read_frame(reader)
            except asyncio.IncompleteReadError:
                break
            except (ValueError, asyncio.LimitOverrunError):
                writer.write(frame(8, struct.pack("!H", 1009)))
                await writer.drain()
                break
            if not fin or opcode not in {1, 2, 8, 9, 10}:
                writer.write(frame(8, struct.pack("!H", 1002)))
                await writer.drain()
                break
            if opcode == 8:
                writer.write(frame(8, payload[:125]))
                await writer.drain()
                break
            if opcode == 9:
                writer.write(frame(10, payload))
                await writer.drain()
                continue
            if opcode == 10:
                continue
            if opcode == 1:
                try:
                    text = payload.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    writer.write(frame(8, struct.pack("!H", 1007)))
                    await writer.drain()
                    break
                if text == "close":
                    writer.write(frame(8, struct.pack("!H", 1000) + b"lab close"))
                    await writer.drain()
                    break
                if text == "error":
                    writer.write(frame(8, struct.pack("!H", 1011) + b"lab error"))
                    await writer.drain()
                    break
                writer.write(frame(1, payload))
            elif opcode == 2:
                writer.write(frame(2, b"lab-binary-ack:" + payload))
            await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError):
        # Lab sessions are isolated; malformed clients are closed without console payload logs.
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve(port: int) -> None:
    server = await asyncio.start_server(handle_client, host="127.0.0.1", port=port, limit=32 * 1024)
    actual_port = server.sockets[0].getsockname()[1]
    print(f"WireScope WebSocket lab ready at ws://127.0.0.1:{actual_port}/echo (loopback only; Ctrl+C to stop)")
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1"], help="loopback only; other binds are rejected")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        asyncio.run(serve(args.port))
    except KeyboardInterrupt:
        print("\nStopping local WebSocket lab")


if __name__ == "__main__":
    main()
