from __future__ import annotations

import asyncio
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from types import SimpleNamespace

from .scope import ScopePolicy

from .analysis import analyze_flow
from .paths import secure_file
from .store import Store


class WireScopeAddon:
    """mitmproxy addon that persists HTTP flows and optionally pauses requests."""

    def __init__(self, store: Store, pending: dict[str, Any], pending_lock: threading.RLock,
                 intercept_event: threading.Event, scope: ScopePolicy | None = None):
        self.store = store
        self.scope = scope or ScopePolicy(store)
        self.pending = pending
        self.pending_lock = pending_lock
        self.intercept_event = intercept_event
        self.websocket_flows: dict[str, Any] = {}
        self.websocket_lock = threading.RLock()
        # Body inspection is CPU-bound and must not block mitmproxy's event loop.
        self._analysis_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="WireScopePassiveAnalysis")
        self._analysis_closed = False

    def _analyze_persisted_flow(self, flow_id: str) -> None:
        try:
            saved = self.store.get_flow(flow_id)
            if saved is not None:
                self.store.save_findings(flow_id, analyze_flow(saved))
        except Exception:
            # Analysis must not disturb request forwarding or log captured secrets.
            return

    def close(self) -> None:
        if not self._analysis_closed:
            self._analysis_closed = True
            self._analysis_pool.shutdown(wait=True, cancel_futures=False)

    @staticmethod
    def _headers(headers: Any) -> list[tuple[str, str]]:
        try:
            return [(str(k), str(v)) for k, v in headers.items(multi=True)]
        except TypeError:
            return [(str(k), str(v)) for k, v in headers.items()]

    @staticmethod
    def _bounded_text(value: str | None, limit: int = 1000) -> str | None:
        if value is None:
            return None
        return value[:limit]

    @staticmethod
    def _is_websocket_handshake(request: Any) -> bool:
        try:
            scheme = urlsplit(str(request.url)).scheme.casefold()
        except (ValueError, UnicodeError):
            scheme = ""
        try:
            headers = [(str(k).casefold(), str(v)) for k, v in request.headers.items(multi=True)]
        except TypeError:
            headers = [(str(k).casefold(), str(v)) for k, v in request.headers.items()]
        upgrade = any(k == "upgrade" and v.strip().casefold() == "websocket" for k, v in headers)
        connection_upgrade = any(k == "connection" and "upgrade" in {part.strip().casefold() for part in v.split(",")} for k, v in headers)
        return scheme in {"ws", "wss"} or (upgrade and connection_upgrade)

    def _websocket_allowed(self, flow: Any) -> bool:
        # Check the URL hostname, mitmproxy's normalized Host, and any already-resolved
        # peer before forwarding the handshake. This reuses the same ScopePolicy as Repeater.
        try:
            request = flow.request
            parsed = urlsplit(str(request.url))
            host = str(getattr(request, "host", "") or parsed.hostname or "")
            if not (self.scope.websocket_url_in_scope(str(request.url)) and self.scope.host_in_scope(host)):
                return False
            peer = self._peer_ip(flow)
            return not (peer and self.scope.address_explicitly_excluded(peer))
        except (ValueError, UnicodeError):
            return False

    def _record_websocket_start(self, flow: Any, *, state: str = "open") -> None:
        request = flow.request
        response = getattr(flow, "response", None)
        try:
            parsed = urlsplit(str(request.url))
            scheme = parsed.scheme.casefold()
            host = str(getattr(request, "host", "") or parsed.hostname or "")
        except (ValueError, UnicodeError):
            scheme, host = "", str(getattr(request, "host", "") or "")
        peer = self._peer_ip(flow)
        self.store.start_websocket(
            connection_id=str(flow.id), flow_id=str(flow.id), url=str(request.url), host=host,
            scheme=scheme, started_at=float(getattr(request, "timestamp_start", None) or time.time()),
            request_headers=self._headers(getattr(request, "headers", {})),
            response_headers=self._headers(getattr(response, "headers", {})) if response else [],
            handshake_status=getattr(response, "status_code", None) if response else None,
            remote_ip=peer, state=state,
        )

    @staticmethod
    def _peer_ip(flow: Any) -> str | None:
        server = getattr(flow, "server_conn", None)
        if server is None:
            return None
        candidate = getattr(server, "ip_address", None) or getattr(server, "peername", None)
        if isinstance(candidate, tuple):
            candidate = candidate[0] if candidate else None
        if candidate is None:
            # `address` can be a hostname before DNS resolution. Only keep it when it is an IP.
            address = getattr(server, "address", None)
            candidate = address[0] if isinstance(address, tuple) and address else address
        try:
            import ipaddress
            return str(ipaddress.ip_address(str(candidate))) if candidate else None
        except ValueError:
            return None

    @staticmethod
    def _block_response() -> Any:
        try:
            from mitmproxy import http
            return http.Response.make(403, b"WebSocket handshake rejected by WireScope scope policy.\n", {"Content-Type": "text/plain; charset=utf-8"})
        except ImportError:  # permits addon unit tests without the optional proxy runtime installed
            return SimpleNamespace(status_code=403, headers={}, raw_content=b"WebSocket handshake rejected by WireScope scope policy.\n", timestamp_end=time.time())

    def request(self, flow: Any) -> None:
        intercepted = self.intercept_event.is_set()
        is_websocket = self._is_websocket_handshake(flow.request)
        with self.pending_lock:
            self.pending[flow.id] = flow
        self.store.record_request(
            flow_id=flow.id,
            started_at=float(getattr(flow.request, "timestamp_start", None) or time.time()),
            method=flow.request.method,
            url=flow.request.url,
            host=flow.request.host,
            path=flow.request.path,
            headers=self._headers(flow.request.headers),
            body=flow.request.raw_content,
            intercepted=intercepted,
        )
        if is_websocket:
            # Do not show a connection as open until mitmproxy confirms the WebSocket handshake.
            # Persist rejected attempts too, but never route them upstream.
            if not self._websocket_allowed(flow):
                self._record_websocket_start(flow, state="connecting")
                self.store.finish_websocket(flow.id, state="rejected", error="WebSocket target is outside configured scope")
                metadata = getattr(flow, "metadata", None)
                if isinstance(metadata, dict):
                    metadata["wirescope_terminal_error"] = "WebSocket target is outside configured scope"
                flow.response = self._block_response()
                with self.pending_lock:
                    self.pending.pop(flow.id, None)
                return
            self._record_websocket_start(flow, state="connecting")
        if intercepted:
            flow.intercept()
        with self.pending_lock:
            self.pending[flow.id] = flow

    def response(self, flow: Any) -> None:
        response = flow.response
        start = getattr(flow.request, "timestamp_start", None)
        end = getattr(response, "timestamp_end", None)
        duration = int(max(0.0, end - start) * 1000) if start and end else None
        self.store.record_response(
            flow_id=flow.id,
            status=getattr(response, "status_code", None),
            headers=self._headers(response.headers) if response else [],
            body=response.raw_content if response else b"",
            duration_ms=duration,
            error=None,
        )
        connection = self.store.get_websocket_connection(str(flow.id))
        status_code = getattr(response, "status_code", None) if response else None
        if connection and connection.get("state") == "connecting" and status_code != 101:
            self.store.finish_websocket(str(flow.id), state="error", error=f"WebSocket handshake rejected with HTTP {status_code}")
        if not self._analysis_closed:
            try:
                self._analysis_pool.submit(self._analyze_persisted_flow, flow.id)
            except RuntimeError:
                pass
        with self.pending_lock:
            self.pending.pop(flow.id, None)

    def _websocket_flows_for_server(self, server_conn: Any) -> list[Any]:
        with self.pending_lock:
            return [
                flow for flow in self.pending.values()
                if getattr(flow, "server_conn", None) is server_conn
                and self._is_websocket_handshake(flow.request)
            ]

    def _reject_websocket_flows(self, flows: list[Any], reason: str, *, kill_flow: bool) -> None:
        """Persist a fail-closed scope decision without logging request or frame contents."""
        for flow in flows:
            flow_id = str(flow.id)
            try:
                self.store.finish_websocket(flow_id, state="rejected", error=reason)
                self.store.record_response(
                    flow_id=flow_id, status=None, headers=[], body=b"", duration_ms=None, error=reason,
                )
            except Exception:
                # Store failure must not cause an explicitly excluded upgrade to be forwarded.
                pass
            metadata = getattr(flow, "metadata", None)
            if isinstance(metadata, dict):
                metadata["wirescope_terminal_error"] = reason
            with self.pending_lock:
                self.pending.pop(flow_id, None)
            if kill_flow:
                try:
                    flow.kill()
                except Exception:
                    pass

    def server_connect(self, data: Any) -> None:
        """Reject a prohibited WebSocket destination before opening its upstream socket.

        Mitmproxy calls this hook immediately before connecting. At this point the
        destination may still be a hostname. We can reliably preflight literal IP
        addresses and the actual authority chosen by mitmproxy; DNS-only IP rules
        are checked again by server_connected once the resolved peer is available.
        """
        server_conn = getattr(data, "server", data)
        flows = self._websocket_flows_for_server(server_conn)
        if not flows:
            return
        address = getattr(server_conn, "address", None)
        host = address[0] if isinstance(address, (tuple, list)) and address else ""
        if not host:
            if self.scope.has_explicit_exclusions():
                reason = "Cannot verify the upstream WebSocket peer against explicit scope exclusions"
                try:
                    server_conn.error = reason
                except Exception:
                    pass
                self._reject_websocket_flows(flows, reason, kill_flow=False)
            return
        # Check the actual destination authority as well as the URL and Host header
        # checked during request(). This prevents a proxy authority mismatch bypass.
        try:
            normalized = self.scope.normalize_host(str(host))
            if not normalized or not self.scope.host_in_scope(str(host)):
                reason = "Upstream WebSocket destination is outside configured scope"
            else:
                import ipaddress
                try:
                    ipaddress.ip_address(normalized)
                except ValueError:
                    reason = ""
                else:
                    reason = (
                        "Upstream WebSocket IP matches an explicit scope exclusion"
                        if self.scope.address_explicitly_excluded(normalized) else ""
                    )
        except (ValueError, UnicodeError):
            reason = "Cannot validate the upstream WebSocket destination"
        if reason:
            try:
                # Setting Server.error is mitmproxy's documented pre-connect abort path.
                server_conn.error = reason
            except Exception:
                pass
            self._reject_websocket_flows(flows, reason, kill_flow=False)

    def server_connect_error(self, data: Any) -> None:
        """Persist upstream connect failures for pending WebSocket upgrades when available."""
        server_conn = getattr(data, "server", data)
        reason = self._bounded_text(str(getattr(server_conn, "error", None) or "Upstream connection failed"))
        with self.pending_lock:
            candidates = [
                flow for flow in self.pending.values()
                if getattr(flow, "server_conn", None) is server_conn
                and self._is_websocket_handshake(flow.request)
            ]
        for flow in candidates:
            connection = self.store.get_websocket_connection(str(flow.id))
            if connection is not None and connection.get("state") == "connecting":
                self.store.finish_websocket(str(flow.id), state="error", error=reason)
                self.store.record_response(
                    flow_id=flow.id, status=None, headers=[], body=b"", duration_ms=None, error=reason,
                )
            with self.pending_lock:
                self.pending.pop(str(flow.id), None)

    def server_connected(self, data: Any) -> None:
        """Reject a WS flow before its HTTP upgrade is sent if DNS resolved to an excluded IP.

        mitmproxy's connection hook receives ServerConnectionHookData, whose ``server``
        attribute is the actual ServerConnection. This event runs after TCP connect but
        before forwarding the HTTP request to the peer. This is a second, resolved-address
        check in addition to the hostname check in request(); no upgrade bytes have been sent.
        """
        server_conn = getattr(data, "server", data)
        candidates = self._websocket_flows_for_server(server_conn)
        if not candidates:
            return
        peer = self._peer_ip(SimpleNamespace(server_conn=server_conn))
        if peer and self.scope.address_explicitly_excluded(peer):
            reason = "Resolved peer address matches an explicit scope exclusion"
        elif peer is None and self.scope.has_explicit_exclusions():
            # For active protocols, an unverifiable peer must not be allowed through
            # if the operator has configured exclusions. This is conservative for
            # upstream-proxy modes where mitmproxy may not expose the final peer.
            reason = "Resolved WebSocket peer is unavailable; cannot verify explicit scope exclusions"
        else:
            return
        for flow in candidates:
            # Capture the resolved endpoint where available without changing payloads.
            self._record_websocket_start(flow, state="connecting")
        self._reject_websocket_flows(candidates, reason, kill_flow=True)

    def websocket_start(self, flow: Any) -> None:
        """Capture the completed handshake and retain only the live in-memory flow reference."""
        self._record_websocket_start(flow)
        peer = self._peer_ip(flow)
        if peer and self.scope.address_explicitly_excluded(peer):
            self.store.finish_websocket(
                str(flow.id), state="rejected", error="Resolved peer address matches an explicit scope exclusion"
            )
            try:
                flow.kill()
            except Exception:
                pass
            return
        with self.websocket_lock:
            self.websocket_flows[str(flow.id)] = flow

    def websocket_message(self, flow: Any) -> None:
        websocket = getattr(flow, "websocket", None)
        messages = getattr(websocket, "messages", None) if websocket is not None else None
        if not messages:
            return
        message = messages[-1]
        # Injected frames are stored atomically by send_websocket_message so they cannot be duplicated.
        if bool(getattr(message, "injected", False)):
            return
        opcode = int(getattr(message, "type", 1))
        if opcode not in {1, 2}:
            return
        raw = bytes(getattr(message, "content", b"") or b"")
        try:
            self._record_websocket_start(flow)
            self.store.append_websocket_message(
                connection_id=str(flow.id), timestamp=float(getattr(message, "timestamp", None) or time.time()),
                direction="client_to_server" if bool(getattr(message, "from_client", False)) else "server_to_client",
                opcode=opcode, payload=raw, source="captured",
            )
        except Exception:
            # Capture failures must never disrupt application traffic or log payload bytes.
            return

    def websocket_end(self, flow: Any) -> None:
        websocket = getattr(flow, "websocket", None)
        close_code = getattr(websocket, "close_code", None) if websocket else None
        close_reason = getattr(websocket, "close_reason", None) if websocket else None
        self.store.finish_websocket(
            str(flow.id), state="closed", ended_at=getattr(websocket, "timestamp_end", None) or time.time(),
            close_code=close_code, close_reason=close_reason,
        )
        with self.websocket_lock:
            self.websocket_flows.pop(str(flow.id), None)

    def error(self, flow: Any) -> None:
        metadata = getattr(flow, "metadata", None)
        terminal_reason = metadata.get("wirescope_terminal_error") if isinstance(metadata, dict) else None
        error = getattr(flow, "error", None)
        message = self._bounded_text(terminal_reason or getattr(error, "msg", None) or str(error or "Proxy error"))
        connection = self.store.get_websocket_connection(str(flow.id))
        if connection is None or connection.get("state") == "connecting":
            # A failed HTTP upgrade has no successful response to preserve.
            self.store.record_response(
                flow_id=flow.id,
                status=None,
                headers=[],
                body=b"",
                duration_ms=None,
                error=message,
            )
        if connection is not None:
            terminal_state = "rejected" if terminal_reason and "scope" in terminal_reason.casefold() else "error"
            self.store.finish_websocket(str(flow.id), state=terminal_state, error=message)
            with self.websocket_lock:
                self.websocket_flows.pop(str(flow.id), None)
        with self.pending_lock:
            self.pending.pop(flow.id, None)
        if self.store.get_websocket_connection(str(flow.id)) is not None:
            self.store.finish_websocket(str(flow.id), state="error", error=message)
            with self.websocket_lock:
                self.websocket_flows.pop(str(flow.id), None)

    def shutdown_websockets(self) -> None:
        with self.websocket_lock:
            active = list(self.websocket_flows.keys())
            self.websocket_flows.clear()
        for connection_id in active:
            self.store.finish_websocket(connection_id, state="interrupted", error="Proxy stopped before WebSocket close was observed")
        # Also mark handshakes still in flight, which have no active WebSocket handle yet.
        self.store.mark_websockets_interrupted("Proxy stopped before WebSocket handshake/close was observed")


class ProxyService:
    """Owns a mitmproxy instance on a dedicated event-loop thread."""

    def __init__(self, store: Store, data_directory: Path, *, upstream_insecure: bool = False, scope: ScopePolicy | None = None):
        self.store = store
        self.scope = scope or ScopePolicy(store)
        self.data_directory = Path(data_directory)
        self.confdir = self.data_directory / "mitmproxy"
        self.confdir.mkdir(parents=True, exist_ok=True)
        self.confdir.chmod(0o700) if __import__("os").name != "nt" else None
        self.ca_cert_path = self.confdir / "mitmproxy-ca-cert.pem"
        self.upstream_insecure = upstream_insecure  # test/lab switch; production default is False.
        self.pending: dict[str, Any] = {}
        self.pending_lock = threading.RLock()
        self.intercept_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master: Any = None
        self._started = threading.Event()
        self._stopped = threading.Event()
        self._error: str | None = None
        self._host = "127.0.0.1"
        self._port = 8080
        self._addon: WireScopeAddon | None = None
        self._state_lock = threading.RLock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._started.is_set() and self._error is None

    @property
    def intercept_enabled(self) -> bool:
        return self.intercept_event.is_set()

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "host": self._host,
            "port": self._port,
            "intercept_enabled": self.intercept_enabled,
            "pending_count": self.pending_count(),
            "ca_available": self.ca_cert_path.is_file(),
            "ca_path": str(self.ca_cert_path),
            "error": self._error,
        }

    def pending_count(self) -> int:
        with self.pending_lock:
            return sum(1 for flow in self.pending.values() if getattr(flow, "intercepted", False))

    def start(self, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
        # Do not accept network-facing binds: the UI always exposes a local-only proxy.
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("WireScope proxy must bind to loopback only")
        if not 1 <= int(port) <= 65535:
            raise ValueError("port must be between 1 and 65535")
        with self._state_lock:
            if self.running:
                return self.status()
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError(self._error or "Proxy is still stopping")
            # Fail fast if the selected loopback port is already occupied.
            family = socket.AF_INET6 if host == "::1" else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                try:
                    probe.bind((host, int(port)))
                except OSError as exc:
                    raise RuntimeError(f"Cannot bind proxy to {host}:{port}: {exc}") from exc
            self._host, self._port = host, int(port)
            self._error = None
            self._started.clear()
            self._stopped.clear()
            self._thread = threading.Thread(target=self._thread_main, name="WireScopeProxy", daemon=True)
            self._thread.start()
        if not self._started.wait(8):
            self.stop()
            raise RuntimeError("Proxy did not start within 8 seconds")
        if self._error:
            raise RuntimeError(self._error)
        # DumpMaster signals its worker lifecycle before the server socket is necessarily accepting.
        # Wait for the actual listener rather than showing a false-positive "running" state.
        deadline = time.monotonic() + 6
        address = "::1" if host == "localhost" else host
        while time.monotonic() < deadline:
            if self._error:
                raise RuntimeError(self._error)
            try:
                with socket.create_connection((address, int(port)), timeout=0.15):
                    return self.status()
            except OSError:
                if self._thread is not None and not self._thread.is_alive():
                    raise RuntimeError(self._error or "Proxy worker exited before the listener became available")
                time.sleep(0.05)
        self.stop()
        raise RuntimeError(f"Proxy listener did not open on {host}:{port}")

    def _thread_main(self) -> None:
        try:
            from mitmproxy import options
            from mitmproxy.tools.dump import DumpMaster

            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            opts = options.Options(
                listen_host=self._host,
                listen_port=self._port,
                confdir=str(self.confdir),
                ssl_insecure=self.upstream_insecure,
            )
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self._master = master
            self._addon = WireScopeAddon(self.store, self.pending, self.pending_lock, self.intercept_event, self.scope)
            master.addons.add(self._addon)
            self._started.set()
            self._loop.run_until_complete(master.run())
        except Exception as exc:  # surfaced to the UI rather than hidden in a worker thread
            self._error = f"{type(exc).__name__}: {exc}"
            self._started.set()
        finally:
            if self._addon is not None:
                self._addon.shutdown_websockets()
                self._addon.close()
            self._stopped.set()
            if self._loop and not self._loop.is_closed():
                try:
                    self._loop.close()
                except Exception:
                    pass
            self._master = None

    def stop(self) -> None:
        with self._state_lock:
            master, loop, thread = self._master, self._loop, self._thread
            if master is not None and loop is not None and loop.is_running():
                def shutdown_on_proxy_loop() -> None:
                    try:
                        with self.pending_lock:
                            pending = list(self.pending.items())
                        for flow_id, flow in pending:
                            if not getattr(flow, "intercepted", False):
                                continue
                            metadata = getattr(flow, "metadata", None)
                            if isinstance(metadata, dict):
                                metadata["wirescope_terminal_error"] = "Proxy stopped while request was paused"
                            try:
                                # Fail closed: never forward a paused request as a side effect of stopping.
                                flow.resume()
                                flow.kill()
                            except Exception:
                                pass
                            self.store.record_response(
                                flow_id=flow_id, status=None, headers=[], body=b"",
                                duration_ms=None, error="Proxy stopped while request was paused",
                            )
                    finally:
                        with self.pending_lock:
                            self.pending.clear()
                        master.shutdown()
                loop.call_soon_threadsafe(shutdown_on_proxy_loop)
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=5)
        self.intercept_event.clear()

    def set_intercept(self, enabled: bool) -> dict[str, Any]:
        if enabled:
            self.intercept_event.set()
        else:
            self.intercept_event.clear()
        return self.status()

    def _dispatch_flow(self, flow_id: str, action: str, replacement: dict[str, Any] | None = None) -> None:
        with self.pending_lock:
            flow = self.pending.get(flow_id)
        if flow is None:
            raise KeyError("Flow is no longer pending; refresh the queue")
        loop = self._loop
        if loop is None or not loop.is_running():
            raise RuntimeError("Proxy event loop is not running")
        done = threading.Event()
        result: list[BaseException] = []

        def operation() -> None:
            try:
                if action == "drop":
                    # Wake an intercepted flow first, then mark it killed before the proxy
                    # event loop can advance the request to its upstream connection.
                    metadata = getattr(flow, "metadata", None)
                    if isinstance(metadata, dict):
                        metadata["wirescope_terminal_error"] = "Dropped by user"
                    if getattr(flow, "intercepted", False):
                        flow.resume()
                    flow.kill()
                    self.store.record_response(
                        flow_id=flow_id, status=None, headers=[], body=b"",
                        duration_ms=None, error="Dropped by user",
                    )
                    with self.pending_lock:
                        self.pending.pop(flow_id, None)
                else:
                    if replacement is not None:
                        request = flow.request
                        request.method = replacement["method"]
                        request.url = replacement["url"]
                        request.headers.clear()
                        request.headers.extend(replacement["headers"])
                        request.content = replacement["body"]
                        # Keep the persisted history in sync with the exact bytes sent.
                        self.store.record_request(
                            flow_id=flow_id,
                            started_at=float(getattr(request, "timestamp_start", None) or time.time()),
                            method=request.method,
                            url=request.url,
                            host=request.host,
                            path=request.path,
                            headers=self._addon._headers(request.headers) if self._addon else [],
                            body=request.raw_content,
                            intercepted=False,
                        )
                    else:
                        self.store.set_intercepted(flow_id, False)
                    flow.resume()
            except BaseException as exc:
                result.append(exc)
            finally:
                done.set()

        loop.call_soon_threadsafe(operation)
        if not done.wait(5):
            raise TimeoutError("Proxy flow action timed out")
        if result:
            raise RuntimeError(str(result[0]))

    def forward(self, flow_id: str, replacement: dict[str, Any] | None = None) -> None:
        self._dispatch_flow(flow_id, "forward", replacement)

    def drop(self, flow_id: str) -> None:
        self._dispatch_flow(flow_id, "drop")

    def send_websocket_message(self, connection_id: str, payload: bytes, *, is_text: bool = True) -> dict[str, Any]:
        if not isinstance(payload, (bytes, bytearray)):
            raise ValueError("Payload must be bytes")
        raw = bytes(payload)
        if len(raw) > self.store.max_ws_message_bytes:
            raise ValueError(f"Message exceeds the configured {self.store.max_ws_message_bytes}-byte limit")
        addon = self._addon
        loop = self._loop
        master = self._master
        if addon is None or loop is None or not loop.is_running() or master is None:
            raise RuntimeError("The proxy is not running; no established WebSocket can be used")
        with addon.websocket_lock:
            flow = addon.websocket_flows.get(str(connection_id))
        if flow is None:
            raise KeyError("WebSocket is not active; select an established connection")
        connection = self.store.get_websocket_connection(str(connection_id))
        if connection is None or connection.get("state") != "open":
            raise RuntimeError("WebSocket connection is no longer open")
        websocket = getattr(flow, "websocket", None)
        if websocket is None or getattr(websocket, "timestamp_end", None) is not None:
            self.store.finish_websocket(str(connection_id), state="interrupted", error="Connection is no longer active")
            with addon.websocket_lock:
                addon.websocket_flows.pop(str(connection_id), None)
            raise RuntimeError("WebSocket connection is closed or interrupted")
        request = flow.request
        url = str(getattr(request, "url", ""))
        host = str(getattr(request, "host", "") or "")
        if not self.scope.websocket_url_in_scope(url) or not self.scope.host_in_scope(host):
            raise PermissionError("WebSocket target is out of scope; no message was sent")
        peer = addon._peer_ip(flow)
        if peer and self.scope.address_explicitly_excluded(peer):
            raise PermissionError("Resolved WebSocket peer matches an explicit scope exclusion")
        if peer is None and self.scope.has_explicit_exclusions():
            raise PermissionError("Cannot verify the WebSocket peer against configured scope exclusions")
        done = threading.Event()
        result: list[BaseException] = []

        def operation() -> None:
            try:
                if getattr(websocket, "timestamp_end", None) is not None:
                    raise RuntimeError("WebSocket closed before the message could be sent")
                # `to_client=False` sends from WireScope's client side to the server.
                master.commands.call("inject.websocket", flow, False, raw, bool(is_text))
                addon.store.append_websocket_message(
                    connection_id=str(connection_id), timestamp=time.time(), direction="client_to_server",
                    opcode=1 if is_text else 2, payload=raw, source="user",
                )
            except BaseException as exc:
                result.append(exc)
            finally:
                done.set()

        loop.call_soon_threadsafe(operation)
        if not done.wait(5):
            raise TimeoutError("WebSocket send timed out")
        if result:
            raise RuntimeError(f"WebSocket send failed: {type(result[0]).__name__}") from result[0]
        return {"status": "sent", "connection_id": str(connection_id), "payload_bytes": len(raw), "opcode": 1 if is_text else 2, "source": "user"}

    def close(self) -> None:
        self.stop()
        self.store.close()
