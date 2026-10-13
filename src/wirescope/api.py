from __future__ import annotations

import asyncio
import base64
import secrets
import binascii
import base64 as b64
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .analysis import analyze_flow
from .comparer import CompareError, compare
from .proxy import ProxyService
from .repeater import RepeaterClient, RepeaterError, parse_raw_request
from .scope import ScopePolicy
from .store import Store
from .transforms import TransformError, transform

STATIC_DIR = Path(__file__).with_name("static")


class ProxyStartRequest(BaseModel):
    port: int = Field(default=8080, ge=1, le=65535)


class InterceptRequest(BaseModel):
    enabled: bool


class ForwardRequest(BaseModel):
    raw_request: str | None = None


class RepeaterSendRequest(BaseModel):
    raw_request: str = Field(min_length=1, max_length=2 * 1024 * 1024)
    timeout: int = Field(default=10, ge=1, le=30)


class ScopeRuleRequest(BaseModel):
    pattern: str = Field(min_length=1, max_length=253)
    mode: str = Field(pattern="^(include|exclude)$")


class TransformRequest(BaseModel):
    operation: str = Field(min_length=1, max_length=40)
    value: str = Field(max_length=2 * 1024 * 1024)


class CompareRequest(BaseModel):
    left: str = Field(max_length=2 * 1024 * 1024)
    right: str = Field(max_length=2 * 1024 * 1024)
    mode: str = Field(default="text", min_length=1, max_length=20)


class FindingStatusRequest(BaseModel):
    status: str = Field(pattern="^(open|false_positive|resolved)$")


class WebSocketSendRequest(BaseModel):
    # Binary messages are Base64 encoded in the local API to preserve exact bytes.
    payload: str = Field(max_length=1_400_000)
    binary: bool = False


def _analyze_existing_flow(store: Store, flow_id: str) -> None:
    """Background task for previously captured responses; no additional network traffic."""
    try:
        flow = store.get_flow(flow_id)
        if flow is not None:
            store.save_findings(flow_id, analyze_flow(flow))
    except Exception:
        # Never log response contents or analysis evidence.
        return


def _as_public_flow(flow: dict[str, Any], detail: bool = False) -> dict[str, Any]:
    safe = {k: v for k, v in flow.items() if k not in {"request_body", "response_body", "request_headers", "response_headers"}}
    safe["intercepted"] = bool(safe.get("intercepted", False))
    if detail:
        req = flow.get("request_body", b"") or b""
        res = flow.get("response_body", b"") or b""
        safe.update({
            "request_headers": flow.get("request_headers", []),
            "response_headers": flow.get("response_headers", []),
            "request_body_text": req.decode("utf-8", errors="replace"),
            "response_body_text": res.decode("utf-8", errors="replace"),
            "request_body_base64": base64.b64encode(req).decode("ascii"),
            "response_body_base64": base64.b64encode(res).decode("ascii"),
            "request_body_bytes": len(req),
            "response_body_bytes": len(res),
        })
    return safe


def _public_websocket_connection(connection: dict[str, Any], *, detail: bool = False) -> dict[str, Any]:
    """Redact URL userinfo and query values in workspace listings; headers remain available in detail."""
    import json as _json
    from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

    safe = dict(connection)
    try:
        parts = urlsplit(str(safe.get("url", "")))
        hostname = (parts.hostname or "").casefold().rstrip(".")
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = f":{parts.port}" if parts.port is not None else ""
        query = "&".join(f"{quote(key, safe='')}=[REDACTED]" for key, _ in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=256))
        safe["url"] = urlunsplit((parts.scheme.casefold(), hostname + port, parts.path or "/", query, ""))
        safe["url_has_credentials"] = parts.username is not None or parts.password is not None
    except (ValueError, UnicodeError):
        safe["url"] = "[invalid URL]"
        safe["url_has_credentials"] = True
    if not detail:
        safe.pop("request_headers", None)
        safe.pop("response_headers", None)
    else:
        for key in ("request_headers", "response_headers"):
            value = safe.get(key, "[]")
            try:
                if isinstance(value, str):
                    value = _json.loads(value)
                safe[key] = value if isinstance(value, list) else []
            except (TypeError, _json.JSONDecodeError):
                safe[key] = []
    return safe


def _public_websocket_message(message: dict[str, Any], *, detail: bool = False) -> dict[str, Any]:
    import base64
    import binascii
    safe = {key: value for key, value in message.items() if key != "payload"}
    if detail:
        raw = bytes(message.get("payload", b"") or b"")
        safe["payload_base64"] = base64.b64encode(raw).decode("ascii")
        safe["payload_hex"] = raw.hex()
        try:
            safe["payload_text"] = raw.decode("utf-8", errors="strict") if int(message.get("opcode", 1)) == 1 else None
        except UnicodeDecodeError:
            safe["payload_text"] = None
            safe["text_decode_error"] = True
    return safe


def _auth_dependency(expected_token: str):
    async def require_token(x_wirescope_token: Annotated[str | None, Header()] = None) -> None:
        if not x_wirescope_token or not secrets.compare_digest(x_wirescope_token, expected_token):
            raise HTTPException(status_code=403, detail="Missing or invalid local session token")
    return require_token


def _validate_scope_pattern(pattern: str) -> str:
    value = pattern.strip().rstrip(".").lower()
    if not value or len(value) > 253:
        raise ValueError("Scope pattern must contain 1–253 characters")
    if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789.*?-:_" for ch in value):
        raise ValueError("Use only hostname characters and * or ? wildcards")
    if not any(ch.isalnum() for ch in value) or value in {"*.*", "*.*.*"}:
        raise ValueError("Wildcard scope must identify at least one hostname label")
    if value.startswith(".") or value.endswith(".") or ".." in value:
        raise ValueError("Invalid hostname pattern")
    return value


def create_app(store: Store, proxy: ProxyService, scope: ScopePolicy, repeater: RepeaterClient) -> FastAPI:
    app = FastAPI(title="WireScope local API", docs_url=None, redoc_url=None, openapi_url=None)
    token = secrets.token_urlsafe(32)
    app.state.session_token = token
    app.state.store = store
    app.state.proxy = proxy
    api_auth = _auth_dependency(token)

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @app.get("/api/session", include_in_schema=False)
    async def session() -> dict[str, str]:
        return {"token": token, "app": "WireScope"}

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/api/status", dependencies=[Depends(api_auth)])
    async def status() -> dict[str, Any]:
        return proxy.status()

    @app.post("/api/proxy/start", dependencies=[Depends(api_auth)])
    async def start_proxy(payload: ProxyStartRequest) -> dict[str, Any]:
        try:
            return proxy.start("127.0.0.1", payload.port)
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/proxy/stop", dependencies=[Depends(api_auth)])
    async def stop_proxy() -> dict[str, bool]:
        proxy.stop()
        return {"stopped": True}

    @app.post("/api/proxy/intercept", dependencies=[Depends(api_auth)])
    async def set_intercept(payload: InterceptRequest) -> dict[str, Any]:
        return proxy.set_intercept(payload.enabled)

    @app.get("/api/ca", dependencies=[Depends(api_auth)])
    async def get_ca() -> FileResponse:
        if not proxy.ca_cert_path.is_file():
            raise HTTPException(status_code=404, detail="CA certificate is created when the proxy starts for the first time")
        return FileResponse(proxy.ca_cert_path, filename="wirescope-ca-cert.pem", media_type="application/x-pem-file")

    @app.get("/api/flows", dependencies=[Depends(api_auth)])
    async def list_flows(
        search: str = Query(default="", max_length=300),
        limit: int = Query(default=300, ge=1, le=1000),
        intercepted: bool | None = None,
    ) -> list[dict[str, Any]]:
        rows = await asyncio.to_thread(store.list_flows, search=search, limit=limit, intercepted=intercepted)
        return [_as_public_flow(row) for row in rows]

    @app.get("/api/flows/{flow_id}", dependencies=[Depends(api_auth)])
    async def get_flow(flow_id: str) -> dict[str, Any]:
        row = await asyncio.to_thread(store.get_flow, flow_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Flow not found")
        return _as_public_flow(row, detail=True)

    @app.post("/api/flows/{flow_id}/forward", dependencies=[Depends(api_auth)])
    async def forward_flow(flow_id: str, payload: ForwardRequest) -> dict[str, str]:
        replacement = None
        if payload.raw_request is not None:
            try:
                parsed = parse_raw_request(payload.raw_request)
                replacement = {"method": parsed.method, "url": parsed.url,
                               "headers": parsed.headers, "body": parsed.body}
            except RepeaterError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            proxy.forward(flow_id, replacement)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (RuntimeError, TimeoutError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": "forwarded"}

    @app.post("/api/flows/{flow_id}/drop", dependencies=[Depends(api_auth)])
    async def drop_flow(flow_id: str) -> dict[str, str]:
        try:
            proxy.drop(flow_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (RuntimeError, TimeoutError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": "dropped"}

    @app.post("/api/repeater/send", dependencies=[Depends(api_auth)])
    async def send_repeater(payload: RepeaterSendRequest) -> dict[str, Any]:
        try:
            return repeater.send(payload.raw_request, payload.timeout)
        except RepeaterError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            # Never return stack traces or credential-bearing internals to the UI.
            raise HTTPException(status_code=502, detail=f"Request failed: {type(exc).__name__}: {str(exc)[:240]}") from exc

    @app.get("/api/scope", dependencies=[Depends(api_auth)])
    async def list_scope() -> dict[str, Any]:
        return {"rules": store.list_scope_rules(), "loopback_default_in_scope": True, "explicit_exclusions_override_loopback": True}

    @app.post("/api/scope", dependencies=[Depends(api_auth)])
    async def add_scope(payload: ScopeRuleRequest) -> dict[str, Any]:
        try:
            pattern = _validate_scope_pattern(payload.pattern)
            return store.add_scope_rule(pattern, payload.mode)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(status_code=409, detail="That scope rule already exists") from exc
            raise

    @app.delete("/api/scope/{rule_id}", dependencies=[Depends(api_auth)])
    async def delete_scope(rule_id: int) -> dict[str, bool]:
        if not store.delete_scope_rule(rule_id):
            raise HTTPException(status_code=404, detail="Scope rule not found")
        return {"deleted": True}

    @app.get("/api/sitemap", dependencies=[Depends(api_auth)])
    async def site_map(
        search: str = Query(default="", max_length=300),
        host: str = Query(default="", max_length=253),
        method: str = Query(default="", max_length=20),
        content_type: str = Query(default="", max_length=100),
        status_filter: str = Query(default="", alias="status", pattern="^(|[1-5]xx|[1-5][0-9]{2})$"),
        scope_filter: str = Query(default="all", alias="scope", pattern="^(all|in_scope|out_of_scope)$"),
        limit: int = Query(default=1000, ge=1, le=2000),
    ) -> dict[str, Any]:
        entries = await asyncio.to_thread(
            store.list_site_map, search=search, host=host, method=method,
            content_type=content_type, status=status_filter, limit=limit,
        )
        scope_cache: dict[str, bool] = {}
        for entry in entries:
            # ScopePolicy remains the sole matching implementation. Cache by hostname to
            # avoid re-reading scope rules for every path on the same host.
            hostname = entry["host"]
            if hostname not in scope_cache:
                scope_cache[hostname] = scope.url_in_scope(entry["url"])
            entry["in_scope"] = False if entry.get("url_has_credentials") else scope_cache[hostname]
        if scope_filter == "in_scope":
            entries = [entry for entry in entries if entry["in_scope"]]
        elif scope_filter == "out_of_scope":
            entries = [entry for entry in entries if not entry["in_scope"]]
        return {"entries": entries, "count": len(entries), "source": "persisted captured traffic only"}

    @app.get("/api/sitemap/endpoint", dependencies=[Depends(api_auth)])
    async def site_map_endpoint(
        origin: str = Query(min_length=8, max_length=2048),
        path: str = Query(min_length=1, max_length=8192),
        method: str = Query(default="", max_length=20),
        limit: int = Query(default=20, ge=1, le=50),
    ) -> dict[str, Any]:
        try:
            parsed_origin = urlsplit(origin)
            if (parsed_origin.scheme.casefold() not in {"http", "https"}
                    or not parsed_origin.hostname
                    or parsed_origin.username is not None or parsed_origin.password is not None
                    or parsed_origin.path not in {"", "/"}
                    or parsed_origin.query or parsed_origin.fragment):
                raise ValueError("origin must be a plain HTTP or HTTPS origin without credentials, path, query, or fragment")
            hostname = parsed_origin.hostname.casefold().rstrip(".")
            host_display = f"[{hostname}]" if ":" in hostname else hostname
            port = parsed_origin.port
            safe_origin = f"{parsed_origin.scheme.casefold()}://{host_display}{':' + str(port) if port is not None else ''}"
            items = await asyncio.to_thread(store.list_endpoint_flows, origin=safe_origin, path=path, method=method, limit=limit)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        # Site Map previews show endpoint paths and dates but omit captured query values
        # and URL userinfo. Full request data remains available only after the user opens
        # the specific capture in HTTP History.
        for item in items:
            parsed = urlsplit(str(item.get("url") or ""))
            item["url"] = f"{safe_origin}{parsed.path or '/'}"
            item["path"] = parsed.path or "/"
        return {"flows": items, "count": len(items)}

    @app.get("/api/findings", dependencies=[Depends(api_auth)])
    async def list_findings(
        search: str = Query(default="", max_length=300),
        severity: str = Query(default="", pattern="^(|info|low|medium|high|critical)$"),
        status_filter: str = Query(default="", alias="status", pattern="^(|open|false_positive|resolved)$"),
        limit: int = Query(default=500, ge=1, le=1000),
    ) -> dict[str, Any]:
        rows = await asyncio.to_thread(store.list_findings, search=search, severity=severity, status=status_filter, limit=limit)
        return {"findings": rows, "count": len(rows)}

    @app.get("/api/findings/{finding_id}", dependencies=[Depends(api_auth)])
    async def get_finding(finding_id: str) -> dict[str, Any]:
        value = await asyncio.to_thread(store.get_finding, finding_id)
        if value is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return value

    @app.post("/api/findings/{finding_id}/status", dependencies=[Depends(api_auth)])
    async def update_finding_status(finding_id: str, payload: FindingStatusRequest) -> dict[str, Any]:
        try:
            changed = store.update_finding_status(finding_id, payload.status)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not changed:
            raise HTTPException(status_code=404, detail="Finding not found")
        return {"id": finding_id, "status": payload.status}

    @app.post("/api/findings/reanalyze", dependencies=[Depends(api_auth)])
    async def reanalyze_findings(background_tasks: BackgroundTasks, limit: int = Query(default=1000, ge=1, le=1000)) -> dict[str, Any]:
        flow_ids = await asyncio.to_thread(store.list_flows_for_analysis, limit=limit)
        for flow_id in flow_ids:
            background_tasks.add_task(_analyze_existing_flow, store, flow_id)
        return {"queued": len(flow_ids), "message": "Passive analysis queued for captured responses only; no network requests will be sent."}

    @app.post("/api/tools/transform", dependencies=[Depends(api_auth)])
    async def transform_text(payload: TransformRequest) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(transform, payload.operation, payload.value)
        except TransformError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/tools/compare", dependencies=[Depends(api_auth)])
    async def compare_text(payload: CompareRequest) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(compare, payload.left, payload.right, payload.mode)
        except CompareError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/websockets/config", dependencies=[Depends(api_auth)])
    async def websocket_config() -> dict[str, int]:
        return {
            "max_message_bytes": store.max_ws_message_bytes,
            "max_message_count": store.max_ws_messages,
            "max_storage_bytes": store.max_ws_storage_bytes,
        }

    @app.get("/api/websockets/connections", dependencies=[Depends(api_auth)])
    async def list_websocket_connections(
        search: str = Query(default="", max_length=200),
        state_filter: str = Query(default="", alias="state", pattern="^(|connecting|open|closed|error|interrupted|rejected)$"),
        limit: int = Query(default=100, ge=1, le=200),
        offset: int = Query(default=0, ge=0, le=1_000_000),
    ) -> dict[str, Any]:
        result = await asyncio.to_thread(store.list_websocket_connections, search=search, state=state_filter, limit=limit, offset=offset)
        public_connections = []
        for item in result["connections"]:
            safe = _public_websocket_connection(item)
            safe["in_scope"] = bool(scope.websocket_url_in_scope(str(item.get("url", ""))) and scope.host_in_scope(str(item.get("host", ""))) and not scope.address_explicitly_excluded(item.get("remote_ip")) and not (item.get("remote_ip") is None and scope.has_explicit_exclusions()))
            public_connections.append(safe)
        result["connections"] = public_connections
        return result

    @app.get("/api/websockets/connections/{connection_id}", dependencies=[Depends(api_auth)])
    async def get_websocket_connection(connection_id: str) -> dict[str, Any]:
        if not connection_id or len(connection_id) > 128:
            raise HTTPException(status_code=422, detail="Invalid WebSocket connection identifier")
        item = await asyncio.to_thread(store.get_websocket_connection, connection_id)
        if item is None:
            raise HTTPException(status_code=404, detail="WebSocket connection not found")
        flow = await asyncio.to_thread(store.get_flow, str(item["flow_id"]))
        safe = _public_websocket_connection(item, detail=True)
        safe["in_scope"] = bool(scope.websocket_url_in_scope(str(item.get("url", ""))) and scope.host_in_scope(str(item.get("host", ""))) and not scope.address_explicitly_excluded(item.get("remote_ip")) and not (item.get("remote_ip") is None and scope.has_explicit_exclusions()))
        safe["source_flow_available"] = flow is not None
        return safe

    @app.get("/api/websockets/connections/{connection_id}/messages", dependencies=[Depends(api_auth)])
    async def list_websocket_messages(
        connection_id: str,
        search: str = Query(default="", max_length=200),
        direction: str = Query(default="", pattern="^(|client_to_server|server_to_client)$"),
        opcode: int | None = Query(default=None, ge=1, le=2),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0, le=1_000_000),
    ) -> dict[str, Any]:
        if opcode not in {None, 1, 2}:
            raise HTTPException(status_code=422, detail="Opcode must be 1 (text) or 2 (binary)")
        if await asyncio.to_thread(store.get_websocket_connection, connection_id) is None:
            raise HTTPException(status_code=404, detail="WebSocket connection not found")
        result = await asyncio.to_thread(store.list_websocket_messages, connection_id, search=search, direction=direction, opcode=opcode, limit=limit, offset=offset)
        result["messages"] = [_public_websocket_message(item) for item in result["messages"]]
        return result

    @app.get("/api/websockets/connections/{connection_id}/messages/{message_id}", dependencies=[Depends(api_auth)])
    async def get_websocket_message(connection_id: str, message_id: int) -> dict[str, Any]:
        if message_id < 1:
            raise HTTPException(status_code=422, detail="Message ID must be positive")
        item = await asyncio.to_thread(store.get_websocket_message, message_id)
        if item is None or str(item.get("connection_id")) != connection_id:
            raise HTTPException(status_code=404, detail="WebSocket message not found")
        return _public_websocket_message(item, detail=True)

    @app.post("/api/websockets/connections/{connection_id}/send", dependencies=[Depends(api_auth)])
    async def send_websocket_message(connection_id: str, payload: WebSocketSendRequest) -> dict[str, Any]:
        if not connection_id or len(connection_id) > 128:
            raise HTTPException(status_code=422, detail="Invalid WebSocket connection identifier")
        try:
            if payload.binary:
                try:
                    raw = b64.b64decode(payload.payload.encode("ascii"), validate=True)
                except (binascii.Error, UnicodeEncodeError) as exc:
                    raise HTTPException(status_code=422, detail="Binary payload must be valid Base64") from exc
            else:
                raw = payload.payload.encode("utf-8", errors="strict")
            if len(raw) > store.max_ws_message_bytes:
                raise HTTPException(status_code=413, detail=f"Message exceeds the configured {store.max_ws_message_bytes}-byte limit")
            result = await asyncio.to_thread(proxy.send_websocket_message, connection_id, raw, is_text=not payload.binary)
            return result
        except HTTPException:
            raise
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc).strip("'")) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (ValueError, RuntimeError, TimeoutError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/health", include_in_schema=False)
    async def health() -> JSONResponse:
        return JSONResponse({"ok": True, "app": "WireScope"})

    return app
