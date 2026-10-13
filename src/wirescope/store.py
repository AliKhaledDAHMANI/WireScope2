from __future__ import annotations

import json
import sqlite3
import threading
import time
import hashlib
import os
import ipaddress
from urllib.parse import parse_qsl, urlsplit
from pathlib import Path
from typing import Any, Iterable

from .paths import secure_file

MAX_BODY_BYTES = 2 * 1024 * 1024
DEFAULT_WS_MESSAGE_BYTES = 256 * 1024
DEFAULT_WS_MESSAGES = 50_000
DEFAULT_WS_STORAGE_BYTES = 64 * 1024 * 1024


def _env_limit(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _safe_origin(parts: Any) -> str:
    """Build an HTTP origin without ever propagating URL userinfo."""
    scheme = str(parts.scheme).casefold()
    hostname = str(parts.hostname or "").casefold().rstrip(".")
    if not hostname:
        return ""
    host_display = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    try:
        port = parts.port
    except ValueError:
        return ""
    return f"{scheme}://{host_display}{':' + str(port) if port is not None else ''}"


class Store:
    """Small SQLite store. Every operation gets a short-lived connection."""

    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # Limits are configurable at launch, but clamped to safe operational bounds.
        self.max_ws_message_bytes = _env_limit("WIRESCOPE_MAX_WS_MESSAGE_BYTES", DEFAULT_WS_MESSAGE_BYTES, 1024, 1024 * 1024)
        self.max_ws_messages = _env_limit("WIRESCOPE_MAX_WS_MESSAGES", DEFAULT_WS_MESSAGES, 100, 250_000)
        self.max_ws_storage_bytes = _env_limit("WIRESCOPE_MAX_WS_STORAGE_BYTES", DEFAULT_WS_STORAGE_BYTES, 1024 * 1024, 512 * 1024 * 1024)
        self._initialize()
        secure_file(self.database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS flows (
                    id TEXT PRIMARY KEY,
                    started_at REAL NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    request_headers TEXT NOT NULL DEFAULT '[]',
                    request_body BLOB NOT NULL DEFAULT X'',
                    request_truncated INTEGER NOT NULL DEFAULT 0,
                    status INTEGER,
                    response_headers TEXT NOT NULL DEFAULT '[]',
                    response_body BLOB NOT NULL DEFAULT X'',
                    response_truncated INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER,
                    error TEXT,
                    intercepted INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_flows_started ON flows(started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
                CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
                CREATE TABLE IF NOT EXISTS scope_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT NOT NULL,
                    mode TEXT NOT NULL CHECK(mode IN ('include', 'exclude')),
                    created_at REAL NOT NULL,
                    UNIQUE(pattern, mode)
                );
                """
            )
            # Migration ledger was introduced after the original Milestone 1 schema.
            # Existing databases are upgraded in place; traffic rows are never recreated.
            db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)")
            db.execute("INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)", (time.time(),))
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
                    confidence TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),
                    url TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','false_positive','resolved')),
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON findings(status, severity);
                CREATE INDEX IF NOT EXISTS idx_findings_flow ON findings(flow_id);
                """
            )
            db.execute("INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)", (time.time(),))
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS websocket_connections (
                    id TEXT PRIMARY KEY,
                    flow_id TEXT NOT NULL UNIQUE REFERENCES flows(id) ON DELETE CASCADE,
                    url TEXT NOT NULL,
                    host TEXT NOT NULL,
                    scheme TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    ended_at REAL,
                    state TEXT NOT NULL CHECK(state IN ('connecting','open','closed','error','interrupted','rejected')),
                    handshake_status INTEGER,
                    request_headers TEXT NOT NULL DEFAULT '[]',
                    response_headers TEXT NOT NULL DEFAULT '[]',
                    remote_ip TEXT,
                    close_code INTEGER,
                    close_reason TEXT,
                    error TEXT,
                    message_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_ws_connections_started ON websocket_connections(started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_ws_connections_host ON websocket_connections(host);
                CREATE INDEX IF NOT EXISTS idx_ws_connections_state ON websocket_connections(state);
                CREATE TABLE IF NOT EXISTS websocket_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_id TEXT NOT NULL REFERENCES websocket_connections(id) ON DELETE CASCADE,
                    timestamp REAL NOT NULL,
                    direction TEXT NOT NULL CHECK(direction IN ('client_to_server','server_to_client')),
                    opcode INTEGER NOT NULL CHECK(opcode IN (1,2)),
                    payload BLOB NOT NULL,
                    payload_size INTEGER NOT NULL,
                    truncated INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL CHECK(source IN ('captured','user'))
                );
                CREATE INDEX IF NOT EXISTS idx_ws_messages_connection ON websocket_messages(connection_id, id DESC);
                CREATE INDEX IF NOT EXISTS idx_ws_messages_time ON websocket_messages(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_ws_messages_direction ON websocket_messages(direction);
                CREATE TRIGGER IF NOT EXISTS trg_ws_message_delete_count
                AFTER DELETE ON websocket_messages
                BEGIN
                    UPDATE websocket_connections SET message_count=MAX(0, message_count-1)
                    WHERE id=OLD.connection_id;
                END;
                """
            )
            # Retention pruning deletes rows; counts reflect retained messages, not lifetime traffic.
            db.execute("UPDATE websocket_connections SET message_count=(SELECT COUNT(*) FROM websocket_messages WHERE connection_id=websocket_connections.id)")
            db.execute("INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(3, ?)", (time.time(),))
            # Connections cannot survive a process restart. Mark rows left open by a crash accordingly.
            db.execute("UPDATE websocket_connections SET state='interrupted', ended_at=COALESCE(ended_at, ?), error=COALESCE(error, 'Application restarted before close was observed') WHERE state IN ('open','connecting')", (time.time(),))

    @staticmethod
    def _body(value: bytes | None) -> tuple[bytes, int]:
        raw = value or b""
        return raw[:MAX_BODY_BYTES], int(len(raw) > MAX_BODY_BYTES)

    def record_request(
        self, *, flow_id: str, started_at: float, method: str, url: str,
        host: str, path: str, headers: Iterable[tuple[str, str]], body: bytes | None,
        intercepted: bool = False,
    ) -> None:
        body_value, truncated = self._body(body)
        now = time.time() if not started_at else started_at
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO flows(id, started_at, method, url, host, path,
                   request_headers, request_body, request_truncated, intercepted)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET method=excluded.method, url=excluded.url,
                   host=excluded.host, path=excluded.path, request_headers=excluded.request_headers,
                   request_body=excluded.request_body, request_truncated=excluded.request_truncated,
                   intercepted=excluded.intercepted""",
                (flow_id, now, method, url, host, path, json.dumps(list(headers)), body_value,
                 truncated, int(intercepted)),
            )

    def record_response(
        self, *, flow_id: str, status: int | None,
        headers: Iterable[tuple[str, str]], body: bytes | None,
        duration_ms: int | None, error: str | None = None,
    ) -> None:
        body_value, truncated = self._body(body)
        with self._lock, self._connect() as db:
            db.execute(
                """UPDATE flows SET status=?, response_headers=?, response_body=?,
                   response_truncated=?, duration_ms=?, error=?, intercepted=0 WHERE id=?""",
                (status, json.dumps(list(headers)), body_value, truncated, duration_ms, error, flow_id),
            )

    def set_intercepted(self, flow_id: str, value: bool) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE flows SET intercepted=? WHERE id=?", (int(value), flow_id))

    def list_flows(self, *, search: str = "", limit: int = 300, intercepted: bool | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        conditions: list[str] = []
        values: list[Any] = []
        if search.strip():
            needle = f"%{search.strip()}%"
            conditions.append("(url LIKE ? OR host LIKE ? OR method LIKE ? OR CAST(status AS TEXT) LIKE ?)")
            values.extend([needle, needle, needle, needle])
        if intercepted is not None:
            conditions.append("intercepted=?")
            values.append(int(intercepted))
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT id, started_at, method, url, host, path, status, duration_ms, error, intercepted, "
                "length(request_body) AS request_bytes, length(response_body) AS response_bytes "
                f"FROM flows{where} ORDER BY started_at DESC LIMIT ?", (*values, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM flows WHERE id=?", (flow_id,)).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["request_headers"] = json.loads(value["request_headers"])
        value["response_headers"] = json.loads(value["response_headers"])
        value["request_body"] = bytes(value["request_body"] or b"")
        value["response_body"] = bytes(value["response_body"] or b"")
        value["intercepted"] = bool(value["intercepted"])
        value["request_truncated"] = bool(value["request_truncated"])
        value["response_truncated"] = bool(value["response_truncated"])
        return value

    def list_scope_rules(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT id, pattern, mode, created_at FROM scope_rules ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def add_scope_rule(self, pattern: str, mode: str) -> dict[str, Any]:
        if mode not in {"include", "exclude"}:
            raise ValueError("mode must be include or exclude")
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "INSERT INTO scope_rules(pattern, mode, created_at) VALUES(?,?,?)",
                (pattern, mode, time.time()),
            )
            rule_id = int(cursor.lastrowid)
        return {"id": rule_id, "pattern": pattern, "mode": mode}

    def delete_scope_rule(self, rule_id: int) -> bool:
        with self._lock, self._connect() as db:
            cursor = db.execute("DELETE FROM scope_rules WHERE id=?", (rule_id,))
        return cursor.rowcount > 0

    def list_site_map(
        self, *, search: str = "", host: str = "", method: str = "",
        content_type: str = "", status: str = "", limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Aggregate every persisted captured flow into observed endpoints; never crawls."""
        limit = max(1, min(int(limit), 2000))
        entries: dict[str, dict[str, Any]] = {}
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "SELECT id, started_at, method, url, host, status, response_headers "
                "FROM flows ORDER BY started_at DESC"
            )
            while True:
                batch = cursor.fetchmany(500)
                if not batch:
                    break
                for row in batch:
                    url = str(row["url"] or "")
                    try:
                        parts = urlsplit(url)
                        if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
                            continue
                        path = parts.path or "/"
                        origin = _safe_origin(parts)
                        hostname = parts.hostname.casefold().rstrip(".")
                        if not origin:
                            continue
                        has_url_credentials = parts.username is not None or parts.password is not None
                    except (ValueError, UnicodeError):
                        continue
                    method_value = str(row["method"] or "GET").upper()
                    key_material = f"{origin}\0{path}\0{method_value}"
                    entry_id = hashlib.sha256(key_material.encode("utf-8", errors="replace")).hexdigest()[:24]
                    headers = []
                    try:
                        headers = json.loads(row["response_headers"] or "[]")
                    except (TypeError, json.JSONDecodeError):
                        pass
                    ctype = ""
                    for pair in headers:
                        if isinstance(pair, (list, tuple)) and len(pair) == 2 and str(pair[0]).casefold() == "content-type":
                            ctype = str(pair[1]).split(";", 1)[0].strip().casefold()
                            break
                    try:
                        params = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=256) if name})
                    except ValueError:
                        # A pathological query string should not break the entire map.
                        params = []
                    stamp = float(row["started_at"] or 0)
                    entry = entries.get(entry_id)
                    if entry is None:
                        entry = entries[entry_id] = {
                            "id": entry_id, "host": hostname, "origin": origin, "path": path,
                            "url": origin + path, "url_has_credentials": bool(has_url_credentials),
                            "method": method_value, "request_count": 0,
                            "statuses": [], "content_types": [], "query_parameters": [],
                            "first_seen": stamp, "last_seen": stamp, "flow_ids": [],
                        }
                    entry["url_has_credentials"] = entry["url_has_credentials"] or bool(has_url_credentials)
                    entry["request_count"] += 1
                    entry["first_seen"] = min(entry["first_seen"], stamp)
                    entry["last_seen"] = max(entry["last_seen"], stamp)
                    if row["status"] is not None and int(row["status"]) not in entry["statuses"]:
                        entry["statuses"].append(int(row["status"]))
                    if ctype and ctype not in entry["content_types"]:
                        entry["content_types"].append(ctype)
                    entry["query_parameters"] = sorted(set(entry["query_parameters"]) | set(params))
                    # Recent flow IDs are ordered newest first because the query sorts descending.
                    if len(entry["flow_ids"]) < 20:
                        entry["flow_ids"].append(str(row["id"]))
        query = search.strip().casefold()
        host_filter = host.strip().casefold()
        method_filter = method.strip().upper()
        type_filter = content_type.strip().casefold()
        status_filter = status.strip().casefold()
        result = []
        for entry in entries.values():
            joined = " ".join([entry["host"], entry["url"], entry["method"], *entry["query_parameters"]]).casefold()
            if query and query not in joined:
                continue
            if host_filter and host_filter not in entry["host"]:
                continue
            if method_filter and method_filter != entry["method"]:
                continue
            if type_filter and not any(type_filter in item for item in entry["content_types"]):
                continue
            if status_filter:
                if status_filter.endswith("xx"):
                    status_class = int(status_filter[0])
                    if not any(code // 100 == status_class for code in entry["statuses"]):
                        continue
                elif not status_filter.isdigit() or int(status_filter) not in entry["statuses"]:
                    continue
            entry["statuses"].sort()
            entry["content_types"].sort()
            result.append(entry)
        result.sort(key=lambda item: item["last_seen"], reverse=True)
        return result[:limit]

    def list_endpoint_flows(self, *, origin: str, path: str, method: str = "", limit: int = 20) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 50))
        parsed_origin = urlsplit(origin)
        if (parsed_origin.scheme.casefold() not in {"http", "https"} or not parsed_origin.hostname
                or parsed_origin.path not in {"", "/"} or parsed_origin.query or parsed_origin.fragment):
            raise ValueError("origin must be an HTTP or HTTPS origin without a path, query, or fragment")
        normalized_origin = _safe_origin(parsed_origin)
        if not normalized_origin or parsed_origin.username is not None or parsed_origin.password is not None:
            raise ValueError("origin must not contain credentials")
        conditions = ["lower(host)=?"]
        values: list[Any] = [parsed_origin.hostname.casefold()]
        if method:
            conditions.append("upper(method)=?")
            values.append(method.upper())
        matches: list[dict[str, Any]] = []
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "SELECT id, started_at, method, url, host, path, status, duration_ms, error, intercepted, "
                "length(request_body) AS request_bytes, length(response_body) AS response_bytes "
                "FROM flows WHERE " + " AND ".join(conditions) + " ORDER BY started_at DESC",
                values,
            )
            while len(matches) < limit:
                batch = cursor.fetchmany(200)
                if not batch:
                    break
                for row in batch:
                    try:
                        parsed = urlsplit(str(row["url"]))
                    except ValueError:
                        continue
                    row_origin = _safe_origin(parsed)
                    if row_origin != normalized_origin or (parsed.path or "/") != path:
                        continue
                    matches.append(dict(row))
                    if len(matches) >= limit:
                        break
        return matches

    def list_flows_for_analysis(self, *, limit: int = 1000) -> list[str]:
        limit = max(1, min(int(limit), 1000))
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT id FROM flows WHERE status IS NOT NULL ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [str(row["id"]) for row in rows]

    def save_findings(self, flow_id: str, findings: list[dict[str, Any]]) -> int:
        """Replace analyzer output for a flow while preserving statuses for stable finding IDs."""
        now = time.time()
        with self._lock, self._connect() as db:
            ids: list[str] = []
            for item in findings:
                finding_id = str(item["id"])
                ids.append(finding_id)
                db.execute(
                    """INSERT INTO findings(id, flow_id, rule_id, title, severity, confidence, url,
                           evidence, explanation, remediation, status, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?, 'open', ?, ?)
                       ON CONFLICT(id) DO UPDATE SET rule_id=excluded.rule_id, title=excluded.title,
                           severity=excluded.severity, confidence=excluded.confidence, url=excluded.url,
                           evidence=excluded.evidence, explanation=excluded.explanation,
                           remediation=excluded.remediation, updated_at=excluded.updated_at""",
                    (finding_id, flow_id, item["rule_id"], item["title"], item["severity"],
                     item["confidence"], item["url"], item["evidence"], item["explanation"],
                     item["remediation"], now, now),
                )
            if ids:
                placeholders = ",".join("?" for _ in ids)
                db.execute(f"DELETE FROM findings WHERE flow_id=? AND id NOT IN ({placeholders})", (flow_id, *ids))
            else:
                db.execute("DELETE FROM findings WHERE flow_id=?", (flow_id,))
        return len(findings)

    def list_findings(self, *, search: str = "", severity: str = "", status: str = "", limit: int = 500) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        conditions: list[str] = []
        values: list[Any] = []
        if search.strip():
            needle = f"%{search.strip()}%"
            conditions.append("(title LIKE ? OR url LIKE ? OR evidence LIKE ? OR explanation LIKE ? OR remediation LIKE ? OR rule_id LIKE ?)")
            values.extend([needle] * 6)
        if severity:
            conditions.append("severity=?")
            values.append(severity)
        if status:
            conditions.append("status=?")
            values.append(status)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT id, flow_id, rule_id, title, severity, confidence, url, evidence, explanation, remediation, status, created_at, updated_at "
                f"FROM findings{where} ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC LIMIT ?",
                (*values, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return dict(row) if row is not None else None

    def update_finding_status(self, finding_id: str, status: str) -> bool:
        if status not in {"open", "false_positive", "resolved"}:
            raise ValueError("status must be open, false_positive, or resolved")
        with self._lock, self._connect() as db:
            cursor = db.execute("UPDATE findings SET status=?, updated_at=? WHERE id=?", (status, time.time(), finding_id))
        return cursor.rowcount > 0


    @staticmethod
    def _ws_headers(headers: Iterable[tuple[str, str]] | str | None) -> str:
        if isinstance(headers, str):
            try:
                parsed = json.loads(headers)
                return json.dumps(parsed if isinstance(parsed, list) else [])
            except (TypeError, json.JSONDecodeError):
                return "[]"
        return json.dumps(list(headers or []))

    def start_websocket(
        self, *, connection_id: str, flow_id: str, url: str, host: str, scheme: str,
        started_at: float, request_headers: Iterable[tuple[str, str]],
        response_headers: Iterable[tuple[str, str]] = (), handshake_status: int | None = None,
        remote_ip: str | None = None, state: str = "open",
    ) -> None:
        if state not in {"connecting", "open"}:
            raise ValueError("Initial WebSocket state must be connecting or open")
        now = time.time()
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO websocket_connections
                   (id, flow_id, url, host, scheme, started_at, last_seen, state, handshake_status,
                    request_headers, response_headers, remote_ip)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET url=excluded.url, host=excluded.host,
                    scheme=excluded.scheme, handshake_status=COALESCE(excluded.handshake_status, websocket_connections.handshake_status),
                    request_headers=excluded.request_headers,
                    response_headers=CASE WHEN excluded.response_headers='[]' THEN websocket_connections.response_headers ELSE excluded.response_headers END,
                    remote_ip=COALESCE(excluded.remote_ip, websocket_connections.remote_ip),
                    last_seen=MAX(websocket_connections.last_seen, excluded.last_seen),
                    state=CASE WHEN websocket_connections.state IN ('closed','error','interrupted','rejected') THEN websocket_connections.state ELSE excluded.state END""",
                (connection_id, flow_id, url[:8192], host[:512], scheme[:16], float(started_at), now, state,
                 handshake_status, self._ws_headers(request_headers), self._ws_headers(response_headers),
                 (remote_ip or "")[:128] or None),
            )

    def append_websocket_message(
        self, *, connection_id: str, timestamp: float, direction: str, opcode: int,
        payload: bytes, source: str = "captured",
    ) -> dict[str, Any] | None:
        if direction not in {"client_to_server", "server_to_client"}:
            raise ValueError("Invalid WebSocket message direction")
        if opcode not in {1, 2}:
            raise ValueError("Only WebSocket text and binary messages are supported")
        if source not in {"captured", "user"}:
            raise ValueError("Invalid WebSocket message source")
        raw = bytes(payload)
        stored = raw[:self.max_ws_message_bytes]
        truncated = int(len(raw) > len(stored))
        with self._lock, self._connect() as db:
            exists = db.execute("SELECT state FROM websocket_connections WHERE id=?", (connection_id,)).fetchone()
            if exists is None or exists["state"] != "open":
                return None
            cursor = db.execute(
                "INSERT INTO websocket_messages(connection_id,timestamp,direction,opcode,payload,payload_size,truncated,source) VALUES(?,?,?,?,?,?,?,?)",
                (connection_id, float(timestamp or time.time()), direction, opcode, stored, len(raw), truncated, source),
            )
            msg_id = int(cursor.lastrowid)
            db.execute("UPDATE websocket_connections SET last_seen=MAX(last_seen,?), message_count=message_count+1 WHERE id=?", (float(timestamp or time.time()), connection_id))
            # Bound row count and payload storage globally. Keep the newest rows when pruning.
            db.execute(
                "DELETE FROM websocket_messages WHERE id IN (SELECT id FROM websocket_messages ORDER BY id ASC LIMIT MAX(0, (SELECT COUNT(*) FROM websocket_messages) - ?))",
                (self.max_ws_messages,),
            )
            db.execute(
                "DELETE FROM websocket_messages WHERE id IN (SELECT id FROM (SELECT id, SUM(length(payload)) OVER (ORDER BY id DESC) AS retained FROM websocket_messages) WHERE retained > ?)",
                (self.max_ws_storage_bytes,),
            )
            row = db.execute("SELECT * FROM websocket_messages WHERE id=?", (msg_id,)).fetchone()
            return dict(row) if row is not None else {
                "id": msg_id, "connection_id": connection_id, "timestamp": float(timestamp or time.time()),
                "direction": direction, "opcode": opcode, "payload": stored, "payload_size": len(raw),
                "truncated": truncated, "source": source,
            }

    def finish_websocket(
        self, connection_id: str, *, state: str = "closed", ended_at: float | None = None,
        close_code: int | None = None, close_reason: str | None = None, error: str | None = None,
    ) -> bool:
        if state not in {"closed", "error", "interrupted", "rejected"}:
            raise ValueError("Invalid terminal WebSocket state")
        with self._lock, self._connect() as db:
            now = float(ended_at or time.time())
            cursor = db.execute(
                """UPDATE websocket_connections SET
                   state=CASE WHEN state IN ('closed','error','interrupted','rejected') THEN state ELSE ? END,
                   ended_at=COALESCE(ended_at, ?), close_code=COALESCE(?, close_code),
                   close_reason=COALESCE(?, close_reason), error=COALESCE(?, error),
                   last_seen=MAX(last_seen, ?) WHERE id=?""",
                (state, now, close_code, (close_reason or "")[:512] or None,
                 (error or "")[:1000] or None, now, connection_id),
            )
            return cursor.rowcount > 0

    def list_websocket_connections(
        self, *, search: str = "", state: str = "", limit: int = 100, offset: int = 0,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 200))
        offset = max(0, min(int(offset), 1_000_000))
        conditions: list[str] = []
        values: list[Any] = []
        if search.strip():
            needle = f"%{search.strip()}%"
            conditions.append("(url LIKE ? OR host LIKE ? OR id LIKE ? OR CAST(handshake_status AS TEXT) LIKE ?)")
            values.extend([needle] * 4)
        if state:
            conditions.append("state=?")
            values.append(state)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self._lock, self._connect() as db:
            total = int(db.execute("SELECT COUNT(*) FROM websocket_connections" + where, values).fetchone()[0])
            rows = db.execute(
                "SELECT id,flow_id,url,host,scheme,started_at,last_seen,ended_at,state,handshake_status,remote_ip,close_code,close_reason,error,message_count,request_headers,response_headers FROM websocket_connections" + where + " ORDER BY last_seen DESC, started_at DESC LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
        return {"connections": [dict(row) for row in rows], "count": total, "limit": limit, "offset": offset}

    def get_websocket_connection(self, connection_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM websocket_connections WHERE id=?", (connection_id,)).fetchone()
        return dict(row) if row is not None else None

    def list_websocket_messages(
        self, connection_id: str, *, search: str = "", direction: str = "", opcode: int | None = None,
        limit: int = 100, offset: int = 0,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 500))
        offset = max(0, min(int(offset), 1_000_000))
        conditions = ["connection_id=?"]
        values: list[Any] = [connection_id]
        if search:
            conditions.append("instr(lower(CAST(payload AS TEXT)), lower(?)) > 0")
            values.append(search[:200])
        if direction:
            conditions.append("direction=?")
            values.append(direction)
        if opcode is not None:
            conditions.append("opcode=?")
            values.append(opcode)
        where = " WHERE " + " AND ".join(conditions)
        with self._lock, self._connect() as db:
            total = int(db.execute("SELECT COUNT(*) FROM websocket_messages" + where, values).fetchone()[0])
            rows = db.execute(
                "SELECT id,connection_id,timestamp,direction,opcode,length(payload) AS stored_bytes,payload_size,truncated,source FROM websocket_messages" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
        return {"messages": [dict(row) for row in rows], "count": total, "limit": limit, "offset": offset}

    def get_websocket_message(self, message_id: int) -> dict[str, Any] | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM websocket_messages WHERE id=?", (message_id,)).fetchone()
        return dict(row) if row is not None else None

    def mark_websockets_interrupted(self, reason: str = "Proxy stopped before close was observed") -> int:
        now = time.time()
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "UPDATE websocket_connections SET state='interrupted',ended_at=COALESCE(ended_at,?),error=COALESCE(error,?),last_seen=MAX(last_seen,?) WHERE state IN ('open','connecting')",
                (now, reason[:1000], now),
            )
            return cursor.rowcount


    def close(self) -> None:
        # Connections are short-lived; this exists to make application shutdown explicit.
        return None
