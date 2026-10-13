from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from urllib.parse import urlsplit
from types import SimpleNamespace

import pytest

from wirescope.proxy import ProxyService, WireScopeAddon
from wirescope.store import Store


class Headers:
    def __init__(self, pairs=()): self.pairs = list(pairs)
    def items(self, multi=False): return list(self.pairs)
    def clear(self): self.pairs.clear()
    def extend(self, pairs): self.pairs.extend(list(pairs))


class Request:
    def __init__(self):
        self._url = "http://127.0.0.1:5000/original"
        self.method = "GET"
        self.headers = Headers([("Host", "127.0.0.1:5000")])
        self._content = b""
        self.timestamp_start = 100.0
    @property
    def url(self): return self._url
    @url.setter
    def url(self, value): self._url = value
    @property
    def host(self): return urlsplit(self._url).hostname or ""
    @property
    def path(self):
        parsed = urlsplit(self._url)
        return (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
    @property
    def raw_content(self): return self._content
    @property
    def content(self): return self._content
    @content.setter
    def content(self, value): self._content = value


class FakeFlow:
    def __init__(self, flow_id):
        self.id = flow_id
        self.request = Request()
        self.intercepted = True
        self.live = True
        self.error = None
        self.was_resumed = False
        self.was_killed = False
    def resume(self): self.intercepted = False; self.was_resumed = True
    def kill(self): self.live = False; self.intercepted = False; self.was_killed = True; self.error = SimpleNamespace(msg="Request killed")


@pytest.fixture
def proxy_harness(tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    service = ProxyService(store, tmp_path)
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    def runner():
        asyncio.set_event_loop(loop)
        ready.set()
        loop.run_forever()
    thread = threading.Thread(target=runner, daemon=True); thread.start(); ready.wait(2)
    service._loop = loop
    service.intercept_event.set()
    service._addon = WireScopeAddon(store, service.pending, service.pending_lock, service.intercept_event)
    yield service, store
    loop.call_soon_threadsafe(loop.stop); thread.join(timeout=2); loop.close(); store.close()


def seed_flow(store: Store, flow_id: str):
    store.record_request(flow_id=flow_id, started_at=100, method="GET", url="http://127.0.0.1:5000/original",
                         host="127.0.0.1", path="/original", headers=[("Host", "127.0.0.1:5000")],
                         body=b"", intercepted=True)


def test_forward_edited_updates_saved_history(proxy_harness):
    service, store = proxy_harness
    flow = FakeFlow("edit-me"); service.pending[flow.id] = flow; seed_flow(store, flow.id)
    service.forward(flow.id, {"method": "POST", "url": "http://127.0.0.1:5000/edited?q=1",
                              "headers": [("Host", "127.0.0.1:5000"), ("Content-Type", "text/plain")],
                              "body": b"new body"})
    saved = store.get_flow(flow.id)
    assert flow.was_resumed and not flow.intercepted
    assert saved["method"] == "POST"
    assert saved["url"].endswith("/edited?q=1")
    assert saved["request_body"] == b"new body"
    assert ["Content-Type", "text/plain"] in saved["request_headers"]
    assert saved["intercepted"] is False


def test_drop_marks_history_and_kills_flow(proxy_harness):
    service, store = proxy_harness
    flow = FakeFlow("drop-me"); service.pending[flow.id] = flow; seed_flow(store, flow.id)
    service.drop(flow.id)
    saved = store.get_flow(flow.id)
    assert flow.was_resumed and flow.was_killed
    assert flow.id not in service.pending
    assert saved["error"] == "Dropped by user"
    assert saved["intercepted"] is False


def test_proxy_refuses_non_loopback_bind(tmp_path: Path):
    service = ProxyService(Store(tmp_path / "history.sqlite3"), tmp_path)
    with pytest.raises(ValueError, match="loopback only"):
        service.start("0.0.0.0", 8080)


def test_stopping_proxy_cancels_paused_requests(proxy_harness):
    service, store = proxy_harness
    flow = FakeFlow("stop-me"); service.pending[flow.id] = flow; seed_flow(store, flow.id)
    stopped = threading.Event()
    class Master:
        def shutdown(self): stopped.set()
    service._master = Master()
    service.stop()
    assert stopped.wait(1)
    saved = store.get_flow(flow.id)
    assert flow.was_resumed and flow.was_killed
    assert saved["error"] == "Proxy stopped while request was paused"
    assert saved["intercepted"] is False
    assert not service.pending
