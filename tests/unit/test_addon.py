from pathlib import Path
from types import SimpleNamespace
import threading

from wirescope.proxy import WireScopeAddon
from wirescope.store import Store


class FakeHeaders:
    def __init__(self, pairs): self.pairs = pairs
    def items(self, multi=False): return iter(self.pairs)


def test_addon_records_request_response_and_pause(tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    pending = {}
    lock = threading.RLock()
    intercept = threading.Event(); intercept.set()
    addon = WireScopeAddon(store, pending, lock, intercept)
    flow = SimpleNamespace(
        id="fake-flow",
        request=SimpleNamespace(url="http://127.0.0.1:5000/", host="127.0.0.1", path="/", method="GET",
                                headers=FakeHeaders([("Host", "127.0.0.1:5000")]), raw_content=b"", timestamp_start=10.0),
        response=None, intercepted=False,
        intercept=lambda: setattr(flow, "intercepted", True),
    )
    addon.request(flow)
    saved = store.get_flow("fake-flow")
    assert saved is not None and saved["intercepted"] is True
    assert pending["fake-flow"] is flow
    flow.response = SimpleNamespace(status_code=200, headers=FakeHeaders([("Content-Type", "text/plain")]),
                                    raw_content=b"ok", timestamp_end=10.025)
    addon.response(flow)
    saved = store.get_flow("fake-flow")
    assert saved is not None
    assert saved["status"] == 200
    assert saved["response_body"] == b"ok"
    assert saved["duration_ms"] == 25
    assert "fake-flow" not in pending
    addon.close()
    assert store.list_findings(search="X-Content-Type-Options")
