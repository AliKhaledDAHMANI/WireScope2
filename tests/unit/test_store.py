from pathlib import Path

from wirescope.store import Store, MAX_BODY_BYTES


def test_store_round_trip_and_search(tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    store.record_request(
        flow_id="flow-a", started_at=123.0, method="GET", url="http://127.0.0.1:5000/hello?q=wire",
        host="127.0.0.1", path="/hello?q=wire", headers=[("Host", "127.0.0.1:5000")],
        body=b"request body", intercepted=True,
    )
    store.record_response(flow_id="flow-a", status=200, headers=[("Content-Type", "text/plain")],
                          body=b"hello", duration_ms=13)
    saved = store.get_flow("flow-a")
    assert saved is not None
    assert saved["request_body"] == b"request body"
    assert saved["response_body"] == b"hello"
    assert saved["status"] == 200
    assert saved["duration_ms"] == 13
    assert saved["intercepted"] is False
    assert len(store.list_flows(search="hello")) == 1
    assert store.list_flows(search="not-here") == []


def test_store_caps_large_bodies(tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    large = b"x" * (MAX_BODY_BYTES + 1)
    store.record_request(flow_id="large", started_at=1, method="POST", url="http://localhost/",
                         host="localhost", path="/", headers=[], body=large)
    flow = store.get_flow("large")
    assert flow is not None
    assert len(flow["request_body"]) == MAX_BODY_BYTES
    assert flow["request_truncated"] is True
