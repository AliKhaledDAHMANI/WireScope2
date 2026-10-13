from pathlib import Path

from fastapi.testclient import TestClient

from wirescope.api import create_app
from wirescope.proxy import ProxyService
from wirescope.repeater import RepeaterClient
from wirescope.scope import ScopePolicy
from wirescope.store import Store
from wirescope.analysis import analyze_flow


def build_client(tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    scope = ScopePolicy(store)
    proxy = ProxyService(store, tmp_path)
    app = create_app(store, proxy, scope, RepeaterClient(scope))
    client = TestClient(app)
    token = client.get("/api/session").json()["token"]
    client.headers.update({"X-WireScope-Token": token})
    return client, store


def add_flow(store, flow_id, url, method="GET", status=200, req_path=None, response_headers=None, body=b"<html>lab</html>"):
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    store.record_request(flow_id=flow_id, started_at=123.0, method=method, url=url, host=parsed.hostname or "",
                         path=req_path or ((parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")),
                         headers=[("Host", parsed.netloc)], body=b"", intercepted=False)
    store.record_response(flow_id=flow_id, status=status,
                          headers=response_headers or [("Content-Type", "text/html")], body=body,
                          duration_ms=12)


def test_site_map_uses_observed_traffic_filters_parameters_and_scope(tmp_path: Path):
    client, store = build_client(tmp_path)
    add_flow(store, "in-flow", "https://app.example.org/account?tab=profile&lang=en")
    add_flow(store, "out-flow", "https://api.example.org/v1/items?id=42", method="POST", status=201,
             response_headers=[("Content-Type", "application/json")], body=b'{"ok":true}')
    store.add_scope_rule("*.example.org", "include")
    store.add_scope_rule("api.example.org", "exclude")

    all_entries = client.get("/api/sitemap").json()["entries"]
    by_host = {entry["host"]: entry for entry in all_entries}
    assert set(by_host) == {"app.example.org", "api.example.org"}
    assert by_host["app.example.org"]["query_parameters"] == ["lang", "tab"]
    assert by_host["app.example.org"]["in_scope"] is True
    assert by_host["api.example.org"]["in_scope"] is False
    assert by_host["api.example.org"]["statuses"] == [201]
    assert client.get("/api/sitemap?scope=in_scope").json()["count"] == 1
    assert client.get("/api/sitemap?scope=out_of_scope").json()["count"] == 1
    assert client.get("/api/sitemap?status=2xx").json()["count"] == 2
    assert client.get("/api/sitemap?status=5xx").json()["count"] == 0

    # URL userinfo must not be copied into Site Map origins or become in-scope by sanitization.
    add_flow(store, "userinfo-flow", "https://alice:secret@app.example.org/private")
    userinfo_entry = next(e for e in client.get("/api/sitemap").json()["entries"] if e["path"] == "/private")
    assert "alice" not in userinfo_entry["origin"] and "secret" not in userinfo_entry["url"]
    assert userinfo_entry["url_has_credentials"] is True and userinfo_entry["in_scope"] is False

    origin = "https://app.example.org"
    detail = client.get("/api/sitemap/endpoint", params={"origin": origin, "path": "/account", "method": "GET"})
    assert detail.status_code == 200
    assert detail.json()["count"] == 1
    assert detail.json()["flows"][0]["id"] == "in-flow"
    assert "profile" not in detail.json()["flows"][0]["url"]
    # Treat the origin strictly: do not echo supplied query values into preview URLs.
    bad_origin = client.get("/api/sitemap/endpoint", params={"origin": "https://app.example.org/?token=secret", "path": "/account"})
    assert bad_origin.status_code == 422
    from pytest import raises
    with raises(ValueError, match="query"):
        store.list_endpoint_flows(origin="https://app.example.org/?token=secret", path="/account")

    scope_data = client.get("/api/scope").json()
    assert scope_data["loopback_default_in_scope"] is True
    assert scope_data["explicit_exclusions_override_loopback"] is True


def test_passive_findings_api_status_and_reanalysis_are_persistent(tmp_path: Path):
    client, store = build_client(tmp_path)
    add_flow(store, "finding-flow", "https://lab.example.org/", response_headers=[("Content-Type", "text/html"), ("Server", "nginx/1.22.0")])
    flow = store.get_flow("finding-flow")
    findings = analyze_flow(flow)
    assert findings
    store.save_findings("finding-flow", findings)

    response = client.get("/api/findings?severity=low&status=open")
    assert response.status_code == 200
    assert response.json()["count"] > 0
    finding_id = response.json()["findings"][0]["id"]
    changed = client.post(f"/api/findings/{finding_id}/status", json={"status": "false_positive"})
    assert changed.status_code == 200
    assert client.get(f"/api/findings/{finding_id}").json()["status"] == "false_positive"
    assert client.get("/api/findings?status=false_positive").json()["count"] == 1

    # The reanalysis task only consumes saved flow data and finishes before TestClient returns.
    queued = client.post("/api/findings/reanalyze?limit=10")
    assert queued.status_code == 200 and queued.json()["queued"] == 1
    assert store.get_finding(finding_id)["status"] == "false_positive"


def test_tools_api_transform_and_compare_with_validation(tmp_path: Path):
    client, _ = build_client(tmp_path)
    encoded = client.post("/api/tools/transform", json={"operation": "base64_encode", "value": "雪 ✓"})
    assert encoded.status_code == 200
    decoded = client.post("/api/tools/transform", json={"operation": "base64_decode", "value": encoded.json()["output"]})
    assert decoded.json()["output"] == "雪 ✓"
    assert client.post("/api/tools/transform", json={"operation": "hex_decode", "value": "xyz"}).status_code == 422

    diff = client.post("/api/tools/compare", json={"left": "A: 1\n\nold", "right": "A: 2\n\nnew", "mode": "text"})
    assert diff.status_code == 200
    assert diff.json()["modified"] == 2
    assert diff.json()["identical"] is False
    assert client.post("/api/tools/compare", json={"left": "x", "right": "y", "mode": "crawler"}).status_code == 422


def test_old_milestone1_database_is_migrated_in_place(tmp_path: Path):
    database = tmp_path / "history.sqlite3"
    store = Store(database)
    store.record_request(flow_id="kept", started_at=1, method="GET", url="http://127.0.0.1/kept", host="127.0.0.1", path="/kept", headers=[], body=b"")
    store.close()
    import sqlite3
    with sqlite3.connect(database) as db:
        db.execute("DROP TABLE findings")
        db.execute("DROP TABLE schema_migrations")
    upgraded = Store(database)
    assert upgraded.get_flow("kept") is not None
    with sqlite3.connect(database) as db:
        versions = [row[0] for row in db.execute("SELECT version FROM schema_migrations ORDER BY version")]
    assert versions == [1, 2, 3]


def test_findings_reanalysis_removes_stale_rows_and_preserves_statuses(tmp_path: Path):
    client, store = build_client(tmp_path)
    add_flow(store, "replace-findings", "https://lab.example.org/", response_headers=[("Content-Type", "text/html")])
    flow = store.get_flow("replace-findings")
    findings = analyze_flow(flow)
    assert len(findings) > 1
    store.save_findings("replace-findings", findings)
    keep = findings[0]["id"]
    assert store.update_finding_status(keep, "resolved")

    # A new analysis result replaces obsolete rules for this capture, but stable IDs retain user review status.
    store.save_findings("replace-findings", [findings[0]])
    remaining = store.list_findings(search="", limit=1000)
    assert [item["id"] for item in remaining] == [keep]
    assert remaining[0]["status"] == "resolved"
    store.save_findings("replace-findings", [])
    assert store.list_findings(limit=1000) == []
