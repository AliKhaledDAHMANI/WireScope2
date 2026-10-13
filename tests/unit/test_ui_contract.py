from html.parser import HTMLParser
from pathlib import Path

from wirescope.api import STATIC_DIR


class ContractParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.nav_views = set()
        self.workspaces = set()
        self.remote_assets = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            assert values["id"] not in self.ids, f"duplicate HTML id: {values['id']}"
            self.ids.add(values["id"])
        if values.get("data-view"):
            self.nav_views.add(values["data-view"])
        if tag == "section" and "workspace-view" in values.get("class", "").split() and values.get("id", "").startswith("view-"):
            self.workspaces.add(values["id"][5:])
        if tag in {"script", "link"}:
            url = values.get("src") if tag == "script" else values.get("href")
            if url and url.startswith(("http://", "https://", "//")):
                self.remote_assets.append(url)


def test_each_navigation_item_has_a_real_workspace_and_no_remote_ui_assets():
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    parser = ContractParser()
    parser.feed(html)
    assert parser.nav_views <= parser.workspaces
    assert {"sitemap", "findings", "decoder", "comparer", "websockets"} <= parser.workspaces
    assert 'id="sitemap-rows" class="sitemap-rows" aria-label="Observed endpoint tree"' in html
    assert "host → path-segment tree" in (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert not parser.remote_assets


def test_milestone2_controls_are_connected_to_local_api_handlers():
    javascript = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    for route in ("/api/sitemap", "/api/sitemap/endpoint", "/api/findings", "/api/findings/reanalyze", "/api/tools/transform", "/api/tools/compare"):
        assert route in javascript, f"missing UI API integration for {route}"
    for control in ("sitemap-refresh", "findings-reanalyze", "decoder-transform", "compare-run", "finding-status-save"):
        assert f"#{control}" in javascript
    assert "async function refreshCompareSources()" in javascript
    assert "function invalidateCompareResult()" in javascript
    assert "const displayLimit = 3000" in javascript
    assert "Copy unified diff for the complete comparison." in javascript


def test_websocket_workspace_is_connected_to_authenticated_local_api():
    javascript = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    for route in ("/api/websockets/config", "/api/websockets/connections", "/messages?", "/send"):
        assert route in javascript
    for control in ("ws-refresh", "ws-connection-search", "ws-message-search", "ws-message-direction", "ws-message-opcode", "ws-send-button"):
        assert f"#{control}" in javascript
    assert "async function sendWebSocketMessage()" in javascript
    assert "inject.websocket" not in javascript  # injection remains in the backend only
