from pathlib import Path

from wirescope.scope import ScopePolicy
from wirescope.store import Store


def test_scope_fails_closed_and_exclusions_win(tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    scope = ScopePolicy(store)
    assert scope.url_in_scope("http://127.0.0.1:5000/")
    assert scope.url_in_scope("http://localhost/")
    assert not scope.url_in_scope("https://example.org/")
    store.add_scope_rule("*.example.org", "include")
    assert scope.url_in_scope("https://api.example.org/v1")
    assert not scope.url_in_scope("https://example.org/")
    store.add_scope_rule("private.api.example.org", "exclude")
    assert not scope.url_in_scope("https://private.api.example.org/")
    store.add_scope_rule("api.example.org", "exclude")
    assert store.add_scope_rule("api.example.org", "include")["mode"] == "include"
    assert not scope.url_in_scope("https://api.example.org/")
    assert not scope.url_in_scope("https://user:pass@example.org/")
    assert not scope.url_in_scope("file:///etc/passwd")


def test_explicit_exclusion_overrides_builtin_loopback_allowance(tmp_path: Path):
    store = Store(tmp_path / "history.sqlite3")
    scope = ScopePolicy(store)
    assert scope.url_in_scope("http://127.0.0.1:5000/")
    store.add_scope_rule("127.0.0.1", "exclude")
    assert not scope.url_in_scope("http://127.0.0.1:5000/")


def test_websocket_scope_accepts_ws_schemes_and_canonicalizes_hosts(tmp_path: Path):
    store = Store(tmp_path / "ws-scope.sqlite3")
    scope = ScopePolicy(store)
    assert scope.websocket_url_in_scope("ws://127.0.0.1:8766/echo")
    assert scope.websocket_url_in_scope("wss://localhost/socket")
    assert not scope.websocket_url_in_scope("wss://user:pass@localhost/socket")
    assert not scope.websocket_url_in_scope("file:///etc/passwd")
    store.add_scope_rule("example.org", "include")
    assert scope.websocket_url_in_scope("wss://EXAMPLE.ORG./")
    assert scope.websocket_url_in_scope("ws://127.1:8766/echo")
    store.add_scope_rule("127.0.0.1", "exclude")
    assert not scope.websocket_url_in_scope("ws://127.1:8766/echo")
    assert scope.address_explicitly_excluded("127.0.0.1")
    assert scope.address_explicitly_excluded("::ffff:127.0.0.1")


def test_scope_normalizes_equivalent_ip_notations_in_scope_rules(tmp_path: Path):
    store = Store(tmp_path / "scope-ip-forms.sqlite3")
    scope = ScopePolicy(store)
    store.add_scope_rule("::ffff:127.0.0.1", "exclude")
    assert not scope.host_in_scope("127.0.0.1")
    assert not scope.host_in_scope("127.1")
    assert scope.address_explicitly_excluded("127.0.0.1")
    store.add_scope_rule("*.xn--bcher-kva.example", "include")
    assert scope.host_in_scope("api.bücher.example")
