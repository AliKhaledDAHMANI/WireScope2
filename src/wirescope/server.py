from __future__ import annotations

import argparse

import uvicorn

from .api import create_app
from .paths import data_dir
from .proxy import ProxyService
from .repeater import RepeaterClient
from .scope import ScopePolicy
from .store import Store


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main() -> None:
    """Start the local-only HTTP API consumed by the Electron desktop shell."""
    parser = argparse.ArgumentParser(description="WireScope local desktop backend")
    parser.add_argument("--port", type=_port, default=8765, help="loopback API port (default: 8765)")
    args = parser.parse_args()

    root = data_dir()
    store = Store(root / "wirescope.sqlite3")
    scope = ScopePolicy(store)
    proxy = ProxyService(store, root, scope=scope)
    repeater = RepeaterClient(scope)
    app = create_app(store, proxy, scope, repeater)

    try:
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=args.port,
            log_level="critical",
            access_log=False,
            server_header=False,
            date_header=False,
        )
    finally:
        proxy.close()
        store.close()


if __name__ == "__main__":
    main()
