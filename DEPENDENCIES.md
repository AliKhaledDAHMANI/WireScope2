# Dependency and license inventory

WireScope's own source is licensed under Apache-2.0. The desktop runtime uses Electron, which bundles the open-source Chromium rendering engine and Node.js. The application does not depend on WebView2, a system WebKit installation, a proprietary runtime, a paid API, or a hosted service.

The tables below list direct dependencies and their declared licenses. They are not a substitute for the exact transitive license inventory required for redistribution. Generate the two inventories for the exact build environment as described below, review each license expression and bundled notice, and include the generated files with release assets.

## Python runtime and packaging dependencies

| Dependency | Purpose | Declared license | Required for |
|---|---|---|---|
| Python standard library | sockets, TLS, SQLite, HTTP utilities, process/runtime | PSF-2.0 | Backend |
| `mitmproxy` | Intercepting HTTP/HTTPS proxy and local certificate generation | MIT | Runtime |
| `fastapi` | Loopback-only local API | MIT | Runtime |
| `uvicorn` | Local ASGI server | BSD-3-Clause | Runtime |
| `pytest` | Automated tests | MIT | Development |
| `pytest-cov` | Test coverage reporting | MIT | Development |
| `httpx` | FastAPI test transport | BSD-3-Clause | Development/test |
| `cryptography` | Test TLS certificates for local integration tests | Apache-2.0 OR BSD-3-Clause | Development/test |
| `pyinstaller` | Bundle the Python backend into a standalone sidecar | GPL-2.0-or-later with bootloader exception; verify exact terms | Packaging |

## JavaScript / desktop dependencies

| Dependency | Purpose | Declared license | Required for |
|---|---|---|---|
| `electron` | Desktop window, open-source Chromium + Node.js runtime | MIT; Electron/Chromium/Node ship additional notices | Desktop runtime |
| `electron-builder` | Build Windows NSIS, Linux AppImage/DEB, and macOS DMG targets | MIT | Packaging |

The full dependency tree contains additional licenses. Chromium, Node.js, Electron, and platform packaging tools carry their own third-party notices. A release must include/review those notices and cannot be considered legally cleared solely from this direct-dependency table.

## Generate the exact environment inventory

After dependencies have been installed for the selected platform:

```bash
python scripts/generate_licenses.py --output THIRD_PARTY_PYTHON_LICENSES.json
node scripts/generate_node_licenses.cjs --output THIRD_PARTY_NODE_LICENSES.json
```

Both commands inspect installed package metadata and report unknown/missing metadata instead of claiming that the inventory is complete. For redistribution, manually verify license expressions, obtain required license texts/notices, and inspect the extra third-party notices included by Electron and Chromium. Repeat on each release platform/architecture.

## Milestones 2–3 additions

Site Map aggregation, passive analysis, URL/Base64/hex/HTML transformations, text comparison, WebSocket SQLite persistence, and the deterministic loopback WebSocket lab use Python standard-library modules only (`sqlite3`, `hashlib`, `re`, `urllib.parse`, `base64`, `html`, `difflib`, `asyncio`, `struct`, and socket/HTTP primitives). No new third-party runtime dependency was introduced for Milestone 2 or 3. WebSocket capture uses the existing mitmproxy runtime dependency; it does not add another proxy engine. This does not change the requirement to inventory and review all transitive dependencies of the existing Python/Electron runtime before distribution.
