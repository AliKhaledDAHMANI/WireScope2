# WireScope

**A free, open-source, local-first desktop HTTP/HTTPS inspection and security-analysis workbench.** Milestones 1–3 provide a real mitmproxy-based HTTP/HTTPS proxy, SQLite traffic history, intercepted-request actions, a scope-gated Repeater, a traffic-derived Site Map, a passive response analyzer with persistent Findings, a local Decoder/Encoder, a local line Comparer, and a proxy-captured WebSocket inspector with persisted frames and scope-gated manual sending. The app is intended for personal use and private teams, not a public SaaS. No account, API key, subscription, telemetry, or cloud service is required.

> **Status: early alpha; not end-to-end qualified.** The current local suite passes 88 tests and skips two real-socket proxy integration tests because `mitmproxy` is unavailable. The backend health/API smoke test passed, but live HTTP/HTTPS/WebSocket proxying and the Electron desktop GUI were not verified: package-index DNS is unavailable, so Python and npm dependency installation could not complete. See [the verification log](docs/MILESTONES.md).

## Workspaces

- **Proxy:** local HTTP/HTTPS proxy listener, intercept toggle and pending-request queue, inspect/edit/forward/drop actions, and manual export of the generated CA certificate. HTTPS interception is provided by mitmproxy when the declared dependencies are installed.
- **HTTP History:** SQLite traffic history, search, and request/response detail views. Stored body bytes are capped at 2 MiB per direction and truncation is recorded.
- **Repeater:** manually edit and send a raw HTTP/1 request; requests are parsed and bounded before network access, use TLS certificate verification, do not automatically follow redirects, do not use ambient proxy settings, and are checked against the existing scope policy.
- **Site Map:** a navigable host → path-segment tree built only from persisted proxy captures. Search/filter by host, path, method, content type, response status, and scope. Shows observed status codes, parameter **names** (not values), counts, and related captures. Does not crawl or send requests to populate the map.
- **Findings:** passive analysis of captured responses for potentially missing/misconfigured security headers, cookie flags, mixed HTTP subresources on HTTPS HTML pages, technology banners, obvious error disclosures, and conservative secret-like patterns. Findings have evidence, severity, confidence, explanations, remediation, capture references, and persistent review status (`open`, `false_positive`, `resolved`). Findings are indicators to review, not automatic confirmation of vulnerabilities.
- **Decoder & Encoder:** local URL, Base64, hexadecimal, and HTML entity transformations. Malformed inputs return errors. Decoded bytes that are not valid UTF-8 are surfaced as exact hex/Base64 bytes rather than replaced with lossy text.
- **Comparer:** local line comparison for text, HTTP requests/responses, headers, or bodies. Shows context, additions, removals, modified line pairs, and a unified diff. Does not send requests.
- **WebSockets:** the source uses the existing mitmproxy hooks for upgrade metadata and captured text/binary frames, direction, timestamps, opcode, close/error state, filtering, pagination, and payload inspection. Manual sending is restricted to a selected, established, in-scope live connection. Stored messages have byte/count caps. Literal/upstream-authority checks run before connect where possible; DNS-resolved peers are checked before forwarding the HTTP upgrade, and missing peer identity fails closed when explicit exclusions exist. Live proxy behavior is not verified in this environment because mitmproxy could not be installed.
- **Settings & scope:** include/exclude host patterns. Explicit exclusions always win, including over the built-in loopback allowance. Non-loopback targets require an inclusion rule before the Repeater or WebSocket sender may send a request/message.

No crawler, Intruder/payload runner, active scanner, or third-party plugin API is implemented; those workspaces are not presented as completed features.

## Safety and privacy model

- The application API and proxy bind to `127.0.0.1` only. The API uses a random per-launch session token.
- Traffic, CA material, scope rules, and findings are stored locally in the application's data directory. There is no telemetry, cloud sync, remote UI assets, or outbound dependency from the analysis/transform/compare modules.
- The local interception CA is **never installed automatically**. Export the public certificate and trust it only in a dedicated test browser/profile when required; do not share its private key.
- Explicit scope exclusions always take precedence. Repeater preserves upstream TLS verification, disables redirect following, and fails closed for malformed requests, embedded URL credentials, and out-of-scope destinations.
- Passive analysis never initiates a request. New captures are analyzed asynchronously from persisted traffic; saved history can be reanalyzed from the Findings workspace.
- Sensitive finding URL query values and URL userinfo are redacted in Site Map/Findings previews. This does not redact original HTTP History, which intentionally retains the captured request and response for inspection.
- Local SQLite data is not encrypted at rest. Protect the OS account and WireScope data directory. The API token is not a boundary against malicious code running as the same OS user.
- Use the application only for systems you own or are explicitly authorized to test. It has no exploitation, stealth, persistence, credential theft, brute-force, or denial-of-service features.

## Technology and runtime

- **Desktop shell:** Electron, which bundles open-source Chromium and Node.js; renderer Node integration is disabled, context isolation/sandbox are enabled, and external navigation/popups are blocked.
- **Backend:** Python 3.11–3.13, FastAPI, Uvicorn, SQLite, and mitmproxy.
- **UI:** local static HTML/CSS/JavaScript served by FastAPI; no remote scripts, CDNs, or external fonts.
- **Milestones 2–3 analysis, comparison, transforms, and WebSocket persistence/lab:** Python standard library only; no new third-party runtime dependency was added for these modules.
- **Packaging:** PyInstaller backend sidecar and Electron Builder configurations for Windows NSIS, Linux AppImage/DEB, and macOS DMG. These are build configurations, not verified installers in this environment.
- Direct dependency license information and license-generation steps are in [`DEPENDENCIES.md`](DEPENDENCIES.md). Full transitive notices must be reviewed for each release environment.

## Run from source

Requirements: Python 3.11–3.13, Node.js 22, npm, and package-index access for the declared dependencies.

```bash
git clone <your-fork-url> wirescope
cd wirescope
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,package]'
npm install
npm start
```

For development, the Electron shell starts the backend with `python` on Windows or `python3` on Linux/macOS. Activate the intended virtual environment first or set `WIRESCOPE_PYTHON` to its Python executable. The UI and API communicate through a temporary loopback port and per-launch token. The traffic proxy binds to `127.0.0.1:8080` by default.

To run only the backend API (without opening Electron):

```bash
python -m wirescope --port 8765
```

This binds the UI/API to `http://127.0.0.1:8765`. It does not create a desktop window.

## Verify with the local lab

Run the deliberately small, non-destructive local target in a separate terminal:

```bash
python lab/run_lab.py --host 127.0.0.1 --port 5000
```

Start WireScope's proxy and use the Repeater to send this request to the lab:

```http
GET http://127.0.0.1:5000/ HTTP/1.1
Host: 127.0.0.1:5000
Accept: */*

```

To inspect browser traffic, configure a dedicated test browser to use `127.0.0.1:8080` as its HTTP and HTTPS proxy. To decrypt HTTPS, export the PEM CA and manually trust it only in that dedicated browser/profile. Remove that trust when testing is complete.

Run the loopback-only WebSocket lab in another terminal (it binds only to `127.0.0.1`):

```bash
python lab/websocket_lab.py --host 127.0.0.1 --port 8766
```

Connect a WebSocket test client to `ws://127.0.0.1:8766/echo` through the WireScope proxy. The lab echoes text, acknowledges binary frames, and provides deterministic close/error scenarios. It never connects to external hosts.

## Tests and static checks

Install the declared development dependencies first:

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
node --check electron/main.cjs
node --check src/wirescope/static/app.js
```

The pytest configuration adds `src/` to the import path, so the test command also works from an uninstalled source checkout. Tests use local HTTP test servers, temporary SQLite databases, or deterministic input data. They do not scan public targets. The integrations `tests/integration/test_proxy_integration.py` and `tests/integration/test_websocket_proxy_integration.py` exercise real loopback HTTP/HTTPS and WebSocket sockets using mitmproxy and test certificates, but skip if those dependencies are unavailable. A static HTML/JavaScript contract test checks workspace/nav integration; it is not a substitute for a launched GUI/end-to-end desktop test.

### Latest verification attempt (2026-10-13)

```text
python -m pytest -q
88 passed, 2 skipped
python -m pytest -q tests/integration/test_proxy_integration.py -rs
1 skipped; exit code 5 (no tests collected after import-time skip)
python -m pytest -q tests/integration/test_websocket_proxy_integration.py -rs
1 skipped; exit code 5 (no tests collected after import-time skip)
python -m compileall -q src/wirescope lab
passed
node --check electron/main.cjs
passed
node --check src/wirescope/static/app.js
passed
```

`python -m pip install -e '.[dev,package]' --retries 0 --timeout 5` failed because name resolution for the package index failed while resolving `setuptools>=69`. `npm install` timed out while fetching `electron@44.7.0` (`EAI_AGAIN` for `registry.npmjs.org`); no `node_modules` was created. `npm start` exited 127 (`electron: not found`). The local backend API was launched separately: `/api/health` returned `{"ok":true,"app":"WireScope"}`, and `/` returned HTTP 200 with the WebSockets workspace markup. That smoke test does not verify Electron GUI workflows or proxy traffic. Neither real-socket integration suite ran; do not treat the skips as passes.

## Build desktop installers

Build on each target operating system rather than assuming cross-platform qualification:

```bash
python -m pip install -e '.[dev,package]'
python scripts/validate_pyinstaller_spec.py
python -m PyInstaller --clean --noconfirm wirescope-backend.spec
python scripts/stage_backend.py
npm install
python scripts/generate_licenses.py --output THIRD_PARTY_PYTHON_LICENSES.json
node scripts/generate_node_licenses.cjs --output THIRD_PARTY_NODE_LICENSES.json
npm run dist
```

The PyInstaller spec normalizes static asset `Tree` entries from three-field TOC records into the two-field `(source_path, destination_directory)` pairs required by `Analysis(datas=...)`; nested assets remain under `wirescope/static/`. `scripts/validate_pyinstaller_spec.py` checks both collected mitmproxy and static data entries, plus binary entries, before the backend build.

Electron Builder targets Windows NSIS, Linux AppImage and DEB, and macOS DMG. Artifacts go in `release/`. The dedicated [Build Linux AppImage workflow](.github/workflows/build-appimage.yml) runs on pushes to `main` or `master` and supports manual execution through `workflow_dispatch`; it builds on GitHub-hosted `ubuntu-24.04` and uploads `release/*.AppImage` as the `WireScope-Linux-AppImage` artifact. Open the repository's **Actions** tab, select **Build Linux AppImage**, open a successful run, and download the artifact from **Artifacts**. Branch/PR runs of the cross-platform CI build the Linux DEB separately to avoid duplicating the AppImage build; version-tag builds retain both Linux targets for the existing release upload. Code signing/notarization and platform qualification remain release tasks. A reviewed lockfile with resolved versions and hashes is required before calling a release reproducible; `package-lock.json` is not included until a dependency install generates and validates it. Workflow configuration alone does not establish successful installers: test install/upgrade/uninstall and proxy behavior on each target OS.

## Local data locations

- Windows: `%LOCALAPPDATA%\WireScope\`
- macOS: `~/Library/Application Support/WireScope/`
- Linux: `$XDG_DATA_HOME/WireScope/` or `~/.local/share/WireScope/`

The directory contains `wirescope.sqlite3` and mitmproxy CA/configuration material. The database uses an in-place schema migration ledger; Milestone 2 added persistent Findings and Milestone 3 adds WebSocket connection/message tables, both through in-place migrations without recreating existing traffic. The app does not upload, sync, or back up this data. Project encryption and named-project/import-export management are not implemented.

## Project documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — process and module design, API routes, persistence, and security boundaries
- [`docs/MILESTONES.md`](docs/MILESTONES.md) — verified source/test status and planned work
- [`DEPENDENCIES.md`](DEPENDENCIES.md) — dependency licensing and license-generation workflow
- [`SECURITY.md`](SECURITY.md) — safety model and reporting guidance
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development/testing conventions

## License

WireScope source is licensed under [Apache-2.0](LICENSE). Third-party dependencies retain their own licenses. The project is not affiliated with or endorsed by PortSwigger, Caido, or the mitmproxy project.
