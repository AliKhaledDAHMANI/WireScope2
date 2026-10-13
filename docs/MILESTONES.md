# Milestone status

Status below distinguishes implementation in source from behavior verified in this authoring environment. A checked source item does not mean a native desktop release has been qualified.

## Milestone 1 — implemented in source; end-to-end/release qualification pending

- [x] Electron shell and bundled Chromium/Node runtime configuration.
- [x] Loopback-only Python API, per-launch token, and backend sidecar entry point.
- [x] mitmproxy HTTP/HTTPS interception integration in source.
- [x] Locally managed CA material and manual PEM export; no automatic trust installation.
- [x] Request interception toggle and paused-flow queue, edit/forward/forward unchanged/drop actions.
- [x] SQLite traffic history and request/response detail APIs with 2 MiB body caps.
- [x] Repeater raw request parser and scope-gated networking, with TLS verification and redirects disabled.
- [x] Scope include/exclude rules, with explicit exclusions taking priority over inclusions and the implicit loopback allowance.
- [x] Unit/API tests for core store, proxy add-on, scope, local Repeater server, interception actions, and API session token.
- [x] Real-socket HTTP/HTTPS integration test exists and targets only local lab servers.
- [x] Electron Builder configuration for Windows NSIS, Linux AppImage/DEB, and macOS DMG.
- [ ] Run the real-socket proxy integration test in an environment with mitmproxy and test crypto dependencies installed.
- [ ] Verify a clean backend/Electron installation, proxy behavior, install/upgrade/uninstall on Windows, Linux, and macOS.
- [ ] Produce and review resolved Python/npm lockfiles with integrity hashes and full transitive license notices; perform signing/notarization where appropriate.

## Milestone 2 — implemented in source; unit/API/static checks pass; desktop/proxy qualification pending

- [x] **Site Map:** host/path-segment navigation tree derived from SQLite traffic only, search and host/method/content-type/status/scope filters, query parameter names, status/content types/counts/timestamps, related capture inspection, and URL-preview redaction. No crawling or added requests.
- [x] **Scope integration:** Site Map uses the existing `ScopePolicy`; excluded destinations are out of scope even if they are loopback. Repeater continues to use the same scope implementation.
- [x] **Passive Findings:** asynchronous analysis of persisted captured response data, persisted finding records, unique stable IDs, severity/confidence/evidence/explanation/remediation/source-flow references, filtering/search/status updates, and reanalysis of existing captures. No active probes are sent.
- [x] **Decoder/Encoder:** local URL, Base64, hex, and HTML entity conversions; strict malformed-input handling, Unicode handling, binary byte preservation as hex/Base64, and size limits.
- [x] **Comparer:** local text/request/response/header/body comparison, normalized line endings, context/add/remove/modify classification, unified diff, source loading from history, and input/line limits.
- [x] SQLite schema version 2 migration adds persisted Findings without recreating older history rows.
- [x] API integration tests for module routes, scope filters, finding status/persistence, transforms/compare validation, and migration from an old schema.
- [x] UI contract tests confirm workspace navigation, local assets, and new control/API wiring; JavaScript syntax checks run separately.
- [ ] Launch GUI with installed Electron dependencies and verify interactions manually or with end-to-end browser/desktop automation.
- [ ] Execute real-socket HTTP/HTTPS proxy integration tests in an environment where `mitmproxy` is installed.
- [ ] Verify packaged app startup and sidecar behavior from native installers on all supported OSes.

### Milestone 2 baseline (before Milestone 3 changes)

```text
python -m pytest -q
67 passed, 1 skipped
```

The skipped test is `tests/integration/test_proxy_integration.py`; `mitmproxy` is not installed in this network-restricted environment. The suite covers deterministic module/unit behavior and API tests, including local Repeater traffic, but it does not prove the live mitmproxy HTTP/HTTPS integration works in this runtime. `node --check` validates JavaScript syntax only; the Electron dependencies are not installed here, so the desktop app and native installers have not been launched or built.

## Milestone 3 — WebSocket source implementation; live proxy integration pending

- [x] Implement WebSocket upgrade/frame lifecycle capture through the existing mitmproxy hooks (`request`, `response`, `websocket_start`, `websocket_message`, `websocket_end`, `error`, `server_connect`, `server_connected`, and `server_connect_error`); no second proxy engine or crawler. Runtime behavior still requires real-socket verification.
- [x] Store handshake metadata and captured text/binary message bytes in SQLite, linked to the originating HTTP flow, with timestamps, direction, opcode, payload size, truncation marker, close metadata, errors, and source (`captured` vs `user`).
- [x] Add connection/message search, state/direction/opcode filters, pagination, payload inspection, and source-flow links in the local WebSockets workspace.
- [x] Add manual message send only over a currently active, explicitly selected in-memory connection; enforce current shared scope, connection open state, peer IP exclusions, configured payload size, and API token.
- [x] Normalize IP/hostname representations in scope matching and make explicit exclusions win. `server_connect` rejects a prohibited selected authority before TCP where possible; `server_connected` rejects resolved IP exclusions before forwarding HTTP upgrade bytes. A DNS target can receive a TCP connection before its resolved IP is checked; missing peer identity fails closed when exclusions exist. This is not a general DNS-rebinding defense.
- [x] Add bounded persistence defaults: per-message cap 256 KiB, 50,000 retained messages and 64 MiB retained payload; configurable through clamped environment variables. Stored binary payloads remain byte-exact within the cap.
- [x] Add a deterministic, non-destructive WebSocket lab hard-bound to `127.0.0.1`, plus tests for echo, binary acknowledgement, multi-message operation and close behavior.
- [x] Add SQLite schema version 3 in-place migration, startup recovery for connections left open after a crash, and regression tests for Milestones 1 and 2.
- [x] No new third-party runtime dependency introduced; the existing mitmproxy package remains the only proxy engine.
- [ ] Run the real-socket WebSocket proxy integration test in an environment with mitmproxy and test crypto dependencies installed.
- [ ] Launch the Electron app with dependencies installed and verify live UI interaction, manual send, and closed-connection states against the lab.
- [ ] Verify packaged app startup and sidecar behavior from native installers on all supported OSes.

### Verification and stabilization attempt (2026-10-13) — incomplete

Baseline at the start of this pass:

```text
python -m pytest -q
83 passed, 2 skipped
```

After adding regression coverage for the pre-connect selected-authority check, unknown resolved peers, fail-closed manual sending, and concurrent payload-byte retention:

```text
python -m pytest -q
88 passed, 2 skipped
python -m compileall -q src/wirescope lab
passed
node --check electron/main.cjs
passed
node --check src/wirescope/static/app.js
passed
```

The two explicit integration commands were also run:

```text
python -m pytest -q tests/integration/test_proxy_integration.py -rs
1 skipped; exit code 5 (module skipped at import because mitmproxy is absent)
python -m pytest -q tests/integration/test_websocket_proxy_integration.py -rs
1 skipped; exit code 5 (module skipped at import because mitmproxy is absent)
```

Dependency installation was attempted but blocked by the environment: `python -m pip install -e '.[dev,package]' --retries 0 --timeout 5` failed resolving `setuptools>=69` because package-index DNS failed. `npm install` timed out during the Electron registry fetch (`EAI_AGAIN`); `node_modules` remains absent. `npm start` exited 127 (`electron: not found`). Therefore real HTTP, HTTPS, and WebSocket proxy traffic is **not verified**, and the Electron desktop GUI has **not been launched or exercised**.

The backend-only smoke test did run: with `PYTHONPATH=src python -m wirescope --port 18765`, `/api/health` returned `{"ok":true,"app":"WireScope"}` and `/` served HTTP 200 with the WebSockets workspace markup. This is not a GUI/proxy E2E test. The source archive contains every non-cache regular file in the inspected repository; see the stabilization delivery checksum. Milestone 3 remains incomplete until both live integration suites run without skips, and manual send/persistence/closure are observed against the local lab through the real proxy runtime.

## Milestone 4 candidate: controlled testing extensions and workflow completeness

- [ ] Add an opt-in, conservative Intruder-style manual payload runner only after per-target request budgets, concurrency/rate limits, strict scope validation, and a global emergency stop are specified and tested.
- [ ] Add separately enabled active checks with bounded budgets, scope enforcement, and local-lab-only test coverage.
- [ ] Design a documented analyzer/plugin API with an explicit extension trust and permissions model.
- [ ] Consider named project workflows, import/export, and optional local encryption.

Source features marked above are implemented, but real-socket proxy integration, interactive desktop behavior, and native releases remain unverified as explicitly listed. Do not mark Milestone 3 fully verified until both live HTTP/HTTPS and WebSocket proxy integration tests pass in an environment with mitmproxy installed, the desktop UI workflows are exercised, and remaining scope limitations are reviewed.
