# Architecture

## Process layout

WireScope is an Electron desktop shell with a Python/FastAPI backend sidecar. Electron provides its bundled Chromium and Node.js runtime; the renderer receives local HTML/CSS/JavaScript from FastAPI and has Node integration disabled, context isolation and sandbox enabled, and external navigation/popups blocked. The API binds to `127.0.0.1` on a per-launch port and uses a random session token. The traffic proxy is a separate listener on `127.0.0.1:8080` by default.

```text
Electron main process
  └─ starts Python sidecar
       └─ FastAPI on 127.0.0.1:<temporary port> + per-launch token
          ├─ static local UI
          ├─ Store / SQLite
          │   ├─ HTTP history + scope rules
          │   ├─ findings and review status
          │   └─ WebSocket connections + bounded message bytes
          ├─ ScopePolicy ── shared include/exclude decisions
          ├─ RepeaterClient ── TLS-verified, bounded, scope-gated requests
          └─ ProxyService ── dedicated worker/event loop
               └─ mitmproxy listener on 127.0.0.1:8080
                    └─ WireScopeAddon ── record HTTP + WS hooks → bounded analysis pool
```

## Module boundaries

- `electron/main.cjs`: starts/supervises the backend, chooses a loopback port, hardens the renderer, blocks external navigation/popups, and shuts down the sidecar.
- `server.py`: backend process entry point and local API/store/proxy lifecycle.
- `api.py`: request-model validation, response shaping, session-token authentication, and dispatch. CPU/local transformations and Site Map aggregation that may block are dispatched with `asyncio.to_thread`; saved-history reanalysis runs through FastAPI background tasks.
- `proxy.py`: proxy worker lifetime, interception queue, event-loop-safe live-flow actions, SQLite capture, WebSocket handshake/frame/close/error hooks, DNS-resolved peer exclusion checks, and a bounded two-worker pool for passive analysis after HTTP responses. Live WebSocket flow objects remain in memory only while the proxy process is running; persisted records never enable reconnection. Analysis/capture failures do not log response bodies, frame payloads, or credentials.
- `store.py`: SQLite persistence, bounded HTTP body and WebSocket frame storage, Site Map aggregation, finding upserts/status, bounded message retention, and in-place schema migrations through version 3. Every database operation uses a short-lived connection.
- `scope.py`: single scope-matching implementation used by Site Map filtering, Repeater, and WebSocket upgrade/send decisions. IP literals, mapped IPv4, legacy IPv4 forms, and IDNA hostnames are normalized before rules match. Explicit matching `exclude` rules override `include` rules **and** the implicit loopback allowance. Without an exclusion, loopback is in scope by default; non-loopback requires an explicit include.
- `repeater.py`: bounded raw-request parser and direct HTTP request execution; redirects disabled, no ambient proxy environment, TLS verification enabled, and scope validated before connection.
- `analysis.py`: pure, passive checks over persisted HTTP response data; this module performs no network I/O.
- `transforms.py`: standard-library URL/Base64/hex/HTML encoders and decoders with strict invalid-input behavior and explicit non-UTF-8 binary reporting.
- `comparer.py`: standard-library line comparisons for text, raw requests/responses, headers, and bodies; it only compares provided strings and never makes a network call.
- WebSocket support: implemented in `WireScopeAddon` and `Store` rather than a second proxy engine. Captures use mitmproxy flow hooks for handshake, frame, end, HTTP error, upstream connection error, pre-connect destination-authority checks, and post-connect resolved-peer checking. `server_connect` rejects an out-of-scope authority before opening the upstream connection where that authority is available; DNS-resolved IP exclusions are checked at `server_connected` before the HTTP upgrade is forwarded. Missing peer identity fails closed when explicit exclusions exist. `api.py` serves filtered/page-limited connection/message metadata and byte-safe payload views; manual send uses mitmproxy’s `inject.websocket` command only for active live flows and marks those records as `user`. Live runtime hook behavior remains unverified until the real-socket tests can run.
- `lab/websocket_lab.py`: standard-library WebSocket test target hard-bound to `127.0.0.1`; deterministic text echo, binary acknowledgement, multiple messages, and close/error paths.
- `static/index.html`, `static/app.css`, `static/app.js`: desktop workspace UI. UI event handlers call the authenticated local API; controls are not decorative placeholders.

## HTTP API used by the UI

All `/api/*` workbench routes below require the `X-WireScope-Token` session header. `/api/session` supplies the per-launch token to the local page; it does not expose the token to remote resources because external navigation and remote assets are blocked.

- Proxy/history core: `/api/status`, `/api/proxy/*`, `/api/flows`, `/api/flows/{id}`, `/api/flows/{id}/forward`, `/api/flows/{id}/drop`, `/api/repeater/send`, `/api/ca`.
- Scope: `/api/scope` GET/POST and `/api/scope/{rule_id}` DELETE.
- Site Map: `/api/sitemap` aggregates only persisted observed flows, with text/host/method/content-type/status/scope filters; `/api/sitemap/endpoint` loads related captures for one normalized origin/path/method. It never crawls or issues network requests. Previews redact URL userinfo and query values; original request/response details remain in History by design.
- Findings: `/api/findings` searches/filters stored findings; `/api/findings/{id}` retrieves one finding; `/api/findings/{id}/status` changes its review status; `/api/findings/reanalyze` schedules analysis of existing saved responses only.
- Local tools: `/api/tools/transform` and `/api/tools/compare`. Inputs are bounded and validated; no external service is involved.
- WebSockets: `/api/websockets/config`, `/api/websockets/connections`, `/api/websockets/connections/{id}`, `/api/websockets/connections/{id}/messages`, `/api/websockets/connections/{id}/messages/{message_id}`, and `POST /api/websockets/connections/{id}/send`. All require the session token. Send payloads are strict UTF-8 text or Base64 binary, size-limited, and permitted only for an active in-scope connection.

## Site Map model

Each capture is parsed only to derive its HTTP(S) origin, path, method, query parameter names, response status, content type, and timestamps. Query values are not needed for endpoint grouping. Endpoints are keyed by normalized origin + path + method; per-entry capture IDs and request counts link them back to actual history data. Filtering and scope calculations are performed locally. Inputs that include URL credentials are marked out of scope rather than silently sanitized into an in-scope destination.

## Passive analyzer and findings lifecycle

A completed proxy response is first persisted under its mitmproxy flow ID. `WireScopeAddon` then submits a bounded analysis job; `analysis.py` reads that saved flow, inspects response headers/cookies/body where available, and returns explainable potential findings. It does not call Repeater, crawl, resolve a host, or send another request. The Findings table references the source flow through a foreign key. Stable finding IDs let reanalysis update evidence while retaining the user's status; obsolete findings for the same flow are removed after a successful replacement analysis. Findings can also be regenerated from already persisted history through the local API.

Rules cover missing/misconfigured CSP, X-Content-Type-Options, HSTS, Referrer-Policy and framing controls; Set-Cookie Secure/HttpOnly/SameSite flags; heuristic HTTP subresource references in HTTPS HTML; server/framework banners; recognizable error disclosures; and a small set of conservative secret-like indicators. Body-based checks are limited to the captured prefix, with a finding when the stored response was truncated. Evidence deliberately avoids storing detected secret values and redacts URL userinfo/query values. Results are indicators to review, not confirmation of exploitability. Absence of a header can be intentional, and regex-based detections can have false positives.

The analysis pool is bounded to two workers so bursts of traffic do not spawn an unbounded number of threads. Reanalysis of existing history uses bounded batches. Analysis exceptions do not log response bodies, request credentials, or finding evidence.

## SQLite schema and migration

- Existing `flows` rows persist request/response metadata and bounded bodies; a 2 MiB cap applies to each direction and truncation is recorded.
- `scope_rules` persists include/exclude patterns.
- `schema_migrations` tracks schema versions 1, 2 and 3. Opening an existing Milestone 1/2 store creates the new tables/indexes in place without recreating existing traffic rows.
- `findings` stores rule ID, severity, confidence, affected URL, redacted evidence, explanation, remediation, review status and timestamps. Its `flow_id` foreign key cascades when a history row is deleted.
- `websocket_connections` stores handshake metadata and terminal state, linked by `flow_id` to the original HTTP history record. `websocket_messages` stores captured/user text and binary payloads as `BLOB`, direction, opcode, timestamps, original payload size and truncation flag. Deleting/pruning messages keeps the retained count synchronized.
- Default WebSocket caps are 256 KiB per message, 50,000 retained messages, and 64 MiB retained payload, clamped through `WIRESCOPE_MAX_WS_MESSAGE_BYTES`, `WIRESCOPE_MAX_WS_MESSAGES`, and `WIRESCOPE_MAX_WS_STORAGE_BYTES`. Startup marks open connections from a prior process run as interrupted; live connections are not restored or reconnected.
- Milestones 2–3 use Python standard-library facilities for analysis, transforms, comparisons, WebSocket storage, and the lab; no new third-party runtime dependency was introduced.

## Flow state

A captured flow is keyed by mitmproxy's flow ID. The request hook records metadata/body in SQLite and stores the live mitmproxy object in an in-memory pending map. When interception is enabled, the live flow pauses before it proceeds upstream. UI actions are dispatched onto the proxy's owning event loop so flow mutation/resume/drop happen safely. Responses/errors update the history row and remove the live object from the pending map.

Interception only affects requests observed after it is enabled. Turning interception off does not silently forward requests already paused; each queued flow must be explicitly forwarded or dropped. Stopping the proxy drops paused requests instead of forwarding them.

For WebSockets, the request hook checks URL/Host scope before allowing an upgrade. `server_connect` checks the selected destination authority before TCP setup where possible; `server_connected` checks the resolved peer before forwarding the HTTP upgrade bytes. A hostname whose DNS answer includes an explicitly excluded IP can still receive a TCP connection before this post-connect check; no WebSocket upgrade request is forwarded after the check rejects it. This is not a general DNS-rebinding defense for unrelated HTTP traffic. If mitmproxy cannot expose the peer and any explicit exclusion exists, the WebSocket is rejected; manual sending also fails closed. Mitmproxy frame hooks preserve binary bytes; unsupported control opcodes are not inserted into the application-data timeline. User-injected sends are recorded separately and are not duplicated when mitmproxy later reports the injected message. Closing or restarting the proxy marks live connections closed/interrupted and drops their in-memory send handles.

## Security boundaries and known limitations

- API/proxy listeners bind only to loopback. The per-launch API token is useful defense in depth, not a security boundary against arbitrary local code running as the same OS user.
- HTTPS MITM requires a user to trust the generated CA in a dedicated test client profile. The private key remains locally stored and the CA is never installed automatically. Upstream TLS verification is enabled by default.
- Repeater rejects out-of-scope destinations, embedded URL credentials, malformed requests, and payloads above its 2 MiB editor limit. It does not use proxy environment variables, automatically follow redirects, or disable TLS verification.
- Original HTTP History intentionally preserves captured data (up to the body cap), which may include credentials or personal data. Local database encryption is not implemented; protect OS account access and data-directory permissions.
- The passive analyzer does not inspect content beyond the stored 2 MiB response prefix. It is heuristic and does not establish whether an application is exploitable or compliant.
- The Site Map is a derived index of traffic already captured. It has no spider, DNS discovery, or endpoint probing functionality.
- WebSocket message storage is bounded and older messages may be pruned. Individual oversized frames are persisted only as a prefix with original byte-size and truncation metadata. The UI may display captured sensitive data; there is no at-rest encryption or automatic payload redaction.
- Resolved-IP exclusion is checked when mitmproxy signals a server connection, before the HTTP upgrade is sent, and checked again at WebSocket start/manual send. Scope is based on explicit host/IP rules; this is not a general DNS-rebinding defense for all HTTP traffic.
- A release must audit full Python/npm dependency trees and Electron/Chromium notices. Native builds, signing, and install/upgrade behavior must be tested on each target platform.

## Next growth path

The next milestone candidate is carefully bounded, explicitly opted-in manual test workflows and/or a documented analyzer extension API. Intruder-like payload execution and active scanning remain deferred until separate opt-in, concurrency/rate-limit, strict scope, request-budget, and emergency-stop controls have comprehensive tests. A plugin API should follow only after its extension trust boundary and permissions are designed.
