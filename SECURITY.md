# Security policy

## Authorized use only

Use WireScope only on systems you own or are explicitly authorized to assess. The proxy binds to loopback only and must not be exposed through port forwarding or a tunnel. Repeater and manually initiated WebSocket messages are scope-checked before network access/action. WebSocket handshakes are checked by URL hostname and the normalized Host; the resolved peer is also checked against explicit IP exclusions before the HTTP upgrade is forwarded. Include/exclude rules use one shared policy: a matching explicit `exclude` always wins, including for loopback; otherwise loopback is in scope by default and external hosts require explicit inclusion.

## Passive analysis and additional traffic

The Site Map is derived only from previously captured SQLite traffic; it does not crawl hosts, resolve targets, or send requests to discover endpoints. WebSocket capture is passive and hooks the existing mitmproxy flow; it does not create WebSocket connections to populate the workspace. The Findings analyzer inspects persisted response headers and the stored response-body prefix and never initiates active probes. Decoder and Comparer are local transformations and perform no network operations. Reanalysis applies rules to saved captures only.

Findings are heuristic indicators, not confirmed vulnerabilities. Header omissions may be intentional, pattern matches may be false positives, and body checks cannot inspect beyond the 2 MiB history body limit. Finding evidence avoids copying detected secret values. Site Map and Findings previews strip URL userinfo and redact query values, but the HTTP History intentionally preserves original captured headers, cookies, URLs, and bounded bodies for inspection.

## Local CA and stored data

WireScope's CA private key is security-sensitive. Import only the public PEM into a dedicated test browser/profile, not into a general-purpose account or system trust store. The CA is never installed automatically; do not share private-key material from the WireScope data directory. Remove test trust after use when appropriate.

Traffic history and findings are stored locally in SQLite and are **not encrypted at rest**. Protect the OS account, backups, and WireScope data directory. The per-launch API token reduces cross-origin drive-by access but is not a boundary against malicious processes running as the same OS user. The Electron renderer disables Node integration, enables context isolation and sandboxing, blocks external navigation/popups, and denies browser permission requests.

## Runtime guarantees and limitations

- API and proxy listeners bind to `127.0.0.1` only.
- Repeater preserves upstream TLS certificate verification, does not use ambient proxy environment variables, does not automatically follow redirects, and rejects out-of-scope hosts, malformed requests, and embedded URL credentials.
- WebSocket scope enforcement has an explicit DNS timing boundary: `server_connect` checks the selected upstream authority before connecting where possible, while exclusions based only on a DNS-resolved peer IP are checked after TCP connection but before forwarding the HTTP upgrade. If peer identity is unavailable while explicit exclusions exist, the WebSocket is rejected and manual sending fails closed. This is not a general DNS-rebinding defense for unrelated HTTP flows.
- No telemetry, cloud synchronization, accounts, paid APIs, or remote UI assets are required.
- The current release has not been qualified via native installer or real-socket mitmproxy HTTP/HTTPS/WebSocket integration in this environment or every supported operating system. A source test or build configuration does not establish platform qualification; the live mitmproxy runtime and Electron GUI remain unverified here because their dependencies could not be installed.

## Report vulnerabilities

Please do not publish exploit details for an unpatched security issue. Open a private security advisory in the repository host if enabled, or contact the maintainers using the private contact documented by the project owner. Include the version, operating system, reproduction steps, expected impact, and whether the report used only a local lab. Never attach real credentials or other people's traffic.
