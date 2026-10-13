# Contributing

Thanks for helping build WireScope. The focus is a maintainable, local-first desktop tool for authorized web security testing.

## Before a pull request

1. Describe the security boundary or user need in the issue/PR.
2. Add tests for behavior, including negative/error cases and scope enforcement when network targets are involved.
3. Use local loopback lab targets in tests. Tests must not scan public services or require a live third-party endpoint.
4. Run `python -m pytest -q` and `node --check electron/main.cjs`; verify that request/response bodies, cookies, Authorization headers, and tokens are not written to application logs.
5. Update `docs/MILESTONES.md` and `DEPENDENCIES.md` for feature/dependency changes.

## Engineering conventions

- No telemetry, remote UI assets, cloud dependencies, paid APIs, mandatory accounts, or proprietary desktop runtime dependency.
- Keep default listeners on loopback. Never allow UI settings to expose the proxy to a LAN interface.
- Active network checks must be opt-in, scope-gated, conservative by default, bounded by request/time budgets, cancellable, and covered by local integration tests.
- Avoid destructive exploit primitives, stealth, persistence, credential theft, brute force, and denial-of-service functionality.
- Do not display future workspace buttons until each operation is implemented and tested.
- Keep network I/O bounded. Repeater caps request/response bodies at 2 MiB and timeouts at 30 seconds.
- Preserve third-party license notices. Generate and review exact Python/npm inventories for platform releases.

## Development setup

```bash
python -m venv .venv
# Activate it for your platform
python -m pip install -e '.[dev,package]'
npm install
python -m pytest -q
node --check electron/main.cjs
npm start
```

Build on the target platform using the commands in README.md. Before releases, commit a reviewed `package-lock.json`, use `npm ci` in CI, audit included third-party notices, and run the HTTP/HTTPS lab integration test on each supported OS.
