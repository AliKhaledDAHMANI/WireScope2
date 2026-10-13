"""Conservative, passive-only analysis of already captured HTTP responses.

The analyzer performs no network I/O. Evidence is intentionally redacted before it is
persisted in findings so a detected token is not duplicated into a second database row.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 0),
    ("AWS access key identifier", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    ("GitHub token-like value", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), 0),
    ("Slack token-like value", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), 0),
    ("Named credential or secret assignment", re.compile(r"(?i)[\"']?(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|passphrase)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{20,})"), 1),
    ("JWT-like token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0),
)
_ERROR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Python traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("PHP fatal error", re.compile(r"Fatal error:\s*(?:Uncaught\s+)?", re.I)),
    ("SQL database error", re.compile(r"(?:SQLSTATE\[[0-9A-Z]+\]|syntax error near|You have an error in your SQL syntax|ORA-\d{5})", re.I)),
    ("Java exception trace", re.compile(r"(?:Exception in thread \"[^\"]+\"|\bat [\w.$]+\([^)]*\.java:\d+\))")),
    ("Unhandled exception message", re.compile(r"\bUnhandled (?:Exception|Promise Rejection)\b", re.I)),
)
_MIXED_CONTENT = re.compile(
    r"(?is)<(?:script|iframe|frame|img|audio|video|source|track|input|embed|object)\b[^>]*?\b(?:src|data)\s*=\s*([\"'])\s*http://([^\"']+)\1"
    r"|<link\b(?=[^>]*\brel\s*=\s*([\"'])(?:stylesheet|preload|modulepreload)[\"'])[^>]*\bhref\s*=\s*([\"'])\s*http://([^\"']+)\4"
    r"|url\(\s*([\"']?)http://([^\)\"'\s]+)\6\s*\)"
)
_SESSION_COOKIE = re.compile(r"(?:session|sess|auth|token|jwt|login|sid|csrf)", re.I)


def _safe_finding_url(url: str) -> str:
    """Retain the affected endpoint while removing URL userinfo and query values."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.casefold()
        hostname = (parts.hostname or "").casefold()
        if not hostname or scheme not in {"http", "https"}:
            return "[invalid captured URL]"
        host_display = f"[{hostname}]" if ":" in hostname else hostname
        try:
            port = parts.port
        except ValueError:
            port = None
        netloc = host_display + (f":{port}" if port is not None else "")
        try:
            query_pairs = [(key, "[redacted]") for key, _ in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100)]
        except ValueError:
            query_pairs = []
        safe_query = urlencode(query_pairs) if query_pairs else ""
        return urlunsplit((scheme, netloc, parts.path or "/", safe_query, ""))[:2048]
    except (ValueError, UnicodeError):
        return "[invalid captured URL]"


def _header_map(headers: Any) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for item in headers or []:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        name, value = str(item[0]), str(item[1])
        output.setdefault(name.casefold(), []).append(value)
    return output


def _body_text(body: Any) -> str:
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    if isinstance(body, str):
        return body
    return ""


def _finding(flow_id: str, rule_id: str, title: str, severity: str, confidence: str,
             url: str, evidence: str, explanation: str, remediation: str) -> dict[str, Any]:
    signature = hashlib.sha256(evidence.encode("utf-8", errors="replace")).hexdigest()[:16]
    finding_id = hashlib.sha256(f"{flow_id}\0{rule_id}\0{signature}".encode()).hexdigest()[:32]
    return {
        "id": finding_id, "flow_id": flow_id, "rule_id": rule_id, "title": title,
        "severity": severity, "confidence": confidence, "url": url,
        "evidence": evidence[:500], "explanation": explanation,
        "remediation": remediation,
    }


def analyze_flow(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """Return explainable findings from one persisted flow; never initiates requests."""
    flow_id = str(flow.get("id") or "")
    raw_url = str(flow.get("url") or "")
    if not flow_id or not raw_url or flow.get("status") is None:
        return []
    url = _safe_finding_url(raw_url)
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        parsed = urlsplit("")
    is_https = parsed.scheme.casefold() == "https"
    response_headers = _header_map(flow.get("response_headers"))
    content_type = ",".join(response_headers.get("content-type", [])).casefold()
    body = _body_text(flow.get("response_body", b""))
    is_html = "text/html" in content_type or "application/xhtml+xml" in content_type or bool(re.search(r"(?i)<html(?:\s|>)", body[:8192]))
    findings: list[dict[str, Any]] = []

    def add(rule: str, title: str, severity: str, confidence: str, evidence: str,
            explanation: str, remediation: str) -> None:
        findings.append(_finding(flow_id, rule, title, severity, confidence, url,
                                 evidence, explanation, remediation))

    csp_values = [value.strip() for value in response_headers.get("content-security-policy", []) if value.strip()]
    if is_html and not csp_values:
        add("header.csp.missing", "HTML response lacks a usable Content-Security-Policy", "low", "low",
            "No non-empty Content-Security-Policy response header was captured.",
            "A CSP can reduce the impact of certain injection flaws, but its absence alone does not prove an exploitable vulnerability and some applications intentionally use other controls.",
            "Assess the application's resource requirements and introduce a restrictive Content-Security-Policy, starting with Report-Only where appropriate.")
    elif is_html and not any(re.search(r"(?i)(?:^|;)\s*[a-z][a-z0-9-]*(?:\s|;|$)", value) for value in csp_values):
        add("header.csp.unusable", "Content-Security-Policy may contain no usable directives", "low", "medium",
            "A non-empty CSP header was captured, but no directive name was recognized.",
            "A syntactically empty or malformed policy may not provide the intended browser protections. Parser behavior can vary, so confirm the exact wire header and browser behavior.",
            "Replace the policy with a syntactically valid, application-specific Content-Security-Policy and validate it in report-only mode before enforcement.")
    if not any(v.strip().casefold() == "nosniff" for v in response_headers.get("x-content-type-options", [])):
        add("header.nosniff.missing", "X-Content-Type-Options is missing or not nosniff", "low", "low",
            "No X-Content-Type-Options: nosniff header was captured.",
            "Without nosniff, some browsers may perform MIME sniffing. The impact depends on response types and browser behavior.",
            "Send X-Content-Type-Options: nosniff and set accurate Content-Type values.")
    hsts_values = [value.strip() for value in response_headers.get("strict-transport-security", []) if value.strip()]
    if is_https and not hsts_values:
        add("header.hsts.missing", "HTTPS response lacks Strict-Transport-Security", "low", "low",
            "No non-empty Strict-Transport-Security response header was captured.",
            "HSTS helps browsers enforce HTTPS on future visits; absence is not evidence that transport is currently unencrypted.",
            "For HTTPS-only production hosts, consider a carefully tested Strict-Transport-Security policy with an appropriate max-age.")
    elif is_https and any(
        (match := re.search(r"(?i)(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)", value)) is None
        or not match.group(1).lstrip("0")
        for value in hsts_values
    ):
        add("header.hsts.weak", "Strict-Transport-Security may be ineffective", "low", "medium",
            "; ".join(hsts_values[:3]),
            "At least one HSTS value has no numeric max-age or sets max-age=0. The server may be intentionally disabling HSTS, but browsers may not retain an HTTPS-only policy.",
            "For HTTPS-only production hosts, choose a positive max-age after validating subdomains and deployment requirements.")
    referrer_values = [value.strip().casefold() for value in response_headers.get("referrer-policy", []) if value.strip()]
    valid_referrer_policies = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
                               "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
    referrer_tokens = [token.strip() for value in referrer_values for token in value.split(",") if token.strip()]
    if is_html and not referrer_values:
        add("header.referrer-policy.missing", "HTML response lacks Referrer-Policy", "info", "low",
            "No Referrer-Policy response header was captured.",
            "Browser defaults can send referrer information to other destinations. Whether this matters depends on URLs and browser policy.",
            "Set an explicit Referrer-Policy, commonly strict-origin-when-cross-origin, or a stricter policy matching the application.")
    elif is_html and (not referrer_tokens or any(token not in valid_referrer_policies for token in referrer_tokens)):
        add("header.referrer-policy.invalid", "Referrer-Policy contains an unrecognized directive", "low", "medium",
            "At least one captured Referrer-Policy token is not a recognized policy name.",
            "Browsers may ignore an invalid policy token or fall back to another recognized token. Review multiple values and deployment intent before treating this as a defect.",
            "Use a documented Referrer-Policy value such as strict-origin-when-cross-origin, no-referrer, or same-origin.")
    csp = " ".join(csp_values)
    has_frame_ancestors = bool(re.search(r"(?i)(?:^|;)\s*frame-ancestors\b", csp))
    xfo_values = [value.strip().casefold() for value in response_headers.get("x-frame-options", []) if value.strip()]
    has_valid_xfo = any(value in {"deny", "sameorigin"} for value in xfo_values)
    if is_html and not has_valid_xfo and not has_frame_ancestors:
        add("header.framing.missing", "HTML response has no usable anti-framing policy", "low", "low",
            "Neither a recognized X-Frame-Options value (DENY/SAMEORIGIN) nor a CSP frame-ancestors directive was captured.",
            "The page may be frameable, which can enable clickjacking in some contexts. Some pages are intentionally embeddable.",
            "Set Content-Security-Policy frame-ancestors to the minimum allowed origins; use X-Frame-Options for older clients if needed.")

    for cookie_value in response_headers.get("set-cookie", []):
        parts = [part.strip() for part in cookie_value.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue
        cookie_name = parts[0].split("=", 1)[0].strip()[:100]
        attrs = {p.split("=", 1)[0].strip().casefold(): p.split("=", 1)[1].strip() if "=" in p else "" for p in parts[1:]}
        sensitive_name = bool(_SESSION_COOKIE.search(cookie_name))
        if "secure" not in attrs:
            add(f"cookie.secure.missing:{cookie_name}", f"Cookie {cookie_name} is not marked Secure", "medium" if sensitive_name else "low", "medium" if sensitive_name else "low",
                f"Set-Cookie names {cookie_name}; Secure attribute is absent on the captured {parsed.scheme or 'unknown-scheme'} response (cookie value omitted).",
                "A cookie without Secure may be sent over plaintext HTTP if the application is also reachable there. The captured response scheme and the cookie's actual purpose should be reviewed; some test or intentionally non-sensitive cookies may not need the flag.",
                "For cookies intended to be used only over HTTPS, set Secure and avoid sending sensitive cookies over plaintext HTTP.")
        if "httponly" not in attrs:
            add(f"cookie.httponly.missing:{cookie_name}", f"Cookie {cookie_name} lacks HttpOnly", "medium" if sensitive_name else "low", "low",
                f"Set-Cookie names {cookie_name}; HttpOnly attribute is absent (cookie value omitted).",
                "JavaScript may be able to read this cookie. Some cookies are intentionally script-readable, so review their purpose before changing the flag.",
                "For session and authentication cookies, set HttpOnly unless client-side script access is explicitly required.")
        same_site_raw = attrs.get("samesite")
        same_site = same_site_raw.casefold().strip() if same_site_raw is not None else ""
        if not same_site:
            add(f"cookie.samesite.missing:{cookie_name}", f"Cookie {cookie_name} lacks SameSite", "low", "low",
                f"Set-Cookie names {cookie_name}; SameSite attribute is absent or empty (cookie value omitted).",
                "Cross-site cookie behavior may rely on browser defaults; the appropriate policy depends on the application's cross-site flows.",
                "Set SameSite=Lax or Strict where compatible; use SameSite=None only for intentional cross-site use and pair it with Secure.")
        elif same_site == "none" and "secure" not in attrs:
            add(f"cookie.samesite.none_without_secure:{cookie_name}", f"Cookie {cookie_name} uses SameSite=None without Secure", "medium", "high",
                f"Set-Cookie names {cookie_name}; SameSite=None is present without Secure (cookie value omitted).",
                "Modern browsers require Secure for SameSite=None cookies, so the cookie may be rejected or fail to behave as intended.",
                "Add Secure to the cookie and verify cross-site behavior in supported browsers.")
        elif same_site not in {"lax", "strict", "none"}:
            add(f"cookie.samesite.invalid:{cookie_name}", f"Cookie {cookie_name} has an unrecognized SameSite value", "low", "medium",
                f"Set-Cookie names {cookie_name}; SameSite value is unrecognized (cookie value omitted).",
                "Browsers may ignore an unrecognized SameSite value and apply their default behavior. Some custom clients may interpret it differently.",
                "Use SameSite=Lax or Strict where compatible, or SameSite=None only for intentional cross-site use together with Secure.")

    if is_https and is_html and body:
        matches = list(_MIXED_CONTENT.finditer(body[:2 * 1024 * 1024]))
        if matches:
            samples = []
            for match in matches[:3]:
                candidate = match.group(2) or match.group(5) or match.group(7) or "HTTP resource"
                # A short origin/path hint is enough; avoid duplicating full page content.
                try:
                    resource = urlsplit("http://" + candidate)
                    samples.append((resource.hostname or "HTTP resource") + (resource.path or "/"))
                except ValueError:
                    samples.append("HTTP resource")
            add("content.mixed_http", "HTTPS HTML references HTTP subresources", "medium", "medium",
                "Detected HTTP subresource reference(s): " + "; ".join(samples),
                "A subresource loaded over HTTP can be modified in transit even when the containing page uses HTTPS. The check is heuristic and may include inert or unused markup.",
                "Serve active and passive subresources over HTTPS and update embedded resource URLs.")

    disclosure_values = []
    for header_name in ("server", "x-powered-by", "x-aspnet-version", "x-runtime", "x-generator"):
        for value in response_headers.get(header_name, []):
            clean = value.strip()[:120]
            if clean:
                disclosure_values.append(f"{header_name}: {clean}")
    versioned = any(re.search(r"\d+(?:\.\d+){1,}", value) for value in disclosure_values)
    if disclosure_values:
        add("disclosure.server_banner", "Response discloses server or technology banner", "low", "high" if versioned else "medium",
            "; ".join(disclosure_values[:4]),
            "Server and framework headers can reveal implementation details and occasionally exact versions. A banner alone is not a vulnerability, and suppressing it does not replace patching.",
            "Remove unnecessary framework/version headers and keep exposed software patched; avoid relying on banner suppression as a primary defense.")

    if body:
        for title, pattern in _ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                add("disclosure.error:" + title.casefold().replace(" ", "_"), "Response may expose a detailed error", "medium", "medium",
                    f"Matched indicator: {match.group(0)[:100]!r}; surrounding response text omitted.",
                    f"The captured response contains a pattern consistent with a {title.lower()}. It may be a sample, documentation, or intentionally displayed content; verify context before treating it as a defect.",
                    "Return generic client-facing errors and keep stack traces, SQL diagnostics, paths, and runtime details in protected server-side logs.")
            if len(findings) >= 80:
                break
        for title, pattern, secret_group in _SECRET_PATTERNS:
            match = pattern.search(body)
            if not match:
                continue
            evidence_match = match.group(secret_group) if secret_group else match.group(0)
            offset = match.start(secret_group) if secret_group else match.start()
            add("disclosure.sensitive:" + title.casefold().replace(" ", "_").replace("/", "_"),
                "Response may expose sensitive material", "high" if title == "Private key material" else "medium", "medium",
                f"Potential {title.lower()} indicator at response character offset {offset}; matched value redacted.",
                "A conservative pattern matched content commonly associated with credentials or private key material. The value is not copied into this finding; false positives are possible, especially in test fixtures or documentation.",
                "Confirm the response's intended audience, remove exposed secrets, rotate any real credentials, and prevent secrets from entering client-visible responses.")
            if len(findings) >= 80:
                break

    if flow.get("response_truncated"):
        add("analysis.body_truncated", "Response body analysis was partial", "info", "high",
            "Stored response body reached the 2 MiB history limit; analysis covered only the stored prefix.",
            "Body-based checks cannot establish that content beyond the stored prefix is safe or free of indicators. This is an inspection limitation, not a vulnerability finding.",
            "Inspect the full response using an appropriate local test capture or reduce the response size before drawing conclusions.")

    return findings
