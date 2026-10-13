from wirescope.analysis import analyze_flow


def base_flow(**overrides):
    value = {
        "id": "capture-1", "url": "https://lab.local/account", "status": 200,
        "response_headers": [("Content-Type", "text/html; charset=utf-8")],
        "response_body": b"<html><script src=\"http://cdn.lab.local/app.js\"></script></html>",
        "response_truncated": False,
    }
    value.update(overrides)
    return value


def test_analyzer_finds_missing_headers_and_mixed_content_without_network():
    findings = analyze_flow(base_flow())
    rules = {item["rule_id"] for item in findings}
    assert "header.csp.missing" in rules
    assert "header.nosniff.missing" in rules
    assert "header.hsts.missing" in rules
    mixed = next(item for item in findings if item["rule_id"] == "content.mixed_http")
    assert "cdn.lab.local/app.js" in mixed["evidence"]
    assert mixed["severity"] == "medium"
    assert all(item["id"] and item["flow_id"] == "capture-1" and item["remediation"] for item in findings)


def test_analyzer_cookie_flags_and_never_persists_cookie_value_as_evidence():
    flow = base_flow(response_headers=[("Content-Type", "text/html"), ("Set-Cookie", "session=topsecretvalue; Path=/")])
    findings = analyze_flow(flow)
    cookie_findings = [item for item in findings if item["rule_id"].startswith("cookie.")]
    assert {item["rule_id"].split(":")[0] for item in cookie_findings} >= {
        "cookie.secure.missing", "cookie.httponly.missing", "cookie.samesite.missing"
    }
    assert all("topsecretvalue" not in item["evidence"] for item in cookie_findings)


def test_analyzer_redacts_secret_and_flags_error_disclosure():
    flow = base_flow(response_body=b"Traceback (most recent call last):\napi_key=ABCDEFGHIJKLMNOPQRSTUVXYZ0123456789")
    findings = analyze_flow(flow)
    assert any(item["rule_id"].startswith("disclosure.error:") for item in findings)
    secret = next(item for item in findings if item["rule_id"].startswith("disclosure.sensitive:"))
    assert "redacted" in secret["evidence"]
    assert "ABCDEFGHIJKLMNOPQRSTUVXYZ0123456789" not in secret["evidence"]


def test_analyzer_skips_missing_responses_and_marks_partial_body():
    assert analyze_flow(base_flow(status=None)) == []
    findings = analyze_flow(base_flow(response_truncated=True))
    assert any(item["rule_id"] == "analysis.body_truncated" for item in findings)


def test_finding_url_redacts_userinfo_and_query_values():
    flow = base_flow(url="https://alice:secret@lab.local/private?token=supersecret&tab=profile")
    finding = analyze_flow(flow)[0]
    assert "alice" not in finding["url"] and "secret" not in finding["url"]
    assert "supersecret" not in finding["url"]
    assert "token" in finding["url"] and "profile" not in finding["url"]


def test_finding_url_never_falls_back_to_unredacted_non_http_url():
    finding = analyze_flow(base_flow(url="ftp://user:password@lab.local/file?token=supersecret"))[0]
    assert finding["url"] == "[invalid captured URL]"
    assert "password" not in finding["url"] and "supersecret" not in finding["url"]


def test_analyzer_flags_unrecognized_security_policy_values():
    flow = base_flow(response_headers=[
        ("Content-Type", "text/html"),
        ("Referrer-Policy", "send-everything"),
        ("Set-Cookie", "session=secret-value; SameSite=maybe"),
    ])
    findings = analyze_flow(flow)
    rules = {item["rule_id"] for item in findings}
    assert "header.referrer-policy.invalid" in rules
    assert "cookie.samesite.invalid:session" in rules
    assert all("secret-value" not in item["evidence"] for item in findings if item["rule_id"].startswith("cookie."))


def test_analyzer_detects_json_style_secret_assignment_without_copying_value():
    secret_value = "very-long-api-secret-value-123456789"
    findings = analyze_flow(base_flow(response_body=(('{"api_key":"' + secret_value + '"}').encode())))
    finding = next(item for item in findings if item["rule_id"].startswith("disclosure.sensitive:"))
    assert secret_value not in finding["evidence"]
    assert "redacted" in finding["evidence"]


def test_analyzer_flags_zero_or_malformed_hsts_max_age():
    for value in ("max-age=0", "max-age=000; includeSubDomains", "max-age=oops"):
        findings = analyze_flow(base_flow(response_headers=[("Content-Type", "text/html"), ("Strict-Transport-Security", value)]))
        assert any(item["rule_id"] == "header.hsts.weak" for item in findings), value
