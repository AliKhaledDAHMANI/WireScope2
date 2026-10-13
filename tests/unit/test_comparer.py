from wirescope.comparer import compare, CompareError
import pytest


def test_identical_content_and_empty_inputs():
    assert compare("same\r\nline", "same\nline")['identical'] is True
    empty = compare("", "")
    assert empty["identical"] is True
    assert empty["rows"] == []


def test_text_diff_reports_added_removed_and_modified_lines():
    result = compare("alpha\nold\nremoved\nkeep\nlast\ntail", "alpha\nnew\nkeep\nlast\nadded\ntail")
    assert result["identical"] is False
    assert result["modified"] == 1
    assert result["removed"] == 1
    assert result["added"] == 1
    assert any(row["type"] == "modified" and row["left"] == "old" and row["right"] == "new" for row in result["rows"])


def test_headers_and_bodies_can_be_compared_separately():
    left = "GET / HTTP/1.1\r\nHost: lab.local\r\nAccept: */*\r\n\r\nold body"
    right = "GET / HTTP/1.1\nHost: lab.local\nAccept: application/json\n\nnew body"
    headers = compare(left, right, "headers")
    assert headers["modified"] == 1
    assert "application/json" in headers["unified_diff"]
    bodies = compare(left, right, "bodies")
    assert bodies["modified"] == 1
    assert bodies["rows"][0]["left"] == "old body"


def test_http_request_and_response_comparison_includes_start_line():
    request = compare("GET / HTTP/1.1\nHost: lab\n\n", "POST / HTTP/1.1\nHost: lab\n\n", "request")
    assert request["modified"] == 1
    response = compare("HTTP/1.1 200 OK\nX-A: 1\n\nA", "HTTP/1.1 201 Created\nX-A: 1\n\nA", "response")
    assert response["modified"] == 1


def test_invalid_mode_and_input_size_rejected():
    with pytest.raises(CompareError):
        compare("a", "b", "network")
    with pytest.raises(CompareError):
        compare("x" * (2 * 1024 * 1024 + 1), "", "text")


def test_headers_mode_accepts_raw_headers_without_a_start_line():
    result = compare("Content-Type: text/plain\nServer: lab", "Content-Type: text/html\nServer: lab", "headers")
    assert result["modified"] == 1
    assert result["rows"][0]["left"] == "Content-Type: text/plain"


def test_large_line_count_is_rejected_before_diff_allocation():
    with pytest.raises(CompareError, match="20,000 lines"):
        compare("x\n" * 20_001, "", "text")
