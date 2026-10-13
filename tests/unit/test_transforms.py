import pytest

from wirescope.transforms import TransformError, transform


@pytest.mark.parametrize("encoder,decoder,value", [
    ("url_encode", "url_decode", "Hello, 雪 ☃ /?&=+"),
    ("base64_encode", "base64_decode", "Unicode ✓ café 你好"),
    ("hex_encode", "hex_decode", "null bytes are text here: 0"),
    ("html_encode", "html_decode", "<tag a='x'>& \"Unicode 雪\""),
])
def test_transform_round_trip_unicode(encoder, decoder, value):
    encoded = transform(encoder, value)
    decoded = transform(decoder, encoded["output"])
    assert decoded["output"] == value
    assert not decoded["binary"]


def test_empty_input_round_trips():
    for operation in ("url_encode", "url_decode", "base64_encode", "base64_decode", "hex_encode", "hex_decode", "html_encode", "html_decode"):
        result = transform(operation, "")
        assert result["output"] == ""
        assert result["binary"] is False


@pytest.mark.parametrize("operation,value", [
    ("url_decode", "%GG"), ("base64_decode", "not base64!"),
    ("hex_decode", "abc"), ("hex_decode", "0x00"),
])
def test_malformed_input_is_reported(operation, value):
    with pytest.raises(TransformError):
        transform(operation, value)


def test_binary_decoding_preserves_exact_bytes_without_utf8_replacement():
    result = transform("hex_decode", "ff00fe")
    assert result["binary"] is True
    assert result["output"] == ""
    assert result["hex"] == "ff00fe"
    assert result["base64"] == "/wD+"
    assert "not valid UTF-8" in result["warning"]


def test_input_limit_and_unknown_operation():
    with pytest.raises(TransformError, match="2 MiB"):
        transform("url_encode", "x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(TransformError, match="Unsupported"):
        transform("whatever", "x")


def test_invalid_unicode_surrogate_is_reported():
    with pytest.raises(TransformError, match="invalid Unicode surrogate"):
        transform("base64_encode", "\ud800")
