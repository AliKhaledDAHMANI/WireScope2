import argparse

import pytest

from wirescope.server import _port


@pytest.mark.parametrize("value,expected", [("1", 1), ("8765", 8765), ("65535", 65535)])
def test_port_accepts_valid_tcp_ports(value, expected):
    assert _port(value) == expected


@pytest.mark.parametrize("value", ["", "abc", "0", "-1", "65536", "1.5"])
def test_port_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError):
        _port(value)
