"""Tests for netverify.tcp.check_tcp_connection.

socket.create_connection is replaced with a mock in every test,
so no real network connections or DNS lookups are made.
"""

import socket
from unittest.mock import patch

import pytest

from netverify.tcp import check_tcp_connection

CREATE_CONNECTION = "netverify.tcp.socket.create_connection"


@pytest.fixture
def mock_create_connection():
    """Replace socket.create_connection with a MagicMock for one test."""
    with patch(CREATE_CONNECTION) as mock:
        yield mock


def test_successful_connection_returns_true(mock_create_connection):
    result = check_tcp_connection("example.com", 80)

    assert result is True
    # The address is passed as one (host, port) tuple with the default timeout.
    mock_create_connection.assert_called_once_with(("example.com", 80), timeout=2.0)

    # The returned socket was used as a context manager and exited cleanly.
    sock = mock_create_connection.return_value
    sock.__enter__.assert_called_once_with()
    sock.__exit__.assert_called_once_with(None, None, None)


def test_custom_timeout_is_passed_through(mock_create_connection):
    check_tcp_connection("example.com", 443, timeout=0.5)

    mock_create_connection.assert_called_once_with(("example.com", 443), timeout=0.5)


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError("connection refused"),
        TimeoutError("timed out"),
        socket.gaierror("name resolution failed"),
        OSError("network unreachable"),
    ],
    ids=["refused", "timeout", "dns-failure", "generic-oserror"],
)
def test_os_errors_return_false(mock_create_connection, error):
    # Make the mocked create_connection raise this error.
    mock_create_connection.side_effect = error

    assert check_tcp_connection("example.com", 80) is False


def test_unexpected_error_is_not_swallowed(mock_create_connection):
    # Only OSError should become False; other errors must reach the caller.
    mock_create_connection.side_effect = ValueError("unexpected")

    with pytest.raises(ValueError):
        check_tcp_connection("example.com", 80)
