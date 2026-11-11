"""Tests for netverify.tcp.verify_tcp_connection and its Boolean wrapper.

socket.create_connection is mocked, so no network or DNS access is used.
"""

import errno
import socket
from unittest.mock import patch

import pytest

from netverify.results import (
    Failure,
    FailureReason,
    Protocol,
    Target,
    VerificationResult,
)
from netverify.tcp import check_tcp_connection, verify_tcp_connection

CREATE_CONNECTION = "netverify.tcp.socket.create_connection"
HOST = "192.0.2.10"
PORT = 80


@pytest.fixture
def mock_create_connection():
    with patch(CREATE_CONNECTION) as mock:
        yield mock


def test_successful_connection_gives_successful_result(mock_create_connection):
    result = verify_tcp_connection(HOST, PORT)

    assert result.success is True
    assert result.failure is None
    assert result.protocol is Protocol.TCP
    assert result.target == Target(HOST, PORT)
    assert result.duration_seconds >= 0

    # Same socket usage as the Boolean API: connect, then close cleanly.
    mock_create_connection.assert_called_once_with((HOST, PORT), timeout=2.0)
    mock_create_connection.return_value.__exit__.assert_called_once_with(None, None, None)


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
         FailureReason.CONNECTION_REFUSED),
        (TimeoutError("timed out"), FailureReason.TIMEOUT),
        (socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
         FailureReason.DNS_RESOLUTION_FAILED),
        (OSError(errno.ENETUNREACH, "Network is unreachable"),
         FailureReason.NETWORK_UNREACHABLE),
        (OSError(errno.EHOSTUNREACH, "No route to host"), FailureReason.HOST_UNREACHABLE),
        (OSError(errno.EADDRNOTAVAIL, "Can't assign requested address"),
         FailureReason.SOCKET_ERROR),
    ],
    ids=["refused", "timeout", "dns", "network-unreachable", "host-unreachable", "other"],
)
def test_failures_are_classified(mock_create_connection, error, reason):
    mock_create_connection.side_effect = error

    result = verify_tcp_connection(HOST, PORT)

    assert result.success is False
    assert result.reason is reason
    assert result.failure.message == str(error)
    assert result.failure.exception_type == type(error).__name__
    # Target and protocol are reported on failure too.
    assert result.protocol is Protocol.TCP
    assert result.target == Target(HOST, PORT)
    assert result.duration_seconds >= 0


def test_duration_comes_from_monotonic_clock(mock_create_connection):
    # A fake clock makes the duration deterministic.
    with patch("netverify.tcp.monotonic", side_effect=[100.0, 100.25]):
        result = verify_tcp_connection(HOST, PORT)

    assert result.duration_seconds == pytest.approx(0.25)


def test_unexpected_error_propagates(mock_create_connection):
    mock_create_connection.side_effect = ValueError("unexpected")

    with pytest.raises(ValueError):
        verify_tcp_connection(HOST, PORT)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [(None, True), (Failure(FailureReason.TIMEOUT, "timed out"), False)],
    ids=["success", "failure"],
)
def test_boolean_api_delegates_to_detailed_api(failure, expected):
    result = VerificationResult(Protocol.TCP, Target(HOST, PORT), 0.0, failure)

    with patch("netverify.tcp.verify_tcp_connection", return_value=result) as verify:
        assert check_tcp_connection(HOST, PORT, timeout=0.5) is expected

    verify.assert_called_once_with(HOST, PORT, timeout=0.5)
