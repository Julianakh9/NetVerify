"""Tests for netverify.udp.verify_udp_echo and its Boolean wrapper.

socket.socket is mocked and hosts are IP addresses (or a mocked lookup),
so no network or DNS access is used.
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
from netverify.udp import check_udp_echo, verify_udp_echo

SOCKET_CLASS = "netverify.udp.socket.socket"
GETHOSTBYNAME = "netverify.udp.socket.gethostbyname"

HOST = "192.0.2.10"
PORT = 9999
PAYLOAD = b"netverify-ping"


@pytest.fixture
def mock_socket():
    """Replace socket.socket; by default the reply is a correct echo."""
    with patch(SOCKET_CLASS) as socket_class:
        sock = socket_class.return_value.__enter__.return_value
        sock.recvfrom.return_value = (PAYLOAD, (HOST, PORT))
        yield socket_class, sock


def test_matching_echo_gives_successful_result(mock_socket):
    result = verify_udp_echo(HOST, PORT)

    assert result.success is True
    assert result.protocol is Protocol.UDP
    assert result.target == Target(HOST, PORT)
    assert result.duration_seconds >= 0


def test_timeout_is_classified(mock_socket):
    _, sock = mock_socket
    sock.recvfrom.side_effect = TimeoutError("timed out")

    result = verify_udp_echo(HOST, PORT)

    assert result.reason is FailureReason.TIMEOUT
    assert result.target == Target(HOST, PORT)


def test_payload_mismatch_is_classified(mock_socket):
    _, sock = mock_socket
    sock.recvfrom.return_value = (b"something else", (HOST, PORT))

    result = verify_udp_echo(HOST, PORT)

    assert result.reason is FailureReason.PAYLOAD_MISMATCH
    # Both payloads are shown so the mismatch can be debugged.
    assert "b'something else'" in result.failure.message
    assert "b'netverify-ping'" in result.failure.message
    assert result.failure.exception_type is None


def test_long_mismatched_payload_is_truncated_in_message(mock_socket):
    _, sock = mock_socket
    sock.recvfrom.return_value = (b"x" * 10_000, (HOST, PORT))

    result = verify_udp_echo(HOST, PORT)

    assert result.reason is FailureReason.PAYLOAD_MISMATCH
    assert "10000 bytes" in result.failure.message
    assert len(result.failure.message) < 200


@pytest.mark.parametrize(
    "sender",
    [("192.0.2.99", PORT), (HOST, 12345)],
    ids=["wrong-ip", "wrong-port"],
)
def test_unexpected_sender_is_classified(mock_socket, sender):
    _, sock = mock_socket
    sock.recvfrom.return_value = (PAYLOAD, sender)

    result = verify_udp_echo(HOST, PORT)

    assert result.reason is FailureReason.UNEXPECTED_SENDER
    assert f"{sender[0]}:{sender[1]}" in result.failure.message
    assert f"{HOST}:{PORT}" in result.failure.message


def test_unexpected_sender_takes_priority_over_payload_mismatch(mock_socket):
    _, sock = mock_socket
    sock.recvfrom.return_value = (b"wrong", ("192.0.2.99", PORT))

    assert verify_udp_echo(HOST, PORT).reason is FailureReason.UNEXPECTED_SENDER


def test_dns_failure_is_classified_before_any_socket_is_created(mock_socket):
    socket_class, _ = mock_socket
    error = socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    with patch(GETHOSTBYNAME, side_effect=error):
        result = verify_udp_echo("unresolvable.invalid", PORT)

    assert result.reason is FailureReason.DNS_RESOLUTION_FAILED
    assert result.target == Target("unresolvable.invalid", PORT)
    socket_class.assert_not_called()


def test_send_error_is_classified_from_errno(mock_socket):
    _, sock = mock_socket
    sock.sendto.side_effect = OSError(errno.ENETUNREACH, "Network is unreachable")

    result = verify_udp_echo(HOST, PORT)

    assert result.reason is FailureReason.NETWORK_UNREACHABLE
    assert result.failure.error_code == errno.ENETUNREACH


def test_duration_comes_from_monotonic_clock(mock_socket):
    with patch("netverify.udp.monotonic", side_effect=[50.0, 50.5]):
        result = verify_udp_echo(HOST, PORT)

    assert result.duration_seconds == pytest.approx(0.5)


def test_unexpected_error_propagates(mock_socket):
    _, sock = mock_socket
    sock.recvfrom.side_effect = ValueError("unexpected")

    with pytest.raises(ValueError):
        verify_udp_echo(HOST, PORT)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [(None, True), (Failure(FailureReason.PAYLOAD_MISMATCH, "mismatch"), False)],
    ids=["success", "failure"],
)
def test_boolean_api_delegates_to_detailed_api(failure, expected):
    result = VerificationResult(Protocol.UDP, Target(HOST, PORT), 0.0, failure)

    with patch("netverify.udp.verify_udp_echo", return_value=result) as verify:
        assert check_udp_echo(HOST, PORT, payload=b"hello", timeout=0.5) is expected

    verify.assert_called_once_with(HOST, PORT, payload=b"hello", timeout=0.5)
