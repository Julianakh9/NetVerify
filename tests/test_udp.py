"""Tests for netverify.udp.check_udp_echo.

socket.socket is replaced with a mock in every test, so no real UDP
traffic is sent. Hosts are IP addresses, so no DNS lookups happen.
"""

import socket
from unittest.mock import patch

import pytest

from netverify.udp import BUFFER_SIZE, check_udp_echo

SOCKET_CLASS = "netverify.udp.socket.socket"

HOST = "192.0.2.10"  # Reserved documentation address, never contacted.
PORT = 9999
PAYLOAD = b"netverify-ping"


@pytest.fixture
def mock_socket():
    """Replace socket.socket and return the mock socket used inside `with`."""
    with patch(SOCKET_CLASS) as socket_class:
        sock = socket_class.return_value.__enter__.return_value
        # Default reply: correct payload from the expected address.
        sock.recvfrom.return_value = (PAYLOAD, (HOST, PORT))
        yield socket_class, sock


def test_matching_echo_returns_true(mock_socket):
    socket_class, sock = mock_socket

    assert check_udp_echo(HOST, PORT) is True

    # An IPv4 UDP socket was created and used with the defaults.
    socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout.assert_called_once_with(2.0)
    sock.sendto.assert_called_once_with(PAYLOAD, (HOST, PORT))
    sock.recvfrom.assert_called_once_with(BUFFER_SIZE)

    # The socket was closed by the context manager.
    socket_class.return_value.__exit__.assert_called_once_with(None, None, None)


def test_custom_payload_and_timeout_are_used(mock_socket):
    _, sock = mock_socket
    sock.recvfrom.return_value = (b"hello", (HOST, PORT))

    assert check_udp_echo(HOST, PORT, payload=b"hello", timeout=0.5) is True

    sock.settimeout.assert_called_once_with(0.5)
    sock.sendto.assert_called_once_with(b"hello", (HOST, PORT))


def test_timeout_returns_false(mock_socket):
    _, sock = mock_socket
    # No reply arrives before the timeout.
    sock.recvfrom.side_effect = TimeoutError("timed out")

    assert check_udp_echo(HOST, PORT) is False


def test_incorrect_response_returns_false(mock_socket):
    _, sock = mock_socket
    sock.recvfrom.return_value = (b"something else", (HOST, PORT))

    assert check_udp_echo(HOST, PORT) is False


@pytest.mark.parametrize(
    "sender",
    [("192.0.2.99", PORT), (HOST, 12345)],
    ids=["wrong-ip", "wrong-port"],
)
def test_unexpected_sender_returns_false(mock_socket, sender):
    _, sock = mock_socket
    # Correct payload, but from the wrong address.
    sock.recvfrom.return_value = (PAYLOAD, sender)

    assert check_udp_echo(HOST, PORT) is False


def test_os_error_returns_false(mock_socket):
    _, sock = mock_socket
    sock.sendto.side_effect = OSError("network unreachable")

    assert check_udp_echo(HOST, PORT) is False
