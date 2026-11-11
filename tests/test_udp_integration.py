"""Integration tests for check_udp_echo using a real UDP server on loopback.

A one-shot UDP server runs in a worker thread on 127.0.0.1 while the test
thread acts as the client. No mocks, no sleeps, and no external hosts.
"""

import socket
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager

from netverify.results import FailureReason, Protocol, Target
from netverify.udp import BUFFER_SIZE, check_udp_echo, verify_udp_echo

LOOPBACK = "127.0.0.1"

# Generous limits: a passing test never waits for them.
# CLIENT_TIMEOUT: socket timeout passed to check_udp_echo.
# SERVER_TIMEOUT: socket timeout for each blocking call in the server
#   thread. This, not RESULT_TIMEOUT, is what makes the thread end.
# RESULT_TIMEOUT: how long the test waits on the Future. It does not stop
#   the thread; it only fails the wait if the thread has not finished.
CLIENT_TIMEOUT = 2.0
SERVER_TIMEOUT = 5.0
RESULT_TIMEOUT = SERVER_TIMEOUT + 1.0

Address = tuple[str, int]
Received = tuple[bytes, Address]
Responder = Callable[[bytes], bytes | None]


def _serve_one_datagram(sock: socket.socket, respond: Responder) -> Received:
    """Receive one datagram, send back respond(data) unless it is None."""
    data, client = sock.recvfrom(BUFFER_SIZE)
    reply = respond(data)
    if reply is not None:
        sock.sendto(reply, client)
    return data, client


@contextmanager
def udp_server(respond: Responder) -> Iterator[tuple[Address, Future[Received]]]:
    """Run a one-shot UDP server on 127.0.0.1 in a worker thread.

    Yields the server address and a Future holding (data, client_address)
    of the datagram it received. Any exception raised in the server thread
    is re-raised in the test when the block exits normally.

    Thread termination: the server thread ends because each of its socket
    calls times out after SERVER_TIMEOUT. That bound holds only if `respond`
    returns promptly; cleanup waits for the thread with no timeout of its
    own, so a `respond` that blocks forever would hang the test.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Bind before starting the thread, so a datagram sent at any point
        # after this is queued by the kernel and cannot be missed.
        sock.bind((LOOPBACK, 0))
        # Bounds each blocking socket call in the server thread.
        sock.settimeout(SERVER_TIMEOUT)

        # Leaving this block calls executor.shutdown(wait=True), which waits
        # for the thread with no timeout, before the socket is closed.
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_serve_one_datagram, sock, respond)
            yield sock.getsockname(), future
            # Surface server-side errors even if the test did not check.
            # If this wait times out it raises, but the thread keeps running
            # until its socket timeout, and shutdown still waits for it.
            future.result(timeout=RESULT_TIMEOUT)


def test_udp_echo_succeeds_against_real_server():
    with udp_server(respond=lambda data: data) as ((host, port), server):
        result = check_udp_echo(host, port, timeout=CLIENT_TIMEOUT)
        received, client = server.result(timeout=RESULT_TIMEOUT)

    assert result is True
    # The server really received the default payload over loopback.
    assert received == b"netverify-ping"
    assert client[0] == LOOPBACK


def test_udp_echo_rejects_incorrect_payload_from_real_server():
    with udp_server(respond=lambda data: b"unexpected-reply") as ((host, port), server):
        result = check_udp_echo(host, port, payload=b"hello", timeout=CLIENT_TIMEOUT)
        received, _ = server.result(timeout=RESULT_TIMEOUT)

    assert received == b"hello"
    # A reply arrived from the right address, but its content was wrong.
    assert result is False


def test_udp_echo_returns_false_when_real_server_does_not_reply():
    with udp_server(respond=lambda data: None) as ((host, port), server):
        # The client must give up after its own timeout.
        result = check_udp_echo(host, port, timeout=0.2)
        received, _ = server.result(timeout=RESULT_TIMEOUT)

    assert received == b"netverify-ping"
    assert result is False


def test_verify_reports_success_from_real_server():
    with udp_server(respond=lambda data: data) as ((host, port), server):
        result = verify_udp_echo(host, port, timeout=CLIENT_TIMEOUT)
        server.result(timeout=RESULT_TIMEOUT)

    assert result.success is True
    assert result.protocol is Protocol.UDP
    assert result.target == Target(host, port)
    assert result.duration_seconds >= 0


def test_verify_reports_payload_mismatch_from_real_server():
    with udp_server(respond=lambda data: b"unexpected-reply") as ((host, port), server):
        result = verify_udp_echo(host, port, timeout=CLIENT_TIMEOUT)
        server.result(timeout=RESULT_TIMEOUT)

    assert result.reason is FailureReason.PAYLOAD_MISMATCH
    assert "b'unexpected-reply'" in result.failure.message


def test_verify_reports_timeout_when_real_server_does_not_reply():
    with udp_server(respond=lambda data: None) as ((host, port), server):
        result = verify_udp_echo(host, port, timeout=0.2)
        server.result(timeout=RESULT_TIMEOUT)

    assert result.reason is FailureReason.TIMEOUT
    assert result.failure.exception_type == "TimeoutError"
