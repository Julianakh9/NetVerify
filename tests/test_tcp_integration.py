"""Integration test for check_tcp_connection using a real loopback socket.

No mocks: a real TCP listener is opened on 127.0.0.1 and the function
connects to it. Nothing leaves this machine.
"""

import socket

from netverify.results import FailureReason, Protocol, Target
from netverify.tcp import check_tcp_connection, verify_tcp_connection


def test_real_tcp_connection_to_local_listener():
    # IPv4 (AF_INET) + TCP (SOCK_STREAM) listening socket.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        # Port 0 asks the OS to pick any free port.
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()

        # The OS completes the handshake from the listen queue,
        # so this succeeds even before accept() is called.
        assert check_tcp_connection(host, port, timeout=1.0) is True

        # Collect the queued connection so it is closed cleanly.
        listener.settimeout(1.0)
        accepted, _ = listener.accept()
        with accepted:
            pass


def test_verify_reports_success_for_local_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()

        result = verify_tcp_connection(host, port, timeout=1.0)

        listener.settimeout(1.0)
        accepted, _ = listener.accept()
        with accepted:
            pass

    assert result.success is True
    assert result.protocol is Protocol.TCP
    assert result.target == Target(host, port)
    assert result.duration_seconds >= 0


def test_verify_reports_refused_for_port_without_listener():
    # Get a free port from the OS, then release it, so nothing is listening.
    # A socket that is bound but not listening is not used: on macOS,
    # connections to it time out instead of being refused.
    # Small theoretical race: another process could take the port between
    # close() and the connection attempt; the test would then fail, not hang.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        host, port = probe.getsockname()

    result = verify_tcp_connection(host, port, timeout=1.0)

    assert result.reason is FailureReason.CONNECTION_REFUSED
    assert result.failure.exception_type == "ConnectionRefusedError"
    assert result.target == Target(host, port)
