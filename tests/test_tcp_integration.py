"""Integration test for check_tcp_connection using a real loopback socket.

No mocks: a real TCP listener is opened on 127.0.0.1 and the function
connects to it. Nothing leaves this machine.
"""

import socket

from netverify.tcp import check_tcp_connection


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
