"""TCP connectivity checks for NetVerify."""

import socket


def check_tcp_connection(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check whether a TCP connection can be established.

    Args:
        host: Hostname or IP address to connect to.
        port: TCP port number to connect to.
        timeout: Socket timeout in seconds for connection attempts; not a
            strict deadline for the entire function.

    Returns:
        True if the connection succeeds. False if it fails with an OSError,
        such as a refused connection, a timeout, or an unresolvable hostname.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
