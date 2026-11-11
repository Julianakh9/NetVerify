"""TCP connectivity checks for NetVerify."""

import socket
from time import monotonic

from netverify.diagnostics import classify_os_error
from netverify.results import Failure, Protocol, Target, VerificationResult


def verify_tcp_connection(
    host: str, port: int, timeout: float = 2.0
) -> VerificationResult:
    """Try to establish a TCP connection and describe the outcome.

    The connection is closed immediately. No application data is sent.

    Args:
        host: Hostname or IP address to connect to.
        port: TCP port number to connect to.
        timeout: Socket timeout in seconds for connection attempts; not a
            strict deadline for the entire function.

    Returns:
        A successful VerificationResult if the connection succeeds, or a
        failed one whose failure is classified from the OSError raised.

    Raises:
        Any exception that is not an OSError, such as a programming error,
        propagates unchanged.
    """
    failure: Failure | None = None
    start = monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as exc:
        failure = classify_os_error(exc)
    duration = monotonic() - start

    return VerificationResult(
        protocol=Protocol.TCP,
        target=Target(host, port),
        duration_seconds=duration,
        failure=failure,
    )


def check_tcp_connection(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check whether a TCP connection can be established.

    Equivalent to verify_tcp_connection(host, port, timeout=timeout).success.

    Args:
        host: Hostname or IP address to connect to.
        port: TCP port number to connect to.
        timeout: Socket timeout in seconds for connection attempts; not a
            strict deadline for the entire function.

    Returns:
        True if the connection succeeds. False if it fails with an OSError,
        such as a refused connection, a timeout, or an unresolvable hostname.
    """
    return verify_tcp_connection(host, port, timeout=timeout).success
