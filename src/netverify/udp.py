"""UDP echo checks for NetVerify."""

import socket
from time import monotonic

from netverify.diagnostics import classify_os_error
from netverify.results import (
    Failure,
    FailureReason,
    Protocol,
    Target,
    VerificationResult,
)

# Receive buffer capacity for recvfrom(): the most bytes read from one reply.
# This is not the maximum UDP payload, but it can hold any IPv4 UDP payload
# (at most 65,507 bytes), so replies are not truncated.
BUFFER_SIZE = 65535

# How many bytes of a payload to show in failure messages.
_PREVIEW_BYTES = 32


def verify_udp_echo(
    host: str,
    port: int,
    payload: bytes = b"netverify-ping",
    timeout: float = 2.0,
) -> VerificationResult:
    """Send one datagram to a UDP echo service and describe the outcome.

    Only the first reply received is checked. It must come from the host's
    IP address and the same port, and contain exactly the payload sent.

    Args:
        host: Hostname or IPv4 address of the echo service.
        port: UDP port number of the echo service.
        payload: Bytes to send. The reply must contain exactly these bytes.
        timeout: Socket timeout in seconds for each send and receive;
            not a strict deadline for the entire function.

    Returns:
        A successful VerificationResult if the reply is valid. Otherwise a
        failed one with reason UNEXPECTED_SENDER, PAYLOAD_MISMATCH, or a
        reason classified from the OSError raised (for example TIMEOUT).

    Raises:
        Any exception that is not an OSError, such as a programming error,
        propagates unchanged.
    """
    failure: Failure | None = None
    start = monotonic()
    try:
        # Resolve the host once, because replies always report an IP address.
        ip = socket.gethostbyname(host)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (ip, port))
            response, sender = sock.recvfrom(BUFFER_SIZE)
    except OSError as exc:
        failure = classify_os_error(exc)
    else:
        failure = _validate_reply(payload, response, (ip, port), sender)
    duration = monotonic() - start

    return VerificationResult(
        protocol=Protocol.UDP,
        target=Target(host, port),
        duration_seconds=duration,
        failure=failure,
    )


def check_udp_echo(
    host: str,
    port: int,
    payload: bytes = b"netverify-ping",
    timeout: float = 2.0,
) -> bool:
    """Check whether a UDP echo service returns the payload it was sent.

    Equivalent to
    verify_udp_echo(host, port, payload=payload, timeout=timeout).success.

    Args:
        host: Hostname or IPv4 address of the echo service.
        port: UDP port number of the echo service.
        payload: Bytes to send. The reply must contain exactly these bytes.
        timeout: Socket timeout in seconds for each send and receive;
            not a strict deadline for the entire function.

    Returns:
        True if the reply matches the payload and comes from the host's
        IP address and the same port. False if the reply is different,
        comes from another address, or the check fails with an OSError
        such as a timeout or an unresolvable hostname.
    """
    return verify_udp_echo(host, port, payload=payload, timeout=timeout).success


def _validate_reply(
    payload: bytes,
    response: bytes,
    expected_sender: tuple[str, int],
    sender: tuple[str, int],
) -> Failure | None:
    """Return a Failure if the reply is invalid, or None if it is valid.

    The sender is checked first: content from the wrong sender is not
    meaningful, whether or not it happens to match.
    """
    if sender != expected_sender:
        return Failure(
            reason=FailureReason.UNEXPECTED_SENDER,
            message=(
                f"Reply came from {_format_address(sender)}, "
                f"expected {_format_address(expected_sender)}"
            ),
        )
    if response != payload:
        return Failure(
            reason=FailureReason.PAYLOAD_MISMATCH,
            message=(
                f"Reply {_preview(response)} ({len(response)} bytes) does not "
                f"match sent payload {_preview(payload)} ({len(payload)} bytes)"
            ),
        )
    return None


def _format_address(address: tuple[str, int]) -> str:
    return f"{address[0]}:{address[1]}"


def _preview(data: bytes) -> str:
    """Show at most _PREVIEW_BYTES of data, so messages stay short."""
    if len(data) <= _PREVIEW_BYTES:
        return repr(data)
    return repr(data[:_PREVIEW_BYTES]) + "..."
