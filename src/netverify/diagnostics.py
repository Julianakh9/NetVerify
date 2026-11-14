"""Classification of socket errors and ICMP errors into structured failures."""

import errno
import socket

from netverify.results import Failure, FailureReason

# ICMP (IPv4) error message types: they quote the datagram that caused them.
ICMP_DESTINATION_UNREACHABLE = 3
ICMP_SOURCE_QUENCH = 4
ICMP_TIME_EXCEEDED = 11
ICMP_PARAMETER_PROBLEM = 12
ICMP_ERROR_TYPES = frozenset(
    {ICMP_DESTINATION_UNREACHABLE, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED, ICMP_PARAMETER_PROBLEM}
)

_ICMP_TYPE_NAMES = {
    ICMP_DESTINATION_UNREACHABLE: "destination unreachable",
    ICMP_SOURCE_QUENCH: "source quench",
    ICMP_TIME_EXCEEDED: "time exceeded",
    ICMP_PARAMETER_PROBLEM: "parameter problem",
}

# Destination unreachable codes (RFC 792, RFC 1122) that mean the same as
# the socket-level NETWORK_UNREACHABLE and HOST_UNREACHABLE reasons.
_UNREACHABLE_REASONS: dict[int, tuple[FailureReason, str]] = {
    0: (FailureReason.NETWORK_UNREACHABLE, "network unreachable"),
    1: (FailureReason.HOST_UNREACHABLE, "host unreachable"),
    6: (FailureReason.NETWORK_UNREACHABLE, "destination network unknown"),
    7: (FailureReason.HOST_UNREACHABLE, "destination host unknown"),
    11: (FailureReason.NETWORK_UNREACHABLE, "network unreachable for type of service"),
    12: (FailureReason.HOST_UNREACHABLE, "host unreachable for type of service"),
}

# errno values with a more specific meaning than a generic socket error.
# Exception types are checked first; this table covers the rest.
_ERRNO_REASONS: dict[int, FailureReason] = {
    errno.ETIMEDOUT: FailureReason.TIMEOUT,
    errno.ECONNREFUSED: FailureReason.CONNECTION_REFUSED,
    errno.ENETUNREACH: FailureReason.NETWORK_UNREACHABLE,
    errno.ENETDOWN: FailureReason.NETWORK_UNREACHABLE,
    errno.EHOSTUNREACH: FailureReason.HOST_UNREACHABLE,
    errno.EHOSTDOWN: FailureReason.HOST_UNREACHABLE,
}


def classify_os_error(exc: OSError) -> Failure:
    """Turn an OSError raised by a socket operation into a Failure.

    Classification order:
        1. socket.gaierror / socket.herror -> DNS_RESOLUTION_FAILED.
           Checked first because their codes are EAI_* values, which can
           overlap numerically with unrelated errno values.
        2. TimeoutError -> TIMEOUT (socket timeouts and ETIMEDOUT).
        3. ConnectionRefusedError -> CONNECTION_REFUSED.
        4. Known errno values (see _ERRNO_REASONS).
        5. Anything else -> SOCKET_ERROR.

    The exception's message, code and class name are kept for debugging.
    """
    if isinstance(exc, (socket.gaierror, socket.herror)):
        reason = FailureReason.DNS_RESOLUTION_FAILED
    elif isinstance(exc, TimeoutError):
        reason = FailureReason.TIMEOUT
    elif isinstance(exc, ConnectionRefusedError):
        reason = FailureReason.CONNECTION_REFUSED
    else:
        reason = _ERRNO_REASONS.get(exc.errno, FailureReason.SOCKET_ERROR)

    exception_type = type(exc).__name__
    return Failure(
        reason=reason,
        message=str(exc) or exception_type,
        error_code=exc.errno,
        exception_type=exception_type,
    )


def classify_icmp_error(icmp_type: int, icmp_code: int, *, source: str | None = None) -> Failure:
    """Turn an ICMP error message received for a request into a Failure.

    Destination unreachable messages whose code means "network" or "host"
    unreachable map to NETWORK_UNREACHABLE or HOST_UNREACHABLE, the same
    reasons used for the equivalent socket errors. Every other ICMP error
    (other unreachable codes, time exceeded, parameter problem, source
    quench) is ICMP_ERROR. The message records the type, the code and the
    sender. error_code and exception_type are None: no OSError is involved,
    and error_code is reserved for OSError codes.

    Args:
        icmp_type: An ICMP error type (see ICMP_ERROR_TYPES).
        icmp_code: The message's code, 0-255.
        source: The address that sent the ICMP error, if known.

    Raises:
        TypeError: icmp_type or icmp_code is not an int.
        ValueError: icmp_code is out of range, or icmp_type is not an ICMP
            error type (for example an echo reply).
    """
    for name, value in (("icmp_type", icmp_type), ("icmp_code", icmp_code)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an int, got {value!r}")
    if not 0 <= icmp_code <= 255:
        raise ValueError(f"icmp_code must be 0-255, got {icmp_code}")
    if icmp_type not in ICMP_ERROR_TYPES:
        raise ValueError(f"ICMP type {icmp_type} is not an error message")

    reason, detail = FailureReason.ICMP_ERROR, None
    if icmp_type == ICMP_DESTINATION_UNREACHABLE and icmp_code in _UNREACHABLE_REASONS:
        reason, detail = _UNREACHABLE_REASONS[icmp_code]
    description = f"type {icmp_type}, code {icmp_code}" + (f": {detail}" if detail else "")
    sender = f" from {source}" if source else ""
    return Failure(
        reason=reason,
        message=f"ICMP {_ICMP_TYPE_NAMES[icmp_type]} ({description}){sender}",
    )
