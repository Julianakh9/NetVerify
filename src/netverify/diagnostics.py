"""Classification of socket errors into structured failures."""

import errno
import socket

from netverify.results import Failure, FailureReason

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
