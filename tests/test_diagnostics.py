"""Tests for netverify.diagnostics.classify_os_error."""

import errno
import socket

import pytest

from netverify.diagnostics import classify_os_error
from netverify.results import FailureReason


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
         FailureReason.DNS_RESOLUTION_FAILED),
        (socket.herror(1, "Unknown host"), FailureReason.DNS_RESOLUTION_FAILED),
        (TimeoutError("timed out"), FailureReason.TIMEOUT),
        # OSError(ETIMEDOUT, ...) is automatically created as a TimeoutError.
        (OSError(errno.ETIMEDOUT, "Operation timed out"), FailureReason.TIMEOUT),
        (ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
         FailureReason.CONNECTION_REFUSED),
        (OSError(errno.ENETUNREACH, "Network is unreachable"),
         FailureReason.NETWORK_UNREACHABLE),
        (OSError(errno.ENETDOWN, "Network is down"), FailureReason.NETWORK_UNREACHABLE),
        (OSError(errno.EHOSTUNREACH, "No route to host"), FailureReason.HOST_UNREACHABLE),
        (OSError(errno.EHOSTDOWN, "Host is down"), FailureReason.HOST_UNREACHABLE),
        # Other errors must not be guessed as unreachable or refused.
        (OSError(errno.EADDRNOTAVAIL, "Can't assign requested address"),
         FailureReason.SOCKET_ERROR),
        (ConnectionResetError(errno.ECONNRESET, "Connection reset by peer"),
         FailureReason.SOCKET_ERROR),
        (OSError("no errno at all"), FailureReason.SOCKET_ERROR),
    ],
    ids=[
        "gaierror", "herror", "timeout-error", "etimedout", "refused",
        "enetunreach", "enetdown", "ehostunreach", "ehostdown",
        "eaddrnotavail", "connection-reset", "no-errno",
    ],
)
def test_os_errors_are_classified(error, reason):
    assert classify_os_error(error).reason is reason


def test_dns_error_is_classified_by_type_not_by_code():
    # EAI_* codes can collide with errno values; the type must win.
    error = socket.gaierror(errno.ENETUNREACH, "lookup failed")

    assert classify_os_error(error).reason is FailureReason.DNS_RESOLUTION_FAILED


def test_debugging_details_are_kept():
    error = ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

    failure = classify_os_error(error)

    assert failure.message == str(error)
    assert failure.error_code == errno.ECONNREFUSED
    assert failure.exception_type == "ConnectionRefusedError"


def test_error_without_message_uses_exception_name():
    failure = classify_os_error(TimeoutError())

    assert failure.message == "TimeoutError"
    assert failure.error_code is None
