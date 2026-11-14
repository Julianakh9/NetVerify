"""Tests for netverify.diagnostics: classify_os_error and classify_icmp_error."""

import errno
import socket

import pytest

from netverify.diagnostics import classify_icmp_error, classify_os_error
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


# classify_icmp_error


@pytest.mark.parametrize(
    ("icmp_type", "code", "reason", "detail"),
    [
        (3, 0, FailureReason.NETWORK_UNREACHABLE, "network unreachable"),
        (3, 1, FailureReason.HOST_UNREACHABLE, "host unreachable"),
        (3, 6, FailureReason.NETWORK_UNREACHABLE, "destination network unknown"),
        (3, 7, FailureReason.HOST_UNREACHABLE, "destination host unknown"),
        (3, 11, FailureReason.NETWORK_UNREACHABLE, "network unreachable for type of service"),
        (3, 12, FailureReason.HOST_UNREACHABLE, "host unreachable for type of service"),
        (3, 2, FailureReason.ICMP_ERROR, None),    # protocol unreachable
        (3, 3, FailureReason.ICMP_ERROR, None),    # port unreachable
        (3, 4, FailureReason.ICMP_ERROR, None),    # fragmentation needed
        (3, 13, FailureReason.ICMP_ERROR, None),   # administratively prohibited
        (3, 255, FailureReason.ICMP_ERROR, None),  # unassigned code
        (4, 0, FailureReason.ICMP_ERROR, None),    # source quench
        (11, 0, FailureReason.ICMP_ERROR, None),   # time exceeded in transit
        (11, 1, FailureReason.ICMP_ERROR, None),   # fragment reassembly time exceeded
        (12, 0, FailureReason.ICMP_ERROR, None),   # parameter problem
    ],
)
def test_icmp_errors_are_classified(icmp_type, code, reason, detail):
    failure = classify_icmp_error(icmp_type, code, source="10.231.0.2")

    assert failure.reason is reason
    assert f"type {icmp_type}, code {code}" in failure.message
    assert failure.message.endswith(" from 10.231.0.2")
    if detail:
        assert detail in failure.message
    # Not an OSError: error_code stays reserved for OSError codes.
    assert failure.error_code is None
    assert failure.exception_type is None


def test_icmp_error_message_names_the_type_and_omits_unknown_sender():
    failure = classify_icmp_error(11, 0)

    assert failure.message == "ICMP time exceeded (type 11, code 0)"


@pytest.mark.parametrize("icmp_type", [0, 5, 8, 13, 255])
def test_non_error_icmp_types_are_rejected(icmp_type):
    with pytest.raises(ValueError, match="not an error message"):
        classify_icmp_error(icmp_type, 0)


@pytest.mark.parametrize(("icmp_type", "code", "error"), [
    (3, -1, ValueError), (3, 256, ValueError),
    (3, True, TypeError), (True, 0, TypeError), ("3", 0, TypeError), (3, 1.0, TypeError),
])
def test_invalid_icmp_type_or_code(icmp_type, code, error):
    with pytest.raises(error):
        classify_icmp_error(icmp_type, code)
