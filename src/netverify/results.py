"""Structured results for NetVerify checks.

This module holds only data. It does no networking and does not decide how
errors are classified; see netverify.diagnostics for that.
"""

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Protocol(StrEnum):
    """Network protocol used by a check."""

    TCP = "tcp"
    UDP = "udp"


class FailureReason(StrEnum):
    """Why a check failed. Values are stable strings for reports."""

    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    NETWORK_UNREACHABLE = "network_unreachable"
    HOST_UNREACHABLE = "host_unreachable"
    PAYLOAD_MISMATCH = "payload_mismatch"
    UNEXPECTED_SENDER = "unexpected_sender"
    SOCKET_ERROR = "socket_error"


@dataclass(frozen=True, slots=True)
class Target:
    """The host and port a check was run against, exactly as given."""

    host: str
    port: int


@dataclass(frozen=True, slots=True)
class Failure:
    """Details of a failed check.

    Attributes:
        reason: Classification of the failure.
        message: Human-readable description. Never empty.
        error_code: Code from the underlying OSError, if any. For DNS
            failures this is a getaddrinfo EAI_* code, not an errno value.
        exception_type: Name of the exception class that caused the
            failure, or None if no exception was involved.
    """

    reason: FailureReason
    message: str
    error_code: int | None = None
    exception_type: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, FailureReason):
            raise TypeError(f"reason must be a FailureReason, got {self.reason!r}")
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("message must be a non-empty string")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """The outcome of one check.

    A result is successful exactly when it has no failure. Success is
    derived rather than stored, so a result can never claim both success
    and a failure.

    Invariants (checked on creation):
        - protocol is a Protocol and target is a Target.
        - duration_seconds is a finite, non-negative number.
        - failure is a Failure or None.
    """

    protocol: Protocol
    target: Target
    duration_seconds: float
    failure: Failure | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.protocol, Protocol):
            raise TypeError(f"protocol must be a Protocol, got {self.protocol!r}")
        if not isinstance(self.target, Target):
            raise TypeError(f"target must be a Target, got {self.target!r}")
        duration = self.duration_seconds
        if isinstance(duration, bool) or not isinstance(duration, (int, float)):
            raise TypeError(f"duration_seconds must be a number, got {duration!r}")
        if not math.isfinite(duration) or duration < 0:
            raise ValueError(
                f"duration_seconds must be finite and non-negative, got {duration!r}"
            )
        if self.failure is not None and not isinstance(self.failure, Failure):
            raise TypeError(f"failure must be a Failure or None, got {self.failure!r}")

    @property
    def success(self) -> bool:
        """True if the check passed."""
        return self.failure is None

    @property
    def reason(self) -> FailureReason | None:
        """The failure reason, or None if the check passed."""
        return None if self.failure is None else self.failure.reason

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of this result."""
        failure = None
        if self.failure is not None:
            failure = {
                "reason": self.failure.reason.value,
                "message": self.failure.message,
                "error_code": self.failure.error_code,
                "exception_type": self.failure.exception_type,
            }
        return {
            "protocol": self.protocol.value,
            "target": {"host": self.target.host, "port": self.target.port},
            "success": self.success,
            "duration_seconds": self.duration_seconds,
            "failure": failure,
        }
