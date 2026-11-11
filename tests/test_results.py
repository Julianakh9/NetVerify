"""Tests for the result model in netverify.results."""

import json
import math
from dataclasses import FrozenInstanceError

import pytest

from netverify.results import (
    Failure,
    FailureReason,
    Protocol,
    Target,
    VerificationResult,
)

TARGET = Target("192.0.2.10", 80)
REFUSED = Failure(
    reason=FailureReason.CONNECTION_REFUSED,
    message="[Errno 61] Connection refused",
    error_code=61,
    exception_type="ConnectionRefusedError",
)


def test_result_without_failure_is_successful():
    result = VerificationResult(Protocol.TCP, TARGET, 0.01)

    assert result.success is True
    assert result.failure is None
    assert result.reason is None


def test_result_with_failure_is_not_successful():
    result = VerificationResult(Protocol.TCP, TARGET, 0.01, failure=REFUSED)

    assert result.success is False
    assert result.reason is FailureReason.CONNECTION_REFUSED


def test_zero_duration_is_allowed():
    assert VerificationResult(Protocol.UDP, TARGET, 0).duration_seconds == 0


def test_results_are_immutable():
    result = VerificationResult(Protocol.TCP, TARGET, 0.01)

    # A successful result cannot later be given a failure.
    with pytest.raises(FrozenInstanceError):
        result.failure = REFUSED
    with pytest.raises(FrozenInstanceError):
        REFUSED.reason = FailureReason.TIMEOUT
    with pytest.raises(FrozenInstanceError):
        TARGET.port = 443


@pytest.mark.parametrize("duration", [-0.001, math.inf, math.nan], ids=["negative", "inf", "nan"])
def test_invalid_duration_is_rejected(duration):
    with pytest.raises(ValueError):
        VerificationResult(Protocol.TCP, TARGET, duration)


@pytest.mark.parametrize("duration", ["0.1", True, None], ids=["str", "bool", "none"])
def test_non_numeric_duration_is_rejected(duration):
    with pytest.raises(TypeError):
        VerificationResult(Protocol.TCP, TARGET, duration)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"protocol": "tcp"},
        {"target": ("192.0.2.10", 80)},
        {"failure": FailureReason.TIMEOUT},
        {"failure": False},
    ],
    ids=["protocol-string", "target-tuple", "failure-reason-only", "failure-false"],
)
def test_wrong_field_types_are_rejected(kwargs):
    fields = {"protocol": Protocol.TCP, "target": TARGET, "duration_seconds": 0.01}
    fields.update(kwargs)

    with pytest.raises(TypeError):
        VerificationResult(**fields)


def test_failure_reason_must_be_enum():
    with pytest.raises(TypeError):
        Failure(reason="timeout", message="timed out")


def test_failure_message_must_not_be_empty():
    with pytest.raises(ValueError):
        Failure(reason=FailureReason.TIMEOUT, message="")


def test_successful_result_to_dict():
    result = VerificationResult(Protocol.UDP, TARGET, 0.5)

    assert result.to_dict() == {
        "protocol": "udp",
        "target": {"host": "192.0.2.10", "port": 80},
        "success": True,
        "duration_seconds": 0.5,
        "failure": None,
    }


def test_failed_result_to_dict_is_json_serializable():
    result = VerificationResult(Protocol.TCP, TARGET, 0.5, failure=REFUSED)

    data = json.loads(json.dumps(result.to_dict()))

    assert data["success"] is False
    assert data["failure"] == {
        "reason": "connection_refused",
        "message": "[Errno 61] Connection refused",
        "error_code": 61,
        "exception_type": "ConnectionRefusedError",
    }
