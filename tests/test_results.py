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


@pytest.mark.parametrize("failure", [None, REFUSED], ids=["success", "failure"])
def test_from_dict_round_trips_through_json(failure):
    result = VerificationResult(Protocol.TCP, TARGET, 0.25, failure=failure)

    rebuilt = VerificationResult.from_dict(json.loads(json.dumps(result.to_dict())))

    assert rebuilt == result


def test_from_dict_rejects_contradictory_success_flag():
    data = VerificationResult(Protocol.TCP, TARGET, 0.25, failure=REFUSED).to_dict()
    data["success"] = True

    with pytest.raises(ValueError, match="contradicts"):
        VerificationResult.from_dict(data)


@pytest.mark.parametrize(
    ("change", "error"),
    [
        (lambda d: d.update(protocol="icmp"), ValueError),
        (lambda d: d["failure"].update(reason="exploded"), ValueError),
        (lambda d: d.update(duration_seconds=-1), ValueError),
        (lambda d: d.pop("target"), KeyError),
    ],
    ids=["unknown-protocol", "unknown-reason", "negative-duration", "missing-target"],
)
def test_from_dict_rejects_invalid_data(change, error):
    data = VerificationResult(Protocol.TCP, TARGET, 0.25, failure=REFUSED).to_dict()
    change(data)

    with pytest.raises(error):
        VerificationResult.from_dict(data)


# Portless protocols (ICMP, ARP) and protocol-specific port rules


def test_protocol_values_are_stable_strings():
    assert [p.value for p in Protocol] == ["tcp", "udp", "icmp", "arp"]
    assert [p for p in Protocol if p.uses_ports] == [Protocol.TCP, Protocol.UDP]


def test_new_failure_reasons_are_stable_strings():
    assert FailureReason.HARDWARE_ADDRESS_MISMATCH.value == "hardware_address_mismatch"
    assert FailureReason.ICMP_ERROR.value == "icmp_error"


def test_target_port_defaults_to_none_and_existing_targets_are_unchanged():
    assert Target("10.0.0.1").port is None
    assert Target("192.0.2.10", 80) == TARGET
    assert TARGET.port == 80


@pytest.mark.parametrize("protocol", [Protocol.ICMP, Protocol.ARP])
def test_portless_protocols_accept_a_target_without_port(protocol):
    result = VerificationResult(protocol, Target("10.231.0.2"), 0.001)

    assert result.success
    assert result.target.port is None


@pytest.mark.parametrize("protocol", [Protocol.ICMP, Protocol.ARP])
@pytest.mark.parametrize("port", [0, 80, "80"])
def test_portless_protocols_reject_a_port(protocol, port):
    with pytest.raises(ValueError, match="have no port"):
        VerificationResult(protocol, Target("10.231.0.2", port), 0.001)


@pytest.mark.parametrize("protocol", [Protocol.TCP, Protocol.UDP])
def test_port_protocols_require_a_port(protocol):
    with pytest.raises(ValueError, match="need a port"):
        VerificationResult(protocol, Target("192.0.2.10"), 0.001)


@pytest.mark.parametrize("protocol", [Protocol.TCP, Protocol.UDP])
@pytest.mark.parametrize("port", [0, 1, 65535, "8080"])
def test_port_protocols_keep_accepting_ports_as_given(protocol, port):
    # Unchanged behavior: the checks pass the caller's port through, and
    # results record it exactly as given.
    assert VerificationResult(protocol, Target("h", port), 0.0).target.port == port


@pytest.mark.parametrize("protocol", [Protocol.ICMP, Protocol.ARP])
@pytest.mark.parametrize(
    "failure",
    [None,
     Failure(FailureReason.TIMEOUT, "no reply within 2.0 seconds"),
     Failure(FailureReason.HARDWARE_ADDRESS_MISMATCH, "is at 02:00:00:00:00:01"),
     Failure(FailureReason.ICMP_ERROR, "ICMP time exceeded (type 11, code 0)")],
    ids=["success", "timeout", "mac-mismatch", "icmp-error"],
)
def test_portless_results_round_trip_through_json(protocol, failure):
    result = VerificationResult(protocol, Target("10.231.0.2"), 0.0005, failure=failure)

    data = json.loads(json.dumps(result.to_dict()))

    assert data["protocol"] == protocol.value
    assert data["target"] == {"host": "10.231.0.2", "port": None}
    assert VerificationResult.from_dict(data) == result


def test_tcp_serialization_is_unchanged():
    data = VerificationResult(Protocol.TCP, TARGET, 0.25, failure=REFUSED).to_dict()

    assert data == {
        "protocol": "tcp",
        "target": {"host": "192.0.2.10", "port": 80},
        "success": False,
        "duration_seconds": 0.25,
        "failure": {
            "reason": "connection_refused",
            "message": "[Errno 61] Connection refused",
            "error_code": 61,
            "exception_type": "ConnectionRefusedError",
        },
    }


@pytest.mark.parametrize(
    ("protocol", "port", "error"),
    [("tcp", None, ValueError),   # TCP data with a null port
     ("udp", None, ValueError),
     ("icmp", 80, ValueError),    # ICMP data with a port
     ("arp", 0, ValueError),
     ("sctp", 80, ValueError)],   # unknown protocol
)
def test_from_dict_enforces_port_rules(protocol, port, error):
    data = {"protocol": protocol, "target": {"host": "h", "port": port},
            "duration_seconds": 0.0, "failure": None}

    with pytest.raises(error):
        VerificationResult.from_dict(data)


def test_from_dict_still_requires_the_port_key_for_portless_protocols():
    data = {"protocol": "icmp", "target": {"host": "10.231.0.2"},
            "duration_seconds": 0.0, "failure": None}

    with pytest.raises(KeyError):
        VerificationResult.from_dict(data)
