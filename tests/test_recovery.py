"""Tests for bounded recovery polling in netverify.recovery.

A fake clock makes every test deterministic: sleeping and running a check
advance fake time instead of real time. One test at the end uses the real
clock and real loopback sockets.
"""

import json
import math
import socket

import pytest

from netverify.recovery import RecoveryResult, wait_for_recovery
from netverify.results import Failure, FailureReason, Protocol, Target, VerificationResult
from netverify.tcp import verify_tcp_connection

TARGET = Target("192.0.2.10", 80)


def ok():
    return VerificationResult(Protocol.TCP, TARGET, 0.01)


def failed(reason=FailureReason.TIMEOUT):
    return VerificationResult(Protocol.TCP, TARGET, 0.01, failure=Failure(reason, str(reason)))


class FakeClock:
    """A monotonic clock that moves only when told to."""

    def __init__(self, start=1000.0):
        self.now = start
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class ScriptedCheck:
    """Returns scripted outcomes; each attempt takes `duration` fake seconds.

    An outcome may be a VerificationResult, an exception to raise, or
    "timeout": a failure that uses the whole timeout it was given.
    """

    def __init__(self, clock, outcomes, duration=0.1, repeat_last=False):
        self.clock = clock
        self.outcomes = list(outcomes)
        self.duration = duration
        self.repeat_last = repeat_last
        self.timeouts = []
        self.started_at = []

    def __call__(self, timeout):
        self.timeouts.append(timeout)
        self.started_at.append(self.clock.now)
        outcome = self.outcomes[0] if self.repeat_last and len(self.outcomes) == 1 \
            else self.outcomes.pop(0)
        if outcome == "timeout":
            self.clock.now += timeout
            return failed(FailureReason.TIMEOUT)
        self.clock.now += self.duration
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def poll(clock, check, **kwargs):
    kwargs = {"deadline": 5.0, "interval": 0.5, "attempt_timeout": 2.0, **kwargs}
    return wait_for_recovery(check, clock=clock, sleep=clock.sleep, **kwargs)


# Polling behaviour


def test_immediate_recovery_needs_one_attempt_and_no_sleep():
    clock = FakeClock()
    check = ScriptedCheck(clock, [ok()])

    result = poll(clock, check)

    assert result.recovered is True
    assert result.attempts == 1
    assert result.elapsed_seconds == pytest.approx(0.1)
    assert clock.sleeps == []
    assert check.timeouts == [2.0]


def test_recovery_after_several_failed_attempts():
    clock = FakeClock()
    unreachable = failed(FailureReason.NETWORK_UNREACHABLE)
    check = ScriptedCheck(clock, [unreachable, unreachable, failed(), ok()])

    result = poll(clock, check)

    assert result.recovered is True
    assert result.attempts == 4
    assert result.failure_reasons == (
        FailureReason.NETWORK_UNREACHABLE,
        FailureReason.NETWORK_UNREACHABLE,
        FailureReason.TIMEOUT,
    )
    assert result.last_result.success is True
    # One pause between consecutive attempts, never a busy loop.
    assert clock.sleeps == [0.5, 0.5, 0.5]
    assert result.elapsed_seconds == pytest.approx(4 * 0.1 + 3 * 0.5)


def test_deadline_exceeded_without_recovery():
    clock = FakeClock()
    check = ScriptedCheck(clock, [failed()], duration=0.1, repeat_last=True)

    result = poll(clock, check, deadline=2.0, interval=0.5)

    assert result.recovered is False
    assert result.last_result.success is False
    # Each attempt takes 0.1 s, then 0.5 s of sleep. Attempts start at 0.0,
    # 0.6, 1.2 and 1.8. After the fourth ends at 1.9, only 0.1 s remains,
    # which is not more than the interval, so polling stops.
    starts = [start - 1000.0 for start in check.started_at]
    assert starts == pytest.approx([0.0, 0.6, 1.2, 1.8])
    assert result.attempts == 4
    assert all(start < 2.0 for start in starts)  # No attempt starts after the deadline.
    assert result.elapsed_seconds == pytest.approx(1.9)


def test_attempt_count_matches_results_and_checks():
    clock = FakeClock()
    check = ScriptedCheck(clock, [failed()] * 6 + [ok()])

    result = poll(clock, check, deadline=60.0, interval=1.0)

    assert result.attempts == len(result.results) == len(check.timeouts) == 7


def test_each_attempt_gets_at_most_the_remaining_budget():
    clock = FakeClock()
    check = ScriptedCheck(clock, ["timeout"] * 10)

    result = poll(clock, check, deadline=5.0, interval=0.5, attempt_timeout=2.0)

    # 0.0-2.0, sleep, 2.5-4.5, sleep, then 0.5 left is not > interval: stop.
    assert check.timeouts == pytest.approx([2.0, 2.0])
    assert result.elapsed_seconds == pytest.approx(4.5)

    clock = FakeClock()
    check = ScriptedCheck(clock, ["timeout"] * 10)
    poll(clock, check, deadline=5.0, interval=0.2, attempt_timeout=2.0)

    # 0.0-2.0, 2.2-4.2, then 4.4 with 0.6 left: the last attempt gets only 0.6.
    assert check.timeouts == pytest.approx([2.0, 2.0, 0.6])


def test_overrunning_attempt_is_reported_truthfully():
    clock = FakeClock()
    # The check ignores its timeout and takes 7 seconds, past the deadline.
    check = ScriptedCheck(clock, [failed()], duration=7.0, repeat_last=True)

    result = poll(clock, check, deadline=5.0)

    assert result.attempts == 1
    assert result.recovered is False
    assert result.elapsed_seconds == pytest.approx(7.0)  # Not clipped to the deadline.


def test_sleep_that_overruns_the_deadline_starts_no_further_attempt():
    clock = FakeClock()
    check = ScriptedCheck(clock, [failed()], repeat_last=True)

    def oversleep(seconds):
        clock.now += 10.0

    result = wait_for_recovery(check, deadline=5.0, interval=0.5, clock=clock, sleep=oversleep)

    assert result.attempts == 1


def test_elapsed_time_is_never_negative():
    clock = FakeClock()
    instant = ScriptedCheck(clock, [ok()], duration=0.0)

    result = poll(clock, instant)

    assert result.elapsed_seconds == 0.0


# Recovery relative to the deadline


def test_success_within_the_deadline():
    clock = FakeClock()
    check = ScriptedCheck(clock, [failed(), ok()], duration=0.1)

    result = poll(clock, check, deadline=5.0)

    assert result.recovered is True
    assert result.recovered_within_deadline is True
    assert result.elapsed_seconds == pytest.approx(0.7)


def test_success_exactly_at_the_deadline_counts_as_within():
    clock = FakeClock()
    # Starts at 0.0 and is observed to succeed at exactly 5.0.
    check = ScriptedCheck(clock, [ok()], duration=5.0)

    result = poll(clock, check, deadline=5.0)

    assert result.elapsed_seconds == 5.0
    assert result.recovered is True
    assert result.recovered_within_deadline is True


def test_success_observed_after_the_deadline():
    clock = FakeClock()
    # Starts within the budget, but the check overruns and succeeds at 7.0.
    check = ScriptedCheck(clock, [ok()], duration=7.0)

    result = poll(clock, check, deadline=5.0)

    assert result.recovered is True                      # Success was observed...
    assert result.recovered_within_deadline is False     # ...but after the deadline.
    assert result.elapsed_seconds == pytest.approx(7.0)  # Not clipped.
    assert result.last_result.success is True            # Final result kept.
    data = result.to_dict()
    assert data["recovered"] is True
    assert data["recovered_within_deadline"] is False


def test_no_successful_observation():
    clock = FakeClock()
    check = ScriptedCheck(clock, [failed()], repeat_last=True)

    result = poll(clock, check, deadline=2.0)

    assert result.recovered is False
    assert result.recovered_within_deadline is False
    assert result.to_dict()["recovered_within_deadline"] is False


# Errors from the check


def test_exception_from_check_propagates_with_attempt_history():
    clock = FakeClock()
    error = RuntimeError("probe could not start")
    check = ScriptedCheck(clock, [failed(FailureReason.NETWORK_UNREACHABLE), error, ok()])

    with pytest.raises(RuntimeError, match="probe could not start") as raised:
        poll(clock, check)

    assert raised.value is error  # Not wrapped or replaced.
    note = raised.value.__notes__[-1]
    assert "attempt 2" in note
    assert "network_unreachable" in note
    assert len(check.timeouts) == 2  # Polling stopped; no third attempt.


def test_exception_in_first_attempt_notes_no_earlier_failures():
    clock = FakeClock()
    check = ScriptedCheck(clock, [OSError("boom")])

    with pytest.raises(OSError) as raised:
        poll(clock, check)

    assert "attempt 1" in raised.value.__notes__[-1]
    assert "none" in raised.value.__notes__[-1]


def test_keyboard_interrupt_is_not_suppressed():
    clock = FakeClock()
    check = ScriptedCheck(clock, [KeyboardInterrupt()])

    with pytest.raises(KeyboardInterrupt):
        poll(clock, check)


def test_check_must_return_a_verification_result():
    clock = FakeClock()
    check = ScriptedCheck(clock, [True])

    with pytest.raises(TypeError, match="VerificationResult"):
        poll(clock, check)


# Configuration


@pytest.mark.parametrize("name", ["deadline", "interval", "attempt_timeout"])
@pytest.mark.parametrize(
    ("value", "error"),
    [(0, ValueError), (-1.0, ValueError), (math.inf, ValueError), (math.nan, ValueError),
     (True, TypeError), ("1", TypeError), (None, TypeError)],
    ids=["zero", "negative", "inf", "nan", "bool", "str", "none"],
)
def test_invalid_configuration_is_rejected_before_any_attempt(name, value, error):
    clock = FakeClock()
    check = ScriptedCheck(clock, [ok()])

    with pytest.raises(error, match=name):
        poll(clock, check, **{name: value})

    assert check.timeouts == []


# RecoveryResult


def test_recovery_result_rejects_inconsistent_data():
    with pytest.raises(ValueError, match="non-empty"):
        RecoveryResult((), 1.0, 5.0, 0.5)
    with pytest.raises(ValueError, match="only the last"):
        RecoveryResult((ok(), failed()), 1.0, 5.0, 0.5)
    with pytest.raises(ValueError, match="elapsed_seconds"):
        RecoveryResult((ok(),), -0.1, 5.0, 0.5)
    with pytest.raises(TypeError):
        RecoveryResult(("ok",), 1.0, 5.0, 0.5)
    with pytest.raises(ValueError, match="non-empty"):
        RecoveryResult([ok()], 1.0, 5.0, 0.5)


def test_recovery_result_to_dict_is_json_serializable():
    result = RecoveryResult((failed(), ok()), 0.75, 5.0, 0.5)

    data = json.loads(json.dumps(result.to_dict()))

    assert data["recovered"] is True
    assert data["attempts"] == 2
    assert data["elapsed_seconds"] == 0.75
    assert [r["success"] for r in data["results"]] == [False, True]


# Real clock and sockets


def test_real_recovery_when_our_listener_is_enabled_after_a_failure():
    # The test owns the server socket and its port throughout. It is bound
    # but not listening at first, so the first real connection fails. How it
    # fails depends on the OS (refused on Linux, a timeout on some others),
    # so no particular reason is assumed.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        order = []

        def check(timeout):
            result = verify_tcp_connection("127.0.0.1", port, timeout=timeout)
            order.append("success" if result.success else "failure")
            if not result.success and "listen" not in order:
                # Enable the listener only after a failure has been observed.
                server.listen(8)
                order.append("listen")
            return result

        recovery = wait_for_recovery(check, deadline=10.0, interval=0.05, attempt_timeout=1.0)

        # The successful connection reached our own listener.
        server.settimeout(5.0)
        connection, (peer_host, _) = server.accept()
        connection.close()

    assert order == ["failure", "listen", "success"]
    assert recovery.recovered is True, recovery.to_dict()
    assert recovery.attempts == 2
    assert recovery.results[0].success is False
    assert peer_host == "127.0.0.1"
    assert recovery.elapsed_seconds >= 0.0
