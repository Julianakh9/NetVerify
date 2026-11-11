"""Bounded polling for network recovery.

wait_for_recovery() runs a check repeatedly until it succeeds or a deadline
passes, and returns a RecoveryResult describing every attempt. It does no
networking itself and does not depend on any platform: the check is a
callback, such as a TCP check on this machine or inside a Linux namespace.

Two kinds of outcome are kept apart:
    - A failed VerificationResult means "not recovered yet": polling goes on.
    - An exception from the check means the check itself could not run (a
      probe or infrastructure problem). It is never suppressed: polling stops
      and the exception propagates, with the attempts so far attached as a note.

Deadline semantics:
    - The deadline governs when attempts start. Each attempt is given at
      most the time remaining as its timeout, but polling cannot forcibly
      interrupt a synchronous check that is already running. A check that
      overruns its timeout (for example, because of slow subprocess startup
      or name resolution) can end after the deadline, unless the check
      bounds those operations itself.
    - elapsed_seconds always reports the true measured time, even when it
      exceeds the deadline. It is never clipped.
    - Polling stops early when the next scheduled attempt would start at or
      after the deadline. An unrecovered result therefore means no attempt
      that ran observed success. It does not prove the network was
      unavailable for the entire deadline.
    - Times are measured when attempts complete in this process. They are
      observation times, not the exact moment the network recovered.
"""

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from netverify.results import FailureReason, VerificationResult

# A check takes the timeout for one attempt, in seconds, and returns its result.
Check = Callable[[float], VerificationResult]


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    """The outcome of polling a check until it succeeded or a deadline passed.

    Attributes:
        results: Every attempt's result, in order, including the final one.
            Polling stops at the first success, so only the last result can
            be successful.
        elapsed_seconds: Measured time from the start of the first attempt
            until polling returned, using a monotonic clock. Never clipped:
            it exceeds deadline_seconds if an attempt overran.
        deadline_seconds: The recovery deadline that was used.
        interval_seconds: The pause between attempts that was used.
    """

    results: tuple[VerificationResult, ...]
    elapsed_seconds: float
    deadline_seconds: float
    interval_seconds: float

    def __post_init__(self) -> None:
        if not isinstance(self.results, tuple) or not self.results:
            raise ValueError("results must be a non-empty tuple")
        for result in self.results:
            if not isinstance(result, VerificationResult):
                raise TypeError(f"results must contain VerificationResult, got {result!r}")
        if any(result.success for result in self.results[:-1]):
            raise ValueError("only the last attempt can be successful")
        _check_seconds("elapsed_seconds", self.elapsed_seconds, allow_zero=True)
        _check_seconds("deadline_seconds", self.deadline_seconds)
        _check_seconds("interval_seconds", self.interval_seconds)

    @property
    def recovered(self) -> bool:
        """True if a successful result was observed.

        The successful attempt may have ended after the deadline, if it
        started within the deadline but overran; see recovered_within_deadline.
        """
        return self.results[-1].success

    @property
    def recovered_within_deadline(self) -> bool:
        """True if success was observed no later than the deadline.

        Defined as `recovered and elapsed_seconds <= deadline_seconds`.
        elapsed_seconds is when the successful attempt was observed to
        complete, not the exact moment the network recovered.
        """
        return self.recovered and self.elapsed_seconds <= self.deadline_seconds

    @property
    def attempts(self) -> int:
        """The number of checks that ran."""
        return len(self.results)

    @property
    def last_result(self) -> VerificationResult:
        """The final attempt's result: the success, or the last failure."""
        return self.results[-1]

    @property
    def failure_reasons(self) -> tuple[FailureReason, ...]:
        """The reason of each failed attempt, in order."""
        return tuple(r.reason for r in self.results if r.reason is not None)

    def to_dict(self) -> dict[str, Any]:
        """Return plain data suitable for json.dumps()."""
        return {
            "recovered": self.recovered,
            "recovered_within_deadline": self.recovered_within_deadline,
            "attempts": self.attempts,
            "elapsed_seconds": self.elapsed_seconds,
            "deadline_seconds": self.deadline_seconds,
            "interval_seconds": self.interval_seconds,
            "results": [result.to_dict() for result in self.results],
        }


def wait_for_recovery(
    check: Check,
    *,
    deadline: float,
    interval: float = 0.5,
    attempt_timeout: float = 2.0,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> RecoveryResult:
    """Run check until it succeeds or the deadline passes.

    The first attempt starts immediately. After each failed attempt, polling
    sleeps for interval seconds and tries again, but only if the next attempt
    would start before the deadline; otherwise it stops, possibly before the
    deadline has passed. Each attempt receives min(attempt_timeout, time
    remaining) as its timeout. See the module docstring for what the
    deadline does and does not guarantee.

    Args:
        check: Called with the timeout for one attempt; returns a
            VerificationResult. A failed result means "not recovered yet".
        deadline: Seconds from the start within which an attempt may start.
        interval: Seconds to wait between attempts. Must be positive, so a
            check that fails instantly cannot cause busy-waiting.
        attempt_timeout: Maximum timeout passed to each attempt.
        clock: Monotonic clock in seconds. Injectable for tests.
        sleep: Sleep function. Injectable for tests.

    Returns:
        A RecoveryResult with every attempt's result.

    Raises:
        TypeError: An argument has the wrong type, or check returned
            something other than a VerificationResult.
        ValueError: deadline, interval or attempt_timeout is not a positive
            finite number.
        Exception: Anything the check raises propagates unchanged, with a
            note describing the attempts made so far.
    """
    _check_seconds("deadline", deadline)
    _check_seconds("interval", interval)
    _check_seconds("attempt_timeout", attempt_timeout)

    results: list[VerificationResult] = []
    start = clock()
    remaining = deadline
    while True:
        result = _attempt(check, min(attempt_timeout, remaining), results, start, clock)
        results.append(result)
        if result.success:
            break
        remaining = deadline - (clock() - start)
        if remaining <= interval:
            break  # The next attempt would start at or after the deadline.
        sleep(interval)
        remaining = deadline - (clock() - start)
        if remaining <= 0:
            break  # The sleep overran the deadline.

    return RecoveryResult(
        results=tuple(results),
        elapsed_seconds=clock() - start,
        deadline_seconds=deadline,
        interval_seconds=interval,
    )


def _attempt(
    check: Check,
    timeout: float,
    earlier: list[VerificationResult],
    start: float,
    clock: Callable[[], float],
) -> VerificationResult:
    try:
        result = check(timeout)
    except Exception as exc:
        reasons = ", ".join(str(r.reason) for r in earlier) or "none"
        exc.add_note(
            f"Recovery polling stopped: attempt {len(earlier) + 1} raised after "
            f"{clock() - start:.3f} seconds. Earlier attempts failed with: {reasons}."
        )
        raise
    if not isinstance(result, VerificationResult):
        raise TypeError(f"check must return a VerificationResult, got {result!r}")
    return result


def _check_seconds(name: str, value: object, *, allow_zero: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number of seconds, got {value!r}")
    if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
        bound = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{name} must be a {bound} finite number, got {value!r}")
