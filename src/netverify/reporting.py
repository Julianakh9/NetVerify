"""Reports for verification and recovery results: JSON data and text lines.

Everything here is pure: functions take results and return data or strings.
They do no networking and no I/O, so the CLI and other tools can share them.

JSON reports share one envelope, versioned by SCHEMA_VERSION:

    {
      "schema_version": 1,
      "command": "tcp" | "udp" | "recover",
      "status": "passed" | "failed" | "error",
      "exit_code": 0 | 1 | 3 | 130,
      "result": {...}   # VerificationResult or RecoveryResult data; absent on error
      "error": {...}    # {"type": ..., "message": ...}; only on error
    }
"""

from dataclasses import replace
from enum import IntEnum
from typing import Any

from netverify.recovery import RecoveryResult
from netverify.results import FailureReason, VerificationResult

SCHEMA_VERSION = 1

PAYLOAD_HIDDEN = (
    "Reply payload does not match the payload sent "
    "(contents hidden; use --show-payload to include them)"
)


class ExitCode(IntEnum):
    """Process exit codes of the netverify command."""

    SUCCESS = 0              # The verification passed.
    VERIFICATION_FAILED = 1  # The check ran, and the target failed it.
    INVALID_INPUT = 2        # Bad command-line usage (argparse's own code).
    INFRASTRUCTURE_ERROR = 3  # The check could not run normally.
    INTERRUPTED = 130        # Stopped with Ctrl-C (128 + SIGINT).


Outcome = VerificationResult | RecoveryResult


def passed(outcome: Outcome) -> bool:
    """Whether an outcome counts as a pass.

    A recovery passes only if success was observed within the deadline.
    """
    if isinstance(outcome, RecoveryResult):
        return outcome.recovered_within_deadline
    return outcome.success


def exit_code_for(outcome: Outcome) -> ExitCode:
    return ExitCode.SUCCESS if passed(outcome) else ExitCode.VERIFICATION_FAILED


def redact_payload(result: VerificationResult) -> VerificationResult:
    """Hide payload contents from a PAYLOAD_MISMATCH failure message.

    The reason, error code and exception type are kept. Other results are
    returned unchanged.
    """
    if result.reason is not FailureReason.PAYLOAD_MISMATCH:
        return result
    assert result.failure is not None
    return replace(result, failure=replace(result.failure, message=PAYLOAD_HIDDEN))


def report(command: str, outcome: Outcome) -> dict[str, Any]:
    """Return the JSON report for a completed check."""
    code = exit_code_for(outcome)
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "status": "passed" if code is ExitCode.SUCCESS else "failed",
        "exit_code": int(code),
        "result": outcome.to_dict(),
    }


def error_report(command: str | None, error: BaseException, code: ExitCode) -> dict[str, Any]:
    """Return the JSON report for a check that could not run normally."""
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "status": "error",
        "exit_code": int(code),
        "error": {"type": type(error).__name__, "message": str(error) or type(error).__name__},
    }


def format_text(command: str, outcome: Outcome) -> str:
    """Return a short human-readable report."""
    if isinstance(outcome, RecoveryResult):
        return _format_recovery(outcome)
    return _format_verification(command, outcome)


def _format_verification(command: str, result: VerificationResult) -> str:
    target = f"{command} {result.target.host}:{result.target.port}"
    duration = _seconds(result.duration_seconds)
    if result.success:
        verb = "connected" if command == "tcp" else "echo matched"
        return f"PASS  {target}  {verb} in {duration}"
    assert result.failure is not None
    return f"FAIL  {target}  {result.failure.reason}: {result.failure.message} ({duration})"


def _format_recovery(recovery: RecoveryResult) -> str:
    last = recovery.last_result
    target = f"recover tcp {last.target.host}:{last.target.port}"
    attempts = f"{recovery.attempts} attempt{'s' if recovery.attempts != 1 else ''}"
    timing = f"{_seconds(recovery.elapsed_seconds)} (deadline {_seconds(recovery.deadline_seconds)})"
    lines = []
    if recovery.recovered_within_deadline:
        lines.append(f"PASS  {target}  recovered after {attempts} in {timing}")
    elif recovery.recovered:
        lines.append(f"FAIL  {target}  recovered only after the deadline: {attempts} in {timing}")
    else:
        assert last.failure is not None
        lines.append(
            f"FAIL  {target}  not recovered: {attempts} in {timing}; "
            f"last failure {last.failure.reason}: {last.failure.message}"
        )
    if recovery.failure_reasons:
        counts: dict[str, int] = {}
        for reason in recovery.failure_reasons:
            counts[str(reason)] = counts.get(str(reason), 0) + 1
        summary = ", ".join(f"{reason} x{count}" for reason, count in counts.items())
        lines.append(f"      failed attempts: {summary}")
    return "\n".join(lines)


def _seconds(value: float) -> str:
    return f"{value * 1000:.1f} ms" if value < 1 else f"{value:.2f} s"
