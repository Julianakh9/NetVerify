"""Unit tests for the netverify CLI: arguments, output formats, exit codes.

The verification functions are replaced by fakes here, so no networking
happens. Real loopback runs are in test_cli_integration.py.
"""

import json
from unittest.mock import patch

import pytest

from netverify import cli
from netverify.recovery import RecoveryResult
from netverify.reporting import PAYLOAD_HIDDEN, SCHEMA_VERSION, ExitCode, redact_payload
from netverify.results import Failure, FailureReason, Protocol, Target, VerificationResult

TARGET = Target("192.0.2.10", 80)
OK = VerificationResult(Protocol.TCP, TARGET, 0.002)
REFUSED = VerificationResult(
    Protocol.TCP, TARGET, 0.001,
    failure=Failure(FailureReason.CONNECTION_REFUSED, "[Errno 111] Connection refused",
                    111, "ConnectionRefusedError"),
)
MISMATCH = VerificationResult(
    Protocol.UDP, TARGET, 0.003,
    failure=Failure(FailureReason.PAYLOAD_MISMATCH,
                    "Reply b'secret-reply' (12 bytes) does not match sent payload "
                    "b'secret-token' (12 bytes)"),
)


def run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def run_json(argv, capsys):
    code, out, err = run([*argv, "--format", "json"], capsys)
    return code, json.loads(out), err


# Exit codes and output for each command


def test_tcp_success_text(capsys):
    with patch.object(cli, "verify_tcp_connection", return_value=OK) as verify:
        code, out, err = run(["tcp", "192.0.2.10", "80", "--timeout", "1.5"], capsys)

    verify.assert_called_once_with("192.0.2.10", 80, timeout=1.5)
    assert code == ExitCode.SUCCESS == 0
    assert out.startswith("PASS  tcp 192.0.2.10:80  connected in")
    assert err == ""


def test_tcp_failure_text(capsys):
    with patch.object(cli, "verify_tcp_connection", return_value=REFUSED):
        code, out, _ = run(["tcp", "192.0.2.10", "80"], capsys)

    assert code == ExitCode.VERIFICATION_FAILED == 1
    assert "FAIL" in out and "connection_refused" in out


@pytest.mark.parametrize(("result", "code", "status"),
                         [(OK, 0, "passed"), (REFUSED, 1, "failed")], ids=["pass", "fail"])
def test_tcp_json_report(capsys, result, code, status):
    with patch.object(cli, "verify_tcp_connection", return_value=result):
        exit_code, report, err = run_json(["tcp", "192.0.2.10", "80"], capsys)

    assert exit_code == code
    assert report == {
        "schema_version": SCHEMA_VERSION,
        "command": "tcp",
        "status": status,
        "exit_code": code,
        "result": result.to_dict(),
    }
    assert err == ""


def test_udp_passes_payload_and_timeout(capsys):
    ok = VerificationResult(Protocol.UDP, TARGET, 0.001)
    with patch.object(cli, "verify_udp_echo", return_value=ok) as verify:
        code, out, _ = run(["udp", "192.0.2.10", "7", "--payload", "héllo", "--timeout", "3"],
                           capsys)

    verify.assert_called_once_with("192.0.2.10", 7, payload="héllo".encode(), timeout=3.0)
    assert code == 0
    assert "echo matched" in out


def test_udp_hides_payload_by_default(capsys):
    with patch.object(cli, "verify_udp_echo", return_value=MISMATCH):
        code, report, _ = run_json(["udp", "192.0.2.10", "7"], capsys)
    with patch.object(cli, "verify_udp_echo", return_value=MISMATCH):
        _, text, _ = run(["udp", "192.0.2.10", "7"], capsys)

    assert code == 1
    assert report["result"]["failure"]["reason"] == "payload_mismatch"
    assert report["result"]["failure"]["message"] == PAYLOAD_HIDDEN
    for output in (json.dumps(report), text):
        assert "secret" not in output


def test_udp_shows_payload_when_asked(capsys):
    with patch.object(cli, "verify_udp_echo", return_value=MISMATCH):
        _, report, _ = run_json(["udp", "192.0.2.10", "7", "--show-payload"], capsys)

    assert "secret-token" in report["result"]["failure"]["message"]


def test_redaction_keeps_everything_but_the_message():
    redacted = redact_payload(MISMATCH)

    assert redacted.reason is FailureReason.PAYLOAD_MISMATCH
    assert redacted.target == MISMATCH.target
    assert redacted.duration_seconds == MISMATCH.duration_seconds
    assert redact_payload(REFUSED) is REFUSED  # Other failures are unchanged.


def recovery(results, elapsed, deadline=5.0):
    return RecoveryResult(tuple(results), elapsed, deadline, 0.5)


@pytest.mark.parametrize(
    ("outcome", "code", "text"),
    [
        (recovery([REFUSED, OK], 1.0), 0, "PASS  recover tcp 192.0.2.10:80  recovered after 2 attempts"),
        (recovery([OK], 7.0), 1, "recovered only after the deadline"),
        (recovery([REFUSED, REFUSED], 4.6), 1, "not recovered: 2 attempts"),
    ],
    ids=["within-deadline", "after-deadline", "not-recovered"],
)
def test_recover_exit_codes_follow_the_deadline(capsys, outcome, code, text):
    with patch.object(cli, "wait_for_recovery", return_value=outcome):
        exit_code, out, _ = run(["recover", "192.0.2.10", "80", "--deadline", "5"], capsys)
    with patch.object(cli, "wait_for_recovery", return_value=outcome):
        _, report, _ = run_json(["recover", "192.0.2.10", "80", "--deadline", "5"], capsys)

    assert exit_code == code
    assert text in out
    assert report["exit_code"] == code
    assert report["result"] == outcome.to_dict()


def test_recover_passes_settings_and_uses_the_tcp_check(capsys):
    with patch.object(cli, "wait_for_recovery", return_value=recovery([OK], 0.1)) as wait, \
         patch.object(cli, "verify_tcp_connection", return_value=OK) as verify:
        run(["recover", "192.0.2.10", "80", "--deadline", "9", "--interval", "0.25",
             "--timeout", "1"], capsys)
        # The check handed to the poller runs the existing TCP check.
        check = wait.call_args.args[0]
        assert check(0.7) is OK

    assert wait.call_args.kwargs == {"deadline": 9.0, "interval": 0.25, "attempt_timeout": 1.0}
    verify.assert_called_once_with("192.0.2.10", 80, timeout=0.7)


def test_recover_text_summarises_failed_attempts(capsys):
    timeout = VerificationResult(Protocol.TCP, TARGET, 1.0,
                                 failure=Failure(FailureReason.TIMEOUT, "timed out"))
    with patch.object(cli, "wait_for_recovery",
                      return_value=recovery([REFUSED, REFUSED, timeout, OK], 2.0)):
        _, out, _ = run(["recover", "192.0.2.10", "80", "--deadline", "5"], capsys)

    assert "failed attempts: connection_refused x2, timeout x1" in out


# Invalid input: exit code 2, a message on stderr, no traceback


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ([], "required"),
        (["ping", "h", "1"], "invalid choice"),
        (["tcp"], "required"),
        (["tcp", "h", "0"], "must be 1-65535"),
        (["tcp", "h", "65536"], "must be 1-65535"),
        (["tcp", "h", "http"], "not a number"),
        (["tcp", "", "80"], "invalid host"),
        (["tcp", " h", "80"], "invalid host"),
        (["tcp", "a" * 64 + ".example", "80"], "invalid host name"),
        (["tcp", "h", "80", "--timeout", "0"], "must be positive"),
        (["tcp", "h", "80", "--timeout", "-1"], "must be positive"),
        (["tcp", "h", "80", "--timeout", "nan"], "must be positive"),
        (["tcp", "h", "80", "--timeout", "inf"], "must be positive"),
        (["tcp", "h", "80", "--timeout", "soon"], "invalid number of seconds"),
        (["tcp", "h", "80", "--format", "xml"], "invalid choice"),
        (["udp", "h", "7", "--payload", ""], "payload must be"),
        (["udp", "h", "7", "--payload", "x" * 65508], "payload must be"),
        (["recover", "h", "80"], "--deadline"),
        (["recover", "h", "80", "--deadline", "5", "--interval", "0"], "must be positive"),
    ],
    ids=lambda value: None if isinstance(value, list) else value,
)
def test_invalid_input_exits_2_without_traceback(capsys, argv, message):
    with patch.object(cli, "verify_tcp_connection") as tcp, \
         patch.object(cli, "verify_udp_echo") as udp, \
         patch.object(cli, "wait_for_recovery") as wait:
        code, out, err = run(argv, capsys)

    assert code == ExitCode.INVALID_INPUT == 2
    assert message in err
    assert "Traceback" not in err
    assert out == ""
    assert not (tcp.called or udp.called or wait.called)  # Nothing ran.


@pytest.mark.parametrize("argv", [["--help"], ["tcp", "--help"], ["--version"]])
def test_help_and_version_exit_0(capsys, argv):
    code, out, _ = run(argv, capsys)

    assert code == 0
    assert out


def test_help_documents_exit_codes(capsys):
    _, out, _ = run(["--help"], capsys)

    for line in ("0    verification passed", "1    verification failed", "2    invalid input",
                 "3    the check could not run normally", "130  interrupted"):
        assert line in out


# Unexpected errors: exit code 3, distinct from a failed verification


def test_unexpected_error_exits_3_with_message_not_traceback(capsys):
    with patch.object(cli, "verify_tcp_connection", side_effect=RuntimeError("resolver broke")):
        code, out, err = run(["tcp", "192.0.2.10", "80"], capsys)

    assert code == ExitCode.INFRASTRUCTURE_ERROR == 3
    assert "netverify: error: RuntimeError: resolver broke" in err
    assert "--debug" in err
    assert "Traceback" not in err
    assert out == ""  # No PASS/FAIL line: this is not a verification result.


def test_unexpected_error_in_json_mode_is_an_error_report(capsys):
    with patch.object(cli, "wait_for_recovery", side_effect=RuntimeError("probe broke")):
        code, report, err = run_json(["recover", "192.0.2.10", "80", "--deadline", "1"], capsys)

    assert code == 3
    assert report == {
        "schema_version": SCHEMA_VERSION,
        "command": "recover",
        "status": "error",
        "exit_code": 3,
        "error": {"type": "RuntimeError", "message": "probe broke"},
    }
    assert "result" not in report
    assert "probe broke" in err


def test_debug_shows_the_original_exception(capsys):
    with patch.object(cli, "verify_tcp_connection", side_effect=RuntimeError("resolver broke")):
        with pytest.raises(RuntimeError, match="resolver broke"):
            cli.main(["tcp", "192.0.2.10", "80", "--debug"])


def test_interrupt_exits_130(capsys):
    with patch.object(cli, "wait_for_recovery", side_effect=KeyboardInterrupt):
        code, report, err = run_json(["recover", "192.0.2.10", "80", "--deadline", "5"], capsys)

    assert code == ExitCode.INTERRUPTED == 130
    assert report["status"] == "error" and report["exit_code"] == 130
    assert "interrupted" in err


def test_json_output_is_a_single_line(capsys):
    with patch.object(cli, "verify_tcp_connection", return_value=REFUSED):
        _, out, _ = run(["tcp", "192.0.2.10", "80", "--format", "json"], capsys)

    assert out.count("\n") == 1  # One JSON document per line, for log tools.
