"""Tests for netverify.linux.commands.run_command, using real subprocesses.

Commands are small Python programs, so these tests run on any platform.
"""

import sys

import pytest

from netverify.linux.commands import CommandError, run_command


def test_successful_command_returns_output():
    completed = run_command([sys.executable, "-c", "print('hello')"])

    assert completed.stdout == "hello\n"


def test_failing_command_reports_status_and_stderr():
    script = "import sys; sys.stderr.write('something broke'); sys.exit(3)"

    with pytest.raises(CommandError) as error:
        run_command([sys.executable, "-c", script])

    assert error.value.returncode == 3
    assert error.value.stderr == "something broke"
    assert "exit status 3" in str(error.value)
    assert "something broke" in str(error.value)


def test_missing_command_is_reported():
    with pytest.raises(CommandError, match="not found") as error:
        run_command(["netverify-command-that-does-not-exist"])

    assert error.value.returncode is None


def test_slow_command_times_out():
    # The child sleeps; the timeout is what is being tested.
    with pytest.raises(CommandError, match="timed out") as error:
        run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)

    assert error.value.returncode is None


def test_arguments_are_not_interpreted_by_a_shell():
    # With a shell, ";" would start a second command.
    completed = run_command([sys.executable, "-c", "import sys; print(sys.argv[1])", "a; echo b"])

    assert completed.stdout == "a; echo b\n"
