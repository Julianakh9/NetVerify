"""Tests for the probe and connectivity helpers, without namespaces.

LocalTopology runs commands directly on this machine instead of inside a
namespace. Everything else is real: the probe runs as a subprocess, uses
real loopback sockets, and returns JSON. This covers the whole result
pipeline on any platform; test_netns_integration.py covers namespaces.
"""

import json
import socket
import subprocess
import sys
import time

import pytest

from netverify.linux import connectivity
from netverify.linux.commands import CommandError, run_command
from netverify.linux.connectivity import (
    PROBE,
    ProbeError,
    tcp_listener,
    verify_tcp_in_namespace,
)
from netverify.linux.probe import main as probe_main
from netverify.linux.topology import Endpoint
from netverify.results import FailureReason, Protocol, Target

LOCAL = Endpoint(namespace="(none)", interface="(none)", address="127.0.0.1", prefix_length=8)


class LocalTopology:
    """Runs commands on this machine, in place of a real namespace."""

    def run(self, endpoint, args, *, timeout):
        return run_command(args, timeout=timeout)

    def popen(self, endpoint, args):
        return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


class FixedOutputTopology(LocalTopology):
    """Pretends the probe printed the given output."""

    def __init__(self, stdout):
        self.stdout = stdout

    def run(self, endpoint, args, *, timeout):
        return subprocess.CompletedProcess(args, 0, self.stdout, "")


def released_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_listener_and_probe_report_successful_connection():
    topology = LocalTopology()

    with tcp_listener(topology, LOCAL, timeout=5.0) as port:
        result = verify_tcp_in_namespace(topology, LOCAL, "127.0.0.1", port, timeout=2.0)

    assert result.success is True
    assert result.protocol is Protocol.TCP
    assert result.target == Target("127.0.0.1", port)


def test_probe_reports_refused_connection_as_result_not_error():
    port = released_port()

    result = verify_tcp_in_namespace(LocalTopology(), LOCAL, "127.0.0.1", port, timeout=2.0)

    assert result.reason is FailureReason.CONNECTION_REFUSED
    assert result.failure.exception_type == "ConnectionRefusedError"


def test_invalid_probe_output_is_a_probe_error():
    with pytest.raises(ProbeError, match="invalid result"):
        verify_tcp_in_namespace(FixedOutputTopology("not json\n"), LOCAL, "127.0.0.1", 80)


def test_empty_probe_output_is_a_probe_error():
    with pytest.raises(ProbeError, match="no result"):
        verify_tcp_in_namespace(FixedOutputTopology(""), LOCAL, "127.0.0.1", 80)


def test_probe_process_failure_is_a_command_error():
    class FailingTopology(LocalTopology):
        def run(self, endpoint, args, *, timeout):
            raise CommandError(args, 1, "", "setpriv: not found", "failed with exit status 1")

    with pytest.raises(CommandError):
        verify_tcp_in_namespace(FailingTopology(), LOCAL, "127.0.0.1", 80)


def test_listener_that_exits_early_is_a_probe_error():
    class EarlyExitTopology(LocalTopology):
        def popen(self, endpoint, args):
            script = "import sys; sys.stderr.write('cannot bind'); sys.exit(2)"
            return super().popen(endpoint, [sys.executable, "-c", script])

    with pytest.raises(ProbeError, match="cannot bind"):
        with tcp_listener(EarlyExitTopology(), LOCAL, timeout=5.0):
            pass


class RecordingTopology(LocalTopology):
    """Keeps the processes it starts, so tests can check they were stopped."""

    def __init__(self, command=None):
        self.command = command
        self.processes = []

    def popen(self, endpoint, args):
        process = super().popen(endpoint, self.command or args)
        self.processes.append(process)
        return process


def test_listener_is_stopped_promptly_when_the_body_raises():
    topology = RecordingTopology()
    start = time.monotonic()

    with pytest.raises(ValueError):
        with tcp_listener(topology, LOCAL, timeout=30.0):
            raise ValueError("check failed before connecting")

    # Not kept waiting for the listener's own 30 second timeout.
    assert time.monotonic() - start < 10.0
    assert topology.processes[0].returncode is not None


def test_listener_that_never_reports_a_port_is_stopped(monkeypatch):
    monkeypatch.setattr(connectivity, "PROBE_OVERHEAD", 0.5)
    topology = RecordingTopology([sys.executable, "-c", "import time; time.sleep(60)"])

    with pytest.raises(ProbeError, match="did not report its port"):
        with tcp_listener(topology, LOCAL, timeout=0.1):
            pass

    assert topology.processes[0].returncode is not None


def test_probe_cli_prints_one_json_result(capsys):
    port = released_port()

    assert probe_main(["tcp-connect", "127.0.0.1", str(port), "--timeout", "1"]) == 0

    data = json.loads(capsys.readouterr().out)
    assert data["success"] is False
    assert data["failure"]["reason"] == "connection_refused"


def test_probe_listener_exits_with_error_when_nothing_connects():
    completed = subprocess.run(
        [*PROBE, "tcp-listen", "127.0.0.1", "--timeout", "0.2"],
        capture_output=True, text=True, timeout=30,
    )

    assert completed.returncode == 1
    assert "port" in json.loads(completed.stdout)
    assert "no connection" in completed.stderr
