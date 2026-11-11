"""Lifecycle tests for VethTopology, using a fake command runner.

No real commands run, so these tests work on any platform without
privileges. They check the exact commands, cleanup after partial setup
failures, and error reporting. Real namespaces are tested in
test_netns_integration.py.
"""

import subprocess
import sys
from unittest.mock import patch

import pytest

from netverify.linux.commands import DEFAULT_TIMEOUT, CommandError
from netverify.linux.topology import (
    TopologyCleanupError,
    TopologySetupError,
    VethTopology,
    missing_prerequisites,
)

SUDO = ["sudo", "-n"]
DROP = ["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--"]


class FakeRunner:
    """Records commands; fails the ones matching fail_when."""

    def __init__(self, fail_when=lambda args: False, pids=""):
        self.calls = []
        self.timeouts = []
        self.fail_when = fail_when
        self.pids = pids

    def __call__(self, args, *, timeout=DEFAULT_TIMEOUT):
        args = list(args)
        self.calls.append(args)
        self.timeouts.append(timeout)
        if self.fail_when(args):
            raise CommandError(args, 2, "", "RTNETLINK answers: Operation not permitted",
                               "failed with exit status 2")
        stdout = self.pids if "pids" in args else ""
        return subprocess.CompletedProcess(args, 0, stdout, "")

    def deleted_namespaces(self):
        return [args[-1] for args in self.calls if args[-3:-1] == ["netns", "delete"]]


def make_topology(runner, **kwargs):
    return VethTopology(runner=runner, privilege=SUDO, drop_privileges=DROP, **kwargs)


def has_sequence(args, *sequence):
    n = len(sequence)
    return any(tuple(args[i:i + n]) == sequence for i in range(len(args) - n + 1))


def test_setup_runs_expected_commands_in_order():
    runner = FakeRunner()
    topology = make_topology(runner)
    left, right = topology.left, topology.right

    topology.setup()

    assert runner.calls == [
        SUDO + ["ip", "netns", "add", left.namespace],
        SUDO + ["ip", "netns", "add", right.namespace],
        SUDO + ["ip", "link", "add", left.interface, "netns", left.namespace, "type", "veth",
                "peer", "name", right.interface, "netns", right.namespace],
        SUDO + ["ip", "-n", left.namespace, "address", "add", "10.231.0.1/30", "dev", left.interface],
        SUDO + ["ip", "-n", left.namespace, "link", "set", "dev", left.interface, "up"],
        SUDO + ["ip", "-n", left.namespace, "link", "set", "dev", "lo", "up"],
        SUDO + ["ip", "-n", right.namespace, "address", "add", "10.231.0.2/30", "dev", right.interface],
        SUDO + ["ip", "-n", right.namespace, "link", "set", "dev", right.interface, "up"],
        SUDO + ["ip", "-n", right.namespace, "link", "set", "dev", "lo", "up"],
    ]


def test_close_stops_processes_then_deletes_namespaces_in_reverse_order():
    runner = FakeRunner(pids="123 456")
    topology = make_topology(runner)
    topology.setup()
    runner.calls.clear()

    topology.close()

    left, right = topology.left.namespace, topology.right.namespace
    assert runner.calls == [
        SUDO + ["ip", "netns", "pids", right],
        SUDO + ["kill", "-KILL", "123", "456"],
        SUDO + ["ip", "netns", "delete", right],
        SUDO + ["ip", "netns", "pids", left],
        SUDO + ["kill", "-KILL", "123", "456"],
        SUDO + ["ip", "netns", "delete", left],
    ]


def test_close_is_idempotent():
    runner = FakeRunner()
    topology = make_topology(runner)
    topology.setup()
    topology.close()
    calls_after_first_close = len(runner.calls)

    topology.close()

    assert len(runner.calls) == calls_after_first_close


def test_context_manager_cleans_up_when_body_raises():
    runner = FakeRunner()

    with pytest.raises(ValueError):
        with make_topology(runner) as topology:
            raise ValueError("test body failed")

    assert runner.deleted_namespaces() == [topology.right.namespace, topology.left.namespace]


@pytest.mark.parametrize(
    ("failing_step", "expected_message", "deleted"),
    [
        (lambda a, t: has_sequence(a, "netns", "add", t.left.namespace),
         "could not create namespace", []),
        (lambda a, t: has_sequence(a, "netns", "add", t.right.namespace),
         "could not create namespace", ["left"]),
        (lambda a, t: has_sequence(a, "link", "add"),
         "could not create the veth pair", ["right", "left"]),
        (lambda a, t: "address" in a and t.right.namespace in a,
         "could not assign 10.231.0.2/30", ["right", "left"]),
    ],
    ids=["first-namespace", "second-namespace", "veth-pair", "address"],
)
def test_partial_setup_failure_removes_only_created_namespaces(
    failing_step, expected_message, deleted
):
    holder = {}
    runner = FakeRunner(fail_when=lambda args: failing_step(args, holder["topology"]))
    topology = holder["topology"] = make_topology(runner)

    with pytest.raises(TopologySetupError) as error:
        topology.setup()

    # The error names the failed step and includes the command's stderr.
    assert expected_message in str(error.value)
    assert "Operation not permitted" in str(error.value)
    assert isinstance(error.value.__cause__, CommandError)

    names = {"left": topology.left.namespace, "right": topology.right.namespace}
    assert runner.deleted_namespaces() == [names[side] for side in deleted]


def test_cleanup_failure_during_failed_setup_is_attached_as_note():
    runner = FakeRunner(fail_when=lambda args: has_sequence(args, "link", "add")
                        or has_sequence(args, "netns", "delete"))
    topology = make_topology(runner)

    with pytest.raises(TopologySetupError) as error:
        topology.setup()

    notes = getattr(error.value, "__notes__", [])
    assert any("Cleanup after the failed setup also failed" in note for note in notes)
    # Both deletions were still attempted.
    assert len(runner.deleted_namespaces()) == 2


def test_close_attempts_every_namespace_before_reporting_failure():
    holder = {}
    runner = FakeRunner(fail_when=lambda args: has_sequence(
        args, "netns", "delete", holder["topology"].right.namespace))
    topology = holder["topology"] = make_topology(runner)
    topology.setup()

    with pytest.raises(TopologyCleanupError, match="could not delete namespace"):
        topology.close()

    assert runner.deleted_namespaces() == [topology.right.namespace, topology.left.namespace]


def test_body_error_is_kept_when_cleanup_also_fails():
    runner = FakeRunner(fail_when=lambda args: has_sequence(args, "netns", "delete"))

    with pytest.raises(ValueError) as error:
        with make_topology(runner):
            raise ValueError("test body failed")

    assert any("Topology cleanup also failed" in note for note in error.value.__notes__)


def fail_first(predicate):
    """A fail_when that fails only the first command matching predicate."""
    failed = []

    def fail_when(args):
        if not failed and predicate(args):
            failed.append(args)
            return True
        return False

    return fail_when


def test_failed_close_can_be_retried():
    holder = {}
    runner = FakeRunner(fail_when=fail_first(lambda args: has_sequence(
        args, "netns", "delete", holder["topology"].right.namespace)))
    topology = holder["topology"] = make_topology(runner)
    topology.setup()
    left, right = topology.left.namespace, topology.right.namespace

    with pytest.raises(TopologyCleanupError, match=right):
        topology.close()

    # Not usable while cleanup is pending.
    with pytest.raises(RuntimeError, match="not active"):
        topology.run(topology.left, ["true"])

    topology.close()  # The retry succeeds.

    # The left namespace was deleted once; the retry only retried the right one.
    assert runner.deleted_namespaces() == [right, left, right]

    calls = len(runner.calls)
    topology.close()  # Now closed: nothing more to do.
    assert len(runner.calls) == calls


def test_failed_cleanup_after_failed_setup_can_be_retried():
    runner = FakeRunner(fail_when=lambda args: has_sequence(args, "link", "add"))
    deletions = fail_first(lambda args: has_sequence(args, "netns", "delete"))
    runner.fail_when = lambda args: has_sequence(args, "link", "add") or deletions(args)
    topology = make_topology(runner)
    left, right = topology.left.namespace, topology.right.namespace

    with pytest.raises(TopologySetupError, match="veth pair") as error:
        topology.setup()

    # The original setup error is kept; the cleanup failure is a note.
    assert any("Cleanup after the failed setup also failed" in note
               for note in error.value.__notes__)
    assert runner.deleted_namespaces() == [right, left]  # right failed, left succeeded

    topology.close()

    assert runner.deleted_namespaces() == [right, left, right]
    with pytest.raises(RuntimeError, match="only be called once"):
        topology.setup()


def test_cleanup_failure_after_body_error_can_be_retried():
    runner = FakeRunner(fail_when=fail_first(lambda args: has_sequence(args, "netns", "delete")))

    with pytest.raises(ValueError):
        with make_topology(runner) as topology:
            raise ValueError("test body failed")

    topology.close()

    right, left = topology.right.namespace, topology.left.namespace
    assert runner.deleted_namespaces() == [right, left, right]


def test_names_are_unique_and_fit_the_interface_name_limit():
    first, second = make_topology(FakeRunner()), make_topology(FakeRunner())

    assert first.left.namespace != second.left.namespace
    assert first.left.namespace.startswith("netverify-")
    for endpoint in (first.left, first.right):
        assert len(endpoint.interface) <= 15


def test_endpoints_use_the_first_two_host_addresses():
    topology = make_topology(FakeRunner(), network="192.168.77.0/29")

    assert topology.left.cidr == "192.168.77.1/29"
    assert topology.right.cidr == "192.168.77.2/29"


@pytest.mark.parametrize(
    "network",
    ["2001:db8::/64", "10.0.0.0/32", "10.0.0.1/30", "not-a-network"],
    ids=["ipv6", "single-address", "host-bits-set", "garbage"],
)
def test_invalid_networks_are_rejected(network):
    with pytest.raises(ValueError):
        make_topology(FakeRunner(), network=network)


def test_exec_command_drops_privileges_after_entering_the_namespace():
    topology = make_topology(FakeRunner())
    topology.setup()

    command = topology.exec_command(topology.left, ["python", "-V"])

    assert command == SUDO + ["ip", "netns", "exec", topology.left.namespace] + DROP + ["python", "-V"]


def test_exec_command_as_root_uses_no_prefixes():
    topology = VethTopology(runner=FakeRunner(), privilege=[])
    topology.setup()

    command = topology.exec_command(topology.right, ["true"])

    assert command == ["ip", "netns", "exec", topology.right.namespace, "true"]


def test_run_passes_command_and_timeout_to_runner():
    runner = FakeRunner()
    topology = make_topology(runner)
    topology.setup()

    topology.run(topology.left, ["true"], timeout=5.0)

    assert runner.calls[-1] == topology.exec_command(topology.left, ["true"])
    assert runner.timeouts[-1] == 5.0


def test_commands_require_an_active_topology():
    topology = make_topology(FakeRunner())

    with pytest.raises(RuntimeError, match="not active"):
        topology.run(topology.left, ["true"])

    topology.setup()
    with pytest.raises(RuntimeError, match="only be called once"):
        topology.setup()

    topology.close()
    with pytest.raises(RuntimeError, match="not active"):
        topology.run(topology.left, ["true"])


def test_endpoint_from_another_topology_is_rejected():
    topology, other = make_topology(FakeRunner()), make_topology(FakeRunner())
    topology.setup()

    with pytest.raises(ValueError, match="does not belong"):
        topology.exec_command(other.left, ["true"])


def test_prerequisites_report_non_linux_platform():
    with patch.object(sys, "platform", "darwin"):
        assert missing_prerequisites(FakeRunner()) == ["Linux (this platform is darwin)"]


def test_prerequisites_report_missing_passwordless_sudo():
    runner = FakeRunner(fail_when=lambda args: args[:2] == ["sudo", "-n"])
    with patch.object(sys, "platform", "linux"), \
         patch("netverify.linux.topology.shutil.which", return_value="/usr/bin/tool"), \
         patch("netverify.linux.topology.os.geteuid", return_value=1000):
        missing = missing_prerequisites(runner)

    assert missing == ["root privileges or passwordless sudo ('sudo -n true' failed)"]


def test_prerequisites_as_root_need_only_ip():
    with patch.object(sys, "platform", "linux"), \
         patch("netverify.linux.topology.shutil.which", return_value="/usr/sbin/ip"), \
         patch("netverify.linux.topology.os.geteuid", return_value=0):
        assert missing_prerequisites(FakeRunner()) == []
