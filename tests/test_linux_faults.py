"""Lifecycle tests for LinkDown, using a fake command runner.

The fake runner keeps track of each interface's up/down state, so these
tests check real state changes without running any command. They work on
any platform without privileges. Real namespaces are tested in
test_netns_integration.py.
"""

import subprocess

import pytest

from netverify.linux.commands import DEFAULT_TIMEOUT, CommandError
from netverify.linux.connectivity import ProbeError
from netverify.linux.faults import (
    FaultError,
    FaultInjectionError,
    FaultRestoreError,
    LinkDown,
    link_is_up,
)
from netverify.linux.topology import TopologyError, VethTopology

SUDO = ["sudo", "-n"]
DROP = ["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--"]
STDERR = "RTNETLINK answers: Operation not permitted"


def has_sequence(args, *sequence):
    n = len(sequence)
    return any(tuple(args[i:i + n]) == sequence for i in range(len(args) - n + 1))


def is_link_set(args, state=None):
    if not has_sequence(args, "link", "set", "dev") or "lo" in args:
        return False
    return state is None or args[-1] == state


def is_link_show(args):
    return has_sequence(args, "link", "show", "dev")


class LinkRunner:
    """Fake runner that keeps track of each veth interface's admin state."""

    def __init__(self, fail_when=lambda args: False, ignore_up=False, show_output=None):
        self.calls = []
        self.up = {}
        self.fail_when = fail_when
        self.ignore_up = ignore_up      # `link set up` succeeds but has no effect
        self.show_output = show_output  # replaces the `link show` output

    def __call__(self, args, *, timeout=DEFAULT_TIMEOUT):
        args = list(args)
        self.calls.append(args)
        if self.fail_when(args):
            raise CommandError(args, 2, "", STDERR, "failed with exit status 2")
        stdout = ""
        if is_link_set(args):
            interface, state = args[args.index("dev") + 1], args[-1]
            if not (self.ignore_up and state == "up"):
                self.up[interface] = state == "up"
        elif is_link_show(args):
            interface = args[args.index("dev") + 1]
            flags = "BROADCAST,MULTICAST" + (",UP,LOWER_UP" if self.up.get(interface) else "")
            stdout = self.show_output if self.show_output is not None else (
                f"5: {interface}@if4: <{flags}> mtu 1500 qdisc noqueue state UP\n"
            )
        return subprocess.CompletedProcess(args, 0, stdout, "")

    def link_changes(self):
        """The `up`/`down` link commands issued after setup, in order."""
        return [args[-1] for args in self.calls[self.setup_calls:] if is_link_set(args)]


@pytest.fixture
def runner():
    return LinkRunner()


@pytest.fixture
def topology(runner):
    topology = VethTopology(runner=runner, privilege=SUDO, drop_privileges=DROP)
    topology.setup()
    runner.setup_calls = len(runner.calls)
    return topology


def test_link_is_down_inside_the_block_and_up_afterwards(runner, topology):
    left = topology.left

    with LinkDown(topology, left):
        assert runner.up[left.interface] is False
        assert runner.up[topology.right.interface] is True  # Only the chosen side.

    assert runner.up[left.interface] is True
    assert runner.link_changes() == ["down", "up"]


def test_exact_commands_privileged_only_to_change_state(runner, topology):
    left = topology.left

    with LinkDown(topology, left):
        pass

    show = SUDO + ["ip", "netns", "exec", left.namespace] + DROP + [
        "ip", "-o", "link", "show", "dev", left.interface]
    change = SUDO + ["ip", "-n", left.namespace, "link", "set", "dev", left.interface]
    assert runner.calls[runner.setup_calls:] == [
        show,              # Read the original state as the calling user.
        change + ["down"],
        change + ["up"],
        show,              # Confirm the restore.
    ]


def test_link_is_restored_when_the_block_raises(runner, topology):
    with pytest.raises(ValueError, match="check failed"):
        with LinkDown(topology, topology.left):
            raise ValueError("check failed")

    assert runner.up[topology.left.interface] is True


def test_link_that_was_already_down_is_left_down(runner, topology):
    topology.set_link_state(topology.left, up=False)

    with LinkDown(topology, topology.left):
        pass

    assert runner.up[topology.left.interface] is False
    assert "up" not in runner.link_changes()


def test_failure_to_bring_link_down_is_an_injection_error_and_restores(runner, topology):
    runner.fail_when = lambda args: is_link_set(args, "down")

    with pytest.raises(FaultInjectionError, match="could not bring") as error:
        with LinkDown(topology, topology.left):
            pytest.fail("the block must not run when injection fails")

    assert STDERR in str(error.value)
    assert isinstance(error.value.__cause__, CommandError)
    # The state was uncertain, so a restore was attempted before reporting.
    assert runner.link_changes() == ["down", "up"]


def test_restore_failure_after_failed_injection_is_attached_as_note(runner, topology):
    runner.fail_when = lambda args: is_link_set(args)

    with pytest.raises(FaultInjectionError) as error:
        with LinkDown(topology, topology.left):
            pass

    assert any("Restoring the link also failed" in note for note in error.value.__notes__)


def test_failure_to_read_state_changes_nothing(runner, topology):
    runner.fail_when = is_link_show

    with pytest.raises(FaultInjectionError, match="could not read the state"):
        with LinkDown(topology, topology.left):
            pass

    assert runner.link_changes() == []


def test_unparseable_state_is_an_injection_error(runner, topology):
    runner.show_output = "unexpected output\n"

    with pytest.raises(FaultInjectionError, match="no link flags"):
        with LinkDown(topology, topology.left):
            pass

    assert runner.link_changes() == []


def test_restore_failure_is_raised_when_the_block_succeeded(runner, topology):
    runner.fail_when = lambda args: is_link_set(args, "up")

    with pytest.raises(FaultRestoreError, match="could not bring") as error:
        with LinkDown(topology, topology.left):
            pass

    assert STDERR in str(error.value)
    assert isinstance(error.value.__cause__, CommandError)


def test_restore_failure_keeps_the_block_error(runner, topology):
    runner.fail_when = lambda args: is_link_set(args, "up")

    with pytest.raises(ValueError, match="check failed") as error:
        with LinkDown(topology, topology.left):
            raise ValueError("check failed")

    assert any("Restoring the link also failed" in note for note in error.value.__notes__)


def test_restore_is_verified(runner, topology):
    runner.ignore_up = True  # `ip link set up` "succeeds" without effect.

    with pytest.raises(FaultRestoreError, match="still down"):
        with LinkDown(topology, topology.left):
            pass


def test_topology_close_still_removes_namespaces_after_failed_restore(runner, topology):
    runner.fail_when = lambda args: is_link_set(args, "up")
    with pytest.raises(FaultRestoreError):
        with LinkDown(topology, topology.left):
            pass

    runner.fail_when = lambda args: False
    topology.close()

    deleted = [args[-1] for args in runner.calls if has_sequence(args, "netns", "delete")]
    assert deleted == [topology.right.namespace, topology.left.namespace]


def test_faults_only_apply_to_the_topologys_own_endpoints(runner, topology):
    other = VethTopology(runner=LinkRunner(), privilege=SUDO, drop_privileges=DROP)

    with pytest.raises(ValueError, match="does not belong"):
        with LinkDown(topology, other.left):
            pass
    with pytest.raises(ValueError, match="does not belong"):
        topology.set_link_state(other.left, up=False)

    assert runner.calls[runner.setup_calls:] == []


def test_faults_need_an_active_topology(runner, topology):
    topology.close()

    with pytest.raises(RuntimeError, match="not active"):
        topology.set_link_state(topology.left, up=False)


def test_set_link_state_passes_the_timeout():
    seen = {}

    def runner(args, *, timeout=DEFAULT_TIMEOUT):
        seen[tuple(args)] = timeout
        return subprocess.CompletedProcess(args, 0, "", "")

    topology = VethTopology(runner=runner, privilege=SUDO, drop_privileges=DROP)
    topology.setup()
    topology.set_link_state(topology.right, up=False, timeout=3.0)

    expected = SUDO + ["ip", "-n", topology.right.namespace, "link", "set", "dev",
                       topology.right.interface, "down"]
    assert seen[tuple(expected)] == 3.0


@pytest.mark.parametrize(
    ("flags", "expected"),
    [("BROADCAST,MULTICAST,UP,LOWER_UP", True),
     ("NO-CARRIER,BROADCAST,MULTICAST,UP", True),   # Up, but the peer is down.
     ("BROADCAST,MULTICAST", False),
     ("BROADCAST,MULTICAST,LOWER_UP", False)],      # "LOWER_UP" is not "UP".
    ids=["up", "up-no-carrier", "down", "lower-up-only"],
)
def test_link_is_up_reads_the_administrative_flag(runner, topology, flags, expected):
    runner.show_output = f"5: nv@if4: <{flags}> mtu 1500 state DOWN\n"

    assert link_is_up(topology, topology.left) is expected


def test_fault_errors_are_distinct_from_other_failures():
    for error in (FaultInjectionError, FaultRestoreError):
        assert issubclass(error, FaultError)
        assert not issubclass(error, (TopologyError, ProbeError, CommandError))
