"""Privilege boundary and public API of the packet checks, with a fake runner.

No commands run, so these tests work on any platform without privileges.
They check the exact command that receives CAP_NET_RAW, everything it must
refuse, and how results come back. Real packets are tested in namespaces.
"""

import json
import math
import subprocess
import sys
from unittest.mock import patch

import pytest

from netverify.linux import packet
from netverify.linux.commands import DEFAULT_TIMEOUT, CommandError
from netverify.linux.connectivity import PROBE_OVERHEAD, ProbeError, verify_tcp_in_namespace
from netverify.linux.packet import (
    link_address,
    missing_packet_prerequisites,
    verify_arp_in_namespace,
    verify_icmp_echo_in_namespace,
)
from netverify.linux.topology import PACKET_PROBE_CAPABILITIES, VethTopology
from netverify.recovery import wait_for_recovery
from netverify.results import Failure, FailureReason, Protocol, Target, VerificationResult

SUDO = ["sudo", "-n"]
DROP = ["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--"]
HARDENED = ["--inh-caps=-all,+net_raw", "--ambient-caps=-all,+net_raw",
            "--bounding-set=-all,+net_raw", "--no-new-privs"]
PROBE = [sys.executable, "-I", "-m", "netverify.linux.packet_probe"]
PEER_MAC = "02:00:00:00:00:02"


class FakeRunner:
    """Records commands. Packet probe commands print probe_output(args)."""

    def __init__(self, probe_output=None, link_output="", fail_probe=None):
        self.calls, self.timeouts = [], []
        self.probe_output = probe_output
        self.link_output = link_output
        self.fail_probe = fail_probe

    def __call__(self, args, *, timeout=DEFAULT_TIMEOUT):
        args = list(args)
        self.calls.append(args)
        self.timeouts.append(timeout)
        stdout = ""
        if "netverify.linux.packet_probe" in args:
            if self.fail_probe:
                raise self.fail_probe
            stdout = self.probe_output(args) if self.probe_output else ""
        elif "link" in args and "show" in args:
            stdout = self.link_output
        return subprocess.CompletedProcess(args, 0, stdout, "")

    def clear(self):
        self.calls.clear()
        self.timeouts.clear()

    def probe_calls(self):
        return [call for call in self.calls if "netverify.linux.packet_probe" in call]


def result_json(protocol, host, failure=None):
    return json.dumps(VerificationResult(protocol, Target(host), 0.0004, failure).to_dict())


def option(args, name):
    return args[args.index(name) + 1]


@pytest.fixture
def ids():
    with patch("netverify.linux.topology.os.getuid", return_value=1000), \
         patch("netverify.linux.topology.os.getgid", return_value=1000):
        yield


@pytest.fixture
def runner():
    def output(args):
        check = args[args.index("netverify.linux.packet_probe") + 1]
        protocol = Protocol.ICMP if check == "icmp-echo" else Protocol.ARP
        return result_json(protocol, option(args, "--destination"))

    return FakeRunner(output)


@pytest.fixture
def topology(runner, ids):
    topo = VethTopology(runner=runner, privilege=SUDO, drop_privileges=DROP)
    topo.setup()
    runner.clear()
    yield topo
    topo.close()


def probe_args(topology, *, destination=None, check="icmp-echo", **overrides):
    endpoint = topology.left
    args = [check, "--interface", endpoint.interface, "--source", endpoint.address,
            "--destination", destination or topology.right.address, "--timeout", "2"]
    for name, value in overrides.items():
        args[args.index(f"--{name}") + 1] = value
    return args


# The privileged command


def test_packet_probe_command_is_exact(topology, runner):
    topology.run_packet_probe(topology.left, probe_args(topology), timeout=17.0)

    assert runner.calls == [[
        *SUDO, "ip", "netns", "exec", topology.left.namespace,
        "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", *HARDENED, "--",
        *PROBE, "icmp-echo", "--interface", topology.left.interface,
        "--source", "10.231.0.1", "--destination", "10.231.0.2", "--timeout", "2.0",
    ]]
    assert runner.timeouts == [17.0]
    assert list(PACKET_PROBE_CAPABILITIES) == HARDENED


def test_only_the_canonical_arguments_reach_the_privileged_process(topology, runner):
    args = ["arp", "--timeout", "1e0", "--expected-mac", "02-00-00-00-00-0A",
            "--destination", "10.231.0.2", "--source", "10.231.0.1",
            "--interface", topology.left.interface]

    topology.run_packet_probe(topology.left, args, timeout=5)

    command = runner.calls[0]
    assert command[command.index("netverify.linux.packet_probe") + 1:] == [
        "arp", "--interface", topology.left.interface, "--source", "10.231.0.1",
        "--destination", "10.231.0.2", "--timeout", "1.0",
        "--expected-mac", "02:00:00:00:00:0a"]


def test_ordinary_commands_never_receive_capabilities(topology, runner):
    topology.run(topology.left, ["ip", "address", "show"])
    topology.exec_command(topology.right, ["true"])
    runner.probe_output = lambda args: result_json(Protocol.TCP, "10.231.0.2")
    with patch("netverify.linux.connectivity._parse_result",
               return_value=VerificationResult(Protocol.TCP, Target("10.231.0.2", 80), 0.1)):
        verify_tcp_in_namespace(topology, topology.left, "10.231.0.2", 80)

    for command in runner.calls + [topology.exec_command(topology.right, ["true"])]:
        assert not any("net_raw" in part or "caps" in part for part in command)
        assert command[command.index("setpriv"):command.index("setpriv") + 5] == DROP


@pytest.mark.parametrize(
    ("arguments", "error", "message"),
    [
        (["/bin/sh", "-c", "id"], ValueError, "unknown packet check"),
        (["icmp-echo"], ValueError, "missing option"),
        ("icmp-echo --interface x", TypeError, "sequence of strings"),
    ],
)
def test_arbitrary_commands_are_refused(topology, runner, arguments, error, message):
    with pytest.raises(error, match=message):
        topology.run_packet_probe(topology.left, arguments, timeout=5)

    assert runner.calls == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"interface": "eth0"}, "is not 'nv"),
        ({"source": "10.231.0.2", "destination": "10.231.0.1"}, "source 10.231.0.2 is not"),
        ({"destination": "10.231.0.5"}, "not a host address in the topology network"),
        ({"destination": "8.8.8.8"}, "not a host address in the topology network"),
        ({"destination": "10.231.0.0"}, "not a host address"),   # network address
        ({"destination": "10.231.0.3"}, "not a host address"),   # broadcast address
        ({"destination": "10.231.0.1"}, "is the source address"),
    ],
)
def test_interfaces_and_destinations_outside_the_topology_are_refused(
        topology, runner, overrides, message):
    with pytest.raises(ValueError, match=message):
        topology.run_packet_probe(topology.left, probe_args(topology, **overrides), timeout=5)

    assert runner.calls == []


def test_other_hosts_on_a_larger_topology_network_are_allowed(runner, ids):
    with VethTopology("10.231.8.0/29", runner=runner, privilege=SUDO,
                      drop_privileges=DROP) as topology:
        runner.clear()
        topology.run_packet_probe(topology.left, probe_args(topology, destination="10.231.8.6"),
                                  timeout=5)
        with pytest.raises(ValueError, match="not a host address"):
            topology.run_packet_probe(topology.left,
                                      probe_args(topology, destination="10.231.8.7"), timeout=5)

    assert len(runner.probe_calls()) == 1


def test_endpoints_of_another_topology_are_refused(topology, runner, ids):
    other = VethTopology(runner=runner, privilege=SUDO, drop_privileges=DROP)
    other.setup()
    runner.clear()

    with pytest.raises(ValueError, match="does not belong to this topology"):
        topology.run_packet_probe(other.left, probe_args(other), timeout=5)

    assert runner.calls == []
    other.close()


def test_inactive_topology_refuses_probes(runner, ids):
    topology = VethTopology(runner=runner, privilege=SUDO, drop_privileges=DROP)

    with pytest.raises(RuntimeError, match="not active"):
        topology.run_packet_probe(topology.left, probe_args(topology), timeout=5)
    assert runner.calls == []


def test_probes_are_never_run_as_root(topology, runner):
    with patch("netverify.linux.topology.os.getuid", return_value=0):
        with pytest.raises(RuntimeError, match="never run as root"):
            topology.run_packet_probe(topology.left, probe_args(topology), timeout=5)

    assert runner.calls == []


def test_probes_are_refused_when_the_topology_runs_as_root(runner, ids):
    topology = VethTopology(runner=runner, privilege=[], drop_privileges=[])
    topology.setup()
    runner.clear()

    with pytest.raises(RuntimeError, match="never run as root"):
        topology.run_packet_probe(topology.left, probe_args(topology), timeout=5)
    assert runner.calls == []


@pytest.mark.parametrize(("timeout", "error"), [
    (0, ValueError), (-1, ValueError), (math.nan, ValueError), (math.inf, ValueError),
    (True, TypeError), ("5", TypeError),
])
def test_invalid_process_timeouts_are_refused(topology, runner, timeout, error):
    with pytest.raises(error):
        topology.run_packet_probe(topology.left, probe_args(topology), timeout=timeout)

    assert runner.calls == []


# Public API


def test_icmp_check_runs_the_probe_and_returns_its_result(topology, runner):
    result = verify_icmp_echo_in_namespace(topology, topology.left, "10.231.0.2", timeout=1.5)

    assert result == VerificationResult(Protocol.ICMP, Target("10.231.0.2"), 0.0004)
    (command,) = runner.probe_calls()
    assert command[command.index("netverify.linux.packet_probe") + 1] == "icmp-echo"
    assert option(command, "--timeout") == "1.5"
    assert runner.timeouts == [1.5 + PROBE_OVERHEAD]


def test_arp_check_passes_the_normalized_expected_mac(topology, runner):
    result = verify_arp_in_namespace(topology, topology.right, "10.231.0.1",
                                     expected_mac="02-00-00-00-00-0A")

    assert result.protocol is Protocol.ARP and result.target == Target("10.231.0.1")
    (command,) = runner.probe_calls()
    assert option(command, "--expected-mac") == "02:00:00:00:00:0a"
    assert option(command, "--interface") == topology.right.interface
    assert topology.right.namespace in command


def test_arp_check_without_expected_mac_omits_the_option(topology, runner):
    verify_arp_in_namespace(topology, topology.left, "10.231.0.2")

    assert "--expected-mac" not in runner.probe_calls()[0]


def test_failed_results_are_returned_not_raised(topology, runner):
    failure = Failure(FailureReason.NETWORK_UNREACHABLE, "Could not open a packet socket")
    runner.probe_output = lambda args: result_json(Protocol.ICMP, "10.231.0.2", failure)

    result = verify_icmp_echo_in_namespace(topology, topology.left, "10.231.0.2")

    assert result.reason is FailureReason.NETWORK_UNREACHABLE


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda t: verify_icmp_echo_in_namespace(t, t.left, "10.231.0.2", timeout=0), ValueError),
        (lambda t: verify_icmp_echo_in_namespace(t, t.left, "10.231.0.2", timeout=61),
         ValueError),
        (lambda t: verify_icmp_echo_in_namespace(t, t.left, "not-an-ip"), ValueError),
        (lambda t: verify_icmp_echo_in_namespace(t, t.left, "10.231.0.1"), ValueError),
        (lambda t: verify_icmp_echo_in_namespace(t, t.left, "192.0.2.1"), ValueError),
        (lambda t: verify_arp_in_namespace(t, t.left, "10.231.0.2", expected_mac="nope"),
         ValueError),
        (lambda t: verify_arp_in_namespace(t, t.left, "10.231.0.2", timeout="2"), TypeError),
    ],
)
def test_invalid_arguments_raise_before_anything_runs(topology, runner, call, error):
    with pytest.raises(error):
        call(topology)

    assert runner.calls == []


@pytest.mark.parametrize(
    ("output", "message"),
    [
        (lambda args: "", "probe printed no result"),
        (lambda args: "not json", "invalid result"),
        (lambda args: result_json(Protocol.ARP, "10.231.0.2"), "returned a arp result"),
        (lambda args: result_json(Protocol.ICMP, "10.231.0.1"), "expected icmp"),
    ],
    ids=["empty", "not-json", "wrong-protocol", "wrong-target"],
)
def test_invalid_probe_output_is_a_probe_error(topology, runner, output, message):
    runner.probe_output = output

    with pytest.raises(ProbeError, match=message):
        verify_icmp_echo_in_namespace(topology, topology.left, "10.231.0.2")


def test_probe_failures_raise_command_error(topology, runner):
    runner.fail_probe = CommandError(["probe"], 3, "", "packet_probe: PermissionError",
                                     "failed with exit status 3")

    with pytest.raises(CommandError, match="exit status 3"):
        verify_arp_in_namespace(topology, topology.left, "10.231.0.2")


def test_packet_checks_work_with_recovery_polling(topology, runner):
    outcomes = iter([
        result_json(Protocol.ICMP, "10.231.0.2",
                    Failure(FailureReason.TIMEOUT, "No echo reply")),
        result_json(Protocol.ICMP, "10.231.0.2"),
    ])
    runner.probe_output = lambda args: next(outcomes)
    clock = iter([0.0, 0.0, 0.1, 0.4, 0.5, 0.5])

    recovery = wait_for_recovery(
        lambda timeout: verify_icmp_echo_in_namespace(topology, topology.left, "10.231.0.2",
                                                      timeout=timeout),
        deadline=5.0, interval=0.3, attempt_timeout=1.0,
        clock=lambda: next(clock), sleep=lambda seconds: None)

    assert recovery.recovered_within_deadline
    assert recovery.failure_reasons == (FailureReason.TIMEOUT,)
    assert [option(c, "--timeout") for c in runner.probe_calls()] == ["1.0", "1.0"]


# link_address


def test_link_address_reads_ip_link_without_privileges(topology, runner):
    runner.link_output = (f"5: {topology.left.interface}@if4: <BROADCAST,UP,LOWER_UP> mtu 1500 "
                          "qdisc noqueue state UP mode DEFAULT\\    link/ether 02:00:00:00:00:0A "
                          "brd ff:ff:ff:ff:ff:ff link-netns peer\n")

    assert link_address(topology, topology.left) == "02:00:00:00:00:0a"
    (command,) = runner.calls
    assert command[-6:] == ["ip", "-o", "link", "show", "dev", topology.left.interface]
    assert not any("net_raw" in part for part in command)


def test_link_address_without_an_ethernet_address_is_an_error(topology, runner):
    runner.link_output = "1: lo: <LOOPBACK,UP> mtu 65536\\    link/loopback 00:00:00:00:00:00\n"

    with pytest.raises(ValueError, match="no Ethernet address"):
        link_address(topology, topology.left)


# missing_packet_prerequisites


def prerequisites(runner, *, uid=1000, scapy=True, base=()):
    with patch.object(packet, "missing_prerequisites", return_value=list(base)), \
         patch.object(packet.os, "getuid", return_value=uid), \
         patch.object(packet.importlib.util, "find_spec",
                      return_value=object() if scapy else None):
        return missing_packet_prerequisites(runner)


def setpriv_help(text):
    def run(args, *, timeout=DEFAULT_TIMEOUT):
        assert args == ["setpriv", "--help"]
        return subprocess.CompletedProcess(args, 0, text, "")
    return run


def test_nothing_missing():
    assert prerequisites(setpriv_help("... --ambient-caps <caps> ...")) == []


def test_topology_prerequisites_come_first():
    assert prerequisites(setpriv_help(""), base=["Linux (this platform is darwin)"]) == [
        "Linux (this platform is darwin)"]


def test_each_packet_prerequisite_is_reported():
    def failing(args, *, timeout=DEFAULT_TIMEOUT):
        raise CommandError(args, None, "", "", "not found")

    missing = prerequisites(failing, uid=0, scapy=False)

    assert missing == [
        "a non-root user (packet probes never run as root)",
        "Scapy (pip install 'netverify[packet]')",
        "a setpriv that supports --ambient-caps (util-linux 2.31+)",
    ]
