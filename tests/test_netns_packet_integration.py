"""Packet-level (ICMP echo, ARP) checks between real Linux network namespaces.

These need everything the other namespace tests need, plus a non-root user,
Scapy, and a setpriv with ambient capability support. Elsewhere they are
skipped with the reason shown; with NETVERIFY_REQUIRE_NETNS=1 (as in CI),
missing prerequisites fail instead.

Packets stay on the veth link between the two namespaces of a topology,
and every test checks its own observable outcome strictly: no retries.
"""

import errno
import glob
import os
import sys
import threading
import time

import pytest

from netverify.linux.commands import run_command
from netverify.linux.connectivity import PROBE_OVERHEAD
from netverify.linux.faults import LinkDown, link_is_up
from netverify.linux.packet import (
    link_address,
    missing_packet_prerequisites,
    verify_arp_in_namespace,
    verify_icmp_echo_in_namespace,
)
from netverify.linux.packet_request import PACKET_PROBE_MODULE
from netverify.linux.topology import VethTopology
from netverify.recovery import wait_for_recovery
from netverify.results import FailureReason, Protocol, Target

pytestmark = pytest.mark.netns

REQUIRE_ENV = "NETVERIFY_REQUIRE_NETNS"
TIMEOUT = 2.0
# How far a check may run past its own deadline: process scheduling and
# the last bounded wait. Far below Scapy's hidden 2 s MAC lookup, which the
# probe must not use.
OVERRUN = 0.5
NET_RAW_ONLY = "0000000000002000"  # bit 13: CAP_NET_RAW
WIDE_NETWORK = "10.231.8.0/29"     # hosts .1-.6; .1 and .2 are the endpoints


@pytest.fixture
def packet_prerequisites():
    missing = missing_packet_prerequisites()
    if missing:
        message = "Packet namespace tests need: " + "; ".join(missing)
        if os.environ.get(REQUIRE_ENV) == "1":
            pytest.fail(f"{message} ({REQUIRE_ENV}=1 forbids skipping)")
        pytest.skip(message)


@pytest.fixture
def topology(packet_prerequisites):
    with VethTopology() as topology:
        yield topology


@pytest.fixture
def wide_topology(packet_prerequisites):
    with VethTopology(WIDE_NETWORK) as topology:
        yield topology


# Observation helpers (read-only)


def host_network_state():
    """The host's interface names and IPv4 routes."""
    links = run_command(["ip", "-o", "link", "show"]).stdout
    names = {line.split(":")[1].strip().split("@")[0] for line in links.splitlines()}
    return names, run_command(["ip", "-4", "route", "show"]).stdout


def namespace_names():
    output = run_command(["ip", "netns", "list"]).stdout
    return {line.split()[0] for line in output.splitlines() if line.strip()}


def probe_processes():
    """(argv, /proc status fields) of every process whose command runs the probe.

    This includes the sudo wrapper (root) as well as the probe itself.
    """
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as file:
                argv = [part.decode() for part in file.read().split(b"\0") if part]
            if PACKET_PROBE_MODULE not in argv:
                continue
            with open(f"/proc/{entry}/status") as file:
                status = dict(line.rstrip("\n").split(":\t", 1) for line in file if ":\t" in line)
        except OSError:
            continue  # The process ended meanwhile.
        found.append((argv, status))
    return found


def running_probe():
    """Status of the probe's own Python process, once it has started Python."""
    expected = [sys.executable, "-I", "-m", PACKET_PROBE_MODULE]
    matches = [status for argv, status in probe_processes() if argv[:4] == expected]
    return matches[0] if len(matches) == 1 else None


def packet_sockets(topology, endpoint):
    """Rows of /proc/net/packet inside endpoint's namespace (one per socket)."""
    lines = topology.run(endpoint, ["cat", "/proc/net/packet"]).stdout.splitlines()
    header = lines[0].split()
    return [dict(zip(header, line.split())) for line in lines[1:] if line.strip()]


def scapy_folders():
    return set(glob.glob("/tmp/netverify-scapy-*"))


def assert_bounded_timeout(result):
    assert result.reason is FailureReason.TIMEOUT, result.failure
    assert TIMEOUT - 0.05 <= result.duration_seconds <= TIMEOUT + OVERRUN, result.duration_seconds


# Privileges


def test_probe_runs_as_the_calling_user_with_only_cap_net_raw(wide_topology):
    topology = wide_topology
    outcome = {}

    def check():
        # Nothing answers this address, so the probe keeps its socket open
        # for the whole timeout, long enough to observe it.
        outcome["result"] = verify_arp_in_namespace(topology, topology.left, "10.231.8.3",
                                                    timeout=4.0)

    worker = threading.Thread(target=check)
    worker.start()
    # Observe while the probe is waiting: first its packet socket (which
    # exists only once the probe runs Python), then the process itself.
    probe, sockets = None, []
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and worker.is_alive():
        sockets = packet_sockets(topology, topology.left)
        if sockets:
            probe = running_probe()
            break
        time.sleep(0.05)
    worker.join(timeout=4.0 + PROBE_OVERHEAD)
    assert not worker.is_alive()

    uid, gid = str(os.getuid()), str(os.getgid())
    assert probe is not None, "the probe process was never observed"
    assert probe["Uid"].split() == [uid] * 4    # real, effective, saved, filesystem
    assert probe["Gid"].split() == [gid] * 4
    assert probe["Groups"].strip() == ""
    for capability_set in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"):
        assert probe[capability_set] == NET_RAW_ONLY, (capability_set, probe[capability_set])
    assert probe["NoNewPrivs"] == "1"
    # The packet socket in the namespace belongs to the calling user.
    assert sockets and {row["User"] for row in sockets} == {uid}

    assert outcome["result"].reason is FailureReason.TIMEOUT
    assert uid != "0"


# Healthy link


@pytest.mark.parametrize("direction", ["left-to-right", "right-to-left"])
def test_icmp_echo_succeeds_in_both_directions(topology, direction):
    source, target = ((topology.left, topology.right) if direction == "left-to-right"
                      else (topology.right, topology.left))

    result = verify_icmp_echo_in_namespace(topology, source, target.address, timeout=TIMEOUT)

    assert result.success is True, result.failure
    assert (result.protocol, result.target) == (Protocol.ICMP, Target(target.address))
    assert 0 < result.duration_seconds < TIMEOUT


@pytest.mark.parametrize("direction", ["left-to-right", "right-to-left"])
def test_arp_reply_gives_the_peer_mac_in_both_directions(topology, direction):
    source, target = ((topology.left, topology.right) if direction == "left-to-right"
                      else (topology.right, topology.left))

    result = verify_arp_in_namespace(topology, source, target.address,
                                     expected_mac=link_address(topology, target),
                                     timeout=TIMEOUT)

    assert result.success is True, result.failure
    assert (result.protocol, result.target) == (Protocol.ARP, Target(target.address))


def test_arp_reply_with_another_mac_than_expected_fails(topology):
    actual = link_address(topology, topology.right)
    wrong = "02:00:5e:00:53:01" if actual != "02:00:5e:00:53:01" else "02:00:5e:00:53:02"

    result = verify_arp_in_namespace(topology, topology.left, topology.right.address,
                                     expected_mac=wrong, timeout=TIMEOUT)

    assert result.reason is FailureReason.HARDWARE_ADDRESS_MISMATCH
    assert actual in result.failure.message and wrong in result.failure.message


def test_unused_destination_address_times_out(wide_topology):
    unused = "10.231.8.3"  # on the link's network, but no interface has it

    arp = verify_arp_in_namespace(wide_topology, wide_topology.left, unused, timeout=TIMEOUT)
    icmp = verify_icmp_echo_in_namespace(wide_topology, wide_topology.left, unused,
                                         timeout=TIMEOUT)

    assert_bounded_timeout(arp)
    assert arp.failure.message == f"No ARP reply from {unused} within 2 seconds"
    assert_bounded_timeout(icmp)
    assert "so no echo request was sent" in icmp.failure.message


# Link faults and recovery


def test_source_link_down_fails_at_socket_open_and_recovers(topology):
    with LinkDown(topology, topology.left):
        assert link_is_up(topology, topology.left) is False
        icmp = verify_icmp_echo_in_namespace(topology, topology.left, topology.right.address,
                                             timeout=TIMEOUT)
        arp = verify_arp_in_namespace(topology, topology.left, topology.right.address,
                                      timeout=TIMEOUT)

    for result in (icmp, arp):
        assert result.reason is FailureReason.NETWORK_UNREACHABLE, result.failure
        assert result.failure.error_code == errno.ENETDOWN
        assert result.failure.message.startswith(
            f"Could not open a packet socket on {topology.left.interface}:")

    assert link_is_up(topology, topology.left) is True
    after_icmp = verify_icmp_echo_in_namespace(topology, topology.left, topology.right.address,
                                               timeout=TIMEOUT)
    after_arp = verify_arp_in_namespace(topology, topology.left, topology.right.address,
                                        timeout=TIMEOUT)
    assert after_icmp.success is True, after_icmp.failure
    assert after_arp.success is True, after_arp.failure


def test_peer_link_down_times_out_within_the_deadline_and_recovers(topology):
    with LinkDown(topology, topology.right):
        began = time.monotonic()
        icmp = verify_icmp_echo_in_namespace(topology, topology.left, topology.right.address,
                                             timeout=TIMEOUT)
        icmp_wall = time.monotonic() - began
        arp = verify_arp_in_namespace(topology, topology.left, topology.right.address,
                                      timeout=TIMEOUT)

    # No hidden MAC lookup: the whole ICMP check, ARP included, keeps to
    # one deadline (the spike measured 4.5 s for 2 s with Scapy's lookup).
    assert_bounded_timeout(icmp)
    assert "so no echo request was sent" in icmp.failure.message
    assert icmp_wall < TIMEOUT + PROBE_OVERHEAD
    assert_bounded_timeout(arp)

    assert link_is_up(topology, topology.right) is True
    after = verify_icmp_echo_in_namespace(topology, topology.left, topology.right.address,
                                          timeout=TIMEOUT)
    assert after.success is True, after.failure


def test_recovery_is_observed_by_polling_over_icmp(topology):
    healthy = verify_icmp_echo_in_namespace(topology, topology.left, topology.right.address,
                                            timeout=TIMEOUT)
    assert healthy.success is True, healthy.failure

    # The link is restored only after polling has observed a failure, so
    # the order is explicit: failure first, then recovery.
    fault = LinkDown(topology, topology.left)
    fault.__enter__()
    restored = []

    def check(timeout):
        result = verify_icmp_echo_in_namespace(topology, topology.left, topology.right.address,
                                               timeout=timeout)
        if not result.success and not restored:
            fault.__exit__(None, None, None)
            restored.append(True)
        return result

    try:
        recovery = wait_for_recovery(check, deadline=20.0, interval=0.2, attempt_timeout=2.0)
    finally:
        if not restored:
            fault.__exit__(None, None, None)

    assert recovery.failure_reasons[0] is FailureReason.NETWORK_UNREACHABLE
    assert recovery.attempts >= 2
    assert recovery.recovered_within_deadline is True, recovery.to_dict()
    assert recovery.last_result.protocol is Protocol.ICMP


# Cleanup and isolation


def test_packet_checks_leave_nothing_behind(packet_prerequisites):
    host_before, folders_before = host_network_state(), scapy_folders()
    assert probe_processes() == []

    with VethTopology(WIDE_NETWORK) as topology:
        left, right = topology.left, topology.right
        results = [
            verify_icmp_echo_in_namespace(topology, left, right.address, timeout=TIMEOUT),
            verify_arp_in_namespace(topology, right, left.address, timeout=TIMEOUT),
            verify_icmp_echo_in_namespace(topology, left, "10.231.8.5", timeout=1.0),
        ]
        host_during = host_network_state()
        sockets = {side.namespace: packet_sockets(topology, side) for side in (left, right)}
        names = {left.namespace, right.namespace}

    assert [r.success for r in results] == [True, True, False]
    assert sockets == {left.namespace: [], right.namespace: []}  # no packet socket left open
    assert probe_processes() == []                               # no probe still running
    assert scapy_folders() == folders_before                     # temporary folders removed
    assert host_during == host_before == host_network_state()    # host untouched
    assert left.interface not in host_during[0]
    assert not names & namespace_names()                         # namespaces removed
