"""Integration tests with real Linux network namespaces.

These need Linux, iproute2, and root or passwordless sudo (plus setpriv when
not root). Elsewhere they are skipped with the reason shown. When
NETVERIFY_REQUIRE_NETNS=1 is set (as in CI), missing prerequisites fail the
tests instead, so they can never be skipped silently.

All traffic stays between the two namespaces of a topology. Nothing is sent
to the host or beyond, and the host's interfaces and routes are not changed.
"""

import os

import pytest

from netverify.linux.commands import DEFAULT_TIMEOUT, CommandError, run_command
from netverify.linux.connectivity import tcp_listener, verify_tcp_in_namespace
from netverify.linux.topology import (
    TopologyCleanupError,
    TopologySetupError,
    VethTopology,
    missing_prerequisites,
)
from netverify.results import FailureReason, Target

pytestmark = pytest.mark.netns

REQUIRE_ENV = "NETVERIFY_REQUIRE_NETNS"


@pytest.fixture
def netns_prerequisites():
    missing = missing_prerequisites()
    if missing:
        message = "Linux namespace tests need: " + "; ".join(missing)
        if os.environ.get(REQUIRE_ENV) == "1":
            pytest.fail(f"{message} ({REQUIRE_ENV}=1 forbids skipping)")
        pytest.skip(message)


@pytest.fixture
def topology(netns_prerequisites):
    with VethTopology() as topology:
        yield topology


def namespace_names():
    """Names from `ip netns list` (readable without privileges)."""
    output = run_command(["ip", "netns", "list"]).stdout
    return {line.split()[0] for line in output.splitlines() if line.strip()}


def host_network_state():
    """The host's interface names and IPv4 routes."""
    links = run_command(["ip", "-o", "link", "show"]).stdout
    names = {line.split(":")[1].strip().split("@")[0] for line in links.splitlines()}
    routes = run_command(["ip", "-4", "route", "show"]).stdout
    return names, routes


def test_topology_configures_both_endpoints(topology):
    assert {topology.left.namespace, topology.right.namespace} <= namespace_names()

    for endpoint in (topology.left, topology.right):
        addresses = topology.run(
            endpoint, ["ip", "-4", "-o", "address", "show", "dev", endpoint.interface]
        ).stdout
        assert endpoint.cidr in addresses

        # Administratively up. (Carrier state can lag slightly, so it is not asserted.)
        link = topology.run(endpoint, ["ip", "-o", "link", "show", "dev", endpoint.interface]).stdout
        assert ",UP" in link or "<UP" in link


def test_namespace_commands_run_as_the_calling_user(topology):
    uid = topology.run(topology.left, ["id", "-u"]).stdout.strip()

    assert uid == str(os.getuid())


def test_tcp_connectivity_between_namespaces(topology):
    with tcp_listener(topology, topology.right, timeout=10.0) as port:
        result = verify_tcp_in_namespace(
            topology, topology.left, topology.right.address, port, timeout=2.0
        )

    assert result.success is True, result.failure
    assert result.target == Target(topology.right.address, port)


def test_closed_port_in_other_namespace_is_refused(topology):
    # The namespace is new and empty, so nothing listens on port 9.
    result = verify_tcp_in_namespace(
        topology, topology.left, topology.right.address, 9, timeout=2.0
    )

    assert result.reason is FailureReason.CONNECTION_REFUSED


def test_topology_does_not_change_host_interfaces_or_routes(netns_prerequisites):
    before = host_network_state()

    with VethTopology() as topology:
        during = host_network_state()
    after = host_network_state()

    assert during == before
    assert after == before
    assert topology.left.interface not in during[0]


def test_close_removes_namespaces(netns_prerequisites):
    topology = VethTopology()
    topology.setup()
    names = {topology.left.namespace, topology.right.namespace}
    assert names <= namespace_names()

    topology.close()

    assert not names & namespace_names()


def test_failed_cleanup_can_be_retried(netns_prerequisites):
    # Real commands, except that the first namespace deletion fails.
    failed = []

    def runner(args, *, timeout=DEFAULT_TIMEOUT):
        if not failed and "netns" in args and "delete" in args:
            failed.append(args)
            raise CommandError(list(args), 1, "", "simulated failure", "failed with exit status 1")
        return run_command(args, timeout=timeout)

    topology = VethTopology(runner=runner)
    topology.setup()
    names = {topology.left.namespace, topology.right.namespace}

    with pytest.raises(TopologyCleanupError, match="simulated failure"):
        topology.close()
    assert len(names & namespace_names()) == 1  # One namespace is still there.

    topology.close()

    assert not names & namespace_names()


def test_partial_setup_failure_removes_created_namespaces(netns_prerequisites):
    # Real commands, except that assigning an address fails after both
    # namespaces and the veth pair already exist.
    def runner(args, *, timeout=DEFAULT_TIMEOUT):
        if "address" in args and "add" in args:
            raise CommandError(list(args), 1, "", "simulated failure", "failed with exit status 1")
        return run_command(args, timeout=timeout)

    topology = VethTopology(runner=runner)

    with pytest.raises(TopologySetupError, match="simulated failure"):
        topology.setup()

    assert not {topology.left.namespace, topology.right.namespace} & namespace_names()
