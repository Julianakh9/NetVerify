"""Linux-specific NetVerify functionality: network namespace topologies,
reversible faults inside them, and TCP and packet-level (ICMP echo, ARP)
checks between their namespaces.

Importing this package is safe on any platform. Linux commands only run
when a topology is set up or used.
"""

from netverify.linux.commands import CommandError, run_command
from netverify.linux.connectivity import (
    ProbeError,
    tcp_listener,
    tcp_server,
    verify_tcp_in_namespace,
)
from netverify.linux.faults import (
    FaultError,
    FaultInjectionError,
    FaultRestoreError,
    LinkDown,
    link_is_up,
)
from netverify.linux.packet import (
    link_address,
    missing_packet_prerequisites,
    verify_arp_in_namespace,
    verify_icmp_echo_in_namespace,
)
from netverify.linux.topology import (
    Endpoint,
    TopologyCleanupError,
    TopologyError,
    TopologySetupError,
    VethTopology,
    missing_prerequisites,
)

__all__ = [
    "CommandError",
    "Endpoint",
    "FaultError",
    "FaultInjectionError",
    "FaultRestoreError",
    "LinkDown",
    "ProbeError",
    "TopologyCleanupError",
    "TopologyError",
    "TopologySetupError",
    "VethTopology",
    "link_address",
    "link_is_up",
    "missing_packet_prerequisites",
    "missing_prerequisites",
    "run_command",
    "tcp_listener",
    "tcp_server",
    "verify_arp_in_namespace",
    "verify_icmp_echo_in_namespace",
    "verify_tcp_in_namespace",
]
