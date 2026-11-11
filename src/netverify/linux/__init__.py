"""Linux-specific NetVerify functionality: network namespace topologies and
reversible faults inside them.

Importing this package is safe on any platform. Linux commands only run
when a topology is set up or used.
"""

from netverify.linux.commands import CommandError, run_command
from netverify.linux.connectivity import ProbeError, tcp_listener, verify_tcp_in_namespace
from netverify.linux.faults import (
    FaultError,
    FaultInjectionError,
    FaultRestoreError,
    LinkDown,
    link_is_up,
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
    "link_is_up",
    "missing_prerequisites",
    "run_command",
    "tcp_listener",
    "verify_tcp_in_namespace",
]
