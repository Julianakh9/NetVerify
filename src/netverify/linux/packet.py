"""Packet-level checks between the namespaces of a topology: ICMP echo and ARP.

Each check runs NetVerify's packet probe (netverify.linux.packet_probe)
inside the source endpoint's namespace, as the calling user with only
CAP_NET_RAW (see VethTopology.run_packet_probe), and returns its
VerificationResult. Packets go only to host addresses on the topology's
own link, through the endpoint's own veth interface.

Needs Scapy in this Python environment: pip install 'netverify[packet]'.
missing_packet_prerequisites() lists what is missing.

Errors are kept in the same three groups as the TCP checks:
    - ValueError / TypeError: invalid arguments; nothing was run.
    - CommandError / ProbeError: the probe could not run or misbehaved
      (for example no Scapy, no CAP_NET_RAW, or invalid output).
    - A VerificationResult with a failure: the check ran and failed.
"""

import importlib.util
import os
import re

from netverify.linux.commands import CommandError, run_command
from netverify.linux.connectivity import PROBE_OVERHEAD, ProbeError, _parse_result
from netverify.linux.packet_request import ARP, ICMP_ECHO, ProbeRequest, build_arguments
from netverify.linux.packet_validation import normalize_mac
from netverify.linux.topology import (
    Endpoint,
    Runner,
    VethTopology,
    missing_prerequisites,
)
from netverify.results import Protocol, Target, VerificationResult

_LINK_ETHER = re.compile(r"\blink/ether ([0-9A-Fa-f:]{17})\b")


def verify_icmp_echo_in_namespace(
    topology: VethTopology,
    source: Endpoint,
    destination: str,
    *,
    timeout: float = 2.0,
) -> VerificationResult:
    """Send an ICMP echo request from source's namespace and check the reply.

    The probe first resolves destination's MAC address with ARP, then
    sends the echo request at layer 2. Both steps share one deadline of
    timeout seconds. The reply must come from destination, with the
    request's identifier, sequence and payload.

    Returns:
        A VerificationResult with Protocol.ICMP and a portless target. On
        failure the reason is, for example, TIMEOUT (no ARP or echo reply),
        NETWORK_UNREACHABLE (source interface down), UNEXPECTED_SENDER,
        PAYLOAD_MISMATCH, an ICMP error classification, or
        HARDWARE_ADDRESS_MISMATCH (inconsistent ARP reply).

    Raises:
        ValueError, TypeError: Invalid destination or timeout (0 < timeout
            <= 60), or source is not this topology's endpoint.
        RuntimeError: The topology is not active, or the caller is root.
        CommandError: The probe could not run or exited with an error.
        ProbeError: The probe ran but did not print a valid result.
    """
    request = ProbeRequest(ICMP_ECHO, source.interface, source.address, destination, timeout)
    return _run_probe(topology, source, request, Protocol.ICMP)


def verify_arp_in_namespace(
    topology: VethTopology,
    source: Endpoint,
    destination: str,
    *,
    expected_mac: str | None = None,
    timeout: float = 2.0,
) -> VerificationResult:
    """Send an ARP request from source's namespace and check the reply.

    Args:
        expected_mac: The MAC address destination must reply with (any
            case, ":" or "-" separators), or None to accept any reply from
            destination. link_address() reads an endpoint's address.

    Returns:
        A VerificationResult with Protocol.ARP and a portless target. On
        failure the reason is, for example, TIMEOUT (no reply),
        NETWORK_UNREACHABLE (source interface down) or
        HARDWARE_ADDRESS_MISMATCH.

    Raises:
        Same as verify_icmp_echo_in_namespace(), plus ValueError for an
        invalid expected_mac.
    """
    request = ProbeRequest(ARP, source.interface, source.address, destination, timeout,
                           expected_mac)
    return _run_probe(topology, source, request, Protocol.ARP)


def link_address(topology: VethTopology, endpoint: Endpoint) -> str:
    """Return the MAC address of endpoint's veth interface.

    Reads `ip -o link show` inside the namespace as the calling user, with
    no privileges. The address is lowercase and colon-separated.

    Raises:
        CommandError: The `ip` command failed.
        ValueError: The output has no Ethernet address.
    """
    shown = topology.run(endpoint, ["ip", "-o", "link", "show", "dev", endpoint.interface])
    match = _LINK_ETHER.search(shown.stdout)
    if match is None:
        raise ValueError(f"no Ethernet address in `ip link show` output: {shown.stdout!r}")
    return normalize_mac(match.group(1))


def missing_packet_prerequisites(runner: Runner = run_command) -> list[str]:
    """Return what is missing to run packet checks here (empty if none).

    Packet checks need everything topologies need, plus: a non-root user
    (packet probes are never run as root), Scapy, and a setpriv that can
    set ambient capabilities (util-linux 2.31 or newer).
    """
    missing = missing_prerequisites(runner)
    if missing:
        return missing
    if os.getuid() == 0:
        missing.append("a non-root user (packet probes never run as root)")
    if importlib.util.find_spec("scapy") is None:
        missing.append("Scapy (pip install 'netverify[packet]')")
    try:
        help_text = runner(["setpriv", "--help"], timeout=10).stdout
    except CommandError:
        help_text = ""
    if "--ambient-caps" not in help_text:
        missing.append("a setpriv that supports --ambient-caps (util-linux 2.31+)")
    return missing


def _run_probe(topology: VethTopology, source: Endpoint, request: ProbeRequest,
               protocol: Protocol) -> VerificationResult:
    completed = topology.run_packet_probe(source, build_arguments(request),
                                          timeout=request.timeout + PROBE_OVERHEAD)
    result = _parse_result(completed.stdout)
    expected = Target(request.destination)
    if result.protocol is not protocol or result.target != expected:
        raise ProbeError(
            f"probe returned a {result.protocol.value} result for {result.target}, "
            f"expected {protocol.value} for {expected}"
        )
    return result
