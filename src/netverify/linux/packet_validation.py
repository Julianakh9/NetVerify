"""Pure validation of ICMP echo and ARP replies.

This module decides whether a received packet answers a request, and if
so, whether the answer is correct. It does no I/O: no Scapy, no sockets,
no subprocesses and no privileges. A packet probe decodes what it receives
into the observation types below and asks the matchers for a verdict.

Every matcher returns:
    - None: the packet is unrelated to the request (for example our own
      outgoing request, another host's traffic or a reply to a different
      request). The caller keeps waiting until its deadline.
    - An Answer: the packet answers the request. Answer.failure is None if
      the answer is correct, otherwise it explains what was wrong.

Observation types check their own fields when created and raise
ValueError or TypeError for impossible values. A probe should treat a
packet it cannot turn into an observation as unrelated, not as an answer.
"""

import ipaddress
import re
from dataclasses import dataclass

from netverify.diagnostics import ICMP_ERROR_TYPES, classify_icmp_error
from netverify.results import Failure, FailureReason

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
ARP_REQUEST = 1
ARP_REPLY = 2

# Largest ICMP echo payload in one IPv4 datagram: 65535 - 20 (IP) - 8 (ICMP).
MAX_ECHO_PAYLOAD = 65507

_MAC = re.compile(r"[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}")


def normalize_mac(text: str) -> str:
    """Return a MAC address as six lowercase, colon-separated octets.

    Accepts ":" or "-" separators (not mixed) in any case.

    Raises:
        TypeError: text is not a string.
        ValueError: text is not a 48-bit MAC address.
    """
    if not isinstance(text, str):
        raise TypeError(f"MAC address must be a string, got {text!r}")
    lowered = text.lower()
    if not _MAC.fullmatch(lowered):
        raise ValueError(f"invalid MAC address {text!r}")
    return lowered.replace("-", ":")


def normalize_ipv4(text: str) -> str:
    """Return an IPv4 address in its canonical dotted form.

    Raises:
        TypeError: text is not a string.
        ValueError: text is not an IPv4 address.
    """
    if not isinstance(text, str):
        raise TypeError(f"IPv4 address must be a string, got {text!r}")
    try:
        return str(ipaddress.IPv4Address(text))
    except ipaddress.AddressValueError:
        raise ValueError(f"invalid IPv4 address {text!r}") from None


def _check_int(name: str, value: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {value!r}")
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} must be 0-{maximum}, got {value}")


def _check_bytes(name: str, value: bytes, maximum: int) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    if len(value) > maximum:
        raise ValueError(f"{name} must be at most {maximum} bytes, got {len(value)}")


def _set(instance: object, name: str, value: object) -> None:
    object.__setattr__(instance, name, value)  # Normalize a frozen field.


@dataclass(frozen=True, slots=True)
class Answer:
    """A packet that answers the request. Correct when failure is None."""

    failure: Failure | None = None

    @property
    def success(self) -> bool:
        return self.failure is None


# ICMP


@dataclass(frozen=True, slots=True)
class EchoRequest:
    """The ICMP echo request that was sent, as the probe built it."""

    source: str
    destination: str
    identifier: int
    sequence: int
    payload: bytes

    def __post_init__(self) -> None:
        _set(self, "source", normalize_ipv4(self.source))
        _set(self, "destination", normalize_ipv4(self.destination))
        _check_int("identifier", self.identifier, 0xFFFF)
        _check_int("sequence", self.sequence, 0xFFFF)
        _check_bytes("payload", self.payload, MAX_ECHO_PAYLOAD)


@dataclass(frozen=True, slots=True)
class QuotedEcho:
    """The echo request quoted inside an ICMP error message."""

    source: str
    destination: str
    identifier: int
    sequence: int

    def __post_init__(self) -> None:
        _set(self, "source", normalize_ipv4(self.source))
        _set(self, "destination", normalize_ipv4(self.destination))
        _check_int("identifier", self.identifier, 0xFFFF)
        _check_int("sequence", self.sequence, 0xFFFF)


@dataclass(frozen=True, slots=True)
class IcmpPacket:
    """A received IPv4 ICMP message, decoded by the probe.

    identifier and sequence are set for echo messages. quoted is set for
    error messages whose quoted datagram is an echo request; it is None
    when the quote is missing, truncated or not an echo request.
    """

    source: str
    destination: str
    icmp_type: int
    icmp_code: int
    identifier: int | None = None
    sequence: int | None = None
    payload: bytes = b""
    quoted: QuotedEcho | None = None

    def __post_init__(self) -> None:
        _set(self, "source", normalize_ipv4(self.source))
        _set(self, "destination", normalize_ipv4(self.destination))
        _check_int("icmp_type", self.icmp_type, 255)
        _check_int("icmp_code", self.icmp_code, 255)
        for name in ("identifier", "sequence"):
            value = getattr(self, name)
            if value is not None:
                _check_int(name, value, 0xFFFF)
        _check_bytes("payload", self.payload, MAX_ECHO_PAYLOAD)
        if self.quoted is not None and not isinstance(self.quoted, QuotedEcho):
            raise TypeError(f"quoted must be a QuotedEcho or None, got {self.quoted!r}")


def match_echo_reply(request: EchoRequest, packet: IcmpPacket) -> Answer | None:
    """Decide whether packet answers the echo request.

    An answer is either:
        - an echo reply (type 0, code 0) addressed to request.source with
          the request's identifier and sequence. It must come from
          request.destination (UNEXPECTED_SENDER otherwise, checked first)
          and carry exactly the request's payload (PAYLOAD_MISMATCH
          otherwise); or
        - an ICMP error addressed to request.source that quotes this
          request (same source, destination, identifier and sequence),
          classified by classify_icmp_error.

    Everything else is unrelated (None): echo requests, including our own
    outgoing one; replies with another identifier or sequence; messages
    addressed elsewhere; and errors that quote another datagram or none.
    """
    if packet.destination != request.source:
        return None

    if packet.icmp_type == ICMP_ECHO_REPLY and packet.icmp_code == 0:
        if (packet.identifier, packet.sequence) != (request.identifier, request.sequence):
            return None
        if packet.source != request.destination:
            return Answer(Failure(
                FailureReason.UNEXPECTED_SENDER,
                f"Echo reply came from {packet.source}, expected {request.destination}",
            ))
        if packet.payload != request.payload:
            return Answer(Failure(
                FailureReason.PAYLOAD_MISMATCH,
                f"Echo reply payload ({len(packet.payload)} bytes) does not match "
                f"the request payload ({len(request.payload)} bytes)",
            ))
        return Answer()

    if packet.icmp_type in ICMP_ERROR_TYPES and packet.quoted is not None:
        quoted = packet.quoted
        if (quoted.source, quoted.destination, quoted.identifier, quoted.sequence) == (
            request.source, request.destination, request.identifier, request.sequence
        ):
            return Answer(classify_icmp_error(packet.icmp_type, packet.icmp_code,
                                              source=packet.source))
    return None


# ARP


@dataclass(frozen=True, slots=True)
class ArpRequest:
    """The ARP request that was sent, and the MAC address expected back.

    expected_mac is None when any MAC address is acceptable.
    """

    sender_mac: str
    sender_ip: str
    target_ip: str
    expected_mac: str | None = None

    def __post_init__(self) -> None:
        _set(self, "sender_mac", normalize_mac(self.sender_mac))
        _set(self, "sender_ip", normalize_ipv4(self.sender_ip))
        _set(self, "target_ip", normalize_ipv4(self.target_ip))
        if self.expected_mac is not None:
            _set(self, "expected_mac", normalize_mac(self.expected_mac))


@dataclass(frozen=True, slots=True)
class ArpPacket:
    """A received Ethernet/IPv4 ARP message, decoded by the probe.

    ethernet_source is the source MAC address of the Ethernet frame, or
    None if the probe did not record it.
    """

    operation: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    ethernet_source: str | None = None

    def __post_init__(self) -> None:
        _check_int("operation", self.operation, 0xFFFF)
        _set(self, "sender_mac", normalize_mac(self.sender_mac))
        _set(self, "sender_ip", normalize_ipv4(self.sender_ip))
        _set(self, "target_mac", normalize_mac(self.target_mac))
        _set(self, "target_ip", normalize_ipv4(self.target_ip))
        if self.ethernet_source is not None:
            _set(self, "ethernet_source", normalize_mac(self.ethernet_source))


def match_arp_reply(request: ArpRequest, packet: ArpPacket) -> Answer | None:
    """Decide whether packet answers the ARP request.

    An answer is an ARP reply (operation 2) about request.target_ip,
    addressed to the requester (target IP and MAC are request.sender_ip
    and request.sender_mac). It fails with HARDWARE_ADDRESS_MISMATCH if:
        - its Ethernet source and ARP sender MAC addresses disagree; or
        - expected_mac is set and the replied MAC address differs from it.

    Everything else is unrelated (None): requests, including our own
    outgoing one; replies about other addresses; and replies to others.
    """
    if packet.operation != ARP_REPLY:
        return None
    if packet.sender_ip != request.target_ip:
        return None
    if (packet.target_ip, packet.target_mac) != (request.sender_ip, request.sender_mac):
        return None

    if packet.ethernet_source is not None and packet.ethernet_source != packet.sender_mac:
        return Answer(Failure(
            FailureReason.HARDWARE_ADDRESS_MISMATCH,
            f"ARP reply for {request.target_ip} says {packet.sender_mac}, but its "
            f"Ethernet frame came from {packet.ethernet_source}",
        ))
    if request.expected_mac is not None and packet.sender_mac != request.expected_mac:
        return Answer(Failure(
            FailureReason.HARDWARE_ADDRESS_MISMATCH,
            f"ARP reply says {request.target_ip} is at {packet.sender_mac}, "
            f"expected {request.expected_mac}",
        ))
    return Answer()
