"""Packet probe: ICMP echo and ARP checks with Scapy, run inside a namespace.

VethTopology.run_packet_probe() starts this module as the calling user with
CAP_NET_RAW as its only capability. It sends and receives Ethernet frames
on one veth interface of a NetVerify topology and prints one
VerificationResult as JSON.

    python -m netverify.linux.packet_probe icmp-echo --interface IF --source IP
        --destination IP --timeout S
    python -m netverify.linux.packet_probe arp --interface IF --source IP
        --destination IP --timeout S [--expected-mac MAC]

Exit status:
    0  a result was printed (whether or not the check passed);
    2  invalid arguments;
    3  the check could not run: Scapy missing, no CAP_NET_RAW, no such
       interface, or an unexpected error. A message goes to stderr.

How a check runs, within one monotonic deadline of --timeout seconds:
    arp:        send an ARP request, then wait for the matching reply.
    icmp-echo:  resolve the destination's MAC address with ARP (as above),
                then send the echo request at layer 2 to that address and
                wait for the matching reply. Scapy's own MAC resolution
                (which has its own hidden timeout) is never used.
    Nothing is sent after the deadline, and nothing received after it is
    accepted. A synchronous socket call can still overrun the deadline;
    the reported duration is then the true elapsed time (see run_check).

Design notes:
    - Scapy is imported only when a check runs, inside a private temporary
      XDG cache/config folder that is always removed (under sudo, HOME is
      /root, which the calling user cannot write). Importing this module
      does not import Scapy.
    - Scapy's socket is opened with nofilter=1: no capture filter is ever
      compiled, so Scapy never starts tcpdump (which would inherit
      CAP_NET_RAW). Frames are filtered in Python.
    - Received frames are decoded with explicit length and checksum checks
      before Scapy's fields are trusted, then turned into the pure
      observation types of netverify.linux.packet_validation, which decide
      whether a frame answers the request.
    - Network errors while opening the socket, sending or receiving are
      classified with classify_os_error (for example ENETDOWN, when the
      source interface is down, becomes NETWORK_UNREACHABLE). Errors that
      mean the probe itself cannot work (no permission, no such interface)
      are not verification results; they end the probe with status 3.
"""

import contextlib
import errno
import json
import os
import secrets
import select
import shutil
import struct
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, Protocol as TypingProtocol, TypeVar

from netverify.diagnostics import ICMP_ERROR_TYPES, classify_os_error
from netverify.linux.packet_request import ARP, ICMP_ECHO, ProbeRequest, parse_arguments
from netverify.linux.packet_validation import (
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    Answer,
    ArpPacket,
    ArpRequest,
    EchoRequest,
    IcmpPacket,
    QuotedEcho,
    match_arp_reply,
    match_echo_reply,
    normalize_mac,
)
from netverify.results import Failure, FailureReason, Protocol, Target, VerificationResult

ETHER_HEADER = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ARP_LENGTH = 28  # Ethernet/IPv4 ARP message
IP_PROTO_ICMP = 1
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
ECHO_PAYLOAD_SIZE = 16
ECHO_TTL = 64

# OSError numbers meaning the probe cannot work at all, rather than that
# the network failed the check. They end the probe with status 3.
INFRASTRUCTURE_ERRNOS = frozenset({
    errno.EPERM, errno.EACCES,          # no CAP_NET_RAW
    errno.ENODEV, errno.ENXIO,          # no such interface
    errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT,
})

T = TypeVar("T")


class Link(TypingProtocol):
    """A layer-2 link: sends and receives whole Ethernet frames."""

    def send(self, frame: bytes) -> None: ...

    def receive(self, timeout: float) -> bytes | None:
        """One received frame, or None if none arrived within timeout."""
        ...

    def close(self) -> None: ...


class ScapyLink:
    """A Link backed by Scapy's Linux packet socket on one interface."""

    def __init__(self, interface: str, *, socket_class: Any = None) -> None:
        if socket_class is None:
            socket_class = _scapy().conf.L2socket
        # nofilter=1: never attach a capture filter (filters are compiled by
        # running tcpdump). promisc=False: receive only frames for us.
        self._socket = socket_class(iface=interface, promisc=False, nofilter=1)

    def send(self, frame: bytes) -> None:
        self._socket.send(frame)

    def receive(self, timeout: float) -> bytes | None:
        ready, _, _ = select.select([self._socket], [], [], max(timeout, 0.0))
        if not ready:
            return None
        # recv_raw() returns (None, None, None) for frames we sent ourselves.
        _, data, _ = self._socket.recv_raw()
        return data

    def close(self) -> None:
        self._socket.close()


class _NetworkFailure(Exception):
    """A network error that ends the check with a classified failure."""

    def __init__(self, failure: Failure) -> None:
        super().__init__(failure.message)
        self.failure = failure


def _attempt(stage: str, operation: Callable[..., T], *args: Any) -> T:
    """Run one socket operation; classify network errors, re-raise the rest."""
    try:
        return operation(*args)
    except OSError as exc:
        if exc.errno in INFRASTRUCTURE_ERRNOS:
            raise
        failure = classify_os_error(exc)
        raise _NetworkFailure(replace(failure, message=f"Could not {stage}: {failure.message}"))


# Scapy, loaded on first use


_SCAPY: SimpleNamespace | None = None


def _scapy() -> SimpleNamespace:
    """Import the parts of Scapy the probe uses (on first call only)."""
    global _SCAPY
    if _SCAPY is None:
        import scapy.all  # noqa: F401  (sets conf.L2socket for this platform)
        from scapy.config import conf
        from scapy.error import Scapy_Exception
        from scapy.layers.inet import ICMP, IP, IPerror, ICMPerror
        from scapy.layers.l2 import ARP as ScapyARP, Ether
        from scapy.packet import Raw
        from scapy.utils import checksum

        _SCAPY = SimpleNamespace(conf=conf, Ether=Ether, ARP=ScapyARP, IP=IP, ICMP=ICMP,
                                 IPerror=IPerror, ICMPerror=ICMPerror, Raw=Raw,
                                 checksum=checksum, Scapy_Exception=Scapy_Exception)
    return _SCAPY


@contextlib.contextmanager
def private_scapy_home() -> Iterator[str]:
    """Point Scapy's cache and config folders at a private temporary folder.

    Scapy creates cache files under XDG_CACHE_HOME (default ~/.cache) when
    imported. Under sudo, HOME is /root, which the calling user cannot
    write. The folder is removed afterwards, and the variables restored.
    """
    folder = tempfile.mkdtemp(prefix="netverify-scapy-")
    saved = {name: os.environ.get(name) for name in ("XDG_CACHE_HOME", "XDG_CONFIG_HOME")}
    os.environ["XDG_CACHE_HOME"] = os.path.join(folder, "cache")
    os.environ["XDG_CONFIG_HOME"] = os.path.join(folder, "config")
    try:
        yield folder
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        shutil.rmtree(folder, ignore_errors=True)


# Building frames


def build_arp_request(source_mac: str, source_ip: str, destination_ip: str) -> bytes:
    """A broadcast ARP request asking for destination_ip's MAC address."""
    s = _scapy()
    frame = s.Ether(src=source_mac, dst=BROADCAST_MAC, type=ETHERTYPE_ARP) / s.ARP(
        op=1, hwsrc=source_mac, psrc=source_ip, hwdst=ZERO_MAC, pdst=destination_ip
    )
    return bytes(frame)


def build_echo_request(source_mac: str, destination_mac: str, request: EchoRequest) -> bytes:
    """An Ethernet frame carrying the ICMP echo request."""
    s = _scapy()
    frame = (
        s.Ether(src=source_mac, dst=destination_mac, type=ETHERTYPE_IPV4)
        / s.IP(src=request.source, dst=request.destination, ttl=ECHO_TTL)
        / s.ICMP(type=ICMP_ECHO_REQUEST, code=0, id=request.identifier, seq=request.sequence)
        / s.Raw(load=request.payload)
    )
    return bytes(frame)


# Decoding received frames


def _dissect(layer: Any, data: bytes) -> Any:
    """Dissect data as a Scapy layer; None if Scapy cannot parse it.

    The callers check lengths and fixed header fields first; this guards
    the remaining variable parts (for example IP options) against
    malformed input.
    """
    try:
        return layer(data)
    except (struct.error, ValueError, IndexError, TypeError, _scapy().Scapy_Exception):
        return None


def _ethernet(frame: bytes) -> tuple[int, str]:
    """The EtherType and source MAC address of an Ethernet II frame.

    Read from the header bytes directly: Scapy's Ether() turns frames whose
    type field is a length (<= 1500) into IEEE 802.3 packets without a
    type field, so it is not used to classify frames.
    """
    (ethertype,) = struct.unpack("!H", frame[12:14])
    return ethertype, ":".join(f"{octet:02x}" for octet in frame[6:12])


def decode_arp(frame: bytes) -> ArpPacket | None:
    """Decode an Ethernet/IPv4 ARP frame; None for anything else or malformed."""
    if len(frame) < ETHER_HEADER + ARP_LENGTH:
        return None
    ethertype, ethernet_source = _ethernet(frame)
    if ethertype != ETHERTYPE_ARP:
        return None
    # Ethernet hardware, IPv4 protocol, 6-byte and 4-byte addresses. Checked
    # on the bytes: Scapy sizes the address fields from hwlen and plen.
    if struct.unpack("!HHBB", frame[ETHER_HEADER:ETHER_HEADER + 6]) != (1, ETHERTYPE_IPV4, 6, 4):
        return None
    arp = _dissect(_scapy().ARP, frame[ETHER_HEADER:ETHER_HEADER + ARP_LENGTH])
    if arp is None:
        return None
    try:
        return ArpPacket(operation=arp.op, sender_mac=arp.hwsrc, sender_ip=arp.psrc,
                         target_mac=arp.hwdst, target_ip=arp.pdst,
                         ethernet_source=ethernet_source)
    except (ValueError, TypeError):
        return None


def decode_icmp(frame: bytes) -> IcmpPacket | None:
    """Decode an Ethernet/IPv4 ICMP frame; None for anything else or malformed.

    The IP header, total length and ICMP checksum are checked first, and the
    ICMP message is taken from the frame by the IP total length, so
    Ethernet padding never becomes payload. Fragments are not decoded.
    """
    if len(frame) < ETHER_HEADER + 20 + 8:
        return None
    ethertype, _ = _ethernet(frame)
    version_ihl = frame[ETHER_HEADER]
    header_length = (version_ihl & 0x0F) * 4
    if ethertype != ETHERTYPE_IPV4 or version_ihl >> 4 != 4 or header_length < 20:
        return None
    if len(frame) < ETHER_HEADER + header_length + 8:
        return None
    s = _scapy()
    # Dissect the IP header alone; its fields now all come from the frame.
    ip = _dissect(s.IP, frame[ETHER_HEADER:ETHER_HEADER + header_length])
    if ip is None or ip.proto != IP_PROTO_ICMP:
        return None
    if ip.frag != 0 or ip.flags.MF:
        return None
    end = ETHER_HEADER + ip.len
    if ip.len < header_length + 8 or end > len(frame):
        return None
    message = frame[ETHER_HEADER + header_length:end]
    if s.checksum(message) != 0:
        return None

    icmp_type, icmp_code = message[0], message[1]
    identifier = sequence = None
    payload = b""
    quoted = None
    if icmp_type in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST):
        identifier, sequence = struct.unpack("!HH", message[4:8])
        payload = message[8:]
    elif icmp_type in ICMP_ERROR_TYPES:
        quoted = decode_quoted_echo(message[8:])
    try:
        return IcmpPacket(source=ip.src, destination=ip.dst, icmp_type=icmp_type,
                          icmp_code=icmp_code, identifier=identifier, sequence=sequence,
                          payload=payload, quoted=quoted)
    except (ValueError, TypeError):
        return None


def decode_quoted_echo(quote: bytes) -> QuotedEcho | None:
    """Decode the echo request quoted in an ICMP error message.

    Returns None unless the quote holds a complete IPv4 header and at least
    the first 8 bytes of an ICMP echo request (which contain its identifier
    and sequence). Truncated quotes are never filled in with defaults.
    """
    if len(quote) < 20 or quote[0] >> 4 != 4:
        return None
    header_length = (quote[0] & 0x0F) * 4
    if header_length < 20 or len(quote) < header_length + 8:
        return None
    s = _scapy()
    ip = _dissect(s.IPerror, quote[:header_length])
    if ip is None or ip.proto != IP_PROTO_ICMP:
        return None
    icmp_type, _, _, identifier, sequence = struct.unpack(
        "!BBHHH", quote[header_length:header_length + 8]
    )
    if icmp_type != ICMP_ECHO_REQUEST:
        return None
    try:
        return QuotedEcho(source=ip.src, destination=ip.dst, identifier=identifier,
                          sequence=sequence)
    except (ValueError, TypeError):
        return None


# Running checks


def run_check(
    request: ProbeRequest,
    *,
    source_mac: str,
    open_link: Callable[[str], Link],
    clock: Callable[[], float] = time.monotonic,
    identifier: int | None = None,
    payload: bytes | None = None,
) -> VerificationResult:
    """Run request's check and return its result.

    The whole check, including opening the socket, shares one deadline of
    request.timeout seconds from the first clock() reading:
        - no packet is sent once the deadline has passed (for ICMP, this
          includes the echo request after ARP resolution);
        - only frames received by the deadline can answer the request;
        - waits for frames are bounded by the time remaining.

    Opening the socket, sending and receiving are synchronous calls that
    cannot be interrupted, so one of them may still overrun the deadline.
    The check then ends as a TIMEOUT without accepting anything late, and
    duration_seconds reports the true elapsed time, which can then exceed
    request.timeout. The link is always closed.

    Raises:
        OSError: An infrastructure error (see INFRASTRUCTURE_ERRNOS).
    """
    start = clock()
    deadline = start + request.timeout
    protocol = Protocol.ICMP if request.check == ICMP_ECHO else Protocol.ARP
    try:
        link = _attempt(f"open a packet socket on {request.interface}", open_link,
                        request.interface)
        try:
            if request.check == ARP:
                failure = _check_arp(link, request, source_mac, deadline, clock)
            else:
                failure = _check_icmp_echo(link, request, source_mac, deadline, clock,
                                           identifier, payload)
        finally:
            link.close()
    except _NetworkFailure as exc:
        failure = exc.failure
    return VerificationResult(protocol, Target(request.destination), clock() - start, failure)


def _out_of_time(request: ProbeRequest, before: str) -> Failure:
    return Failure(FailureReason.TIMEOUT,
                   f"The {request.timeout:g}-second deadline passed before {before}")


def _check_arp(link: Link, request: ProbeRequest, source_mac: str, deadline: float,
               clock: Callable[[], float]) -> Failure | None:
    if clock() >= deadline:
        return _out_of_time(request, "the ARP request could be sent")
    answer, _ = _resolve(link, request, source_mac, request.expected_mac, deadline, clock)
    if answer is None:
        return Failure(FailureReason.TIMEOUT,
                       f"No ARP reply from {request.destination} within "
                       f"{request.timeout:g} seconds")
    return answer.failure


def _check_icmp_echo(link: Link, request: ProbeRequest, source_mac: str, deadline: float,
                     clock: Callable[[], float], identifier: int | None,
                     payload: bytes | None) -> Failure | None:
    if clock() >= deadline:
        return _out_of_time(request, "the ARP request could be sent")
    answer, arp_reply = _resolve(link, request, source_mac, None, deadline, clock)
    if answer is None:
        return Failure(FailureReason.TIMEOUT,
                       f"No ARP reply for {request.destination} within {request.timeout:g} "
                       "seconds, so no echo request was sent")
    if answer.failure is not None:
        return answer.failure
    assert isinstance(arp_reply, ArpPacket)
    # Resolution may have used the whole budget; the echo must not start late.
    if clock() >= deadline:
        return _out_of_time(request, f"the echo request could be sent (the ARP reply for "
                                     f"{request.destination} arrived just in time)")

    echo = EchoRequest(
        source=request.source,
        destination=request.destination,
        identifier=secrets.randbelow(0x10000) if identifier is None else identifier,
        sequence=1,
        payload=secrets.token_bytes(ECHO_PAYLOAD_SIZE) if payload is None else payload,
    )
    frame = build_echo_request(source_mac, arp_reply.sender_mac, echo)
    _attempt("send the echo request", link.send, frame)
    answer, _ = _wait(link, deadline, clock, decode_icmp,
                      lambda packet: match_echo_reply(echo, packet))
    if answer is None:
        return Failure(FailureReason.TIMEOUT,
                       f"No echo reply from {request.destination} within "
                       f"{request.timeout:g} seconds")
    return answer.failure


def _resolve(link: Link, request: ProbeRequest, source_mac: str, expected_mac: str | None,
             deadline: float, clock: Callable[[], float]) -> tuple[Answer | None, Any]:
    arp = ArpRequest(sender_mac=source_mac, sender_ip=request.source,
                     target_ip=request.destination, expected_mac=expected_mac)
    _attempt("send the ARP request", link.send,
             build_arp_request(source_mac, request.source, request.destination))
    return _wait(link, deadline, clock, decode_arp, lambda packet: match_arp_reply(arp, packet))


def _wait(link: Link, deadline: float, clock: Callable[[], float],
          decode: Callable[[bytes], Any], match: Callable[[Any], Answer | None]
          ) -> tuple[Answer | None, Any]:
    """Receive frames until one answers the request or the deadline passes.

    Each wait is bounded by the time remaining, but a receive call can still
    return late. A frame is only considered if it was received by the
    deadline, so a late answer is never reported as a timely one.
    """
    while (remaining := deadline - clock()) > 0:
        frame = _attempt("receive packets", link.receive, remaining)
        if clock() > deadline:
            return None, None  # Received after the deadline: not in time.
        if frame is None:
            continue
        packet = decode(frame)
        if packet is None:
            continue
        answer = match(packet)
        if answer is not None:
            return answer, packet
    return None, None


def interface_mac(interface: str, *, sys_root: str = "/sys/class/net") -> str:
    """The interface's MAC address, from sysfs (inside the namespace).

    Raises:
        OSError: The interface does not exist (ENOENT is reported as ENODEV).
        ValueError: The address is not a MAC address.
    """
    try:
        with open(os.path.join(sys_root, interface, "address")) as file:
            text = file.read().strip()
    except FileNotFoundError:
        raise OSError(errno.ENODEV, f"No such interface: {interface}") from None
    return normalize_mac(text)


def main(argv: Sequence[str] | None = None, *,
         open_link: Callable[[str], Link] = ScapyLink,
         source_mac: Callable[[str], str] = interface_mac) -> int:
    try:
        request = parse_arguments(sys.argv[1:] if argv is None else argv)
    except (ValueError, TypeError) as exc:
        print(f"packet_probe: invalid arguments: {exc}", file=sys.stderr)
        return 2

    try:
        with private_scapy_home():
            try:
                _scapy()
            except ImportError as exc:
                print("packet_probe: Scapy is required for packet checks "
                      f"(pip install 'netverify[packet]'): {exc}", file=sys.stderr)
                return 3
            result = run_check(request, source_mac=source_mac(request.interface),
                               open_link=open_link)
    except Exception as exc:  # The probe could not run; not a network result.
        print(f"packet_probe: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(result.to_dict()), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
