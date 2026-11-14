"""Offline tests for netverify.linux.packet_probe.

Frames are built and dissected with Scapy, but nothing is sent: checks run
over a fake link with a fake clock, so these tests need no Linux, no
privileges and no real time. Real packets are tested in namespaces.
"""

import errno
import json
import os
import socket
import subprocess

import pytest
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

import netverify.linux.packet_probe as probe
from netverify.linux.packet_request import ProbeRequest
from netverify.linux.packet_validation import ArpPacket, EchoRequest, IcmpPacket, QuotedEcho
from netverify.results import FailureReason, Protocol, Target

ME, PEER, OTHER = "10.231.0.1", "10.231.0.2", "10.231.0.3"
MY_MAC, PEER_MAC, OTHER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
IFACE = "nv0011aabbl"
IDENT, PAYLOAD = 0x1234, bytes(range(16))

ICMP_REQUEST = ProbeRequest("icmp-echo", IFACE, ME, PEER, 2.0)
ARP_REQUEST = ProbeRequest("arp", IFACE, ME, PEER, 2.0, PEER_MAC)


# Frames a peer might send


def pad(frame):
    """Pad to the Ethernet minimum of 60 bytes, as real NICs do."""
    return frame + b"\x00" * max(0, 60 - len(frame))


def arp_reply_frame(*, sender_mac=PEER_MAC, sender_ip=PEER, target_mac=MY_MAC, target_ip=ME,
                    ether_src=None, op=2):
    return pad(bytes(Ether(src=ether_src or sender_mac, dst=target_mac)
                     / ARP(op=op, hwsrc=sender_mac, psrc=sender_ip, hwdst=target_mac,
                           pdst=target_ip)))


def echo_reply_frame(request_frame, *, source=PEER, payload=None, ident=None, seq=None):
    request = Ether(request_frame)
    echo = request[ICMP]
    return pad(bytes(
        Ether(src=PEER_MAC, dst=MY_MAC) / IP(src=source, dst=ME)
        / ICMP(type=0, id=echo.id if ident is None else ident,
               seq=echo.seq if seq is None else seq)
        / Raw(load=bytes(echo.payload) if payload is None else payload)
    ))


def icmp_error_frame(request_frame, *, icmp_type=3, code=1, source=PEER, quote_bytes=28):
    quote = bytes(Ether(request_frame)[IP])[:quote_bytes]
    return pad(bytes(Ether(src=PEER_MAC, dst=MY_MAC) / IP(src=source, dst=ME)
                     / ICMP(type=icmp_type, code=code) / Raw(load=quote)))


def kind(frame):
    """'arp' or 'icmp' for a frame the probe sent."""
    return "arp" if Ether(frame).haslayer(ARP) else "icmp"


# Fakes


class FakeClock:
    def __init__(self, now=100.0):
        self.now = now

    def __call__(self):
        return self.now


class FakeLink:
    """A link whose peer answers with responder(frame) -> [(delay, frame), ...].

    receive() returns queued frames after their delay, or waits out the
    whole timeout (advancing the fake clock) when nothing is due in time.
    """

    def __init__(self, clock, responder=lambda frame: [], *, fail=None, blocking=False,
                 send_delays=None):
        self.clock, self.responder, self.fail = clock, responder, fail or {}
        # blocking: receive() waits for the next queued frame even past its
        # timeout, as a synchronous call that overruns. send_delays: how long
        # sending each kind of frame takes ("arp" or "icmp").
        self.blocking, self.send_delays = blocking, send_delays or {}
        self.sent, self.queue, self.waits = [], [], []
        self.closed = False

    def send(self, frame):
        self._maybe_fail("send")
        self.clock.now += self.send_delays.get(kind(frame), 0.0)
        self.sent.append(frame)
        self.queue += [(self.clock.now + delay, reply) for delay, reply in self.responder(frame)]
        self.queue.sort(key=lambda item: item[0])

    def receive(self, timeout):
        self._maybe_fail("receive")
        assert timeout > 0
        self.waits.append(timeout)
        if self.queue and (self.blocking or self.queue[0][0] <= self.clock.now + timeout):
            due, frame = self.queue.pop(0)
            self.clock.now = max(self.clock.now, due)
            return frame
        self.clock.now += timeout
        return None

    def close(self):
        self.closed = True

    def _maybe_fail(self, stage):
        if stage in self.fail:
            raise self.fail[stage]


def healthy_peer(frame):
    if kind(frame) == "arp":
        return [(0.001, arp_reply_frame())]
    return [(0.001, echo_reply_frame(frame))]


def run(request, responder=healthy_peer, *, clock=None, fail=None, open_error=None,
        open_delay=0.0, **link_options):
    clock = clock or FakeClock()
    links = []

    def open_link(interface):
        assert interface == request.interface
        clock.now += open_delay
        if open_error is not None:
            raise open_error
        links.append(FakeLink(clock, responder, fail=fail, **link_options))
        return links[-1]

    result = probe.run_check(request, source_mac=MY_MAC, open_link=open_link, clock=clock,
                             identifier=IDENT, payload=PAYLOAD)
    return result, (links[0] if links else None)


# Building frames


def test_arp_request_frame():
    frame = Ether(probe.build_arp_request(MY_MAC, ME, PEER))

    assert (frame.src, frame.dst, frame.type) == (MY_MAC, "ff:ff:ff:ff:ff:ff", 0x0806)
    arp = frame[ARP]
    assert (arp.op, arp.hwsrc, arp.psrc, arp.hwdst, arp.pdst) == (
        1, MY_MAC, ME, "00:00:00:00:00:00", PEER)


def test_echo_request_frame_has_correct_fields_and_checksums():
    request = EchoRequest(ME, PEER, IDENT, 1, PAYLOAD)
    raw = probe.build_echo_request(MY_MAC, PEER_MAC, request)
    frame = Ether(raw)

    assert (frame.src, frame.dst, frame.type) == (MY_MAC, PEER_MAC, 0x0800)
    assert (frame[IP].src, frame[IP].dst, frame[IP].ttl, frame[IP].proto) == (ME, PEER, 64, 1)
    assert (frame[ICMP].type, frame[ICMP].code, frame[ICMP].id, frame[ICMP].seq) == (
        8, 0, IDENT, 1)
    assert bytes(frame[ICMP].payload) == PAYLOAD
    # Checksums as Scapy would compute them for a fresh packet.
    rebuilt = Ether(raw)
    del rebuilt[IP].chksum, rebuilt[ICMP].chksum
    assert bytes(rebuilt) == raw


# Decoding ARP


def test_arp_reply_is_decoded_and_normalized():
    frame = arp_reply_frame(sender_mac=PEER_MAC.upper())

    assert probe.decode_arp(frame) == ArpPacket(
        operation=2, sender_mac=PEER_MAC, sender_ip=PEER, target_mac=MY_MAC, target_ip=ME,
        ethernet_source=PEER_MAC)


@pytest.mark.parametrize(
    "frame",
    [
        pytest.param(b"", id="empty"),
        pytest.param(arp_reply_frame()[:41], id="truncated"),
        pytest.param(b"\xff" * 60, id="garbage"),
        pytest.param(pad(bytes(Ether(src=PEER_MAC, dst=MY_MAC) / IP(src=PEER, dst=ME)
                               / ICMP())), id="not-arp"),
        pytest.param(pad(bytes(Ether(src=PEER_MAC, dst=MY_MAC)
                               / ARP(op=2, hwtype=6, hwsrc=PEER_MAC, psrc=PEER))),
                     id="not-ethernet-hardware"),
        # Unpadded: the ARP header ends before its addresses.
        pytest.param(bytes(Ether(src=PEER_MAC, dst=MY_MAC, type=0x0806)
                           / Raw(load=b"\x00\x01\x08\x00\x06\x04\x00\x02")),
                     id="arp-header-without-addresses"),
        # A type field <= 1500 is an IEEE 802.3 length, not an EtherType.
        pytest.param(b"\x00" * 60, id="802.3-length-frame"),
    ],
)
def test_non_arp_or_malformed_frames_are_not_decoded_as_arp(frame):
    assert probe.decode_arp(frame) is None


def test_zero_padding_after_an_arp_header_reads_as_zero_addresses_and_matches_nothing():
    # Padding fills the address fields with zeros: a complete, if useless,
    # ARP message. It decodes, and no request would ever match it.
    frame = pad(bytes(Ether(src=PEER_MAC, dst=MY_MAC, type=0x0806)
                      / Raw(load=b"\x00\x01\x08\x00\x06\x04\x00\x02")))

    packet = probe.decode_arp(frame)

    assert (packet.sender_ip, packet.target_ip) == ("0.0.0.0", "0.0.0.0")


# Decoding ICMP


def echo_request_frame():
    return probe.build_echo_request(MY_MAC, PEER_MAC, EchoRequest(ME, PEER, IDENT, 1, PAYLOAD))


def test_echo_reply_is_decoded_without_ethernet_padding():
    frame = echo_reply_frame(echo_request_frame(), payload=b"ab")
    assert len(frame) == 60  # 14 + 20 + 8 + 2 bytes, padded

    assert probe.decode_icmp(frame) == IcmpPacket(
        source=PEER, destination=ME, icmp_type=0, icmp_code=0, identifier=IDENT, sequence=1,
        payload=b"ab")


def test_ip_options_are_skipped_using_the_header_length():
    from scapy.layers.inet import IPOption_NOP
    frame = bytes(Ether(src=PEER_MAC, dst=MY_MAC)
                  / IP(src=PEER, dst=ME, options=[IPOption_NOP()] * 4)
                  / ICMP(type=0, id=IDENT, seq=1) / Raw(load=PAYLOAD))

    packet = probe.decode_icmp(frame)

    assert packet.identifier == IDENT and packet.payload == PAYLOAD


def test_icmp_error_with_a_complete_quote_is_decoded():
    packet = probe.decode_icmp(icmp_error_frame(echo_request_frame(), icmp_type=3, code=1))

    assert (packet.icmp_type, packet.icmp_code) == (3, 1)
    assert packet.quoted == QuotedEcho(source=ME, destination=PEER, identifier=IDENT, sequence=1)


@pytest.mark.parametrize("quote_bytes", [0, 19, 20, 27])
def test_truncated_quotes_are_not_filled_with_defaults(quote_bytes):
    packet = probe.decode_icmp(icmp_error_frame(echo_request_frame(), quote_bytes=quote_bytes))

    assert packet is not None and packet.icmp_type == 3
    assert packet.quoted is None


def test_quote_of_a_non_echo_datagram_is_not_an_echo_quote():
    udp = bytes(IP(src=ME, dst=PEER) / UDP(sport=1, dport=2) / Raw(load=b"12345678"))
    frame = pad(bytes(Ether(src=PEER_MAC, dst=MY_MAC) / IP(src=PEER, dst=ME)
                      / ICMP(type=3, code=3) / Raw(load=udp)))

    assert probe.decode_icmp(frame).quoted is None


def test_quote_with_an_invalid_ip_header_is_not_an_echo_quote():
    quote = bytearray(bytes(Ether(echo_request_frame())[IP])[:28])
    quote[0] = 0x44  # version 4, header length 16 bytes: impossible
    frame = pad(bytes(Ether(src=PEER_MAC, dst=MY_MAC) / IP(src=PEER, dst=ME)
                      / ICMP(type=3, code=1) / Raw(load=bytes(quote))))

    assert probe.decode_icmp(frame).quoted is None


def corrupt(frame, offset):
    frame = bytearray(frame)
    frame[offset] ^= 0xFF
    return bytes(frame)


def fragment(flags, frag):
    return bytes(Ether(src=PEER_MAC, dst=MY_MAC) / IP(src=PEER, dst=ME, flags=flags, frag=frag)
                 / ICMP(type=0, id=IDENT, seq=1) / Raw(load=PAYLOAD))


@pytest.mark.parametrize(
    "frame",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x00" * 41, id="too-short"),
        pytest.param(arp_reply_frame(), id="arp-frame"),
        pytest.param(corrupt(echo_reply_frame(echo_request_frame()), 14 + 20 + 8),
                     id="bad-icmp-checksum"),
        pytest.param(echo_reply_frame(echo_request_frame(), payload=bytes(64))[:80],
                     id="ip-length-beyond-frame"),
        pytest.param(fragment("MF", 0), id="first-fragment"),
        pytest.param(fragment(0, 8), id="later-fragment"),
        pytest.param(pad(bytes(Ether(src=PEER_MAC, dst=MY_MAC) / IP(src=PEER, dst=ME)
                               / UDP() / Raw(load=PAYLOAD))), id="udp"),
        pytest.param(b"\xff" * 64, id="garbage"),
    ],
)
def test_non_icmp_or_malformed_frames_are_not_decoded_as_icmp(frame):
    assert probe.decode_icmp(frame) is None


def test_decoders_never_raise_on_arbitrary_bytes():
    frames = [bytes([i]) * n for i in (0, 1, 0x45, 0xFF) for n in (0, 14, 42, 60, 100)]
    frames += [arp_reply_frame()[:n] for n in range(0, 61)]
    frames += [echo_reply_frame(echo_request_frame())[:n] for n in range(0, 61)]
    frames += [icmp_error_frame(echo_request_frame())[:n] for n in range(0, 71)]
    # Every single-byte corruption of a valid ARP, echo and error frame.
    for valid in (arp_reply_frame(), echo_reply_frame(echo_request_frame()),
                  icmp_error_frame(echo_request_frame())):
        frames += [corrupt(valid, offset) for offset in range(len(valid))]

    for frame in frames:
        probe.decode_arp(frame)
        probe.decode_icmp(frame)


# ARP checks


def test_arp_check_passes_with_the_expected_mac():
    result, link = run(ARP_REQUEST)

    assert result.success
    assert (result.protocol, result.target) == (Protocol.ARP, Target(PEER))
    assert result.duration_seconds == pytest.approx(0.001)
    assert [kind(frame) for frame in link.sent] == ["arp"]
    assert link.closed


def test_arp_check_reports_an_unexpected_mac():
    result, _ = run(ARP_REQUEST, lambda frame: [(0.001, arp_reply_frame(
        sender_mac=OTHER_MAC))])

    assert result.reason is FailureReason.HARDWARE_ADDRESS_MISMATCH


def test_arp_check_ignores_unrelated_frames_before_the_reply():
    def noisy_peer(frame):
        return [(0.001, b"\xff" * 60),
                (0.002, arp_reply_frame(sender_ip=OTHER, sender_mac=OTHER_MAC)),
                (0.003, arp_reply_frame(op=1)),
                (0.004, echo_reply_frame(echo_request_frame())),
                (0.005, arp_reply_frame())]

    result, _ = run(ARP_REQUEST, noisy_peer)

    assert result.success
    assert result.duration_seconds == pytest.approx(0.005)


def test_arp_check_times_out_at_the_deadline():
    result, link = run(ARP_REQUEST, lambda frame: [])

    assert result.reason is FailureReason.TIMEOUT
    assert result.failure.message == f"No ARP reply from {PEER} within 2 seconds"
    assert result.duration_seconds == pytest.approx(2.0)
    assert link.closed


def test_reply_after_the_deadline_is_not_accepted():
    result, _ = run(ARP_REQUEST, lambda frame: [(2.5, arp_reply_frame())])

    assert result.reason is FailureReason.TIMEOUT


# ICMP echo checks


def test_icmp_check_resolves_with_arp_then_sends_the_echo_at_layer_2():
    result, link = run(ICMP_REQUEST)

    assert result.success
    assert (result.protocol, result.target) == (Protocol.ICMP, Target(PEER))
    assert [kind(frame) for frame in link.sent] == ["arp", "icmp"]
    echo = Ether(link.sent[1])
    assert echo.dst == PEER_MAC  # the address learned from the ARP reply
    assert (echo[ICMP].id, bytes(echo[ICMP].payload)) == (IDENT, PAYLOAD)
    assert link.closed


def test_icmp_check_without_an_arp_reply_sends_no_echo_request():
    result, link = run(ICMP_REQUEST, lambda frame: [])

    assert result.reason is FailureReason.TIMEOUT
    assert "so no echo request was sent" in result.failure.message
    assert [kind(frame) for frame in link.sent] == ["arp"]


def test_arp_resolution_and_echo_share_one_deadline():
    # ARP is answered after 1.5 s; the echo reply would take 1 s more, so
    # it misses the 2 s deadline. No step may wait beyond what is left.
    def slow_peer(frame):
        return [(1.5, arp_reply_frame())] if kind(frame) == "arp" else [
            (1.0, echo_reply_frame(frame))]

    clock = FakeClock()
    result, link = run(ICMP_REQUEST, slow_peer, clock=clock)

    assert result.reason is FailureReason.TIMEOUT
    assert result.failure.message == f"No echo reply from {PEER} within 2 seconds"
    assert result.duration_seconds == pytest.approx(2.0)
    assert link.waits[-1] == pytest.approx(0.5)
    assert clock.now == pytest.approx(102.0)


def test_inconsistent_arp_reply_fails_before_any_echo_request():
    result, link = run(ICMP_REQUEST, lambda frame: [(0.001, arp_reply_frame(
        ether_src=OTHER_MAC))])

    assert result.reason is FailureReason.HARDWARE_ADDRESS_MISMATCH
    assert [kind(frame) for frame in link.sent] == ["arp"]


@pytest.mark.parametrize(
    ("echo_reply", "reason"),
    [
        (lambda frame: echo_reply_frame(frame, source=OTHER), FailureReason.UNEXPECTED_SENDER),
        (lambda frame: echo_reply_frame(frame, payload=b"different"),
         FailureReason.PAYLOAD_MISMATCH),
        (lambda frame: icmp_error_frame(frame, icmp_type=3, code=1),
         FailureReason.HOST_UNREACHABLE),
        (lambda frame: icmp_error_frame(frame, icmp_type=11, code=0), FailureReason.ICMP_ERROR),
    ],
    ids=["unexpected-sender", "payload-mismatch", "host-unreachable", "time-exceeded"],
)
def test_icmp_check_classifies_wrong_answers(echo_reply, reason):
    def peer(frame):
        return [(0.001, arp_reply_frame())] if kind(frame) == "arp" else [
            (0.001, echo_reply(frame))]

    result, _ = run(ICMP_REQUEST, peer)

    assert result.reason is reason


def test_icmp_check_ignores_replies_to_other_requests():
    def peer(frame):
        if kind(frame) == "arp":
            return [(0.001, arp_reply_frame())]
        return [(0.001, echo_reply_frame(frame, ident=IDENT + 1)),
                (0.002, echo_reply_frame(frame, seq=2)),
                (0.003, icmp_error_frame(frame, quote_bytes=24)),  # truncated quote
                (0.004, echo_reply_frame(frame))]

    result, _ = run(ICMP_REQUEST, peer)

    assert result.success
    assert result.duration_seconds == pytest.approx(0.005)



# The shared deadline: nothing sent after it, nothing accepted after it


def test_reply_received_after_the_deadline_is_not_a_timely_success():
    # The receive call overruns: the reply is only observed at 2.3 s.
    result, link = run(ARP_REQUEST, lambda frame: [(2.3, arp_reply_frame())], blocking=True)

    assert result.reason is FailureReason.TIMEOUT
    assert result.duration_seconds == pytest.approx(2.3)  # the true elapsed time
    assert link.closed


def test_reply_received_exactly_at_the_deadline_is_accepted():
    result, _ = run(ARP_REQUEST, lambda frame: [(2.0, arp_reply_frame())], blocking=True)

    assert result.success
    assert result.duration_seconds == pytest.approx(2.0)


def test_late_arp_reply_sends_no_echo_request():
    result, link = run(ICMP_REQUEST, lambda frame: [(2.4, arp_reply_frame())], blocking=True)

    assert result.reason is FailureReason.TIMEOUT
    assert "so no echo request was sent" in result.failure.message
    assert [kind(frame) for frame in link.sent] == ["arp"]
    assert result.duration_seconds == pytest.approx(2.4)


def test_arp_reply_at_the_deadline_leaves_no_time_to_send_the_echo():
    result, link = run(ICMP_REQUEST, lambda frame: [(2.0, arp_reply_frame())], blocking=True)

    assert result.reason is FailureReason.TIMEOUT
    assert result.failure.message == (
        "The 2-second deadline passed before the echo request could be sent "
        f"(the ARP reply for {PEER} arrived just in time)")
    assert [kind(frame) for frame in link.sent] == ["arp"]


def test_slow_socket_open_leaves_no_time_to_send_anything():
    result, link = run(ICMP_REQUEST, open_delay=2.5)

    assert result.reason is FailureReason.TIMEOUT
    assert result.failure.message == (
        "The 2-second deadline passed before the ARP request could be sent")
    assert link.sent == [] and link.closed
    assert result.duration_seconds == pytest.approx(2.5)


def test_arp_check_after_a_slow_socket_open_sends_nothing():
    result, link = run(ARP_REQUEST, open_delay=2.0)

    assert result.reason is FailureReason.TIMEOUT
    assert link.sent == [] and link.waits == []


def test_send_that_overruns_the_deadline_accepts_no_reply():
    # Sending the ARP request takes 3 s; the reply is already queued, but
    # the deadline has passed, so nothing is received or accepted.
    result, link = run(ARP_REQUEST, send_delays={"arp": 3.0})

    assert result.reason is FailureReason.TIMEOUT
    assert link.waits == []
    assert result.duration_seconds == pytest.approx(3.0)
    assert link.closed


def test_slow_echo_send_cannot_turn_a_late_reply_into_success():
    result, link = run(ICMP_REQUEST, send_delays={"icmp": 1.999}, blocking=True)

    # ARP is answered at 0.001 s; sending the echo ends exactly at the 2 s
    # deadline, so no time is left to wait for its reply (due at 2.001 s).
    assert result.reason is FailureReason.TIMEOUT
    assert [kind(frame) for frame in link.sent] == ["arp", "icmp"]
    assert len(link.waits) == 1  # only the ARP wait; none after the echo
    assert result.duration_seconds == pytest.approx(2.0)


def test_every_wait_is_bounded_by_the_time_remaining():
    clock = FakeClock()
    result, link = run(ICMP_REQUEST, lambda frame: [(0.7, arp_reply_frame())]
                       if kind(frame) == "arp" else [], clock=clock)

    assert result.reason is FailureReason.TIMEOUT
    assert link.waits[0] == pytest.approx(2.0)
    assert link.waits[-1] == pytest.approx(1.3)  # what is left after ARP took 0.7 s
    assert clock.now == pytest.approx(102.0)


# Socket errors


DOWN = OSError(errno.ENETDOWN, "Network is down")


def test_network_error_when_opening_the_socket_is_a_classified_failure():
    result, link = run(ICMP_REQUEST, open_error=DOWN)

    assert link is None  # nothing was opened, so nothing to close or send
    assert result.reason is FailureReason.NETWORK_UNREACHABLE
    # The OSError's own text, as classify_os_error reports it elsewhere.
    assert result.failure.message == (
        f"Could not open a packet socket on {IFACE}: [Errno {errno.ENETDOWN}] Network is down")
    assert result.failure.error_code == errno.ENETDOWN
    assert result.target == Target(PEER)


@pytest.mark.parametrize(("stage", "message"), [
    ("send", "Could not send the ARP request"),
    ("receive", "Could not receive packets"),
])
def test_network_errors_while_sending_or_receiving_are_classified(stage, message):
    result, link = run(ARP_REQUEST, fail={stage: OSError(errno.ENETUNREACH,
                                                         "Network is unreachable")})

    assert result.reason is FailureReason.NETWORK_UNREACHABLE
    assert result.failure.message.startswith(message)
    assert link.closed


@pytest.mark.parametrize("request_", [ARP_REQUEST, ICMP_REQUEST], ids=["arp", "icmp"])
def test_enobufs_when_sending_is_a_socket_error_not_a_timeout(request_):
    # Seen on Linux when the peer's link is down and the kernel already
    # drops the source's frames: the send fails at once with ENOBUFS.
    # It stays a classified socket error, distinct from TIMEOUT.
    result, link = run(request_, fail={"send": OSError(errno.ENOBUFS,
                                                       "No buffer space available")})

    assert result.reason is FailureReason.SOCKET_ERROR
    assert result.failure.error_code == errno.ENOBUFS
    assert result.failure.exception_type == "OSError"
    assert result.failure.message == (
        f"Could not send the ARP request: [Errno {errno.ENOBUFS}] No buffer space available")
    assert link.sent == [] and link.waits == []  # nothing sent, no waiting
    assert result.duration_seconds == pytest.approx(0.0)
    assert link.closed


@pytest.mark.parametrize("error", [
    PermissionError(errno.EPERM, "Operation not permitted"),
    OSError(errno.ENODEV, "No such device"),
], ids=["no-capability", "no-interface"])
def test_infrastructure_errors_are_raised_not_reported_as_results(error):
    with pytest.raises(OSError) as raised:
        run(ARP_REQUEST, open_error=error)

    assert raised.value is error


def test_infrastructure_error_after_opening_still_closes_the_link():
    links = []

    def open_link(interface):
        links.append(FakeLink(FakeClock(), fail={"send": PermissionError(errno.EPERM, "no")}))
        return links[-1]

    with pytest.raises(PermissionError):
        probe.run_check(ARP_REQUEST, source_mac=MY_MAC, open_link=open_link, clock=FakeClock())

    assert links[0].closed


def test_unexpected_exceptions_close_the_link():
    links = []

    def open_link(interface):
        links.append(FakeLink(FakeClock(), fail={"receive": RuntimeError("bug")}))
        return links[-1]

    with pytest.raises(RuntimeError):
        probe.run_check(ARP_REQUEST, source_mac=MY_MAC, open_link=open_link, clock=FakeClock())

    assert links[0].closed


def test_checks_start_no_subprocesses(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError(f"subprocess started: {args}")

    monkeypatch.setattr(subprocess.Popen, "__init__", forbidden)

    assert run(ICMP_REQUEST)[0].success
    assert run(ARP_REQUEST)[0].success


# The Scapy socket wrapper


class RecordingSocket:
    """Stands in for Scapy's L2Socket; readable when its peer socket writes."""

    created = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.local, self.remote = socket.socketpair()
        self.sent, self.closed, self.next = [], False, (None, None, None)
        RecordingSocket.created.append(self)

    def fileno(self):
        return self.local.fileno()

    def send(self, frame):
        self.sent.append(frame)

    def recv_raw(self):
        self.local.recv(1)
        return self.next

    def close(self):
        self.closed = True
        self.local.close()
        self.remote.close()


def test_scapy_link_never_attaches_a_capture_filter():
    link = probe.ScapyLink(IFACE, socket_class=RecordingSocket)

    assert RecordingSocket.created[-1].kwargs == {"iface": IFACE, "promisc": False,
                                                  "nofilter": 1}
    link.close()


def test_scapy_link_sends_receives_and_closes():
    link = probe.ScapyLink(IFACE, socket_class=RecordingSocket)
    sock = RecordingSocket.created[-1]

    link.send(b"frame")
    assert sock.sent == [b"frame"]
    assert link.receive(0.01) is None          # nothing readable: select times out

    sock.remote.send(b"x")
    sock.next = (Ether, b"data", 0.0)
    assert link.receive(1.0) == b"data"

    sock.remote.send(b"x")
    sock.next = (None, None, None)             # our own outgoing frame
    assert link.receive(1.0) is None

    link.close()
    assert sock.closed


# Running as a process: main()


def test_main_prints_one_result_and_uses_a_private_scapy_home(monkeypatch, capsys):
    seen = {}
    monkeypatch.setenv("XDG_CACHE_HOME", "/original/cache")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    def open_link(interface):
        seen["cache"] = os.environ["XDG_CACHE_HOME"]
        seen["config"] = os.environ["XDG_CONFIG_HOME"]
        seen["folder_exists"] = os.path.isdir(os.path.dirname(seen["cache"]))
        return FakeLink(FakeClock(), healthy_peer)

    code = probe.main(["arp", "--interface", IFACE, "--source", ME, "--destination", PEER,
                       "--timeout", "2", "--expected-mac", PEER_MAC],
                      open_link=open_link, source_mac=lambda interface: MY_MAC)
    out, err = capsys.readouterr()

    assert code == 0 and err == ""
    result = json.loads(out)
    assert result["protocol"] == "arp" and result["success"] is True
    assert result["target"] == {"host": PEER, "port": None}
    folder = os.path.dirname(seen["cache"])
    assert os.path.basename(folder).startswith("netverify-scapy-")
    assert seen["config"] == os.path.join(folder, "config") and seen["folder_exists"]
    assert not os.path.exists(folder)                          # removed afterwards
    assert os.environ["XDG_CACHE_HOME"] == "/original/cache"   # restored
    assert "XDG_CONFIG_HOME" not in os.environ


def test_main_rejects_invalid_arguments_with_status_2(capsys):
    assert probe.main(["arp", "--interface", "-x"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and "invalid arguments" in err


@pytest.mark.parametrize(
    ("open_link", "source_mac", "message"),
    [
        (lambda i: (_ for _ in ()).throw(PermissionError(errno.EPERM, "Operation not permitted")),
         lambda i: MY_MAC, "PermissionError"),
        (None, lambda i: (_ for _ in ()).throw(OSError(errno.ENODEV, "No such interface")),
         "No such interface"),
    ],
    ids=["no-capability", "no-interface"],
)
def test_main_reports_infrastructure_errors_with_status_3(capsys, open_link, source_mac, message):
    code = probe.main(["icmp-echo", "--interface", IFACE, "--source", ME, "--destination", PEER,
                       "--timeout", "1"], open_link=open_link, source_mac=source_mac)
    out, err = capsys.readouterr()

    assert code == 3
    assert out == ""  # no result: this is not a verification outcome
    assert message in err


def test_main_explains_missing_scapy(monkeypatch, capsys):
    def no_scapy():
        raise ModuleNotFoundError("No module named 'scapy'")

    monkeypatch.setattr(probe, "_scapy", no_scapy)

    code = probe.main(["arp", "--interface", IFACE, "--source", ME, "--destination", PEER,
                       "--timeout", "1"], source_mac=lambda i: MY_MAC)

    assert code == 3
    assert "pip install 'netverify[packet]'" in capsys.readouterr().err


def test_private_scapy_home_is_removed_even_after_an_error():
    with pytest.raises(RuntimeError):
        with probe.private_scapy_home() as folder:
            assert os.path.isdir(folder)
            raise RuntimeError("boom")

    assert not os.path.exists(folder)


# Interface MAC address from sysfs


def test_interface_mac_reads_sysfs(tmp_path):
    (tmp_path / IFACE).mkdir()
    (tmp_path / IFACE / "address").write_text("02:00:00:00:00:0A\n")

    assert probe.interface_mac(IFACE, sys_root=str(tmp_path)) == "02:00:00:00:00:0a"


def test_missing_interface_is_reported_as_enodev(tmp_path):
    with pytest.raises(OSError) as error:
        probe.interface_mac(IFACE, sys_root=str(tmp_path))

    assert error.value.errno == errno.ENODEV


def test_interface_without_a_mac_address_is_rejected(tmp_path):
    (tmp_path / IFACE).mkdir()
    (tmp_path / IFACE / "address").write_text("\n")

    with pytest.raises(ValueError):
        probe.interface_mac(IFACE, sys_root=str(tmp_path))
