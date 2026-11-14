"""Unit tests for netverify.linux.packet_validation.

Pure logic only: no Scapy, sockets, privileges or subprocesses, so these
run on every platform.
"""

import ast
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import netverify.linux.packet_validation as validation
from netverify.linux.packet_validation import (
    MAX_ECHO_PAYLOAD,
    Answer,
    ArpPacket,
    ArpRequest,
    EchoRequest,
    IcmpPacket,
    QuotedEcho,
    match_arp_reply,
    match_echo_reply,
    normalize_ipv4,
    normalize_mac,
)
from netverify.results import Failure, FailureReason

ME, PEER, OTHER = "10.231.0.1", "10.231.0.2", "10.231.0.3"
MY_MAC, PEER_MAC, OTHER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
PAYLOAD = bytes(range(16))

ECHO = EchoRequest(source=ME, destination=PEER, identifier=0x1234, sequence=1, payload=PAYLOAD)


def reply(**changes):
    """The correct echo reply to ECHO, with optional changes."""
    packet = IcmpPacket(source=PEER, destination=ME, icmp_type=0, icmp_code=0,
                        identifier=0x1234, sequence=1, payload=PAYLOAD)
    return replace(packet, **changes)


def icmp_error(icmp_type=3, icmp_code=1, *, sender=PEER, **quote_changes):
    """An ICMP error from sender quoting ECHO, with optional changes to the quote."""
    quoted = replace(QuotedEcho(source=ME, destination=PEER, identifier=0x1234, sequence=1),
                     **quote_changes)
    return IcmpPacket(source=sender, destination=ME, icmp_type=icmp_type,
                      icmp_code=icmp_code, quoted=quoted)


# Answer


def test_answer_success_follows_failure():
    assert Answer().success
    assert not Answer(Failure(FailureReason.TIMEOUT, "t")).success


# ICMP echo replies


def test_correct_echo_reply_is_a_successful_answer():
    assert match_echo_reply(ECHO, reply()) == Answer()


@pytest.mark.parametrize(
    "packet",
    [
        pytest.param(reply(identifier=0x1235), id="other-identifier"),
        pytest.param(reply(sequence=2), id="other-sequence"),
        pytest.param(reply(destination=OTHER), id="addressed-to-another-host"),
        pytest.param(reply(icmp_code=1), id="echo-reply-with-nonzero-code"),
        pytest.param(reply(identifier=None, sequence=None), id="reply-without-echo-fields"),
        # Our own outgoing request, as a packet socket sees it.
        pytest.param(IcmpPacket(source=ME, destination=PEER, icmp_type=8, icmp_code=0,
                                identifier=0x1234, sequence=1, payload=PAYLOAD),
                     id="own-echo-request"),
        # The peer pinging us with the same identifier and sequence.
        pytest.param(IcmpPacket(source=PEER, destination=ME, icmp_type=8, icmp_code=0,
                                identifier=0x1234, sequence=1, payload=PAYLOAD),
                     id="incoming-echo-request"),
        pytest.param(reply(icmp_type=13), id="timestamp-message"),
        pytest.param(reply(icmp_type=5), id="redirect"),
    ],
)
def test_unrelated_icmp_packets_are_ignored(packet):
    assert match_echo_reply(ECHO, packet) is None


def test_echo_reply_from_unexpected_sender_fails():
    answer = match_echo_reply(ECHO, reply(source=OTHER))

    assert answer.failure.reason is FailureReason.UNEXPECTED_SENDER
    assert answer.failure.message == f"Echo reply came from {OTHER}, expected {PEER}"


@pytest.mark.parametrize("payload", [b"", PAYLOAD[:-1], PAYLOAD + b"x", bytes(16)],
                         ids=["empty", "truncated", "extended", "different"])
def test_echo_reply_with_different_payload_fails(payload):
    answer = match_echo_reply(ECHO, reply(payload=payload))

    assert answer.failure.reason is FailureReason.PAYLOAD_MISMATCH
    # Lengths only: payload contents are never copied into messages.
    assert answer.failure.message == (
        f"Echo reply payload ({len(payload)} bytes) does not match the request payload (16 bytes)"
    )


def test_unexpected_sender_is_checked_before_payload():
    answer = match_echo_reply(ECHO, reply(source=OTHER, payload=b"different"))

    assert answer.failure.reason is FailureReason.UNEXPECTED_SENDER


def test_empty_payload_request_matches_empty_reply():
    request = replace(ECHO, payload=b"")

    assert match_echo_reply(request, reply(payload=b"")) == Answer()


# ICMP errors that quote the request


@pytest.mark.parametrize(
    ("icmp_type", "icmp_code", "reason"),
    [(3, 0, FailureReason.NETWORK_UNREACHABLE),
     (3, 1, FailureReason.HOST_UNREACHABLE),
     (3, 13, FailureReason.ICMP_ERROR),
     (11, 0, FailureReason.ICMP_ERROR),
     (12, 0, FailureReason.ICMP_ERROR)],
)
def test_icmp_error_quoting_the_request_is_a_classified_answer(icmp_type, icmp_code, reason):
    answer = match_echo_reply(ECHO, icmp_error(icmp_type, icmp_code))

    assert answer.failure.reason is reason
    assert answer.failure.message.endswith(f"from {PEER}")


def test_icmp_error_from_an_intermediate_router_is_still_an_answer():
    # Errors may come from any router on the path, so the sender is not checked.
    answer = match_echo_reply(ECHO, icmp_error(3, 1, sender="192.0.2.1"))

    assert answer.failure.reason is FailureReason.HOST_UNREACHABLE
    assert "from 192.0.2.1" in answer.failure.message


@pytest.mark.parametrize(
    "changes",
    [{"identifier": 0x1235}, {"sequence": 2}, {"destination": OTHER}, {"source": OTHER}],
    ids=["identifier", "sequence", "destination", "source"],
)
def test_icmp_error_quoting_another_datagram_is_ignored(changes):
    assert match_echo_reply(ECHO, icmp_error(**changes)) is None


def test_icmp_error_without_a_usable_quote_is_ignored():
    packet = IcmpPacket(source=PEER, destination=ME, icmp_type=3, icmp_code=1)

    assert match_echo_reply(ECHO, packet) is None


def test_icmp_error_addressed_to_another_host_is_ignored():
    packet = replace(icmp_error(), destination=OTHER)

    assert match_echo_reply(ECHO, packet) is None


# ARP replies

ARP = ArpRequest(sender_mac=MY_MAC, sender_ip=ME, target_ip=PEER, expected_mac=PEER_MAC)


def arp_reply(**changes):
    """The correct ARP reply to ARP, with optional changes."""
    packet = ArpPacket(operation=2, sender_mac=PEER_MAC, sender_ip=PEER,
                       target_mac=MY_MAC, target_ip=ME, ethernet_source=PEER_MAC)
    return replace(packet, **changes)


def test_correct_arp_reply_is_a_successful_answer():
    assert match_arp_reply(ARP, arp_reply()) == Answer()


def test_any_mac_is_accepted_without_an_expected_mac():
    request = replace(ARP, expected_mac=None)

    assert match_arp_reply(request, arp_reply(sender_mac=OTHER_MAC,
                                              ethernet_source=OTHER_MAC)) == Answer()


def test_reply_without_recorded_ethernet_source_is_checked_on_arp_fields():
    assert match_arp_reply(ARP, arp_reply(ethernet_source=None)) == Answer()


def test_arp_reply_with_unexpected_mac_fails():
    answer = match_arp_reply(ARP, arp_reply(sender_mac=OTHER_MAC, ethernet_source=OTHER_MAC))

    assert answer.failure.reason is FailureReason.HARDWARE_ADDRESS_MISMATCH
    assert answer.failure.message == (
        f"ARP reply says {PEER} is at {OTHER_MAC}, expected {PEER_MAC}"
    )


def test_arp_reply_whose_ethernet_and_arp_senders_disagree_fails():
    answer = match_arp_reply(ARP, arp_reply(ethernet_source=OTHER_MAC))

    assert answer.failure.reason is FailureReason.HARDWARE_ADDRESS_MISMATCH
    assert "Ethernet frame came from 02:00:00:00:00:03" in answer.failure.message


@pytest.mark.parametrize(
    "packet",
    [
        # Our own outgoing request, as a packet socket sees it.
        pytest.param(ArpPacket(operation=1, sender_mac=MY_MAC, sender_ip=ME,
                               target_mac="00:00:00:00:00:00", target_ip=PEER,
                               ethernet_source=MY_MAC), id="own-request"),
        pytest.param(arp_reply(operation=1), id="request-from-peer"),
        pytest.param(arp_reply(operation=3), id="rarp-operation"),
        pytest.param(arp_reply(sender_ip=OTHER), id="reply-about-another-address"),
        pytest.param(arp_reply(target_ip=OTHER), id="reply-to-another-ip"),
        pytest.param(arp_reply(target_mac=OTHER_MAC), id="reply-to-another-mac"),
    ],
)
def test_unrelated_arp_packets_are_ignored(packet):
    assert match_arp_reply(ARP, packet) is None


def test_mac_comparison_ignores_case_and_separator_style():
    request = replace(ARP, expected_mac="02-00-00-00-00-02")
    packet = arp_reply(sender_mac="02:00:00:00:00:02".upper(), ethernet_source="02-00-00-00-00-02")

    assert match_arp_reply(request, packet) == Answer()


# Normalization and invalid input


@pytest.mark.parametrize(("text", "expected"), [
    ("02:00:00:00:00:0A", "02:00:00:00:00:0a"),
    ("02-00-00-00-00-0a", "02:00:00:00:00:0a"),
    ("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"),
])
def test_normalize_mac(text, expected):
    assert normalize_mac(text) == expected


@pytest.mark.parametrize("text", [
    "", "02:00:00:00:00", "02:00:00:00:00:00:00", "02:00:00-00:00:00", "0200.0000.0001",
    "02:00:00:00:00:0g", "2:0:0:0:0:1", " 02:00:00:00:00:01", "02:00:00:00:00:01\n",
])
def test_invalid_mac_addresses_are_rejected(text):
    with pytest.raises(ValueError, match="invalid MAC address"):
        normalize_mac(text)


@pytest.mark.parametrize("text", ["", "10.231.0", "10.231.0.256", "010.231.0.1",
                                  "::1", "10.231.0.1/30", " 10.231.0.1", "host"])
def test_invalid_ipv4_addresses_are_rejected(text):
    with pytest.raises(ValueError, match="invalid IPv4 address"):
        normalize_ipv4(text)


@pytest.mark.parametrize("value", [None, 3232235777, b"10.0.0.1"])
def test_non_string_addresses_are_type_errors(value):
    with pytest.raises(TypeError):
        normalize_ipv4(value)
    with pytest.raises(TypeError):
        normalize_mac(value)


def test_observations_store_normalized_addresses_and_are_immutable():
    request = ArpRequest(sender_mac="02-00-00-00-00-01", sender_ip=ME, target_ip=PEER,
                         expected_mac="02:00:00:00:00:0A")

    assert (request.sender_mac, request.expected_mac) == (MY_MAC, "02:00:00:00:00:0a")
    with pytest.raises(FrozenInstanceError):
        request.target_ip = OTHER  # type: ignore[misc]


@pytest.mark.parametrize(
    ("build", "error"),
    [
        (lambda: replace(ECHO, identifier=-1), ValueError),
        (lambda: replace(ECHO, identifier=0x10000), ValueError),
        (lambda: replace(ECHO, sequence=True), TypeError),
        (lambda: replace(ECHO, sequence=1.0), TypeError),
        (lambda: replace(ECHO, payload="text"), TypeError),
        (lambda: replace(ECHO, payload=bytearray(PAYLOAD)), TypeError),
        (lambda: replace(ECHO, payload=bytes(MAX_ECHO_PAYLOAD + 1)), ValueError),
        (lambda: replace(ECHO, destination="10.231.0.999"), ValueError),
        (lambda: reply(icmp_type=256), ValueError),
        (lambda: reply(icmp_code=-1), ValueError),
        (lambda: reply(identifier=0x10000), ValueError),
        (lambda: reply(sequence="1"), TypeError),
        (lambda: reply(source="fe80::1"), ValueError),
        (lambda: replace(icmp_error(), quoted=("10.0.0.1", PEER, 1, 1)), TypeError),
        (lambda: QuotedEcho(source=ME, destination=PEER, identifier=1, sequence=-1), ValueError),
        (lambda: arp_reply(operation=0x10000), ValueError),
        (lambda: arp_reply(operation=None), TypeError),
        (lambda: arp_reply(sender_mac="not-a-mac"), ValueError),
        (lambda: arp_reply(ethernet_source="02:00:00:00:00"), ValueError),
        (lambda: replace(ARP, target_ip="10.231.0.1.5"), ValueError),
        (lambda: replace(ARP, expected_mac=""), ValueError),
    ],
)
def test_malformed_observations_are_rejected(build, error):
    with pytest.raises(error):
        build()


def test_boundary_values_are_accepted():
    request = replace(ECHO, identifier=0, sequence=0xFFFF, payload=bytes(MAX_ECHO_PAYLOAD))
    packet = reply(identifier=0, sequence=0xFFFF, payload=bytes(MAX_ECHO_PAYLOAD))

    assert match_echo_reply(request, packet) == Answer()
    assert IcmpPacket(source=PEER, destination=ME, icmp_type=255, icmp_code=255).icmp_type == 255


# Independence from I/O


def test_module_imports_nothing_that_does_io():
    tree = ast.parse(Path(validation.__file__).read_text())
    imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom) and node.module}
    from_netverify = {node.module for node in ast.walk(tree)
                      if isinstance(node, ast.ImportFrom) and node.module
                      and node.module.startswith("netverify")}

    assert imported <= {"ipaddress", "re", "dataclasses", "netverify"}
    assert from_netverify == {"netverify.diagnostics", "netverify.results"}
