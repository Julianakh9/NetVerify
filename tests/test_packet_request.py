"""Tests for netverify.linux.packet_request: the packet probe's strict arguments.

These arguments are the only input that reaches the process run with
CAP_NET_RAW, so parsing must reject anything but the exact documented form.
"""

import math

import pytest

from netverify.linux.packet_request import (
    MAX_PROBE_TIMEOUT,
    ProbeRequest,
    build_arguments,
    parse_arguments,
)

ICMP = ["icmp-echo", "--interface", "nv0011aabbl", "--source", "10.231.0.1",
        "--destination", "10.231.0.2", "--timeout", "2.0"]
ARP = ["arp", "--interface", "nv0011aabbl", "--source", "10.231.0.1",
       "--destination", "10.231.0.2", "--timeout", "2.0", "--expected-mac", "02:00:00:00:00:02"]


def test_icmp_arguments_parse():
    assert parse_arguments(ICMP) == ProbeRequest(
        "icmp-echo", "nv0011aabbl", "10.231.0.1", "10.231.0.2", 2.0)


def test_arp_arguments_parse_and_normalize_the_mac():
    arguments = ARP[:-1] + ["02-00-00-00-00-0A"]

    assert parse_arguments(arguments).expected_mac == "02:00:00:00:00:0a"


def test_options_may_come_in_any_order_and_expected_mac_is_optional():
    shuffled = ["arp", "--timeout", "1", "--destination", "10.231.0.2",
                "--source", "10.231.0.1", "--interface", "nv0011aabbl"]

    request = parse_arguments(shuffled)

    assert request.expected_mac is None
    assert request.timeout == 1.0


@pytest.mark.parametrize("arguments", [ICMP, ARP], ids=["icmp", "arp"])
def test_build_arguments_round_trips(arguments):
    request = parse_arguments(arguments)

    assert parse_arguments(build_arguments(request)) == request
    assert build_arguments(request)[0] == arguments[0]


def test_build_arguments_is_canonical():
    request = ProbeRequest("arp", "nv0011aabbl", "10.231.0.1", "10.231.0.2", 1,
                           "02-00-00-00-00-0A")

    assert build_arguments(request) == [
        "arp", "--interface", "nv0011aabbl", "--source", "10.231.0.1",
        "--destination", "10.231.0.2", "--timeout", "1.0",
        "--expected-mac", "02:00:00:00:00:0a",
    ]


def replace_value(arguments, option, value):
    arguments = list(arguments)
    arguments[arguments.index(option) + 1] = value
    return arguments


def without(arguments, option):
    arguments = list(arguments)
    index = arguments.index(option)
    del arguments[index:index + 2]
    return arguments


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ([], "missing packet check"),
        (["ping"] + ICMP[1:], "unknown packet check"),
        (["/bin/sh", "-c", "id"], "unknown packet check"),
        (ICMP + ["--extra"], "exactly one value"),
        (ICMP + ["--verbose", "1"], "unknown option"),
        (ICMP + ["--expected-mac", "02:00:00:00:00:02"], "unknown option"),  # ARP only
        (ICMP + ["--timeout", "3"], "more than once"),
        (without(ICMP, "--timeout"), "missing option(s): --timeout"),
        (without(without(ARP, "--source"), "--interface"), "--interface, --source"),
        (["icmp-echo", "--interface=nv0011aabbl"] + ICMP[3:], "exactly one value"),
        (["icmp-echo", "--iface", "nv0011aabbl"] + ICMP[3:], "unknown option"),
        (replace_value(ICMP, "--interface", ""), "invalid interface"),
        (replace_value(ICMP, "--interface", "-i"), "invalid interface"),
        (replace_value(ICMP, "--interface", "../eth0"), "invalid interface"),
        (replace_value(ICMP, "--interface", ".."), "invalid interface"),
        (replace_value(ICMP, "--interface", "a" * 16), "invalid interface"),
        (replace_value(ICMP, "--interface", "eth0 lo"), "invalid interface"),
        (replace_value(ICMP, "--interface", "eth/0"), "invalid interface"),
        (replace_value(ICMP, "--source", "10.231.0"), "invalid IPv4"),
        (replace_value(ICMP, "--destination", "example.com"), "invalid IPv4"),
        (replace_value(ICMP, "--destination", "fe80::1"), "invalid IPv4"),
        (replace_value(ICMP, "--destination", "10.231.0.1"), "is the source address"),
        (replace_value(ICMP, "--timeout", "0"), "greater than 0"),
        (replace_value(ICMP, "--timeout", "-1"), "greater than 0"),
        (replace_value(ICMP, "--timeout", "60.000001"), "at most 60"),
        (replace_value(ICMP, "--timeout", "nan"), "greater than 0"),
        (replace_value(ICMP, "--timeout", "inf"), "greater than 0"),
        (replace_value(ICMP, "--timeout", "soon"), "invalid timeout"),
        (replace_value(ICMP, "--timeout", " 2"), "invalid timeout"),
        (replace_value(ARP, "--expected-mac", "02:00:00:00:00"), "invalid MAC"),
    ],
)
def test_invalid_arguments_are_rejected(arguments, message):
    with pytest.raises(ValueError) as error:
        parse_arguments(arguments)

    assert message in str(error.value)


@pytest.mark.parametrize("arguments", ["icmp-echo --interface x", ["icmp-echo", 1], [None]])
def test_arguments_must_be_a_list_of_strings(arguments):
    with pytest.raises(TypeError):
        parse_arguments(arguments)


@pytest.mark.parametrize("timeout", [1e-6, 0.5, 2, MAX_PROBE_TIMEOUT])
def test_timeout_boundaries_are_accepted(timeout):
    assert ProbeRequest("arp", "nv1", "10.0.0.1", "10.0.0.2", timeout).timeout == timeout


@pytest.mark.parametrize(("timeout", "error"), [
    (0, ValueError), (-0.1, ValueError), (MAX_PROBE_TIMEOUT + 0.001, ValueError),
    (math.nan, ValueError), (math.inf, ValueError), (True, TypeError), ("2", TypeError),
    (None, TypeError),
])
def test_invalid_timeouts_are_rejected(timeout, error):
    with pytest.raises(error):
        ProbeRequest("arp", "nv1", "10.0.0.1", "10.0.0.2", timeout)


def test_expected_mac_is_only_for_arp():
    with pytest.raises(ValueError, match="ARP checks only"):
        ProbeRequest("icmp-echo", "nv1", "10.0.0.1", "10.0.0.2", 1.0, "02:00:00:00:00:02")


def test_addresses_are_stored_in_canonical_form():
    request = ProbeRequest("icmp-echo", "nv1", "10.0.0.1", "10.0.0.2", 1.0)

    assert (request.source, request.destination, request.timeout) == ("10.0.0.1", "10.0.0.2", 1.0)
    assert isinstance(request.timeout, float)
