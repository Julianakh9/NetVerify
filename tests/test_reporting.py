"""Tests for text output of portless results in netverify.reporting.

Most reporting behavior is covered through the CLI in test_cli.py; these
tests cover the ICMP/ARP target formatting added for packet checks, and
confirm TCP output is unchanged.
"""

from netverify.recovery import RecoveryResult
from netverify.reporting import format_text, report
from netverify.results import Failure, FailureReason, Protocol, Target, VerificationResult

TCP_OK = VerificationResult(Protocol.TCP, Target("127.0.0.1", 8080), 0.0003)
ICMP_OK = VerificationResult(Protocol.ICMP, Target("10.231.0.2"), 0.0005)
ARP_MISMATCH = VerificationResult(
    Protocol.ARP, Target("10.231.0.2"), 0.0004,
    failure=Failure(FailureReason.HARDWARE_ADDRESS_MISMATCH,
                    "ARP reply says 10.231.0.2 is at 02:00:00:00:00:02, expected 02:00:00:00:00:01"),
)


def test_tcp_text_is_unchanged():
    assert format_text("tcp", TCP_OK) == "PASS  tcp 127.0.0.1:8080  connected in 0.3 ms"


def test_udp_text_is_unchanged():
    udp = VerificationResult(Protocol.UDP, Target("127.0.0.1", 9999), 0.0004)

    assert format_text("udp", udp) == "PASS  udp 127.0.0.1:9999  echo matched in 0.4 ms"


def test_successful_icmp_text_describes_an_echo_reply():
    assert format_text("icmp", ICMP_OK) == "PASS  icmp 10.231.0.2  echo reply received in 0.5 ms"


def test_successful_arp_text_describes_an_arp_reply():
    arp = VerificationResult(Protocol.ARP, Target("10.231.0.2"), 0.0003)

    text = format_text("arp", arp)

    assert text == "PASS  arp 10.231.0.2  ARP reply received in 0.3 ms"
    assert "echo" not in text


def test_success_text_follows_the_protocol_not_the_command_name():
    arp = VerificationResult(Protocol.ARP, Target("10.231.0.2"), 0.0003)

    assert "ARP reply received" in format_text("custom", arp)
    assert "connected" in format_text("custom", TCP_OK)


def test_portless_targets_are_shown_without_a_port():
    assert format_text("icmp", ICMP_OK).startswith("PASS  icmp 10.231.0.2  ")
    assert format_text("arp", ARP_MISMATCH) == (
        "FAIL  arp 10.231.0.2  hardware_address_mismatch: ARP reply says 10.231.0.2 is at "
        "02:00:00:00:00:02, expected 02:00:00:00:00:01 (0.4 ms)"
    )
    assert "None" not in format_text("icmp", ICMP_OK)


def test_recovery_text_names_the_checked_protocol():
    tcp = RecoveryResult((TCP_OK,), 0.1, 5.0, 0.5)
    icmp = RecoveryResult((ICMP_OK,), 0.1, 5.0, 0.5)

    assert format_text("recover", tcp).startswith("PASS  recover tcp 127.0.0.1:8080  ")
    assert format_text("recover", icmp).startswith("PASS  recover icmp 10.231.0.2  ")


def test_portless_json_report_keeps_the_envelope():
    data = report("icmp", ICMP_OK)

    assert set(data) == {"schema_version", "command", "status", "exit_code", "result"}
    assert data["schema_version"] == 1
    assert data["result"]["target"] == {"host": "10.231.0.2", "port": None}
