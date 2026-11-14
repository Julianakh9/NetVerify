"""The packet probe's request: strict parsing and building of its arguments.

The packet probe (netverify.linux.packet_probe) is the only command that
NetVerify runs with CAP_NET_RAW. VethTopology.run_packet_probe() parses
every argument list with parse_arguments() and runs only the canonical
form from build_arguments(), so nothing but these validated values can
reach the privileged process. This module is pure and imports no Scapy.

Argument list:
    icmp-echo --interface IF --source IP --destination IP --timeout S
    arp       --interface IF --source IP --destination IP --timeout S
              [--expected-mac MAC]

Each option is given exactly once, as two separate items ("--name",
"value"); abbreviations and "--name=value" forms are not accepted.
"""

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass

from netverify.linux.packet_validation import normalize_ipv4, normalize_mac

PACKET_PROBE_MODULE = "netverify.linux.packet_probe"

ICMP_ECHO = "icmp-echo"
ARP = "arp"
CHECKS = (ICMP_ECHO, ARP)

# Longest wait one probe may be asked for. Callers add process overhead.
MAX_PROBE_TIMEOUT = 60.0

# Linux interface names: at most 15 bytes. Starting with a letter or digit
# also rules out option-like values and "." / "..".
_INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")

_OPTIONS = {
    ICMP_ECHO: ("--interface", "--source", "--destination", "--timeout"),
    ARP: ("--interface", "--source", "--destination", "--timeout", "--expected-mac"),
}
_REQUIRED = ("--interface", "--source", "--destination", "--timeout")


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    """One packet check for the probe to run. Validated on creation.

    Attributes:
        check: "icmp-echo" or "arp".
        interface: The veth interface to send and receive on.
        source: This interface's IPv4 address.
        destination: The IPv4 address to check.
        timeout: The single deadline for the whole check, in seconds
            (0 < timeout <= MAX_PROBE_TIMEOUT).
        expected_mac: For "arp" only: the MAC address the reply must
            give, or None to accept any.
    """

    check: str
    interface: str
    source: str
    destination: str
    timeout: float
    expected_mac: str | None = None

    def __post_init__(self) -> None:
        if self.check not in CHECKS:
            raise ValueError(f"unknown packet check {self.check!r}; expected one of {CHECKS}")
        if not isinstance(self.interface, str) or not _INTERFACE.fullmatch(self.interface):
            raise ValueError(f"invalid interface name {self.interface!r}")
        object.__setattr__(self, "source", normalize_ipv4(self.source))
        object.__setattr__(self, "destination", normalize_ipv4(self.destination))
        if self.source == self.destination:
            raise ValueError(f"destination {self.destination} is the source address")
        object.__setattr__(self, "timeout", check_timeout(self.timeout))
        if self.expected_mac is not None:
            if self.check != ARP:
                raise ValueError("expected_mac applies to ARP checks only")
            object.__setattr__(self, "expected_mac", normalize_mac(self.expected_mac))


def check_timeout(value: float) -> float:
    """Return value as a float if it is a valid probe timeout.

    Raises:
        TypeError: value is not a number (bool is rejected).
        ValueError: value is not finite, or not in (0, MAX_PROBE_TIMEOUT].
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"timeout must be a number, got {value!r}")
    if not math.isfinite(value) or not 0 < value <= MAX_PROBE_TIMEOUT:
        raise ValueError(f"timeout must be greater than 0 and at most {MAX_PROBE_TIMEOUT:g}"
                         f" seconds, got {value!r}")
    return float(value)


def build_arguments(request: ProbeRequest) -> list[str]:
    """Return the canonical argument list for request."""
    arguments = [
        request.check,
        "--interface", request.interface,
        "--source", request.source,
        "--destination", request.destination,
        "--timeout", repr(request.timeout),
    ]
    if request.expected_mac is not None:
        arguments += ["--expected-mac", request.expected_mac]
    return arguments


def parse_arguments(arguments: Sequence[str]) -> ProbeRequest:
    """Parse a probe argument list strictly.

    Raises:
        ValueError: Unknown check or option, a repeated or missing option,
            a missing value, or an invalid value.
        TypeError: arguments is not a list of strings.
    """
    if isinstance(arguments, str) or not all(isinstance(a, str) for a in arguments):
        raise TypeError("arguments must be a sequence of strings")
    if not arguments:
        raise ValueError("missing packet check")
    check, rest = arguments[0], list(arguments[1:])
    if check not in CHECKS:
        raise ValueError(f"unknown packet check {check!r}; expected one of {CHECKS}")
    if len(rest) % 2:
        raise ValueError("every option needs exactly one value")

    values: dict[str, str] = {}
    for name, value in zip(rest[::2], rest[1::2]):
        if name not in _OPTIONS[check]:
            raise ValueError(f"unknown option {name!r} for {check}")
        if name in values:
            raise ValueError(f"option {name} given more than once")
        values[name] = value
    missing = [name for name in _REQUIRED if name not in values]
    if missing:
        raise ValueError(f"missing option(s): {', '.join(missing)}")

    timeout_text = values["--timeout"]
    if timeout_text != timeout_text.strip():
        raise ValueError(f"invalid timeout {timeout_text!r}")
    try:
        timeout = float(timeout_text)
    except ValueError:
        raise ValueError(f"invalid timeout {timeout_text!r}") from None
    return ProbeRequest(
        check=check,
        interface=values["--interface"],
        source=values["--source"],
        destination=values["--destination"],
        timeout=timeout,
        expected_mac=values.get("--expected-mac"),
    )
