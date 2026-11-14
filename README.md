# NetVerify

[![Tests](https://github.com/Julianakh9/NetVerify/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/Julianakh9/NetVerify/actions/workflows/tests.yml)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

NetVerify is a Python network verification and automated testing framework.
It checks whether TCP services accept connections and UDP echo services
answer correctly. Each outcome comes back as a structured, classified result
rather than a bare `True` or `False`. It can also poll a service until it
recovers. On Linux, it builds disposable network namespaces and injects
reversible link faults, so recovery behaviour can be tested without touching
the host network. Inside those namespaces it can also verify ICMP echo and
ARP at the packet level.

The core has no runtime dependencies beyond the Python standard library, and
it can be used as a Python library or as the `netverify` command. The packet
checks are optional: they need [Scapy](https://scapy.net/), installed with the
`packet` extra (see [Installation](#installation)).

### Intended use cases

- **Scripts and CI steps** that must know whether a service is reachable,
  using documented exit codes and one-line JSON reports.
- **Readiness and recovery checks:** waiting, within a bounded deadline, for
  a service to accept connections after a restart or deployment.
- **Diagnosing connection failures,** with the cause classified as refused,
  timed out, unreachable, DNS failure, wrong UDP sender or payload mismatch.
- **Testing network failure handling on Linux:** take a virtual link down,
  check that connections fail, restore it and check that they recover, all
  inside isolated namespaces.
- **Packet-level checks on Linux:** confirm that an address answers ICMP
  echo, or ARP with the expected MAC address, across NetVerify's own test
  link, and how each fails when the link is down.

It is a verification tool, not a monitoring service. It runs one check (or
one bounded recovery poll) per call and keeps no history.

### Architecture

| Module | Responsibility |
|---|---|
| `netverify.tcp`, `netverify.udp` | The checks. Detailed (`verify_*`) and Boolean (`check_*`) APIs. |
| `netverify.results` | The immutable result model: `VerificationResult`, `Target`, `Failure`, `FailureReason` |
| `netverify.diagnostics` | Classifies socket errors into a `FailureReason` |
| `netverify.recovery` | `wait_for_recovery()` and `RecoveryResult`: bounded polling of any check |
| `netverify.reporting` | JSON report envelope, exit codes, text formatting, payload redaction |
| `netverify.cli` | The `netverify` command: parses arguments, calls the APIs above, reports |
| `netverify.linux` | Linux only: namespace topologies, in-namespace TCP checks, fault injection |
| `netverify.linux.packet` | Linux only: ICMP echo and ARP checks (`verify_icmp_echo_in_namespace`, `verify_arp_in_namespace`) |
| `netverify.linux.packet_probe` | The packet probe process: the only module that uses Scapy |
| `netverify.linux.packet_request`, `netverify.linux.packet_validation` | Pure logic: the probe's strictly parsed arguments, and reply matching |

The checks, result model and recovery logic do not import `netverify.linux`,
and the CLI adds no networking of its own: every command calls the same
public functions a Python user would. Scapy is imported only inside the
packet probe process, when a packet check runs; everything else, including
`import netverify.linux`, works without it.

## Goals

- Apply object-oriented programming principles in Python
- Build reusable software components
- Develop automated tests with pytest
- Strengthen practical networking knowledge
- Practice systematic debugging

## Features

### Implemented

- **TCP connectivity check:** can a TCP connection to `host:port` be established?
- **UDP echo verification:** does a UDP echo service return exactly the payload it was sent?
- **Structured results:** each check can return a `VerificationResult` describing the target, the outcome, a classified failure reason and the duration.
- **Boolean APIs:** the original `True`/`False` functions still work as before.
- **Command-line interface:** `netverify tcp`, `netverify udp` and
  `netverify recover`, with text or JSON output and documented exit codes
  (see [Command-Line Interface](#command-line-interface)).
- **Linux network namespace topologies:** two temporary, isolated network
  namespaces joined by a virtual Ethernet (veth) link, with TCP checks run
  from inside a namespace (Linux only; see
  [Linux Network Namespaces](#linux-network-namespaces)).
- **Recovery monitoring:** poll a check until it succeeds or a deadline
  passes, and record every attempt (see
  [Recovery Monitoring](#recovery-monitoring)).
- **Reversible fault injection:** take a topology's virtual link down for
  the duration of a `with` block, and restore it afterwards (Linux only; see
  [Reversible Fault Injection](#reversible-fault-injection)).
- **ICMP echo and ARP verification:** packet-level checks between a
  topology's namespaces, run as the calling user with only `CAP_NET_RAW`
  (Linux only, optional Scapy dependency; see
  [Packet-Level Verification](#packet-level-verification-icmp-and-arp)).

### Possible future work

Not implemented:

- More advanced network verification scenarios
- IPv6 support (including ICMPv6 and neighbour discovery)
- Configurable retries for UDP checks
- Packet checks from the command line, or against hosts outside a
  NetVerify topology

## Installation

Requirements:

- Python 3.11 or newer (tested with 3.11, 3.12 and 3.13).
- No third-party runtime dependencies for the core.
- For the Linux namespace features only: see
  [Requirements](#requirements) under Linux Network Namespaces.
- For the packet checks only: the optional `packet` extra, which installs
  Scapy 2.6.1 (GPL-2.0-only; see [Third-party licenses](#third-party-licenses)),
  plus the [packet prerequisites](#packet-check-requirements).

NetVerify is not published on PyPI; it is installed from the GitHub
repository.

### v0.1.0: the latest published release

```bash
python3 -m venv .venv
.venv/bin/python -m pip install "git+https://github.com/Julianakh9/NetVerify.git@v0.1.0"
.venv/bin/netverify --version     # netverify 0.1.0
```

v0.1.0 does not include the packet checks and has no `packet` extra.

### v0.2.0: release candidate (not yet published)

v0.2.0 adds the ICMP and ARP packet checks. It is a release candidate: it
has not been tagged or published, and it is available only from the
`feature/m7-scapy-packet-verification` branch. To try it from a clone:

```bash
git clone --branch feature/m7-scapy-packet-verification https://github.com/Julianakh9/NetVerify.git
cd NetVerify
python3 -m venv .venv
.venv/bin/python -m pip install .              # core only, without Scapy
.venv/bin/python -m pip install ".[packet]"    # or: with Scapy 2.6.1, for packet checks
.venv/bin/netverify --version                  # netverify 0.2.0
```

Both forms install the `netverify` package and the `netverify` command.
The `packet` extra also installs Scapy, pinned to 2.6.1, the only version
NetVerify has been tested with; Scapy is installed from its own
distribution and is not part of NetVerify (see
[Third-party licenses](#third-party-licenses)). Without the extra,
everything else works unchanged, and a packet check fails with a message
naming the extra to install.

For development, with pytest and an editable install, see [Setup](#setup).

## Usage

### Detailed APIs

```python
from netverify.tcp import verify_tcp_connection
from netverify.udp import verify_udp_echo
from netverify.results import FailureReason

result = verify_tcp_connection("127.0.0.1", 8080, timeout=2.0)

if result.success:
    print(f"Connected in {result.duration_seconds:.3f}s")
else:
    print(result.reason)            # e.g. FailureReason.CONNECTION_REFUSED
    print(result.failure.message)   # e.g. "[Errno 61] Connection refused"

result = verify_udp_echo("127.0.0.1", 9999, payload=b"netverify-ping", timeout=2.0)
if result.reason is FailureReason.PAYLOAD_MISMATCH:
    print(result.failure.message)
```

| Function | Returns |
|---|---|
| `verify_tcp_connection(host, port, timeout=2.0)` | `VerificationResult` |
| `verify_udp_echo(host, port, payload=b"netverify-ping", timeout=2.0)` | `VerificationResult` |

### Boolean APIs (backward compatible)

```python
from netverify.tcp import check_tcp_connection
from netverify.udp import check_udp_echo

check_tcp_connection("127.0.0.1", 8080, timeout=2.0)  # True or False
check_udp_echo("127.0.0.1", 9999, timeout=2.0)        # True or False
```

Each Boolean function returns `verify_*(...).success` from its detailed
counterpart, so both share one networking implementation. Signatures and
results are unchanged from earlier versions.

### Behavior shared by all checks

- `timeout` is the socket timeout in seconds for each blocking socket
  operation. It is not a strict deadline for the entire function.
- Only `OSError` failures are turned into failed results (or `False`). Any
  other exception, such as a programming error, reaches the caller.
- Sockets are always closed.

## Command-Line Interface

Installing NetVerify (see [Setup](#setup)) also installs a `netverify`
command. `python -m netverify` works the same way.

| Command | Checks |
|---|---|
| `netverify tcp HOST PORT` | A TCP connection can be established |
| `netverify udp HOST PORT` | A UDP echo service returns exactly the payload sent |
| `netverify recover HOST PORT --deadline S` | Polls a TCP connection until it succeeds or the deadline passes |

| Option | Commands | Default |
|---|---|---|
| `--format {text,json}` | all | `text` |
| `--timeout S` | all (for `recover`: the largest timeout for one attempt) | `2.0` |
| `--debug` | all: also print the full traceback of an unexpected error to standard error (the exit code stays `3`) | off |
| `--payload TEXT` | `udp`: text to send, UTF-8 encoded, 1–65507 bytes | `netverify-ping` |
| `--show-payload` | `udp`: include payload contents in mismatch reports | off |
| `--deadline S` | `recover` (required): seconds within which attempts may start | — |
| `--interval S` | `recover`: seconds between attempts | `0.5` |

Durations (`--timeout`, `--deadline`, `--interval`) must be greater than 0
and at most 86400 seconds (one day). Anything else, including `nan`, `inf`
and huge values such as `1e300`, is invalid input (exit code `2`).

`netverify --help` and `netverify COMMAND --help` describe every option.
The commands call the same functions as the Python API
(`verify_tcp_connection`, `verify_udp_echo`, `wait_for_recovery`), so results
and their meaning are identical.

### Examples

```console
$ netverify tcp 127.0.0.1 8080
PASS  tcp 127.0.0.1:8080  connected in 0.3 ms

$ netverify tcp 127.0.0.1 9
FAIL  tcp 127.0.0.1:9  connection_refused: [Errno 61] Connection refused (0.2 ms)

$ netverify udp 127.0.0.1 9999 --payload hello --timeout 1
PASS  udp 127.0.0.1:9999  echo matched in 0.4 ms

$ netverify recover 127.0.0.1 8080 --deadline 1 --interval 0.3
FAIL  recover tcp 127.0.0.1:8080  not recovered: 4 attempts in 917.1 ms (deadline 1.00 s); last failure connection_refused: [Errno 61] Connection refused
      failed attempts: connection_refused x4

$ netverify tcp 127.0.0.1 8080 --format json
{"schema_version": 1, "command": "tcp", "status": "passed", "exit_code": 0, "result": {"protocol": "tcp", "target": {"host": "127.0.0.1", "port": 8080}, "success": true, "duration_seconds": 0.000276, "failure": null}}
```

Using the exit code in a script or CI step:

```bash
if netverify tcp db.internal 5432 --timeout 3; then
  echo "database reachable"
fi
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Verification passed. For `recover`: success was observed within the deadline. |
| `1` | Verification failed: the check ran and the target failed it. For `recover`: no success was observed, or it was observed only after the deadline. |
| `2` | Invalid input: bad usage, an invalid port, host, number of seconds or payload. The message goes to standard error. Nothing is run. |
| `3` | The check could not run normally: an unexpected or infrastructure error. Kept separate from `1`, so a broken check is never mistaken for an unreachable target. Also `3` with `--debug`, which adds the traceback on standard error; with `--format json`, the error report is still printed on standard output. |
| `130` | Interrupted with Ctrl-C. |

Network errors that the checks classify, such as refused connections,
timeouts and DNS failures, are verification failures (`1`), not errors (`3`).

### Output formats

- **Text** (default): one `PASS` or `FAIL` line on standard output. For
  `recover`, a second line counts the failure reasons of failed attempts.
- **JSON** (`--format json`): exactly one JSON document on one line of
  standard output, for tools and CI. Every report has the same envelope:

| Key | Value |
|---|---|
| `schema_version` | `1`. It changes only if the envelope changes incompatibly. |
| `command` | `"tcp"`, `"udp"` or `"recover"` |
| `status` | `"passed"`, `"failed"` or `"error"` |
| `exit_code` | The process exit code (`0`, `1`, `3` or `130`) |
| `result` | For `passed` and `failed`: the `VerificationResult` data (see [Result Model](#result-model)), or for `recover` the `RecoveryResult` data (see [Recovery Monitoring](#recovery-monitoring)) |
| `error` | For `error` only: `{"type": ..., "message": ...}` |

Errors (exit codes `3` and `130`) also print a one-line message to standard
error in both formats. Invalid input (exit code `2`) produces no JSON. argparse
reports it on standard error before any check runs.

### Payload privacy

UDP payloads are never included in reports. A `payload_mismatch` failure
normally shows previews of the bytes sent and received. The CLI replaces
that message with a fixed text unless `--show-payload` is given, while keeping
the reason and other fields. A payload given with `--payload` is still
visible to other local users in the process list, so do not pass secrets on
the command line.

## Result Model

Defined in `netverify.results`. All classes are immutable (frozen dataclasses).

| Type | Purpose |
|---|---|
| `VerificationResult` | The outcome of one check: `protocol`, `target`, `duration_seconds`, `failure` |
| `Target` | The `host` and `port` checked, exactly as given. `port` is `None` for ICMP and ARP. |
| `Failure` | Why a check failed: `reason`, `message`, `error_code`, `exception_type` |
| `Protocol` | Enum: `TCP`, `UDP`, `ICMP`, `ARP` |
| `FailureReason` | Enum of failure classifications (see below) |

Rules every result follows:

- A result is successful exactly when `failure` is `None`. `success` is
  derived from `failure` rather than stored, so a result cannot claim both
  success and a failure.
- TCP and UDP results have a port; ICMP and ARP results have none
  (`target.port` is `None`, `"port": null` in JSON).
- `duration_seconds` is finite and non-negative, measured with a monotonic
  clock (`time.monotonic()`), so system clock changes do not affect it.
- Field types are checked when a result is created.

Convenience properties: `result.success` (bool) and `result.reason`
(`FailureReason` or `None`).

### JSON-serializable output

`result.to_dict()` returns plain data ready for `json.dumps()`. Enum values
are stable lowercase strings:

```json
{
  "protocol": "tcp",
  "target": {"host": "127.0.0.1", "port": 8080},
  "success": false,
  "duration_seconds": 0.0013,
  "failure": {
    "reason": "connection_refused",
    "message": "[Errno 61] Connection refused",
    "error_code": 61,
    "exception_type": "ConnectionRefusedError"
  }
}
```

## Failure Classification

`netverify.diagnostics.classify_os_error()` turns socket errors into a
`Failure`. The exception type is checked first, then the errno value:

| `FailureReason` | Cause |
|---|---|
| `DNS_RESOLUTION_FAILED` | `socket.gaierror` or `socket.herror` |
| `TIMEOUT` | `TimeoutError`, including socket timeouts and `ETIMEDOUT` |
| `CONNECTION_REFUSED` | `ConnectionRefusedError` (`ECONNREFUSED`) |
| `NETWORK_UNREACHABLE` | `ENETUNREACH`, `ENETDOWN` |
| `HOST_UNREACHABLE` | `EHOSTUNREACH`, `EHOSTDOWN` |
| `SOCKET_ERROR` | Any other `OSError`. It is never guessed as a more specific reason. |

UDP replies have two further reasons:

| `FailureReason` | Cause |
|---|---|
| `UNEXPECTED_SENDER` | The reply did not come from the target's IP address and port. Checked first. |
| `PAYLOAD_MISMATCH` | The reply bytes differ from the payload sent. |

For debugging, each `Failure` keeps the original exception's message, code
(`error_code`) and class name (`exception_type`). For DNS failures,
`error_code` is a `getaddrinfo` `EAI_*` code, not an errno value. UDP
mismatch messages show up to 32 bytes of each payload, plus their lengths.

Packet checks (ICMP and ARP) use the same reasons where they mean the same
thing, plus two of their own:

| `FailureReason` | Cause |
|---|---|
| `HARDWARE_ADDRESS_MISMATCH` | An ARP reply gave a MAC address other than the expected one, or its Ethernet and ARP sender addresses disagree. |
| `ICMP_ERROR` | An ICMP error message quoting the request, with no more specific reason. |

`netverify.diagnostics.classify_icmp_error()` maps ICMP errors that quote
the request: destination unreachable codes 0, 6 and 11 are
`NETWORK_UNREACHABLE`; codes 1, 7 and 12 are `HOST_UNREACHABLE`; every other
error (other unreachable codes, time exceeded, parameter problem, source
quench) is `ICMP_ERROR`. The type and code are in the message; `error_code`
stays reserved for `OSError` codes.

### How UDP replies are validated

1. The host is resolved to an IPv4 address.
2. The payload is sent to that address and port.
3. The first datagram received is accepted as the reply.
4. The reply must come from the same IP address and port, and contain
   exactly the bytes that were sent.

## Recovery Monitoring

`netverify.recovery.wait_for_recovery()` runs a check repeatedly until it
succeeds or a deadline passes. It works on any platform. The check is any
callable that takes a timeout in seconds and returns a `VerificationResult`.

```python
from netverify.recovery import wait_for_recovery
from netverify.tcp import verify_tcp_connection

recovery = wait_for_recovery(
    lambda timeout: verify_tcp_connection("127.0.0.1", 8080, timeout=timeout),
    deadline=10.0,        # attempts may start within 10 s
    interval=0.5,         # pause between attempts (must be > 0)
    attempt_timeout=2.0,  # largest timeout given to one attempt
)
print(recovery.recovered, recovery.attempts, recovery.elapsed_seconds)
```

How polling works:

1. The first attempt starts immediately.
2. Each attempt gets `min(attempt_timeout, time remaining)` as its timeout.
3. After a failed attempt, polling sleeps for `interval` and tries again,
   but only if the next attempt would start before the deadline.
4. Polling stops at the first success.

`deadline`, `interval` and `attempt_timeout` must be positive finite
numbers. Invalid values raise `ValueError` or `TypeError` before any
attempt runs.

**Failed results versus errors.** A failed `VerificationResult` means
"not recovered yet", and polling continues. An exception raised by the check
means the check itself could not run, for example a probe failure. It is
never suppressed: polling stops, and the same exception propagates with a
note listing the attempts made so far.

`RecoveryResult` (immutable) describes the outcome:

| Field or property | Meaning |
|---|---|
| `results` | Every attempt's `VerificationResult`, in order, including the final one |
| `attempts` | Number of attempts that ran |
| `last_result` | The final attempt's result |
| `failure_reasons` | The reason of each failed attempt, in order |
| `recovered` | A successful result was observed |
| `recovered_within_deadline` | `recovered and elapsed_seconds <= deadline_seconds` |
| `elapsed_seconds` | Measured time until polling returned (monotonic clock), never clipped |
| `deadline_seconds`, `interval_seconds` | The settings used |

`to_dict()` returns JSON-ready data, including `recovered_within_deadline`.

### Deadline semantics

- **The deadline governs when attempts start.** It cannot forcibly
  interrupt a check that is already running. A synchronous check that
  overruns its timeout, for example because of slow subprocess startup or
  name resolution, can end after the deadline, unless the check bounds
  those operations itself. In that case `recovered` can be `True` while
  `recovered_within_deadline` is `False`.
- **Times are observation times.** `elapsed_seconds` is when polling saw
  the result, not the exact moment the network recovered.
- **Polling can stop before the deadline,** when the next scheduled attempt
  would start too late. `recovered=False` means no attempt that ran observed
  success. It does not prove the network was unavailable for the whole
  deadline.

## Linux Network Namespaces

The `netverify.linux` package builds a small, disposable test network on
Linux and runs checks inside it. It is separate from the TCP and UDP
modules, which do not depend on it, and importing it is safe on any
platform.

```python
from netverify.linux import VethTopology, tcp_listener, verify_tcp_in_namespace

with VethTopology() as topology:          # creates, then always removes
    with tcp_listener(topology, topology.right) as port:
        result = verify_tcp_in_namespace(
            topology, topology.left, topology.right.address, port
        )
    print(result.success)
```

`VethTopology` creates:

- two namespaces with random names, `netverify-<token>-left` and
  `netverify-<token>-right`;
- a veth pair whose two ends are created directly inside those namespaces;
- the addresses `10.231.0.1/30` (left) and `10.231.0.2/30` (right) by
  default, configurable with `VethTopology(network=...)`;
- the veth interfaces and loopback set up in both namespaces.

Two helpers run a TCP server inside a namespace and yield its port:

| Helper | Accepts | Stops |
|---|---|---|
| `tcp_listener(topology, endpoint, timeout=10.0)` | One connection | After that connection, or after `timeout` |
| `tcp_server(topology, endpoint, duration=60.0)` | Any number of connections, so it suits recovery polling | When the `with` block ends, by closing the server's standard input; at the latest after `duration` |

If `tcp_server` does not exit within 5 seconds of its input closing, it is
sent SIGTERM. Anything still running is killed when the topology closes.

### Safety and privileges

- **Nothing on the host changes.** No interface, address, route or firewall
  rule is added to the host. A namespace test checks that the host's
  interfaces and IPv4 routes are the same before, during and after.
- **Only its own resources.** Cleanup deletes only the namespaces that this
  topology created. Deleting a namespace also removes the veth end inside it.
- **Limited privileges.** Only the `ip` commands that create, configure and
  delete namespaces run as root, through `sudo -n`, which fails rather than
  asking for a password. Commands run inside a namespace switch back to the
  calling user with `setpriv`.
- **No shell.** Every command is run as an explicit argument list.
- **Cleanup runs even on failure.** It runs after a failed setup step or an
  exception in the `with` block. If a deletion fails, `close()` raises
  `TopologyCleanupError` and can be called again to retry.

### Errors are kept separate

| Outcome | Meaning |
|---|---|
| `TopologySetupError` | The test network could not be built. The message names the step and includes `ip`'s error output. |
| `CommandError` / `ProbeError` | The check could not run inside the namespace, or printed no valid result. |
| `VerificationResult` with a `failure` | The check ran, and the connection failed. |

### Requirements

Linux with `ip` (iproute2) and either root or passwordless `sudo`, plus
`setpriv` (util-linux) when not running as root.
`netverify.linux.missing_prerequisites()` lists what is missing. Packet
checks need more; see [Packet check requirements](#packet-check-requirements).

### Reversible Fault Injection

`LinkDown` brings one of a topology's veth interfaces administratively down
for the duration of a `with` block, then restores it:

```python
from netverify.linux import LinkDown, VethTopology, link_is_up

with VethTopology() as topology:
    with LinkDown(topology, topology.left):
        ...                                    # the left link is down here
    assert link_is_up(topology, topology.left)  # restored afterwards
```

How it works:

1. **Before anything changes,** an endpoint from another topology, or a
   topology that is not active, is rejected with `ValueError` or
   `RuntimeError`.
2. **On entry,** the interface's original state is read as the calling user
   (`ip -o link show` inside the namespace, with no privileges), then the
   interface is set down.
3. **On exit,** an interface that was up before is set up again, and its
   state is read back to confirm the restore. An interface that was already
   down is left down. Exit runs even if the block raises.

Safety:

- **Only the topology's own interfaces.** Faults go through
  `VethTopology.set_link_state()`. It takes the interface name from the
  topology's own endpoint, and refuses endpoints from other topologies. The
  host's interfaces, routes and firewall are never touched.
- **One privileged command.** Only `ip -n <namespace> link set dev <veth>
  up|down` runs with `sudo -n`.
- **Restored, or deleted with the topology.** If restoring fails, the
  topology's `close()` still deletes the namespace, and the interface with
  it.

Fault errors share no base class with topology or probe errors:

| Outcome | Meaning |
|---|---|
| `FaultInjectionError` | The fault could not be applied: the link state could not be read, or the link could not be set down. A restore is attempted before it is raised, in case the command took effect. |
| `FaultRestoreError` | The link could not be set up again, or is still down afterwards. If the `with` block raised, its exception is kept and this is attached to it as a note. |
| `VerificationResult` with a `failure` | A check ran while the fault was active and failed: the expected outcome, not an error. |

Both errors subclass `FaultError`.

#### Healthy → fault → recovery scenario

The namespace integration test
`test_connectivity_fails_while_link_is_down_and_returns_after_restore`
checks the whole cycle, connecting from the left namespace to a listener in
the right namespace:

| Phase | Expected |
|---|---|
| Healthy | The TCP connection succeeds. |
| Fault (left link down) | The link reads as down. A listener is running, so a failure cannot be a missing service. The TCP connection fails. The host's interfaces and routes are unchanged. |
| Recovery | The link reads as up, and the TCP connection succeeds again on the first attempt, with no retry. |

**Accepted failure classifications during the fault:** `NETWORK_UNREACHABLE`,
`HOST_UNREACHABLE` or `TIMEOUT`, all of which mean the packets had no
working path. Success and `CONNECTION_REFUSED` fail the test. The test
accepts all three because the exact reason depends on Linux routing
behaviour and has not been confirmed. The CI runs do not record which
reason occurred.

#### Recovery polling scenario

The namespace test
`test_recovery_after_restoring_the_link_is_observed_by_polling` does not
assume recovery is instantaneous:

1. One `tcp_server` in the right namespace serves every phase.
2. A connection from the left namespace succeeds while healthy, and fails
   with one of the accepted reasons above while the link is down.
3. After the link is restored, `wait_for_recovery()` polls (20 s deadline,
   0.2 s interval) until a connection succeeds.

The test requires `recovered`, and bounds `elapsed_seconds` to allow one
attempt's subprocess overhead past the deadline.

## Packet-Level Verification (ICMP and ARP)

`netverify.linux` can check ICMP echo and ARP between the two namespaces of
a topology, by sending and receiving Ethernet frames on the topology's own
veth interface. Linux only; needs the optional `packet` extra.

```python
from netverify.linux import (
    VethTopology, link_address, verify_arp_in_namespace, verify_icmp_echo_in_namespace,
)

with VethTopology() as topology:
    echo = verify_icmp_echo_in_namespace(
        topology, topology.left, topology.right.address, timeout=2.0
    )
    arp = verify_arp_in_namespace(
        topology, topology.left, topology.right.address,
        expected_mac=link_address(topology, topology.right),  # optional
        timeout=2.0,
    )
    print(echo.success, arp.success)
```

| Function | Checks |
|---|---|
| `verify_icmp_echo_in_namespace(topology, source, destination, *, timeout=2.0)` | `destination` answers an ICMP echo request sent from `source`'s namespace |
| `verify_arp_in_namespace(topology, source, destination, *, expected_mac=None, timeout=2.0)` | `destination` answers an ARP request, with `expected_mac` if given |
| `link_address(topology, endpoint)` | Returns the MAC address of an endpoint's veth interface (read without privileges) |
| `missing_packet_prerequisites()` | Lists what is missing to run packet checks here |

Both checks return a `VerificationResult` with `Protocol.ICMP` or
`Protocol.ARP` and a portless target, so they work with
`wait_for_recovery()` and the reporting functions like any other check.

### How a check runs

Each check runs NetVerify's packet probe (`python -m
netverify.linux.packet_probe`) inside the source namespace. Scapy builds
the outgoing frames and dissects incoming headers; the decision whether a
frame answers the request is made by NetVerify's own pure validation code.

- **ARP:** send a broadcast ARP request, then wait for a reply about the
  destination address, addressed to the source's own IP and MAC address.
- **ICMP echo:** first resolve the destination's MAC address with the same
  ARP exchange, then send the echo request at layer 2 to that address, and
  wait for an echo reply with the request's identifier, sequence number and
  random payload. Scapy's own MAC address resolution, which has a hidden
  timeout of its own, is never used.
- **Frames are checked before they are trusted:** frame type, header
  lengths, IP total length and ICMP checksum. Fragments, truncated frames
  and other traffic are ignored, so the check keeps waiting.

### One shared deadline

`timeout` (more than 0, at most 60 seconds) is one monotonic deadline for
the whole check: opening the socket, ARP resolution and, for ICMP, the echo
request and reply.

- Each wait for a frame is bounded by the time remaining.
- No packet is sent once the deadline has passed. For ICMP, if ARP
  resolution uses up the time, no echo request is sent.
- A frame received after the deadline is never accepted.
- `duration_seconds` is the true elapsed time, measured inside the probe.

**Limitation:** opening the socket, sending and receiving are synchronous
calls that cannot be interrupted, so one can run past the deadline. The
check then ends as `TIMEOUT` without accepting anything late, and
`duration_seconds` reports the real time, which can exceed `timeout`. The
probe's process startup (sudo, namespace entry, Python and Scapy imports)
is not part of `timeout`; the probe process is given `timeout` plus a fixed
allowance of 15 seconds before it is treated as hung (`CommandError`).

### Results

| Situation | Result |
|---|---|
| A correct reply | Success |
| No reply by the deadline (for example, nobody has the address, or the peer's link is down) | `TIMEOUT` |
| The source interface is down | `NETWORK_UNREACHABLE`, from `ENETDOWN` when the packet socket is opened |
| An echo reply from another address, or with a different payload | `UNEXPECTED_SENDER`, `PAYLOAD_MISMATCH` |
| An ICMP error quoting the request | See [Failure Classification](#failure-classification) |
| An ARP reply with another MAC address than `expected_mac`, or inconsistent Ethernet and ARP addresses | `HARDWARE_ADDRESS_MISMATCH` |

The `TIMEOUT` and `NETWORK_UNREACHABLE` rows for link faults were observed
in the Linux namespace tests in CI (see
[Continuous Integration](#continuous-integration)).

Errors are kept separate as for TCP checks: invalid arguments raise
`ValueError` or `TypeError` before anything runs; a probe that cannot run
at all (no Scapy, no `CAP_NET_RAW`, no such interface) exits with status 3
and the call raises `CommandError`; invalid probe output raises
`ProbeError`; a check that ran and failed returns a failed result.

### Security model

Packet sockets need the `CAP_NET_RAW` capability. NetVerify grants it to
one command only, and as narrowly as it can:

- **One privileged entry point.** `VethTopology.run_packet_probe()` is the
  only command that runs with a capability. It takes probe arguments, never
  a command: the program is always this Python interpreter running
  `-I -m netverify.linux.packet_probe`.
- **Strict arguments.** The arguments are parsed strictly (each option
  exactly once, no abbreviations, validated interface name, IPv4
  addresses and timeout), and only their re-built canonical form is run.
- **Only the topology's own network.** The source must be one of the
  topology's endpoints, with its own interface and address, and the
  destination must be a host address on the topology's link (not its
  network or broadcast address, and not the source itself). The namespace
  contains only loopback and the veth link, with no route out.
- **Calling user, one capability.** The probe runs as the calling user,
  through `setpriv` with `--inh-caps=-all,+net_raw`,
  `--ambient-caps=-all,+net_raw`, `--bounding-set=-all,+net_raw`,
  `--no-new-privs` and `--clear-groups`. It is never run as root: the call
  is refused if the caller is root.
- **No helper processes.** The probe opens Scapy's packet socket with no
  capture filter, so Scapy never starts `tcpdump` (which would inherit the
  capability); frames are filtered in Python.
- **Nothing written outside a private folder.** Scapy's cache and
  configuration go to a temporary folder created by the probe and removed
  when it exits.
- **Ordinary commands are unchanged.** `run()`, `exec_command()`, `popen()`
  and the TCP checks never receive any capability.

The namespace tests check these properties on Linux: while a probe runs,
its process has the calling user's IDs, no supplementary groups, exactly
`CAP_NET_RAW` in its effective, permitted, inheritable, ambient and
bounding sets, and no-new-privs set; its packet socket belongs to the
calling user; and afterwards no packet socket, probe process, temporary
folder or namespace is left, and the host's interfaces and routes are
unchanged.

### Packet check requirements

Everything in [Requirements](#requirements), plus:

- a non-root user (the probe runs as the calling user);
- Scapy 2.6.1 in the same Python environment (`pip install ".[packet]"`);
- `setpriv` with ambient capability support (util-linux 2.31 or newer).

`netverify.linux.missing_packet_prerequisites()` lists what is missing.

### Recovery over ICMP

```python
from netverify.recovery import wait_for_recovery

recovery = wait_for_recovery(
    lambda timeout: verify_icmp_echo_in_namespace(
        topology, topology.left, topology.right.address, timeout=timeout
    ),
    deadline=20.0, interval=0.2, attempt_timeout=2.0,
)
```

The namespace test `test_recovery_is_observed_by_polling_over_icmp` takes
the source link down, observes a failed attempt, restores the link, and
requires recovery within the deadline.

## Current Limitations

- **IPv4 only.** UDP checks use `AF_INET`.
- **First response only.** The UDP check validates only the first datagram
  it receives. A stray datagram from another sender causes a failure, even
  if the correct reply would have arrived later.
- **Single UDP attempt.** There are no retries, so one lost packet causes a
  failure.
- **Silent drops are reported as `TIMEOUT`.** A firewalled TCP port, or any
  port whose packets are dropped instead of refused, times out.
- **Closed UDP ports usually report `TIMEOUT`.** The UDP socket is not
  connected, so the operating system usually does not report
  `CONNECTION_REFUSED` for UDP.
- **Broad DNS category.** Every `socket.gaierror` is reported as
  `DNS_RESOLUTION_FAILED`, including rare non-DNS `getaddrinfo` errors.
- **Hostname lookup is not covered by `timeout`,** and `duration_seconds`
  includes it.
- **Resolved IP address is not a separate field.** For UDP it appears only
  in `UNEXPECTED_SENDER` messages.
- **No traceback in results.** A `Failure` keeps the exception's details but
  not the exception object.
- **Tested platforms.** The suite runs locally on macOS and in CI on Ubuntu
  Linux (see [Continuous Integration](#continuous-integration)). Windows is
  not tested. Namespace tests have run only in CI, on Ubuntu 24.04 with
  Python 3.11.
- **Namespace topologies are Linux only,** and can only be left behind if
  the process is killed before cleanup runs. To find leftovers:
  `ip netns list | grep '^netverify-'`.
- **Packet checks are limited by design:** Linux only, IPv4 only, inside a
  NetVerify topology only, a single attempt per check with no retries (one
  ARP request, and for ICMP one echo request), and no command-line command.
- **Packet deadline overrun.** A synchronous socket call can run past the
  check's deadline; nothing late is accepted, and the reported duration is
  the real one (see [One shared deadline](#one-shared-deadline)).
- **Proxy ARP fails ARP checks with an expected MAC.** A reply whose
  Ethernet and ARP sender addresses differ is reported as
  `HARDWARE_ADDRESS_MISMATCH`.
- **One tested Scapy version.** The `packet` extra pins Scapy 2.6.1. Packet
  checks have run on Linux only in CI, on Ubuntu 24.04 with Python 3.11; the
  offline Scapy tests run on Python 3.11, 3.12 and 3.13.

## Setup

For development. Requires Python 3.11 or newer. From the project root:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

This installs `netverify` in editable mode, along with pytest and Scapy
2.6.1 from the `dev` optional dependencies defined in `pyproject.toml`
(Scapy is needed by the packet tests). It also installs the `netverify`
command into the virtual environment (`.venv/bin/netverify`). The NetVerify
core itself has no runtime dependencies beyond the Python standard library.

## Running the Tests

From the project root:

```bash
.venv/bin/python -m pytest -v    # every test, by name
.venv/bin/python -m pytest -q    # short summary with the total count
```

pytest discovers tests in `tests/`, as configured in `pyproject.toml`.

Namespace tests are marked `netns`. Without Linux and the required
privileges they are skipped, and the reason is shown with `-ra`. Packet
namespace tests also need the
[packet check requirements](#packet-check-requirements):

```bash
.venv/bin/python -m pytest -m "not netns"   # everything except namespace tests
.venv/bin/python -m pytest -m netns -ra     # only namespace tests
NETVERIFY_REQUIRE_NETNS=1 .venv/bin/python -m pytest -m netns   # fail instead of skipping
```

| File | Type | What it covers |
|---|---|---|
| `tests/test_results.py` | Unit | Result model rules, per-protocol port rules, immutability, `to_dict()` and `from_dict()` |
| `tests/test_diagnostics.py` | Unit | Classification of each error type, errno value and ICMP error |
| `tests/test_reporting.py` | Unit | Text output for each protocol, portless targets, JSON envelope |
| `tests/test_tcp.py` | Unit (mocked) | Boolean TCP API |
| `tests/test_tcp_verify.py` | Unit (mocked) | Detailed TCP API, classification, duration and delegation |
| `tests/test_udp.py` | Unit (mocked) | Boolean UDP API |
| `tests/test_udp_verify.py` | Unit (mocked) | Detailed UDP API, reply validation, duration and delegation |
| `tests/test_tcp_integration.py` | Integration | Real TCP success and refused connections |
| `tests/test_udp_integration.py` | Integration | Real UDP echo, payload mismatch and timeout |
| `tests/test_cli.py` | Unit (mocked checks) | CLI arguments, validation, output formats, exit codes, payload hiding |
| `tests/test_cli_integration.py` | Integration | CLI against real loopback servers, including `python -m netverify` and the `netverify` script |
| `tests/test_recovery.py` | Unit (fake clock) and integration | Polling schedule, deadline semantics, attempt counting, invalid settings, exceptions; one real-socket recovery on `127.0.0.1` |
| `tests/test_linux_topology.py` | Unit (fake runner) | Exact `ip` commands, cleanup after partial setup failures, cleanup retries |
| `tests/test_linux_commands.py` | Integration | Running commands: errors, missing commands, timeouts, no shell |
| `tests/test_linux_connectivity.py` | Integration | The in-namespace check, one-shot listener and multi-connection server, run on `127.0.0.1` without namespaces |
| `tests/test_linux_faults.py` | Unit (fake runner) | `LinkDown` life cycle: restore after errors, injection and restore failures, verified restore, own interfaces only |
| `tests/test_netns_integration.py` | Namespace (`netns`) | Real namespaces: configuration, connectivity, host isolation, cleanup, the healthy → fault → recovery scenario, and recovery polling |
| `tests/test_packet_validation.py` | Unit (pure) | ICMP and ARP reply matching, ignored traffic, mismatches, malformed values |
| `tests/test_packet_request.py` | Unit (pure) | Strict parsing of the packet probe's arguments |
| `tests/test_packet_probe.py` | Unit (offline Scapy, fake link and clock) | Frame building and decoding, malformed frames, the shared deadline, socket error classification, cleanup, no subprocesses |
| `tests/test_linux_packet.py` | Unit (fake runner) | The exact privileged command, everything it refuses, the public packet API, recovery polling |
| `tests/test_optional_scapy.py` | Integration (subprocess) | NetVerify imports and works with every `scapy` import blocked |
| `tests/test_netns_packet_integration.py` | Namespace (`netns`) | Real ICMP and ARP: capabilities of the running probe, both directions, wrong MAC, unused address, source and peer link down, restore, recovery polling, cleanup |

- **Unit tests** mock the socket layer, the clock or the command runner
  where needed, so they use no network or DNS access and never assert real
  timings. The packet probe tests build and dissect real frames with Scapy,
  but send nothing.
- **Integration tests** use real sockets on `127.0.0.1` only and contact no
  external hosts. UDP integration tests run a one-shot echo server in a
  worker thread, with a timeout on every wait.
- **Namespace tests** need Linux and privileges, and send traffic only
  between the two namespaces of a test topology.

## Continuous Integration

The [Tests workflow](.github/workflows/tests.yml) runs on GitHub Actions on
every push to `main`, on every pull request, and on manual request.

| Job | Runner | Python | Privileges | Runs |
|---|---|---|---|---|
| `pytest (Python …)` | `ubuntu-24.04` | 3.11, 3.12, 3.13 (one job each) | None | Every test except namespace tests (`-m "not netns"`), including the offline Scapy tests |
| `Linux namespaces` | `ubuntu-24.04` | 3.11 | `sudo -n` for `ip` commands; `CAP_NET_RAW` for the packet probe only | Namespace tests only (`-m netns`), TCP and packet |

Every job installs NetVerify with `pip install -e ".[dev]"`, which includes
Scapy 2.6.1. A failing test fails the workflow. In GitHub Actions, the test
suite also adds one annotation to each job with the pytest counts and the
names of the namespace tests that passed (`tests/conftest.py`), so results
can be checked without access to the job logs.

The namespace job:

1. Checks that `ip`, `setpriv` and passwordless `sudo` are available.
2. Runs pytest as the normal runner user, with `NETVERIFY_REQUIRE_NETNS=1`.
   Missing prerequisites then fail the tests instead of skipping them, and
   if no namespace test is collected, pytest's exit status also fails the
   job.
3. Always checks afterwards that no `netverify-*` namespace was left
   behind, even if earlier steps failed.

It uses Python 3.11, the oldest supported version.

**Verified:**

- The first run, on commit `65fcdde`, passed for all three Python versions
  ([run 43035620517](https://github.com/Julianakh9/NetVerify/actions/runs/43035620517)).
- The first run with namespace tests, on commit `40eaba4`, passed all four
  jobs, including the namespace job's leftover-namespace check
  ([run 43059673280](https://github.com/Julianakh9/NetVerify/actions/runs/43059673280)).
- The first run with fault injection, on commit `bedd784`, passed all four
  jobs. The namespace job ran the healthy → fault → recovery test, and its
  leftover-namespace check passed
  ([run 43064412675](https://github.com/Julianakh9/NetVerify/actions/runs/43064412675)).
- The first run with recovery monitoring, on commit `e3f8c6f`, passed all
  four jobs. The namespace job ran the recovery polling test, and its
  leftover-namespace check passed
  ([run 43080592924](https://github.com/Julianakh9/NetVerify/actions/runs/43080592924)).
- The first run with the command-line interface, on commit `cad920c`,
  passed all four jobs. The CLI tests, including the installed `netverify`
  script, ran in all three Python jobs
  ([run 43082568045](https://github.com/Julianakh9/NetVerify/actions/runs/43082568045)).
- The run with the final CLI corrections (duration limits and `--debug`
  exit codes), on commit `40e9247`, passed all four jobs, including the
  leftover-namespace check
  ([run 43263893574](https://github.com/Julianakh9/NetVerify/actions/runs/43263893574)).
- The first run with ICMP and ARP packet verification, on commit `8b2b6a3`
  of the `feature/m7-scapy-packet-verification` branch (started manually),
  passed all four jobs: 637 tests passed in each Python job, and 21
  namespace tests passed (10 TCP and topology tests, 11 packet tests),
  with no failures, errors or skips; the leftover-namespace check passed
  ([run 43577545940](https://github.com/Julianakh9/NetVerify/actions/runs/43577545940)).

Each job's log records the exact Python version used (in the "Set up
Python" step) and the installed package versions (in the "Show installed
packages" step).

## Technologies

- **In use:** Python 3.11–3.13, pytest, argparse, TCP and UDP sockets
  (`socket` module), Linux network namespaces and veth pairs (iproute2),
  Linux capabilities (`setpriv`), Scapy 2.6.1 (optional, packet checks
  only), setuptools packaging, Git, GitHub Actions on Ubuntu Linux

## Current Status

- **v0.1.0** is the latest published release.
- **v0.2.0** is a release candidate, not yet published. It adds ICMP and
  ARP packet verification, which is implemented and verified in CI (see
  [Continuous Integration](#continuous-integration)). Its publication
  waits for a final review of the licensing questions described in
  [Third-party licenses](#third-party-licenses).

The version numbers mark early releases: the Python API and the JSON report
format (`schema_version` 1) may still change in later 0.x versions.

## License

NetVerify's own source code is released under the [MIT License](LICENSE).
Copyright (c) 2026 Juliana Khoury.

### Third-party licenses

**Scapy** (optional, used only by the packet checks)

- Project: [scapy.net](https://scapy.net/); source code:
  [github.com/secdev/scapy](https://github.com/secdev/scapy).
- Copyright: Philippe Biondi and the Scapy community (the copyright notices
  in Scapy's source files name the individual authors).
- License: the GNU General Public License, version 2. Scapy 2.6.1 declares
  `GPL-2.0-only` in its package metadata and ships the GPL version 2 text;
  its source files carry `GPL-2.0-only` or `GPL-2.0-or-later` notices, with
  a few files under other licenses.
- Version used by NetVerify: 2.6.1, the only version it has been tested
  with.

How NetVerify relates to Scapy:

- NetVerify's repository, source distribution and wheel contain no Scapy
  code, and NetVerify's release artifacts do not include Scapy.
- Scapy is installed separately, from its own distribution, only when the
  `packet` extra is requested. NetVerify's package metadata only names it
  as that extra's dependency.
- Only the packet probe (`netverify.linux.packet_probe`) imports Scapy, in
  its own process, when a packet check runs. The rest of NetVerify works
  without it.

Open licensing questions, which this README does not resolve:

- Making Scapy an optional dependency does not, by itself, settle whether
  or how the GPL's obligations apply when NetVerify and Scapy are used or
  distributed together. Interpretations differ on whether a program that
  imports a GPL-licensed library in its own process forms a single combined
  work with it.
- Anyone who redistributes NetVerify together with Scapy, for example in a
  container image, a virtual machine image or a bundled application, is
  distributing Scapy and must comply with its license for that
  distribution. Whether those obligations also extend to NetVerify's code
  in the combination is one of the questions above.
- If you plan such a redistribution, particularly a commercial one, seek
  qualified legal advice.

This section is information about licensing, not legal advice.
