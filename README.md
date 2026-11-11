# NetVerify

[![Tests](https://github.com/Julianakh9/NetVerify/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/Julianakh9/NetVerify/actions/workflows/tests.yml)

## Overview

NetVerify is a Python-based network verification and automated testing framework.

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
- **Linux network namespace topologies:** two temporary, isolated network
  namespaces joined by a virtual Ethernet (veth) link, with TCP checks run
  from inside a namespace (Linux only; see
  [Linux Network Namespaces](#linux-network-namespaces)).
- **Reversible fault injection:** take a topology's virtual link down for
  the duration of a `with` block, and restore it afterwards (Linux only; see
  [Reversible Fault Injection](#reversible-fault-injection)).

### Planned

Not yet implemented:

- More advanced network verification scenarios
- IPv6 support
- Configurable retries for UDP checks

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

## Result Model

Defined in `netverify.results`. All classes are immutable (frozen dataclasses).

| Type | Purpose |
|---|---|
| `VerificationResult` | The outcome of one check: `protocol`, `target`, `duration_seconds`, `failure` |
| `Target` | The `host` and `port` checked, exactly as given |
| `Failure` | Why a check failed: `reason`, `message`, `error_code`, `exception_type` |
| `Protocol` | Enum: `TCP`, `UDP` |
| `FailureReason` | Enum of failure classifications (see below) |

Rules every result follows:

- A result is successful exactly when `failure` is `None`. `success` is
  derived from `failure` rather than stored, so a result cannot claim both
  success and a failure.
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

### How UDP replies are validated

1. The host is resolved to an IPv4 address.
2. The payload is sent to that address and port.
3. The first datagram received is accepted as the reply.
4. The reply must come from the same IP address and port, and contain
   exactly the bytes that were sent.

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
`netverify.linux.missing_prerequisites()` lists what is missing.

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

## Setup

Requires Python 3.11 or newer. From the project root:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

This installs `netverify` in editable mode, along with pytest from the `dev`
optional dependencies defined in `pyproject.toml`.

## Running the Tests

From the project root:

```bash
.venv/bin/python -m pytest -v    # every test, by name
.venv/bin/python -m pytest -q    # short summary with the total count
```

pytest discovers tests in `tests/`, as configured in `pyproject.toml`.

Namespace tests are marked `netns`. Without Linux and the required
privileges they are skipped, and the reason is shown with `-ra`:

```bash
.venv/bin/python -m pytest -m "not netns"   # everything except namespace tests
.venv/bin/python -m pytest -m netns -ra     # only namespace tests
NETVERIFY_REQUIRE_NETNS=1 .venv/bin/python -m pytest -m netns   # fail instead of skipping
```

| File | Type | What it covers |
|---|---|---|
| `tests/test_results.py` | Unit | Result model rules, immutability, `to_dict()` and `from_dict()` |
| `tests/test_diagnostics.py` | Unit | Classification of each error type and errno value |
| `tests/test_tcp.py` | Unit (mocked) | Boolean TCP API |
| `tests/test_tcp_verify.py` | Unit (mocked) | Detailed TCP API, classification, duration and delegation |
| `tests/test_udp.py` | Unit (mocked) | Boolean UDP API |
| `tests/test_udp_verify.py` | Unit (mocked) | Detailed UDP API, reply validation, duration and delegation |
| `tests/test_tcp_integration.py` | Integration | Real TCP success and refused connections |
| `tests/test_udp_integration.py` | Integration | Real UDP echo, payload mismatch and timeout |
| `tests/test_linux_topology.py` | Unit (fake runner) | Exact `ip` commands, cleanup after partial setup failures, cleanup retries |
| `tests/test_linux_commands.py` | Integration | Running commands: errors, missing commands, timeouts, no shell |
| `tests/test_linux_connectivity.py` | Integration | The in-namespace check and listener, run on `127.0.0.1` without namespaces |
| `tests/test_linux_faults.py` | Unit (fake runner) | `LinkDown` life cycle: restore after errors, injection and restore failures, verified restore, own interfaces only |
| `tests/test_netns_integration.py` | Namespace (`netns`) | Real namespaces: configuration, connectivity, host isolation, cleanup, and the healthy → fault → recovery scenario |

- **Unit tests** mock the socket layer, the clock or the command runner
  where needed, so they use no network or DNS access and never assert real
  timings.
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
| `pytest (Python …)` | `ubuntu-24.04` | 3.11, 3.12, 3.13 (one job each) | None | Every test except namespace tests (`-m "not netns"`) |
| `Linux namespaces` | `ubuntu-24.04` | 3.11 | `sudo -n` for `ip` commands only | Namespace tests only (`-m netns`) |

Every job installs NetVerify with `pip install -e ".[dev]"`. A failing test
fails the workflow.

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

Each job's log records the exact Python version used (in the "Set up
Python" step) and the installed package versions (in the "Show installed
packages" step).

## Technologies

- **In use:** Python 3.11–3.13, pytest, TCP and UDP sockets (`socket`
  module), Linux network namespaces and veth pairs (iproute2), Git, GitHub
  Actions on Ubuntu Linux
- **May be considered later:** Scapy

## Current Status

**In Progress — reversible fault injection milestone complete**
