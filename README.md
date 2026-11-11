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
  not tested.

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

| File | Type | What it covers |
|---|---|---|
| `tests/test_results.py` | Unit | Result model rules, immutability and `to_dict()` |
| `tests/test_diagnostics.py` | Unit | Classification of each error type and errno value |
| `tests/test_tcp.py` | Unit (mocked) | Boolean TCP API |
| `tests/test_tcp_verify.py` | Unit (mocked) | Detailed TCP API, classification, duration and delegation |
| `tests/test_udp.py` | Unit (mocked) | Boolean UDP API |
| `tests/test_udp_verify.py` | Unit (mocked) | Detailed UDP API, reply validation, duration and delegation |
| `tests/test_tcp_integration.py` | Integration | Real TCP success and refused connections |
| `tests/test_udp_integration.py` | Integration | Real UDP echo, payload mismatch and timeout |

- **Unit tests** mock the socket layer and the clock where needed, so they
  use no network or DNS access and never assert real timings.
- **Integration tests** use real sockets on `127.0.0.1` only and contact no
  external hosts. UDP integration tests run a one-shot echo server in a
  worker thread, with a timeout on every wait.

## Continuous Integration

The [Tests workflow](.github/workflows/tests.yml) runs on GitHub Actions on
every push to `main`, on every pull request, and on manual request.

| Runner | Python versions |
|---|---|
| `ubuntu-24.04` | 3.11, 3.12, 3.13 |

Each Python version runs as a separate job that installs NetVerify with
`pip install -e ".[dev]"` and runs the full pytest suite, unit and
integration tests together. A failing test fails the workflow.

**Verified:** the first run, on commit `65fcdde`, passed for all three
Python versions
([run 43035620517](https://github.com/Julianakh9/NetVerify/actions/runs/43035620517)).
Each job's log records the exact Python version used (in the "Set up
Python" step) and the installed package versions (in the "Show installed
packages" step).

## Technologies

- **In use:** Python 3.11–3.13, pytest, TCP and UDP sockets (`socket`
  module), Git, GitHub Actions on Ubuntu Linux
- **May be considered later:** Scapy

## Current Status

**In Progress — Linux CI milestone complete**
