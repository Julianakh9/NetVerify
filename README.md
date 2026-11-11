# NetVerify

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

#### TCP connectivity check — `netverify.tcp.check_tcp_connection`

```python
from netverify.tcp import check_tcp_connection

check_tcp_connection("127.0.0.1", 8080, timeout=2.0)  # True or False
```

- Returns `True` if a TCP connection to `host:port` can be established.
- Returns `False` if the attempt fails with an `OSError`, such as a refused
  connection, a timeout or an unresolvable hostname.
- Other exceptions are not caught and reach the caller.
- `timeout` is the socket timeout in seconds for connection attempts. It is
  not a strict deadline for the entire function.
- The socket is always closed. No application data is sent.

#### UDP echo verification — `netverify.udp.check_udp_echo`

```python
from netverify.udp import check_udp_echo

check_udp_echo("127.0.0.1", 9999, payload=b"netverify-ping", timeout=2.0)  # True or False
```

Sends one datagram to a UDP echo service and checks the first reply.

How a reply is validated:

1. The host is resolved to an IPv4 address.
2. The payload is sent to that address and port.
3. The first datagram received is accepted as the reply.
4. The result is `True` only if both of these hold:
   - The reply bytes exactly equal the payload that was sent.
   - The reply came from the same IP address and port the payload was sent to.

The result is `False` if the reply content differs, the reply comes from
another address, no reply arrives within `timeout`, or another `OSError`
occurs, such as an unresolvable hostname. Other exceptions reach the caller.
`timeout` applies to each send and receive. It is not a strict deadline for
the entire function.

### Current Limitations

- **IPv4 only.** UDP checks use `AF_INET`. IPv6 is not supported.
- **Boolean results only.** Both checks return `True` or `False`, without
  saying why a check failed.
- **First response only.** The UDP check validates only the first datagram it
  receives. A stray datagram from another sender causes `False`, even if the
  correct reply would have arrived later.
- **Single UDP attempt.** There are no retries, so one lost packet causes
  `False`.
- **Hostname lookup not covered by `timeout`.** A slow DNS lookup can take
  longer than `timeout`.
- **Closed UDP ports look like silence.** A closed port is usually reported
  the same way as a server that does not reply: `False` after the full
  timeout.

### Planned

Not yet implemented:

- A shared verification result model with structured failure diagnostics,
  reporting why a check failed
- IPv6 support
- Configurable retries for UDP checks
- Linux networking support and verification

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
.venv/bin/python -m pytest -v
```

pytest discovers tests in `tests/`, as configured in `pyproject.toml`. The
suite contains 18 test cases, all passing.

| File | Type | Cases |
|---|---|---|
| `tests/test_tcp.py` | Unit (mocked) | 7 |
| `tests/test_tcp_integration.py` | Integration (loopback) | 1 |
| `tests/test_udp.py` | Unit (mocked) | 7 |
| `tests/test_udp_integration.py` | Integration (loopback) | 3 |
| **Total** | | **18** |

Unit tests mock the socket layer, so they use no network or DNS access.
Integration tests use real sockets on `127.0.0.1` only and contact no
external hosts.

### TCP tests

- **Unit:** a successful connection, a custom timeout, four `OSError` types
  (refused, timeout, DNS failure, generic) in one parametrized test, and an
  unexpected exception that must propagate.
- **Integration:** a real connection to a temporary listener.

### UDP tests

**Unit** (`socket.socket` mocked):

1. A matching echo returns `True`, and the socket is created, configured and
   closed correctly.
2. A custom payload and timeout are used.
3. A receive timeout returns `False`.
4. An incorrect reply payload returns `False`.
5. A reply from the wrong IP address returns `False`.
6. A reply from the wrong port returns `False`.
7. An `OSError` while sending returns `False`.

Cases 5 and 6 are one parametrized test.

**Integration** (a real one-shot UDP server in a worker thread):

1. A real echo server: the check returns `True`.
2. A server that replies with an incorrect payload: the check returns `False`.
3. A server that never replies: the check times out and returns `False`.

## Technologies

- **In use:** Python 3.11, pytest, TCP and UDP sockets (`socket` module), Git
- **Planned:** Linux
- **May be considered later:** Scapy

## Current Status

**In Progress — UDP echo verification milestone complete**
