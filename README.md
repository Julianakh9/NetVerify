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

**TCP connectivity check** — `netverify.tcp.check_tcp_connection`

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

### Planned

Not yet implemented:

- UDP checks
- Linux networking support and verification
- Failure diagnostics that report why a check failed, not only that it failed

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
suite contains 8 test cases:

- **`tests/test_tcp.py`** — 7 unit test cases. `socket.create_connection` is
  mocked, so no network or DNS access is used. They cover a successful
  connection, a custom timeout, four `OSError` types (one parametrized test)
  and an unexpected exception that must propagate.
- **`tests/test_tcp_integration.py`** — 1 integration test that makes a real
  TCP connection to a temporary listener on `127.0.0.1`. It uses loopback
  only and contacts no external hosts.

## Technologies

- **In use:** Python 3.11, pytest, TCP sockets (`socket` module), Git
- **Planned:** UDP sockets, Linux
- **May be considered later:** Scapy

## Current Status

**In Progress — TCP connectivity milestone complete**
