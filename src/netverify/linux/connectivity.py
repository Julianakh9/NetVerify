"""Connectivity checks between the namespaces of a topology.

Errors are kept in three separate groups:
    - TopologySetupError: the topology itself could not be built.
    - CommandError / ProbeError: the probe could not run or misbehaved.
    - A VerificationResult with a failure: the network check ran and failed.
"""

import json
import selectors
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager

from netverify.linux.topology import Endpoint, VethTopology
from netverify.results import VerificationResult

# -I isolates the probe from environment variables and the current directory.
PROBE = [sys.executable, "-I", "-m", "netverify.linux.probe"]

# Extra time allowed for sudo, namespace entry and Python startup.
PROBE_OVERHEAD = 15.0

# How long to wait for a stopped listener to exit.
STOP_TIMEOUT = 5.0


class ProbeError(Exception):
    """The probe failed to produce a result. This is not a connectivity result."""


def verify_tcp_in_namespace(
    topology: VethTopology,
    source: Endpoint,
    host: str,
    port: int,
    *,
    timeout: float = 2.0,
) -> VerificationResult:
    """Run verify_tcp_connection(host, port) from inside source's namespace.

    Returns:
        The VerificationResult produced inside the namespace.

    Raises:
        CommandError: The probe process could not run or exited with an error.
        ProbeError: The probe ran but did not print a valid result.
    """
    args = [*PROBE, "tcp-connect", host, str(port), "--timeout", str(timeout)]
    completed = topology.run(source, args, timeout=timeout + PROBE_OVERHEAD)
    return _parse_result(completed.stdout)


@contextmanager
def tcp_listener(
    topology: VethTopology, endpoint: Endpoint, *, timeout: float = 10.0
) -> Iterator[int]:
    """Run a one-shot TCP listener on endpoint.address inside its namespace.

    Yields the port once the listener is ready. The listener accepts one
    connection and exits; if nothing connects it exits after timeout
    seconds. If the block raises, or the listener never reports its port,
    the listener is stopped at once instead of being waited for.

    Raises:
        ProbeError: The listener did not report a port in time, or exited first.
    """
    args = [*PROBE, "tcp-listen", endpoint.address, "--timeout", str(timeout)]
    process = topology.popen(endpoint, args)
    try:
        yield _wait_for_port(process, timeout + PROBE_OVERHEAD)
    except BaseException:
        _stop(process)
        raise
    else:
        try:
            process.communicate(timeout=timeout + PROBE_OVERHEAD)
        except subprocess.TimeoutExpired:
            _stop(process)


def _stop(process: subprocess.Popen[str]) -> None:
    """Terminate the process and reap it, waiting a bounded time.

    SIGTERM, not SIGKILL: when the process is `sudo`, sudo relays SIGTERM
    to the command it runs, but SIGKILL would kill sudo alone and leave the
    command running. If the signal is refused or the process does not exit,
    the pipes are closed and topology.close() kills what remains in the
    namespace.
    """
    try:
        process.terminate()
    except PermissionError:
        pass  # e.g. sudo running as root; topology.close() is the backstop.
    try:
        process.communicate(timeout=STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()


def _wait_for_port(process: subprocess.Popen[str], timeout: float) -> int:
    assert process.stdout is not None
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise ProbeError(f"TCP listener did not report its port within {timeout} seconds")

    line = process.stdout.readline()
    if not line:
        # Output closed without a port: the listener exited early.
        _, stderr = process.communicate(timeout=timeout)
        raise ProbeError(
            f"TCP listener exited with status {process.returncode} before "
            f"reporting its port: {stderr.strip()}"
        )
    try:
        return int(json.loads(line)["port"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ProbeError(f"TCP listener printed an invalid ready line: {line!r}") from exc


def _parse_result(stdout: str) -> VerificationResult:
    lines = stdout.strip().splitlines()
    if not lines:
        raise ProbeError("probe printed no result")
    try:
        return VerificationResult.from_dict(json.loads(lines[-1]))
    except (ValueError, KeyError, TypeError) as exc:
        raise ProbeError(f"probe printed an invalid result: {lines[-1]!r}") from exc
