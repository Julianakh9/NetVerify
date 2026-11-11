"""CLI integration tests with real sockets on 127.0.0.1.

Nothing is mocked: each test runs the netverify CLI against a real local
server (or a closed port) and checks the output and exit code. Some tests
run the CLI in a separate process, through `python -m netverify` and the
installed `netverify` console script.
"""

import json
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest

from netverify import cli
from netverify.reporting import PAYLOAD_HIDDEN

SERVER_TIMEOUT = 5.0   # Bounds every wait in the UDP server thread.
PROCESS_TIMEOUT = 30.0


@pytest.fixture
def tcp_port():
    """A listening TCP port on 127.0.0.1, owned by the test."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        yield server.getsockname()[1]


@pytest.fixture
def closed_port():
    """A port with nothing listening (bound, then released)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@contextmanager
def udp_server(reply):
    """A one-shot UDP server that answers one datagram with reply(data).

    Yields the port. Errors in the server thread are re-raised here.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
         ThreadPoolExecutor(max_workers=1) as pool:
        server.bind(("127.0.0.1", 0))
        server.settimeout(SERVER_TIMEOUT)

        def serve():
            data, address = server.recvfrom(65535)
            server.sendto(reply(data), address)

        future = pool.submit(serve)
        yield server.getsockname()[1]
        future.result(timeout=SERVER_TIMEOUT + 1)


def run_cli(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_tcp_pass(tcp_port, capsys):
    code, out, _ = run_cli(["tcp", "127.0.0.1", str(tcp_port)], capsys)

    assert code == 0
    assert out.startswith(f"PASS  tcp 127.0.0.1:{tcp_port}")


def test_tcp_refused_is_a_verification_failure(closed_port, capsys):
    code, out, _ = run_cli(["tcp", "127.0.0.1", str(closed_port), "--format", "json"], capsys)

    report = json.loads(out)
    assert code == 1
    assert report["status"] == "failed"
    assert report["result"]["failure"]["reason"] == "connection_refused"


def test_udp_echo_pass(capsys):
    with udp_server(lambda data: data) as port:
        code, out, _ = run_cli(["udp", "127.0.0.1", str(port), "--payload", "hello"], capsys)

    assert code == 0
    assert "echo matched" in out


def test_udp_mismatch_hides_payload(capsys):
    with udp_server(lambda data: b"different-secret") as port:
        code, out, _ = run_cli(["udp", "127.0.0.1", str(port), "--payload", "my-secret",
                                "--format", "json"], capsys)

    report = json.loads(out)
    assert code == 1
    assert report["result"]["failure"]["reason"] == "payload_mismatch"
    assert report["result"]["failure"]["message"] == PAYLOAD_HIDDEN
    assert "secret" not in out


def test_recover_pass_on_a_listening_port(tcp_port, capsys):
    code, out, _ = run_cli(["recover", "127.0.0.1", str(tcp_port), "--deadline", "5",
                            "--format", "json"], capsys)

    report = json.loads(out)
    assert code == 0
    assert report["result"]["recovered_within_deadline"] is True
    assert report["result"]["attempts"] == 1


def test_recover_fails_when_nothing_listens(closed_port, capsys):
    code, out, _ = run_cli(["recover", "127.0.0.1", str(closed_port), "--deadline", "0.6",
                            "--interval", "0.2", "--timeout", "0.5", "--format", "json"], capsys)

    report = json.loads(out)
    assert code == 1
    assert report["status"] == "failed"
    assert report["result"]["recovered"] is False
    assert report["result"]["attempts"] >= 1


# Separate processes: the real entry points and exit statuses.


def run_process(command, *args):
    return subprocess.run([*command, *args], capture_output=True, text=True,
                          timeout=PROCESS_TIMEOUT)


def console_script():
    """The installed `netverify` script, next to this Python interpreter."""
    script = Path(sys.executable).parent / "netverify"
    assert script.exists(), f"console script not installed at {script}; run pip install -e ."
    return [str(script)]


@pytest.mark.parametrize("command", [
    pytest.param([sys.executable, "-m", "netverify"], id="python-m"),
    pytest.param(None, id="console-script"),
])
def test_entry_points_report_exit_codes(command, tcp_port, closed_port):
    command = command or console_script()

    passed = run_process(command, "tcp", "127.0.0.1", str(tcp_port), "--format", "json")
    failed = run_process(command, "tcp", "127.0.0.1", str(closed_port))
    invalid = run_process(command, "tcp", "127.0.0.1", "99999")

    assert passed.returncode == 0
    assert json.loads(passed.stdout)["status"] == "passed"
    assert failed.returncode == 1
    assert failed.stdout.startswith("FAIL")
    assert invalid.returncode == 2
    assert "must be 1-65535" in invalid.stderr
    assert "Traceback" not in invalid.stderr
