"""Small command-line probe, run inside a network namespace.

Python 3.11 cannot switch a running process into another network namespace,
so checks run in a separate process started with `ip netns exec`. Results
are printed as one JSON line for the parent process to read.

Usage:
    python -m netverify.linux.probe tcp-connect HOST PORT [--timeout SECONDS]
        Prints a VerificationResult as JSON. Exit status 0 whether or not
        the connection succeeded; the result describes the outcome.

    python -m netverify.linux.probe tcp-listen HOST [--timeout SECONDS]
        Listens on an OS-assigned port, prints {"port": N}, accepts one
        connection, then exits 0. Exits 1 if nothing connects in time.

Nothing here is Linux-specific, so it can also be tested without namespaces.
"""

import argparse
import json
import socket
import sys
from collections.abc import Sequence

from netverify.tcp import verify_tcp_connection


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m netverify.linux.probe",
        description="Run one NetVerify check and print the result as JSON.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    connect = commands.add_parser("tcp-connect", help="verify a TCP connection")
    connect.add_argument("host")
    connect.add_argument("port", type=int)
    connect.add_argument("--timeout", type=float, default=2.0)

    listen = commands.add_parser("tcp-listen", help="accept one TCP connection")
    listen.add_argument("host")
    listen.add_argument("--timeout", type=float, default=10.0)

    args = parser.parse_args(argv)
    if args.command == "tcp-connect":
        result = verify_tcp_connection(args.host, args.port, timeout=args.timeout)
        print(json.dumps(result.to_dict()), flush=True)
        return 0
    return _listen_once(args.host, args.timeout)


def _listen_once(host: str, timeout: float) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((host, 0))
        listener.listen(1)
        # Ready signal: the port is printed only after listen(), so a client
        # that reads it can connect immediately.
        print(json.dumps({"port": listener.getsockname()[1]}), flush=True)
        listener.settimeout(timeout)
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            print(f"no connection within {timeout} seconds", file=sys.stderr)
            return 1
        with connection:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
