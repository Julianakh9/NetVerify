"""The netverify command-line interface.

    netverify tcp HOST PORT [--timeout S]
    netverify udp HOST PORT [--payload TEXT] [--show-payload] [--timeout S]
    netverify recover HOST PORT --deadline S [--interval S] [--timeout S]

Every command accepts --format {text,json} and --debug. The commands call
the existing verification APIs (netverify.tcp, netverify.udp,
netverify.recovery); this module only parses arguments, reports results
and chooses the exit code. See netverify.reporting.ExitCode for the codes.
"""

import argparse
import json
import math
import sys
from collections.abc import Callable, Sequence
from importlib.metadata import PackageNotFoundError, version

from netverify.recovery import wait_for_recovery
from netverify.reporting import (
    ExitCode,
    Outcome,
    error_report,
    exit_code_for,
    format_text,
    redact_payload,
    report,
)
from netverify.results import VerificationResult
from netverify.tcp import verify_tcp_connection
from netverify.udp import verify_udp_echo

# The largest UDP payload that fits in one IPv4 datagram.
MAX_UDP_PAYLOAD = 65507

EPILOG = """\
exit codes:
  0    verification passed (recover: success observed within the deadline)
  1    verification failed (the check ran and the target failed it)
  2    invalid input
  3    the check could not run normally (unexpected or infrastructure error)
  130  interrupted
"""


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        # --help or --version (0), or invalid input (2). argparse has
        # already printed the message.
        return exit_.code if isinstance(exit_.code, int) else ExitCode.INVALID_INPUT

    try:
        outcome = args.handler(args)
    except KeyboardInterrupt as exc:
        _report_error(args, exc, ExitCode.INTERRUPTED, "interrupted")
        return ExitCode.INTERRUPTED
    except Exception as exc:
        if args.debug:
            raise
        _report_error(args, exc, ExitCode.INFRASTRUCTURE_ERROR,
                      f"{type(exc).__name__}: {exc} (use --debug for the traceback)")
        return ExitCode.INFRASTRUCTURE_ERROR

    if args.format == "json":
        print(json.dumps(report(args.command, outcome)))
    else:
        print(format_text(args.command, outcome))
    return exit_code_for(outcome)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"], default="text",
                        help="output format (default: text)")
    common.add_argument("--debug", action="store_true",
                        help="show the full traceback for unexpected errors")

    target = argparse.ArgumentParser(add_help=False)
    target.add_argument("host", type=_host, help="host name or IP address")
    target.add_argument("port", type=_port, help="port number (1-65535)")

    parser = argparse.ArgumentParser(
        prog="netverify",
        description="Verify network connectivity and report structured results.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add_command(name: str, help_: str, handler: Callable[[argparse.Namespace], Outcome]
                    ) -> argparse.ArgumentParser:
        command = commands.add_parser(
            name, parents=[target, common], help=help_, description=help_,
            epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        command.set_defaults(handler=handler)
        return command

    tcp = add_command("tcp", "check that a TCP connection can be established", _run_tcp)
    tcp.add_argument("--timeout", type=_seconds, default=2.0,
                     help="socket timeout in seconds (default: 2.0)")

    udp = add_command("udp", "check that a UDP echo service returns the payload sent", _run_udp)
    udp.add_argument("--timeout", type=_seconds, default=2.0,
                     help="socket timeout in seconds (default: 2.0)")
    udp.add_argument("--payload", type=_payload, default=b"netverify-ping",
                     help="text to send, UTF-8 encoded (default: netverify-ping)")
    udp.add_argument("--show-payload", action="store_true",
                     help="include payload contents in mismatch reports (hidden by default)")

    recover = add_command(
        "recover", "poll a TCP connection until it succeeds or a deadline passes", _run_recover
    )
    recover.add_argument("--deadline", type=_seconds, required=True,
                         help="seconds within which attempts may start")
    recover.add_argument("--interval", type=_seconds, default=0.5,
                         help="seconds between attempts (default: 0.5)")
    recover.add_argument("--timeout", type=_seconds, default=2.0,
                         help="largest timeout for one attempt, in seconds (default: 2.0)")
    return parser


# Command handlers: each calls an existing API and returns its result.


def _run_tcp(args: argparse.Namespace) -> VerificationResult:
    return verify_tcp_connection(args.host, args.port, timeout=args.timeout)


def _run_udp(args: argparse.Namespace) -> VerificationResult:
    result = verify_udp_echo(args.host, args.port, payload=args.payload, timeout=args.timeout)
    return result if args.show_payload else redact_payload(result)


def _run_recover(args: argparse.Namespace) -> Outcome:
    return wait_for_recovery(
        lambda timeout: verify_tcp_connection(args.host, args.port, timeout=timeout),
        deadline=args.deadline,
        interval=args.interval,
        attempt_timeout=args.timeout,
    )


def _report_error(args: argparse.Namespace, error: BaseException, code: ExitCode,
                  message: str) -> None:
    print(f"netverify: error: {message}", file=sys.stderr)
    if args.format == "json":
        print(json.dumps(error_report(args.command, error, code)))


# Argument types. Raising ArgumentTypeError makes argparse print a usage
# error and exit with status 2, without a traceback.


def _host(text: str) -> str:
    if not text or text != text.strip():
        raise argparse.ArgumentTypeError(f"invalid host {text!r}")
    try:
        text.encode("idna")  # The same encoding socket uses for host names.
    except UnicodeError:
        raise argparse.ArgumentTypeError(f"invalid host name {text!r}") from None
    return text


def _port(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port {text!r}: not a number") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"invalid port {port}: must be 1-65535")
    return port


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number of seconds {text!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"invalid number of seconds {text!r}: must be positive")
    return value


def _payload(text: str) -> bytes:
    data = text.encode("utf-8")
    if not 1 <= len(data) <= MAX_UDP_PAYLOAD:
        raise argparse.ArgumentTypeError(
            f"payload must be 1-{MAX_UDP_PAYLOAD} bytes, got {len(data)}"
        )
    return data


def _version() -> str:
    try:
        return version("netverify")
    except PackageNotFoundError:
        return "unknown"


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())


if __name__ == "__main__":
    run()
