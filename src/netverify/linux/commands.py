"""Running external commands safely, with informative errors."""

import shlex
import subprocess
from collections.abc import Sequence

# Upper bound for one command. Setup commands finish in milliseconds; this
# only stops a hung command from blocking forever.
DEFAULT_TIMEOUT = 30.0


class CommandError(Exception):
    """An external command could not run, failed, or timed out.

    Attributes:
        command: The argument list that was run.
        returncode: Exit status, or None if the command never finished.
        stdout: Captured standard output.
        stderr: Captured standard error.
    """

    def __init__(
        self,
        command: Sequence[str],
        returncode: int | None,
        stdout: str,
        stderr: str,
        reason: str,
    ) -> None:
        self.command = list(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        message = f"Command {reason}: {shlex.join(self.command)}"
        if stderr.strip():
            message += f"\nstderr: {stderr.strip()}"
        super().__init__(message)


def run_command(
    args: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT
) -> subprocess.CompletedProcess[str]:
    """Run a command from an argument list (never through a shell).

    Returns:
        The completed process, with stdout and stderr captured as text.

    Raises:
        CommandError: If the command is not found, exits with a non-zero
            status, or does not finish within timeout seconds.
    """
    command = list(args)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise CommandError(command, None, "", "", "not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(
            command,
            None,
            _as_text(exc.stdout),
            _as_text(exc.stderr),
            f"timed out after {timeout} seconds",
        ) from exc

    if completed.returncode != 0:
        raise CommandError(
            command,
            completed.returncode,
            completed.stdout,
            completed.stderr,
            f"failed with exit status {completed.returncode}",
        )
    return completed


def _as_text(output: str | bytes | None) -> str:
    # TimeoutExpired may hold bytes even when text=True was requested.
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output
