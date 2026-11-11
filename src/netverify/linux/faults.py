"""Reversible network faults inside a VethTopology.

A fault changes only an interface that belongs to a test-created topology,
and is undone when its `with` block ends, including when the block raises.
Faults never touch the host: the interfaces exist only inside the
topology's namespaces, and deleting the topology removes them anyway.

Errors are kept separate from other kinds of failure:
    - FaultInjectionError: the fault could not be applied.
    - FaultRestoreError: the original state could not be restored.
    - A VerificationResult with a failure: a check ran and the connection
      failed, which is the expected outcome while a fault is active.
"""

import re
from types import TracebackType

from netverify.linux.commands import CommandError
from netverify.linux.topology import Endpoint, VethTopology

# The flags in `ip -o link show` output, e.g. "<BROADCAST,MULTICAST,UP,LOWER_UP>".
_FLAGS = re.compile(r"<([^>]*)>")


class FaultError(Exception):
    """Base class for fault injection errors. Not a connectivity result."""


class FaultInjectionError(FaultError):
    """The fault could not be applied."""


class FaultRestoreError(FaultError):
    """The interface could not be restored to its original state."""


def link_is_up(topology: VethTopology, endpoint: Endpoint) -> bool:
    """Return whether endpoint's veth interface is administratively up.

    Runs `ip -o link show` inside the namespace as the calling user; reading
    link state needs no privileges.

    Raises:
        CommandError: The command failed.
        ValueError: The output could not be parsed, or endpoint does not
            belong to the topology.
        RuntimeError: The topology is not active.
    """
    return _parse_admin_up(_show_link(topology, endpoint))


def _show_link(topology: VethTopology, endpoint: Endpoint) -> str:
    return topology.run(endpoint, ["ip", "-o", "link", "show", "dev", endpoint.interface]).stdout


def _parse_admin_up(output: str) -> bool:
    match = _FLAGS.search(output)
    if match is None:
        raise ValueError(f"no link flags in `ip link show` output: {output!r}")
    return "UP" in match.group(1).split(",")


class LinkDown:
    """Bring a topology's veth interface down for the duration of a `with` block.

    Usage:
        with LinkDown(topology, topology.left):
            ...  # the link is down here
        # the link is back in its original state here

    On entry, the interface's original state is recorded and the interface is
    set down. On exit, an interface that was up is set up again, and the
    result is checked. If the block raised, that exception is kept and any
    restore failure is attached to it as a note.

    If restoring fails, the interface stays down until the topology is
    closed, which deletes it.
    """

    def __init__(self, topology: VethTopology, endpoint: Endpoint) -> None:
        self.topology = topology
        self.endpoint = endpoint
        self._restore_needed = False

    def __enter__(self) -> "LinkDown":
        # Misuse (a foreign endpoint or an inactive topology) raises
        # ValueError or RuntimeError from the topology here, unwrapped,
        # before anything runs. exec_command() only builds the command.
        self.topology.exec_command(self.endpoint, [])
        try:
            was_up = _parse_admin_up(_show_link(self.topology, self.endpoint))
        except (CommandError, ValueError) as exc:
            raise FaultInjectionError(
                f"Fault injection failed: could not read the state of "
                f"{self._description}. {exc}"
            ) from exc

        # Restore only what was up before; a link that was already down stays down.
        self._restore_needed = was_up
        try:
            self.topology.set_link_state(self.endpoint, up=False)
        except CommandError as exc:
            # The command may still have taken effect (e.g. it timed out), so
            # restore before reporting the failure.
            error = FaultInjectionError(
                f"Fault injection failed: could not bring {self._description} down. {exc}"
            )
            try:
                self._restore()
            except FaultRestoreError as restore_error:
                error.add_note(f"Restoring the link also failed: {restore_error}")
            raise error from exc
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self._restore()
        except FaultRestoreError as restore_error:
            if exc is None:
                raise
            # Keep the original error visible; attach the restore failure.
            exc.add_note(f"Restoring the link also failed: {restore_error}")

    @property
    def _description(self) -> str:
        return f"{self.endpoint.interface} in {self.endpoint.namespace}"

    def _restore(self) -> None:
        if not self._restore_needed:
            return
        try:
            self.topology.set_link_state(self.endpoint, up=True)
            restored = _parse_admin_up(_show_link(self.topology, self.endpoint))
        except (CommandError, ValueError) as exc:
            raise FaultRestoreError(
                f"Fault restore failed: could not bring {self._description} back up. {exc}"
            ) from exc
        if not restored:
            raise FaultRestoreError(
                f"Fault restore failed: {self._description} is still down after `ip link set up`."
            )
        self._restore_needed = False
