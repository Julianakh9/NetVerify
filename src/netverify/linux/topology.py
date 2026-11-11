"""Two Linux network namespaces connected by a veth pair.

Safety properties:
    - Both veth ends are created directly inside their namespaces, so no
      interface, address or route is ever added to the host.
    - Resource names contain a random token, so they cannot clash with
      existing resources or with other topologies.
    - Cleanup deletes only namespaces this object created. Deleting a
      namespace also destroys the veth end inside it.
    - Only the `ip` setup/cleanup commands are privileged. Commands run in
      a namespace drop back to the calling user after entering it.
"""

import ipaddress
import os
import secrets
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from itertools import islice
from types import TracebackType

from netverify.linux.commands import DEFAULT_TIMEOUT, CommandError, run_command

# A runner takes an argument list (and an optional timeout keyword) and
# returns a CompletedProcess or raises CommandError. Tests inject fakes.
Runner = Callable[..., subprocess.CompletedProcess[str]]

DEFAULT_NETWORK = "10.231.0.0/30"
NAME_PREFIX = "netverify"


class TopologyError(Exception):
    """Base class for topology lifecycle errors."""


class TopologySetupError(TopologyError):
    """The topology could not be created. This is not a connectivity result."""


class TopologyCleanupError(TopologyError):
    """One or more resources created by the topology could not be removed."""


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One side of the topology: a namespace and its veth interface."""

    namespace: str
    interface: str
    address: str
    prefix_length: int

    @property
    def cidr(self) -> str:
        """The interface address in CIDR notation, e.g. "10.231.0.1/30"."""
        return f"{self.address}/{self.prefix_length}"


def privilege_prefix() -> list[str]:
    """Prefix for privileged commands: none as root, otherwise `sudo -n`.

    `-n` makes sudo fail immediately instead of prompting for a password.
    """
    return [] if os.geteuid() == 0 else ["sudo", "-n"]


def missing_prerequisites(runner: Runner = run_command) -> list[str]:
    """Return what is missing to run namespace topologies here (empty if none)."""
    if not sys.platform.startswith("linux"):
        return [f"Linux (this platform is {sys.platform})"]

    missing = []
    if shutil.which("ip") is None:
        missing.append("the 'ip' command from iproute2")
    if os.geteuid() != 0:
        if shutil.which("setpriv") is None:
            missing.append("the 'setpriv' command from util-linux")
        if shutil.which("sudo") is None:
            missing.append("root privileges or sudo")
        else:
            try:
                runner(["sudo", "-n", "true"], timeout=10)
            except CommandError:
                missing.append("root privileges or passwordless sudo ('sudo -n true' failed)")
    return missing


class VethTopology:
    """Two uniquely named namespaces ("left" and "right") joined by a veth pair.

    Usage:
        with VethTopology() as topology:
            topology.run(topology.left, ["ip", "address", "show"])

    The left endpoint gets the first host address of `network`, the right
    endpoint the second. Addresses exist only inside the namespaces.
    """

    def __init__(
        self,
        network: str = DEFAULT_NETWORK,
        *,
        runner: Runner = run_command,
        privilege: Sequence[str] | None = None,
        drop_privileges: Sequence[str] | None = None,
    ) -> None:
        """
        Args:
            network: IPv4 network for the veth link; needs two host addresses.
            runner: Runs commands. Defaults to run_command.
            privilege: Prefix for privileged commands. Defaults to
                privilege_prefix().
            drop_privileges: Command prefix used after entering a namespace
                to run as the calling user. Defaults to setpriv when not root.

        Raises:
            ValueError: If network is not an IPv4 network with two host addresses.
        """
        net = ipaddress.IPv4Network(network)
        hosts = list(islice(net.hosts(), 2))
        if len(hosts) < 2:
            raise ValueError(f"network {network} needs at least two host addresses")

        token = secrets.token_hex(4)
        self.name = f"{NAME_PREFIX}-{token}"
        # Interface names are limited to 15 characters: "nv" + 8 hex + 1.
        self.left = Endpoint(f"{self.name}-left", f"nv{token}l", str(hosts[0]), net.prefixlen)
        self.right = Endpoint(f"{self.name}-right", f"nv{token}r", str(hosts[1]), net.prefixlen)

        self._run = runner
        self._privilege = list(privilege_prefix() if privilege is None else privilege)
        if drop_privileges is None:
            drop_privileges = _default_drop_privileges(self._privilege)
        self._drop_privileges = list(drop_privileges)
        self._created_namespaces: list[str] = []
        self._state = "new"

    # Lifecycle

    def setup(self) -> None:
        """Create both namespaces, the veth pair, and configure the interfaces.

        If any step fails, everything created so far is removed before the
        error is raised. If that cleanup also fails, the failure is attached
        to the setup error as a note, and close() can retry it.

        Raises:
            TopologySetupError: A setup step failed. The message names the
                step and includes the command's stderr.
            RuntimeError: setup() was already called.
        """
        if self._state != "new":
            raise RuntimeError("setup() can only be called once per topology")
        self._state = "setting-up"
        try:
            self._create_namespace(self.left.namespace)
            self._create_namespace(self.right.namespace)
            self._setup_step(
                "create the veth pair",
                [
                    "ip", "link", "add", self.left.interface, "netns", self.left.namespace,
                    "type", "veth",
                    "peer", "name", self.right.interface, "netns", self.right.namespace,
                ],
            )
            for endpoint in (self.left, self.right):
                self._configure_endpoint(endpoint)
        except BaseException as exc:
            try:
                self._cleanup()
            except TopologyCleanupError as cleanup_error:
                exc.add_note(f"Cleanup after the failed setup also failed: {cleanup_error}")
            raise
        self._state = "active"

    def close(self) -> None:
        """Remove everything this topology created. Safe to call repeatedly.

        The topology counts as closed only once every namespace it created
        is gone. If a deletion fails, calling close() again retries only the
        namespaces that are still left.

        Raises:
            TopologyCleanupError: A namespace could not be deleted. Every
                namespace is still attempted before this is raised.
        """
        if self._state != "closed":
            self._cleanup()

    def _cleanup(self) -> None:
        # "cleanup-pending" blocks commands until the namespaces are gone,
        # and stays set if a deletion fails, so that close() can retry.
        self._state = "cleanup-pending"
        self._remove_created_namespaces()
        self._state = "closed"

    def __enter__(self) -> "VethTopology":
        self.setup()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except TopologyCleanupError as cleanup_error:
            if exc is None:
                raise
            # Keep the original error visible; attach the cleanup failure.
            exc.add_note(f"Topology cleanup also failed: {cleanup_error}")

    # Running commands inside a namespace

    def exec_command(self, endpoint: Endpoint, args: Sequence[str]) -> list[str]:
        """Return the full argument list that runs args inside endpoint's namespace."""
        self._require_own_endpoint(endpoint)
        return [
            *self._privilege, "ip", "netns", "exec", endpoint.namespace,
            *self._drop_privileges, *args,
        ]

    def run(
        self, endpoint: Endpoint, args: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT
    ) -> subprocess.CompletedProcess[str]:
        """Run a command inside endpoint's namespace and wait for it.

        Raises:
            CommandError: The command failed, was not found, or timed out.
        """
        return self._run(self.exec_command(endpoint, args), timeout=timeout)

    def popen(
        self, endpoint: Endpoint, args: Sequence[str], *, stdin: int | None = None
    ) -> subprocess.Popen[str]:
        """Start a command inside endpoint's namespace without waiting for it.

        stdout and stderr are pipes in text mode. stdin is passed to Popen
        (for example subprocess.PIPE); by default it is inherited. Processes
        still running in the namespace are stopped by close().
        """
        return subprocess.Popen(
            self.exec_command(endpoint, args),
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    # Link state

    def set_link_state(
        self, endpoint: Endpoint, *, up: bool, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        """Bring endpoint's veth interface administratively up or down.

        Only the topology's own veth interfaces can be changed: the interface
        name comes from the endpoint, and the endpoint must belong to this
        active topology. This is the only privileged command available
        after setup.

        Raises:
            CommandError: The `ip` command failed or timed out.
            RuntimeError: The topology is not active.
            ValueError: endpoint does not belong to this topology.
        """
        self._require_own_endpoint(endpoint)
        state = "up" if up else "down"
        self._run(
            [*self._privilege, "ip", "-n", endpoint.namespace,
             "link", "set", "dev", endpoint.interface, state],
            timeout=timeout,
        )

    # Internal helpers

    def _require_own_endpoint(self, endpoint: Endpoint) -> None:
        self._require_active()
        if endpoint not in (self.left, self.right):
            raise ValueError(f"{endpoint!r} does not belong to this topology")

    def _create_namespace(self, name: str) -> None:
        self._setup_step(f"create namespace {name}", ["ip", "netns", "add", name])
        # Recorded only after it exists, so cleanup never touches a
        # namespace this object did not create.
        self._created_namespaces.append(name)

    def _configure_endpoint(self, endpoint: Endpoint) -> None:
        ns = endpoint.namespace
        self._setup_step(
            f"assign {endpoint.cidr} to {endpoint.interface} in {ns}",
            ["ip", "-n", ns, "address", "add", endpoint.cidr, "dev", endpoint.interface],
        )
        self._setup_step(
            f"bring up {endpoint.interface} in {ns}",
            ["ip", "-n", ns, "link", "set", "dev", endpoint.interface, "up"],
        )
        self._setup_step(
            f"bring up loopback in {ns}",
            ["ip", "-n", ns, "link", "set", "dev", "lo", "up"],
        )

    def _setup_step(self, description: str, args: list[str]) -> None:
        try:
            self._run([*self._privilege, *args])
        except CommandError as exc:
            raise TopologySetupError(
                f"Topology setup failed: could not {description}. {exc}"
            ) from exc

    def _remove_created_namespaces(self) -> None:
        # Only namespaces this object created are in the list, and each is
        # removed from it once deleted, so a retry never touches anything else.
        errors = []
        for namespace in reversed(list(self._created_namespaces)):
            self._stop_processes(namespace)
            try:
                self._run([*self._privilege, "ip", "netns", "delete", namespace])
            except CommandError as exc:
                errors.append(f"could not delete namespace {namespace}: {exc}")
            else:
                self._created_namespaces.remove(namespace)
        if errors:
            raise TopologyCleanupError("Topology cleanup failed: " + " | ".join(errors))

    def _stop_processes(self, namespace: str) -> None:
        """Best effort: kill processes still running in the namespace.

        Without this, a leftover process would keep the namespace (and its
        veth end) alive after its name is deleted. Failures here are not
        fatal; the namespace deletion that follows reports its own errors.
        """
        try:
            listing = self._run([*self._privilege, "ip", "netns", "pids", namespace])
        except CommandError:
            return
        pids = listing.stdout.split()
        if pids:
            try:
                self._run([*self._privilege, "kill", "-KILL", *pids])
            except CommandError:
                pass  # A process may have exited in the meantime.

    def _require_active(self) -> None:
        if self._state != "active":
            raise RuntimeError(f"topology is not active (state: {self._state})")


def _default_drop_privileges(privilege: Sequence[str]) -> list[str]:
    """Run namespace commands as the calling user when setup uses sudo."""
    if not privilege:
        return []  # Already running as root; there is no other user to return to.
    return [
        "setpriv",
        f"--reuid={os.getuid()}",
        f"--regid={os.getgid()}",
        "--clear-groups",
        "--",
    ]
