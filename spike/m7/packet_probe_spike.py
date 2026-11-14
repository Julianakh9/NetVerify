"""TEMPORARY Milestone 7 Phase 0 spike probe. Not production code; never merged.

Runs inside a NetVerify-owned namespace as the calling (non-root) user,
started by run_spike.py. Imports Scapy, opens a packet socket on the given
veth interface only, and prints one JSON line describing everything it
observed: identity, capability sets at each stage, the owner of the packet
socket, Scapy log records, Python warnings, subprocesses Scapy started, and
the packet outcome.

    packet_probe_spike.py caps --iface IFACE
    packet_probe_spike.py icmp --iface IFACE --address ADDR [--timeout S]
    packet_probe_spike.py arp  --iface IFACE --address ADDR --expected-mac MAC [--timeout S]

Exit status is 0 whenever a JSON line was printed; failures are data.
"""

import argparse
import json
import logging
import os
import secrets
import select
import shutil
import subprocess
import sys
import tempfile
import time
import warnings

START = time.monotonic()
MAX_TIMEOUT = 10.0
STATUS_FIELDS = ("Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
                 "NoNewPrivs")

# Record Scapy log records (warnings about routes, MAC resolution, ...).
LOG: list[str] = []


class _ListHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        if len(LOG) < 40:
            LOG.append(f"{record.levelname} {record.name}: {record.getMessage()}"[:300])


logging.getLogger("scapy").addHandler(_ListHandler())

# Record any subprocess Scapy starts: it would inherit CAP_NET_RAW.
SPAWNED: list[list[str]] = []
_original_popen_init = subprocess.Popen.__init__


def _recording_popen_init(self, args, *rest, **kwargs):  # type: ignore[no-untyped-def]
    SPAWNED.append([args] if isinstance(args, (str, bytes)) else [str(a) for a in args])
    return _original_popen_init(self, args, *rest, **kwargs)


subprocess.Popen.__init__ = _recording_popen_init  # type: ignore[method-assign]

STAGE = "start"


def status() -> dict[str, str]:
    fields = {}
    with open("/proc/self/status") as f:
        for line in f:
            key, _, value = line.partition(":")
            if key in STATUS_FIELDS:
                fields[key] = " ".join(value.split())
    return fields


def open_sockets() -> int:
    """How many sockets this process still has open (any kind)."""
    count = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            count += os.readlink(f"/proc/self/fd/{fd}").startswith("socket:")
        except OSError:
            pass  # The fd used by listdir itself is already closed.
    return count


def socket_owner_uid(sock) -> str | None:  # type: ignore[no-untyped-def]
    """The User column of /proc/self/net/packet for this packet socket."""
    inode = str(os.fstat(sock.fileno()).st_ino)
    with open("/proc/self/net/packet") as f:
        header = f.readline().split()
        for line in f:
            row = dict(zip(header, line.split()))
            if row.get("Inode") == inode:
                return row.get("User")
    return None


def receive(sock, deadline: float, accept, seen: list[str]):  # type: ignore[no-untyped-def]
    """Read packets until accept(pkt) returns a value or the deadline passes."""
    while (remaining := deadline - time.monotonic()) > 0:
        ready, _, _ = select.select([sock], [], [], remaining)
        if not ready:
            break
        pkt = sock.recv()
        if pkt is None:
            continue
        if len(seen) < 30:
            seen.append(pkt.summary()[:120])
        verdict = accept(pkt)
        if verdict is not None:
            return verdict
    return None


def run_icmp(args: argparse.Namespace, out: dict) -> None:
    global STAGE
    from scapy.all import ICMP, IP, Raw, conf, IPerror, ICMPerror

    ident, seq, payload = secrets.randbelow(0xFFFF) + 1, 1, secrets.token_bytes(16)
    out["request"] = {"id": ident, "seq": seq, "payload_bytes": len(payload)}
    STAGE = "open L3 socket"
    sock = conf.L3socket(iface=args.iface, promisc=False)
    try:
        out["caps_after_open"] = status()
        out["socket_owner_uid"] = socket_owner_uid(sock)
        STAGE = "send"
        sent_at = time.monotonic()
        sock.send(IP(dst=args.address) / ICMP(id=ident, seq=seq) / Raw(payload))
        out["send_seconds"] = round(time.monotonic() - sent_at, 4)
        out["caps_after_send"] = status()

        def accept(pkt):  # type: ignore[no-untyped-def]
            ip, icmp = pkt.getlayer(IP), pkt.getlayer(ICMP)
            if ip is None or icmp is None:
                return None
            if icmp.type == 0 and icmp.id == ident and icmp.seq == seq:
                return {"kind": "echo_reply", "src": ip.src,
                        "payload_match": bytes(icmp.payload) == payload}
            inner = pkt.getlayer(ICMPerror)
            if icmp.type in (3, 11) and inner is not None and inner.id == ident:
                return {"kind": "icmp_error", "type": icmp.type, "code": icmp.code,
                        "src": ip.src, "quoted_dst": pkt.getlayer(IPerror).dst}
            return None

        STAGE = "receive"
        seen: list[str] = []
        start = time.monotonic()
        verdict = receive(sock, start + args.timeout, accept, seen)
        out["receive_seconds"] = round(time.monotonic() - start, 4)
        out["outcome"] = verdict or {"kind": "timeout"}
        out["seen"] = seen
        out["caps_after_receive"] = status()
    finally:
        sock.close()


def run_arp(args: argparse.Namespace, out: dict) -> None:
    global STAGE
    from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr

    STAGE = "read interface addresses"
    my_mac, my_ip = get_if_hwaddr(args.iface), get_if_addr(args.iface)
    out["source"] = {"mac": my_mac, "ip": my_ip}
    STAGE = "open L2 socket"
    sock = conf.L2socket(iface=args.iface, promisc=False)
    try:
        out["caps_after_open"] = status()
        out["socket_owner_uid"] = socket_owner_uid(sock)
        STAGE = "send"
        sent_at = time.monotonic()
        sock.send(Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac)
                  / ARP(op=1, hwsrc=my_mac, psrc=my_ip, hwdst="00:00:00:00:00:00",
                        pdst=args.address))
        out["send_seconds"] = round(time.monotonic() - sent_at, 4)
        out["caps_after_send"] = status()

        def accept(pkt):  # type: ignore[no-untyped-def]
            arp = pkt.getlayer(ARP)
            if arp is None or arp.op != 2 or arp.psrc != args.address or arp.pdst != my_ip:
                return None
            mac = arp.hwsrc.lower()
            return {"kind": "arp_reply", "mac": mac,
                    "mac_match": mac == args.expected_mac.lower(),
                    "ether_src": pkt.getlayer(Ether).src.lower()}

        STAGE = "receive"
        seen: list[str] = []
        start = time.monotonic()
        verdict = receive(sock, start + args.timeout, accept, seen)
        out["receive_seconds"] = round(time.monotonic() - start, 4)
        out["outcome"] = verdict or {"kind": "timeout"}
        out["seen"] = seen
        out["caps_after_receive"] = status()
    finally:
        sock.close()


def run_caps(args: argparse.Namespace, out: dict) -> None:
    global STAGE
    from scapy.all import conf

    STAGE = "open L2 socket"
    sock = conf.L2socket(iface=args.iface, promisc=False)
    try:
        out["caps_after_open"] = status()
        out["socket_owner_uid"] = socket_owner_uid(sock)
    finally:
        sock.close()


def main() -> int:
    global STAGE
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["caps", "icmp", "arp"])
    parser.add_argument("--iface", required=True)
    parser.add_argument("--address")
    parser.add_argument("--expected-mac")
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()
    if not 0 < args.timeout <= MAX_TIMEOUT:
        parser.error(f"--timeout must be in (0, {MAX_TIMEOUT}]")

    home = os.environ.get("HOME")
    # Run 1 finding: under sudo, HOME is /root, and Scapy fails to import
    # because it cannot create /root/.cache as the calling user. Give Scapy
    # a private, user-owned cache/config folder instead, removed on exit.
    scratch = tempfile.mkdtemp(prefix="netverify-spike-scapy-")
    os.environ["XDG_CACHE_HOME"] = os.path.join(scratch, "cache")
    os.environ["XDG_CONFIG_HOME"] = os.path.join(scratch, "config")
    try:
        return _run(args, home, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _run(args: argparse.Namespace, home: str | None, scratch: str) -> int:
    global STAGE
    out: dict = {
        "command": args.command,
        "resuid": os.getresuid(),
        "resgid": os.getresgid(),
        "groups": os.getgroups(),
        "home": home,
        "home_writable": bool(home) and os.access(home, os.W_OK),
        "caps_start": status(),
    }
    try:
        STAGE = "import scapy"
        began = time.monotonic()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            import scapy
            import scapy.all  # noqa: F401  (initializes conf, routes, sockets)
        out["scapy_version"] = scapy.VERSION
        out["scapy_import_seconds"] = round(time.monotonic() - began, 3)
        out["python_warnings"] = [f"{w.category.__name__}: {w.message}"[:300] for w in caught][:20]
        out["caps_after_import"] = status()
        {"caps": run_caps, "icmp": run_icmp, "arp": run_arp}[args.command](args, out)
    except Exception as exc:  # The spike reports every failure as data.
        out["exception"] = {"stage": STAGE, "type": type(exc).__name__,
                            "errno": getattr(exc, "errno", None), "message": str(exc)[:500]}
    out["caps_end"] = status()
    out["open_sockets_at_end"] = open_sockets()
    out["scapy_files_written"] = sorted(
        os.path.relpath(os.path.join(root, name), scratch)
        for root, dirs, files in os.walk(scratch) for name in dirs + files)[:20]
    out["scapy_log"] = LOG
    out["spawned_subprocesses"] = SPAWNED[:10]
    out["total_seconds"] = round(time.monotonic() - START, 3)
    print(json.dumps(out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
