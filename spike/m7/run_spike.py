"""TEMPORARY Milestone 7 Phase 0 spike orchestrator. Not production code; never merged.

Uses the unchanged production VethTopology and LinkDown. Runs
packet_probe_spike.py inside the topology's namespaces as the calling user
with different capability settings, and records what happened.

    run_spike.py collect REPORT.json     run every experiment, write the report
    run_spike.py annotate REPORT.json SECTION   print GitHub ::notice lines
    run_spike.py check REPORT.json       compare observations with expectations

`collect` exits 0 even when experiments fail: failures are findings.
"""

import errno
import json
import os
import platform
import re
import subprocess
import sys
import time
import traceback
from pathlib import Path

from netverify.linux import LinkDown, VethTopology, link_is_up

PROBE = str(Path(__file__).with_name("packet_probe_spike.py").resolve())
SUBCOMMANDS = {"caps", "icmp", "arp"}
PACKET_TIMEOUT = "2"
RUN_TIMEOUT = 45.0  # sudo + namespace entry + Scapy import + packet timeout

# Capability options added to the topology's setpriv prefix. "none" is the
# production prefix unchanged (the negative control).
VARIANTS = {
    "none": [],
    "basic": ["--inh-caps=+net_raw", "--ambient-caps=+net_raw"],
    "hardened": ["--inh-caps=-all,+net_raw", "--ambient-caps=-all,+net_raw",
                 "--bounding-set=-all,+net_raw", "--no-new-privs"],
}
NET_RAW_ONLY = "0000000000002000"  # bit 13: CAP_NET_RAW


def probe_command(topology, endpoint, variant, subcommand, extra):
    """The full command for one probe run. Elevated capabilities are only
    ever added in front of this fixed interpreter + probe script."""
    if subcommand not in SUBCOMMANDS:
        raise ValueError(subcommand)
    argv = topology.exec_command(endpoint, [sys.executable, "-I", PROBE, subcommand, *extra])
    if "setpriv" not in argv:
        raise RuntimeError("expected a setpriv prefix; the spike must not run as root")
    end_of_options = argv.index("--", argv.index("setpriv"))
    return argv[:end_of_options] + VARIANTS[variant] + argv[end_of_options:]


def run_probe(topology, endpoint, variant, subcommand, extra):
    argv = probe_command(topology, endpoint, variant, subcommand, extra)
    began = time.monotonic()
    record = {"variant": variant, "endpoint": endpoint.namespace.rsplit("-", 1)[-1],
              "setpriv_options": VARIANTS[variant]}
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        record.update(error=f"probe timed out after {exc.timeout} s",
                      stderr=(exc.stderr or "")[-1500:] if isinstance(exc.stderr, str) else "")
        record["wall_seconds"] = round(time.monotonic() - began, 3)
        return record
    record["wall_seconds"] = round(time.monotonic() - began, 3)
    record["returncode"] = done.returncode
    record["stderr"] = done.stderr[-1500:]
    lines = done.stdout.strip().splitlines()
    try:
        record["probe"] = json.loads(lines[-1])
    except (IndexError, ValueError):
        record["stdout"] = done.stdout[-1500:]
    return record


def mac_address(topology, endpoint):
    shown = topology.run(endpoint, ["ip", "-o", "link", "show", "dev", endpoint.interface])
    return re.search(r"link/ether (\S+)", shown.stdout).group(1).lower()


def host_snapshot():
    def lines(args):
        return subprocess.run(args, capture_output=True, text=True, check=True,
                              timeout=10).stdout.splitlines()
    links = sorted(line.split(":")[1].strip().split("@")[0]
                   for line in lines(["ip", "-o", "link", "show"]))
    return {"links": links, "ipv4_routes": lines(["ip", "-4", "route", "show"]),
            "ipv6_routes": lines(["ip", "-6", "route", "show"])}


def tool_version(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout.strip()
    except OSError as exc:
        return f"unavailable: {exc}"


def collect(path):
    report = {"environment": {
        "kernel": platform.release(), "python": platform.python_version(),
        "uid": os.getuid(), "gid": os.getgid(),
        "setpriv": tool_version(["setpriv", "--version"]),
        "ip": tool_version(["ip", "-V"]),
    }}
    topology = None
    try:
        if os.geteuid() == 0:
            raise RuntimeError("refusing to run as root: the spike tests the non-root path")
        report["host_before"] = host_snapshot()
        with VethTopology() as topology:
            left, right = topology.left, topology.right
            report["topology"] = {"name": topology.name, "left": left.interface,
                                  "right": right.interface}
            macs = {"left": mac_address(topology, left), "right": mac_address(topology, right)}
            report["macs"] = macs

            caps = {v: run_probe(topology, left, v, "caps", ["--iface", left.interface])
                    for v in VARIANTS}
            report["caps"] = caps
            chosen = next((v for v in ("hardened", "basic") if _caps_ok(caps[v])), None)
            report["chosen_variant"] = chosen
            if chosen is None:
                return  # No non-root variant works; packet experiments cannot run.

            def icmp(src, dst, variant=chosen):
                return run_probe(topology, src, variant, "icmp",
                                 ["--iface", src.interface, "--address", dst.address,
                                  "--timeout", PACKET_TIMEOUT])

            def arp(src, dst, variant=chosen):
                side = "left" if dst is left else "right"
                return run_probe(topology, src, variant, "arp",
                                 ["--iface", src.interface, "--address", dst.address,
                                  "--expected-mac", macs[side], "--timeout", PACKET_TIMEOUT])

            icmp_r, arp_r = report["icmp"], report["arp"] = {}, {}
            icmp_r["healthy"], arp_r["healthy"] = icmp(left, right), arp(left, right)
            icmp_r["healthy_reverse"], arp_r["healthy_reverse"] = icmp(right, left), arp(right, left)
            if chosen != "basic":
                icmp_r["healthy_basic"], arp_r["healthy_basic"] = (
                    icmp(left, right, "basic"), arp(left, right, "basic"))

            with LinkDown(topology, left):
                report["link_left_down_reads_up"] = link_is_up(topology, left)
                icmp_r["source_link_down"] = icmp(left, right)
                arp_r["source_link_down"] = arp(left, right)
            report["link_left_restored_reads_up"] = link_is_up(topology, left)
            icmp_r["source_link_restored"] = icmp(left, right)
            arp_r["source_link_restored"] = arp(left, right)

            with LinkDown(topology, right):
                icmp_r["peer_link_down"] = icmp(left, right)
                arp_r["peer_link_down"] = arp(left, right)
            report["link_right_restored_reads_up"] = link_is_up(topology, right)
            icmp_r["peer_link_restored"] = icmp(left, right)
            arp_r["peer_link_restored"] = arp(left, right)
    except BaseException as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)[:1000],
                           "traceback": traceback.format_exc()[-3000:]}
    finally:
        namespaces = tool_version(["ip", "netns", "list"]).splitlines()
        report["cleanup"] = {
            "namespaces_left": [n for n in namespaces if n.startswith("netverify-")],
            "topology_state": getattr(topology, "_state", None),
        }
        try:
            after = host_snapshot()
            report["cleanup"]["host_unchanged"] = after == report.get("host_before")
            if after != report.get("host_before"):
                report["cleanup"]["host_after"] = after
        except Exception as exc:
            report["cleanup"]["host_check_error"] = repr(exc)
        Path(path).write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))


def _caps_ok(record):
    probe = record.get("probe", {})
    return (not probe.get("exception") and probe.get("resuid", [0])[0] != 0
            and probe.get("caps_after_open", {}).get("CapEff") == NET_RAW_ONLY)


# Reporting: GitHub annotations, which the public API can read back.


def _escape(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _summary(record):
    if "probe" not in record:
        return record
    p = record["probe"]
    keys = ("resuid", "resgid", "groups", "home", "home_writable", "scapy_version",
            "scapy_import_seconds", "socket_owner_uid", "request", "send_seconds",
            "receive_seconds", "outcome", "exception", "python_warnings", "scapy_log",
            "spawned_subprocesses", "open_sockets_at_end", "total_seconds")
    out = {"variant": record["variant"], "from": record["endpoint"],
           "wall_seconds": record["wall_seconds"], "returncode": record.get("returncode")}
    out.update({k: p[k] for k in keys if p.get(k) not in (None, [], {})})
    out["CapEff"] = {stage: p[stage]["CapEff"] for stage in
                     ("caps_start", "caps_after_import", "caps_after_open", "caps_after_send",
                      "caps_after_receive", "caps_end") if stage in p}
    out["seen"] = p.get("seen", [])[:8]
    if record.get("stderr"):
        out["stderr"] = record["stderr"][-400:]
    return out


def annotate(path, section):
    report = json.loads(Path(path).read_text())
    items = []
    if section == "environment":
        items = [("environment", report["environment"]),
                 ("chosen_variant", report.get("chosen_variant")),
                 ("macs", report.get("macs")), ("error", report.get("error"))]
    elif section == "caps":
        for variant, record in report.get("caps", {}).items():
            p = record.get("probe", {})
            items.append((f"caps {variant}", {
                "setpriv_options": record.get("setpriv_options"),
                "resuid": p.get("resuid"), "groups": p.get("groups"),
                "status_after_open": p.get("caps_after_open") or p.get("caps_after_import"),
                "socket_owner_uid": p.get("socket_owner_uid"),
                "home": p.get("home"), "scapy_import_seconds": p.get("scapy_import_seconds"),
                "scapy_files_written": p.get("scapy_files_written"),
                "python_warnings": p.get("python_warnings"), "scapy_log": p.get("scapy_log"),
                "spawned_subprocesses": p.get("spawned_subprocesses"),
                "exception": p.get("exception"), "stderr": record.get("stderr", "")[-300:],
                "error": record.get("error")}))
    elif section in ("icmp", "arp"):
        items = [(f"{section} {name}", _summary(r))
                 for name, r in report.get(section, {}).items()]
    elif section == "cleanup":
        items = [("cleanup", report.get("cleanup")),
                 ("link states", {k: v for k, v in report.items() if k.startswith("link_")})]
    for title, value in items:
        if value is not None:
            print(f"::notice title=spike {title}::{_escape(json.dumps(value))}")


def check(path):
    report = json.loads(Path(path).read_text())
    uid = report["environment"]["uid"]
    results = []

    def expect(name, condition):
        results.append((name, bool(condition)))

    def outcome(section, name):
        return report.get(section, {}).get(name, {}).get("probe", {}).get("outcome", {})

    control = report.get("caps", {}).get("none", {}).get("probe", {})
    # Run 1 showed a PermissionError from `import scapy` can pass for this,
    # so the refusal must come from opening the packet socket.
    control_error = control.get("exception") or {}
    expect("control without CAP_NET_RAW is refused when opening the packet socket",
           control_error.get("type") == "PermissionError"
           and control_error.get("stage") == "open L2 socket")
    expect("Scapy imported in every variant",
           all((r.get("probe", {}).get("exception") or {}).get("stage") != "import scapy"
               for r in report.get("caps", {}).values()))
    for variant in ("basic", "hardened"):
        expect(f"{variant} CAP_NET_RAW variant opens a packet socket as uid {uid}",
               _caps_ok(report.get("caps", {}).get(variant, {})))
    hardened = report.get("caps", {}).get("hardened", {}).get("probe", {})
    hardened_status = hardened.get("caps_after_open", {})
    expect("hardened variant: bounding set is CAP_NET_RAW only and no-new-privs is set",
           hardened_status.get("CapBnd") == NET_RAW_ONLY
           and hardened_status.get("NoNewPrivs") == "1")
    expect("packet experiments used the hardened variant",
           report.get("chosen_variant") == "hardened")

    # Every packet run, whichever path it takes: the calling user, only
    # CAP_NET_RAW at every stage that was observed, no socket left open,
    # and a normal exit.
    for section in ("icmp", "arp"):
        for name, record in report.get(section, {}).items():
            p = record.get("probe", {})
            observed = [p[key]["CapEff"] for key in p
                        if key.startswith("caps_") and isinstance(p[key], dict)]
            expect(f"{section} {name}: uid {uid}, only CAP_NET_RAW at all "
                   f"{len(observed)} observed stages, no open sockets at exit",
                   record.get("returncode") == 0
                   and p.get("resuid") == [uid] * 3
                   and observed and set(observed) == {NET_RAW_ONLY}
                   and p.get("open_sockets_at_end") == 0)

    # Path 1: the socket opened. It must be owned by the calling user, and
    # CAP_NET_RAW must be the only capability through open, send and receive.
    opened = ("healthy", "healthy_reverse", "healthy_basic", "source_link_restored",
              "peer_link_down", "peer_link_restored")
    for section in ("icmp", "arp"):
        for name in opened:
            p = report.get(section, {}).get(name, {}).get("probe", {})
            stages = [p.get(s, {}).get("CapEff")
                      for s in ("caps_after_open", "caps_after_send", "caps_after_receive")]
            expect(f"{section} {name}: socket opened, owned by uid {uid}, CAP_NET_RAW only "
                   "after open, send and receive",
                   p.get("exception") is None
                   and p.get("socket_owner_uid") == str(uid)
                   and stages == [NET_RAW_ONLY] * 3)

    # Path 2: the source interface is down. Opening the socket must fail
    # with ENETDOWN, so no socket owner or post-open observation can exist.
    for section, stage in (("icmp", "open L3 socket"), ("arp", "open L2 socket")):
        p = report.get(section, {}).get("source_link_down", {}).get("probe", {})
        error = p.get("exception") or {}
        expect(f"{section} source_link_down: OSError ENETDOWN ({errno.ENETDOWN}) at "
               f"'{stage}', with no socket owner or post-open observations",
               error.get("type") == "OSError" and error.get("errno") == errno.ENETDOWN
               and error.get("stage") == stage
               and "socket_owner_uid" not in p
               and not any(k in p for k in ("caps_after_open", "caps_after_send",
                                            "caps_after_receive"))
               and "outcome" not in p)

    for name in ("healthy", "healthy_reverse", "healthy_basic", "source_link_restored",
                 "peer_link_restored"):
        expect(f"icmp {name}: echo reply from the target with matching payload",
               outcome("icmp", name).get("kind") == "echo_reply"
               and outcome("icmp", name).get("payload_match"))
        expect(f"arp {name}: reply with the expected MAC",
               outcome("arp", name).get("kind") == "arp_reply"
               and outcome("arp", name).get("mac_match"))
    for section in ("icmp", "arp"):
        expect(f"{section} peer_link_down: timeout, no reply",
               outcome(section, "peer_link_down").get("kind") == "timeout")
    expect("link reads down during the fault and up after each restore",
           report.get("link_left_down_reads_up") is False
           and report.get("link_left_restored_reads_up") is True
           and report.get("link_right_restored_reads_up") is True)
    cleanup = report.get("cleanup", {})
    expect("no namespaces left", cleanup.get("namespaces_left") == [])
    expect("host links and routes unchanged", cleanup.get("host_unchanged") is True)
    expect("no orchestrator error", "error" not in report)

    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"::error title=spike expectation failed::{_escape(name)}")
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    command, path = sys.argv[1], sys.argv[2]
    if command == "collect":
        collect(path)
        sys.exit(0)
    if command == "annotate":
        annotate(path, sys.argv[3])
        sys.exit(0)
    sys.exit(check(path))
