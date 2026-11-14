"""Scapy is optional: the core library must import and work without it.

Runs a separate Python process in which every `scapy` import fails, as if
Scapy were not installed, and checks that NetVerify (including the packet
modules) imports, a real loopback TCP check and the CLI work, Scapy is
never loaded, and the packet probe explains what is missing.
"""

import json
import subprocess
import sys
import textwrap

SCRIPT = textwrap.dedent('''
    import importlib.abc, json, socket, sys

    class NoScapy(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name == "scapy" or name.startswith("scapy."):
                raise ModuleNotFoundError(f"No module named {name!r} (blocked by test)")
            return None

    sys.meta_path.insert(0, NoScapy())

    import netverify.cli, netverify.diagnostics, netverify.recovery, netverify.reporting
    import netverify.results, netverify.tcp, netverify.udp
    import netverify.linux
    import netverify.linux.packet, netverify.linux.packet_probe
    import netverify.linux.packet_request, netverify.linux.packet_validation
    from netverify.linux import (link_address, verify_arp_in_namespace,
                                 verify_icmp_echo_in_namespace)
    from netverify.tcp import verify_tcp_connection

    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(8)  # two connections are made and never accepted
        port = server.getsockname()[1]
        passed = verify_tcp_connection("127.0.0.1", port, timeout=2.0)
        cli_code = netverify.cli.main(["tcp", "127.0.0.1", str(port), "--format", "json"])

    probe_code = netverify.linux.packet_probe.main(
        ["arp", "--interface", "nv1l", "--source", "10.231.0.1",
         "--destination", "10.231.0.2", "--timeout", "1"],
        source_mac=lambda interface: "02:00:00:00:00:01")

    print(json.dumps({
        "tcp_success": passed.success,
        "cli_code": cli_code,
        "probe_code": probe_code,
        "scapy_loaded": sorted(m for m in sys.modules if m.split(".")[0] == "scapy"),
    }))
''')


def test_core_imports_and_works_without_scapy():
    process = subprocess.run([sys.executable, "-I", "-c", SCRIPT], capture_output=True,
                             text=True, timeout=60)

    assert process.returncode == 0, process.stderr
    lines = process.stdout.strip().splitlines()
    cli_report, outcome = json.loads(lines[0]), json.loads(lines[-1])
    assert outcome == {"tcp_success": True, "cli_code": 0, "probe_code": 3, "scapy_loaded": []}
    assert cli_report["status"] == "passed"
    assert "Scapy is required for packet checks (pip install 'netverify[packet]')" in (
        process.stderr)
