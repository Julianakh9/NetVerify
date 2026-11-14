# Milestone 7, Phase 0: Scapy feasibility spike (temporary)

This branch only. Not production code, and never merged into `main`.

The question: can Scapy send and receive ICMP and ARP inside NetVerify's own
namespaces, as the normal (non-root) user, with only `CAP_NET_RAW`?

- `packet_probe_spike.py` runs inside a namespace. It is the only file that
  imports Scapy. It records the UID, the capability sets at each stage,
  which user owns the packet socket, Scapy warnings, and the packet outcome.
- `run_spike.py` builds a topology with the unchanged production
  `VethTopology` and `LinkDown`. It runs the probe with:
  - no capabilities, as a control;
  - a basic `CAP_NET_RAW` variant;
  - a hardened `CAP_NET_RAW` variant, which also limits the bounding set and
    sets no-new-privs.

  Each variant is tested with the link healthy, down, and restored.
- `.github/workflows/m7-scapy-spike.yml` runs it on pushes to this branch.
