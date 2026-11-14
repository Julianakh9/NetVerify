"""Shared pytest configuration.

In GitHub Actions only, add one annotation summarizing the run: outcome
counts and the names of the namespace (netns) tests that passed. Job logs
need a signed-in user to read, but check-run annotations are public, so
this lets anyone confirm which Linux tests actually ran. Nothing changes
elsewhere.
"""

import json
import os


def pytest_terminal_summary(terminalreporter):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    stats = terminalreporter.stats

    def reports(outcome):
        return [r for r in stats.get(outcome, []) if getattr(r, "when", "call") in ("call", "setup")]

    summary = {
        "passed": len(reports("passed")),
        "failed": len(reports("failed")),
        "errors": len(stats.get("error", [])),
        "skipped": len(stats.get("skipped", [])),
        "netns_passed": sorted(r.nodeid.split("::")[-1] for r in reports("passed")
                               if "netns" in r.keywords),
        "failed_tests": sorted(r.nodeid for r in reports("failed"))[:20],
    }
    message = json.dumps(summary)
    for raw, escaped in (("%", "%25"), ("\r", "%0D"), ("\n", "%0A")):
        message = message.replace(raw, escaped)
    terminalreporter.write_line(f"::notice title=pytest summary::{message}")
