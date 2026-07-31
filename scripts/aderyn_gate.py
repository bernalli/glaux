"""Fail CI on Aderyn High findings, by reading the report rather than the exit code.

Aderyn **always exits 0** — verified in its own `driver.rs` — so a gate wired to
its exit status is green forever, including on a run that found real bugs. This
script is the gate: it parses the JSON report and fails on a non-empty
`high_issues.issues`.

Just as important, it fails *closed*. A missing, unreadable, or unexpectedly
shaped report means the analysis did not happen, which is not the same as
"nothing was found" — a silent aderyn failure must never be indistinguishable
from a clean run. That case exits 2.

Findings that were triaged as false positives are suppressed at the code with
`// aderyn-fp-next-line`, each one carrying the reasoning next to what it
describes; the full triage lives in `docs/static-analysis.md`. Suppressing here,
in the gate, would hide them from anyone reading the source.

Exit codes:
    0 - no High findings
    1 - at least one High finding (each is printed)
    2 - the report could not be used, so nothing was verified

Usage:
    python3 scripts/aderyn_gate.py --report report.json
"""

import argparse
import json
import sys
from typing import Any

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_UNUSABLE = 2


class UnusableReport(Exception):
    """The report cannot be trusted to answer "were there High findings?".

    Deliberately not a `TypeError`, even where the cause is a shape mismatch: a
    malformed report is an expected outcome of an external tool misbehaving, not
    a bug in this module, and the two must not be caught by the same handler.
    """


def load_report(path: str) -> dict[str, Any]:
    """Read the Aderyn JSON report.

    Raises `UnusableReport` with a human-readable reason if the file is missing
    or is not valid JSON, so the caller can fail closed rather than assume clean.
    """
    try:
        with open(path, encoding="utf-8") as report_file:
            report = json.load(report_file)
    except FileNotFoundError as exc:
        raise UnusableReport(f"report not found at {path} — did aderyn run?") from exc
    except json.JSONDecodeError as exc:
        raise UnusableReport(f"report at {path} is not valid JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise UnusableReport(f"report at {path} is not a JSON object")
    return report


def extract_high_issues(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull `high_issues.issues` out of the report.

    A report without that path is treated as unusable rather than as clean: the
    key is absent when aderyn changed its schema or wrote a partial file, and
    reading either as "no findings" is the failure mode this gate exists to
    prevent.
    """
    high_issues = report.get("high_issues")
    if not isinstance(high_issues, dict):
        raise UnusableReport("report has no `high_issues` object — schema changed?")
    issues = high_issues.get("issues")
    if not isinstance(issues, list):
        raise UnusableReport(
            "report has no `high_issues.issues` list — schema changed?"
        )
    return issues


def format_issue(issue: dict[str, Any]) -> list[str]:
    """Render one finding as one line per flagged instance."""
    title = issue.get("title", "<untitled detector>")
    instances = issue.get("instances")
    if not isinstance(instances, list) or not instances:
        return [f"  {title}"]
    lines = []
    for instance in instances:
        path = instance.get("contract_path", "<unknown file>")
        line_no = instance.get("line_no", "?")
        lines.append(f"  {path}:{line_no}  {title}")
    return lines


def main() -> int:
    """Parse args, read the report, and return the process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report", required=True, help="path to the aderyn JSON report"
    )
    args = parser.parse_args()

    try:
        issues = extract_high_issues(load_report(args.report))
    except UnusableReport as exc:
        print(f"aderyn gate: UNUSABLE REPORT — {exc}", file=sys.stderr)
        return EXIT_UNUSABLE

    if not issues:
        print("aderyn gate: no High findings")
        return EXIT_CLEAN

    count = sum(len(issue.get("instances") or [1]) for issue in issues)
    print(f"aderyn gate: {count} High finding(s)", file=sys.stderr)
    for issue in issues:
        for line in format_issue(issue):
            print(line, file=sys.stderr)
    print(
        "\nIf one is a false positive, triage it in docs/static-analysis.md and "
        "suppress it at the code with `// aderyn-fp-next-line`, never here.",
        file=sys.stderr,
    )
    return EXIT_FINDINGS


if __name__ == "__main__":
    sys.exit(main())
