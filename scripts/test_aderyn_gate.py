"""Tests for the Aderyn CI gate.

The behaviour that matters most here is failing closed: a gate that treats a
missing or malformed report as "clean" is worse than no gate, because it reports
success for an analysis that never ran.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from aderyn_gate import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_UNUSABLE,
    UnusableReport,
    extract_high_issues,
    format_issue,
    load_report,
)


def write_report(tmp_path: Path, payload: Any) -> str:
    """Write `payload` as a report file and return its path."""
    path = tmp_path / "report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def run_gate(monkeypatch: pytest.MonkeyPatch, report_path: str) -> int:
    """Invoke the gate's `main()` with `--report report_path`."""
    import aderyn_gate

    monkeypatch.setattr("sys.argv", ["aderyn_gate.py", "--report", report_path])
    return aderyn_gate.main()


def test_clean_report_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_report(tmp_path, {"high_issues": {"issues": []}})
    assert run_gate(monkeypatch, path) == EXIT_CLEAN


def test_report_with_high_finding_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_report(
        tmp_path,
        {
            "high_issues": {
                "issues": [
                    {
                        "title": "Storage Array Edited with Memory",
                        "instances": [
                            {"contract_path": "src/GlauxAccount.sol", "line_no": 206}
                        ],
                    }
                ]
            }
        },
    )
    assert run_gate(monkeypatch, path) == EXIT_FINDINGS


def test_missing_report_is_unusable_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An aderyn run that died before writing must fail the build, not pass it."""
    assert run_gate(monkeypatch, str(tmp_path / "absent.json")) == EXIT_UNUSABLE


def test_malformed_json_is_unusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "report.json"
    path.write_text("{ this is not json", encoding="utf-8")
    assert run_gate(monkeypatch, str(path)) == EXIT_UNUSABLE


def test_report_without_high_issues_key_is_unusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A schema change must not be read as an absence of findings."""
    path = write_report(tmp_path, {"low_issues": {"issues": []}})
    assert run_gate(monkeypatch, path) == EXIT_UNUSABLE


def test_high_issues_not_a_list_is_unusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_report(tmp_path, {"high_issues": {"issues": "none"}})
    assert run_gate(monkeypatch, path) == EXIT_UNUSABLE


def test_json_array_at_top_level_is_unusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_report(tmp_path, [])
    assert run_gate(monkeypatch, path) == EXIT_UNUSABLE


def test_load_report_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(UnusableReport, match="did aderyn run"):
        load_report(str(tmp_path / "nope.json"))


def test_extract_high_issues_returns_the_list() -> None:
    issues = [{"title": "x", "instances": []}]
    assert extract_high_issues({"high_issues": {"issues": issues}}) == issues


def test_format_issue_names_file_and_line() -> None:
    lines = format_issue(
        {
            "title": "Yul block contains `return`",
            "instances": [{"contract_path": "src/GlauxDelegate.sol", "line_no": 112}],
        }
    )
    assert lines == ["  src/GlauxDelegate.sol:112  Yul block contains `return`"]


def test_format_issue_survives_an_instance_less_finding() -> None:
    assert format_issue({"title": "detector without instances"}) == [
        "  detector without instances"
    ]
