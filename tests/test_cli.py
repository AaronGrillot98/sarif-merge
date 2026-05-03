"""End-to-end CLI tests via the in-process main()."""

import json
from pathlib import Path

import pytest

from sarif_merge.cli import main


def test_cli_writes_sarif_and_markdown(all_scanner_files, tmp_path: Path, capsys):
    out_sarif = tmp_path / "merged.sarif"
    out_md = tmp_path / "summary.md"
    rc = main([
        *(str(p) for p in all_scanner_files),
        "--output", str(out_sarif),
        "--markdown", str(out_md),
    ])
    assert rc == 0, capsys.readouterr().err
    assert out_sarif.exists()
    assert out_md.exists()

    doc = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 5

    md = out_md.read_text(encoding="utf-8")
    assert "Security scan summary" in md
    assert "Top findings" in md


def test_cli_writes_to_stdout_when_no_output(all_scanner_files, capsys):
    rc = main([*(str(p) for p in all_scanner_files)])
    captured = capsys.readouterr()
    assert rc == 0
    # stdout should contain valid JSON-shaped SARIF.
    doc = json.loads(captured.out)
    assert doc["version"] == "2.1.0"


def test_cli_fail_on_high_returns_nonzero(all_scanner_files, tmp_path: Path):
    rc = main([
        *(str(p) for p in all_scanner_files),
        "--output", str(tmp_path / "x.sarif"),
        "--fail-on", "high",
    ])
    # Test fixtures contain HIGH and CRITICAL findings.
    assert rc == 1


def test_cli_fail_on_critical_only_with_no_critical_returns_zero(tmp_path: Path):
    """Build a SARIF input that has only HIGH findings, run with --fail-on critical."""
    import json as _json
    only_high = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "x"}},
            "results": [{
                "ruleId": "R", "level": "warning",
                "message": {"text": "medium-only finding"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": 1}
                }}]
            }]
        }]
    }
    p = tmp_path / "only-medium.sarif"
    p.write_text(_json.dumps(only_high), encoding="utf-8")

    rc = main([
        str(p),
        "--output", str(tmp_path / "merged.sarif"),
        "--fail-on", "critical",
    ])
    assert rc == 0


def test_cli_reports_missing_input(tmp_path: Path, capsys):
    rc = main([
        str(tmp_path / "does-not-exist.sarif"),
        "--output", str(tmp_path / "out.sarif"),
    ])
    captured = capsys.readouterr()
    assert rc == 2
    assert "input not found" in captured.err


def test_cli_reports_invalid_sarif(tmp_path: Path, capsys):
    bad = tmp_path / "bad.sarif"
    bad.write_text("not json", encoding="utf-8")
    rc = main([
        str(bad),
        "--output", str(tmp_path / "out.sarif"),
    ])
    captured = capsys.readouterr()
    assert rc == 2
    assert "not valid JSON" in captured.err


def test_cli_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "sarif-merge" in out
