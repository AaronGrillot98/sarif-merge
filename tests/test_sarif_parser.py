"""Tests for the SARIF v2.1.0 parser."""

import json
from pathlib import Path

import pytest

from sarif_merge.sarif import SarifParseError, load_sarif, parse_findings
from sarif_merge.severity import Severity


def _findings(path: Path):
    doc = load_sarif(path)
    return list(parse_findings(doc))


# ---------- error handling ----------

def test_load_rejects_non_json(tmp_path: Path):
    p = tmp_path / "broken.sarif"
    p.write_text("not json", encoding="utf-8")
    with pytest.raises(SarifParseError, match="not valid JSON"):
        load_sarif(p)


def test_load_rejects_non_object_root(tmp_path: Path):
    p = tmp_path / "weird.sarif"
    p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(SarifParseError, match="must be an object"):
        load_sarif(p)


def test_load_rejects_missing_runs(tmp_path: Path):
    p = tmp_path / "no-runs.sarif"
    p.write_text(json.dumps({"version": "2.1.0"}), encoding="utf-8")
    with pytest.raises(SarifParseError, match="missing 'runs'"):
        load_sarif(p)


def test_load_tolerates_zero_finding_runs(tmp_path: Path):
    p = tmp_path / "empty.sarif"
    p.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ToolA"}}, "results": []}]
    }), encoding="utf-8")
    assert _findings(p) == []


# ---------- per-scanner shape parsing ----------

def test_bandit_parses_with_issue_severity_property(fixtures_dir: Path):
    findings = _findings(fixtures_dir / "bandit.sarif")
    assert len(findings) == 2

    by_rule = {f.rule_id: f for f in findings}
    b602 = by_rule["B602"]
    assert b602.severity == Severity.HIGH
    assert b602.location.file == "src/talonedge/cli.py"
    assert b602.location.line == 42
    assert b602.sources == ("bandit",)


def test_semgrep_parses_security_severity_float(fixtures_dir: Path):
    findings = _findings(fixtures_dir / "semgrep.sarif")
    assert len(findings) == 1
    f = findings[0]
    # 8.5 → HIGH per CVSS-style mapping.
    assert f.severity == Severity.HIGH
    assert f.sources == ("semgrep",)


def test_trivy_extracts_cwe_and_critical_severity(fixtures_dir: Path):
    findings = _findings(fixtures_dir / "trivy.sarif")
    assert len(findings) == 3

    by_rule = {f.rule_id: f for f in findings}
    cve = by_rule["CVE-2026-99999"]
    assert cve.severity == Severity.CRITICAL  # 9.5

    shell = by_rule["TRIVY-PYTHON-CWE-78"]
    assert "78" in shell.cwe


def test_gitleaks_parses(fixtures_dir: Path):
    findings = _findings(fixtures_dir / "gitleaks.sarif")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH  # falls back to result.level=error
    assert findings[0].sources == ("gitleaks",)


def test_tfsec_severity_from_rule_property(fixtures_dir: Path):
    findings = _findings(fixtures_dir / "tfsec.sarif")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_scanner_name_is_lowercased(fixtures_dir: Path):
    # Bandit's SARIF emits `"name": "Bandit"`; we normalize to lowercase.
    findings = _findings(fixtures_dir / "bandit.sarif")
    assert all(f.sources == ("bandit",) for f in findings)


# ---------- path normalization ----------

def test_paths_with_file_uri_are_stripped(tmp_path: Path):
    doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "X"}},
            "results": [{
                "ruleId": "R1",
                "level": "warning",
                "message": {"text": "m"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file:///home/runner/repo/src/app.py"},
                        "region": {"startLine": 1}
                    }
                }]
            }]
        }]
    }
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(doc), encoding="utf-8")
    fs = _findings(p)
    assert fs[0].location.file == "home/runner/repo/src/app.py"


def test_windows_backslashes_are_normalized(tmp_path: Path):
    doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "X"}},
            "results": [{
                "ruleId": "R1",
                "level": "note",
                "message": {"text": "m"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src\\app\\main.py"},
                        "region": {"startLine": 1}
                    }
                }]
            }]
        }]
    }
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(doc), encoding="utf-8")
    fs = _findings(p)
    assert fs[0].location.file == "src/app/main.py"


# ---------- edge cases ----------

def test_result_with_no_locations_uses_unknown_path(tmp_path: Path):
    doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "X"}},
            "results": [{
                "ruleId": "R",
                "level": "warning",
                "message": {"text": "stray"},
                "locations": []
            }]
        }]
    }
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(doc), encoding="utf-8")
    fs = _findings(p)
    assert len(fs) == 1
    assert fs[0].location.file == "(unknown)"
    assert fs[0].location.line == 0


def test_result_with_ruleindex_resolves_rule(tmp_path: Path):
    doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "X",
                    "rules": [
                        {"id": "R0", "name": "first"},
                        {"id": "R1", "name": "second", "properties": {"security-severity": "9.0"}},
                    ]
                }
            },
            "results": [{
                "ruleIndex": 1,
                "level": "warning",
                "message": {"text": "via index"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": 1}
                    }
                }]
            }]
        }]
    }
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(doc), encoding="utf-8")
    fs = _findings(p)
    assert fs[0].rule_id == "R1"
    assert fs[0].severity == Severity.CRITICAL
