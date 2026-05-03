"""End-to-end dedup + scoring across multiple scanners."""

from pathlib import Path

from sarif_merge.dedupe import dedupe
from sarif_merge.finding import Finding, Location
from sarif_merge.sarif import load_sarif, parse_findings
from sarif_merge.score import apply_consensus
from sarif_merge.severity import Severity


def _all_findings(paths):
    out = []
    for p in paths:
        out.extend(parse_findings(load_sarif(p)))
    return out


def test_three_scanners_on_same_shell_injection_collapse_to_one(all_scanner_files):
    """Bandit B602, Semgrep dangerous-subprocess, Trivy TRIVY-PYTHON-CWE-78
    all flag the same line in src/talonedge/cli.py. After dedupe + scoring:
    one finding, confidence 3, severity bumped to CRITICAL."""
    raw = _all_findings(all_scanner_files)
    merged = dedupe(raw)
    scored = apply_consensus(merged)

    matches = [f for f in scored if f.location.file == "src/talonedge/cli.py"]
    assert len(matches) == 1, f"Expected 1 merged finding, got {len(matches)}: {[m.rule_id for m in matches]}"
    f = matches[0]
    assert f.confidence == 3, f"Expected 3 sources, got {f.sources}"
    assert set(f.sources) == {"bandit", "semgrep", "trivy"}
    # Base was HIGH; consensus bump → CRITICAL.
    assert f.base_severity == Severity.HIGH
    assert f.severity == Severity.CRITICAL


def test_two_scanners_on_same_waf_finding_bump_to_critical(all_scanner_files):
    """Trivy AVD-AWS-0011 line 121 + tfsec AVD-AWS-0011 line 122 — within line
    tolerance, same rule id. Should collapse to one finding, confidence 2,
    severity bumped from HIGH to CRITICAL."""
    raw = _all_findings(all_scanner_files)
    merged = dedupe(raw)
    scored = apply_consensus(merged)

    waf = [f for f in scored if "AVD-AWS-0011" in f.rule_id.upper()]
    assert len(waf) == 1
    assert waf[0].confidence == 2
    assert set(waf[0].sources) == {"trivy", "tfsec"}
    assert waf[0].severity == Severity.CRITICAL


def test_secret_finding_overlaps_bandit_hardcoded_password_and_gitleaks(all_scanner_files):
    """Bandit B105 hardcoded_password line 7 + gitleaks generic-api-key line 7
    in the same file. Different rule IDs and no shared CWE — these should
    NOT collapse, because there's no signal they're the same finding."""
    raw = _all_findings(all_scanner_files)
    merged = dedupe(raw)

    in_policy = [f for f in merged if f.location.file == "src/talonedge/policy.py"]
    # Both findings present, neither merged, because rule IDs differ and
    # neither has a CWE that matches.
    assert len(in_policy) == 2
    confidences = sorted(f.confidence for f in in_policy)
    assert confidences == [1, 1]


def test_solo_finding_keeps_base_severity(all_scanner_files):
    """Trivy CVE-2026-99999 in Dockerfile is reported only by Trivy. Severity
    should stay CRITICAL (no further bump possible) and confidence 1."""
    raw = _all_findings(all_scanner_files)
    scored = apply_consensus(dedupe(raw))

    cve = [f for f in scored if f.rule_id == "CVE-2026-99999"]
    assert len(cve) == 1
    assert cve[0].confidence == 1
    assert cve[0].severity == Severity.CRITICAL
    assert cve[0].base_severity == Severity.CRITICAL


def test_total_count_after_dedupe(all_scanner_files):
    """5 scanners produced 8 raw findings. After dedup the test fixtures
    should collapse to 5 unique findings."""
    raw = _all_findings(all_scanner_files)
    assert len(raw) == 8  # bandit 2 + semgrep 1 + trivy 3 + gitleaks 1 + tfsec 1
    merged = dedupe(raw)
    assert len(merged) == 5  # 1 shell-injection (3 scanners) + 1 WAF (2) + B105 + gitleaks + CVE


def test_findings_sorted_by_severity_then_confidence(all_scanner_files):
    raw = _all_findings(all_scanner_files)
    scored = apply_consensus(dedupe(raw))
    severities = [int(f.severity) for f in scored]
    assert severities == sorted(severities, reverse=True)


# ---------- unit-test scenarios with synthetic Findings ----------

def test_line_tolerance_collapses_close_lines():
    a = Finding(
        rule_id="R", rule_name="r", message="m1", severity=Severity.HIGH,
        location=Location(file="a.py", line=10), cwe=("78",),
        sources=("scannerA",), confidence=1, base_severity=Severity.HIGH,
    )
    b = Finding(
        rule_id="R", rule_name="r", message="m2", severity=Severity.HIGH,
        location=Location(file="a.py", line=12), cwe=("78",),  # within tolerance
        sources=("scannerB",), confidence=1, base_severity=Severity.HIGH,
    )
    merged = dedupe([a, b])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"scannerA", "scannerB"}


def test_line_outside_tolerance_does_not_collapse():
    a = Finding(
        rule_id="R", rule_name="r", message="m1", severity=Severity.HIGH,
        location=Location(file="a.py", line=10), cwe=("78",),
        sources=("scannerA",), base_severity=Severity.HIGH,
    )
    b = Finding(
        rule_id="R", rule_name="r", message="m2", severity=Severity.HIGH,
        location=Location(file="a.py", line=20),  # 10 lines apart
        cwe=("78",),
        sources=("scannerB",), base_severity=Severity.HIGH,
    )
    merged = dedupe([a, b])
    assert len(merged) == 2


def test_different_files_never_merge_even_with_same_rule():
    a = Finding(
        rule_id="R", rule_name="r", message="m", severity=Severity.HIGH,
        location=Location(file="a.py", line=10), cwe=("78",),
        sources=("X",), base_severity=Severity.HIGH,
    )
    b = Finding(
        rule_id="R", rule_name="r", message="m", severity=Severity.HIGH,
        location=Location(file="b.py", line=10), cwe=("78",),
        sources=("Y",), base_severity=Severity.HIGH,
    )
    merged = dedupe([a, b])
    assert len(merged) == 2


def test_consensus_bump_threshold_configurable():
    f = Finding(
        rule_id="R", rule_name="r", message="m", severity=Severity.MEDIUM,
        location=Location(file="a.py", line=1),
        sources=("a", "b"), confidence=2, base_severity=Severity.MEDIUM,
    )
    # Default threshold 2 → bump applied.
    after_default = apply_consensus([f])
    assert after_default[0].severity == Severity.HIGH
    # Threshold 3 → no bump.
    f.severity = Severity.MEDIUM  # reset
    f.base_severity = Severity.MEDIUM
    after_strict = apply_consensus([f], bump_threshold=3)
    assert after_strict[0].severity == Severity.MEDIUM


def test_empty_input_returns_empty():
    assert dedupe([]) == []
    assert apply_consensus([]) == []
