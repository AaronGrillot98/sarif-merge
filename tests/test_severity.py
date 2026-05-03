"""Severity normalization across scanner vocabularies."""

from sarif_merge.severity import Severity


def test_sarif_levels_map_to_ordered_severities():
    assert Severity.from_sarif_level("error") == Severity.HIGH
    assert Severity.from_sarif_level("warning") == Severity.MEDIUM
    assert Severity.from_sarif_level("note") == Severity.LOW
    assert Severity.from_sarif_level("none") == Severity.NONE
    assert Severity.from_sarif_level(None) == Severity.NONE
    assert Severity.from_sarif_level("UNKNOWN-VALUE") == Severity.NONE


def test_string_aliases():
    assert Severity.from_string("HIGH") == Severity.HIGH
    assert Severity.from_string("low") == Severity.LOW
    assert Severity.from_string("info") == Severity.LOW
    assert Severity.from_string("warn") == Severity.MEDIUM
    assert Severity.from_string("BLOCKER") == Severity.CRITICAL
    assert Severity.from_string(None) == Severity.NONE


def test_security_severity_ranges():
    # CVSS-style float; SARIF guidance.
    assert Severity.from_security_severity(9.9) == Severity.CRITICAL
    assert Severity.from_security_severity(9.0) == Severity.CRITICAL
    assert Severity.from_security_severity(8.5) == Severity.HIGH
    assert Severity.from_security_severity(7.0) == Severity.HIGH
    assert Severity.from_security_severity(6.9) == Severity.MEDIUM
    assert Severity.from_security_severity(4.0) == Severity.MEDIUM
    assert Severity.from_security_severity(3.9) == Severity.LOW
    assert Severity.from_security_severity(0.1) == Severity.LOW
    assert Severity.from_security_severity(0.0) == Severity.NONE


def test_security_severity_handles_strings_and_garbage():
    assert Severity.from_security_severity("8.5") == Severity.HIGH
    assert Severity.from_security_severity("garbage") == Severity.NONE
    assert Severity.from_security_severity(None) == Severity.NONE


def test_to_sarif_level_round_trip_lossy_for_critical():
    # CRITICAL collapses to 'error' in SARIF; that's fine — SARIF only has 4
    # levels. We keep the distinction in our internal model and surface it
    # via properties.consensus_severity in the emitted SARIF.
    assert Severity.HIGH.to_sarif_level() == "error"
    assert Severity.CRITICAL.to_sarif_level() == "error"
    assert Severity.MEDIUM.to_sarif_level() == "warning"
    assert Severity.LOW.to_sarif_level() == "note"
    assert Severity.NONE.to_sarif_level() == "none"


def test_severity_is_orderable():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert max(Severity.LOW, Severity.HIGH) == Severity.HIGH


def test_bump_caps_at_critical():
    assert Severity.LOW.bump(1) == Severity.MEDIUM
    assert Severity.MEDIUM.bump(2) == Severity.CRITICAL
    assert Severity.HIGH.bump(1) == Severity.CRITICAL
    assert Severity.CRITICAL.bump(1) == Severity.CRITICAL
    assert Severity.CRITICAL.bump(99) == Severity.CRITICAL


def test_bump_negative_or_zero_is_noop():
    assert Severity.MEDIUM.bump(0) == Severity.MEDIUM
    assert Severity.MEDIUM.bump(-1) == Severity.MEDIUM
