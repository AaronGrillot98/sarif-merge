"""Cross-scanner consensus scoring.

If N independent scanners agree on a finding, it's more likely real than any
one scanner's heuristic. We bump the severity by one level for any finding
agreed by 2+ scanners. Severity is capped at CRITICAL — agreement on a
critical can't bump it further.

This is opinionated. The function is a single place to retune the heuristic.
"""

from __future__ import annotations

from .finding import Finding
from .severity import Severity


def apply_consensus(findings: list[Finding], *, bump_threshold: int = 2) -> list[Finding]:
    """Return new Finding objects with consensus-bumped severity.

    The merge step in ``dedupe`` already set ``confidence = len(sources)`` and
    ``base_severity`` to the original (un-bumped) max severity. This pass
    promotes the public ``severity`` field when confidence >= bump_threshold.
    """
    out: list[Finding] = []
    for f in findings:
        # base_severity is set by the parser; if a finding was never merged
        # by dedupe, its base_severity equals its current severity.
        base = f.base_severity if f.base_severity != Severity.NONE else f.severity
        if f.confidence >= bump_threshold:
            promoted = base.bump(1)
        else:
            promoted = base
        # Replace severity, leave base_severity recording the un-bumped value.
        f.severity = promoted
        f.base_severity = base
        out.append(f)
    return out
