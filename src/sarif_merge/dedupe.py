"""Bucket findings into equivalence classes and merge each class."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .finding import Finding


DEFAULT_LINE_TOLERANCE = 2
"""How many lines apart two findings can sit and still be considered the same.

Different scanners point at slightly different lines for the same issue
(e.g. one points at the function def, another at the call). 2 absorbs
common scanner-specific offsets without collapsing genuinely different
findings on adjacent lines.
"""


def dedupe(
    findings: Iterable[Finding],
    *,
    line_tolerance: int = DEFAULT_LINE_TOLERANCE,
) -> list[Finding]:
    """Group findings that are likely the same issue and merge each group.

    Two-pass algorithm:
      1. Bucket by (file, primary_cwe_or_rule). Line tolerance is applied
         within a bucket so we don't have to compare every-pair-against-
         every-pair.
      2. Inside each (file, key) bucket, walk findings sorted by line. A new
         finding that's within ``line_tolerance`` of the running cluster's
         line range joins the cluster; otherwise it starts a new cluster.

    Returns merged findings sorted by (severity desc, confidence desc, file).
    """
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        cwe_or_rule = f.primary_cwe() or _normalized_rule(f.rule_id)
        buckets[(f.location.file, cwe_or_rule)].append(f)

    merged: list[Finding] = []
    for bucket in buckets.values():
        merged.extend(_merge_bucket(bucket, line_tolerance))

    merged.sort(
        key=lambda f: (-int(f.severity), -f.confidence, f.location.file, f.location.line)
    )
    return merged


def _merge_bucket(findings: list[Finding], tolerance: int) -> list[Finding]:
    """Cluster findings in a single (file, key) bucket by line proximity."""
    if not findings:
        return []
    findings.sort(key=lambda f: f.location.line)

    clusters: list[Finding] = []
    cluster: Finding = findings[0]
    cluster_min_line = cluster.location.line
    cluster_max_line = cluster.location.line

    for f in findings[1:]:
        if f.location.line - cluster_max_line <= tolerance:
            cluster = cluster.merge(f)
            cluster_max_line = max(cluster_max_line, f.location.line)
        else:
            clusters.append(cluster)
            cluster = f
            cluster_min_line = f.location.line
            cluster_max_line = f.location.line
    clusters.append(cluster)
    return clusters


def _normalized_rule(rule_id: str) -> str:
    # Local import to avoid creating a finding<->dedupe import cycle.
    from .finding import _normalize_rule_id
    return _normalize_rule_id(rule_id)
