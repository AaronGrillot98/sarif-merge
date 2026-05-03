"""Internal Finding model and the merge logic that combines two findings.

A ``Finding`` is what the rest of the pipeline reasons over — every SARIF
parser produces these, dedup buckets them, the renderer reads them. SARIF is
verbose and inconsistent across scanners; this model is small and uniform.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from .severity import Severity


@dataclass(frozen=True)
class Location:
    """Where in the codebase a finding lives."""

    file: str
    """Path relative to the repo root, forward-slashed and normalized."""

    line: int
    """1-based line number. 0 means 'whole file' or 'unknown line'."""

    column: int = 0
    """1-based column. 0 means unknown."""

    def normalize_path(self) -> str:
        # Already normalized at construction time, but keep the helper so
        # callers don't have to reach into the dataclass.
        return self.file


@dataclass
class Finding:
    """One security finding, possibly merged across multiple scanners."""

    rule_id: str
    """Scanner-internal rule identifier, e.g. ``B602`` (bandit) or ``CKV_AWS_19``."""

    rule_name: str
    """Human-readable rule name."""

    message: str
    """Why this is a finding, in human terms."""

    severity: Severity
    """Normalized severity. After consensus scoring, this may be bumped."""

    location: Location

    cwe: tuple[str, ...] = field(default_factory=tuple)
    """CWE identifiers as plain strings ('79', '89'). Tuple to keep hashable."""

    sources: tuple[str, ...] = field(default_factory=tuple)
    """Names of scanners that reported this finding (e.g. 'bandit', 'trivy')."""

    confidence: int = 1
    """How many distinct scanners agreed on this finding."""

    base_severity: Severity = Severity.NONE
    """Severity before consensus bumping. NONE until set by ``score``."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Per-scanner properties that don't fit the canonical fields, e.g. SARIF
    fingerprint, helpUri, tags. Always sub-keyed by source name to avoid
    collisions when merging."""

    def primary_cwe(self) -> str | None:
        return self.cwe[0] if self.cwe else None

    def dedupe_key(self) -> tuple[str, int, str]:
        """Stable key used to bucket findings during dedup.

        Two findings collapse if they share file + line (within tolerance) +
        primary CWE (or normalized rule id when CWE is missing). The line
        tolerance is applied at bucket-build time, not here.
        """
        cwe_or_rule = self.primary_cwe() or _normalize_rule_id(self.rule_id)
        return (self.location.file, self.location.line, cwe_or_rule)

    def merge(self, other: "Finding") -> "Finding":
        """Combine two findings believed to refer to the same underlying issue.

        Severity is the max of the two. Sources concatenate (deduplicated,
        order-preserving). The longer message wins (longer = usually more
        informative). Extra dictionaries union under their source-name keys.
        """
        merged_sources = _ordered_unique(self.sources + other.sources)
        merged_cwe = _ordered_unique(self.cwe + other.cwe)
        merged_extra = {**self.extra, **other.extra}
        # Prefer the more informative message; ties broken by shorter (cleaner)
        # rule_id, then by alphabetical scanner name for determinism.
        if len(other.message) > len(self.message):
            primary = other
        elif len(other.message) < len(self.message):
            primary = self
        else:
            primary = self if self.rule_id <= other.rule_id else other
        return replace(
            primary,
            severity=Severity(max(int(self.severity), int(other.severity))),
            sources=merged_sources,
            cwe=merged_cwe,
            confidence=len(merged_sources),
            extra=merged_extra,
        )


def _normalize_rule_id(rule_id: str) -> str:
    """Lowercase + collapse whitespace + strip noisy prefixes.

    Different scanners prefix their rule ids inconsistently; we normalize so
    ``B602`` and ``b602`` and ``BANDIT.B602`` look identical when bucketing.
    """
    if not rule_id:
        return ""
    s = rule_id.strip().lower().replace(" ", "")
    # Collapse known scanner-name prefixes.
    for prefix in ("bandit.", "semgrep.", "trivy.", "gitleaks.", "tfsec.", "checkov."):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    return s


def _ordered_unique(seq) -> tuple:
    """Order-preserving dedup of a sequence of hashables."""
    seen = set()
    out = []
    for x in seq:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return tuple(out)
