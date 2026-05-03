"""Severity normalization across scanner vocabularies.

Every scanner has its own severity scheme. We map all of them onto a single
5-point ordinal. ``Severity`` is integer-comparable (``HIGH > MEDIUM``) so
the dedup/scoring logic can work with simple ``max()`` calls.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_sarif_level(cls, level: str | None) -> "Severity":
        """SARIF result.level: none|note|warning|error."""
        return {
            "error": cls.HIGH,
            "warning": cls.MEDIUM,
            "note": cls.LOW,
            "none": cls.NONE,
        }.get((level or "").lower(), cls.NONE)

    @classmethod
    def from_string(cls, value: Any) -> "Severity":
        """Best-effort parse from any free-text severity tag."""
        if value is None:
            return cls.NONE
        s = str(value).strip().upper()
        if s in cls.__members__:
            return cls[s]
        # Common aliases used by various scanners.
        return {
            "INFO": cls.LOW,
            "INFORMATIONAL": cls.LOW,
            "WARN": cls.MEDIUM,
            "WARNING": cls.MEDIUM,
            "MODERATE": cls.MEDIUM,
            "ERROR": cls.HIGH,
            "SEVERE": cls.HIGH,
            "BLOCKER": cls.CRITICAL,
        }.get(s, cls.NONE)

    @classmethod
    def from_security_severity(cls, value: Any) -> "Severity":
        """SARIF rule.properties.security-severity is a 0.0–10.0 float (CVSS-like).

        Mapping per the SARIF 2.1.0 guidance:
        9.0–10.0 = critical, 7.0–8.9 = high, 4.0–6.9 = medium, 0.1–3.9 = low.
        """
        try:
            f = float(value)
        except (TypeError, ValueError):
            return cls.NONE
        if f >= 9.0:
            return cls.CRITICAL
        if f >= 7.0:
            return cls.HIGH
        if f >= 4.0:
            return cls.MEDIUM
        if f > 0.0:
            return cls.LOW
        return cls.NONE

    def to_sarif_level(self) -> str:
        return {
            Severity.NONE: "none",
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }[self]

    def label(self) -> str:
        return self.name

    def bump(self, levels: int = 1) -> "Severity":
        """Increase severity by ``levels``, capped at CRITICAL."""
        return Severity(min(int(self) + max(0, levels), int(Severity.CRITICAL)))
