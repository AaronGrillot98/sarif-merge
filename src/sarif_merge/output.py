"""Emit the merged findings as a SARIF v2.1.0 document.

We synthesize a single ``run`` with a synthetic driver named ``sarif-merge``.
Each merged finding becomes one ``result``. The ``properties.sources`` array
records every scanner that reported it; ``properties.confidence`` records the
N. The original per-scanner data lives under ``properties.original`` keyed by
scanner name so it is not lost.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .finding import Finding


SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Build a SARIF v2.1.0 document from merged findings."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        if f.rule_id not in rules_by_id:
            rules_by_id[f.rule_id] = _rule_for(f)
        results.append(_result_for(f))

    run = {
        "tool": {
            "driver": {
                "name": "sarif-merge",
                "version": __version__,
                "informationUri": "https://github.com/AaronGrillot98/sarif-merge",
                "rules": list(rules_by_id.values()),
            }
        },
        "results": results,
    }
    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def _rule_for(f: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": f.rule_id,
        "name": f.rule_name or f.rule_id,
        "shortDescription": {"text": f.rule_name or f.rule_id},
    }
    if f.cwe:
        rule["properties"] = {"cwe": list(f.cwe)}
    return rule


def _result_for(f: Finding) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.location.file},
        }
    }
    if f.location.line:
        region: dict[str, Any] = {"startLine": f.location.line}
        if f.location.column:
            region["startColumn"] = f.location.column
        location["physicalLocation"]["region"] = region

    return {
        "ruleId": f.rule_id,
        "level": f.severity.to_sarif_level(),
        "message": {"text": f.message},
        "locations": [location],
        "properties": {
            "sources": list(f.sources),
            "confidence": f.confidence,
            "consensus_severity": f.severity.label(),
            "base_severity": f.base_severity.label(),
            "cwe": list(f.cwe),
            "original": f.extra,
        },
    }
