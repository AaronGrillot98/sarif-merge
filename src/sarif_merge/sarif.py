"""SARIF v2.1.0 parsing.

SARIF is a verbose JSON schema. The bits we care about per finding are:

  sarif.runs[i].tool.driver.name                  -> scanner name
  sarif.runs[i].tool.driver.rules[]               -> rule definitions (severity hints)
  sarif.runs[i].results[].ruleId                  -> rule that fired
  sarif.runs[i].results[].level                   -> SARIF-standard severity
  sarif.runs[i].results[].message.text            -> human message
  sarif.runs[i].results[].locations[0]
      .physicalLocation
        .artifactLocation.uri                     -> file path
        .region.startLine / .startColumn          -> position
  sarif.runs[i].results[].properties              -> scanner-specific extras
  sarif.runs[i].results[].rule                    -> reference to rules[i]

Per-scanner quirks we normalize:
  Bandit:   stores actual severity in result.properties (issue_severity).
  Trivy:    severity in rule.properties.security-severity (CVSS-style float).
  tfsec:    severity in rule.properties.severity (string).
  Semgrep:  encodes severity in `level` plus rule.properties.security-severity.
  gitleaks: emits everything as level=error; we trust that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from .finding import Finding, Location
from .severity import Severity


SARIF_SCHEMA_KEY = "$schema"
RUNS = "runs"
TOOL = "tool"
DRIVER = "driver"
RULES = "rules"
RESULTS = "results"


class SarifParseError(ValueError):
    """Raised when a SARIF file is structurally invalid for our needs."""


def load_sarif(path: Path) -> dict[str, Any]:
    """Read and JSON-decode a SARIF file. Caller handles FileNotFoundError."""
    raw = path.read_text(encoding="utf-8")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SarifParseError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(doc, dict):
        raise SarifParseError(f"{path}: SARIF root must be an object")
    if RUNS not in doc or not isinstance(doc[RUNS], list):
        raise SarifParseError(f"{path}: SARIF document missing 'runs' array")
    return doc


def parse_findings(doc: dict[str, Any], *, source_hint: str | None = None) -> Iterator[Finding]:
    """Yield ``Finding`` objects from one parsed SARIF document.

    ``source_hint`` is used as the scanner name when the SARIF document does
    not embed one (rare but possible). For well-formed scanner output this is
    ignored in favor of ``runs[].tool.driver.name``.
    """
    for run in doc.get(RUNS, []):
        tool = run.get(TOOL) or {}
        driver = tool.get(DRIVER) or {}
        scanner = driver.get("name") or source_hint or "unknown"
        scanner = str(scanner).strip().lower()

        # Rules are referenced by index or id from each result. Build a lookup.
        rules_by_id: dict[str, dict[str, Any]] = {}
        rules_list: list[dict[str, Any]] = list(driver.get(RULES) or [])
        for rule in rules_list:
            rid = rule.get("id")
            if rid:
                rules_by_id[str(rid)] = rule

        for result in run.get(RESULTS, []) or []:
            yield _parse_result(result, scanner, rules_by_id, rules_list)


def _parse_result(
    result: dict[str, Any],
    scanner: str,
    rules_by_id: dict[str, dict[str, Any]],
    rules_list: list[dict[str, Any]],
) -> Finding:
    rule_id = str(result.get("ruleId") or "").strip()
    rule = rules_by_id.get(rule_id, {})
    # Some scanners use ruleIndex into runs[].tool.driver.rules instead of ruleId.
    if not rule and "ruleIndex" in result:
        try:
            rule = rules_list[int(result["ruleIndex"])]
            if not rule_id:
                rule_id = str(rule.get("id") or "")
        except (IndexError, ValueError, TypeError):
            rule = {}

    rule_name = str(rule.get("name") or rule.get("shortDescription", {}).get("text") or rule_id)

    message = _extract_message(result)

    # Severity precedence (highest-information wins):
    #   1. result.properties.{security-severity, severity, issue_severity, problem.severity}
    #   2. rule.properties.{security-severity, severity}
    #   3. result.level (SARIF standard)
    #   4. rule.defaultConfiguration.level
    severity = _severity_for(result, rule)

    location = _extract_location(result)

    cwe = _extract_cwe(result, rule)

    properties = result.get("properties") or {}

    extra = {scanner: {
        "rule_id": rule_id,
        "level": result.get("level"),
        "result_properties": properties,
        "fingerprint": result.get("fingerprints") or properties.get("fingerprint"),
    }}

    return Finding(
        rule_id=rule_id or "(unknown)",
        rule_name=rule_name,
        message=message,
        severity=severity,
        location=location,
        cwe=cwe,
        sources=(scanner,),
        confidence=1,
        base_severity=severity,
        extra=extra,
    )


def _extract_message(result: dict[str, Any]) -> str:
    msg = result.get("message") or {}
    if isinstance(msg, str):
        return msg.strip()
    text = msg.get("text") or msg.get("markdown") or ""
    return str(text).strip()


def _severity_for(result: dict[str, Any], rule: dict[str, Any]) -> Severity:
    # 1. Result-level explicit severity properties (most specific).
    rprops = result.get("properties") or {}
    for key in ("security-severity", "issue_severity", "severity", "problem.severity"):
        if key in rprops:
            sev = (Severity.from_security_severity(rprops[key])
                   if key == "security-severity"
                   else Severity.from_string(rprops[key]))
            if sev != Severity.NONE:
                return sev

    # 2. Rule-level properties (typed once per rule, applies to all firings).
    ruleprops = rule.get("properties") or {}
    for key in ("security-severity",):
        if key in ruleprops:
            sev = Severity.from_security_severity(ruleprops[key])
            if sev != Severity.NONE:
                return sev
    for key in ("severity", "issue_severity"):
        if key in ruleprops:
            sev = Severity.from_string(ruleprops[key])
            if sev != Severity.NONE:
                return sev

    # 3. Standard SARIF level on the result.
    if result.get("level"):
        sev = Severity.from_sarif_level(result["level"])
        if sev != Severity.NONE:
            return sev

    # 4. Default level on the rule.
    cfg = (rule.get("defaultConfiguration") or {})
    if cfg.get("level"):
        return Severity.from_sarif_level(cfg["level"])

    return Severity.NONE


def _extract_location(result: dict[str, Any]) -> Location:
    locations = result.get("locations") or []
    if not locations:
        return Location(file="(unknown)", line=0)

    physical = (locations[0] or {}).get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}

    uri = artifact.get("uri") or "(unknown)"
    file_path = _normalize_path(uri)

    line = int(region.get("startLine") or 0)
    column = int(region.get("startColumn") or 0)

    return Location(file=file_path, line=line, column=column)


def _normalize_path(uri: str) -> str:
    """Strip ``file://`` schemes, leading ``./``, and Windows backslashes."""
    p = uri
    if p.startswith("file:///"):
        p = p[len("file:///"):]
    elif p.startswith("file://"):
        p = p[len("file://"):]
    p = p.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    return p


def _extract_cwe(result: dict[str, Any], rule: dict[str, Any]) -> tuple[str, ...]:
    """Pull CWE numbers from the standard places.

    SARIF puts them in:
      - result.taxa[*].id  with toolComponent.name == 'CWE'
      - rule.relationships[*].target.id  with target.toolComponent.name == 'CWE'
      - rule.properties.cwe (some scanners just dump a string list here)
    """
    found: list[str] = []

    for taxa_entry in result.get("taxa") or []:
        if _is_cwe_component(taxa_entry.get("toolComponent")):
            cwe_id = _normalize_cwe(taxa_entry.get("id"))
            if cwe_id:
                found.append(cwe_id)

    for rel in rule.get("relationships") or []:
        target = rel.get("target") or {}
        if _is_cwe_component(target.get("toolComponent")):
            cwe_id = _normalize_cwe(target.get("id"))
            if cwe_id:
                found.append(cwe_id)

    raw = (rule.get("properties") or {}).get("cwe")
    if isinstance(raw, str):
        found.extend(_normalize_cwe(x) for x in raw.replace(",", " ").split() if x)
    elif isinstance(raw, list):
        found.extend(_normalize_cwe(x) for x in raw if x)

    return tuple(dict.fromkeys(c for c in found if c))


def _is_cwe_component(component: dict[str, Any] | None) -> bool:
    if not isinstance(component, dict):
        return False
    name = (component.get("name") or "").upper()
    return "CWE" in name


def _normalize_cwe(value: Any) -> str:
    """Strip 'CWE-' prefix and any whitespace; keep the bare number."""
    if value is None:
        return ""
    s = str(value).strip().upper()
    if s.startswith("CWE-"):
        s = s[4:]
    elif s.startswith("CWE:"):
        s = s[4:]
    return s.lstrip("0") or s
