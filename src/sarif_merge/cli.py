"""Command-line entry point for sarif-merge."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .dedupe import DEFAULT_LINE_TOLERANCE, dedupe
from .finding import Finding
from .output import to_sarif
from .render import render_markdown
from .sarif import SarifParseError, load_sarif, parse_findings
from .score import apply_consensus
from .severity import Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sarif-merge",
        description=(
            "Merge SARIF outputs from multiple security scanners. Deduplicates "
            "overlapping findings, bumps severity for cross-scanner consensus, "
            "and emits a single unified SARIF + Markdown summary."
        ),
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="One or more SARIF v2.1.0 files. Empty/zero-finding inputs are tolerated.",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Write the unified SARIF here. Default: stdout.",
    )
    parser.add_argument(
        "--markdown", "-m",
        type=Path,
        default=None,
        help="Write a human-readable Markdown summary here (e.g. $GITHUB_STEP_SUMMARY).",
    )
    parser.add_argument(
        "--line-tolerance",
        type=int,
        default=DEFAULT_LINE_TOLERANCE,
        help=f"Lines apart still treated as the same finding. Default: {DEFAULT_LINE_TOLERANCE}.",
    )
    parser.add_argument(
        "--bump-threshold",
        type=int,
        default=2,
        help="Min unique scanners required before bumping severity. Default: 2.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="Exit non-zero if any merged finding meets or exceeds this level. Default: none.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many findings to list in the Markdown 'Top findings' table. Default: 10.",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"sarif-merge {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    findings: list[Finding] = []
    errors: list[str] = []
    for path in args.inputs:
        if not path.exists():
            errors.append(f"input not found: {path}")
            continue
        try:
            doc = load_sarif(path)
        except SarifParseError as exc:
            errors.append(str(exc))
            continue
        # Use the file stem as a fallback scanner name if the SARIF doc omits one.
        for f in parse_findings(doc, source_hint=path.stem):
            findings.append(f)

    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return 2

    merged = dedupe(findings, line_tolerance=args.line_tolerance)
    scored = apply_consensus(merged, bump_threshold=args.bump_threshold)

    sarif_doc = to_sarif(scored)
    sarif_text = json.dumps(sarif_doc, indent=2, sort_keys=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(sarif_text, encoding="utf-8")
    else:
        print(sarif_text)

    if args.markdown:
        md = render_markdown(scored, top_n=args.top)
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(md, encoding="utf-8")

    threshold = Severity[args.fail_on.upper()] if args.fail_on != "none" else None
    if threshold is not None:
        worst = max((int(f.severity) for f in scored), default=0)
        if worst >= int(threshold):
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
