# sarif-merge

> Merge, deduplicate, and consensus-score SARIF output from multiple security scanners — and emit one unified report instead of five overlapping ones.

Every modern Security CI pipeline runs a stack: Bandit, Semgrep, Trivy, gitleaks, tfsec, Checkov, and so on. They all emit SARIF. They all overlap. The reviewer sees the same finding three times under three different rule IDs and stops reading.

`sarif-merge` ingests SARIF v2.1.0 from any number of scanners and produces:

1. A **unified SARIF** file containing one entry per real finding, with all reporting scanners listed under `properties.sources`.
2. A **Markdown summary** suitable for posting as a PR comment, sorted by severity × cross-scanner confidence.

A finding reported by three scanners gets bumped one severity level — the heuristic is "if three independent tools agree, pay attention."

## Install

```bash
pip install -e .
```

## Use

```bash
sarif-merge \
  bandit.sarif semgrep.sarif trivy.sarif gitleaks.sarif tfsec.sarif \
  --output merged.sarif \
  --markdown summary.md
```

In a GitHub Actions step:

```yaml
- name: Merge SARIF outputs
  run: |
    sarif-merge \
      bandit.sarif semgrep.sarif trivy.sarif gitleaks.sarif tfsec.sarif \
      --output merged.sarif \
      --markdown $GITHUB_STEP_SUMMARY
```

The Markdown lands directly in the PR's job summary and (with one extra `gh pr comment` step) on the PR conversation.

## How it works

### Identity

Two findings collapse into one if they share:

- the same source file (canonicalized to the workspace-relative path)
- the same line (with ±2 line tolerance to absorb scanner-specific column offsets)
- the same primary CWE — or, when CWE isn't reported, the same normalized rule ID

### Severity normalization

Every scanner uses its own severity vocabulary. Internally `sarif-merge` collapses everything to a 5-point ordinal:

| Internal | SARIF level | Trivy | Bandit | tfsec | Semgrep |
|---|---|---|---|---|---|
| CRITICAL | error | CRITICAL | — | CRITICAL | error + sec ≥ 9 |
| HIGH | error | HIGH | HIGH | HIGH | error + sec ≥ 7 |
| MEDIUM | warning | MEDIUM | MEDIUM | MEDIUM | warning |
| LOW | note | LOW | LOW | LOW | info |
| NONE | none | UNKNOWN | — | — | — |

### Consensus scoring

Each merged finding gets a `confidence` count = number of unique scanners that flagged it.

When confidence ≥ 2, severity is bumped one level (capped at CRITICAL). The intuition: agreement from independent tools is a stronger signal than any single tool's heuristic.

## Output

### Markdown summary (PR comment)

Headers with totals, top-N findings table, by-scanner breakdown, by-severity breakdown.

### Unified SARIF

Compliant with [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html). Each merged finding's `properties.sources` lists every scanner that reported it; the `level` reflects the consensus-bumped severity.

## License

MIT — see [LICENSE](LICENSE).
