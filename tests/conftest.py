"""Shared fixtures for sarif-merge tests."""

from __future__ import annotations

from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def all_scanner_files(fixtures_dir: Path) -> list[Path]:
    return [
        fixtures_dir / "bandit.sarif",
        fixtures_dir / "semgrep.sarif",
        fixtures_dir / "trivy.sarif",
        fixtures_dir / "gitleaks.sarif",
        fixtures_dir / "tfsec.sarif",
    ]
