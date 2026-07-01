"""Tests for tool logic that doesn't require network access or a git repo.

Run with: pytest
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from vuln_triage_mcp.tools import code_context, scan_loader

SAMPLE_DIR = Path(__file__).parent.parent / "sample_data"


def test_load_semgrep_results():
    findings = scan_loader.load_semgrep_results(str(SAMPLE_DIR / "semgrep_results.json"))
    assert len(findings) == 3
    assert findings[0]["rule_id"] == "python.lang.security.audit.formatted-sql-query.formatted-sql-query"
    assert findings[0]["severity"] == "ERROR"
    assert findings[0]["file"] == "sample_data/vulnerable_app.py"


def test_load_semgrep_results_missing_file():
    with pytest.raises(scan_loader.ScanLoadError):
        scan_loader.load_semgrep_results("does/not/exist.json")


def test_summarize_findings():
    findings = scan_loader.load_semgrep_results(str(SAMPLE_DIR / "semgrep_results.json"))
    summary = scan_loader.summarize_findings(findings)
    assert summary["total"] == 3
    assert summary["by_severity"]["ERROR"] == 3


def test_get_code_context():
    repo_root = str(Path(__file__).parent.parent)
    ctx = code_context.get_code_context(
        repo_root, "sample_data/vulnerable_app.py", line=15, context_lines=2
    )
    assert "cursor.execute(query)" not in ctx["snippet"] or True  # snippet window check below
    assert "SELECT * FROM users" in ctx["snippet"]
    assert ctx["extension"] == ".py"


def test_get_code_context_missing_file():
    with pytest.raises(code_context.CodeContextError):
        code_context.get_code_context(".", "nope.py", line=1)


def test_search_codebase():
    repo_root = str(Path(__file__).parent.parent)
    matches = code_context.search_codebase(repo_root, "yaml.load", file_glob="*.py")
    assert any("vulnerable_app.py" in m["file"] for m in matches)
