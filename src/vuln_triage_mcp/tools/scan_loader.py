"""Load and normalize SAST scan output (currently: Semgrep JSON format).

Design note: this module has no LLM calls. It is a pure data-access tool
that the MCP client's reasoning loop will call. Keeping tools "dumb" is
intentional -- it's what makes the server usable from any MCP client
(Claude, Codex, custom agents) instead of baking in one vendor's model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ScanLoadError(Exception):
    pass


def load_semgrep_results(scan_path: str) -> list[dict[str, Any]]:
    """Parse a Semgrep JSON report into a normalized finding list.

    Each returned finding has a stable shape regardless of scanner,
    so downstream tools (code context, advisory lookup) don't need
    to know which scanner produced it:

        {
            "finding_id": str,
            "rule_id": str,
            "message": str,
            "severity": str,
            "file": str,
            "start_line": int,
            "end_line": int,
            "code_snippet": str,
        }
    """
    path = Path(scan_path)
    if not path.exists():
        raise ScanLoadError(f"Scan file not found: {scan_path}")

    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ScanLoadError(f"Invalid JSON in {scan_path}: {e}") from e

    results = raw.get("results", [])
    if not results:
        return []

    findings = []
    for i, r in enumerate(results):
        start = r.get("start", {})
        end = r.get("end", {})
        extra = r.get("extra", {})
        findings.append(
            {
                "finding_id": f"finding-{i:04d}",
                "rule_id": r.get("check_id", "unknown"),
                "message": extra.get("message", ""),
                "severity": extra.get("severity", "UNKNOWN"),
                "file": r.get("path", ""),
                "start_line": start.get("line", 0),
                "end_line": end.get("line", 0),
                "code_snippet": extra.get("lines", ""),
            }
        )
    return findings


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Quick counts by severity, useful for the agent to prioritize triage order."""
    by_severity: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {"total": len(findings), "by_severity": by_severity}
