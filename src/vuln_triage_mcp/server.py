"""MCP server entrypoint.

Exposes vulnerability-triage tools over the Model Context Protocol.
No LLM lives here -- the connected client (Claude Desktop, Claude Code,
Codex, or any other MCP-compatible agent) provides the reasoning loop.
This server only provides grounded, verifiable data access.

Run directly for local stdio testing:
    python -m vuln_triage_mcp.server

Or via the installed console script:
    vuln-triage-mcp
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from vuln_triage_mcp.tools import advisory, code_context, scan_loader

mcp = FastMCP("vuln-triage-mcp")


@mcp.tool()
def load_scan_results(scan_path: str) -> dict:
    """Load a Semgrep JSON scan report and return normalized findings plus a
    severity summary. Call this first to see what needs triaging."""
    findings = scan_loader.load_semgrep_results(scan_path)
    return {
        "findings": findings,
        "summary": scan_loader.summarize_findings(findings),
    }


@mcp.tool()
def get_code_context(repo_root: str, file_path: str, line: int, context_lines: int = 15) -> dict:
    """Return source code surrounding a specific file/line, so the finding
    can be evaluated in context rather than in isolation."""
    return code_context.get_code_context(repo_root, file_path, line, context_lines)


@mcp.tool()
def get_git_blame(repo_root: str, file_path: str, line: int) -> dict:
    """Return the commit, author, and summary for the line that triggered a
    finding. Recently-changed code is a stronger prioritization signal."""
    return code_context.get_git_blame(repo_root, file_path, line)


@mcp.tool()
def search_codebase(repo_root: str, pattern: str, file_glob: str = "*") -> list:
    """Grep the repository for a pattern -- e.g. to check whether a sanitizer
    wraps a tainted input, or whether a vulnerable function is called elsewhere."""
    return code_context.search_codebase(repo_root, pattern, file_glob)


@mcp.tool()
async def check_dependency_advisory(package: str, version: str, ecosystem: str = "PyPI") -> dict:
    """Look up known CVEs/advisories for a package+version via OSV.dev, to
    assess whether a dependency finding is actually exploitable at this version."""
    return await advisory.check_dependency_advisory(package, version, ecosystem)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
