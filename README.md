# vuln-triage-mcp

An [MCP](https://modelcontextprotocol.io) server that gives any MCP-compatible
AI agent (Claude Desktop, Claude Code, Codex, etc.) the tools it needs to
autonomously triage SAST/SCA scan findings — pulling code context, git
history, and dependency advisories to judge whether a finding is a real,
exploitable issue rather than noise.

## Why this exists

Static analysis tools are noisy. A human still has to open each finding,
read the surrounding code, check who touched it and when, and decide if
it's exploitable. That triage work is exactly the kind of multi-step,
tool-using reasoning an agent is good at — *if* it has grounded access to
the repo instead of guessing from the finding text alone.

This project doesn't call an LLM itself. It exposes **tools**; the
reasoning loop lives in whatever MCP client connects to it. That's a
deliberate design choice: it keeps the server model-agnostic and testable
independent of any one vendor's agent framework.

## Architecture

```
MCP Client (Claude Desktop / Claude Code / Codex / your own agent)
        │  MCP protocol (stdio)
        ▼
vuln-triage-mcp server  ──────────────────────────────
  tools:
    load_scan_results          parse Semgrep JSON → normalized findings
    get_code_context            read code around a finding's line
    get_git_blame                who/when touched that line
    search_codebase              grep for sanitizers / other call sites
    check_dependency_advisory    OSV.dev lookup for a package+version
```

Each tool is a pure function with no hidden state — same input, same
output, independently testable (see `tests/`).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

## Connect it to an MCP client

Add to your client's MCP config (e.g. Claude Desktop's `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vuln-triage": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "vuln_triage_mcp.server"]
    }
  }
}
```

Restart the client, then just ask it to triage a scan, e.g.:

> "Load the scan results in sample_data/semgrep_results.json and triage
> each finding against the repo at sample_data/ — tell me which are
> real and how you'd fix them."

## Try it without a full setup

`sample_data/` contains a small intentionally-vulnerable Python file and a
matching Semgrep-style JSON report, so you can see the agent work end to
end without scanning a real codebase first.

## Run the tests

```bash
pip install pytest
pytest tests/ -v
```

## Roadmap

- [x] v0 — scan loading + code context tools, working against sample data
- [ ] v1 — richer dependency advisory reasoning (transitive deps, reachability)
- [ ] v2 — `draft_fix_pr` tool (human-approval-gated PR creation via GitHub API)
- [ ] v3 — eval harness against known-vulnerable repos (Juice Shop, WebGoat) to
      measure triage precision/recall and publish numbers in this README
- [ ] v4 — GitHub Action wrapper so this runs automatically on every PR

## Status

Early / actively developed. This is a portfolio project demonstrating
agentic tool design in the AppSec/DevSecOps space — feedback and issues
welcome.
