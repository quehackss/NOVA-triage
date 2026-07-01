"""Pull surrounding code and git history for a given file/line.

This is what lets the agent reason about *exploitability* rather than
just repeating the scanner's one-line message: is the tainted input
actually reachable from user input, is there sanitization nearby,
who wrote it and when.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class CodeContextError(Exception):
    pass


def get_code_context(
    repo_root: str, file_path: str, line: int, context_lines: int = 15
) -> dict[str, str | int]:
    """Return the code around `line` in `file_path`, plus its file extension."""
    full_path = Path(repo_root) / file_path
    if not full_path.exists():
        raise CodeContextError(f"File not found: {full_path}")

    lines = full_path.read_text(errors="replace").splitlines()
    start = max(0, line - 1 - context_lines)
    end = min(len(lines), line + context_lines)

    numbered = [f"{i + 1:>5}: {lines[i]}" for i in range(start, end)]

    return {
        "file": file_path,
        "target_line": line,
        "snippet": "\n".join(numbered),
        "extension": full_path.suffix,
    }


def get_git_blame(repo_root: str, file_path: str, line: int) -> dict[str, str]:
    """Return author, date, and commit summary for the line, if the repo is a git repo.

    Useful for triage: recently-changed security-sensitive code is a higher
    priority signal than code that's been stable and unexploited for years.
    """
    try:
        result = subprocess.run(
            ["git", "blame", "-L", f"{line},{line}", "--porcelain", file_path],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return {"error": f"git blame unavailable: {e}"}

    out = result.stdout
    author = next((l.split(" ", 1)[1] for l in out.splitlines() if l.startswith("author ")), "unknown")
    summary = next((l.split(" ", 1)[1] for l in out.splitlines() if l.startswith("summary ")), "")
    commit_hash = out.splitlines()[0].split(" ")[0] if out else "unknown"

    return {"commit": commit_hash, "author": author, "summary": summary}


def search_codebase(repo_root: str, pattern: str, file_glob: str = "*") -> list[dict[str, str | int]]:
    """Grep the repo for a pattern (e.g. to check if a sink is called elsewhere,
    or whether a sanitizer wraps the tainted input)."""
    try:
        result = subprocess.run(
            ["grep", "-rn", "--include", file_glob, pattern, "."],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError as e:
        raise CodeContextError(f"grep unavailable: {e}") from e

    matches = []
    for line in result.stdout.splitlines()[:200]:  # cap to keep tool output bounded
        parts = line.split(":", 2)
        if len(parts) == 3:
            matches.append({"file": parts[0], "line": int(parts[1]), "text": parts[2].strip()})
    return matches
