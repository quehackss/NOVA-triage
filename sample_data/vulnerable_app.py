"""Intentionally vulnerable sample app for demoing vuln-triage-mcp.

Do not deploy this. It exists only so the MCP tools have something
concrete to find and reason about.
"""

import os
import sqlite3

import yaml  # pinned to a known-vulnerable version in requirements-sample.txt


def get_user(username: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: string-formatted SQL, classic SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def load_config(path: str):
    with open(path) as f:
        # VULNERABLE: unsafe yaml.load allows arbitrary object deserialization
        return yaml.load(f, Loader=yaml.Loader)


def run_backup(target_dir: str):
    # VULNERABLE: shell=True with unsanitized input, command injection
    os.system(f"tar -czf backup.tar.gz {target_dir}")
