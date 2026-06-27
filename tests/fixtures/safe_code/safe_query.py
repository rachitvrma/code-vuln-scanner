# tests/fixtures/safe_code/safe_query.py
# ----------------------------------------
# Correct, secure code used to test for false positives.
# The scanner should NOT flag these patterns.

import sqlite3
import os
from pathlib import Path


def get_user(username: str) -> dict:
    """✓ Safe: parameterised query prevents SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ✓ CWE-89 mitigated: placeholder ? keeps data and SQL separate
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}


def delete_user(user_id: int) -> None:
    """✓ Safe: integer parameter is never interpolated as a string."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def run_tool(tool_name: str, arg: str) -> None:
    """✓ Safe: subprocess called with a list, never shell=True."""
    import subprocess
    allowed = {"ls", "echo", "cat"}
    if tool_name not in allowed:
        raise ValueError(f"Tool '{tool_name}' is not whitelisted.")
    subprocess.run([tool_name, arg], shell=False, check=True)  # ✓ no injection risk


def read_config(filename: str) -> str:
    """✓ Safe: path is canonicalised and checked against a base directory."""
    base = Path("/etc/myapp").resolve()
    target = (base / filename).resolve()
    if not str(target).startswith(str(base)):
        raise PermissionError("Path traversal attempt detected.")
    return target.read_text()


# ✓ Credentials loaded from environment, not hardcoded
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
API_KEY     = os.environ.get("API_KEY", "")
