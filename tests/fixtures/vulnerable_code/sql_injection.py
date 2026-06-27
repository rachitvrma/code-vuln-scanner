# tests/fixtures/vulnerable_code/sql_injection.py
# -------------------------------------------------
# Intentionally vulnerable code for testing purposes.
# DO NOT use any patterns from this file in production.

import sqlite3


def get_user(username: str) -> dict:
    """VULNERABLE: SQL Injection via f-string interpolation."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ CWE-89: Unsanitised user input injected directly into SQL
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}


def delete_user(user_id: str) -> None:
    """VULNERABLE: SQL Injection via string concatenation."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ CWE-89: String concatenation builds raw SQL
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()
    conn.close()


def search_products(category: str) -> list:
    """VULNERABLE: SQL Injection via % formatting."""
    conn = sqlite3.connect("store.db")
    cursor = conn.cursor()

    # ❌ CWE-89: % formatting is not parameterised
    sql = "SELECT * FROM products WHERE category = '%s'" % category
    cursor.execute(sql)
    return cursor.fetchall()
