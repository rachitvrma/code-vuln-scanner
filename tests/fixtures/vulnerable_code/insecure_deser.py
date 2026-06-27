# tests/fixtures/vulnerable_code/insecure_deser.py
# --------------------------------------------------
# Intentionally vulnerable code for testing purposes.
# DO NOT use any patterns from this file in production.

import pickle
import yaml
import marshal
import base64
import os


# ❌ CWE-502: pickle.loads on untrusted network data
def load_user_session(raw_bytes: bytes) -> dict:
    """Load a session from a cookie value — never do this with pickle!"""
    return pickle.loads(raw_bytes)


# ❌ CWE-502: yaml.load with the full Loader (can execute Python)
def parse_config(yaml_string: str) -> dict:
    """Parse YAML config — using unsafe Loader."""
    return yaml.load(yaml_string, Loader=yaml.Loader)


# ❌ CWE-502: marshal is not safe for untrusted input
def restore_state(blob: bytes) -> object:
    """Restore application state from blob."""
    return marshal.loads(blob)


# ❌ CWE-78 + CWE-502: deserialise then execute
def run_task(encoded_task: str) -> None:
    """Decode a base64-encoded pickled callable and run it."""
    task_bytes = base64.b64decode(encoded_task)
    task = pickle.loads(task_bytes)  # ❌ CWE-502
    task()                            # arbitrary code execution


# ❌ CWE-798: hardcoded secret key
SECRET_KEY = "s3cr3t-flask-key-do-not-share"   # ❌ CWE-798
DB_PASSWORD = "admin1234"                        # ❌ CWE-798

# ❌ CWE-78: command injection
def backup_file(filename: str) -> None:
    os.system(f"cp {filename} /backups/")        # ❌ CWE-78
