"""
static_analysis/bandit_wrapper.py
----------------------------------
Runs Bandit (Python-only security linter) as a subprocess and
returns results as StaticFinding objects.

Why subprocess instead of Bandit's Python API?
  Bandit's internal API changes between minor versions.
  The JSON CLI output is stable and well-documented.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import List

from loguru import logger

from ..models import StaticFinding


# Bandit severity → canonical string (Bandit uses HIGH/MEDIUM/LOW)
_SEV_MAP = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
_CONF_MAP = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


class BanditAnalyzer:
    """
    Wraps the ``bandit`` CLI to scan Python source code.

    Only works for Python.  The caller (scanner.py) is responsible
    for only calling this when language == 'python'.

    Usage::

        ba = BanditAnalyzer()
        findings = ba.analyze(python_source_code)
    """

    def __init__(self) -> None:
        self._available = self._check_bandit()

    def _check_bandit(self) -> bool:
        """Return True if bandit is installed and callable."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning(
                "bandit not found. Install it: pip install bandit\n"
                "Python static analysis will be skipped."
            )
            return False

    @property
    def is_available(self) -> bool:
        return self._available

    def analyze(self, code: str) -> List[StaticFinding]:
        """
        Run Bandit on *code* and return a list of findings.

        Parameters
        ----------
        code : Python source code as a string.

        Returns
        -------
        List[StaticFinding] — empty list if Bandit is unavailable or finds nothing.
        """
        if not self._available:
            logger.debug("Bandit unavailable — skipping Python static analysis.")
            return []

        # Write code to a temp file (Bandit needs a file path)
        tmp_path: str = ""
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".py",
                mode="w",
                encoding="utf-8",
                delete=False,
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name

            result = subprocess.run(
                [
                    "bandit",
                    "--format", "json",
                    "--quiet",          # suppress progress output
                    "--severity-level", "low",
                    "--confidence-level", "low",
                    tmp_path,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Bandit exits with code 1 when it finds issues — that's fine
            if not result.stdout:
                logger.debug("Bandit produced no output.")
                return []

            return self._parse_output(result.stdout)

        except subprocess.TimeoutExpired:
            logger.warning("Bandit timed out (60 s) analysing the file.")
            return []
        except Exception as exc:
            logger.error(f"Bandit analysis failed: {exc}")
            return []
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _parse_output(self, stdout: str) -> List[StaticFinding]:
        """Parse Bandit's JSON output into StaticFinding objects."""
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.warning(f"Could not parse Bandit JSON output: {exc}")
            return []

        findings: List[StaticFinding] = []
        for issue in data.get("results", []):
            try:
                cwe_raw = issue.get("issue_cwe", {})
                cwe_id = (
                    f"CWE-{cwe_raw['id']}"
                    if isinstance(cwe_raw, dict) and "id" in cwe_raw
                    else None
                )
                findings.append(StaticFinding(
                    tool="bandit",
                    severity=_SEV_MAP.get(issue.get("issue_severity", "LOW"), "LOW"),
                    confidence=_CONF_MAP.get(issue.get("issue_confidence", "LOW"), "LOW"),
                    line_number=int(issue.get("line_number", 0)),
                    col_offset=int(issue.get("col_offset", 0)),
                    test_id=issue.get("test_id", ""),
                    test_name=issue.get("test_name", ""),
                    issue_text=issue.get("issue_text", ""),
                    code=issue.get("code", "").strip(),
                    cwe=cwe_id,
                ))
            except Exception as exc:
                logger.warning(f"Skipping Bandit result entry: {exc}")

        logger.info(f"Bandit found {len(findings)} issues.")
        return findings
