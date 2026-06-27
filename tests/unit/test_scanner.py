"""
tests/unit/test_scanner.py
---------------------------
Unit tests for the main scanner pipeline and response parser.
SKIP_LLM=true is set in conftest.py so no Ollama is needed.
"""

from __future__ import annotations

import pytest

from vuln_scanner.llm.response_parser import parse_vulnerabilities
from vuln_scanner.models import Severity


# ─────────────────────────────────────────────────────────────────────────────
# ResponseParser tests
# ─────────────────────────────────────────────────────────────────────────────

class TestResponseParser:

    def test_parses_clean_json(self):
        raw = '''{
          "vulnerabilities": [
            {
              "type": "SQL Injection",
              "cwe_id": "CWE-89",
              "cve_references": [],
              "severity": "HIGH",
              "line_numbers": [10],
              "description": "User input in SQL query",
              "code_snippet": "cursor.execute(f\\"SELECT * FROM users WHERE id={uid}\\")",
              "remediation": "Use parameterised queries",
              "confidence": 0.95
            }
          ],
          "overall_risk": "HIGH",
          "summary": "Found 1 SQL injection."
        }'''
        vulns, summary, risk = parse_vulnerabilities(raw)
        assert len(vulns) == 1
        assert vulns[0].type == "SQL Injection"
        assert vulns[0].severity == Severity.HIGH
        assert vulns[0].cwe_id == "CWE-89"
        assert 10 in vulns[0].line_numbers
        assert risk == Severity.HIGH

    def test_parses_json_in_markdown_fence(self):
        raw = '''Here is my analysis:
```json
{
  "vulnerabilities": [
    {
      "type": "Command Injection",
      "cwe_id": "CWE-78",
      "cve_references": [],
      "severity": "HIGH",
      "line_numbers": [5],
      "description": "shell=True used",
      "code_snippet": "subprocess.run(cmd, shell=True)",
      "remediation": "Use a list of args",
      "confidence": 0.9
    }
  ],
  "overall_risk": "HIGH",
  "summary": "One command injection found."
}
```'''
        vulns, summary, risk = parse_vulnerabilities(raw)
        assert len(vulns) == 1
        assert vulns[0].type == "Command Injection"

    def test_handles_empty_vulnerabilities(self):
        raw = '{"vulnerabilities": [], "overall_risk": "INFO", "summary": "Clean."}'
        vulns, summary, risk = parse_vulnerabilities(raw)
        assert vulns == []
        assert risk == Severity.INFO

    def test_handles_malformed_json_gracefully(self):
        raw = "Sorry, I cannot analyse this code."
        vulns, summary, risk = parse_vulnerabilities(raw)
        assert vulns == []
        assert risk == Severity.INFO

    def test_confidence_is_float(self):
        raw = '''{
          "vulnerabilities": [{
            "type": "XSS",
            "cwe_id": "CWE-79",
            "cve_references": [],
            "severity": "MEDIUM",
            "line_numbers": [3],
            "description": "test",
            "code_snippet": "echo $_GET",
            "remediation": "escape output",
            "confidence": 0.7
          }],
          "overall_risk": "MEDIUM",
          "summary": "XSS found."
        }'''
        vulns, _, _ = parse_vulnerabilities(raw)
        assert abs(vulns[0].confidence - 0.7) < 0.01

    def test_severity_normalisation(self):
        """Moderate/moderate are mapped to MEDIUM."""
        raw = '''{
          "vulnerabilities": [{
            "type": "Open Redirect",
            "cwe_id": "CWE-601",
            "cve_references": [],
            "severity": "MODERATE",
            "line_numbers": [],
            "description": "redirect",
            "code_snippet": "",
            "remediation": "whitelist",
            "confidence": 0.6
          }],
          "overall_risk": "MODERATE",
          "summary": "redirect found."
        }'''
        vulns, _, risk = parse_vulnerabilities(raw)
        assert vulns[0].severity == Severity.MEDIUM
        assert risk == Severity.MEDIUM

    def test_handles_truncated_json(self):
        """Should not crash on truncated output — returns partial or empty."""
        raw = '{"vulnerabilities": [{"type": "SQL Injection", "severity": "HIGH'
        vulns, _, _ = parse_vulnerabilities(raw)
        # Should not raise; empty or partial is acceptable
        assert isinstance(vulns, list)


# ─────────────────────────────────────────────────────────────────────────────
# VulnerabilityScanner pipeline tests (SKIP_LLM=true)
# ─────────────────────────────────────────────────────────────────────────────

class TestVulnerabilityScanner:

    def test_scan_returns_scan_result(self, scanner, sql_injection_code):
        from vuln_scanner.models import ScanResult
        result = scanner.scan(sql_injection_code, language="python", filename="test.py")
        assert isinstance(result, ScanResult)

    def test_empty_code_returns_error(self, scanner):
        result = scanner.scan("   ", filename="empty.py")
        assert result.error is not None

    def test_language_auto_detect_python(self, scanner):
        code = "import os\ndef main():\n    pass"
        result = scanner.scan(code, language="auto", filename="script.py")
        assert result.language == "python"

    def test_language_auto_detect_c(self, scanner, buffer_overflow_c_code):
        result = scanner.scan(buffer_overflow_c_code, language="auto", filename="main.c")
        assert result.language in ("c", "cpp")

    def test_pattern_matches_returned(self, scanner, insecure_deser_code):
        result = scanner.scan(insecure_deser_code, language="python")
        assert len(result.pattern_matches) > 0

    def test_sql_injection_detected_by_patterns(self, scanner, sql_injection_code):
        result = scanner.scan(sql_injection_code, language="python")
        all_types = {m.vulnerability_type for m in result.pattern_matches}
        assert "SQL Injection" in all_types

    def test_buffer_overflow_detected_by_patterns(self, scanner, buffer_overflow_c_code):
        result = scanner.scan(buffer_overflow_c_code, language="c")
        all_types = {m.vulnerability_type for m in result.pattern_matches}
        assert "Buffer Overflow" in all_types

    def test_scan_time_is_positive(self, scanner, sql_injection_code):
        result = scanner.scan(sql_injection_code, language="python")
        assert result.scan_time > 0

    def test_code_hash_is_consistent(self, scanner, sql_injection_code):
        r1 = scanner.scan(sql_injection_code, language="python")
        r2 = scanner.scan(sql_injection_code, language="python")
        assert r1.code_hash == r2.code_hash

    def test_severity_counts(self, scanner, insecure_deser_code):
        result = scanner.scan(insecure_deser_code, language="python")
        # Pattern-matcher should find critical/high findings (pickle, etc.)
        total = (
            result.critical_count
            + result.high_count
            + result.medium_count
            + result.low_count
        )
        assert total == result.total_vulnerabilities
